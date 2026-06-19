#!/usr/bin/env python3
"""
Bulk-issue certificates from a CSV against CyberArk Certificate Manager - SaaS,
and download each one *with its private key* in PEM and PKCS#12 (.p12) form.

Two key-generation modes:

  --keygen central   (default)  CM SaaS generates the key AND the certificate.
                                The private key is retrieved back through the
                                tenant's edge-encryption key (libsodium sealed box).
                                Requires an issuing template with "Allow Venafi to
                                generate the key" enabled.

  --keygen local                The key pair is generated on THIS host, a CSR is
                                uploaded, and the issued certificate is downloaded
                                and paired with the local key. Requires a template
                                with "Allow uploaded CSR" enabled (e.g. Built-In CA
                                "Default"). The private key never leaves this host.

For every row in the CSV the script issues a certificate, then writes into the
output directory:

    <name>.key.pem        private key (encrypted unless --decrypt-key)
    <name>.crt.pem        leaf certificate only
    <name>.chain.pem      issuer chain (intermediates + root), if any
    <name>.fullchain.pem  leaf + chain, no key (nginx/Apache "ssl_certificate")
    <name>.pem            combined: leaf + chain + private key (e.g. HAProxy)
    <name>.p12            PKCS#12 keystore (key + leaf + chain), password protected

By default each certificate's files are bundled into <name>.zip (pass --no-zip for
loose files). A results.csv manifest is always written alongside, un-zipped.

Key/.p12 password (in priority order):
  1. --prompt-password  -> prompt once, use that one password for ALL certs.
  2. --key-password / CCM_KEY_PASSWORD -> one password for ALL certs.
  3. a CSV password column (KeyPassword / Password / Passphrase / ...) -> per-row.
  4. otherwise -> a strong random password is generated per certificate.
results.csv records only the password SOURCE (prompt/shared/csv/random), never the value.
Randomly-generated passwords are the only ones that would otherwise be unrecoverable, so
they are written to a SEPARATE GENERATED-PASSWORDS.csv next to the output - distribute it
securely and delete it afterwards. Supplied/column passwords are not echoed anywhere.

Requires: Python 3.8+, `requests`, `cryptography`, and (for --keygen central) `pynacl`
    pip install requests cryptography pynacl

Example (central keygen - the common case):
    python ccm_csv_cert_issue.py \
        --csv ./samples/device_sample_for_bulk_cert.csv \
        --api-key <YOUR_API_KEY> \
        --application-name "Example Devices" \
        --issuing-template "MSCA-1year" \
        --output-dir ./out \
        --key-password "ChangeMe123!"
"""

import argparse
import csv
import getpass
import ipaddress
import os
import re
import secrets
import string
import sys
import time
import zipfile
from urllib.parse import quote

import requests
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    pkcs12, BestAvailableEncryption, NoEncryption,
)

# --------------------------------------------------------------------------- #
# CSV header handling
# --------------------------------------------------------------------------- #

_HEADER_ALIASES = {
    "commonname": "cn", "cn": "cn", "subject": "cn", "fqdn": "cn", "hostname": "cn",
    "country": "c", "c": "c", "countryname": "c",
    "state": "st", "st": "st", "province": "st", "stateorprovince": "st", "stateprovince": "st",
    "locality": "l", "locatlity": "l", "location": "l", "city": "l", "l": "l",
    "organization": "o", "organisation": "o", "org": "o", "o": "o",
    "organizationunit": "ou", "organizationalunit": "ou", "organisationunit": "ou",
    "orgunit": "ou", "ou": "ou", "department": "ou",
    "email": "email", "emailaddress": "email", "e": "email",
}


# CSV columns that supply a per-certificate key/P12 password.
_PASSWORD_HEADERS = {"keypassword", "password", "pfxpassword", "p12password",
                     "passphrase", "keypass", "pwd"}

# Alphabet for generated passwords: alphanumerics + a few widely-safe symbols
# (no quotes/backticks/spaces, so they paste cleanly into shells and openssl).
_PW_ALPHABET = string.ascii_letters + string.digits + "!@#%-_+="


def gen_password(length: int = 20) -> str:
    return "".join(secrets.choice(_PW_ALPHABET) for _ in range(length))


def _norm(header: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (header or "").strip().lower())


def parse_csv_rows(path: str):
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError(f"CSV {path} has no header row")
        col_role = {}
        for col in reader.fieldnames:
            n = _norm(col)
            if n in _HEADER_ALIASES:
                col_role[col] = _HEADER_ALIASES[n]
            elif n in _PASSWORD_HEADERS:
                col_role[col] = "pw"
            elif n.startswith("san") or n in ("dnsnames", "dnsname", "subjectalternativename",
                                              "subjectalternativenames", "altname", "altnames"):
                col_role[col] = "san"
            else:
                col_role[col] = None

        for lineno, raw in enumerate(reader, start=2):
            rec = {"cn": "", "c": "", "st": "", "l": "", "o": "", "ou": "",
                   "email": "", "sans": [], "pw": "", "_line": lineno}
            for col, value in raw.items():
                role = col_role.get(col)
                value = (value or "").strip()
                if not value or role is None:
                    continue
                if role == "san":
                    rec["sans"].extend(s for s in re.split(r"[,;\s]+", value) if s)
                else:
                    rec[role] = value
            if not rec["cn"]:
                print(f"  ! line {lineno}: no CommonName, skipping")
                continue
            yield rec


def dns_and_ip_sans(rec):
    """Return (dns_names, ip_addrs) including the CN as a DNS name, de-duplicated."""
    dns, ips, seen = [], [], set()
    for raw in [rec["cn"]] + rec["sans"]:
        if not raw or raw.lower() in seen:
            continue
        seen.add(raw.lower())
        try:
            ips.append(str(ipaddress.ip_address(raw)))
        except ValueError:
            dns.append(raw)
    return dns, ips


# --------------------------------------------------------------------------- #
# CCM SaaS REST client
# --------------------------------------------------------------------------- #

class CcmClient:
    def __init__(self, api_key: str, base_url: str = "https://api.venafi.cloud"):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "tppl-api-key": api_key,
            "Content-Type": "application/json",
        })

    def request(self, method, path, json_body=None, accept=None):
        headers = {"accept": accept} if accept else None
        resp = self.session.request(
            method, f"{self.base_url}{path}", json=json_body, headers=headers, timeout=90
        )
        if not resp.ok:
            raise RuntimeError(f"HTTP {resp.status_code} on {method} {path}: {resp.text}")
        return resp

    def json(self, method, path, json_body=None):
        return self.request(method, path, json_body=json_body).json()


def resolve_user_id(client):
    return client.json("GET", "/v1/useraccounts")["user"]["id"]


def resolve_issuing_template(client, name):
    cits = client.json("GET", "/v1/certificateissuingtemplates").get("certificateIssuingTemplates", [])
    for c in cits:
        if c.get("name", "").lower() == name.lower():
            return c
    available = ", ".join(repr(c.get("name")) for c in cits)
    raise RuntimeError(f"Issuing template '{name}' not found. Available: {available}")


def ensure_application(client, name, owner_id, cit_id, cit_alias):
    encoded = quote(name, safe="")
    try:
        app = client.json("GET", f"/outagedetection/v1/applications/name/{encoded}")
        alias_map = app.get("certificateIssuingTemplateAliasIdMap") or {}
        if cit_id not in alias_map.values():
            raise RuntimeError(
                f"Application '{name}' exists ({app['id']}) but is not linked to issuing "
                f"template '{cit_alias}'. Link it in the CCM UI, or use a different "
                f"--application-name."
            )
        print(f"      Reusing application '{name}' ({app['id']}), template '{cit_alias}' linked")
        return app["id"]
    except RuntimeError as e:
        if "HTTP 404" not in str(e):
            raise
    body = {
        "name": name,
        "ownerIdsAndTypes": [{"ownerId": owner_id, "ownerType": "USER"}],
        "certificateIssuingTemplateAliasIdMap": {cit_alias: cit_id},
    }
    created = client.json("POST", "/outagedetection/v1/applications", body)
    app_id = created["applications"][0]["id"]
    print(f"      Created application '{name}' ({app_id}) linked to template '{cit_alias}'")
    return app_id


def poll_request(client, req_id, timeout, interval):
    deadline = time.time() + timeout
    while time.time() < deadline:
        rr = client.json("GET", f"/outagedetection/v1/certificaterequests/{req_id}")
        status = rr.get("status")
        ids = rr.get("certificateIds") or rr.get("certificateIdsForReissue")
        if status in ("ISSUED", "COMPLETED") and ids:
            return ids[0]
        if status in ("FAILED", "REJECTED", "CANCELLED"):
            raise RuntimeError(f"request {req_id} ended as {status}: {rr.get('errorInformation')}")
        time.sleep(interval)
    raise RuntimeError(f"request {req_id} not issued within {timeout}s")


# --------------------------------------------------------------------------- #
# Issuance - central keygen (CM SaaS generates key + cert)
# --------------------------------------------------------------------------- #

def issue_central(client, rec, app_id, cit_id, key_size, validity, key_password,
                  poll_timeout, poll_interval):
    try:
        from nacl.public import PublicKey, SealedBox
    except ImportError:
        raise RuntimeError("--keygen central needs the 'pynacl' package (pip install pynacl)")

    dns, ips = dns_and_ip_sans(rec)
    csr_attrs = {
        "commonName": rec["cn"],
        "keyTypeParameters": {"keyType": "RSA", "keyLength": key_size},
        "subjectAlternativeNamesByType": {},
    }
    if rec["o"]:  csr_attrs["organization"] = rec["o"]
    if rec["ou"]: csr_attrs["organizationalUnits"] = [rec["ou"]]
    if rec["l"]:  csr_attrs["locality"] = rec["l"]
    if rec["st"]: csr_attrs["state"] = rec["st"]
    if rec["c"]:  csr_attrs["country"] = rec["c"]
    if dns: csr_attrs["subjectAlternativeNamesByType"]["dnsNames"] = dns
    if ips: csr_attrs["subjectAlternativeNamesByType"]["ipAddresses"] = ips

    body = {
        "isVaaSGenerated": True,
        "applicationId": app_id,
        "certificateIssuingTemplateId": cit_id,
        "csrAttributes": csr_attrs,
    }
    if validity:
        body["validityPeriod"] = validity
    resp = client.json("POST", "/outagedetection/v1/certificaterequests", body)
    req_id = resp["certificateRequests"][0]["id"]
    cert_id = poll_request(client, req_id, poll_timeout, poll_interval)

    # Retrieve the private key: encrypt a passphrase against the tenant edge key.
    cert = client.json("GET", f"/outagedetection/v1/certificates/{cert_id}")
    dek = cert.get("dekHash")
    if not dek:
        raise RuntimeError(f"certificate {cert_id} has no dekHash - key was not service-generated")
    pub = client.json("GET", f"/v1/edgeencryptionkeys/{dek}")["key"]
    box = SealedBox(PublicKey(__import__("base64").b64decode(pub)))

    def seal(p):
        import base64
        return base64.b64encode(box.encrypt(p.encode("utf-8"))).decode("ascii")

    ks_body = {
        "exportFormat": "PKCS12",
        "encryptedPrivateKeyPassphrase": seal(key_password),
        "encryptedKeystorePassphrase": seal(key_password),
        "certificateLabel": rec["cn"],
    }
    p12_bytes = client.request(
        "POST", f"/outagedetection/v1/certificates/{cert_id}/keystore", json_body=ks_body
    ).content
    key, leaf, cas = pkcs12.load_key_and_certificates(p12_bytes, key_password.encode())
    return key, leaf, list(cas or []), cert_id


# --------------------------------------------------------------------------- #
# Issuance - local keygen (we make the key + CSR, upload CSR)
# --------------------------------------------------------------------------- #

def issue_local(client, rec, app_id, cit_id, key_size, validity,
                poll_timeout, poll_interval):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, rec["cn"])]
    for value, oid in (
        (rec["c"], NameOID.COUNTRY_NAME),
        (rec["st"], NameOID.STATE_OR_PROVINCE_NAME),
        (rec["l"], NameOID.LOCALITY_NAME),
        (rec["o"], NameOID.ORGANIZATION_NAME),
        (rec["ou"], NameOID.ORGANIZATIONAL_UNIT_NAME),
        (rec["email"], NameOID.EMAIL_ADDRESS),
    ):
        if value:
            attrs.append(x509.NameAttribute(oid, value))
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(attrs))

    dns, ips = dns_and_ip_sans(rec)
    san = [x509.DNSName(d) for d in dns] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
    csr_pem = builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()

    body = {
        "applicationId": app_id,
        "certificateIssuingTemplateId": cit_id,
        "certificateSigningRequest": csr_pem,
    }
    if validity:
        body["validityPeriod"] = validity
    resp = client.json("POST", "/outagedetection/v1/certificaterequests", body)
    req_id = resp["certificateRequests"][0]["id"]
    cert_id = poll_request(client, req_id, poll_timeout, poll_interval)

    chain_pem = client.request(
        "GET",
        f"/outagedetection/v1/certificates/{cert_id}/contents?format=PEM&chainOrder=EE_FIRST",
        accept="text/plain",
    ).text
    certs = x509.load_pem_x509_certificates(chain_pem.encode())
    return key, certs[0], certs[1:], cert_id


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

def safe_filename(common_name):
    return re.sub(r'[<>:"/\\|?]', "_", common_name.replace("*", "_"))


def write_outputs(out_dir, rec, key, leaf, cas, key_password, decrypt_key, zip_per_cert):
    base = safe_filename(rec["cn"])
    enc = NoEncryption() if decrypt_key else BestAvailableEncryption(key_password.encode())
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, enc
    ).decode()
    leaf_pem = leaf.public_bytes(serialization.Encoding.PEM).decode()
    chain_only = "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in cas)

    p12 = pkcs12.serialize_key_and_certificates(
        name=rec["cn"].encode(), key=key, cert=leaf, cas=cas or None,
        encryption_algorithm=BestAvailableEncryption(key_password.encode()),
    )

    files = {
        f"{base}.key.pem": key_pem,
        f"{base}.crt.pem": leaf_pem,
        f"{base}.fullchain.pem": leaf_pem + chain_only,
        f"{base}.pem": leaf_pem + chain_only + key_pem,
        f"{base}.p12": p12,
    }
    if chain_only:
        files[f"{base}.chain.pem"] = chain_only

    written = []
    for fname, content in files.items():
        path = os.path.join(out_dir, fname)
        if isinstance(content, bytes):
            with open(path, "wb") as f:
                f.write(content)
        else:
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(content)
        written.append(fname)

    if zip_per_cert:
        zpath = os.path.join(out_dir, f"{base}.zip")
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
            for fname in written:
                z.write(os.path.join(out_dir, fname), fname)
        for fname in written:
            os.remove(os.path.join(out_dir, fname))
        return [f"{base}.zip"]
    return written


# --------------------------------------------------------------------------- #

def main():
    p = argparse.ArgumentParser(
        description="Bulk-issue certificates from a CSV against CCM SaaS and download "
                    "each with its private key (PEM + PKCS#12).",
    )
    p.add_argument("--csv", required=True, help="Path to the input CSV.")
    p.add_argument("--api-key", help="CCM SaaS API key (or set CCM_API_KEY).")
    p.add_argument("--application-name", required=True, help="Application to use (created if missing).")
    p.add_argument("--issuing-template", required=True, help="Issuing template name.")
    p.add_argument("--output-dir", required=True, help="Directory for the generated files.")
    p.add_argument("--keygen", choices=["central", "local"], default="central",
                   help="central = CM SaaS generates the key (default); local = generate the key "
                        "here and upload a CSR.")
    p.add_argument("--key-password", help="Use ONE password for every cert's PEM key and .p12 "
                   "(or set CCM_KEY_PASSWORD). If omitted, each cert uses its CSV password column, "
                   "or a generated random password (recorded in results.csv).")
    p.add_argument("--prompt-password", action="store_true",
                   help="Prompt once for a password and use it for ALL certs (overrides the CSV column).")
    p.add_argument("--decrypt-key", action="store_true",
                   help="Write the PEM private key unencrypted (the .p12 stays password protected).")
    p.add_argument("--key-size", type=int, default=2048, help="RSA key size (default 2048).")
    p.add_argument("--validity", help="Optional validity period, ISO-8601 (e.g. P90D).")
    p.add_argument("--no-zip", action="store_true",
                   help="Write loose files instead of bundling each cert into <name>.zip (default: zip).")
    p.add_argument("--zip-per-cert", action="store_true", help=argparse.SUPPRESS)  # back-compat no-op; zip is default
    p.add_argument("--poll-timeout", type=int, default=180, help="Seconds to wait per cert (default 180).")
    p.add_argument("--poll-interval", type=int, default=3, help="Seconds between status polls (default 3).")
    p.add_argument("--api-base-url", default="https://api.venafi.cloud",
                   help="Regional API base URL (default https://api.venafi.cloud).")
    args = p.parse_args()

    api_key = args.api_key or os.environ.get("CCM_API_KEY")
    if not api_key:
        p.error("API key required: pass --api-key or set CCM_API_KEY")

    # Password resolution. A "shared" password (prompt / flag / env) is used for every
    # cert. Otherwise each row uses its CSV password column, or a generated random one.
    password_mode = None  # 'prompt' | 'shared' | None (per-cert)
    if args.prompt_password:
        shared_password = getpass.getpass("Password for ALL certificate keys/.p12: ")
        if not shared_password:
            p.error("--prompt-password: empty password entered")
        password_mode = "prompt"
    else:
        shared_password = args.key_password or os.environ.get("CCM_KEY_PASSWORD")
        if shared_password:
            password_mode = "shared"
    if shared_password:
        print("      Password mode: one shared password for all certificates")
    else:
        print("      Password mode: per-cert (CSV column if present, else generated random)")

    os.makedirs(args.output_dir, exist_ok=True)
    client = CcmClient(api_key, args.api_base_url)

    print(f"[1/3] Resolving user, issuing template and application (keygen={args.keygen})...")
    user_id = resolve_user_id(client)
    cit = resolve_issuing_template(client, args.issuing_template)
    cit_id, cit_alias = cit["id"], cit["name"]
    print(f"      Template: '{cit_alias}' ({cit_id}), CA={cit.get('certificateAuthority')}")

    # Validate the template supports the requested mode, up front.
    if args.keygen == "central" and not cit.get("keyGeneratedByVenafiAllowed"):
        raise RuntimeError(
            f"Template '{cit_alias}' does not allow Venafi-generated keys, so --keygen central "
            f"cannot work. Enable 'Allow Venafi to generate the key' on the template, pick a "
            f"template that allows it, or use --keygen local.")
    if args.keygen == "local" and not cit.get("csrUploadAllowed", True):
        raise RuntimeError(
            f"Template '{cit_alias}' does not allow uploaded CSRs, so --keygen local cannot work. "
            f"Use --keygen central or a template that allows uploaded CSRs.")

    app_id = ensure_application(client, args.application_name, user_id, cit_id, cit_alias)

    print(f"[2/3] Reading rows from {args.csv}...")
    rows = list(parse_csv_rows(args.csv))
    print(f"      {len(rows)} certificate(s) to issue")

    print("[3/3] Issuing certificates...")
    results = []
    generated = []  # (cn, password) for randomly-generated passwords only
    for i, rec in enumerate(rows, 1):
        label = rec["cn"]
        # Resolve this cert's password and where it came from (source, not the value).
        if shared_password:
            pw, pw_source = shared_password, password_mode
        elif rec["pw"]:
            pw, pw_source = rec["pw"], "csv"
        else:
            pw, pw_source = gen_password(), "random"
        try:
            if args.keygen == "central":
                key, leaf, cas, cert_id = issue_central(
                    client, rec, app_id, cit_id, args.key_size, args.validity,
                    pw, args.poll_timeout, args.poll_interval)
            else:
                key, leaf, cas, cert_id = issue_local(
                    client, rec, app_id, cit_id, args.key_size, args.validity,
                    args.poll_timeout, args.poll_interval)
            files = write_outputs(args.output_dir, rec, key, leaf, cas,
                                  pw, args.decrypt_key, not args.no_zip)
            if pw_source == "random":
                generated.append((label, pw))
            serial = format(leaf.serial_number, "x")
            base = safe_filename(rec["cn"])
            exts = "  ".join(f[len(base):] if f.startswith(base) else f for f in files)
            print(f"  [{i}/{len(rows)}] ISSUED  {label}  ({args.keygen} keygen)")
            print(f"           files  {exts}")
            print(f"           cert   {cert_id}")
            results.append({"commonName": label, "status": "ISSUED", "keyGeneration": args.keygen,
                            "certificateId": cert_id, "serial": serial, "passwordSource": pw_source,
                            "files": ";".join(files), "error": ""})
        except Exception as e:
            print(f"  [{i}/{len(rows)}] FAILED  {label}")
            print(f"           {e}")
            results.append({"commonName": label, "status": "FAILED", "keyGeneration": args.keygen,
                            "certificateId": "", "serial": "", "passwordSource": pw_source,
                            "files": "", "error": str(e)})

    manifest = os.path.join(args.output_dir, "results.csv")
    with open(manifest, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["commonName", "status", "keyGeneration", "certificateId",
                                          "serial", "passwordSource", "files", "error"])
        w.writeheader()
        w.writerows(results)

    # Secrets, kept OUT of the inventory manifest: only the randomly-generated passwords
    # (the ones that would otherwise be unrecoverable) go to a separate, clearly-named file.
    secrets_path = None
    if generated:
        secrets_path = os.path.join(args.output_dir, "GENERATED-PASSWORDS.csv")
        with open(secrets_path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["commonName", "keyPassword"])
            w.writerows(generated)

    ok = sum(1 for r in results if r["status"] == "ISSUED")
    failed = len(results) - ok
    print(f"\nDone.     {ok} issued, {failed} failed  ({len(results)} total)")
    print(f"Output:   {os.path.abspath(args.output_dir)}")
    print(f"Manifest: {manifest}  (password source only, no secrets)")
    if secrets_path:
        print(f"SECRETS:  {secrets_path}  ({len(generated)} generated password(s)) "
              f"- distribute securely, then DELETE this file")
    if ok != len(results):
        sys.exit(2)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, FileNotFoundError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
