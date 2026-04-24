#!/usr/bin/env python3
"""
Upload a certificate to CyberArk Certificate Manager SaaS, associate it with an
application, assign a tag, then download the chain back.

End-to-end workflow against the CyberArk Certificate Manager SaaS REST API
(https://api.venafi.cloud). The script:

  1. Resolves the calling user (owner for the application).
  2. Creates the application, or reuses it if one with the same name exists.
  3. Extracts the end-entity certificate from the supplied PEM and uploads it,
     associating it with the application.
  4. Creates the tag + value (or reuses them) and assigns "TagName:TagValue" to
     the uploaded certificate via PATCH /v1/tagsassignment.
  5. Downloads the certificate chain back to the specified output path.

Only the public certificate is uploaded. If the input PEM contains a full chain
or a private key, only the first BEGIN CERTIFICATE block is used for the upload;
the service infers the chain from its known issuer certificates.

Requires: Python 3.8+ and the `requests` package (pip install requests).

Example:
    python ccm_cert_workflow.py \
        --pem-path ./mycert.pem \
        --api-key <YOUR_API_KEY> \
        --application-name "Billing App" \
        --tag-name "Service Now" \
        --tag-value INC0012345 \
        --output-path ./mycert-downloaded.pem
"""

import argparse
import base64
import hashlib
import re
import sys
from urllib.parse import quote

import requests


class CcmClient:
    def __init__(self, api_key: str, base_url: str = "https://api.venafi.cloud"):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "tppl-api-key": api_key,
            "Content-Type": "application/json",
        })

    def request(self, method: str, path: str, json_body=None, accept=None):
        headers = {"accept": accept} if accept else None
        resp = self.session.request(
            method, f"{self.base_url}{path}", json=json_body, headers=headers, timeout=30
        )
        if not resp.ok:
            raise RuntimeError(
                f"HTTP {resp.status_code} on {method} {path}: {resp.text}"
            )
        return resp

    def json(self, method: str, path: str, json_body=None):
        return self.request(method, path, json_body=json_body).json()


def extract_first_certificate_base64(pem_path: str) -> str:
    with open(pem_path, "r", encoding="utf-8") as f:
        text = f.read()
    m = re.search(
        r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
        text,
        re.DOTALL,
    )
    if not m:
        raise ValueError(f"No -----BEGIN CERTIFICATE----- block found in {pem_path}")
    return re.sub(r"\s+", "", m.group(1))


def sha1_fingerprint(cert_b64: str) -> str:
    der = base64.b64decode(cert_b64)
    return hashlib.sha1(der).hexdigest().upper()


def find_certificate_id_by_fingerprint(client: "CcmClient", fingerprint: str):
    body = {
        "expression": {
            "operands": [{"field": "fingerprint", "operator": "MATCH", "value": fingerprint}]
        },
        "paging": {"pageNumber": 0, "pageSize": 1},
    }
    resp = client.json("POST", "/outagedetection/v1/certificatesearch", body)
    certs = resp.get("certificates") or []
    return certs[0]["id"] if certs else None


def ensure_application(client: CcmClient, name: str, owner_id: str) -> str:
    encoded = quote(name, safe="")
    try:
        existing = client.json("GET", f"/outagedetection/v1/applications/name/{encoded}")
        print(f"      Reusing existing application id: {existing['id']}")
        return existing["id"]
    except RuntimeError as e:
        if "HTTP 404" not in str(e):
            raise
    body = {
        "name": name,
        "ownerIdsAndTypes": [{"ownerId": owner_id, "ownerType": "USER"}],
    }
    created = client.json("POST", "/outagedetection/v1/applications", body)
    app_id = created["applications"][0]["id"]
    print(f"      Created application id: {app_id}")
    return app_id


def ensure_tag_and_value(client: CcmClient, tag_name: str, tag_value: str) -> None:
    encoded = quote(tag_name, safe="")
    try:
        existing = client.json("GET", f"/v1/tags/{encoded}")
        print(f"      Reusing existing tag id: {existing['id']}")
    except RuntimeError as e:
        if "HTTP 404" not in str(e):
            raise
        created = client.json("POST", "/v1/tags", {"name": tag_name, "values": [tag_value]})
        print(f"      Created tag id: {created['id']}")

    values = client.json("GET", f"/v1/tags/{encoded}/values")
    match = next((v for v in values.get("values", []) if v["value"] == tag_value), None)
    if match:
        print(f"      Reusing existing value id: {match['id']}")
    else:
        client.json("POST", f"/v1/tags/{encoded}/values", {"values": [tag_value]})
        print(f"      Added value '{tag_value}'")


def main():
    parser = argparse.ArgumentParser(
        description="Upload a cert to CyberArk Certificate Manager SaaS, tag it, and download it back.",
    )
    parser.add_argument("--pem-path", required=True, help="Path to the source PEM file.")
    parser.add_argument("--api-key", required=True, help="CyberArk Certificate Manager SaaS API key.")
    parser.add_argument("--application-name", required=True, help="Application to create/reuse.")
    parser.add_argument("--tag-name", required=True, help="Tag name to create/reuse.")
    parser.add_argument("--tag-value", required=True, help="Tag value to create/reuse.")
    parser.add_argument("--output-path", required=True, help="Path for the downloaded PEM.")
    parser.add_argument(
        "--api-base-url",
        default="https://api.venafi.cloud",
        help="Regional API base URL (default: https://api.venafi.cloud).",
    )
    args = parser.parse_args()

    client = CcmClient(args.api_key, args.api_base_url)

    # 1. Resolve user
    print("[1/6] Resolving current user...")
    user_resp = client.json("GET", "/v1/useraccounts")
    user_id = user_resp["user"]["id"]
    print(f"      User: {user_resp['user']['username']} ({user_id})")

    # 2. Application
    print(f"[2/6] Ensuring application '{args.application_name}' exists...")
    app_id = ensure_application(client, args.application_name, user_id)

    # 3. Upload certificate
    print(f"[3/6] Uploading certificate from {args.pem_path}...")
    cert_b64 = extract_first_certificate_base64(args.pem_path)
    fingerprint = sha1_fingerprint(cert_b64)
    upload_body = {
        "certificates": [{"certificate": cert_b64, "applicationIds": [app_id]}]
    }
    uploaded = client.json("POST", "/outagedetection/v1/certificates", upload_body)
    infos = uploaded.get("certificateInformations") or []
    if infos:
        cert_id = infos[0]["id"]
        print(f"      Certificate id: {cert_id}  (fingerprint: {fingerprint})")
    elif uploaded.get("statistics", {}).get("existed", 0) > 0:
        cert_id = find_certificate_id_by_fingerprint(client, fingerprint)
        if not cert_id:
            raise RuntimeError(
                f"Upload reported existed=1 but fingerprint {fingerprint} not found via search"
            )
        print(f"      Certificate already existed; id: {cert_id}  (fingerprint: {fingerprint})")
    else:
        raise RuntimeError(f"Upload did not return a certificate id. Response: {uploaded}")

    # 4. Tag + value
    print(f"[4/6] Ensuring tag '{args.tag_name}' with value '{args.tag_value}' exists...")
    ensure_tag_and_value(client, args.tag_name, args.tag_value)

    # 5. Assign tag
    print(f"[5/6] Assigning '{args.tag_name}:{args.tag_value}' to certificate {cert_id}...")
    assign_body = {
        "action": "ADD",
        "entityIds": [cert_id],
        "entityType": "CERTIFICATE",
        "targetedTags": [f"{args.tag_name}:{args.tag_value}"],
    }
    assign = client.json("PATCH", "/v1/tagsassignment", assign_body)
    status = assign["tagsAssignInformation"][0]["status"]
    print(f"      Status: {status}")

    # 6. Download
    print(f"[6/6] Downloading certificate chain to {args.output_path}...")
    dl = client.request(
        "GET",
        f"/outagedetection/v1/certificates/{cert_id}/contents?format=PEM&chainOrder=ROOT_FIRST",
        accept="text/plain",
    )
    pem_text = dl.text
    with open(args.output_path, "w", encoding="utf-8", newline="") as f:
        f.write(pem_text)
    cert_count = len(re.findall(r"BEGIN CERTIFICATE", pem_text))
    print(f"      Saved {len(pem_text)} bytes, {cert_count} certificate(s) in chain")

    print()
    print("Done.")
    print(f"  Application : {args.application_name}  ({app_id})")
    print(f"  Certificate : {cert_id}")
    print(f"  Tag         : {args.tag_name}:{args.tag_value}")
    print(f"  Downloaded  : {args.output_path}")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, FileNotFoundError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
