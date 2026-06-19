# Bulk Certificate Issuance from a CSV — with private key (PEM + P12)

Give the tool a **CSV** of certificate subjects. It has **CyberArk Certificate Manager — SaaS**
issue each certificate, then downloads the certificate **and its private key** — packaged
ready to deploy.

By default:

- **CM SaaS generates the key** (central keygen) — you don't create CSRs.
- **Each certificate's files are bundled into a single `.zip`** (one per device).
- **Each gets its own random password**, saved to one file you hand out, then delete.

You can change any of this — see [Passwords](#passwords) and [Other modes](#other-modes).

| Script | Runtime | Central keygen | Local keygen |
|--------|---------|:--------------:|:------------:|
| `ccm_csv_cert_issue.py` | Python 3.8+ (`requests`, `cryptography`, `pynacl`) | ✅ (default) | ✅ |
| `Invoke-CcmCsvCertIssue.ps1` | PowerShell **7+** + `PSSodium` for central; 5.1 / 7+ for local | ✅ (default) | ✅ |

> Central keygen retrieves the service-generated key by sealing a passphrase against the
> tenant edge key (a libsodium "sealed box"). Python does this with `pynacl`; **PowerShell
> does it with the `PSSodium` module on PowerShell 7+** (the same approach VenafiPS uses).
> The script can install PSSodium for you with `-InstallDeps`. Local keygen needs neither.

---

## Quick start

1. **Make a CSV** — one row per certificate (only `CommonName` is required):

   ```csv
   CommonName,country,Locatlity,Organization,OrganizationUnit,State
   device001.example.com,US,Anytown,Example Corp,Devices,AZ
   device002.example.com,US,Anytown,Example Corp,Devices,AZ
   device003.example.com,US,Anytown,Example Corp,Devices,AZ
   ```
   (Sample: [`samples/device_sample_for_bulk_cert.csv`](samples/device_sample_for_bulk_cert.csv).)

2. **Run it** — central keygen is the default, and with no password flag each certificate gets
   its own random password:

   ```bash
   # Python
   python ccm_csv_cert_issue.py \
     --csv ./devices.csv \
     --api-key <YOUR_API_KEY> \
     --application-name "Example Devices" \
     --issuing-template "MSCA-1year" \
     --output-dir ./out
   ```

   ```powershell
   # PowerShell 7 (central keygen needs PSSodium; -InstallDeps grabs it automatically)
   pwsh ./Invoke-CcmCsvCertIssue.ps1 `
     -CsvPath ./devices.csv -ApiKey <YOUR_API_KEY> `
     -ApplicationName "Example Devices" -IssuingTemplate "MSCA-1year" `
     -OutputDir ./out -InstallDeps
   ```

3. **Collect the output** — one zip per device, plus an inventory and a password file:

   ```
   out/
     device001.example.com.zip      # the cert + key, in every common format
     device002.example.com.zip
     device003.example.com.zip
     results.csv                            # what was issued (NO passwords)
     GENERATED-PASSWORDS.csv                # one password per device — SECRET
   ```

   Each `<device>.zip` contains: `.crt.pem`, `.chain.pem`, `.fullchain.pem`, `.key.pem`,
   `.pem`, and `.p12` (see [Which file should I use?](#which-file-should-i-use)).

4. **Hand off the passwords safely.** `GENERATED-PASSWORDS.csv` is the *only* record of the
   random passwords. Deliver it over a secure channel, then **delete it**. `results.csv`
   contains no secrets and is safe to keep.

> The issuing template you choose must allow **Venafi-generated keys** for central keygen, and
> its subject rules must allow your common names. In the sandbox, `MSCA-1year` allows both
> (any CN). See [Choosing an application + template](#choosing-an-application--template).

---

## Prerequisites

- A CCM — SaaS **API key** (*Settings → API Keys* in the UI).
- An **application** and an **issuing template** (see below). If the application doesn't exist
  the tool creates it and links the template; if it exists, the template must already be linked.
- **Python:** `pip install requests cryptography pynacl`.
- **PowerShell:** local keygen needs nothing extra. **Central keygen needs PowerShell 7+ and
  the `PSSodium` module** — pass `-InstallDeps` to install it automatically (CurrentUser scope,
  no admin), or run `Install-Module PSSodium -Scope CurrentUser` yourself. On Windows, PSSodium
  also needs the Microsoft Visual C++ Runtime (present on most servers).

The tool validates the template against the chosen mode up front and stops with a clear message
if it can't support it (e.g. central keygen against a template that forbids Venafi-generated keys).

### Choosing an application + template

| You want… | Use a template that has… | Sandbox example |
|-----------|--------------------------|-----------------|
| **Central keygen** (CM SaaS makes the key) | **"Allow Venafi to generate the key"** enabled | `MSCA-1year` (any CN) |
| **Local keygen** (key made on the host) | **"Allow uploaded CSR"** enabled | Built-In `Default` (any CN) |

The certificate subjects in your CSV must also satisfy the template's subject rules (some
public-CA templates are restricted to specific domains).

---

## CSV format

Header names are matched **case-insensitively** and tolerate common variants — including the
sample file's `Locatlity` typo. Only `CommonName` is required.

| Field | Accepted header names |
|-------|------------------------|
| Common Name (required) | `CommonName`, `CN`, `Subject`, `FQDN`, `Hostname` |
| Country | `country`, `C`, `CountryName` |
| State / Province | `State`, `ST`, `Province`, `StateOrProvince` |
| Locality / City | `Locality`, **`Locatlity`**, `Location`, `City`, `L` |
| Organization | `Organization`, `Org`, `O` |
| Org. Unit | `OrganizationUnit`, `OrganizationalUnit`, `OU`, `Department` |
| Email | `Email`, `EmailAddress`, `E` |
| SAN(s) | any column starting with `San`, or `DnsNames` / `SubjectAlternativeName` |
| Password (optional) | `KeyPassword`, `Password`, `Passphrase`, `PfxPassword`, `P12Password`, `Pwd` |

The common name is automatically added as a DNS SAN. SAN columns may hold several values
separated by `,`, `;` or spaces; values that parse as IP addresses become IP SANs. The optional
password column is only one of several ways to set passwords — see [Passwords](#passwords).

---

## Output files (per certificate)

| File | Contents | Typical consumer |
|------|----------|------------------|
| `<name>.fullchain.pem` | leaf + chain, **no key** | nginx / Apache `ssl_certificate` |
| `<name>.key.pem`   | private key (encrypted unless `--decrypt-key`) | nginx / Apache `ssl_certificate_key` |
| `<name>.crt.pem`   | leaf certificate only | tools that want leaf + chain split |
| `<name>.chain.pem` | issuer chain (intermediates + root) | …the chain half of the above |
| `<name>.pem`       | combined: leaf + chain + **key** | HAProxy / appliances |
| `<name>.p12`       | PKCS#12 keystore (key + leaf + chain), password protected | IIS / Windows, Java / Tomcat |

Plus, in the output folder (not inside the per-cert zips):

| File | Contents |
|------|----------|
| `results.csv` | inventory: CN, status, **`keyGeneration`** (central/local), certificate id, serial, `passwordSource`, files, error — **no secrets** |
| `GENERATED-PASSWORDS.csv` | only written when random passwords were generated — CN + password — **secret** |

The `keyGeneration` column records, per certificate, whether the private key was generated
**centrally** (by CM SaaS) or **locally** (on this host) — so anyone reading the manifest knows
how each key was produced.

> **Packaging.** By default each certificate's files are delivered as one **`<name>.zip`** (one
> archive per device, plus the loose `results.csv` / `GENERATED-PASSWORDS.csv`). Pass
> `--no-zip` / `-NoZip` to write the individual files instead.

---

## Passwords

The same password protects a certificate's PEM private key and its `.p12`. There are four ways
to set it, resolved in this order:

| # | How | Behaviour |
|---|-----|-----------|
| 1 | `--prompt-password` / `-PromptPassword` | Prompt **once** and use that one password for **all** certificates. |
| 2 | `--key-password` / `-KeyPassword` (or `CCM_KEY_PASSWORD`) | One password for **all** certificates. |
| 3 | a **password column** in the CSV | Each row uses **its own** password; blank rows fall through to #4. |
| 4 | *(nothing supplied — the default)* | A **strong random** password is generated **per certificate**. |

### Where passwords are recorded

- **`results.csv` never contains a password** — only a `passwordSource` column: `random`,
  `csv`, `shared`, or `prompt`.
- Passwords you supplied yourself (`prompt` / `shared` / `csv`) are **not written anywhere** —
  you already have them.
- **Randomly-generated** passwords are the only ones saved (otherwise they'd be lost): they go
  to **`GENERATED-PASSWORDS.csv`** in the output folder — not inside the per-cert zips.

> **`GENERATED-PASSWORDS.csv` is a secret.** It is the only record of the random passwords —
> deliver it over a secure channel, then **delete it**. It is kept out of the zips and covered
> by `.gitignore`. Generated passwords are 20 characters from `A–Z a–z 0–9 ! @ # % - _ + =`.

If you'd rather control passwords yourself, add a password column
([`samples/device_sample_with_passwords.csv`](samples/device_sample_with_passwords.csv)) or
pass `--key-password` / `--prompt-password`.

### Unencrypted private key (`--decrypt-key`)

Some deployments (nginx, Apache, many appliances) want the **private key file without a
passphrase**. Pass `--decrypt-key` / `-DecryptKey` and the **`<name>.key.pem`** (and the key
inside the combined `<name>.pem`) is written **unencrypted** — no password needed to use it.

Important: this affects **only the PEM key file**. The **`.p12` always has a password**, because
PKCS#12 keystores require one. The `.p12` password follows the normal rules above — so if you use
`--decrypt-key` **without** also giving a password, each `.p12` gets a **random** password that is
recorded in `GENERATED-PASSWORDS.csv`. In other words:

| You ran… | `key.pem` | `.p12` password |
|----------|-----------|-----------------|
| `--decrypt-key` only | unencrypted | random, in `GENERATED-PASSWORDS.csv` |
| `--decrypt-key --key-password "X"` | unencrypted | `X` (one you chose) |
| *(neither)* | encrypted with the cert's password | same password |

If you only need the unencrypted PEM, you can simply ignore (or delete) the `.p12`.

> On **Windows PowerShell 5.1**, `-DecryptKey` has no effect — 5.1 cannot write a PEM key at
> all, so the key is only inside the `.p12`. Use **PowerShell 7+** or the Python tool to get an
> unencrypted `key.pem`.

---

## Which file should I use?

Both "separated" and "combined" PEM layouts are common — pick by what your target expects. The
tool writes all of them so you don't have to choose up front.

- **Separated** (certificate in one file, key in another) is the most common layout and the
  security best practice. nginx, Apache and Kubernetes work this way.
- **Combined** (leaf + chain + key in one file) is what a few products want — **HAProxy** is
  the classic example. Treat it like a key file.
- **"fullchain"** (leaf + chain in one file, leaf first) is what nginx/Apache expect for the
  certificate itself; the root is generally not required.
- **PKCS#12 (`.p12`)** is the single-file, password-protected keystore for **Windows (IIS/CAPI)**
  and **Java (Tomcat)**.

| Target | Use |
|--------|-----|
| **nginx** | `ssl_certificate` → `<name>.fullchain.pem`; `ssl_certificate_key` → `<name>.key.pem` |
| **Apache httpd** (2.4.8+) | `SSLCertificateFile` → `<name>.fullchain.pem`; `SSLCertificateKeyFile` → `<name>.key.pem` |
| **HAProxy** | one file: `<name>.pem` (leaf + chain + key) |
| **IIS / Windows** | import `<name>.p12` (see [`README-p12-capi-import.md`](README-p12-capi-import.md)) |
| **Java / Tomcat** | `<name>.p12` as a PKCS#12 keystore |
| **Kubernetes** TLS secret | `tls.crt` → `<name>.fullchain.pem`; `tls.key` → `<name>.key.pem` |

> **Security.** Three outputs contain the private key: `<name>.key.pem`, the combined
> `<name>.pem`, and `<name>.p12` (plus `GENERATED-PASSWORDS.csv`, which holds the passwords).
> Protect those. `<name>.crt.pem`, `<name>.chain.pem` and `<name>.fullchain.pem` are public.

---

## Other modes

### Local keygen (key made on the host, CSR uploaded)

Use when the key must never leave the machine, or with a template that only allows uploaded
CSRs (e.g. Built-In `Default`).

```bash
# Python
python ccm_csv_cert_issue.py --keygen local \
  --csv ./devices.csv --api-key <YOUR_API_KEY> \
  --application-name "Example Devices" --issuing-template "Default" --output-dir ./out
```

```powershell
# PowerShell — pass -KeyGen local (the default is central). Local keygen needs no PSSodium.
# PS 7 gives full PEM + P12; Windows PowerShell 5.1 gives P12 + cert/chain PEM (no .key.pem).
pwsh ./Invoke-CcmCsvCertIssue.ps1 -KeyGen local `
  -CsvPath ./devices.csv -ApiKey <YOUR_API_KEY> `
  -ApplicationName "Example Devices" -IssuingTemplate "Default" -OutputDir ./out -KeyPassword "ChangeMe123!"
```

> **PowerShell 5.1 note (local keygen).** .NET Framework can't export a private key to PEM, so
> on 5.1 the key is delivered **only inside the `.p12`**. Use PowerShell 7+ for a standalone
> `.key.pem`. (Central keygen is PowerShell 7+ only anyway.) Wildcard CNs become `_` in names.

### Common options

| Python | PowerShell | Description |
|--------|------------|-------------|
| `--keygen central\|local` | `-KeyGen central\|local` | Key generation mode. **Both default to `central`.** |
| *(n/a)* | `-InstallDeps` | For central keygen, auto-install the `PSSodium` module if missing (PowerShell). |
| `--key-password` | `-KeyPassword` | One shared password for all certs (else CSV column or random). |
| `--prompt-password` | `-PromptPassword` | Prompt once and use that one password for all certs. |
| `--decrypt-key` | `-DecryptKey` | Write the PEM key unencrypted; the `.p12` still gets a password (random if none given) — see [Unencrypted private key](#unencrypted-private-key---decrypt-key). |
| `--key-size N` | `-KeySize N` | RSA key size (default 2048). |
| `--validity P90D` | `-Validity P90D` | Optional ISO-8601 validity period. |
| `--no-zip` | `-NoZip` | Write loose files instead of one `<name>.zip` per certificate. |
| `--api-base-url URL` | `-ApiBaseUrl URL` | Regional endpoint (default `https://api.venafi.cloud`). |

The API key and a shared key password can also come from the `CCM_API_KEY` and
`CCM_KEY_PASSWORD` environment variables instead of `--api-key`/`-ApiKey` and
`--key-password`/`-KeyPassword` (so the key never appears on the command line):

```powershell
# PowerShell — set for the current session, then run without -ApiKey/-KeyPassword
$env:CCM_API_KEY      = "<YOUR_API_KEY>"
$env:CCM_KEY_PASSWORD = "ChangeMe123!"   # optional; omit to get a random password per cert
pwsh ./Invoke-CcmCsvCertIssue.ps1 -CsvPath ./devices.csv `
  -ApplicationName "Example Devices" -IssuingTemplate "MSCA-1year" -OutputDir ./out -InstallDeps
```

```bash
# Bash
export CCM_API_KEY="<YOUR_API_KEY>"
export CCM_KEY_PASSWORD="ChangeMe123!"   # optional; omit to get a random password per cert
python ccm_csv_cert_issue.py --csv ./devices.csv \
  --application-name "Example Devices" --issuing-template "MSCA-1year" --output-dir ./out
```

A command-line value (`--api-key` / `--key-password`) takes precedence over the
environment variable if both are set.

---

## Verifying the output

```bash
# List the P12 bags and confirm the chain (use the device's password)
openssl pkcs12 -in out/device001.example.com.p12 -info -nokeys -passin pass:<password>

# Confirm the private key matches the certificate (the two hashes must be identical)
openssl pkcs12 -in out/<name>.p12 -nocerts -nodes -passin pass:<password> | openssl rsa  -noout -modulus | openssl md5
openssl pkcs12 -in out/<name>.p12 -clcerts -nokeys -passin pass:<password> | openssl x509 -noout -modulus | openssl md5
```

To import the `.p12` into the **Windows certificate store (CAPI)** and confirm the key works
there, see **[`README-p12-capi-import.md`](README-p12-capi-import.md)**.

---

## API calls under the hood

| Step | Method + path |
|------|---------------|
| Resolve user (application owner) | `GET /v1/useraccounts` |
| Resolve issuing template by name | `GET /v1/certificateissuingtemplates` |
| Find / create application | `GET /outagedetection/v1/applications/name/{name}` → `POST /outagedetection/v1/applications` |
| Submit request — **central** | `POST /outagedetection/v1/certificaterequests` (`isVaaSGenerated:true`, `csrAttributes`) |
| Submit request — **local** | `POST /outagedetection/v1/certificaterequests` (`certificateSigningRequest`) |
| Poll request | `GET /outagedetection/v1/certificaterequests/{id}` until `status = ISSUED` |
| Retrieve key — **central** | `GET /outagedetection/v1/certificates/{id}` (for `dekHash`) → `GET /v1/edgeencryptionkeys/{dekHash}` → `POST /outagedetection/v1/certificates/{id}/keystore` (passphrases sealed with libsodium) |
| Download chain — **local** | `GET /outagedetection/v1/certificates/{id}/contents?format=PEM&chainOrder=EE_FIRST` |

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `Template '…' does not allow Venafi-generated keys` | Central keygen against a template that forbids it (e.g. Built-In `Default`). | Use a template with "Allow Venafi to generate the key" (e.g. `MSCA-1year`), or `--keygen local`. |
| `HTTP 400 ... Driver generated csr is not allowed` | Same as above, reported by the API. | Same fix. |
| `--keygen central needs the 'pynacl' package` | Python: `pynacl` not installed. | `pip install pynacl`. |
| `Central keygen ... requires PowerShell 7+` | Ran PowerShell central keygen on 5.1. | Run with `pwsh` (PowerShell 7+), or use `-KeyGen local`. |
| `Central keygen needs the PSSodium module` | PowerShell: PSSodium not installed. | Re-run with `-InstallDeps`, or `Install-Module PSSodium -Scope CurrentUser`. |
| `PSSodium failed to load … Visual C++ Runtime` | PowerShell: native libsodium can't load. | Install the latest Microsoft Visual C++ Runtime, then retry. |
| `HTTP 400` about the subject / `subjectCNRegexes` | The CN doesn't match the template's allowed subjects. | Use a template whose domain rules match your CSV. |
| `Application '…' exists but is not linked to template '…'` | The app exists without that template. | Link it in the UI, or pass a different application name so the tool creates one. |
| PowerShell: no `.key.pem` produced | Local keygen under Windows PowerShell 5.1. | Use PowerShell 7+, or take the key from the `.p12`. |
| `HTTP 401` on the first call | Wrong API key or region. | Check the key and set the correct `--api-base-url`. |
