# CyberArk Certificate Manager — Upload / Tag / Download Workflow

Two equivalent scripts — one in **PowerShell**, one in **Python 3** — that run the same end-to-end flow against the *CyberArk Certificate Manager — SaaS* REST API at `https://api.venafi.cloud`:

1. Resolve the current user (used as the application owner).
2. Create the application, or reuse it if one with the same name already exists.
3. Extract the end-entity certificate from the supplied PEM and upload it, associating it with the application.
4. Create the tag and tag value (or reuse them if they exist), then assign `TagName:TagValue` to the uploaded certificate.
5. Download the certificate chain back to the path you specify.

Both scripts are idempotent — re-running them against the same inputs leaves the tenant in the same end state.

## Files

| File | Description |
|------|-------------|
| `Invoke-CcmCertWorkflow.ps1` | PowerShell 5.1 or PowerShell 7+ script. |
| `ccm_cert_workflow.py` | Python 3.8+ script (depends on the `requests` library). |
| `README.md` | This file. |
| `README.html` | Same content as this file, rendered as a standalone HTML page. |

## Prerequisites

- An API key for your CyberArk Certificate Manager — SaaS tenant (*Configuration → API Keys* in the UI).
- Network reachability to the regional API endpoint (default `https://api.venafi.cloud`; use `-ApiBaseUrl` / `--api-base-url` for EU, AU, UK, SG, CA).
- A PEM file containing at least the end-entity ("leaf") certificate. A full chain or a PEM that also contains a private key is fine — only the first `-----BEGIN CERTIFICATE-----` block is uploaded.
- **PowerShell:** Windows PowerShell 5.1 or PowerShell 7+. No extra modules required.
- **Python:** Python 3.8+ with the `requests` library (`pip install requests`).

## Parameters

| PowerShell | Python | Required | Description |
|------------|--------|----------|-------------|
| `-PemPath` | `--pem-path` | Yes | Path to the PEM file. If it contains multiple certificates, only the first block is uploaded. |
| `-ApiKey` | `--api-key` | Yes | CyberArk Certificate Manager SaaS API key. Sent as the `tppl-api-key` header. |
| `-ApplicationName` | `--application-name` | Yes | Application to create, or to reuse if it already exists. |
| `-TagName` | `--tag-name` | Yes | Tag name (e.g. `Service Now`). Reused if it already exists. |
| `-TagValue` | `--tag-value` | Yes | Tag value (e.g. a ServiceNow ticket number). Reused if it already exists on the tag. |
| `-OutputPath` | `--output-path` | Yes | Where to save the downloaded PEM (certificate chain, root first). |
| `-ApiBaseUrl` | `--api-base-url` | No | Regional base URL. Defaults to `https://api.venafi.cloud`. |

## Usage

### PowerShell

```powershell
.\Invoke-CcmCertWorkflow.ps1 `
  -PemPath .\mycert.pem `
  -ApiKey <YOUR_API_KEY> `
  -ApplicationName "Billing App" `
  -TagName "Service Now" `
  -TagValue INC0012345 `
  -OutputPath .\mycert-downloaded.pem
```

If your environment blocks unsigned scripts, bypass the execution policy for one invocation:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-CcmCertWorkflow.ps1 -PemPath .\mycert.pem ...
```

### Python

```bash
python ccm_cert_workflow.py \
  --pem-path ./mycert.pem \
  --api-key <YOUR_API_KEY> \
  --application-name "Billing App" \
  --tag-name "Service Now" \
  --tag-value INC0012345 \
  --output-path ./mycert-downloaded.pem
```

### Example output

```
[1/6] Resolving current user...
      User: user@example.com (e6a97930-3e53-11f1-873d-551f3f70f949)
[2/6] Ensuring application 'Billing App' exists...
      Created application id: 18843050-4000-11f1-aadd-6510565d75b3
[3/6] Uploading certificate from ./mycert.pem...
      Certificate id: 5786acd0-3ff4-11f1-a4df-a5ca8bcb08da  (fingerprint: DF80...3E1B)
[4/6] Ensuring tag 'Service Now' with value 'INC0012345' exists...
      Created tag id: b8dcc5d0-4000-11f1-911d-739defcc3b48
      Added value 'INC0012345'
[5/6] Assigning 'Service Now:INC0012345' to certificate 5786acd0-3ff4-11f1-a4df-a5ca8bcb08da...
      Status: ASSIGNED
[6/6] Downloading certificate chain to ./mycert-downloaded.pem...
      Saved 5461 bytes, 3 certificate(s) in chain

Done.
  Application : Billing App  (18843050-4000-11f1-aadd-6510565d75b3)
  Certificate : 5786acd0-3ff4-11f1-a4df-a5ca8bcb08da
  Tag         : Service Now:INC0012345
  Downloaded  : ./mycert-downloaded.pem
```

## API calls under the hood

| Step | Method + path | Notes |
|------|---------------|-------|
| 1. Resolve user | `GET /v1/useraccounts` | Supplies the `ownerId` for the application. |
| 2a. Find application | `GET /outagedetection/v1/applications/name/{name}` | Reused if it returns 200; on 404 we fall through to create. |
| 2b. Create application | `POST /outagedetection/v1/applications` | Body: `{ name, ownerIdsAndTypes }`. |
| 3. Upload certificate | `POST /outagedetection/v1/certificates` | Body: `{ certificates: [{ certificate, applicationIds }] }`. If the cert already exists (`statistics.existed > 0`), the script looks it up via `POST /outagedetection/v1/certificatesearch` filtered on the SHA-1 fingerprint it computed locally. |
| 4a. Get or create tag | `GET /v1/tags/{name}` → fallback `POST /v1/tags` | Body on create: `{ name, values: [value] }`. |
| 4b. Ensure tag value | `GET /v1/tags/{name}/values` → fallback `POST /v1/tags/{name}/values` | Body on create: `{ values: [value] }`. |
| 5. Assign tag to cert | `PATCH /v1/tagsassignment` | Body: `{ action: "ADD", entityIds: [certId], entityType: "CERTIFICATE", targetedTags: ["Name:Value"] }`. Note that `targetedTags` uses the `TagName:TagValue` string form, not UUIDs. |
| 6. Download chain | `GET /outagedetection/v1/certificates/{id}/contents?format=PEM&chainOrder=ROOT_FIRST` | Header: `accept: text/plain`. |

## Notes and caveats

> **Only the public certificate is uploaded.** If the PEM contains a private key, the key is *ignored* — the simple `/outagedetection/v1/certificates` endpoint accepts only the public certificate. Uploading a key would require the PKCS#8 / PKCS#12 import endpoint, which encrypts the key with NaCl/libsodium against the tenant's edge-instance public key. That flow is intentionally not implemented here.

> **Certificate ordering in the input PEM.** The script uses the first `-----BEGIN CERTIFICATE-----` block it finds. For standard files (`cert.pem`, `fullchain.pem`) the end-entity cert is first, so this is correct. However — note that the *downloaded* file uses `ROOT_FIRST` ordering. If you feed a previously downloaded file back into the script, the first block will be the root CA, the upload will store the root, and the download call will fail because roots have no issuer chain in the service. Use the original `cert.pem` / `fullchain.pem` — not a `ROOT_FIRST` round-trip — as the input.

> **Regional endpoints.** For tenants outside US-default, pass `-ApiBaseUrl` (PowerShell) or `--api-base-url` (Python) with the correct regional URL, e.g. `https://api.venafi.eu` or `https://api.au.venafi.cloud`.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `HTTP 401` on the first call | Invalid or expired API key, or wrong regional endpoint. | Confirm the key in the CCM UI (*Configuration → API Keys*) and make sure the base URL matches your tenant's region. |
| Script cannot be loaded / not digitally signed | PowerShell execution policy blocks unsigned scripts. | Run with `powershell.exe -ExecutionPolicy Bypass -File .\Invoke-CcmCertWorkflow.ps1 ...`, or run `Unblock-File .\Invoke-CcmCertWorkflow.ps1` then `Set-ExecutionPolicy -Scope Process RemoteSigned`. |
| `Upload reported existed=1 but fingerprint ... not found via search` | The certificate was imported previously but retired/hidden so it doesn't surface in the default search view. | Check *Inventory → Certificates* with *Include retired* enabled, or use a different copy of the cert. |
| `HTTP 400 ... Issuer certificates not available` during download (step 6) | The cert you uploaded is a root or an unknown intermediate — the service can't build a chain. | Make sure the PEM's first block is the end-entity cert, not a root/intermediate. |
