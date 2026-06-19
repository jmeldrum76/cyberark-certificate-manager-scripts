# Importing & Verifying the P12 in the Windows Certificate Store (CAPI)

After issuing certificates with the bulk workflow
([`README-csv-issuance.md`](README-csv-issuance.md)), each `<name>.p12` is a complete,
password-protected PKCS#12 keystore containing the **private key**, the **leaf
certificate**, and the **issuer chain**. This guide shows how to import that `.p12`
into the Windows certificate store (CAPI/CNG) and **prove the private key actually
works** — not just that the file is structurally valid.

> This was tested end-to-end against a Windows Server 2019 box. See
> [Proven test results](#proven-test-results) below for the exact output.

## Which store?

| Store | Path | Use when | Admin needed |
|-------|------|----------|--------------|
| Current user | `Cert:\CurrentUser\My` | the cert is for an app running as your user | No |
| Local machine | `Cert:\LocalMachine\My` | the cert is for a service/IIS/whole-machine use | Yes (elevated) |

## Method 1 — PowerShell (`Import-PfxCertificate`)

```powershell
# Password the .p12 was created with (the -KeyPassword you passed to the issuance script)
$pw = ConvertTo-SecureString 'ChangeMe123!' -AsPlainText -Force

# Import into the LocalMachine store (run PowerShell as Administrator), key marked exportable
$imp = Import-PfxCertificate -FilePath 'C:\out\device001.example.com.p12' `
        -CertStoreLocation Cert:\LocalMachine\My -Password $pw -Exportable

$imp.Thumbprint        # the imported certificate's thumbprint
```

For a non-elevated, per-user import, use `-CertStoreLocation Cert:\CurrentUser\My`
instead (no admin required).

## Method 2 — GUI

1. Double-click the `.p12` file → **Certificate Import Wizard**.
2. Choose **Current User** or **Local Machine** (Local Machine prompts for elevation).
3. Enter the password. Tick **Mark this key as exportable** if you may need to
   re-export the key later.
4. Let Windows **automatically select the store**, or place it in **Personal**.

You can also open the machine store directly with `certlm.msc` (Local Machine) or the
user store with `certmgr.msc`, then **Personal → Certificates → All Tasks → Import**.

## Verifying the private key actually works

Importing succeeds even for a cert with no usable key, so verify properly. The check
that matters is a **sign/verify roundtrip through the CAPI key handle** — if that
passes, Windows can really use the key.

```powershell
$cert = Get-Item ("Cert:\LocalMachine\My\" + $imp.Thumbprint)

"Subject        = $($cert.Subject)"
"HasPrivateKey  = $($cert.HasPrivateKey)"           # must be True

# Use the private key via CAPI/CNG to sign, then verify with the public key
$rsaPriv = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
$rsaPub  = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
$data = [Text.Encoding]::UTF8.GetBytes('capi-roundtrip-test')
$sig  = $rsaPriv.SignData($data, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
"KeyProvider    = $($rsaPriv.GetType().Name)"       # RSACng / RSACryptoServiceProvider
"SignVerify_OK  = $($rsaPub.VerifyData($data, $sig, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1))"   # must be True
```

Check that the full chain is present in the keystore:

```powershell
$chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
$chain.ChainPolicy.RevocationMode = 'NoCheck'
"ChainBuilt     = $($chain.Build($cert))"
"ChainElements  = $($chain.ChainElements.Count)"    # leaf + intermediate(s) + root
"ChainStatus    = $((($chain.ChainStatus | ForEach-Object { $_.Status }) -join ', '))"
```

## "UntrustedRoot" is expected for the Built-In CA

If `ChainStatus` shows `UntrustedRoot`, that is **not** a problem with the `.p12`.
It means the issuing CA's root (e.g. *CyberArk CM SaaS Built-In CA*) isn't in the
machine's **Trusted Root Certification Authorities** store. The full chain is already
inside the `.p12`; the machine just doesn't trust that private root yet.

To make the chain validate, import the root (and intermediate) once per machine. The
`<name>.chain.pem` file produced by the issuance workflow contains them:

```powershell
# Import every CA cert from the chain file into Trusted Roots (elevated).
# (Strictly, only the self-signed root belongs in Root; intermediates go in CA.)
Import-Certificate -FilePath 'C:\out\device001.example.com.chain.pem' `
    -CertStoreLocation Cert:\LocalMachine\Root
```

After trusting the root, re-run the chain build above and `ChainBuilt` becomes `True`
with an empty `ChainStatus`.

## Proven test results

A freshly issued `.p12` was imported into `Cert:\LocalMachine\My` on Windows Server
2019 and exercised:

| Check | Result |
|-------|--------|
| `p12_exists` | `True` |
| Imported thumbprint | `AA3238647D3F2BBA180629D5F59003E8695B1077` |
| Subject | `CN=device001.example.com, O=Example Corp, OU=Devices, L=Anytown, S=AZ, C=US` |
| Issuer | `CN=CyberArk CM SaaS Built-In Intermediate CA - G1, OU=Built-in, O=CyberArk Software Ltd., C=IL` |
| `HasPrivateKey` | `True` |
| Key provider | `RSACng` (key stored in the Windows CNG/CAPI key store) |
| **CAPI sign/verify roundtrip** | **`True`** |
| Chain elements in the keystore | `3` (leaf + intermediate + root) |
| Chain status | `UntrustedRoot` (root not in Trusted Roots — expected for a private CA) |

The sign/verify roundtrip passing is the definitive proof: Windows imported the key
into CAPI and can actually use it to sign.

## Removing the certificate (cleanup)

```powershell
Remove-Item ("Cert:\LocalMachine\My\" + $imp.Thumbprint) -Force
# or, by subject:
Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -match 'example' | Remove-Item
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `The specified network password is not correct` on import | Wrong `.p12` password. | Use the exact `-KeyPassword` the issuance script used. |
| `Access is denied` importing to `LocalMachine` | Not elevated. | Run PowerShell as Administrator, or import to `CurrentUser\My`. |
| `HasPrivateKey = False` after import | Imported a cert-only file, or the key didn't attach. | Re-import the `.p12` (not the `.crt.pem`); ensure the file is the keystore. |
| `ChainStatus = UntrustedRoot` | The private CA root isn't trusted on this machine. | Import the root from `<name>.chain.pem` into Trusted Roots (see above). |
| Need to re-export the key later | Imported without `-Exportable`. | Re-import with `-Exportable` (PowerShell) or tick *Mark key as exportable* (GUI). |
