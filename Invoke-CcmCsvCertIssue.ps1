<#
.SYNOPSIS
    Bulk-issue certificates from a CSV against CyberArk Certificate Manager - SaaS,
    and download each one *with its private key* in PEM and PKCS#12 (.p12) form.

    Supports CENTRAL key generation (CM SaaS makes the key - the default) and LOCAL key
    generation (the key is made on this host and a CSR is uploaded). Central keygen needs
    PowerShell 7+ and the PSSodium module (it retrieves the service-generated key via a
    libsodium sealed box, exactly like VenafiPS). See -KeyGen and -InstallDeps.

.DESCRIPTION
    For every row in the CSV the script:

      1. CENTRAL keygen: asks CM SaaS to generate the key + cert, then retrieves the key
         by sealing a passphrase against the tenant edge key (PSSodium).
         LOCAL keygen: generates an RSA key pair on this host and uploads a CSR.
      2. Submits the request to a CCM SaaS application + issuing template
         (POST /outagedetection/v1/certificaterequests).
      3. Polls the request until the certificate is ISSUED.
      4. Retrieves the certificate + private key.
      5. Writes, per certificate, into the output directory:
            <name>.key.pem        private key (encrypted unless -DecryptKey)   [PowerShell 7+ only]
            <name>.crt.pem        leaf certificate only
            <name>.chain.pem      issuer chain (intermediates + root), if any
            <name>.fullchain.pem  leaf + chain, no key (nginx/Apache "ssl_certificate")
            <name>.pem            combined: leaf + chain + private key         [PowerShell 7+ only]
            <name>.p12            PKCS#12 keystore (key + leaf + chain), password protected
         By default each certificate's files are bundled into <name>.zip (-NoZip for loose
         files); results.csv is always written un-zipped.

    PowerShell version behaviour (detected up front):
      * CENTRAL keygen -> requires PowerShell 7+ and PSSodium (auto-installable with
                          -InstallDeps). The template must allow Venafi-generated keys.
      * LOCAL keygen, PowerShell 7+  -> produces all files (PEM private key + .p12).
      * LOCAL keygen, PowerShell 5.1 -> .NET Framework cannot export a private key to
                          PEM, so the key is delivered ONLY inside the password-protected
                          .p12; the cert and chain are still written as PEM.
      * Below 5.1      -> the script stops with a clear error.

.PARAMETER CsvPath
    Path to the input CSV. Header names are matched case-insensitively and tolerate
    common variants (e.g. CommonName/CN, Locatlity/Locality, OrganizationUnit/OU).
    Any column whose name starts with "San" (or "DnsNames") is treated as a SAN.

.PARAMETER ApiKey
    CCM SaaS API key. Sent as the "tppl-api-key" header. If omitted, the script reads
    the CCM_API_KEY environment variable.

.PARAMETER ApplicationName
    Application to use. Created (and linked to the issuing template) if it does not exist.

.PARAMETER IssuingTemplate
    Issuing template name to use (e.g. "Default").

.PARAMETER OutputDir
    Directory for the generated files (created if missing).

.PARAMETER KeyPassword
    Use ONE password for every certificate's PEM key and .p12 (or set CCM_KEY_PASSWORD).
    If neither this nor -PromptPassword is given, each certificate uses its CSV password
    column (KeyPassword / Password / Passphrase / ...) when present, otherwise a strong
    random password is generated for that certificate. Every password used is written to
    results.csv (shown as "<shared>" when a single shared password was supplied), so
    protect that file (it is in .gitignore).

.PARAMETER PromptPassword
    Prompt once (hidden input) for a password and use it for ALL certificates. Overrides
    any CSV password column.

.PARAMETER DecryptKey
    Write the PEM private key unencrypted (PowerShell 7+). The .p12 is still password
    protected. Ignored on PowerShell 5.1 (no PEM key is produced there).

.PARAMETER KeySize
    RSA key size. Default 2048.

.PARAMETER Validity
    Optional validity period, ISO-8601 (e.g. P90D).

.PARAMETER NoZip
    Write loose files instead of bundling each certificate's files into <name>.zip.
    By default the script zips each certificate into its own <name>.zip (results.csv is
    always left un-zipped).

.PARAMETER KeyGen
    'central' (default) - CM SaaS generates the key and certificate; the key is retrieved
    via the tenant edge key (needs PowerShell 7+ and PSSodium, and a template that allows
    Venafi-generated keys). 'local' - generate the key on this host and upload a CSR.

.PARAMETER InstallDeps
    For central keygen, auto-install the PSSodium module from the PSGallery if it is missing
    (otherwise the script tells you how to install it). Run-as-admin not required
    (installs to CurrentUser scope).

.PARAMETER ApiBaseUrl
    Regional API base URL. Default https://api.venafi.cloud.

.EXAMPLE
    # Central keygen (default) - PowerShell 7 + PSSodium (auto-install with -InstallDeps)
    pwsh ./Invoke-CcmCsvCertIssue.ps1 -CsvPath ./devices.csv -ApiKey <YOUR_API_KEY> `
        -ApplicationName "Example Devices" -IssuingTemplate "MSCA-1year" `
        -OutputDir ./out -InstallDeps

.EXAMPLE
    # Local keygen
    pwsh ./Invoke-CcmCsvCertIssue.ps1 -CsvPath ./devices.csv -ApiKey <YOUR_API_KEY> `
        -KeyGen local -ApplicationName "Example Devices" -IssuingTemplate "Default" `
        -OutputDir ./out -KeyPassword "ChangeMe123!"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $CsvPath,
    [string] $ApiKey,
    [Parameter(Mandatory)] [string] $ApplicationName,
    [Parameter(Mandatory)] [string] $IssuingTemplate,
    [Parameter(Mandatory)] [string] $OutputDir,
    [string] $KeyPassword,
    [switch] $PromptPassword,
    [switch] $DecryptKey,
    [int] $KeySize = 2048,
    [string] $Validity,
    [switch] $NoZip,
    [switch] $ZipPerCert,   # back-compat no-op; per-cert zipping is the default
    [int] $PollTimeoutSec = 180,
    [int] $PollIntervalSec = 3,
    [ValidateSet('local','central')] [string] $KeyGen = 'central',
    [switch] $InstallDeps,
    [string] $ApiBaseUrl = 'https://api.venafi.cloud'
)

$ErrorActionPreference = 'Stop'

# CENTRAL key generation (CM SaaS makes the key and we retrieve it) needs a libsodium
# "sealed box" to encrypt the key passphrase against the tenant edge key. .NET has no
# native sealed box, so - exactly like VenafiPS - we use the PSSodium module (native
# libsodium), which requires PowerShell 7+. The prerequisites are checked below, and
# PSSodium can be auto-installed with -InstallDeps. LOCAL keygen needs none of this.

# --- PowerShell version detection (done up front, before any issuance) -------
$psVer = $PSVersionTable.PSVersion
if ($psVer.Major -lt 5 -or ($psVer.Major -eq 5 -and $psVer.Minor -lt 1)) {
    throw "This script requires Windows PowerShell 5.1+ or PowerShell 7+. Detected $psVer."
}
$script:CanExportPemKey = ($psVer.Major -ge 7)
Write-Host "PowerShell $psVer detected." -ForegroundColor Cyan
if ($script:CanExportPemKey) {
    Write-Host "  Mode: full output (PEM private key + certificate/chain PEM + .p12)." -ForegroundColor Cyan
} else {
    Write-Host "  Mode: P12 + certificate/chain PEM. The private key is delivered ONLY inside" -ForegroundColor Yellow
    Write-Host "        the password-protected .p12 (PEM private-key export needs PowerShell 7+)." -ForegroundColor Yellow
    if ($DecryptKey) { Write-Host "  -DecryptKey is ignored on Windows PowerShell 5.1 (no PEM key is written)." -ForegroundColor Yellow }
}

# --- Central keygen prerequisites (PowerShell 7 + PSSodium), checked up front ----
function Initialize-CentralKeygenDeps {
    param([bool] $AutoInstall)
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        throw "Central key generation (-KeyGen central) requires PowerShell 7+ (the PSSodium module does not load on Windows PowerShell 5.1). Detected $($PSVersionTable.PSVersion). Re-run with pwsh, or use -KeyGen local."
    }
    if (-not (Get-Module PSSodium -ListAvailable)) {
        $install = $AutoInstall
        if (-not $install -and [Environment]::UserInteractive) {
            $ans = Read-Host "Central keygen needs the PSSodium module (libsodium), which isn't installed. Install it now from the PSGallery? [Y/N]"
            $install = ($ans -match '^(y|yes)$')
        }
        if (-not $install) {
            throw "Central keygen needs the PSSodium module. Install it with 'Install-Module PSSodium -Scope CurrentUser', or re-run with -InstallDeps."
        }
        Write-Host "Installing PSSodium from the PSGallery..." -ForegroundColor Cyan
        try { Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force -ErrorAction Stop | Out-Null } catch {}
        Install-Module PSSodium -Scope CurrentUser -Force -AllowClobber
    }
    try { Import-Module PSSodium -Force -ErrorAction Stop }
    catch { throw "PSSodium failed to load. Ensure PowerShell 7+ and (on Windows) the latest Visual C++ Runtime are installed. $_" }
    if (-not (Get-Command ConvertTo-SodiumEncryptedString -ErrorAction SilentlyContinue)) {
        throw "PSSodium loaded but ConvertTo-SodiumEncryptedString is unavailable - check the PSSodium installation."
    }
    Write-Host "  Central keygen: PowerShell 7 + PSSodium ready." -ForegroundColor Cyan
}
if ($KeyGen -eq 'central') { Initialize-CentralKeygenDeps -AutoInstall:$InstallDeps.IsPresent }

if (-not $ApiKey) { $ApiKey = $env:CCM_API_KEY }
if (-not $ApiKey) { throw "API key required: pass -ApiKey or set CCM_API_KEY." }

# Password resolution. A "shared" password (prompt / param / env) is used for every
# cert. Otherwise each row uses its CSV password column, or a generated random one.
$script:SharedPassword = $null
$script:PasswordMode = $null   # 'prompt' | 'shared' | $null (per-cert)
if ($PromptPassword) {
    $sec = Read-Host -AsSecureString "Password for ALL certificate keys/.p12"
    $script:SharedPassword = [System.Net.NetworkCredential]::new('', $sec).Password
    if (-not $script:SharedPassword) { throw "-PromptPassword: empty password entered." }
    $script:PasswordMode = 'prompt'
} elseif ($KeyPassword) {
    $script:SharedPassword = $KeyPassword; $script:PasswordMode = 'shared'
} elseif ($env:CCM_KEY_PASSWORD) {
    $script:SharedPassword = $env:CCM_KEY_PASSWORD; $script:PasswordMode = 'shared'
}
if ($script:SharedPassword) {
    Write-Host "  Password mode: one shared password for all certificates" -ForegroundColor Cyan
} else {
    Write-Host "  Password mode: per-cert (CSV column if present, else generated random)" -ForegroundColor Cyan
}

function New-RandomPassword([int]$Length = 20) {
    $alphabet = [char[]]('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#%-_+=')
    $bytes = New-Object 'byte[]' $Length
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    -join ($bytes | ForEach-Object { $alphabet[$_ % $alphabet.Length] })
}

$ApiBaseUrl = $ApiBaseUrl.TrimEnd('/')
$headers = @{ 'tppl-api-key' = $ApiKey; 'Content-Type' = 'application/json' }

function Invoke-CcmApi {
    param([string] $Method, [string] $Path, [object] $Body, [string] $Accept = 'application/json')
    $h = $headers.Clone(); $h['accept'] = $Accept
    $params = @{ Method = $Method; Uri = "$ApiBaseUrl$Path"; Headers = $h }
    if ($null -ne $Body) { $params.Body = ($Body | ConvertTo-Json -Depth 10 -Compress) }
    try { return Invoke-RestMethod @params }
    catch {
        $status = 0; $respBody = ''
        if ($_.Exception.Response) {
            try { $status = [int]$_.Exception.Response.StatusCode } catch {}
            try {
                $s = $_.Exception.Response.GetResponseStream(); $s.Position = 0
                $respBody = (New-Object System.IO.StreamReader($s)).ReadToEnd()
            } catch {}
        }
        if (-not $respBody) { $respBody = $_.ErrorDetails.Message }
        throw "HTTP $status on $Method $Path : $respBody"
    }
}

# --- PEM helpers that work on both Windows PowerShell 5.1 and PowerShell 7 ---
function ConvertTo-Pem([string] $Label, [byte[]] $Der) {
    $b64 = [Convert]::ToBase64String($Der, [Base64FormattingOptions]::InsertLineBreaks)
    return "-----BEGIN $Label-----`n$b64`n-----END $Label-----`n"
}

function Get-CertsFromPem([string] $Pem) {
    $coll = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    foreach ($m in [regex]::Matches($Pem, '(?s)-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----')) {
        $der = [Convert]::FromBase64String(($m.Groups[1].Value -replace '\s',''))
        $coll.Add([System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$der)) | Out-Null
    }
    return $coll
}

# --- CSV header mapping -----------------------------------------------------
$HeaderAliases = @{
    'commonname'='cn'; 'cn'='cn'; 'subject'='cn'; 'fqdn'='cn'; 'hostname'='cn'
    'country'='c'; 'c'='c'; 'countryname'='c'
    'state'='st'; 'st'='st'; 'province'='st'; 'stateorprovince'='st'; 'stateprovince'='st'
    'locality'='l'; 'locatlity'='l'; 'location'='l'; 'city'='l'; 'l'='l'
    'organization'='o'; 'organisation'='o'; 'org'='o'; 'o'='o'
    'organizationunit'='ou'; 'organizationalunit'='ou'; 'organisationunit'='ou'; 'orgunit'='ou'; 'ou'='ou'; 'department'='ou'
    'email'='email'; 'emailaddress'='email'; 'e'='email'
}
function Get-NormHeader([string]$h) { ($h -replace '[^a-z0-9]','').ToLower() }
$PasswordHeaders = @('keypassword','password','pfxpassword','p12password','passphrase','keypass','pwd')

function Read-CsvRows([string]$path) {
    $rows = Import-Csv -Path $path
    if (-not $rows) { throw "CSV $path is empty or has no data rows." }
    $cols = $rows[0].PSObject.Properties.Name
    $colRole = @{}
    foreach ($c in $cols) {
        $n = Get-NormHeader $c
        if ($HeaderAliases.ContainsKey($n)) { $colRole[$c] = $HeaderAliases[$n] }
        elseif ($n -in $PasswordHeaders) { $colRole[$c] = 'pw' }
        elseif ($n -like 'san*' -or $n -in @('dnsnames','dnsname','subjectalternativename','subjectalternativenames','altname','altnames')) { $colRole[$c] = 'san' }
        else { $colRole[$c] = $null }
    }
    $out = @()
    $line = 1
    foreach ($r in $rows) {
        $line++
        $rec = [ordered]@{ cn=''; c=''; st=''; l=''; o=''; ou=''; email=''; pw=''; sans=@(); line=$line }
        foreach ($c in $cols) {
            $role = $colRole[$c]; $val = "$($r.$c)".Trim()
            if (-not $val -or -not $role) { continue }
            if ($role -eq 'san') { $rec.sans += ($val -split '[,;\s]+' | Where-Object { $_ }) }
            else { $rec[$role] = $val }
        }
        if (-not $rec.cn) { Write-Host "  ! line ${line}: no CommonName, skipping" -ForegroundColor Yellow; continue }
        $out += [pscustomobject]$rec
    }
    return $out
}

# --- Crypto helpers ---------------------------------------------------------
function New-CsrFromRecord($rec, [int]$keySize) {
    $rsa = [System.Security.Cryptography.RSA]::Create($keySize)

    function Esc([string]$v) { $v -replace '([,+="<>;\\])','\$1' }
    $parts = @("CN=$(Esc $rec.cn)")
    if ($rec.o)  { $parts += "O=$(Esc $rec.o)" }
    if ($rec.ou) { $parts += "OU=$(Esc $rec.ou)" }
    if ($rec.l)  { $parts += "L=$(Esc $rec.l)" }
    if ($rec.st) { $parts += "ST=$(Esc $rec.st)" }
    if ($rec.c)  { $parts += "C=$(Esc $rec.c)" }
    if ($rec.email) { $parts += "E=$(Esc $rec.email)" }
    $dn = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new(($parts -join ', '))

    $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        $dn, $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

    $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $seen = @{}; $hasSan = $false
    foreach ($name in @($rec.cn) + $rec.sans) {
        if (-not $name) { continue }
        $k = $name.ToLower(); if ($seen.ContainsKey($k)) { continue }; $seen[$k] = $true
        [System.Net.IPAddress]$ip = $null
        if ([System.Net.IPAddress]::TryParse($name, [ref]$ip)) { $san.AddIpAddress($ip) }
        else { $san.AddDnsName($name) }
        $hasSan = $true
    }
    if ($hasSan) { $req.CertificateExtensions.Add($san.Build()) }

    # CreateSigningRequest() (DER) exists on both 5.1 and 7; wrap to PEM ourselves.
    $csrPem = ConvertTo-Pem 'CERTIFICATE REQUEST' ($req.CreateSigningRequest())
    return @{ Rsa = $rsa; CsrPem = $csrPem }
}

function Get-SafeName([string]$cn) {
    ($cn -replace '\*','_') -replace '[<>:"/\\|?]','_'
}

function Export-CertFiles($rec, $rsa, [string]$chainPem, [string]$outDir, [string]$keyPassword, [bool]$decryptKey, [bool]$zip) {
    $base = Get-SafeName $rec.cn

    $coll = Get-CertsFromPem $chainPem
    if ($coll.Count -eq 0) { throw "no certificates parsed from downloaded chain" }
    $leaf = $coll[0]
    $cas  = @(); for ($i=1; $i -lt $coll.Count; $i++) { $cas += $coll[$i] }

    $leafPem   = ConvertTo-Pem 'CERTIFICATE' $leaf.RawData
    $chainOnly = ''
    foreach ($c in $cas) { $chainOnly += (ConvertTo-Pem 'CERTIFICATE' $c.RawData) }

    # PKCS#12 (key + leaf + chain), password protected - works on 5.1 and 7.
    $leafWithKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($leaf, $rsa)
    $exportColl = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $exportColl.Add($leafWithKey) | Out-Null
    foreach ($c in $cas) { $exportColl.Add($c) | Out-Null }
    $p12Bytes = $exportColl.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $keyPassword)

    $files = [ordered]@{}
    $files["$base.crt.pem"] = $leafPem
    $files["$base.fullchain.pem"] = $leafPem + $chainOnly
    if ($chainOnly) { $files["$base.chain.pem"] = $chainOnly }
    $files["$base.p12"] = $p12Bytes

    if ($script:CanExportPemKey) {
        if ($decryptKey) {
            $keyPem = ConvertTo-Pem 'PRIVATE KEY' ($rsa.ExportPkcs8PrivateKey())
        } else {
            $pbe = [System.Security.Cryptography.PbeParameters]::new(
                [System.Security.Cryptography.PbeEncryptionAlgorithm]::Aes256Cbc,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256, 100000)
            $keyPem = ConvertTo-Pem 'ENCRYPTED PRIVATE KEY' ($rsa.ExportEncryptedPkcs8PrivateKey([char[]]$keyPassword, $pbe))
        }
        $files["$base.key.pem"] = $keyPem
        $files["$base.pem"]     = $leafPem + $chainOnly + $keyPem
    }

    $written = @()
    foreach ($fname in $files.Keys) {
        $path = Join-Path $outDir $fname
        if ($files[$fname] -is [byte[]]) { [System.IO.File]::WriteAllBytes($path, $files[$fname]) }
        else { [System.IO.File]::WriteAllText($path, $files[$fname], [System.Text.UTF8Encoding]::new($false)) }
        $written += $fname
    }

    if ($zip) {
        $zpath = Join-Path $outDir "$base.zip"
        if (Test-Path $zpath) { Remove-Item $zpath }
        $tmp = Join-Path $outDir ".ziptmp_$base"
        New-Item -ItemType Directory -Path $tmp -Force | Out-Null
        foreach ($f in $written) { Move-Item (Join-Path $outDir $f) (Join-Path $tmp $f) }
        Compress-Archive -Path (Join-Path $tmp '*') -DestinationPath $zpath
        Remove-Item $tmp -Recurse -Force
        return @{ Files = @("$base.zip"); Serial = $leaf.SerialNumber }
    }
    return @{ Files = $written; Serial = $leaf.SerialNumber }
}

# --- Central keygen: CM SaaS makes the key; retrieve it via the edge key (PSSodium) ---
function Invoke-CentralKeygen($rec, $appId, $citId, $keySize, $validity, $keyPassword, $pollTimeout, $pollInterval) {
    # SANs: CN first, then extras (de-duplicated; IPs split out)
    $dns = @(); $ips = @(); $seen = @{}
    foreach ($n in @($rec.cn) + $rec.sans) {
        if (-not $n) { continue }
        $k = $n.ToLower(); if ($seen.ContainsKey($k)) { continue }; $seen[$k] = $true
        [System.Net.IPAddress]$ip = $null
        if ([System.Net.IPAddress]::TryParse($n, [ref]$ip)) { $ips += $n } else { $dns += $n }
    }
    $sanByType = @{}
    if ($dns) { $sanByType.dnsNames = $dns }
    if ($ips) { $sanByType.ipAddresses = $ips }
    $csrAttr = @{
        commonName = $rec.cn
        keyTypeParameters = @{ keyType = 'RSA'; keyLength = $keySize }
        subjectAlternativeNamesByType = $sanByType
    }
    if ($rec.o)  { $csrAttr.organization = $rec.o }
    if ($rec.ou) { $csrAttr.organizationalUnits = @($rec.ou) }
    if ($rec.l)  { $csrAttr.locality = $rec.l }
    if ($rec.st) { $csrAttr.state = $rec.st }
    if ($rec.c)  { $csrAttr.country = $rec.c }
    $body = @{ isVaaSGenerated = $true; applicationId = $appId; certificateIssuingTemplateId = $citId; csrAttributes = $csrAttr }
    if ($validity) { $body.validityPeriod = $validity }
    $reqResp = Invoke-CcmApi -Method Post -Path '/outagedetection/v1/certificaterequests' -Body $body
    $reqId = $reqResp.certificateRequests[0].id

    $deadline = (Get-Date).AddSeconds($pollTimeout)
    $certId = $null
    while ((Get-Date) -lt $deadline) {
        $rr = Invoke-CcmApi -Method Get -Path "/outagedetection/v1/certificaterequests/$reqId"
        $ids = if ($rr.certificateIds) { $rr.certificateIds } else { $rr.certificateIdsForReissue }
        if ($rr.status -in @('ISSUED','COMPLETED') -and $ids) { $certId = $ids[0]; break }
        if ($rr.status -in @('FAILED','REJECTED','CANCELLED')) { throw "request $reqId ended as $($rr.status)" }
        Start-Sleep -Seconds $pollInterval
    }
    if (-not $certId) { throw "request $reqId not issued within ${pollTimeout}s" }

    # Retrieve the service-generated key: seal the passphrase against the tenant edge key.
    $cert = Invoke-CcmApi -Method Get -Path "/outagedetection/v1/certificates/$certId"
    if (-not $cert.dekHash) { throw "certificate $certId has no dekHash - key was not service-generated" }
    $publicKey = (Invoke-CcmApi -Method Get -Path "/v1/edgeencryptionkeys/$($cert.dekHash)").key
    $enc = ConvertTo-SodiumEncryptedString -Text $keyPassword -PublicKey $publicKey
    $ksBody = @{ exportFormat = 'PKCS12'; encryptedPrivateKeyPassphrase = $enc; encryptedKeystorePassphrase = $enc; certificateLabel = $rec.cn }

    $tmp = [IO.Path]::GetTempFileName()
    try {
        $h = @{ 'tppl-api-key' = $ApiKey; 'accept' = 'application/octet-stream' }
        Invoke-WebRequest -Method Post -Uri "$ApiBaseUrl/outagedetection/v1/certificates/$certId/keystore" `
            -Headers $h -Body ($ksBody | ConvertTo-Json) -ContentType 'application/json' -OutFile $tmp -UseBasicParsing | Out-Null
        $p12Bytes = [IO.File]::ReadAllBytes($tmp)
    } finally { if (Test-Path $tmp) { Remove-Item $tmp -Force } }

    # Parse the keystore -> leaf-first chain PEM + RSA key (Export-CertFiles handles the rest).
    $coll = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $coll.Import($p12Bytes, $keyPassword, 'Exportable')
    $leaf = $coll | Where-Object { $_.HasPrivateKey } | Select-Object -First 1
    if (-not $leaf) { throw "keystore for $certId contained no private key" }
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($leaf)
    $chainPem = ConvertTo-Pem 'CERTIFICATE' $leaf.RawData
    foreach ($c in $coll) { if ($c.Thumbprint -ne $leaf.Thumbprint) { $chainPem += (ConvertTo-Pem 'CERTIFICATE' $c.RawData) } }
    return @{ CertId = $certId; Rsa = $rsa; ChainPem = $chainPem }
}

# --- Resolve template + application -----------------------------------------
Write-Host "[1/3] Resolving user, issuing template and application..."
$userId = (Invoke-CcmApi -Method Get -Path '/v1/useraccounts').user.id

$cits = (Invoke-CcmApi -Method Get -Path '/v1/certificateissuingtemplates').certificateIssuingTemplates
$cit = $cits | Where-Object { $_.name -ieq $IssuingTemplate } | Select-Object -First 1
if (-not $cit) { throw "Issuing template '$IssuingTemplate' not found. Available: $(( $cits.name | ForEach-Object { "'$_'" }) -join ', ')" }
Write-Host "      Template: '$($cit.name)' ($($cit.id)), keygen=$KeyGen"

# Validate the template supports the requested keygen mode, up front.
if ($KeyGen -eq 'central' -and -not $cit.keyGeneratedByVenafiAllowed) {
    throw "Template '$($cit.name)' does not allow Venafi-generated keys, so -KeyGen central cannot work. Enable 'Allow Venafi to generate the key' on the template, pick one that allows it, or use -KeyGen local."
}
if ($KeyGen -eq 'local' -and ($cit.PSObject.Properties.Name -contains 'csrUploadAllowed') -and -not $cit.csrUploadAllowed) {
    throw "Template '$($cit.name)' does not allow uploaded CSRs, so -KeyGen local cannot work. Use -KeyGen central or a template that allows uploaded CSRs."
}

$appId = $null
try {
    $enc = [uri]::EscapeDataString($ApplicationName)
    $app = Invoke-CcmApi -Method Get -Path "/outagedetection/v1/applications/name/$enc"
    $aliasMap = $app.certificateIssuingTemplateAliasIdMap
    $linked = $false
    if ($aliasMap) { $linked = ($aliasMap.PSObject.Properties.Value -contains $cit.id) }
    if (-not $linked) {
        throw "Application '$ApplicationName' exists ($($app.id)) but is not linked to template '$($cit.name)'. Link it in the CCM UI or use a different -ApplicationName."
    }
    $appId = $app.id
    Write-Host "      Reusing application '$ApplicationName' ($appId), template '$($cit.name)' linked"
} catch {
    if ($_.Exception.Message -notmatch 'HTTP 404') { throw }
    $body = @{
        name = $ApplicationName
        ownerIdsAndTypes = @(@{ ownerId = $userId; ownerType = 'USER' })
        certificateIssuingTemplateAliasIdMap = @{ "$($cit.name)" = $cit.id }
    }
    $created = Invoke-CcmApi -Method Post -Path '/outagedetection/v1/applications' -Body $body
    $appId = $created.applications[0].id
    Write-Host "      Created application '$ApplicationName' ($appId) linked to template '$($cit.name)'"
}

# --- Read CSV ---------------------------------------------------------------
Write-Host "[2/3] Reading rows from $CsvPath..."
$rows = Read-CsvRows -path $CsvPath
Write-Host "      $($rows.Count) certificate(s) to issue"
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# --- Issue ------------------------------------------------------------------
Write-Host "[3/3] Issuing certificates..."
$results = @()
$generated = @()   # (commonName, keyPassword) for randomly-generated passwords only
$i = 0
foreach ($rec in $rows) {
    $i++
    $label = $rec.cn
    # Resolve this cert's password and where it came from (source, not the value).
    if ($script:SharedPassword) { $pw = $script:SharedPassword; $pwSource = $script:PasswordMode }
    elseif ($rec.pw)            { $pw = $rec.pw;                 $pwSource = 'csv' }
    else                        { $pw = New-RandomPassword;      $pwSource = 'random' }
    try {
        if ($KeyGen -eq 'central') {
            $ck = Invoke-CentralKeygen -rec $rec -appId $appId -citId $cit.id -keySize $KeySize -validity $Validity -keyPassword $pw -pollTimeout $PollTimeoutSec -pollInterval $PollIntervalSec
            $certId = $ck.CertId
            $res = Export-CertFiles -rec $rec -rsa $ck.Rsa -chainPem $ck.ChainPem -outDir $OutputDir -keyPassword $pw -decryptKey $DecryptKey.IsPresent -zip (-not $NoZip.IsPresent)
        } else {
            $csr = New-CsrFromRecord -rec $rec -keySize $KeySize
            $reqBody = @{
                applicationId = $appId
                certificateIssuingTemplateId = $cit.id
                certificateSigningRequest = $csr.CsrPem
            }
            if ($Validity) { $reqBody.validityPeriod = $Validity }
            $reqResp = Invoke-CcmApi -Method Post -Path '/outagedetection/v1/certificaterequests' -Body $reqBody
            $reqId = $reqResp.certificateRequests[0].id

            $deadline = (Get-Date).AddSeconds($PollTimeoutSec)
            $certId = $null
            while ((Get-Date) -lt $deadline) {
                $rr = Invoke-CcmApi -Method Get -Path "/outagedetection/v1/certificaterequests/$reqId"
                $ids = if ($rr.certificateIds) { $rr.certificateIds } else { $rr.certificateIdsForReissue }
                if ($rr.status -in @('ISSUED','COMPLETED') -and $ids) { $certId = $ids[0]; break }
                if ($rr.status -in @('FAILED','REJECTED','CANCELLED')) { throw "request $reqId ended as $($rr.status)" }
                Start-Sleep -Seconds $PollIntervalSec
            }
            if (-not $certId) { throw "request $reqId not issued within ${PollTimeoutSec}s" }

            $chainPem = Invoke-CcmApi -Method Get -Path "/outagedetection/v1/certificates/$certId/contents?format=PEM&chainOrder=EE_FIRST" -Accept 'text/plain'
            $res = Export-CertFiles -rec $rec -rsa $csr.Rsa -chainPem $chainPem -outDir $OutputDir -keyPassword $pw -decryptKey $DecryptKey.IsPresent -zip (-not $NoZip.IsPresent)
        }
        if ($pwSource -eq 'random') { $generated += [pscustomobject]@{ commonName=$label; keyPassword=$pw } }
        $base = Get-SafeName $rec.cn
        $exts = ($res.Files | ForEach-Object { if ($_.StartsWith($base)) { $_.Substring($base.Length) } else { $_ } }) -join '  '
        Write-Host ("  [{0}/{1}] " -f $i,$rows.Count) -NoNewline
        Write-Host "ISSUED" -ForegroundColor Green -NoNewline
        Write-Host ("  {0}  ({1} keygen)" -f $label,$KeyGen)
        Write-Host ("           files  {0}" -f $exts) -ForegroundColor DarkGray
        Write-Host ("           cert   {0}" -f $certId) -ForegroundColor DarkGray
        $results += [pscustomobject]@{ commonName=$label; status='ISSUED'; keyGeneration=$KeyGen; certificateId=$certId; serial=$res.Serial; passwordSource=$pwSource; files=($res.Files -join ';'); error='' }
    } catch {
        Write-Host ("  [{0}/{1}] " -f $i,$rows.Count) -NoNewline
        Write-Host "FAILED" -ForegroundColor Red -NoNewline
        Write-Host ("  {0}" -f $label)
        Write-Host ("           {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow
        $results += [pscustomobject]@{ commonName=$label; status='FAILED'; keyGeneration=$KeyGen; certificateId=''; serial=''; passwordSource=$pwSource; files=''; error=$_.Exception.Message }
    }
}

$manifest = Join-Path $OutputDir 'results.csv'
$results | Export-Csv -Path $manifest -NoTypeInformation -Encoding utf8

# Secrets, kept OUT of the inventory manifest: only the randomly-generated passwords
# (the ones that would otherwise be unrecoverable) go to a separate, clearly-named file.
$secretsPath = $null
if ($generated.Count -gt 0) {
    $secretsPath = Join-Path $OutputDir 'GENERATED-PASSWORDS.csv'
    $generated | Export-Csv -Path $secretsPath -NoTypeInformation -Encoding utf8
}

$ok = ($results | Where-Object { $_.status -eq 'ISSUED' }).Count
$failed = $results.Count - $ok
Write-Host ""
Write-Host ("Done.     {0} issued, {1} failed  ({2} total)" -f $ok,$failed,$results.Count) -ForegroundColor Cyan
Write-Host ("Output:   {0}" -f (Resolve-Path $OutputDir).Path)
Write-Host ("Manifest: {0}  (password source only, no secrets)" -f $manifest)
if ($secretsPath) {
    Write-Host ("SECRETS:  {0}  ({1} generated password(s)) - distribute securely, then DELETE this file" -f $secretsPath, $generated.Count) -ForegroundColor Yellow
}
if ($ok -ne $results.Count) { exit 2 }
