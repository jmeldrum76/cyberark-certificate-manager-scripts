<#
.SYNOPSIS
    Upload a certificate to CyberArk Certificate Manager SaaS, associate it with an
    application, assign a tag, then download it back.

.DESCRIPTION
    End-to-end workflow against the CyberArk Certificate Manager SaaS REST API
    (https://api.venafi.cloud). The script:

      1. Resolves the calling user (owner for the application).
      2. Creates the application, or reuses it if one with the same name exists.
      3. Extracts the end-entity certificate from the supplied PEM and uploads it,
         associating it with the application.
      4. Creates the tag + value (or reuses them if they exist) and assigns the
         "TagName:TagValue" pair to the uploaded certificate via
         PATCH /v1/tagsassignment.
      5. Downloads the certificate chain back to the specified output path.

    Only the public certificate is uploaded. If PemPath contains a full chain or a
    private key, only the first BEGIN CERTIFICATE block is used for the upload; the
    service infers the chain from its known issuer certificates.

.PARAMETER PemPath
    Path to the PEM file containing the certificate to upload. If the file contains
    multiple certificates (a full chain), only the first (end-entity) block is used.

.PARAMETER ApiKey
    CyberArk Certificate Manager SaaS API key. Sent as the "tppl-api-key" header.

.PARAMETER ApplicationName
    Application name to create or reuse.

.PARAMETER TagName
    Tag name to create or reuse (e.g. "Service Now").

.PARAMETER TagValue
    Tag value to create or reuse under the tag (e.g. a ServiceNow ticket number).

.PARAMETER OutputPath
    Path for the downloaded PEM (cert chain, root first).

.PARAMETER ApiBaseUrl
    Base URL for the regional API endpoint. Defaults to https://api.venafi.cloud.

.EXAMPLE
    .\Invoke-CcmCertWorkflow.ps1 `
        -PemPath .\mycert.pem `
        -ApiKey <YOUR_API_KEY> `
        -ApplicationName "Billing App" `
        -TagName "Service Now" `
        -TagValue "INC0012345" `
        -OutputPath .\mycert-downloaded.pem
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $PemPath,
    [Parameter(Mandatory)] [string] $ApiKey,
    [Parameter(Mandatory)] [string] $ApplicationName,
    [Parameter(Mandatory)] [string] $TagName,
    [Parameter(Mandatory)] [string] $TagValue,
    [Parameter(Mandatory)] [string] $OutputPath,
    [string] $ApiBaseUrl = 'https://api.venafi.cloud'
)

$ErrorActionPreference = 'Stop'
$headers = @{ 'tppl-api-key' = $ApiKey; 'Content-Type' = 'application/json' }
$ApiBaseUrl = $ApiBaseUrl.TrimEnd('/')

function Invoke-CcmApi {
    param(
        [string] $Method,
        [string] $Path,
        [object] $Body
    )
    $uri = "$ApiBaseUrl$Path"
    $params = @{ Method = $Method; Uri = $uri; Headers = $headers }
    if ($null -ne $Body) {
        $params.Body = ($Body | ConvertTo-Json -Depth 10 -Compress)
    }
    try {
        return Invoke-RestMethod @params
    } catch {
        $status = 0
        $respBody = ''
        if ($_.Exception.Response) {
            $status = [int]$_.Exception.Response.StatusCode
            try {
                $s = $_.Exception.Response.GetResponseStream()
                $s.Position = 0
                $respBody = (New-Object System.IO.StreamReader($s)).ReadToEnd()
            } catch {}
        }
        throw "HTTP $status on $Method $Path : $respBody"
    }
}

function Get-FirstCertificateBase64 {
    param([string] $Path)
    $text = [System.IO.File]::ReadAllText($Path)
    $m = [regex]::Match($text, '(?s)-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----')
    if (-not $m.Success) {
        throw "No -----BEGIN CERTIFICATE----- block found in $Path"
    }
    return ($m.Groups[1].Value -replace '\s', '')
}

function Get-CertificateFingerprintSha1 {
    param([string] $Base64Der)
    $bytes = [Convert]::FromBase64String($Base64Der)
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $hash = $sha1.ComputeHash($bytes)
    } finally { $sha1.Dispose() }
    return -join ($hash | ForEach-Object { $_.ToString('X2') })
}

function Find-CertificateIdByFingerprint {
    param([string] $Fingerprint)
    $body = @{
        expression = @{ operands = @(@{ field = 'fingerprint'; operator = 'MATCH'; value = $Fingerprint }) }
        paging     = @{ pageNumber = 0; pageSize = 1 }
    }
    $resp = Invoke-CcmApi -Method Post -Path '/outagedetection/v1/certificatesearch' -Body $body
    if ($resp.certificates -and $resp.certificates.Count -gt 0) {
        return $resp.certificates[0].id
    }
    return $null
}

if (-not (Test-Path $PemPath)) { throw "PEM file not found: $PemPath" }

# 1. Resolve user (owner for the application)
Write-Host "[1/6] Resolving current user..."
$user = Invoke-CcmApi -Method Get -Path '/v1/useraccounts'
$userId = $user.user.id
Write-Host ("      User: {0} ({1})" -f $user.user.username, $userId)

# 2. Create or reuse the application
Write-Host "[2/6] Ensuring application '$ApplicationName' exists..."
$appId = $null
try {
    $encodedName = [uri]::EscapeDataString($ApplicationName)
    $existing = Invoke-CcmApi -Method Get -Path "/outagedetection/v1/applications/name/$encodedName"
    $appId = $existing.id
    Write-Host "      Reusing existing application id: $appId"
} catch {
    if ($_.Exception.Message -notmatch 'HTTP 404') { throw }
    $body = @{
        name = $ApplicationName
        ownerIdsAndTypes = @(@{ ownerId = $userId; ownerType = 'USER' })
    }
    $created = Invoke-CcmApi -Method Post -Path '/outagedetection/v1/applications' -Body $body
    $appId = $created.applications[0].id
    Write-Host "      Created application id: $appId"
}

# 3. Upload the certificate and associate with the application
Write-Host "[3/6] Uploading certificate from $PemPath..."
$certB64 = Get-FirstCertificateBase64 -Path $PemPath
$fingerprint = Get-CertificateFingerprintSha1 -Base64Der $certB64
$uploadBody = @{
    certificates = @(@{ certificate = $certB64; applicationIds = @($appId) })
}
$uploaded = Invoke-CcmApi -Method Post -Path '/outagedetection/v1/certificates' -Body $uploadBody
if ($uploaded.certificateInformations -and $uploaded.certificateInformations.Count -gt 0) {
    $certId = $uploaded.certificateInformations[0].id
    Write-Host "      Certificate id: $certId  (fingerprint: $fingerprint)"
} elseif ($uploaded.statistics.existed -gt 0) {
    $certId = Find-CertificateIdByFingerprint -Fingerprint $fingerprint
    if (-not $certId) {
        throw "Upload reported existed=1 but fingerprint $fingerprint not found via search"
    }
    Write-Host "      Certificate already existed; id: $certId  (fingerprint: $fingerprint)"
} else {
    throw "Upload did not return a certificate id. Response: $($uploaded | ConvertTo-Json -Depth 5 -Compress)"
}

# 4. Create or reuse the tag + value
Write-Host "[4/6] Ensuring tag '$TagName' with value '$TagValue' exists..."
$encodedTag = [uri]::EscapeDataString($TagName)
try {
    $tag = Invoke-CcmApi -Method Get -Path "/v1/tags/$encodedTag"
    Write-Host "      Reusing existing tag id: $($tag.id)"
} catch {
    if ($_.Exception.Message -notmatch 'HTTP 404') { throw }
    $tag = Invoke-CcmApi -Method Post -Path '/v1/tags' -Body @{ name = $TagName; values = @($TagValue) }
    Write-Host "      Created tag id: $($tag.id)"
}

$values = Invoke-CcmApi -Method Get -Path "/v1/tags/$encodedTag/values"
$existingValue = $values.values | Where-Object { $_.value -eq $TagValue }
if (-not $existingValue) {
    $null = Invoke-CcmApi -Method Post -Path "/v1/tags/$encodedTag/values" -Body @{ values = @($TagValue) }
    Write-Host "      Added value '$TagValue'"
} else {
    Write-Host "      Reusing existing value id: $($existingValue.id)"
}

# 5. Assign the tag to the uploaded certificate
Write-Host "[5/6] Assigning '$TagName`:$TagValue' to certificate $certId..."
$assignBody = @{
    action       = 'ADD'
    entityIds    = @($certId)
    entityType   = 'CERTIFICATE'
    targetedTags = @("$TagName`:$TagValue")
}
$assign = Invoke-CcmApi -Method Patch -Path '/v1/tagsassignment' -Body $assignBody
$status = $assign.tagsAssignInformation[0].status
Write-Host "      Status: $status"

# 6. Download the certificate back
Write-Host "[6/6] Downloading certificate chain to $OutputPath..."
$downloadUri = "$ApiBaseUrl/outagedetection/v1/certificates/$certId/contents?format=PEM&chainOrder=ROOT_FIRST"
$resp = Invoke-WebRequest -Method Get -Uri $downloadUri `
    -Headers @{ 'tppl-api-key' = $ApiKey; 'accept' = 'text/plain' } `
    -UseBasicParsing
[System.IO.File]::WriteAllText($OutputPath, $resp.Content, (New-Object System.Text.UTF8Encoding $false))
$certCount = ([regex]::Matches($resp.Content, 'BEGIN CERTIFICATE')).Count
Write-Host ("      Saved {0} bytes, {1} certificate(s) in chain" -f (Get-Item $OutputPath).Length, $certCount)

Write-Host ""
Write-Host "Done."
Write-Host "  Application : $ApplicationName  ($appId)"
Write-Host "  Certificate : $certId"
Write-Host "  Tag         : $TagName`:$TagValue"
Write-Host "  Downloaded  : $OutputPath"
