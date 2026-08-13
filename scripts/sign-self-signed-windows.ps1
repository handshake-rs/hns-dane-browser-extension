[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string[]]$Path,

  [string]$TimestampUrl = 'http://timestamp.acs.microsoft.com',

  [string]$PinnedCertificate
)

$ErrorActionPreference = 'Stop'

$pfxBase64 = $env:WINDOWS_SELF_SIGNED_PFX_BASE64
$pfxPassword = $env:WINDOWS_SELF_SIGNED_PFX_PASSWORD
$expectedPublisher = $env:WINDOWS_AUTHENTICODE_PUBLISHER
$expectedCertificateSha256 = $env:WINDOWS_SELF_SIGNED_CERTIFICATE_SHA256
if ([string]::IsNullOrWhiteSpace($pfxBase64) -or
    [string]::IsNullOrWhiteSpace($pfxPassword) -or
    [string]::IsNullOrWhiteSpace($expectedPublisher) -or
    $expectedCertificateSha256 -notmatch '^[a-f0-9]{64}$') {
  throw 'The protected self-signed Windows signing inputs are incomplete or malformed.'
}
if ($TimestampUrl -notmatch '^https?://[^\s]+$') {
  throw 'The RFC 3161 timestamp URL is invalid.'
}
$expectedCertificateSha256 = $expectedCertificateSha256.ToLowerInvariant()
if ([string]::IsNullOrWhiteSpace($PinnedCertificate)) {
  $PinnedCertificate = Join-Path `
    $PSScriptRoot `
    '..\release\windows-self-signed-code-signing.cer'
}

function Get-CertificateSha256 {
  param(
    [Parameter(Mandatory = $true)]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
  )

  $sha256 = [System.Security.Cryptography.SHA256]::Create()
  try {
    return [BitConverter]::ToString(
      $sha256.ComputeHash($Certificate.RawData)
    ).Replace('-', '').ToLowerInvariant()
  } finally {
    $sha256.Dispose()
  }
}

function Test-ByteArraysEqual {
  param(
    [Parameter(Mandatory = $true)][byte[]]$Left,
    [Parameter(Mandatory = $true)][byte[]]$Right
  )

  if ($Left.Length -ne $Right.Length) {
    return $false
  }
  $difference = 0
  for ($index = 0; $index -lt $Left.Length; $index++) {
    $difference = $difference -bor ($Left[$index] -bxor $Right[$index])
  }
  return $difference -eq 0
}

function Clear-ByteArray {
  param([byte[]]$Bytes)

  if ($null -ne $Bytes) {
    [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($Bytes)
  }
}

function Assert-SelfSignedCodeSigningCertificate {
  param(
    [Parameter(Mandatory = $true)]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
    [Parameter(Mandatory = $true)]
    [string]$Source
  )

  if ($Certificate.Subject -ne $expectedPublisher -or
      $Certificate.Issuer -ne $expectedPublisher) {
    throw "$Source is not the approved self-signed publisher."
  }
  if ((Get-CertificateSha256 -Certificate $Certificate) -ne
      $expectedCertificateSha256) {
    throw "$Source SHA-256 does not match the approved certificate."
  }
  if ($Certificate.SignatureAlgorithm.Value -ne '1.2.840.113549.1.1.11') {
    throw "$Source is not signed with sha256WithRSAEncryption."
  }

  $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey(
    $Certificate
  )
  try {
    if ($null -eq $rsa -or $rsa.KeySize -lt 3072) {
      throw "$Source does not have an RSA key of at least 3072 bits."
    }
  } finally {
    if ($null -ne $rsa) {
      $rsa.Dispose()
    }
  }

  $hasCodeSigningEku = $false
  $hasDigitalSignatureUsage = $false
  $isCertificateAuthority = $false
  foreach ($extension in $Certificate.Extensions) {
    if ($extension -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
      foreach ($usage in $extension.EnhancedKeyUsages) {
        if ($usage.Value -eq '1.3.6.1.5.5.7.3.3') {
          $hasCodeSigningEku = $true
        }
      }
    }
    if ($extension -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension] -and
        ($extension.KeyUsages -band
          [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature)) {
      $hasDigitalSignatureUsage = $true
    }
    if ($extension -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] -and
        $extension.CertificateAuthority) {
      $isCertificateAuthority = $true
    }
  }
  if (-not $hasCodeSigningEku -or -not $hasDigitalSignatureUsage -or
      $isCertificateAuthority) {
    throw "$Source does not satisfy the leaf code-signing certificate policy."
  }

  $now = [DateTime]::UtcNow
  if ($Certificate.NotBefore.ToUniversalTime() -gt $now.AddMinutes(5) -or
      $Certificate.NotAfter.ToUniversalTime() -lt $now.AddDays(30)) {
    throw "$Source is not currently usable."
  }
}

function Find-SignTool {
  $command = Get-Command 'signtool.exe' -ErrorAction SilentlyContinue
  if ($null -ne $command) {
    return $command.Source
  }
  $candidate = Get-ChildItem `
    -Path "${env:ProgramFiles(x86)}\Windows Kits\10\bin" `
    -Filter 'signtool.exe' `
    -File `
    -Recurse `
    -ErrorAction SilentlyContinue |
      Where-Object { $_.DirectoryName -match '\\x64$' } |
      Sort-Object FullName -Descending |
      Select-Object -First 1 -ExpandProperty FullName
  if (-not $candidate -or
      -not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
    throw 'Unable to locate signtool.exe in the installed Windows SDK.'
  }
  return $candidate
}

$temporaryBase = if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
  [System.IO.Path]::GetTempPath()
} else {
  $env:RUNNER_TEMP
}
$temporary = Join-Path $temporaryBase (
  'hns-windows-self-signing-' + [guid]::NewGuid().ToString('N')
)
$pfxPath = Join-Path $temporary 'code-signing.pfx'
$pfxBytes = $null
$pfxCertificates = $null
$certificate = $null
$importedCertificate = $null
$certificateImportedByThisRun = $false
$pinnedCertificateObject = $null
$securePassword = $null
$certificateStorePath = $null
$pinnedCertificateBytes = $null
try {
  $pinnedCertificatePath = (Resolve-Path -LiteralPath $PinnedCertificate).Path
  $pinnedCertificateBytes = [System.IO.File]::ReadAllBytes(
    $pinnedCertificatePath
  )
  $pinnedCertificateObject = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
    $pinnedCertificateBytes
  )
  if ($pinnedCertificateObject.HasPrivateKey) {
    throw 'The committed pinned Windows certificate unexpectedly contains a private key.'
  }
  Assert-SelfSignedCodeSigningCertificate `
    -Certificate $pinnedCertificateObject `
    -Source 'The committed pinned Windows certificate'

  [void](New-Item -ItemType Directory -Path $temporary)
  try {
    $pfxBytes = [Convert]::FromBase64String($pfxBase64)
  } catch {
    throw 'The protected Windows signing PFX is not valid base64.'
  }
  if ($pfxBytes.Length -lt 1024 -or $pfxBytes.Length -gt 49152) {
    throw 'The protected Windows signing PFX has an invalid size.'
  }
  [System.IO.File]::WriteAllBytes($pfxPath, $pfxBytes)
  $pfxCertificates = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
  $pfxCertificates.Import(
    $pfxBytes,
    $pfxPassword,
    [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
  )
  if ($pfxCertificates.Count -ne 1) {
    throw 'The protected Windows signing PFX must contain exactly one certificate.'
  }
  $certificate = $pfxCertificates[0]
  if (-not $certificate.HasPrivateKey) {
    throw 'The protected Windows signing PFX has no private key.'
  }
  Assert-SelfSignedCodeSigningCertificate `
    -Certificate $certificate `
    -Source 'The protected Windows signing PFX certificate'
  if (-not (Test-ByteArraysEqual `
      -Left $certificate.RawData `
      -Right $pinnedCertificateObject.RawData)) {
    throw 'The protected PFX certificate does not exactly match the committed public certificate.'
  }

  $signtool = Find-SignTool
  $certificateStorePath = "Cert:\CurrentUser\My\$($certificate.Thumbprint)"
  if (Test-Path -LiteralPath $certificateStorePath) {
    throw 'The approved self-signed certificate unexpectedly already exists in CurrentUser\My.'
  }
  $securePassword = ConvertTo-SecureString `
    -String $pfxPassword `
    -AsPlainText `
    -Force
  $importedCertificates = @(Import-PfxCertificate `
    -FilePath $pfxPath `
    -CertStoreLocation 'Cert:\CurrentUser\My' `
    -Password $securePassword)
  $certificateImportedByThisRun = $true
  if ($importedCertificates.Count -ne 1) {
    throw 'The protected PFX did not import exactly one certificate.'
  }
  $importedCertificate = $importedCertificates[0]
  $matchingPrivateCertificates = @(
    Get-ChildItem -LiteralPath 'Cert:\CurrentUser\My' |
      Where-Object {
        $_.Thumbprint -eq $certificate.Thumbprint -and $_.HasPrivateKey
      }
  )
  if ($matchingPrivateCertificates.Count -ne 1 -or
      $importedCertificate.Thumbprint -ne $certificate.Thumbprint -or
      -not $importedCertificate.HasPrivateKey) {
    throw 'Exactly one approved private key was not imported into CurrentUser\My.'
  }
  foreach ($candidate in $Path) {
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
      throw "Self-signed Windows release input is missing: $candidate"
    }
    $binary = (Resolve-Path -LiteralPath $candidate).Path
    if ([System.IO.Path]::GetExtension($binary) -ne '.exe') {
      throw "Self-signed Windows release input is not an executable: $binary"
    }
    $existingSignature = Get-AuthenticodeSignature -LiteralPath $binary
    if ($existingSignature.Status -ne
        [System.Management.Automation.SignatureStatus]::NotSigned) {
      throw "Refusing to overwrite or append to an existing signature on $binary."
    }
    & $signtool sign `
      /fd SHA256 `
      /sha1 $certificate.Thumbprint `
      /s My `
      /tr $TimestampUrl `
      /td SHA256 `
      /d 'HNS DANE Browser' `
      /du 'https://github.com/handshake-rs/hns-dane-browser-extension' `
      $binary | Out-Host
    if ($LASTEXITCODE -ne 0) {
      throw "SignTool failed to self-sign and timestamp $binary."
    }
    $newSignature = Get-AuthenticodeSignature -LiteralPath $binary
    if ($newSignature.SignatureType.ToString() -ne 'Authenticode' -or
        $null -eq $newSignature.SignerCertificate -or
        $null -eq $newSignature.TimeStamperCertificate -or
        (Get-CertificateSha256 -Certificate $newSignature.SignerCertificate) -ne
          $expectedCertificateSha256 -or
        -not (Test-ByteArraysEqual `
          -Left $newSignature.SignerCertificate.RawData `
          -Right $pinnedCertificateObject.RawData)) {
      throw "SignTool did not produce the exact embedded, timestamped signature on $binary."
    }
    Write-Output "Self-signed and timestamped $([System.IO.Path]::GetFileName($binary))."
  }
} finally {
  $certificateRemovalError = $null
  if ($certificateImportedByThisRun -and
      $null -ne $certificateStorePath -and
      (Test-Path -LiteralPath $certificateStorePath)) {
    try {
      Remove-Item -LiteralPath $certificateStorePath -Force
    } catch {
      $certificateRemovalError = $_
    }
  }
  if ($null -ne $importedCertificate) {
    $importedCertificate.Dispose()
  }
  if ($null -ne $pfxCertificates) {
    foreach ($pfxCertificate in $pfxCertificates) {
      $pfxCertificate.Dispose()
    }
  }
  if ($null -ne $pinnedCertificateObject) {
    $pinnedCertificateObject.Dispose()
  }
  if ($null -ne $securePassword) {
    $securePassword.Dispose()
  }
  Clear-ByteArray -Bytes $pfxBytes
  Clear-ByteArray -Bytes $pinnedCertificateBytes
  if (Test-Path -LiteralPath $temporary) {
    Remove-Item -LiteralPath $temporary -Recurse -Force
  }
  $env:WINDOWS_SELF_SIGNED_PFX_BASE64 = $null
  $env:WINDOWS_SELF_SIGNED_PFX_PASSWORD = $null
  if ($certificateImportedByThisRun -and
      $null -ne $certificateStorePath -and
      (Test-Path -LiteralPath $certificateStorePath)) {
    throw 'The self-signed Windows private key was not removed from CurrentUser\My.'
  }
  if ($null -ne $certificateRemovalError) {
    throw "Unable to remove the self-signed Windows private key: $certificateRemovalError"
  }
}
