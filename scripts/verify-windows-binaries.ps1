[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string[]]$Path,

  [switch]$RequireAuthenticode,

  [string]$ExpectedPublisher,

  [switch]$AllowSelfSigned,

  [string]$ExpectedCertificateSha256,

  [string]$SelfSignedCertificate,

  [string]$EvidenceOutput
)

$ErrorActionPreference = 'Stop'

if ($RequireAuthenticode -and [string]::IsNullOrWhiteSpace($ExpectedPublisher)) {
  throw 'ExpectedPublisher is required when RequireAuthenticode is enabled.'
}
if ($AllowSelfSigned -and -not $RequireAuthenticode) {
  throw 'AllowSelfSigned requires RequireAuthenticode.'
}
if ($AllowSelfSigned -and
    ($ExpectedCertificateSha256 -notmatch '^[a-f0-9]{64}$' -or
     [string]::IsNullOrWhiteSpace($SelfSignedCertificate))) {
  throw 'Self-signed verification requires the pinned certificate and its lowercase SHA-256.'
}
if ($AllowSelfSigned) {
  $ExpectedCertificateSha256 = $ExpectedCertificateSha256.ToLowerInvariant()
}
if (-not [string]::IsNullOrWhiteSpace($EvidenceOutput) -and
    -not $AllowSelfSigned) {
  throw 'Signing evidence can be emitted only for the exact self-signed policy.'
}

if ($AllowSelfSigned -and
    $null -eq ('HnsDaneBrowser.WindowsCrypt32' -as [type])) {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace HnsDaneBrowser {
  public static class WindowsCrypt32 {
    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CertResyncCertificateChainEngine(
      IntPtr chainEngine
    );
  }
}
'@
}

function Sync-CurrentUserCertificateChainEngine {
  if (-not [HnsDaneBrowser.WindowsCrypt32]::CertResyncCertificateChainEngine(
      [IntPtr]::Zero
    )) {
    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw "Unable to resynchronize the current-user certificate chain engine: $errorCode"
  }
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

function Test-CertificateEku {
  param(
    [Parameter(Mandatory = $true)]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
    [Parameter(Mandatory = $true)]
    [string]$Oid
  )

  foreach ($extension in $Certificate.Extensions) {
    if ($extension -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
      foreach ($usage in $extension.EnhancedKeyUsages) {
        if ($usage.Value -eq $Oid) {
          return $true
        }
      }
    }
  }
  return $false
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

function Assert-SelfSignedCertificatePolicy {
  param(
    [Parameter(Mandatory = $true)]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
  )

  if ($Certificate.HasPrivateKey -or
      $Certificate.Subject -ne $ExpectedPublisher -or
      $Certificate.Issuer -ne $ExpectedPublisher -or
      (Get-CertificateSha256 -Certificate $Certificate) -ne
        $ExpectedCertificateSha256 -or
      $Certificate.SignatureAlgorithm.Value -ne '1.2.840.113549.1.1.11' -or
      -not (Test-CertificateEku `
        -Certificate $Certificate `
        -Oid '1.3.6.1.5.5.7.3.3')) {
    throw 'The committed self-signed Windows certificate does not match release policy.'
  }

  $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey(
    $Certificate
  )
  try {
    if ($null -eq $rsa -or $rsa.KeySize -lt 3072) {
      throw 'The self-signed Windows certificate requires an RSA key of at least 3072 bits.'
    }
  } finally {
    if ($null -ne $rsa) {
      $rsa.Dispose()
    }
  }

  $hasDigitalSignatureUsage = $false
  $isCertificateAuthority = $false
  foreach ($extension in $Certificate.Extensions) {
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
  if (-not $hasDigitalSignatureUsage -or $isCertificateAuthority) {
    throw 'The self-signed Windows certificate is not a non-CA digital-signature leaf.'
  }

  $now = [DateTime]::UtcNow
  if ($Certificate.NotBefore.ToUniversalTime() -gt $now.AddMinutes(5) -or
      $Certificate.NotAfter.ToUniversalTime() -lt $now.AddDays(30)) {
    throw 'The self-signed Windows certificate is not currently usable.'
  }
}

function Find-VisualStudioTool {
  param([Parameter(Mandatory = $true)][string]$Name)

  $command = Get-Command $Name -ErrorAction SilentlyContinue
  if ($null -ne $command) {
    return $command.Source
  }

  $vswhereCandidates = @(
    "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe",
    "$env:ProgramFiles\Microsoft Visual Studio\Installer\vswhere.exe"
  )
  $vswhere = $vswhereCandidates |
    Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
    Select-Object -First 1
  if (-not $vswhere) {
    throw 'Unable to locate Visual Studio Installer vswhere.exe.'
  }

  $located = & $vswhere -latest -products '*' `
    -find "VC\Tools\MSVC\**\bin\Host*\*\$Name" |
      Select-Object -First 1
  if (-not $located) {
    $located = Get-ChildItem `
      -Path "${env:ProgramFiles(x86)}\Windows Kits\10\bin" `
      -Filter $Name `
      -File `
      -Recurse `
      -ErrorAction SilentlyContinue |
        Where-Object { $_.DirectoryName -match '\\x64$' } |
        Sort-Object FullName -Descending |
        Select-Object -First 1 -ExpandProperty FullName
  }
  if (-not $located -or
      -not (Test-Path -LiteralPath $located -PathType Leaf)) {
    throw "Unable to locate $Name in the installed Visual Studio toolchain."
  }
  return $located
}

$selfSignedRootStore = $null
$selfSignedPinnedCertificate = $null
$selfSignedPinnedCertificateRaw = $null
$selfSignedRootThumbprint = $null
$selfSignedRootAdded = $false
$verifiedBinaries = [System.Collections.Generic.List[string]]::new()
$signingEvidenceFiles = [System.Collections.Generic.List[object]]::new()

try {
  if ($AllowSelfSigned) {
    $certificatePath = (Resolve-Path -LiteralPath $SelfSignedCertificate).Path
    $certificateBytes = [System.IO.File]::ReadAllBytes($certificatePath)
    $selfSignedPinnedCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
      $certificateBytes
    )
    Assert-SelfSignedCertificatePolicy `
      -Certificate $selfSignedPinnedCertificate
    $selfSignedPinnedCertificateRaw = $selfSignedPinnedCertificate.RawData
    $selfSignedRootThumbprint = $selfSignedPinnedCertificate.Thumbprint
    $selfSignedRootStore = [System.Security.Cryptography.X509Certificates.X509Store]::new(
      [System.Security.Cryptography.X509Certificates.StoreName]::Root,
      [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    )
    $selfSignedRootStore.Open(
      [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite
    )
    $existing = $selfSignedRootStore.Certificates.Find(
      [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
      $selfSignedPinnedCertificate.Thumbprint,
      $false
    )
    if ($existing.Count -ne 0) {
      throw 'The self-signed Windows release certificate unexpectedly already exists in CurrentUser\Root.'
    }
    $selfSignedRootStore.Add($selfSignedPinnedCertificate)
    $selfSignedRootAdded = $true
    Sync-CurrentUserCertificateChainEngine
  }

  $dumpbin = Find-VisualStudioTool -Name 'dumpbin.exe'
  $signtool = if ($RequireAuthenticode) {
    Find-VisualStudioTool -Name 'signtool.exe'
  } else {
    $null
  }

$allowedSystemImports = [System.Collections.Generic.HashSet[string]]::new(
  [System.StringComparer]::OrdinalIgnoreCase
)
@(
  'advapi32.dll',
  'bcrypt.dll',
  'bcryptprimitives.dll',
  'cfgmgr32.dll',
  'combase.dll',
  'comctl32.dll',
  'comdlg32.dll',
  'crypt32.dll',
  'd2d1.dll',
  'd3d11.dll',
  'dcomp.dll',
  'dwmapi.dll',
  'dwrite.dll',
  'dxgi.dll',
  'gdi32.dll',
  'hid.dll',
  'imm32.dll',
  'iphlpapi.dll',
  'kernel32.dll',
  'ncrypt.dll',
  'ntdll.dll',
  'ole32.dll',
  'oleaut32.dll',
  'opengl32.dll',
  'powrprof.dll',
  'propsys.dll',
  'rpcrt4.dll',
  'secur32.dll',
  'setupapi.dll',
  'shell32.dll',
  'shcore.dll',
  'shlwapi.dll',
  'uiautomationcore.dll',
  'user32.dll',
  'userenv.dll',
  'uxtheme.dll',
  'version.dll',
  'winhttp.dll',
  'winmm.dll',
  'winspool.drv',
  'wintrust.dll',
  'ws2_32.dll'
) | ForEach-Object {
  [void]$allowedSystemImports.Add($_)
}

foreach ($candidate in $Path) {
  $binary = (Resolve-Path -LiteralPath $candidate).Path
  if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
    throw "Windows release binary is missing: $candidate"
  }

  $dependencyOutput = & $dumpbin /dependents $binary | Out-String
  if ($LASTEXITCODE -ne 0) {
    throw "Unable to inspect Windows dependencies for $binary."
  }
  $imports = [regex]::Matches(
    $dependencyOutput,
    '(?im)^\s+([A-Za-z0-9_.-]+\.(?:dll|drv))\s*$'
  ) | ForEach-Object {
    $_.Groups[1].Value.ToLowerInvariant()
  } | Sort-Object -Unique
  if (-not $imports) {
    throw "$binary has no inspectable Windows imports."
  }

  $nonAllowlistedImports = [System.Collections.Generic.List[string]]::new()
  foreach ($import in $imports) {
    if ($import -match '^(api-ms-win-crt-|ucrtbase|vcruntime|msvcp)') {
      throw "$binary depends on a dynamic Microsoft CRT: $import"
    }
    if ($import -match '^(api|ext)-ms-win-[a-z0-9_.-]+\.dll$') {
      continue
    }
    if (-not $allowedSystemImports.Contains($import)) {
      [void]$nonAllowlistedImports.Add($import)
      continue
    }
    $systemPath = Join-Path $env:SystemRoot "System32\$import"
    if (-not (Test-Path -LiteralPath $systemPath -PathType Leaf)) {
      throw "$binary imports $import, but it is absent from System32."
    }
  }
  if ($nonAllowlistedImports.Count -gt 0) {
    throw "$binary imports non-allowlisted DLLs: $($nonAllowlistedImports -join ', ')"
  }

  if ($RequireAuthenticode) {
    $signature = Get-AuthenticodeSignature -LiteralPath $binary
    if ($signature.SignatureType.ToString() -ne 'Authenticode') {
      throw "$binary does not have an embedded Authenticode signature."
    }
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
      throw "$binary does not have a valid Authenticode signature: $($signature.StatusMessage)"
    }
    if ($null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -ne $ExpectedPublisher) {
      throw "$binary signer subject does not match the approved publisher."
    }
    if ($null -eq $signature.TimeStamperCertificate) {
      throw "$binary has no RFC 3161 timestamp certificate."
    }
    if ($AllowSelfSigned -and
        ($signature.SignerCertificate.Subject -ne $signature.SignerCertificate.Issuer -or
         (Get-CertificateSha256 -Certificate $signature.SignerCertificate) -ne
           $ExpectedCertificateSha256 -or
         -not (Test-ByteArraysEqual `
           -Left $signature.SignerCertificate.RawData `
           -Right $selfSignedPinnedCertificateRaw))) {
      throw "$binary was not signed by the exact pinned self-signed certificate."
    }
    if (-not (Test-CertificateEku `
      -Certificate $signature.TimeStamperCertificate `
      -Oid '1.3.6.1.5.5.7.3.8')) {
      throw "$binary timestamp certificate lacks the time-stamping EKU."
    }
    & $signtool verify /pa /all /v /tw $binary | Out-Host
    if ($LASTEXITCODE -ne 0) {
      throw "SignTool rejected the Authenticode signature on $binary."
    }
    [void]$verifiedBinaries.Add($binary)
    if ($AllowSelfSigned) {
      $binarySha256 = (Get-FileHash `
        -LiteralPath $binary `
        -Algorithm SHA256).Hash.ToLowerInvariant()
      $timestampCertificateSha256 = Get-CertificateSha256 `
        -Certificate $signature.TimeStamperCertificate
      [void]$signingEvidenceFiles.Add([ordered]@{
        fileName = [System.IO.Path]::GetFileName($binary)
        sha256 = $binarySha256
        signatureType = 'Authenticode'
        timestampCertificateSha256 = $timestampCertificateSha256
      })
    }
  }
}

Write-Output 'Windows import and Authenticode policy verification passed.'
} finally {
  try {
    if ($selfSignedRootAdded -and $null -ne $selfSignedRootStore) {
      $selfSignedRootStore.Remove($selfSignedPinnedCertificate)
      Sync-CurrentUserCertificateChainEngine
    }
  } finally {
    if ($null -ne $selfSignedRootStore) {
      $selfSignedRootStore.Close()
      $selfSignedRootStore.Dispose()
    }
    if ($null -ne $selfSignedPinnedCertificate) {
      $selfSignedPinnedCertificate.Dispose()
    }
  }
}

if ($AllowSelfSigned) {
  if ([string]::IsNullOrWhiteSpace($selfSignedRootThumbprint) -or
      (Test-Path -LiteralPath "Cert:\CurrentUser\Root\$selfSignedRootThumbprint")) {
    throw 'The temporary self-signed trust anchor was not completely removed.'
  }
  foreach ($binary in $verifiedBinaries) {
    $untrustedSignature = Get-AuthenticodeSignature -LiteralPath $binary
    $acceptableUntrustedStatuses = @(
      [System.Management.Automation.SignatureStatus]::NotTrusted,
      [System.Management.Automation.SignatureStatus]::UnknownError
    )
    if ($untrustedSignature.Status -notin $acceptableUntrustedStatuses -or
        $untrustedSignature.SignatureType.ToString() -ne 'Authenticode' -or
        $null -eq $untrustedSignature.SignerCertificate -or
        $null -eq $untrustedSignature.TimeStamperCertificate -or
        $untrustedSignature.SignerCertificate.Subject -ne $ExpectedPublisher -or
        $untrustedSignature.SignerCertificate.Issuer -ne $ExpectedPublisher -or
        (Get-CertificateSha256 -Certificate $untrustedSignature.SignerCertificate) -ne
          $ExpectedCertificateSha256 -or
        -not (Test-ByteArraysEqual `
          -Left $untrustedSignature.SignerCertificate.RawData `
          -Right $selfSignedPinnedCertificateRaw)) {
      throw "$binary did not return to the expected intact-but-untrusted self-signed state."
    }
  }
  Write-Output 'Self-signed trust was removed; signatures remain intact but are not publicly trusted.'
}

if (-not [string]::IsNullOrWhiteSpace($EvidenceOutput)) {
  $evidencePath = [System.IO.Path]::GetFullPath($EvidenceOutput)
  if (Test-Path -LiteralPath $evidencePath) {
    throw 'Refusing to replace an existing Windows signing-evidence file.'
  }
  $evidenceParent = [System.IO.Path]::GetDirectoryName($evidencePath)
  if ([string]::IsNullOrWhiteSpace($evidenceParent) -or
      -not (Test-Path -LiteralPath $evidenceParent -PathType Container)) {
    throw 'The Windows signing-evidence parent directory does not exist.'
  }
  $resolvedEvidenceParent = (Resolve-Path -LiteralPath $evidenceParent).Path
  $candidateEvidencePath = Join-Path `
    $resolvedEvidenceParent `
    [System.IO.Path]::GetFileName($evidencePath)
  if ($candidateEvidencePath -ne $evidencePath) {
    throw 'The Windows signing-evidence path does not have a stable parent.'
  }
  $evidenceFileName = [System.IO.Path]::GetFileName($evidencePath)
  if ([string]::IsNullOrWhiteSpace($evidenceFileName) -or
      $evidenceFileName -in @('.', '..') -or
      $evidenceFileName.IndexOfAny(
        [System.IO.Path]::GetInvalidFileNameChars()
      ) -ge 0) {
    throw 'The Windows signing-evidence filename is invalid.'
  }
  $uniqueEvidenceNames = @(
    $signingEvidenceFiles | ForEach-Object { $_.fileName } | Sort-Object -Unique
  )
  if ($signingEvidenceFiles.Count -ne $verifiedBinaries.Count -or
      $uniqueEvidenceNames.Count -ne $signingEvidenceFiles.Count -or
      $signingEvidenceFiles.Count -eq 0) {
    throw 'The verified Windows signing-evidence inventory is incomplete or ambiguous.'
  }
  $evidence = [ordered]@{
    schemaVersion = 1
    codeSigningStatus = 'selfSignedAuthenticode'
    certificateTrust = 'notPubliclyTrusted'
    timestampStatus = 'rfc3161Sha256'
    signerSubject = $ExpectedPublisher
    signerCertificateSha256 = $ExpectedCertificateSha256
    files = @($signingEvidenceFiles)
  }
  $evidenceJson = $evidence | ConvertTo-Json -Depth 4
  $evidenceStream = [System.IO.File]::Open(
    $evidencePath,
    [System.IO.FileMode]::CreateNew,
    [System.IO.FileAccess]::Write,
    [System.IO.FileShare]::None
  )
  try {
    $writer = [System.IO.StreamWriter]::new(
      $evidenceStream,
      [System.Text.UTF8Encoding]::new($false)
    )
    try {
      $writer.Write("$evidenceJson`n")
      $writer.Flush()
      $evidenceStream.Flush($true)
    } finally {
      $writer.Dispose()
    }
  } finally {
    $evidenceStream.Dispose()
  }
  Write-Output "Wrote exact Windows signing evidence to $evidencePath."
}
