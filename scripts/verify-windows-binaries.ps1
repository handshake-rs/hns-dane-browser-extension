[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string[]]$Path,

  [switch]$RequireAuthenticode,

  [string]$ExpectedPublisher
)

$ErrorActionPreference = 'Stop'

if ($RequireAuthenticode -and [string]::IsNullOrWhiteSpace($ExpectedPublisher)) {
  throw 'ExpectedPublisher is required when RequireAuthenticode is enabled.'
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
  'cfgmgr32.dll',
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

  foreach ($import in $imports) {
    if ($import -match '^(api-ms-win-crt-|ucrtbase|vcruntime|msvcp)') {
      throw "$binary depends on a dynamic Microsoft CRT: $import"
    }
    if ($import -match '^(api|ext)-ms-win-[a-z0-9_.-]+\.dll$') {
      continue
    }
    if (-not $allowedSystemImports.Contains($import)) {
      throw "$binary imports a non-allowlisted DLL: $import"
    }
    $systemPath = Join-Path $env:SystemRoot "System32\$import"
    if (-not (Test-Path -LiteralPath $systemPath -PathType Leaf)) {
      throw "$binary imports $import, but it is absent from System32."
    }
  }

  if ($RequireAuthenticode) {
    $signature = Get-AuthenticodeSignature -FilePath $binary
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
      throw "$binary does not have a valid Authenticode signature: $($signature.StatusMessage)"
    }
    if ($signature.SignerCertificate.Subject -ne $ExpectedPublisher) {
      throw "$binary signer subject does not match the approved publisher."
    }
    if ($null -eq $signature.TimeStamperCertificate) {
      throw "$binary has no RFC 3161 timestamp certificate."
    }
    & $signtool verify /pa /all /v /tw $binary | Out-Host
    if ($LASTEXITCODE -ne 0) {
      throw "SignTool rejected the Authenticode signature on $binary."
    }
  }
}

Write-Output 'Windows import and Authenticode policy verification passed.'
