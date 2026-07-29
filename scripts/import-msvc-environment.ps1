[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('x64', 'arm64')]
  [string]$Architecture
)

$ErrorActionPreference = 'Stop'
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

$installation = & $vswhere -latest -products '*' -property installationPath
if (-not $installation) {
  throw 'Unable to locate a Visual Studio installation.'
}
$developerShell = Join-Path $installation 'Common7\Tools\VsDevCmd.bat'
if (-not (Test-Path -LiteralPath $developerShell -PathType Leaf)) {
  throw 'Unable to locate VsDevCmd.bat.'
}

$targetArchitecture = if ($Architecture -eq 'arm64') { 'arm64' } else { 'amd64' }
$environmentLines = & cmd.exe /s /c (
  "`"$developerShell`" -no_logo -arch=$targetArchitecture " +
  '-host_arch=amd64 && set'
)
if ($LASTEXITCODE -ne 0) {
  throw "Visual Studio failed to configure the $Architecture build environment."
}
foreach ($line in $environmentLines) {
  if ($line -match '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
    Set-Item -Path "Env:$($Matches[1])" -Value $Matches[2]
  }
}

if (-not $env:VCToolsInstallDir -or -not $env:WindowsSdkDir) {
  throw 'The Visual Studio C++ environment is incomplete.'
}
