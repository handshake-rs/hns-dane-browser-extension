[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-p]{32}$')]
    [string[]] $ExtensionId,

    [ValidateSet('all', 'chrome', 'chromium', 'edge', 'brave', 'vivaldi', 'opera')]
    [string[]] $Browser = @('all'),

    [string] $NativeHost,
    [string] $InstallRoot
)

$ErrorActionPreference = 'Stop'
$HostName = 'com.denuoweb.hns_dane_browser'
$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepositoryRoot = [IO.Path]::GetFullPath((Join-Path $ScriptDirectory '..\..'))
$NoticeSource = Join-Path $RepositoryRoot 'extension\THIRD_PARTY_NOTICES.txt'
$ProductLicenseSource = Join-Path $RepositoryRoot 'LICENSE'
if (-not $NativeHost) {
    $NativeHost = Join-Path $RepositoryRoot 'rust\target\release\hns-chromium-native-host.exe'
}
if (-not $InstallRoot) {
    $InstallRoot = Join-Path $env:LOCALAPPDATA 'HnsDaneBrowser\Chromium'
}
$NativeHost = [IO.Path]::GetFullPath($NativeHost)
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
if (-not (Test-Path -LiteralPath $NativeHost -PathType Leaf)) {
    throw "Release native host is missing: $NativeHost"
}
if (-not (Test-Path -LiteralPath $NoticeSource -PathType Leaf)) {
    throw "Third-party notices are missing: $NoticeSource"
}
if (-not (Test-Path -LiteralPath $ProductLicenseSource -PathType Leaf)) {
    throw "Product license is missing: $ProductLicenseSource"
}

$DataDirectory = Join-Path $InstallRoot 'data'
$BinaryDirectory = Join-Path $InstallRoot 'bin'
$LicenseDirectory = Join-Path $InstallRoot 'licenses'
$InstalledHost = Join-Path $BinaryDirectory 'hns-chromium-native-host.exe'
$ManifestPath = Join-Path $InstallRoot "$HostName.json"
New-Item -ItemType Directory -Force -Path $DataDirectory, $BinaryDirectory, $LicenseDirectory | Out-Null
Copy-Item -LiteralPath $NativeHost -Destination $InstalledHost -Force
Copy-Item -LiteralPath $NoticeSource -Destination (Join-Path $LicenseDirectory 'THIRD_PARTY_NOTICES.txt') -Force
Copy-Item -LiteralPath $ProductLicenseSource -Destination (Join-Path $LicenseDirectory 'LICENSE') -Force

$ManifestArguments = @('--print-host-manifest')
foreach ($Id in $ExtensionId) {
    $ManifestArguments += '--extension-id'
    $ManifestArguments += $Id
}
$Manifest = & $InstalledHost @ManifestArguments
if ($LASTEXITCODE -ne 0 -or -not $Manifest) {
    throw 'The native host failed to produce its registration manifest.'
}
[IO.File]::WriteAllText(
    $ManifestPath,
    (($Manifest -join [Environment]::NewLine) + [Environment]::NewLine),
    [Text.UTF8Encoding]::new($false)
)

$RegistryRoots = @{
    chrome   = @('HKCU:\Software\Google\Chrome\NativeMessagingHosts')
    chromium = @('HKCU:\Software\Chromium\NativeMessagingHosts')
    edge     = @('HKCU:\Software\Microsoft\Edge\NativeMessagingHosts')
    brave    = @(
        'HKCU:\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts',
        'HKCU:\Software\Google\Chrome\NativeMessagingHosts'
    )
    vivaldi  = @(
        'HKCU:\Software\Vivaldi\NativeMessagingHosts',
        'HKCU:\Software\Google\Chrome\NativeMessagingHosts'
    )
    # Opera documents the Google Chrome native-messaging registry contract.
    opera    = @('HKCU:\Software\Google\Chrome\NativeMessagingHosts')
}
$SelectedBrowsers = if ($Browser -contains 'all') { $RegistryRoots.Keys } else { $Browser }
foreach ($Name in $SelectedBrowsers) {
    foreach ($RegistryRoot in $RegistryRoots[$Name]) {
        $Registration = Join-Path $RegistryRoot $HostName
        New-Item -Force -Path $Registration | Out-Null
        Set-Item -Path $Registration -Value $ManifestPath
    }
}

$CaStatusText = & $InstalledHost --data-dir $DataDirectory --ca-info
if ($LASTEXITCODE -ne 0) {
    throw 'The native host failed to initialize its local CA.'
}
$CaStatus = $CaStatusText | ConvertFrom-Json
if ($CaStatus.certificateSha1 -notmatch '^[0-9a-f]{40}$' -or
    $CaStatus.certificateSha256 -notmatch '^[0-9a-f]{64}$' -or
    -not (Test-Path -LiteralPath $CaStatus.certificatePath -PathType Leaf)) {
    throw 'The native host returned invalid local-CA metadata.'
}

& certutil.exe -user -delstore Root $CaStatus.certificateSha1 *> $null
& certutil.exe -user -addstore Root $CaStatus.certificatePath
if ($LASTEXITCODE -ne 0) {
    throw 'Windows rejected the per-user local CA trust installation.'
}

# The extension stays blocked until trust installation succeeds and this
# explicit marker is written.
& $InstalledHost --data-dir $DataDirectory --mark-ca-installed
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to record the completed local CA installation.'
}

Write-Host "Installed HNS DANE Browser native host for: $($SelectedBrowsers -join ', ')"
Write-Host "Local CA SHA-256: $($CaStatus.certificateSha256)"
