[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-p]{32}$')]
    [string[]] $ExtensionId,

    [ValidateSet('all', 'chrome', 'chromium', 'edge', 'brave', 'vivaldi', 'opera')]
    [string[]] $Browser = @('all'),

    [string] $NativeHost
)

$ErrorActionPreference = 'Stop'
$HostName = 'com.denuoweb.hns_dane_browser'
$ManualRootMarkerValue = 'HNS DANE Browser manual installer root v1'
$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepositoryRoot = [IO.Path]::GetFullPath((Join-Path $ScriptDirectory '..\..'))
$NoticeSource = Join-Path $RepositoryRoot 'extension\THIRD_PARTY_NOTICES.txt'
$ProductLicenseSource = Join-Path $RepositoryRoot 'LICENSE'
if (-not $NativeHost) {
    $NativeHost = Join-Path $RepositoryRoot 'rust\target\release\hns-chromium-native-host.exe'
}
if (-not $env:LOCALAPPDATA -or -not [IO.Path]::IsPathRooted($env:LOCALAPPDATA)) {
    throw 'LOCALAPPDATA must identify an absolute per-user application-data directory.'
}
$InstallRoot = Join-Path $env:LOCALAPPDATA 'HnsDaneBrowser\Chromium'
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
$ManualRootMarker = Join-Path $InstallRoot '.manual-install-root'
if (Test-Path -LiteralPath $InstallRoot) {
    $RootItem = Get-Item -LiteralPath $InstallRoot -Force
    if (-not $RootItem.PSIsContainer -or
        ($RootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Refusing unsafe manual install root: $InstallRoot"
    }
    if (Test-Path -LiteralPath $ManualRootMarker) {
        $MarkerItem = Get-Item -LiteralPath $ManualRootMarker -Force
        if ($MarkerItem.PSIsContainer -or
            ($MarkerItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            (Get-Content -LiteralPath $ManualRootMarker -Raw).TrimEnd() -ne
                $ManualRootMarkerValue) {
            throw 'Refusing an invalid manual-install ownership marker.'
        }
    } elseif (Get-ChildItem -LiteralPath $InstallRoot -Force | Select-Object -First 1) {
        throw 'Refusing a non-empty manual install root without its ownership marker.'
    }
    $RedirectedPath = Get-ChildItem -LiteralPath $InstallRoot -Force -Recurse |
        Where-Object {
            $_.Attributes -band [IO.FileAttributes]::ReparsePoint
        } |
        Select-Object -First 1
    if ($RedirectedPath) {
        throw "Refusing a manual install root that contains a reparse point: $($RedirectedPath.FullName)"
    }
}
New-Item -ItemType Directory -Force -Path $DataDirectory, $BinaryDirectory, $LicenseDirectory | Out-Null
[IO.File]::WriteAllText(
    $ManualRootMarker,
    "$ManualRootMarkerValue$([Environment]::NewLine)",
    [Text.UTF8Encoding]::new($false)
)
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
    chrome   = @('Software\Google\Chrome\NativeMessagingHosts')
    chromium = @('Software\Chromium\NativeMessagingHosts')
    edge     = @('Software\Microsoft\Edge\NativeMessagingHosts')
    brave    = @(
        'Software\BraveSoftware\Brave-Browser\NativeMessagingHosts',
        'Software\Google\Chrome\NativeMessagingHosts'
    )
    vivaldi  = @(
        'Software\Vivaldi\NativeMessagingHosts',
        'Software\Google\Chrome\NativeMessagingHosts'
    )
    # Opera documents the Google Chrome native-messaging registry contract.
    opera    = @('Software\Google\Chrome\NativeMessagingHosts')
}
$SelectedBrowsers = if ($Browser -contains 'all') { $RegistryRoots.Keys } else { $Browser }
$SelectedRegistryRoots = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase
)
foreach ($Name in $SelectedBrowsers) {
    foreach ($RegistryRoot in $RegistryRoots[$Name]) {
        [void] $SelectedRegistryRoots.Add($RegistryRoot)
    }
}
$RegistryViews = @(
    [Microsoft.Win32.RegistryView]::Registry32,
    [Microsoft.Win32.RegistryView]::Registry64
)
foreach ($RegistryRoot in $SelectedRegistryRoots) {
    $Registration = "$RegistryRoot\$HostName"
    foreach ($RegistryView in $RegistryViews) {
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::CurrentUser,
            $RegistryView
        )
        try {
            $ExistingKey = $BaseKey.OpenSubKey($Registration, $false)
            if ($ExistingKey) {
                try {
                    $ExistingValue = $ExistingKey.GetValue(
                        '',
                        $null,
                        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                    )
                } finally {
                    $ExistingKey.Close()
                }
                if ($null -ne $ExistingValue -and
                    $ExistingValue -ne $ManifestPath) {
                    throw "Refusing to replace a foreign native-messaging registration in $RegistryView view: HKCU\$Registration"
                }
            }
        } finally {
            $BaseKey.Close()
        }
    }
}
foreach ($RegistryRoot in $SelectedRegistryRoots) {
    $Registration = "$RegistryRoot\$HostName"
    foreach ($RegistryView in $RegistryViews) {
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::CurrentUser,
            $RegistryView
        )
        try {
            $RegistrationKey = $BaseKey.CreateSubKey(
                $Registration,
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
            )
            try {
                $RegistrationKey.SetValue(
                    '',
                    $ManifestPath,
                    [Microsoft.Win32.RegistryValueKind]::String
                )
            } finally {
                $RegistrationKey.Close()
            }
        } finally {
            $BaseKey.Close()
        }
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

Write-Host "Installed Shakescape native host for: $($SelectedBrowsers -join ', ')"
Write-Host "Local CA SHA-256: $($CaStatus.certificateSha256)"
