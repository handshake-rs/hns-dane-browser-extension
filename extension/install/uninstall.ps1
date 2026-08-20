[CmdletBinding()]
param(
    [ValidateSet('all')]
    [string[]] $Browser = @('all')
)

$ErrorActionPreference = 'Stop'
$HostName = 'com.denuoweb.hns_dane_browser'
$ManualRootMarkerValue = 'HNS DANE Browser manual installer root v1'
if (-not $env:LOCALAPPDATA -or -not [IO.Path]::IsPathRooted($env:LOCALAPPDATA)) {
    throw 'LOCALAPPDATA must identify an absolute per-user application-data directory.'
}
$InstallRoot = Join-Path $env:LOCALAPPDATA 'HnsDaneBrowser\Chromium'
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
$DataDirectory = Join-Path $InstallRoot 'data'
$InstalledHost = Join-Path $InstallRoot 'bin\hns-chromium-native-host.exe'
$ManifestPath = Join-Path $InstallRoot "$HostName.json"
$CaBundlePath = Join-Path $DataDirectory 'chromium-ca\ca-bundle.json'
$CaCertificatePath = Join-Path $DataDirectory 'chromium-ca\hns-dane-browser-local-ca.pem'
$ManualRootMarker = Join-Path $InstallRoot '.manual-install-root'

if (-not (Test-Path -LiteralPath $InstallRoot)) {
    Write-Host "No manual installation exists at the fixed per-user root: $InstallRoot"
    return
}
$RootItem = Get-Item -LiteralPath $InstallRoot -Force
if (-not $RootItem.PSIsContainer -or
    ($RootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw "Refusing unsafe manual install root: $InstallRoot"
}
if (-not (Test-Path -LiteralPath $ManualRootMarker -PathType Leaf)) {
    throw 'Refusing recursive removal without the manual-install ownership marker.'
}
$MarkerItem = Get-Item -LiteralPath $ManualRootMarker -Force
if (($MarkerItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
    (Get-Content -LiteralPath $ManualRootMarker -Raw).TrimEnd() -ne
        $ManualRootMarkerValue) {
    throw 'Refusing recursive removal without the exact manual-install ownership marker.'
}
$RedirectedPath = Get-ChildItem -LiteralPath $InstallRoot -Force -Recurse |
    Where-Object {
        $_.Attributes -band [IO.FileAttributes]::ReparsePoint
    } |
    Select-Object -First 1
if ($RedirectedPath) {
    throw "Refusing recursive removal because the manual install root contains a reparse point: $($RedirectedPath.FullName)"
}

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
    opera    = @('Software\Google\Chrome\NativeMessagingHosts')
}
$SelectedRegistryRoots = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase
)
foreach ($Name in $RegistryRoots.Keys) {
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
            $RegistrationKey = $BaseKey.OpenSubKey($Registration, $false)
            if ($RegistrationKey) {
                try {
                    $RegisteredManifest = $RegistrationKey.GetValue(
                        '',
                        $null,
                        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                    )
                } finally {
                    $RegistrationKey.Close()
                }
                if ($RegisteredManifest -eq $ManifestPath) {
                    $BaseKey.DeleteSubKeyTree($Registration, $false)
                } else {
                    Write-Warning "Leaving foreign native-messaging registration untouched in $RegistryView view: HKCU\$Registration"
                }
            }
        } finally {
            $BaseKey.Close()
        }
    }
}

$CaStatus = $null
if ((Test-Path -LiteralPath $InstalledHost -PathType Leaf) -and
    (Test-Path -LiteralPath $CaBundlePath -PathType Leaf)) {
    try {
        $CaStatus = (& $InstalledHost --data-dir $DataDirectory --ca-info) | ConvertFrom-Json
        & $InstalledHost --data-dir $DataDirectory --clear-ca-installed
    } catch {
        Write-Warning "Unable to read or clear local-CA state: $_"
    }
}
if (-not $CaStatus -and (Test-Path -LiteralPath $CaCertificatePath -PathType Leaf)) {
    try {
        $Certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $CaCertificatePath
        )
        $CaStatus = [PSCustomObject]@{
            certificateSha1 = $Certificate.Thumbprint.ToLowerInvariant()
        }
        $Certificate.Dispose()
    } catch {
        Write-Warning "Unable to identify the persisted local CA: $_"
    }
}
if ($CaStatus -and $CaStatus.certificateSha1 -match '^[0-9a-f]{40}$') {
    & certutil.exe -user -delstore Root $CaStatus.certificateSha1
    if ($LASTEXITCODE -ne 0) {
        Write-Warning 'The local CA was not present in the per-user Windows root store.'
    }
} else {
    Write-Warning 'Exact Windows CA metadata is unavailable; leaving trust entries untouched.'
}

if ($InstallRoot -eq [IO.Path]::GetPathRoot($InstallRoot) -or
    $InstallRoot.Length -lt 16) {
    throw "Refusing to purge unsafe install root: $InstallRoot"
}
if (Test-Path -LiteralPath $InstallRoot) {
    Remove-Item -LiteralPath $InstallRoot -Recurse -Force
}

Write-Host 'Removed the Shakescape native host, trust anchor, registrations, and runtime data.'
