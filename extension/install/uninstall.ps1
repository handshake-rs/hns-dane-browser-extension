[CmdletBinding()]
param(
    [ValidateSet('all')]
    [string[]] $Browser = @('all'),
    [string] $InstallRoot
)

$ErrorActionPreference = 'Stop'
$HostName = 'com.denuoweb.hns_dane_browser'
if (-not $InstallRoot) {
    $InstallRoot = Join-Path $env:LOCALAPPDATA 'HnsDaneBrowser\Chromium'
}
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
$DataDirectory = Join-Path $InstallRoot 'data'
$InstalledHost = Join-Path $InstallRoot 'bin\hns-chromium-native-host.exe'
$ManifestPath = Join-Path $InstallRoot "$HostName.json"
$CaBundlePath = Join-Path $DataDirectory 'chromium-ca\ca-bundle.json'
$CaCertificatePath = Join-Path $DataDirectory 'chromium-ca\hns-dane-browser-local-ca.pem'

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
    opera    = @('HKCU:\Software\Google\Chrome\NativeMessagingHosts')
}
$SelectedBrowsers = $RegistryRoots.Keys
foreach ($Name in $SelectedBrowsers) {
    foreach ($RegistryRoot in $RegistryRoots[$Name]) {
        $Registration = Join-Path $RegistryRoot $HostName
        if (Test-Path -LiteralPath $Registration) {
            $RegisteredManifest = (Get-Item -LiteralPath $Registration).GetValue('')
            if ($RegisteredManifest -eq $ManifestPath) {
                Remove-Item -LiteralPath $Registration -Force
            }
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
    & certutil.exe -user -delstore Root 'HNS DANE Browser Local CA'
    if ($LASTEXITCODE -ne 0) {
        Write-Warning 'No HNS DANE Browser local CA was present in the per-user Windows root store.'
    }
}

$ProfileRoot = [IO.Path]::GetFullPath($env:USERPROFILE)
if ($InstallRoot -eq [IO.Path]::GetPathRoot($InstallRoot) -or
    $InstallRoot -eq $ProfileRoot -or
    $InstallRoot.Length -lt 16) {
    throw "Refusing to purge unsafe install root: $InstallRoot"
}
if (Test-Path -LiteralPath $InstallRoot) {
    Remove-Item -LiteralPath $InstallRoot -Recurse -Force
}

Write-Host 'Removed the HNS DANE Browser native host, trust anchor, registrations, and runtime data.'
