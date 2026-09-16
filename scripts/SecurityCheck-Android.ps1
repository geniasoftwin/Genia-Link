$ErrorActionPreference = 'Stop'
Write-Host 'Genia Link v0.3.1 RC4 Android stability - build + protocol/security checks...'
& (Join-Path $PSScriptRoot 'SecurityCheck.ps1') -IncludeAndroid
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$root = Split-Path -Parent $PSScriptRoot

$installScriptPath = Join-Path $root 'scripts\Install-Android.ps1'
$installBytes = [System.IO.File]::ReadAllBytes($installScriptPath)
if (@($installBytes | Where-Object { $_ -gt 0x7F }).Count -gt 0) {
    throw 'Install-Android.ps1 must remain ASCII-only for Windows PowerShell 5.1 compatibility.'
}
$tokens = $null
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($installScriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) {
    $messages = ($parseErrors | ForEach-Object { $_.Message }) -join '; '
    throw "Install-Android.ps1 has PowerShell parse errors: $messages"
}

$manifestPath = Join-Path $root 'src\GeniaLink.Android\AndroidManifest.xml'
[xml]$manifest = Get-Content -LiteralPath $manifestPath -Raw
$androidNs = 'http://schemas.android.com/apk/res/android'
$permissions = @($manifest.manifest.'uses-permission' | ForEach-Object { $_.GetAttribute('name', $androidNs) })
$expectedPermissions = @(
    'android.permission.INTERNET',
    'android.permission.ACCESS_NETWORK_STATE',
    'android.permission.CHANGE_NETWORK_STATE',
    'android.permission.POST_NOTIFICATIONS',
    'android.permission.FOREGROUND_SERVICE',
    'android.permission.FOREGROUND_SERVICE_DATA_SYNC',
    'android.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE',
    'android.permission.WAKE_LOCK',
    'android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS'
)
$unexpected = @($permissions | Where-Object { $_ -and $_ -notin $expectedPermissions })
$missing = @($expectedPermissions | Where-Object { $_ -notin $permissions })
if ($unexpected.Count -gt 0) {
    throw "Unexpected Android permission(s): $($unexpected -join ', ')"
}
if ($missing.Count -gt 0) {
    throw "Required Android permission(s) missing: $($missing -join ', ')"
}

$application = $manifest.manifest.application
if ($application.GetAttribute('allowBackup', $androidNs) -ne 'false') {
    throw 'Android allowBackup must remain false.'
}
if ($application.GetAttribute('usesCleartextTraffic', $androidNs) -ne 'false') {
    throw 'Android usesCleartextTraffic must remain false.'
}
if (-not $application.GetAttribute('label', $androidNs)) {
    throw 'Android application label is missing.'
}
if (-not $application.GetAttribute('icon', $androidNs)) {
    throw 'Android application icon is missing.'
}

$stringsPath = Join-Path $root 'src\GeniaLink.Android\Resources\values\strings.xml'
[xml]$stringsXml = Get-Content -LiteralPath $stringsPath -Raw
$appName = @($stringsXml.resources.string | Where-Object { $_.name -eq 'app_name' } | Select-Object -First 1)
if ($appName.Count -ne 1 -or [string]$appName[0].InnerText -ne 'Genia Link') {
    throw 'Android app_name resource must be exactly "Genia Link".'
}

$requiredIconResources = @(
    'src\GeniaLink.Android\Resources\drawable\ic_launcher_foreground.xml',
    'src\GeniaLink.Android\Resources\drawable\ic_transfer_notification.xml',
    'src\GeniaLink.Android\Resources\drawable-nodpi\genialink_logo.png',
    'src\GeniaLink.Android\Resources\mipmap-anydpi-v26\ic_launcher.xml',
    'src\GeniaLink.Android\Resources\mipmap-anydpi-v26\ic_launcher_round.xml'
)
foreach ($relativePath in $requiredIconResources) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $relativePath) -PathType Leaf)) {
        throw "Required Android icon resource is missing: $relativePath"
    }
}


$launcherForegroundPath = Join-Path $root 'src\GeniaLink.Android\Resources\drawable\ic_launcher_foreground.xml'
$launcherForegroundText = Get-Content -LiteralPath $launcherForegroundPath -Raw
if ($launcherForegroundText -notmatch '@drawable/genialink_logo') {
    throw 'Android adaptive launcher foreground must use the approved Genia Link artwork.'
}

$androidProjectText = Get-Content -LiteralPath (Join-Path $root 'src\GeniaLink.Android\GeniaLink.Android.csproj') -Raw
if ($androidProjectText -notmatch '<ApplicationDisplayVersion>0\.3\.1-rc4</ApplicationDisplayVersion>' -or
    $androidProjectText -notmatch '<ApplicationVersion>15</ApplicationVersion>') {
    throw 'Android app/display versions must identify RC4.'
}


$foregroundServicePath = Join-Path $root 'src\GeniaLink.Android\Services\TransferForegroundService.cs'
$foregroundServiceText = Get-Content -LiteralPath $foregroundServicePath -Raw
if ($foregroundServiceText -notmatch 'ForegroundServiceType\s*=\s*ForegroundService\.TypeDataSync' -or
    $foregroundServiceText -notmatch 'StartForeground\([^\r\n]+ForegroundService\.TypeDataSync' -or
    $foregroundServiceText -notmatch 'WakeLockFlags\.Partial') {
    throw 'Android transfer foreground service must remain dataSync + PARTIAL_WAKE_LOCK.'
}

$availabilityServicePath = Join-Path $root 'src\GeniaLink.Android\Services\LocalAvailabilityService.cs'
$availabilityServiceText = Get-Content -LiteralPath $availabilityServicePath -Raw
$deviceNamingPath = Join-Path $root 'src\GeniaLink.Android\Services\AndroidDeviceNaming.cs'
if (-not (Test-Path -LiteralPath $deviceNamingPath -PathType Leaf)) {
    throw 'Android device-kind helper is missing.'
}
$deviceNamingText = Get-Content -LiteralPath $deviceNamingPath -Raw
if ($availabilityServiceText -notmatch 'ForegroundServiceType\s*=\s*ForegroundService\.TypeConnectedDevice' -or
    $availabilityServiceText -notmatch 'StartForeground\([^\r\n]+ForegroundService\.TypeConnectedDevice' -or
    $availabilityServiceText -notmatch 'RegisterNetworkCallback' -or
    $availabilityServiceText -notmatch '_identity\.DeviceKind' -or
    $availabilityServiceText -notmatch 'OnAuthenticatedPeerSeenCore' -or
    $availabilityServiceText -notmatch 'UpdateTrustedEndpointCore' -or
    $deviceNamingText -notmatch 'GetDeviceKind' -or
    $deviceNamingText -notmatch 'DeviceKind\.AndroidPhone' -or
    $deviceNamingText -notmatch 'DeviceKind\.AndroidTablet') {
    throw 'Android background availability service must remain connectedDevice + network-aware, derive Android device kind through identity, and persist endpoints only from authenticated sessions.'
}

$alwaysReadyPath = Join-Path $root 'src\GeniaLink.Android\Services\AlwaysReadySettings.cs'
if (-not (Test-Path -LiteralPath $alwaysReadyPath -PathType Leaf)) {
    throw 'Android Always Ready settings helper is missing.'
}
$alwaysReadyText = Get-Content -LiteralPath $alwaysReadyPath -Raw
if ($alwaysReadyText -notmatch 'IsIgnoringBatteryOptimizations' -or
    $alwaysReadyText -notmatch 'ActionRequestIgnoreBatteryOptimizations' -or
    $alwaysReadyText -notmatch 'ActionIgnoreBatteryOptimizationSettings') {
    throw 'Android Always Ready mode must use the official battery-optimization APIs.'
}
if ($alwaysReadyText -notmatch 'SharedPreferences' -or
    $alwaysReadyText -notmatch 'always_ready_user_enabled_v3' -or
    $alwaysReadyText -notmatch 'IsEnabled\(context\)\s*&&\s*IsBatteryOptimizationExempt\(context\)') {
    throw 'Android Always Ready must require both explicit user opt-in and the real system battery-optimization exemption.'
}

Write-Host 'ANDROID MANIFEST/BRANDING/BACKGROUND CHECK PASSED'

$mainActivityPath = Join-Path $root 'src\GeniaLink.Android\MainActivity.cs'
$mainActivityText = Get-Content -LiteralPath $mainActivityPath -Raw
$remoteBrowserLayoutPath = Join-Path $root 'src\GeniaLink.Android\Resources\layout\remote_browser_row.xml'
$remoteBrowserBackgroundPath = Join-Path $root 'src\GeniaLink.Android\Resources\drawable\remote_browser_row_background.xml'
$remoteBrowserSelectedPath = Join-Path $root 'src\GeniaLink.Android\Resources\drawable\remote_browser_row_selected_background.xml'
if (-not (Test-Path -LiteralPath $remoteBrowserLayoutPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $remoteBrowserBackgroundPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $remoteBrowserSelectedPath -PathType Leaf)) {
    throw 'Polished Android remote-browser resources are missing.'
}
$remoteBrowserLayoutText = Get-Content -LiteralPath $remoteBrowserLayoutPath -Raw
if ($remoteBrowserLayoutText -notmatch 'remote_browser_check' -or
    $remoteBrowserLayoutText -notmatch 'remote_browser_detail' -or
    $remoteBrowserLayoutText -notmatch '@drawable/remote_browser_row_background') {
    throw 'Android remote-browser rows must keep explicit selection, metadata, and polished local styling.'
}
if ($mainActivityText -notmatch 'Intent\.ActionSend' -or
    $mainActivityText -notmatch 'Intent\.ActionSendMultiple' -or
    $mainActivityText -notmatch 'DataMimeType\s*=\s*"\*/\*"') {
    throw 'Android Share target filters are missing.'
}
if ($mainActivityText -notmatch '_staleDevices' -or
    $mainActivityText -notmatch 'last known LAN endpoint' -or
    $mainActivityText -notmatch 'selected\.IdentityMatches' -or
    $mainActivityText -notmatch 'AndroidFileTransferClient\.SendFilesAsync' -or
    $mainActivityText -notmatch 'RestorePersistedTrustedEndpoints' -or
    $mainActivityText -notmatch 'TryPersistVerifiedEndpoint' -or
    $mainActivityText -notmatch 'OnBackgroundTrustedEndpointSaved' -or
    $mainActivityText -notmatch 'RemoteFolderClient\.ListFilesAsync' -or
    $mainActivityText -notmatch 'RemoteFolderClient\.RequestDownloadAsync' -or
    $mainActivityText -notmatch 'RemoteFolderClient\.GetPreviewAsync' -or
    $mainActivityText -notmatch 'RemoteBrowserIndex\.BuildDirectory' -or
    $mainActivityText -notmatch 'ShowRemotePreviewAsync' -or
    $mainActivityText -notmatch 'OfferReplaceSameNameTrustedDevice' -or
    $mainActivityText -notmatch 'SetCustomTitle' -or
    $mainActivityText -notmatch '_browseButton') {
    throw 'Android sleeping trusted-peer fallback and remote Genia Link folder UI must retain identity checks and authenticated clients.'
}

$androidOnDeviceSeenMatch = [regex]::Match(
    $mainActivityText,
    'private void OnDeviceSeen\(DiscoveredDevice device\).*?private void OnDeviceExpired',
    [System.Text.RegularExpressions.RegexOptions]::Singleline)
if (-not $androidOnDeviceSeenMatch.Success -or $androidOnDeviceSeenMatch.Value -match 'UpdateVerifiedEndpoint') {
    throw 'UDP discovery must not persist a trusted endpoint on Android.'
}

$persistEndpointMatch = [regex]::Match(
    $mainActivityText,
    'private void TryPersistVerifiedEndpoint\(DiscoveredDevice device, string source\).*?private void OnBackgroundTrustedEndpointSaved',
    [System.Text.RegularExpressions.RegexOptions]::Singleline)
if (-not $persistEndpointMatch.Success -or
    $persistEndpointMatch.Value -notmatch 'RunOnUiThreadIfAlive\(\(\) => ApplyAuthenticatedEndpointToUi') {
    throw 'Authenticated endpoint persistence must marshal Android UI refreshes to the main thread.'
}

$androidTrustedStorePath = Join-Path $root 'src\GeniaLink.Android\Services\TrustedDeviceStore.cs'
$androidTrustedStoreText = Get-Content -LiteralPath $androidTrustedStorePath -Raw
if ($androidTrustedStoreText -notmatch 'LastVerifiedAddress' -or
    $androidTrustedStoreText -notmatch 'UpdateVerifiedEndpoint' -or
    $androidTrustedStoreText -notmatch 'LocalNetworkPolicy\.IsAllowedAddress') {
    throw 'Android trusted-device store must validate persistent authenticated endpoint metadata.'
}

$androidServerPath = Join-Path $root 'src\GeniaLink.Android\Services\AndroidFileTransferServer.cs'
$androidServerText = Get-Content -LiteralPath $androidServerPath -Raw
if ($androidServerText -notmatch 'CreateResumeKey' -or
    $androidServerText -notmatch 'CreateFileAccept\(offer\.TransferId, resumeOffset\)' -or
    $androidServerText -notmatch 'MaxPendingResumeRows' -or
    $androidServerText -notmatch 'authenticatedPeerSeen\?\.Invoke\(remoteDeviceId, remoteAddress\)' -or
    $androidServerText -notmatch 'remoteDeviceId != handshake\.RemoteDeviceId' -or
    $androidServerText -notmatch 'MessageType\.BrowseRequest' -or
    $androidServerText -notmatch 'MessageType\.PreviewRequest' -or
    $androidServerText -notmatch 'RemotePreviewPolicy' -or
    $androidServerText -notmatch 'DownloadRootRelativePath' -or
    $androidServerText -notmatch 'TryGetSharedRelativeDirectory' -or
    $androidServerText -notmatch 'CreateDownloadRequestAccepted' -or
    $androidServerText -notmatch 'AndroidFileTransferClient\.SendFilesAsync' -or
    $androidServerText -notmatch 'WakeLockFlags\.Partial' -or
    $androidServerText -notmatch 'SendRequestedDocumentsAfterCommandSessionAsync') {
    throw 'Android resumable receive/remote-folder protections are missing or no longer root-confined/authenticated.'
}

$resumeIndexPath = Join-Path $root 'src\GeniaLink.Android\Services\AndroidResumeIndex.cs'
if (-not (Test-Path -LiteralPath $resumeIndexPath -PathType Leaf)) {
    throw 'Android private resume index implementation is missing.'
}
$resumeIndexText = Get-Content -LiteralPath $resumeIndexPath -Raw
if ($resumeIndexText -notmatch 'resume-index\.json' -or
    $androidServerText -notmatch 'resumeIndex\.GetMatching' -or
    $androidServerText -notmatch 'resumeIndex\.Upsert') {
    throw 'Android app-private MediaStore resume index protections are missing.'
}

foreach ($scriptName in @('Install-SendTo.ps1', 'Remove-SendTo.ps1', 'Build-Android-Apk.ps1')) {
    $scriptPath = Join-Path $root ("scripts\" + $scriptName)
    $scriptBytes = [System.IO.File]::ReadAllBytes($scriptPath)
    if (@($scriptBytes | Where-Object { $_ -gt 0x7F }).Count -gt 0) {
        throw "$scriptName must remain ASCII-only for Windows PowerShell 5.1 compatibility."
    }
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) {
        throw "$scriptName has PowerShell parse errors."
    }
}

Write-Host 'ANDROID SHARE/RESUME CHECK PASSED'
