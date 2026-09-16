param(
    [string]$Serial,
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    [switch]$NoLaunch
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$project = Join-Path $root 'src\GeniaLink.Android\GeniaLink.Android.csproj'
$packageId = 'com.geniapixia.genialink'

function Find-Adb {
    $candidates = @()
    if ($env:ANDROID_SDK_ROOT) {
        $candidates += (Join-Path $env:ANDROID_SDK_ROOT 'platform-tools\adb.exe')
    }
    if ($env:ANDROID_HOME) {
        $candidates += (Join-Path $env:ANDROID_HOME 'platform-tools\adb.exe')
    }
    if ($env:LOCALAPPDATA) {
        $candidates += (Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe')
    }
    $candidates += 'C:\Program Files (x86)\Android\android-sdk\platform-tools\adb.exe'
    $candidates += 'C:\Program Files\Android\android-sdk\platform-tools\adb.exe'

    foreach ($candidate in $candidates | Select-Object -Unique) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return $candidate
        }
    }

    $command = Get-Command adb -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    throw 'adb.exe was not found. Check Android SDK Platform-Tools installation.'
}

function Get-AdbDevices([string]$AdbPath) {
    $lines = & $AdbPath devices 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "adb devices failed with exit code $LASTEXITCODE."
    }

    $result = @()
    foreach ($line in $lines) {
        if ($line -match '^([^\s]+)\s+(device|unauthorized|offline)\b') {
            $result += [PSCustomObject]@{
                Serial = $Matches[1]
                State = $Matches[2]
            }
        }
    }
    return @($result)
}

$adb = Find-Adb
Write-Host "ADB: $adb"
& $adb start-server | Out-Host
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$devices = @(Get-AdbDevices $adb)
if ($Serial) {
    $selected = $devices | Where-Object { $_.Serial -eq $Serial } | Select-Object -First 1
    if (-not $selected) {
        throw "Device '$Serial' was not found in adb devices."
    }
    if ($selected.State -ne 'device') {
        throw "Device '$Serial' is '$($selected.State)'; expected 'device'."
    }
}
else {
    $ready = @($devices | Where-Object { $_.State -eq 'device' })
    if ($ready.Count -eq 0) {
        $details = if ($devices.Count -eq 0) { 'ADB device list is empty' } else { ($devices | ForEach-Object { "$($_.Serial):$($_.State)" }) -join ', ' }
        throw "No ready Android device ($details). Unlock the phone and approve USB debugging."
    }
    if ($ready.Count -gt 1) {
        throw 'More than one ready Android device was found. Run again with -Serial <serial-number>.'
    }
    $Serial = $ready[0].Serial
}

Write-Host "Device: $Serial"
$state = (& $adb -s $Serial get-state 2>&1 | Select-Object -First 1).Trim()
if ($LASTEXITCODE -ne 0 -or $state -ne 'device') {
    throw "ADB target is not ready: '$state'."
}

Write-Host "Building and installing Genia Link Android ($Configuration)..."
$dotnetArgs = @(
    'build',
    $project,
    '-f', 'net10.0-android',
    '-c', $Configuration,
    '-t:Install',
    "-p:AdbTarget=-s $Serial",
    '--nologo'
)
& dotnet @dotnetArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if (-not $NoLaunch) {
    Write-Host 'Launching Genia Link...'
    & $adb -s $Serial shell monkey -p $packageId -c android.intent.category.LAUNCHER 1 | Out-Host
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host 'ANDROID INSTALL PASSED'
