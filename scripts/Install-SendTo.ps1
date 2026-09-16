$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root 'artifacts\portable-win-x64\GeniaLink.exe'
if (-not (Test-Path $exe)) {
    throw 'Portable GeniaLink.exe not found. Run .\scripts\Publish-Portable.ps1 first.'
}
$trustedPath = Join-Path $env:LOCALAPPDATA 'Genia Link\trusted-devices.json'
if (-not (Test-Path $trustedPath)) {
    throw 'No trusted devices found. Pair a device first.'
}
$devices = @(Get-Content -Raw -Encoding UTF8 $trustedPath | ConvertFrom-Json)
if ($devices.Count -eq 0) { throw 'No trusted devices found.' }
$sendTo = [Environment]::GetFolderPath('SendTo')
Get-ChildItem -LiteralPath $sendTo -Filter 'Genia Link - *.lnk' -ErrorAction SilentlyContinue | Remove-Item -Force
$shell = New-Object -ComObject WScript.Shell
$count = 0
foreach ($device in $devices) {
    $name = [string]$device.DeviceName
    foreach ($ch in [IO.Path]::GetInvalidFileNameChars()) { $name = $name.Replace([string]$ch, '_') }
    if ([string]::IsNullOrWhiteSpace($name)) { $name = 'Device' }
    $shortcut = $shell.CreateShortcut((Join-Path $sendTo ("Genia Link - {0}.lnk" -f $name)))
    $shortcut.TargetPath = $exe
    $shortcut.Arguments = "--send-to $($device.DeviceId)"
    $shortcut.WorkingDirectory = Split-Path -Parent $exe
    $shortcut.IconLocation = "$exe,0"
    $shortcut.Description = "Send with Genia Link to $name"
    $shortcut.Save()
    $count++
}
Write-Host "SENDTO INSTALL PASSED: $count shortcut(s) created."
