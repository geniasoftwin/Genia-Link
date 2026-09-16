param(
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$project = Join-Path $root 'src\GeniaLink.Android\GeniaLink.Android.csproj'
$dist = Join-Path $root 'dist'
$outputName = 'GeniaLink-v0.3.1-RC4-Android.apk'
$outputPath = Join-Path $dist $outputName

Write-Host 'Genia Link v0.3.1 RC4 - building signed Android APK...'
& (Join-Path $PSScriptRoot 'SecurityCheck-Android.ps1')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& dotnet build $project -f net10.0-android -c $Configuration -t:SignAndroidPackage -p:AndroidPackageFormats=apk --nologo
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$apkRoot = Join-Path $root "src\GeniaLink.Android\bin\$Configuration\net10.0-android"
$apk = Get-ChildItem -LiteralPath $apkRoot -Recurse -Filter '*-Signed.apk' |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
if ($null -eq $apk) {
    throw 'Signed Android APK was not found after a successful build.'
}

New-Item -ItemType Directory -Path $dist -Force | Out-Null
Copy-Item -LiteralPath $apk.FullName -Destination $outputPath -Force
$hash = Get-FileHash -LiteralPath $outputPath -Algorithm SHA256
Write-Host "APK: $outputPath"
Write-Host "SHA-256: $($hash.Hash)"
