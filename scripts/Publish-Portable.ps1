$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$outDir = Join-Path $root 'artifacts\portable-win-x64'

Write-Host 'Genia Link v0.3.1 RC4 - running offline security checks first...'
& (Join-Path $PSScriptRoot 'SecurityCheck.ps1')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if (Test-Path $outDir) {
    Remove-Item $outDir -Recurse -Force
}

Write-Host 'Publishing self-contained single-file GeniaLink.exe for win-x64...'

# Run from the repository root and use relative paths. This avoids an MSBuild
# command-line parsing edge case when an absolute repository path contains
# commas (for example: "Sources, Projects Windows") as well as spaces.
Push-Location $root
try {
    dotnet publish '.\src\GeniaLink.Windows\GeniaLink.Windows.csproj' -c Release -r win-x64 --self-contained true `
      -p:PublishSingleFile=true `
      -p:IncludeNativeLibrariesForSelfExtract=true `
      -p:EnableCompressionInSingleFile=true `
      -p:PublishTrimmed=false `
      -p:DebugType=None `
      -p:DebugSymbols=false `
      -o '.\artifacts\portable-win-x64'

    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    Pop-Location
}

Write-Host "Portable build ready: $outDir\GeniaLink.exe"
