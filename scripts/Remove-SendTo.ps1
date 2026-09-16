$ErrorActionPreference = 'Stop'
$sendTo = [Environment]::GetFolderPath('SendTo')
$items = @(Get-ChildItem -LiteralPath $sendTo -Filter 'Genia Link - *.lnk' -ErrorAction SilentlyContinue)
$items | Remove-Item -Force
Write-Host "SENDTO REMOVE PASSED: $($items.Count) shortcut(s) removed."
