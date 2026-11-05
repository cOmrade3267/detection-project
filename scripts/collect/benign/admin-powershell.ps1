# Benign admin PowerShell: the kind of enumeration/maintenance a sysadmin runs.
# Generates process_create + file_create telemetry, no internet needed.
# Review and adapt to your environment; keep it genuinely benign.

Write-Host "benign: admin PowerShell enumeration"
Get-Process | Select-Object -First 20 | Out-Null
Get-Service | Where-Object Status -eq "Running" | Select-Object -First 20 | Out-Null
Get-ChildItem C:\Windows\System32 -File | Select-Object -First 50 | Out-Null
Get-HotFix -ErrorAction SilentlyContinue | Out-Null
Get-LocalUser -ErrorAction SilentlyContinue | Out-Null
ipconfig /all | Out-Null
systeminfo | Out-Null

$work = Join-Path $env:TEMP ("benign-" + (Get-Random))
New-Item -ItemType Directory -Path $work -Force | Out-Null
1..5 | ForEach-Object { "line $_" | Out-File (Join-Path $work "note$_.txt") }
Get-ChildItem $work | Out-Null
Remove-Item $work -Recurse -Force
Write-Host "done"
