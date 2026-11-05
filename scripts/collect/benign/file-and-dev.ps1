# Benign file operations + developer tools (if installed).
# Generates file_create + process_create telemetry. Internet not required.
# Dev-tool blocks are guarded so missing tools don't error; review before running.

Write-Host "benign: file operations"
$src = Join-Path $env:TEMP ("src-" + (Get-Random))
$dst = Join-Path $env:TEMP ("dst-" + (Get-Random))
New-Item -ItemType Directory -Path $src, $dst -Force | Out-Null
1..10 | ForEach-Object {
    $f = Join-Path $src ("file$_.dat")
    $bytes = [byte[]]::new(1024)
    (New-Object Random).NextBytes($bytes)
    [System.IO.File]::WriteAllBytes($f, $bytes)   # works on PowerShell 5.1 and 7
}
Copy-Item (Join-Path $src "*") $dst
Compress-Archive -Path (Join-Path $src "*") -DestinationPath (Join-Path $env:TEMP "bundle.zip") -Force
Remove-Item $src, $dst, (Join-Path $env:TEMP "bundle.zip") -Recurse -Force

# Developer tools, only if present (common on a dev-profile host).
function Invoke-IfPresent($exe, [scriptblock] $block) {
    if (Get-Command $exe -ErrorAction SilentlyContinue) { & $block }
}
Invoke-IfPresent git     { git --version | Out-Null; git help -a 2>$null | Out-Null }
Invoke-IfPresent python  { python --version 2>&1 | Out-Null; python -c "print(sum(range(100)))" | Out-Null }
Invoke-IfPresent node    { node --version | Out-Null }
Invoke-IfPresent dotnet  { dotnet --info 2>$null | Out-Null }
Write-Host "done"
