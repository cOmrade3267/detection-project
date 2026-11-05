# Benign application + web activity. NEEDS INTERNET (run with the NAT network,
# not the isolated one) and installed apps; blocks are guarded so missing apps
# don't error. Review before running -- keep URLs to ordinary, safe sites.

Write-Host "benign: apps + web (needs internet; guarded)"

# A browser visiting a few ordinary sites (process_create + network + dns).
$edge = Join-Path ${env:ProgramFiles(x86)} "Microsoft\Edge\Application\msedge.exe"
$urls = @("https://www.wikipedia.org", "https://www.microsoft.com", "https://example.com")
if (Test-Path $edge) {
    foreach ($u in $urls) { Start-Process $edge $u; Start-Sleep -Seconds 4 }
    Start-Sleep -Seconds 5
    Get-Process msedge -ErrorAction SilentlyContinue | Stop-Process -ErrorAction SilentlyContinue
} else {
    foreach ($u in $urls) { Invoke-WebRequest $u -UseBasicParsing -TimeoutSec 15 | Out-Null }
}

# Office automation, only if installed (process_create + file_create).
try {
    $word = New-Object -ComObject Word.Application
    $word.Visible = $false
    $doc = $word.Documents.Add()
    $doc.Content.Text = "Benign collection document."
    $out = Join-Path $env:TEMP ("benign-" + (Get-Random) + ".docx")
    $doc.SaveAs([ref]$out); $doc.Close(); $word.Quit()
    Remove-Item $out -ErrorAction SilentlyContinue
} catch {
    Write-Host "  (Word not installed; skipped Office automation)"
}
Write-Host "done"
