<#
.SYNOPSIS
  Record one labeled benign session: run a workload, or time a natural-use window.

.DESCRIPTION
  Benign data is the scarce, FP-driving part (docs/lab-setup.md s3). Run this
  many times across days so there are many independent benign sessions for the
  FP learning curve. Two modes:
    -Workload <path>   run a scripts/collect/benign/*.ps1 workload as the session
    -DurationMinutes N time a natural-use window (you use the VM normally)
  With neither, it waits for you to press Enter to end the session.

.EXAMPLE
  .\run-benign-session.ps1 -Workload .\benign\admin-powershell.ps1 `
    -DefenderState off -SysmonConfig swift -OsVersion win11-23h2 -UserType standard
.EXAMPLE
  .\run-benign-session.ps1 -DurationMinutes 20 -UserType standard   # natural use
#>
param(
    [string] $Workload = "",
    [int] $DurationMinutes = 0,
    [string] $DefenderState = "",
    [string] $SysmonConfig = "",
    [string] $OsVersion = "",
    [string] $UserType = "",
    [string] $Notes = ""
)

. "$PSScriptRoot\_labels.ps1"

$runId = New-RunId "b"
$kind = "natural-use"
$start = (Get-Date).ToUniversalTime()

if ($Workload) {
    $kind = "workload=" + (Split-Path $Workload -Leaf)
    Write-Host "running benign workload $Workload ..." -ForegroundColor Cyan
    & $Workload
} elseif ($DurationMinutes -gt 0) {
    Write-Host "natural-use window: use the VM normally for $DurationMinutes min ..." -ForegroundColor Cyan
    Start-Sleep -Seconds ($DurationMinutes * 60)
} else {
    Read-Host "Do normal things, then press Enter to end this benign session"
}

$end = (Get-Date).ToUniversalTime()

$note = ($Notes + " " + $kind).Trim()
Append-LabelRow -RunId $runId -SessionId ("ben-" + $runId) -Label "benign" `
    -StartUtc $start -EndUtc $end -Source "lab" -DefenderState $DefenderState `
    -SysmonConfig $SysmonConfig -OsVersion $OsVersion -UserType $UserType -Notes $note
