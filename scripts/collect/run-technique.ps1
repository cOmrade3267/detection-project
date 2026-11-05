<#
.SYNOPSIS
  Run one Atomic Red Team test, time it, and append a labeled malicious row.

.DESCRIPTION
  One command per technique run (docs/lab-setup.md s4). Runs prereqs, times the
  test in UTC, runs cleanup, and records the run in C:\labels.csv with a fresh
  run_id and all metadata. Run from a fresh clean-baseline snapshot each time,
  and repeat each technique >= 5 times (vary -TestNumber where variants exist).

.EXAMPLE
  .\run-technique.ps1 -TechniqueId T1059.001 -TestNumber 1 `
    -DefenderState off -SysmonConfig swift -OsVersion win11-23h2 -UserType standard
#>
param(
    [Parameter(Mandatory)] [string] $TechniqueId,
    [int] $TestNumber,
    [string] $DefenderState = "",
    [string] $SysmonConfig = "",
    [string] $OsVersion = "",
    [string] $UserType = "",
    [string] $Notes = ""
)

. "$PSScriptRoot\_labels.ps1"

$runId = New-RunId "r"
$testArg = @{}
if ($PSBoundParameters.ContainsKey("TestNumber")) { $testArg["TestNumbers"] = $TestNumber }

Write-Host "=== $TechniqueId (test $TestNumber) run $runId ===" -ForegroundColor Cyan
Invoke-AtomicTest $TechniqueId @testArg -GetPrereqs

$start = (Get-Date).ToUniversalTime()
Invoke-AtomicTest $TechniqueId @testArg
$end = (Get-Date).ToUniversalTime()

Invoke-AtomicTest $TechniqueId @testArg -Cleanup

Append-LabelRow -RunId $runId -SessionId ("mal-" + $runId) -Label "malicious" `
    -StartUtc $start -EndUtc $end -TechniqueId $TechniqueId `
    -AtomicTestNumber ([string]$TestNumber) -DefenderState $DefenderState `
    -SysmonConfig $SysmonConfig -OsVersion $OsVersion -UserType $UserType -Notes $Notes

Write-Host "Remember: export logs, copy C:\labels.csv out, then revert the snapshot." -ForegroundColor Yellow
