# Benign scheduled task: create, run, and remove a harmless task.
# Generates process_create (taskeng/svchost -> the action) + registry telemetry.
# Review before running.

$taskName = "BenignCollect-" + (Get-Random)
Write-Host "benign: scheduled task $taskName"

$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -Command Get-Date | Out-Null"
$trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddSeconds(15))

try {
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
        -Description "benign data-collection task" | Out-Null
    Start-ScheduledTask -TaskName $taskName
    Start-Sleep -Seconds 5
} finally {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
}
Write-Host "done"
