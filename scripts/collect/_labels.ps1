# Shared helper: append one correctly-shaped row to the run log (C:\labels.csv).
# Dot-source it from the collectors:  . "$PSScriptRoot\_labels.ps1"
#
# The column order MUST match docs/labels.template.csv and src/detect/label.py.
# Review this before running -- it is short on purpose so you can explain it.

$script:LabelsPath = "C:\labels.csv"

function Append-LabelRow {
    param(
        [Parameter(Mandatory)] [string] $RunId,
        [Parameter(Mandatory)] [string] $SessionId,
        [Parameter(Mandatory)] [ValidateSet("benign", "malicious")] [string] $Label,
        [Parameter(Mandatory)] [datetime] $StartUtc,
        [Parameter(Mandatory)] [datetime] $EndUtc,
        [string] $TechniqueId = "",
        [string] $AtomicTestNumber = "",
        [string] $Source = "lab",
        [string] $DefenderState = "",
        [string] $SysmonConfig = "",
        [string] $OsVersion = "",
        [string] $UserType = "",
        [string] $Notes = ""
    )

    # [ordered] preserves the exact column order the pipeline expects.
    $row = [ordered]@{
        run_id             = $RunId
        host               = $env:COMPUTERNAME
        os_version         = $OsVersion
        user_type          = $UserType
        sysmon_config      = $SysmonConfig
        defender_state     = $DefenderState
        session_id         = $SessionId
        source             = $Source
        label              = $Label
        technique_id       = $TechniqueId
        atomic_test_number = $AtomicTestNumber
        start_utc          = $StartUtc.ToUniversalTime().ToString("o")
        end_utc            = $EndUtc.ToUniversalTime().ToString("o")
        notes              = $Notes
    }

    # Export-Csv -Append writes the header only when the file is new, then
    # appends without it -- so the header is correct and written exactly once.
    [pscustomobject]$row |
        Export-Csv -Path $script:LabelsPath -Append -NoTypeInformation -Encoding ascii
    Write-Host "appended $Label row $RunId -> $script:LabelsPath"
}

# A readable, unique id: prefix + timestamp to the millisecond.
function New-RunId([string] $Prefix) {
    return $Prefix + (Get-Date -Format "yyyyMMddHHmmssfff")
}
