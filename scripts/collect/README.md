# VM-side collection helpers

PowerShell that runs **inside the Windows lab VM** to produce data in the exact
`labels.csv` format the pipeline expects (`docs/lab-setup.md`,
`docs/labels.template.csv`). They are **not** run by the repo's CI — they need a
Windows host, Sysmon, and Atomic Red Team.

> **Review every script before running it.** They are short and commented on
> purpose: you must be able to explain anything in your own project, and you are
> running them on a machine you've chosen to treat as disposable.

## Setup (once, from a fresh clean-baseline)

```powershell
# allow local scripts for this session only:
Set-ExecutionPolicy -Scope Process -Bypass
cd C:\path\to\scripts\collect
```

Pass the same metadata flags on every call so each row is tagged for the later
host/Defender splits: `-DefenderState on|off -SysmonConfig swift|modular
-OsVersion win11-23h2 -UserType standard|admin`.

## Malicious runs (>= 5 per technique)

```powershell
# from a fresh clean-baseline each run; repeat >= 5x, vary -TestNumber for variants:
.\run-technique.ps1 -TechniqueId T1059.001 -TestNumber 1 `
  -DefenderState off -SysmonConfig swift -OsVersion win11-23h2 -UserType standard
# then: export logs (lab-setup.md s6), copy C:\labels.csv out, revert snapshot.
```

## Benign sessions (scripted + natural)

```powershell
# scripted workload as one labeled session (run the set repeatedly across days):
.\run-benign-session.ps1 -Workload .\benign\admin-powershell.ps1 `
  -DefenderState off -SysmonConfig swift -OsVersion win11-23h2 -UserType standard

# a natural-use window:
.\run-benign-session.ps1 -DurationMinutes 20 -SysmonConfig swift -OsVersion win11-23h2 -UserType standard
```

Workloads in `benign/`: `admin-powershell.ps1`, `scheduled-task.ps1`,
`file-and-dev.ps1` (all internet-free) and `apps-and-web.ps1` (needs the NAT
network + installed apps). Add your own; each should be genuinely benign and
representative of the host's real use.

## Output

Every call appends one row to `C:\labels.csv` (header written once). Copy it out
**before every snapshot-revert** — reverting discards it. Then on the analysis
machine, `labels.csv` + the exported `.evtx` feed `make all` / `make label`.
