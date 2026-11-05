# Lab setup

How the labeled dataset is produced, so a reviewer can reproduce it and I can
defend every label in an interview. Anything that must be measured or is
specific to my host is left as `TODO` / `<…>` — fill it from the actual run,
never from memory (CLAUDE.md rules 1 and 4).

## 0. Goals and safety

- Produce two kinds of data on the same host, same Sysmon config:
  - **benign** — normal use, the negative class;
  - **malicious** — Atomic Red Team tests, each with a known technique id and a
    recorded start/end time, the positive class.
- Everything is labeled by **session / host / time**, which is also the unit the
  pipeline splits on (no leakage — see `docs/design.md` s6).

**Isolation (non-negotiable):**
- Run only in an isolated VM with **no bridged network**; host-only or fully
  disconnected. Atomic tests can download payloads and change system state.
- Snapshot before any malicious run; **revert after every technique** so one
  test can't contaminate the next (clean parent→child lineage per test).
- Never run attack tooling on a machine with real credentials or data.

## 1. Virtual machine

A single Windows client VM (`win-lab`) on a Fedora host using KVM/libvirt,
built as in section 1a. Record the exact specs used so the dataset is
reproducible:

| Item | Value |
|---|---|
| OS / build | `TODO` (e.g. Windows 11 Enterprise evaluation, build `<n>`) |
| Role | Standalone workstation, local account (no Microsoft account) |
| vCPU / RAM / disk | `TODO` (planned: 4 vCPU / 6 GB / 60 GB, VirtIO) |
| Hypervisor | KVM + libvirt/QEMU on Fedora, versions `TODO` |
| Network | libvirt isolated network `lab-isolated` for all test runs (no `<forward>`) |
| Baseline snapshot name | `clean-baseline` (Sysmon + atomics installed) |
| Defender | `TODO` (on / off — see 1a step 4; it changes which techniques execute) |

Keep the VM patched to a fixed date and record it; "patched as of `<date>`" is
part of the dataset description.

### 1a. Fedora host setup (KVM / libvirt)

**Host requirements:** hardware virtualization (`vmx`/`svm`), about 6 GB RAM
free for the guest, and about 60 GB free disk. Close memory-heavy apps before
running the VM.

**1. Install KVM and libvirt**
```bash
# Install the concrete packages, NOT `@virtualization`: on Fedora with dnf5
# (Fedora 41+) the `@virtualization` group shorthand can resolve to nothing and
# "complete" without installing anything. Direct package names are reliable.
sudo dnf install -y qemu-kvm libvirt virt-install virt-manager virt-viewer
sudo systemctl enable --now libvirtd
sudo usermod -aG libvirt,kvm $USER
# log out and back in so the group change applies, then verify:
virt-host-validate qemu
```
(`virt-host-validate` ships with libvirt, so it only exists *after* this install;
if the command is "not found", the install did not actually add the packages —
check `rpm -q libvirt qemu-kvm`.)

**2. Download media (while online)**
- Windows 11 Enterprise (or Windows 10) **evaluation ISO** from the Microsoft
  Evaluation Center (free, time-limited; note the expiry date: `TODO`).
- VirtIO drivers ISO:
  ```bash
  mkdir -p ~/vm && cd ~/vm
  curl -LO https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso
  ```
- Inside the VM later: Sysmon, a community Sysmon config, `Invoke-AtomicRedTeam`.

**3. Create the VM** (virt-manager, first time)
```bash
virt-manager
```
- Local install media, pick the Windows ISO.
- 6144 MB RAM, 4 vCPUs, 60 GB disk. Choose "Customize before install".
- Disk bus **VirtIO**, NIC model **virtio**, add `virtio-win.iso` as a second
  CD-ROM so the installer can load the storage driver.
- Firmware **UEFI** with **TPM** for Windows 11 (or use Windows 10 to skip TPM).
- Name the VM `win-lab`.
- Create a **local account** (on Windows 11 press `Shift+F10`, run
  `OOBE\BYPASSNRO`). Never sign in with a personal Microsoft account.

**4. Provision while the VM still has internet (default NAT network).** Run all
PowerShell **as Administrator**. (URLs verified live 2026-11; re-check if a
download 404s — CLAUDE.md rule 4.)

1. **VirtIO guest tools** from the virtio CD (find its drive letter in Explorer):
   ```powershell
   Start-Process "D:\virtio-win-guest-tools.exe" -ArgumentList "/quiet" -Wait  # adjust drive
   ```
2. **Get the collection helpers** (this repo) into the VM — no git needed:
   ```powershell
   New-Item C:\lab -ItemType Directory -Force | Out-Null; cd C:\lab
   Invoke-WebRequest https://github.com/cOmrade3267/detection-project/archive/refs/heads/main.zip -OutFile repo.zip
   Expand-Archive repo.zip -DestinationPath C:\lab -Force
   # helpers at C:\lab\detection-project-main\scripts\collect\
   ```
3. **Sysmon + config** (section 2 explains the config choice; `swift` shown):
   ```powershell
   cd C:\lab
   Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
   Expand-Archive Sysmon.zip -DestinationPath Sysmon -Force
   Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig.xml
   .\Sysmon\Sysmon64.exe -accepteula -i sysmonconfig.xml
   Select-String C:\lab\sysmonconfig.xml -Pattern 'sysmonconfig version' | Select-Object -First 1  # RECORD this
   ```
4. **Security 4688 + command line** (the pipeline consumes these):
   ```powershell
   auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
   reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
     /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
   ```
5. **Atomic Red Team:**
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
   Install-AtomicRedTeam -getAtomics -Force
   Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
   Invoke-AtomicTest T1059.001 -ShowDetailsBrief   # smoke test
   ```
6. **Decide on Defender** and record it — it is now a `labels.csv` column
   (`defender_state`), so pass the matching `-DefenderState on|off` to every
   collection-helper call. Leave it **on** (blocks are part of the data) or
   **off** so techniques execute. To disable: turn off **Tamper Protection** in
   the Windows Security GUI first, then
   ```powershell
   Set-MpPreference -DisableRealtimeMonitoring $true
   Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"
   ```
   State the choice in the README limitations either way.
7. **Verify Sysmon is logging** (if empty, fix the config before collecting):
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Format-Table TimeCreated, Id
   ```
8. Shut down and take the clean snapshot (the state you revert to before every
   malicious run):
   ```bash
   virsh shutdown win-lab
   virsh snapshot-create-as win-lab clean-baseline \
     --description "Sysmon(swift) + atomics + 4688 auditing, NAT"
   ```

**5. Create the isolated network and switch the VM to it**
```bash
cat > ~/vm/isolated.xml <<'EOF'
<network>
  <name>lab-isolated</name>
  <!-- no <forward> element = fully isolated: no NAT, no route to the host LAN -->
  <bridge name="virbr-lab" stp="on" delay="0"/>
</network>
EOF
sudo virsh net-define ~/vm/isolated.xml
sudo virsh net-start lab-isolated
sudo virsh net-autostart lab-isolated

virsh shutdown win-lab
virsh detach-interface win-lab network --persistent
virsh attach-interface win-lab network lab-isolated --model virtio --persistent
virsh start win-lab
```
**Verify isolation from inside the VM before any atomic:** `ping 8.8.8.8` and
`Test-NetConnection google.com -Port 443` must both fail. Record the result:
`TODO`.

If the VM runs under the user session libvirt (`qemu:///session`) instead of the
system one, add `--connect qemu:///system` (or set
`LIBVIRT_DEFAULT_URI=qemu:///system`) so `virsh` and `virt-manager` see the same
VM and network.

**6. Per-technique run: record the label in the `labels.csv` schema**

Run from a fresh `clean-baseline` snapshot each time, using the helper
(section 8) which records the full section-5 row for you:
```powershell
.\run-technique.ps1 -TechniqueId T1059.001 -TestNumber 1 `
  -DefenderState off -SysmonConfig swift -OsVersion win11-23h2 -UserType standard
# appends one malicious row (run_id, metadata, UTC start/end) to C:\labels.csv
```
Export the logs (section 6), copy `labels.csv` out, then revert on the host:
```bash
virsh snapshot-revert win-lab clean-baseline
```
Reverting also discards `C:\labels.csv` inside the VM, so **copy it out before
every revert**.

**7. Getting logs and labels out of an isolated VM**

Pick one and record which: `TODO`.
- Shut the VM down and read its disk read-only on the host:
  ```bash
  sudo dnf install -y libguestfs-tools
  sudo guestmount -a /var/lib/libvirt/images/win-lab.qcow2 -i --ro /mnt
  # copy the .evtx and labels.csv out, then:
  sudo guestunmount /mnt
  ```
- Or briefly re-attach the NAT network for a quick copy, then switch back to
  `lab-isolated` and re-verify isolation.

Do not leave a writable shared folder mounted while atomics are running.

**Safety reminders:** use a throwaway VM with no personal data or logged-in
accounts; never run Atomic Red Team on the Fedora host or on a VM that can reach
the LAN.

## 2. Sysmon install and config

The install/auditing commands are in **section 1a step 3–4** (run there, in
order). This section is the *choice* behind them — the config decides which
events exist, so it is part of the methodology.

- **Config:** use a **community base config** (do not hand-roll). Section 1a uses
  **SwiftOnSecurity `sysmon-config`** (`sysmon_config = swift`) — simple, widely
  understood, and it emits every event the pipeline needs. Olaf Hartong
  `sysmon-modular` is the heavier alternative; add it later as the **second
  config** for the L1 controlled-variable comparison (clone the repo and build
  its merged `sysmonconfig.xml`; the raw single-file URL is not stable).
- **Record, as methodology:** Sysmon version (`TODO`), the config repo **commit/
  tag** (`TODO`), and whether 4688 command-line capture was enabled (section 1a
  step 4 enables it). Commit the config file (or its hash) with the dataset
  notes.
- **Why these:** the pipeline consumes **Sysmon EID 1, 3, 7, 11, 13, 22** and
  **Security 4688** (`src/detect/normalize.py`); 4688 with command line needs
  both Audit Process Creation and the `ProcessCreationIncludeCmdLine` policy,
  which step 4 sets. Without the command-line policy, Security-event command-line
  features are empty.
- **Update the config later** with `Sysmon64.exe -c sysmonconfig.xml`.

## 3. Benign collection (negative class)

Goal: a representative sample of normal activity, captured under the same config.
Benign data is the scarce part (there is no clean public benign Sysmon corpus —
`data/README.md`), and it drives the false-positive estimate, so collect it two
ways:

- **Scripted sessions (for the learning curve).** Run the workload scripts in
  `scripts/collect/benign/` (browsing, Office, software install, admin
  PowerShell, scheduled task, dev tools, Windows Update, file copies). Each is
  wrapped as one labeled benign **session** by `run-benign-session.ps1`, which
  records the start/end window and appends a `label=benign` row. Run them
  repeatedly across days so there are **many independent sessions** to subsample
  — the FP **learning curve** (`make benign-report`, built once data exists)
  needs that to show whether more benign data would change the conclusion.
- **Natural use (for realism).** Also use the VM normally for stretches, each
  logged as one benign session, so the benign set isn't only scripted behavior.

- Benign runs do **not** need snapshot-revert, but keep sessions time-separated
  so each has a clean `[start_utc, end_utc]` boundary.
- Record `os_version`, `user_type`, `sysmon_config`, `defender_state` on every
  benign row too (the helper fills them), so benign data is usable in the L1/L4
  splits later.

> Volume note: counts (events, processes, sessions) are **measured**, never
> estimated — fill them in the README from a real `make benign-report` run.

## 4. Malicious collection (positive class) — Atomic Red Team

Tooling: Red Canary **Atomic Red Team** via the `Invoke-AtomicRedTeam`
PowerShell module. Record the module/content commit used: `TODO`.

**Repeat each technique ≥ 5 times** (the "insufficient evidence" threshold):
per-technique recall from a single run is noise, so a technique with fewer than
5 runs is flagged `insufficient evidence` in the report and no conclusion is
drawn from it. Vary the atomic test number where the technique has variants, so
the runs aren't identical.

Per-run procedure — one command with the helper, or by hand:

```powershell
# from scripts/collect/ inside the VM, from a fresh clean-baseline each run:
.\run-technique.ps1 -TechniqueId T1059.001 -TestNumber 1
# -> runs prereqs, the atomic, records UTC start/end, runs cleanup,
#    and appends one malicious row (with run_id + all metadata) to C:\labels.csv
```

By hand the steps are: revert to clean snapshot → record UTC start → run the
atomic → record UTC end → run `-Cleanup` → append the run-log row (section 5) →
export logs (section 6) → revert before the next run.

**Target technique matrix.** Pick techniques across the Enterprise tactics
reachable on a Windows client; cover at least what our rules target
(`T1059.001`, `T1105`, `T1218.005`) plus others so the model is tested beyond the
rules. A starter matrix (confirm each is present in your Atomic Red Team content
version before relying on it — CLAUDE.md rule 4):

| tactic | technique_id | name | example atomic | runs done |
|---|---|---|---|---|
| Execution | T1059.001 | PowerShell | 1 | `TODO` |
| Execution | T1059.003 | Windows Command Shell | 1 | `TODO` |
| Execution | T1053.005 | Scheduled Task | 1 | `TODO` |
| Defense Evasion | T1218.005 | Mshta | 1 | `TODO` |
| Defense Evasion | T1218.011 | Rundll32 | 1 | `TODO` |
| Defense Evasion | T1218.010 | Regsvr32 | 1 | `TODO` |
| Defense Evasion | T1140 | Deobfuscate/Decode | 1 | `TODO` |
| Command & Control | T1105 | Ingress Tool Transfer | 1 | `TODO` |
| Discovery | T1082 | System Information Discovery | 1 | `TODO` |
| Discovery | T1057 | Process Discovery | 1 | `TODO` |
| Persistence | T1547.001 | Registry Run Keys | 1 | `TODO` |
| Credential Access | T1003.001 | LSASS Memory | 1 | `TODO` |

Fill "runs done" from the actual run log; the report derives it from
`labels.csv`, this column is just the plan. Mark any you skip and why.

## 5. Labeling schema

One run-log CSV, `data/lab/labels.csv`, one row per benign session **or** per
technique run. This is the single source of truth the pipeline joins against —
labels are **attached from this log, never inferred** (`normalize.py` reserves
the columns but leaves them null). A ready-to-copy header with example rows is in
[`labels.template.csv`](labels.template.csv); the collection helper scripts
(section 8) append rows in exactly this format.

| column | req? | meaning |
|---|---|---|
| `run_id` | yes | unique id per row (benign session or technique run); lets the report count runs per technique |
| `host` | yes | hostname (matches Sysmon `Computer`) |
| `os_version` | rec | e.g. `win11-23h2`, `win10-22h2` — split variable (L1) |
| `user_type` | rec | `standard` or `admin` — split variable (L1) |
| `sysmon_config` | rec | e.g. `swift`, `modular` — controlled variable (L1) |
| `defender_state` | rec | `on` or `off` — first-class split (L4) |
| `session_id` | yes | session id (groups events; split unit) |
| `source` | yes | `lab` (public samples use `public`, eval-only) |
| `label` | yes | `benign` or `malicious` |
| `technique_id` | mal | ATT&CK id for malicious rows; empty for benign |
| `atomic_test_number` | mal | Atomic Red Team test number — distinguishes repeated/variant runs |
| `start_utc` | yes | session/test start, ISO-8601 UTC |
| `end_utc` | yes | session/test end, ISO-8601 UTC |
| `notes` | no | free text |

"req?": **yes** = required (pipeline errors without it); **rec** = recommended —
record it now so the L1/L4 host/Defender splits work later **without re-collecting**;
**mal** = malicious rows only. The recommended columns are carried from the run
log onto every matched event (`src/detect/label.py`), so a later split can hold
out a host, Sysmon config, or Defender state.

**Time-window labeling rule:** an event is labeled by the run-log row whose
`host` matches `Computer` and whose `[start_utc, end_utc]` contains the event
`timestamp`; it inherits that row's `label`, `technique_id`, `source`, and
`session_id`. Events **outside every window** are labeled `unlabeled`, NOT benign:
they include OS setup, tool installs, Atomic Red Team prerequisite downloads and
idle time, none of which anyone vouched for. `make evaluate` excludes them from
training and evaluation (it prints how many). This was changed after the first
real-data run, where about 87% of events were outside every window and would
otherwise have been counted as benign, which would have corrupted the
false-positive numbers and emptied the train split. Clear the Sysmon and Security
logs (`wevtutil cl ...`) just before taking the clean-baseline snapshot so setup
noise stays out of the data in the first place. This window→event attachment is
the "attach labels" step in the README reproduce flow, applied to the normalized
Parquet before `make evaluate`.

> Keep windows tight (start logging just before the test, stop just after) so
> background noise isn't mislabeled malicious. Snapshot-revert between tests is
> what makes the windows trustworthy.

## 6. Export into the pipeline

1. Export the relevant channels to `.evtx` (per session or per day):
   ```powershell
   wevtutil epl "Microsoft-Windows-Sysmon/Operational" sysmon_<session>.evtx
   wevtutil epl Security security_<session>.evtx
   ```
2. Copy files out to `data/lab/raw/` on the analysis machine (the VM has no
   bridged network — use a shared folder / read-only transfer).
3. Run the pipeline:
   ```bash
   make ingest    EVTX=data/lab/raw/sysmon_<session>.evtx OUT=data/lab/raw/<session>.parquet
   make normalize IN=data/lab/raw/<session>.parquet       OUT=data/lab/normalized/<session>.parquet
   # attach labels.csv (time-window rule, section 5):
   make label     IN=data/lab/normalized/<session>.parquet LABELS=data/lab/labels.csv \
                  OUT=data/lab/normalized/<session>-labeled.parquet SRC=lab
   # concat labeled sessions into one Parquet, then:
   make evaluate  EVENTS=data/lab/normalized/labeled.parquet
   ```

   `make label` applies the time-window rule in `src/detect/label.py`: each event
   gets the label of the run-log row whose `host` matches and whose
   `[start_utc, end_utc]` contains the event timestamp (malicious wins on
   overlap; events outside every window are `unlabeled`, and `--default-label benign`
restores the old behavior only if you deliberately want it).

Public held-out sets (EVTX-ATTACK-SAMPLES, hayabusa-sample-evtx) go through the
same ingest/normalize with `source = public` and are **evaluation-only** — never
in the training split (`data/README.md`).

## 7. Reproducibility checklist

Record all of these with the dataset (they define the methodology):

- [ ] Windows build + "patched as of" date
- [ ] Sysmon version + config source and exact commit/hash
- [ ] Whether Security 4688 command-line capture was enabled
- [ ] Atomic Red Team content commit
- [ ] Exact technique list + atomic test numbers run
- [ ] Benign session count and date range (scripted **and** natural)
- [ ] ≥ 5 runs per technique (fewer = "insufficient evidence" in the report)
- [ ] `defender_state` recorded per row (for the L4 split)
- [ ] Event/process/session counts (measured, filled into the README)
- [ ] `labels.csv` committed (the run log; `.evtx`/data are gitignored)

## 8. Collection helper scripts (`scripts/collect/`)

VM-side PowerShell that makes each run one command and guarantees the
`labels.csv` format. **Review them before running** — you must be able to
explain anything in your own project (they are short and commented). They are
written for the Windows VM and are not exercised by the repo's CI.

| script | what it does |
|---|---|
| `run-technique.ps1` | Runs one Atomic test (prereqs → test → cleanup), times it in UTC, and appends one `malicious` row with a fresh `run_id` and all metadata. |
| `run-benign-session.ps1` | Wraps a benign workload (or a manual natural-use window) as one labeled `benign` session row. |
| `benign/*.ps1` | The scripted benign workloads (browsing, Office, install, admin PowerShell, scheduled task, dev tools, Windows Update, file copies). |
| `_labels.ps1` | Shared helper: appends a correctly-shaped row to `C:\labels.csv`, writing the header once. |

All scripts take `-DefenderState`, `-SysmonConfig`, `-OsVersion`, `-UserType`
(recorded per row) so the L1/L4 splits work without re-collecting. Copy
`C:\labels.csv` out before every snapshot-revert.
