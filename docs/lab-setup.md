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
sudo dnf install -y @virtualization
sudo systemctl enable --now libvirtd
sudo usermod -aG libvirt,kvm $USER
# log out and back in so the group change applies, then verify:
virt-host-validate qemu
```

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

**4. Provision while the VM still has internet (default NAT network)**
1. Install the VirtIO guest tools from the virtio ISO
   (`virtio-win-guest-tools.exe`).
2. Install Sysmon with the config chosen in section 2.
3. Install Atomic Red Team:
   ```powershell
   IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
   Install-AtomicRedTeam -getAtomics
   ```
4. **Decide on Defender** and record it in the table above: leave it on (its
   blocks are part of the data) or disable it in this lab VM so techniques
   execute. This affects the results, so state the choice in the README
   limitations.
5. Shut down and take the clean snapshot:
   ```bash
   virsh snapshot-create-as win-lab clean-baseline \
     --description "Sysmon + atomics installed, networked"
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

Run from a fresh `clean-baseline` snapshot each time. In the VM, log a row in
the section 5 format (UTC times):
```powershell
$s = (Get-Date).ToUniversalTime().ToString("o")
Invoke-AtomicTest T1059.001 -TestNumbers 1
$e = (Get-Date).ToUniversalTime().ToString("o")
Invoke-AtomicTest T1059.001 -Cleanup
"atomic-T1059.001-1,$env:COMPUTERNAME,lab,malicious,T1059.001,$s,$e" |
  Out-File -Append -Encoding ascii C:\labels.csv
```
(`labels.csv` columns: `session_id,host,source,label,technique_id,start_utc,end_utc`;
write the header once.) Export the logs (section 6), copy `labels.csv` out, then
revert on the host:
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

1. Download **Sysmon** (Sysinternals) — record the exact version: `TODO`.
2. Use a **community base config** as the starting point (do not hand-roll):
   - SwiftOnSecurity `sysmon-config`, or
   - Olaf Hartong `sysmon-modular`.
   Record which one and the **exact commit/tag** you used: `TODO`. Commit the
   config file (or its hash) alongside the dataset notes — the config decides
   which events exist, so it is part of the methodology.
3. Install / update:
   ```powershell
   Sysmon64.exe -accepteula -i sysmon-config.xml      # first install
   Sysmon64.exe -c sysmon-config.xml                  # update config later
   ```
4. Confirm the channel is populated:
   `Microsoft-Windows-Sysmon/Operational`.

The pipeline consumes **Sysmon EID 1, 3, 7, 11, 13, 22** and **Security 4688**
(`src/detect/normalize.py`). For 4688 with command line, also enable:
- Audit Process Creation (Security 4688), and
- "Include command line in process creation events"
  (`Administrative Templates → System → Audit Process Creation`).
Record whether 4688 command-line capture was on: `TODO` (affects which
command-line features exist for Security events).

## 3. Benign collection (negative class)

Goal: a representative sample of normal activity, captured under the same config.

- Duration / sessions: `TODO` (target 1–2 weeks of light use, or N scripted
  sessions — record the actual number and dates).
- Activities to cover (each as its own **session** so they split cleanly):
  browsing, Office documents, software installs/updates, admin PowerShell
  (benign), scheduled tasks, Windows Update, file copies.
- For each benign session record a row in the run log (section 5) with
  `label = benign`, `technique_id` empty, and the session's start/end time.
- Benign runs do **not** need snapshot-revert, but keep sessions
  time-separated so each has a clean boundary.

> Volume note: counts (events, processes, sessions) are **measured**, never
> estimated — fill them in the README from a real `make`/inspection run.

## 4. Malicious collection (positive class) — Atomic Red Team

Tooling: Red Canary **Atomic Red Team** via the `Invoke-AtomicRedTeam`
PowerShell module. Record the module/content commit used: `TODO`.

Per-technique procedure (repeat for each chosen technique):

1. **Revert to the clean snapshot.**
2. Start a new logging session; note `session_id` and the **UTC start time**.
3. Run the atomic(s) for the technique:
   ```powershell
   Invoke-AtomicTest T1059.001 -GetPrereqs
   Invoke-AtomicTest T1059.001            # optionally -TestNumbers 1,2
   ```
4. Note the **UTC end time**. Run the cleanup:
   ```powershell
   Invoke-AtomicTest T1059.001 -Cleanup
   ```
5. Append a run-log row (section 5) with `label = malicious`, the
   `technique_id`, session_id, host, and start/end times.
6. Export the logs for that session (section 6), then **revert** before the next
   technique.

**Technique selection:** start with 10–15 techniques across tactics; if time is
short, cut to ~8 (CLAUDE.md s7). List the exact techniques actually run here:

| technique_id | name | atomic test numbers | notes |
|---|---|---|---|
| `TODO` | | | |

Aim to cover the techniques our rules target (`T1059.001`, `T1105`, `T1218.005`)
plus others so the model is tested beyond what the rules already catch.

## 5. Labeling schema

One run-log CSV, `data/lab/labels.csv`, one row per session (benign or one
technique run). This is the single source of truth the pipeline joins against —
labels are **attached from this log, never inferred** (`normalize.py` reserves
the columns but leaves them null).

| column | meaning |
|---|---|
| `session_id` | unique id for the session (groups events; split unit) |
| `host` | hostname (matches Sysmon `Computer`) |
| `source` | `lab` (public samples use `public`, eval-only) |
| `label` | `benign` or `malicious` |
| `technique_id` | ATT&CK id for malicious rows; empty for benign |
| `start_utc` | session/test start, ISO-8601 UTC |
| `end_utc` | session/test end, ISO-8601 UTC |

**Time-window labeling rule:** an event is labeled by the run-log row whose
`host` matches `Computer` and whose `[start_utc, end_utc]` contains the event
`timestamp`; it inherits that row's `label`, `technique_id`, `source`, and
`session_id`. Events on a malicious host **outside** any test window stay benign
(the revert keeps windows clean). This window→event attachment is the "attach
labels" step in the README reproduce flow, applied to the normalized Parquet
before `make evaluate`.

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
   overlap; events outside every window take `SRC`/benign).

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
- [ ] Benign session count and date range
- [ ] Event/process/session counts (measured, filled into the README)
- [ ] `labels.csv` committed (the run log; `.evtx`/data are gitignored)
