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

Already built: a hardened Windows Server AD VM. Record the exact specs used so
the dataset is reproducible:

| Item | Value |
|---|---|
| OS / build | `TODO` (e.g. Windows Server 2022, build `<n>`) |
| Role | Standalone AD DC / domain `<lab.local>` |
| vCPU / RAM / disk | `TODO` |
| Hypervisor | `TODO` (VirtualBox / Hyper-V / VMware) + version |
| Network | host-only / disconnected (confirm no bridge) |
| Baseline snapshot name | `TODO` (the clean state reverted to) |

Keep the VM patched to a fixed date and record it; "patched as of `<date>`" is
part of the dataset description.

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
   # attach labels.csv (time-window rule, section 5), concat sessions, then:
   make evaluate  EVENTS=data/lab/normalized/labeled.parquet
   ```

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
