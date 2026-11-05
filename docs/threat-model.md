# Threat model — what this detects, misses, and how to evade it

Being specific about blind spots and evasion is the point of this page: a
detection project that only lists what it catches is not credible. Everything
below is a property of the design, independent of the (still `TODO`) measured
numbers.

## Detection surface

The pipeline sees **host telemetry only**: Sysmon EID 1 (process create), 3
(network connect), 7 (image load), 11 (file create), 13 (registry set), 22 (DNS)
and Security 4688, aggregated to **one unit per process**. Detection is (a)
hand-written + SigmaHQ-format rules and (b) an unsupervised model over
per-process behavioral features. The trust boundary assumes Sysmon is installed,
its config logs the events above, the logs are intact, and the labels are
correct.

## What it can detect

- **Known bad patterns (rules):** encoded PowerShell, LOLBin download/exec
  (certutil, mshta), and any technique expressible as field matches on the
  common schema — including standard SigmaHQ rules for the supported subset.
- **Anomalous processes (model):** behavior that deviates from the benign
  manifold — rare parent→child lineage (e.g. `winword.exe`→`powershell.exe`),
  high-entropy or encoded command lines, execution from `Temp`/`AppData`/
  `Downloads`, unusual network fan-out or uncommon destination ports, and bursty
  activity. Each alert is explained by its top contributing features, so a miss
  or a false positive is inspectable.
- **Techniques that leave a host process/network/file/registry footprint** —
  the catalogue in `docs/lab-setup.md §4`.

## What it cannot detect (blind spots)

- **Anything outside the telemetry.** In-memory-only activity with no child
  process / network / file event, kernel- or driver-level actions, pure network
  attacks with no host footprint, and cloud/identity/SaaS attacks are invisible.
- **Events the Sysmon config doesn't emit.** We map EID 1/3/7/11/13/22 + 4688.
  `CreateRemoteThread` (8), `ProcessAccess` (10, injection), WMI subscription
  (19–21), raw-access reads (9) and PowerShell script-block logging (4104) are
  **not** mapped — techniques that show up only there are missed. (4104 would
  also expose script *contents*; we see the command line, not what a script
  does once running.)
- **Cross-process / cross-session campaigns.** The unit is one process with its
  own events plus its parent link. Multi-stage activity spread across unrelated
  processes or sessions isn't correlated.
- **Correct-but-unlabeled attacks in evaluation.** Recall is only measured for
  techniques actually run in the lab; a technique nobody ran can't be scored.

## How an attacker evades it

- **Living off the land.** Use signed, common binaries with ordinary
  parent→child lineage, no `-enc`/`-nop`, executing from normal paths. The
  rarity and LOLBin features raise the bar, but LOTL that closely mimics admin
  behavior scores as benign. This is the fundamental limit of behavioral
  anomaly detection.
- **Slow and low.** Spread actions over time to stay under the burstiness /
  events-per-minute features, and across sessions to defeat per-process
  aggregation. Our window is the process; a patient actor stays below every
  volume threshold.
- **Feature-aware mimicry.** Knowing the 22 features, craft each below its
  tell: low-entropy command lines, payloads named like system images, few
  distinct destinations, common ports. The feature list is public (it must be,
  to be defensible), which is also an evasion aid.
- **Training-data poisoning.** If attacker activity is present during the window
  collected as "benign", the model learns it as normal. The lab's time-window
  labeling and snapshot-revert mitigate this here; a production system that
  updates a per-host baseline online is more exposed, and would need vetted
  baseline windows and human-in-the-loop updates (see `scaling.md`).
- **Telemetry tampering.** Alter the Sysmon config, clear or stop the channel,
  or route activity through events we don't ingest. Our ingest tolerates
  "dirty" `.evtx` by skipping the unparseable tail (and warning) — a crafted bad
  chunk could hide trailing events, so tolerance is a small evasion surface we
  accept for robustness, and surface loudly.

## Residual risk and what raises the bar

No single layer is sufficient, which is why the project reports **rules OR
model** and **per-technique recall**: the union costs an attacker more (evade
both a signature and the anomaly score), and the per-technique table makes the
blind spots explicit rather than hiding them in an aggregate number. The honest
posture is "a tripwire for noisy or careless attacker behavior and a baseline to
measure coverage", not "a complete defense".
