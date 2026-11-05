# Design decisions and trade-offs

## 1. `.evtx` parser — chose `evtx` (pyevtx-rs), fallback `python-evtx`

**Decision:** parse with the `evtx` PyPI package (Rust-backed bindings to
omerbenamram/evtx, pyevtx-rs), using its JSON record output. Keep `python-evtx`
(pure Python) as a documented fallback behind the `parsers-pure` extra.

**Candidates considered:**

| Option | Pros | Cons |
|---|---|---|
| `evtx` / pyevtx-rs (chosen) | Rust speed on millions of events; `pip install` (abi3 wheels, Py3.7+, Linux/macOS x86_64); emits JSON that drops straight into pandas | Native wheel — ARM/Windows build from source (needs Rust) |
| `evtx_dump` (Rust CLI) | Same speed | External binary to install/version separately → hurts `make setup` reproducibility; subprocess + temp-file plumbing |
| `python-evtx` (pure Python) | Zero native deps, maximally portable | Slow at volume; last release 0.7.4 (2021) |

**Why:** the pipeline must be reproducible via a single `make setup` (rule 5)
*and* handle large event volumes. pyevtx-rs gives both — Rust throughput with a
plain `pip install` and no external binary — so it beats `evtx_dump` on
reproducibility and `python-evtx` on speed. JSON output avoids hand-rolling XML
parsing. The fallback covers platforms without a prebuilt wheel.

**Ingest contract:** ingest stays *faithful*, not interpretive. It promotes only
routing fields (`event_record_id`, `timestamp`, `provider`, `event_id`,
`channel`, `computer`) to typed columns and preserves the full event as
`event_json`. All field interpretation (EventData → common schema) is
`normalize.py`'s job, so ingest never has to change when the schema evolves.

## 2. Common schema (normalize.py)

**Decision:** one wide, mostly-nullable row per event, keyed by a normalized
`action` verb (`process_create`, `network_connect`, `image_load`,
`file_create`, `registry_set`, `dns_query`; `unknown` for unmapped). A
per-`(provider, event_id)` mapper fills the fields relevant to its action; all
others stay null.

**Why one wide table, not per-type tables:** features and rules are written
once against a single schema, and process-centric joins (by `process_guid`)
span event types. A wide nullable frame is simpler to reason about than a star
of per-type tables for this volume, and Parquet stores the nulls cheaply.

**Covered now:** Sysmon EID 1/3/7/11/13/22 and Security 4688 — the set the
feature work needs. `event_json` from ingest is retained so an unmapped or
newly-needed field is always recoverable without re-ingesting.

**EventData shape:** handled both as a named object (`{"Image": ...}`) and as
the list-of-`Data` form (`[{"@Name": "Image", "#text": ...}]`) that some
renderers emit, so normalization doesn't depend on one serializer.

**Labels** (`label`, `technique_id`, `source`, `session_id`) are columns on the
schema but populated later from the lab run log, never inferred here.

## 3. Features (features.py)

**Unit of analysis: one row per process** (`process_guid`). All events carrying
that guid — the `process_create` plus its network/file/image/registry/dns
events — aggregate into a single feature row. Rules and the model therefore
score *processes*, which is how an analyst triages ("is this process
malicious?") and lets us report per-process precision/recall.

**Fit/transform split (the leakage rule, in code):** `FeatureBuilder.fit()`
learns frequency tables (parent-image → child-image pair rarity) on the
**training** events only; `.transform()` applies them to any set. A pair unseen
in training gets maximum rarity. Intrinsic features (command-line entropy,
counts, path flags) need no fitting — they depend only on the row itself, so
they can't leak. This mirrors "fit scalers/encoders on training data only"
(CLAUDE.md s3) and is the seam a reviewer will inspect.

**Feature set (small, each justified — CLAUDE.md s4):**
- *Command line:* length, Shannon entropy, encoded/`-nop`/hidden-window flags,
  long base64 token — obfuscated PowerShell and LOLBin abuse look unusual here.
- *Image:* LOLBin basename flag; execution from Temp/AppData/Downloads/
  ProgramData (living-off-the-land and dropper staging).
- *Lineage:* integrity level (ordinal); parent→child pair rarity (learned);
  child-process fan-out (one process spawning many is suspicious).
- *Network (EID 3):* connection count, distinct destination IPs/ports, count of
  uncommon ports.
- *Volume/burst:* per-action event counts, active duration, events per minute.

Booleans are emitted as 0/1 so the Isolation Forest and the rules engine share
one numeric matrix. Identifier/label columns (`process_guid`, `host`,
`session_id`, `source`, `label`, `technique_id`) ride alongside the features but
are never fed to the model.

## 4. Models (model.py)

**Three detectors with one interface — z-score baseline (B), Isolation Forest
(primary), Local Outlier Factor (comparison).** All consume the
`FEATURE_COLUMNS` matrix, impute missing values with a **median learned on
train**, and emit an anomaly score where **higher = more anomalous**. Fitting is
on the training split only, benign rows (`fit_on_benign`), matching the
unsupervised premise: learn "normal", flag outliers.

**Why Isolation Forest (primary):** little labeled attack data in production, so
we learn the benign manifold unsupervised. IF isolates outliers with random
splits — near log-linear, few hyper-parameters, no distance metric to tune, and
split-based so **scale-invariant** (we impute but don't standardize it).

**Why also LOF:** a second model with a *different inductive bias* is a fairer
test than one model vs. a trivial baseline. Local Outlier Factor is
density/distance-based — it flags points sparse relative to their local
neighbourhood, catching anomalies IF's axis-aligned splits can miss. Because it
is distance-based it **is standardized** (impute → scale → LOF), and run in
`novelty=True` mode so it scores unseen test rows. *Rejected alternative:*
one-class SVM — kernel- and scale-sensitive with an extra `nu`/`gamma` to tune
and worse scaling; LOF gives the contrasting bias more cheaply.

**Why the z-score baseline:** the ML models must beat something trivial. The
baseline standardizes each feature on train (mean/std) and scores a process by
its **mean absolute z** across features — a pure "how unusual is this row"
number. If IF/LOF can't beat it on PR-AUC, they aren't earning their complexity.

**Scores → threshold on validation, never test.** Detectors return continuous
scores. The alert threshold is set at a **fixed budget** (default 100 alerts per
10k processes) by taking that quantile of scores on a **validation split carved
from train** (`threshold_at_rate`), then applied unchanged to test — so the cut
never sees test data (the leakage a reviewer checks). *Rejected alternative:*
top-k on the test scores (`alerts_at_budget`, kept for same-volume comparisons)
— it tunes the threshold on the very set being measured. Models persist via
joblib for a reproducible `make train` → score flow.

**Explainability:** every alert carries its top contributing features (the
features most elevated vs. the benign mean, in σ) and any matching rule ids, so
an analyst gets a "why" for triage, not just a score (`artifacts/alert_explanations.csv`).

## 5. Rules (rules.py) — Baseline A

**A small, hand-rolled Sigma-style engine, not a pySigma dependency.** It reads
YAML rules from `rules/` and matches them against the normalized common-schema
events. A deliberately scoped subset of Sigma is supported so it's honest to
call it "Sigma-style" without pulling the full spec:

- `detection` holds named selection blocks; a block is an AND over its field
  specs, a list value is OR, and `field|all` makes a list AND.
- Field modifiers: `contains`, `startswith`, `endswith`, `re`, default equals.
  String comparisons are case-insensitive (Sigma semantics).
- `condition` is a boolean expression over block names (`and`/`or`/`not`/
  parentheses), plus Sigma's `all of them` / `1 of them` / `all|1 of <prefix>*`
  shorthand, evaluated via a restricted AST walk — no `eval`, only BoolOp/
  UnaryOp/Name nodes, so a rule file can't execute arbitrary code.
- It also loads **standard SigmaHQ-format YAML** for this subset: Windows field
  names are mapped to the schema, `logsource.category` scopes the rule to an
  action, and `attack.*` tags set the technique. Any unsupported modifier is
  **rejected at load** (never silently mismatched). The exact supported/rejected
  matrix is in [`sigma-support.md`](sigma-support.md).

**Why hand-rolled (not pySigma):** pySigma *converts* rules to SIEM queries; it
doesn't execute them on a DataFrame, so it would add a heavy dependency and still
need an executor. The project must not copy rules/code from other repos
(CLAUDE.md s3). Writing the engine and the rules originals keeps licensing clean
(SigmaHQ is only a reference for *ideas*), keeps the dependency surface small,
and makes every match defensible in an interview. SigmaHQ via Chainsaw/Hayabusa
remains the **external** baseline run separately in evaluation.

**Output:** event-level alerts (rule id/title, `technique_id`, level,
`process_guid`, timestamp). `alerts_by_process` rolls them up to the
per-process unit the model uses, so Baseline A and the model compare on the same
rows. Each rule ships with a positive and a negative test event under `tests/`.

## 6. Split & leakage (split.py)

**Split by group, then by time.** The unit is a group (session, falling back to
host), never a random event, so no process/session straddles train and test.
By default the **most recent groups** (by earliest timestamp) become the test
set — train on the past, evaluate on the future, which is how the detector will
actually be used and avoids temporal leakage. The **public** dataset is
evaluation-only: any `source == "public"` row is forced into test and never
train. `assert_no_leakage` encodes all three invariants and runs inside
`run_evaluation` on every evaluation, not just in tests, so a regression can't
silently produce inflated numbers. `FeatureBuilder` and the models fit their
frequency tables / imputers / scalers on the train split only (s3, s4).

## 7. Evaluation metrics (evaluate.py)

**Not accuracy.** Benign dwarfs malicious, so accuracy is ~100% for a detector
that alerts on nothing. We report:

- **Precision / recall / F1** at a defined operating point.
- **PR-AUC (average precision)** — threshold-free ranking quality on the
  imbalanced positive class; the single headline number for "how well does the
  score separate malicious from benign".
- **False positives per 10,000 benign** — the SOC-relevant cost; one analyst's
  day is spent on a handful of alerts, so FP volume, not FP rate, is what bites.
- **Per-technique recall** — the research question is *which* techniques each
  approach misses, so recall is broken out by ATT&CK id (worst first).

**Fixed alert budget for fairness.** Rules define their own operating point (any
hit). The unsupervised models are thresholded to a fixed budget (default 100
alerts / 10k processes) chosen on a **validation split**, not on test (s4). The
combined approach is rules OR model. Lab and public splits are reported
separately because the public set is a different distribution and eval-only.

**Confidence intervals.** A single test set gives one number; we attach 95%
intervals by **bootstrapping over sessions** (resample whole sessions with
replacement, recompute each metric), so the interval reflects between-session
variance — the honest uncertainty when there are few hosts — rather than
treating every process as independent. The same session draws are reused across
approaches so the intervals are comparable.

**Ablation.** Features are grouped (cmdline / image / lineage / network /
volume); dropping each group and refitting the Isolation Forest shows which
signals the model actually uses (PR-AUC delta vs. the full model).

**Robustness.** Beyond the session split, a `lab_vs_public` holdout trains only
on the lab and tests only on the public set — the harder, cross-distribution
question of whether the model generalizes off its own host.

Every number is regenerated by `make evaluate`, which also rewrites the README
results table from `summary.csv` (between markers); none is hard-coded, so the
README table stays `TODO` until a real run.

## 8. External SigmaHQ baseline (external.py)

**The rules-only reference is the full SigmaHQ corpus run through an external
tool, not our handful of rules.** Chainsaw (WithSecure) and Hayabusa (Yamato
Security) are Rust CLIs the analyst runs on the same `.evtx` with the SigmaHQ
ruleset; we ingest their output and compare, which is exactly research question
1 ("how much does a pure rules approach miss, per technique").

Why ingest rather than reimplement: those tools *are* the industry rules-only
baseline, and running SigmaHQ ourselves would mean copying rules (forbidden,
CLAUDE.md s3) and re-doing their field mappings. They stay external; we only
parse results.

**Alignment:** each external alert carries a host, an event record id, and
ATT&CK tags. We join `(host, event_record_id)` back to the normalized events to
recover the `process_guid`, so the external baseline lands on the **same
per-process units** as our rules and model — a fair, like-for-like comparison.
Parsers are defensive (field-name variants across tool versions; ATT&CK ids
scraped from tag fields) and tool install is the user's (not a pip dep); tests
use captured sample output so they need neither binary.
