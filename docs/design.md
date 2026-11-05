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

**Isolation Forest (primary) + z-score baseline (B).** Both consume the
`FEATURE_COLUMNS` matrix, impute missing values with a **median learned on
train**, and emit an anomaly score where **higher = more anomalous**. Fitting is
on the training split only (ideally benign rows — `fit_on_benign`), matching the
unsupervised premise: learn "normal", flag outliers.

**Why Isolation Forest:** little labeled attack data in production, so we learn
the benign manifold unsupervised. IF isolates outliers with random splits — near
log-linear, few hyper-parameters, no distance metric to tune, and it handles the
mixed-scale, long-tailed features here better than distance methods. LOF and
one-class SVM are left as optional comparisons (both scale worse and SVM is
kernel/scale-sensitive). IF is split-based so it is scale-invariant; we impute
but don't standardize for it.

**Why the z-score baseline:** the ML model must beat something trivial. The
baseline standardizes each feature on train (mean/std) and scores a process by
its **mean absolute z** across features — a pure "how unusual is this row"
number. If IF can't beat it on PR-AUC, IF isn't earning its complexity.

**Scores, not hard labels:** detectors return continuous scores; thresholding
is deferred to evaluation at a **fixed alert budget** (`alerts_at_budget`), so
rules and model are compared at equal alert volume rather than at arbitrary
cutoffs. Models persist via joblib for a reproducible `make train` → score flow.

## 5. Later decisions

> TODO. Record each remaining decision so it is defensible in an interview:
>
> - Train/test split strategy and how leakage is prevented + tested. (See s3 +
>   detect.split; expand once the full pipeline wiring exists.)
> - Evaluation metric choices (PR-AUC, FP/10k benign) and why not accuracy.
