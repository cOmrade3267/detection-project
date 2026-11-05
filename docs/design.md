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

## 3. Later decisions

> TODO. Record each remaining decision so it is defensible in an interview:
>
> - Feature set and the justification for each feature (and what was dropped).
> - Why Isolation Forest (vs. LOF / one-class SVM) and the frequency baseline.
> - Train/test split strategy and how leakage is prevented + tested.
> - Evaluation metric choices (PR-AUC, FP/10k benign) and why not accuracy.
