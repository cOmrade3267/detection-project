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

## 2. Common schema and later decisions

> TODO. Record each remaining decision so it is defensible in an interview:
>
> - Common schema: which fields, how Sysmon and Security EIDs map onto it.
> - Feature set and the justification for each feature (and what was dropped).
> - Why Isolation Forest (vs. LOF / one-class SVM) and the frequency baseline.
> - Train/test split strategy and how leakage is prevented + tested.
> - Evaluation metric choices (PR-AUC, FP/10k benign) and why not accuracy.
