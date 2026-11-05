# Test fixtures

## `sysmon.evtx`

A small real Sysmon event log, committed so the real-parser integration test in
`tests/test_ingest.py` runs in CI instead of being skipped.

- **Source:** the test corpus of the `evtx` Rust parser we depend on —
  [omerbenamram/evtx](https://github.com/omerbenamram/evtx), file
  `samples/sysmon.evtx`.
- **License:** Apache-2.0 (the parser repo's license). This single data file
  keeps that license; the project's own code stays MIT.
- **Why this one:** it is genuine Sysmon telemetry (EID 1/3/11/13 plus a few we
  don't map), it is the exact parser's own fixture, and it is deliberately
  "dirty" (zero-filled trailing chunks), which exercises our tolerant ingest.
- **SHA-256:** `e1817fd7241ad2b5b9660e179adec878d157f1fa25333e52aef263c69bcd970b`

Two real-log bugs this fixture caught (now regression-tested):
1. A dirty/zero-filled chunk made `records_json()` raise and abort the whole
   ingest — fixed by tolerant iteration (`ingest._iter_tolerant`).
2. pyevtx-rs timestamps carry a trailing `" UTC"` word (`...Z UTC`) that made
   `pd.to_datetime` null every row — fixed by `ingest._clean_timestamps`.

## Other `.evtx`

All other `.evtx` are gitignored. Drop additional local samples here to exercise
the integration test on more data; mind each source's license and do not commit
telemetry from your own lab.
