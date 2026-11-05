# Test fixtures

Drop a **small** sample `.evtx` here (e.g. one trimmed file from
hayabusa-sample-evtx) to enable the real-parser integration test in
`tests/test_ingest.py`. Without one, that single test is skipped; the pure-logic
tests always run.

`.evtx` files are gitignored (see repo `.gitignore`) — keep them local, mind the
source's license, and do not commit telemetry.
