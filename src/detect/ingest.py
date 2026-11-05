"""ingest: raw .evtx -> columnar event store (JSON/Parquet).

Why: downstream steps need fast, typed, re-readable access to millions of
events. We convert once to Parquet so normalize/features never re-parse XML.
The .evtx parser (Rust `evtx_dump` vs. `python-evtx`) is a decision to make
and justify here before any code lands — see CLAUDE.md suggested prompt #2.

TODO: implement. No logic yet (scaffold).
"""
