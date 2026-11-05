"""ingest: raw .evtx -> columnar event store (Parquet).

Why: downstream steps need fast, typed, re-readable access to millions of
events. We convert once to Parquet so normalize/features never re-parse the
binary log.

Parser: the `evtx` package (pyevtx-rs, Rust-backed) via its JSON record output
-- Rust speed with a plain `pip install`, chosen over the `evtx_dump` CLI
(external binary, hurts reproducibility) and pure-Python `python-evtx` (slow at
volume). See docs/design.md for the full justification.

Ingest is faithful, not interpretive: it promotes only routing fields to typed
columns and preserves the whole event as `event_json`. All field interpretation
(EventData -> common schema) belongs in normalize.py, so this module never has
to change when the schema evolves.

The parser import is lazy (inside `evtx_to_records`) so the pure-pandas helpers
below -- and their tests -- do not require the native parser to be installed.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

import pandas as pd

# Canonical timestamp dtype. Fixed explicitly because pandas >=3 infers the
# datetime resolution from the input (us for parsed ISO strings, s for empty),
# so without this the column's unit would vary by pandas version and by whether
# a file had any events.
TIMESTAMP_DTYPE = "datetime64[ns, UTC]"

# Typed columns promoted out of every event. event_json holds the full record
# so normalize.py can reach any field we did not promote.
COLUMNS: dict[str, str] = {
    "event_record_id": "Int64",
    "timestamp": TIMESTAMP_DTYPE,
    "provider": "string",
    "event_id": "Int64",
    "channel": "string",
    "computer": "string",
    "event_json": "string",
}


def evtx_to_records(path: str | Path) -> Iterator[dict[str, Any]]:
    """Yield raw records from an .evtx file as ``{event_record_id, timestamp, data}``.

    ``data`` is the event's JSON *string*, exactly as pyevtx-rs emits it. The
    parser is imported here so importing this module (and unit-testing the
    helpers) never requires the native extension.
    """
    try:
        from evtx import PyEvtxParser
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise ImportError(
            "The 'evtx' parser is not installed. Install the project "
            "(`pip install -e .`), or use the pure-Python fallback "
            "(`pip install -e '.[parsers-pure]'`)."
        ) from exc

    parser = PyEvtxParser(str(path))
    yield from parser.records_json()


def _event_id(system: dict[str, Any]) -> Any:
    """Extract EventID, which may be a bare int or ``{'#text': '1', ...}``."""
    raw = system.get("EventID")
    if isinstance(raw, dict):
        raw = raw.get("#text")
    return raw


def _provider_name(system: dict[str, Any]) -> Any:
    """Provider name lives under ``Provider.#attributes.Name``."""
    provider = system.get("Provider")
    if isinstance(provider, dict):
        return provider.get("#attributes", {}).get("Name")
    return provider


def extract_common_fields(record: dict[str, Any]) -> dict[str, Any]:
    """Map one raw record to the promoted columns, preserving the full event.

    Pure: takes a ``{event_record_id, timestamp, data}`` dict (``data`` a JSON
    string) and returns one row dict. Missing fields become ``None`` rather than
    raising, so a malformed event never aborts a whole ingest run.
    """
    data = record.get("data")
    try:
        event = json.loads(data) if isinstance(data, str) else (data or {})
    except (json.JSONDecodeError, TypeError):
        event = {}

    system = (event.get("Event") or {}).get("System") or {}

    return {
        "event_record_id": record.get("event_record_id"),
        "timestamp": record.get("timestamp"),
        "provider": _provider_name(system),
        "event_id": _event_id(system),
        "channel": system.get("Channel"),
        "computer": system.get("Computer"),
        "event_json": data if isinstance(data, str) else json.dumps(event),
    }


def records_to_frame(records: Iterable[dict[str, Any]]) -> pd.DataFrame:
    """Build a typed DataFrame from raw records, with a stable schema even if empty."""
    rows = [extract_common_fields(r) for r in records]
    frame = pd.DataFrame(rows, columns=list(COLUMNS))
    frame["timestamp"] = pd.to_datetime(
        frame["timestamp"], utc=True, errors="coerce"
    ).astype(TIMESTAMP_DTYPE)
    for col, dtype in COLUMNS.items():
        if col == "timestamp":
            continue
        frame[col] = frame[col].astype(dtype)
    return frame


def write_parquet(frame: pd.DataFrame, out_path: str | Path) -> Path:
    """Write the frame to Parquet, creating parent directories. Returns the path."""
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    frame.to_parquet(out, index=False)
    return out


def ingest_file(evtx_path: str | Path, out_path: str | Path) -> Path:
    """Convert a single .evtx file to a Parquet event store. Returns the output path."""
    frame = records_to_frame(evtx_to_records(evtx_path))
    return write_parquet(frame, out_path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert an .evtx file to Parquet.")
    parser.add_argument("evtx", type=Path, help="input .evtx file")
    parser.add_argument("out", type=Path, help="output .parquet file")
    args = parser.parse_args(argv)

    out = ingest_file(args.evtx, args.out)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
