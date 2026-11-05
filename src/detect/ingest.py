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
import time
import warnings
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd

# Default records per Parquet row group when streaming. Big enough to amortize
# per-chunk overhead, small enough that peak memory stays flat on huge files.
DEFAULT_CHUNK_SIZE = 50_000

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


def _iter_tolerant(records: Iterable[dict[str, Any]], *, strict: bool) -> Iterator[dict[str, Any]]:
    """Yield from the parser's record stream, surviving a mid-file parse error.

    Real .evtx are routinely "dirty": a log allocates fixed-size chunks and
    leaves the unused tail zero-filled, so pyevtx-rs raises when it reaches the
    first blank chunk. The generator cannot be resumed once it raises (the
    binding validates chunks eagerly and offers no per-chunk skip), so we
    recover every record up to that point and stop.

    This truncates on a *mid*-file corruption, which would silently under-count
    detections -- so we warn loudly with the recovered count, and ``strict=True``
    re-raises instead for runs that must fail on any unreadable byte.
    """
    iterator = iter(records)
    recovered = 0
    while True:
        try:
            record = next(iterator)
        except StopIteration:
            return
        except Exception as exc:  # parser chunk/record failure
            if strict:
                raise
            warnings.warn(
                f"evtx parse stopped after {recovered} records: {exc}. "
                "Recovered records emitted; tail (if any) skipped. "
                "Re-run with strict=True to fail instead.",
                RuntimeWarning,
                stacklevel=2,
            )
            return
        recovered += 1
        yield record


def evtx_to_records(path: str | Path, *, strict: bool = False) -> Iterator[dict[str, Any]]:
    """Yield raw records from an .evtx file as ``{event_record_id, timestamp, data}``.

    ``data`` is the event's JSON *string*, exactly as pyevtx-rs emits it. The
    parser is imported here so importing this module (and unit-testing the
    helpers) never requires the native extension. A parse error partway through
    a dirty log is tolerated (see :func:`_iter_tolerant`) unless ``strict``.
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
    yield from _iter_tolerant(parser.records_json(), strict=strict)


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


def _clean_timestamps(series: pd.Series) -> pd.Series:
    """Parse the parser's timestamp strings to UTC, tolerating its quirks.

    pyevtx-rs renders timestamps like ``2017-12-26T13:10:29.1368792Z UTC`` -- an
    ISO instant with a trailing `` UTC`` zone *name* appended after the ``Z``.
    pandas can't parse that compound form and coerces the whole column to NaT,
    which would silently null every timestamp (breaking the time split, label
    windows, and doctor's range). Strip a trailing zone-name word before parsing.
    """
    if not pd.api.types.is_datetime64_any_dtype(series):
        # Not already parsed (object/string/str across pandas versions): drop a
        # trailing zone-NAME word (" UTC"); the preceding Z/offset already fixes
        # the zone, so this leaves a string pandas can parse.
        series = series.astype("string").str.replace(r"\s+UTC\s*$", "", regex=True, case=False)
    return pd.to_datetime(series, utc=True, errors="coerce").astype(TIMESTAMP_DTYPE)


def records_to_frame(records: Iterable[dict[str, Any]]) -> pd.DataFrame:
    """Build a typed DataFrame from raw records, with a stable schema even if empty."""
    rows = [extract_common_fields(r) for r in records]
    frame = pd.DataFrame(rows, columns=list(COLUMNS))
    frame["timestamp"] = _clean_timestamps(frame["timestamp"])
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


def iter_record_frames(
    records: Iterable[dict[str, Any]], chunk_size: int = DEFAULT_CHUNK_SIZE
) -> Iterator[pd.DataFrame]:
    """Yield typed DataFrames of at most ``chunk_size`` rows from a record stream.

    Streaming keeps peak memory bounded by one chunk instead of the whole log,
    which matters on multi-GB .evtx files. Each chunk goes through
    ``records_to_frame`` so every chunk carries the identical, forced schema.
    """
    if chunk_size < 1:
        raise ValueError("chunk_size must be >= 1")
    batch: list[dict[str, Any]] = []
    for record in records:
        batch.append(record)
        if len(batch) >= chunk_size:
            yield records_to_frame(batch)
            batch = []
    if batch:
        yield records_to_frame(batch)


@dataclass
class IngestStats:
    """Reproducible throughput numbers from one ingest run."""

    rows: int
    seconds: float
    out_path: Path

    @property
    def events_per_sec(self) -> float:
        return self.rows / self.seconds if self.seconds > 0 else float("nan")


def write_parquet_stream(
    frames: Iterable[pd.DataFrame], out_path: str | Path
) -> tuple[Path, int]:
    """Write typed frames to one Parquet file as successive row groups.

    Uses a single ``ParquetWriter`` so memory stays flat regardless of file
    size. The schema is pinned from an empty typed frame, so an all-null chunk
    (e.g. a run of unmapped events) can't drift the column types between row
    groups. Returns ``(path, total_rows)``; always writes a valid, schema-correct
    file even when the stream is empty.
    """
    import pyarrow as pa
    import pyarrow.parquet as pq

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    schema = pa.Table.from_pandas(records_to_frame([]), preserve_index=False).schema
    writer = pq.ParquetWriter(out, schema)
    total = 0
    try:
        for frame in frames:
            if frame.empty:
                continue
            table = pa.Table.from_pandas(frame, schema=schema, preserve_index=False)
            writer.write_table(table)
            total += frame.shape[0]
    finally:
        writer.close()
    return out, total


def ingest_file(
    evtx_path: str | Path,
    out_path: str | Path,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> IngestStats:
    """Stream a single .evtx file to a Parquet event store in bounded memory.

    Returns :class:`IngestStats` (row count, wall-clock seconds, output path) so
    throughput is measured by the same path that does the real work -- no
    separate, divergent benchmark code.
    """
    start = time.perf_counter()
    frames = iter_record_frames(evtx_to_records(evtx_path), chunk_size=chunk_size)
    out, rows = write_parquet_stream(frames, out_path)
    return IngestStats(rows=rows, seconds=time.perf_counter() - start, out_path=out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert an .evtx file to Parquet.")
    parser.add_argument("evtx", type=Path, help="input .evtx file")
    parser.add_argument("out", type=Path, help="output .parquet file")
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        help=f"records per Parquet row group (default {DEFAULT_CHUNK_SIZE})",
    )
    args = parser.parse_args(argv)

    stats = ingest_file(args.evtx, args.out, chunk_size=args.chunk_size)
    print(
        f"wrote {stats.out_path} "
        f"({stats.rows} events in {stats.seconds:.2f}s, "
        f"{stats.events_per_sec:,.0f} events/sec)"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
