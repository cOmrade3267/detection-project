"""doctor: a data-quality report over an ingested or normalized event store.

Why: real .evtx expose problems synthetic tests never do -- a provider whose
EventData uses an unexpected key, a whole EID we don't map, clock skew, a host
name that drifts between logs. Finding those by eye in a million-row Parquet is
hopeless. `make doctor` prints the few numbers that catch bad data early:

- events per EID (and per action, once normalized),
- the share of rows we failed to map (action == "unknown"),
- null rate per column (a column that's null everywhere means a broken mapper),
- the time range and per-host counts (catches clock skew and stray hosts),
- duplicate (host, event_record_id) pairs (join key integrity for external.py).

It is read-only and never mutates the data. Numbers printed here are diagnostics,
not results -- they are not the metrics the README reports.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd

# EIDs the pipeline knows how to normalize, for the "unmapped" check. Kept in
# sync with normalize._MAPPERS by intent; doctor only *reports*, so a drift here
# shows up as a higher unmapped count, never as wrong data.
KNOWN_EVENT_IDS = frozenset({1, 3, 7, 11, 13, 22, 4688})


@dataclass
class DoctorReport:
    """Structured data-quality findings for one event store."""

    n_rows: int
    columns: list[str]
    events_per_eid: dict[int, int]
    events_per_action: dict[str, int]
    unmapped_rows: int
    unmapped_event_ids: dict[int, int]
    null_rate: dict[str, float]
    time_min: pd.Timestamp | None
    time_max: pd.Timestamp | None
    hosts: dict[str, int]
    duplicate_record_ids: int
    warnings: list[str] = field(default_factory=list)

    @property
    def unmapped_fraction(self) -> float:
        return self.unmapped_rows / self.n_rows if self.n_rows else 0.0


def _counts(series: pd.Series) -> dict[Any, int]:
    """value -> count, dropping nulls, as plain Python ints (not numpy)."""
    vc = series.value_counts(dropna=True)
    return {k: int(v) for k, v in vc.items()}


def build_report(frame: pd.DataFrame) -> DoctorReport:
    """Compute data-quality findings from an ingested or normalized frame.

    Works on either stage: it keys off whichever columns are present, so it can
    run right after ingest (routing columns only) or after normalize (adds
    ``action`` and the common schema).
    """
    n = len(frame)
    warnings: list[str] = []

    eid_col = "event_id"
    events_per_eid = (
        {int(k): v for k, v in _counts(frame[eid_col]).items()}
        if eid_col in frame.columns
        else {}
    )

    unmapped_event_ids = {k: v for k, v in events_per_eid.items() if k not in KNOWN_EVENT_IDS}

    # Mapped-ness: prefer the normalize signal (action == "unknown") when present,
    # else fall back to EID membership so doctor still works on raw ingest output.
    if "action" in frame.columns:
        events_per_action = _counts(frame["action"])
        unmapped_rows = int((frame["action"] == "unknown").sum())
    else:
        events_per_action = {}
        unmapped_rows = int(frame[eid_col].isin(KNOWN_EVENT_IDS).eq(False).sum()) if eid_col in frame.columns else 0

    null_rate = {col: round(float(frame[col].isna().mean()), 4) for col in frame.columns} if n else {
        col: 0.0 for col in frame.columns
    }

    time_min = time_max = None
    if "timestamp" in frame.columns and frame["timestamp"].notna().any():
        time_min = frame["timestamp"].min()
        time_max = frame["timestamp"].max()
        if time_min == time_max and n > 1:
            warnings.append("all events share one timestamp -- check the clock/parse path")

    host_col = "host" if "host" in frame.columns else ("computer" if "computer" in frame.columns else None)
    hosts = _counts(frame[host_col]) if host_col else {}

    duplicate_record_ids = 0
    if host_col and "event_record_id" in frame.columns:
        key = frame[[host_col, "event_record_id"]].dropna()
        duplicate_record_ids = int(key.duplicated().sum())
        if duplicate_record_ids:
            warnings.append(
                f"{duplicate_record_ids} duplicate (host, event_record_id) rows -- "
                "external.py joins on this key; dedupe or the baseline double-counts"
            )

    if n == 0:
        warnings.append("event store is empty")
    if unmapped_event_ids:
        warnings.append(
            f"{sum(unmapped_event_ids.values())} events in {len(unmapped_event_ids)} "
            f"unmapped EID(s): {sorted(unmapped_event_ids)} -- add a mapper or ignore on purpose"
        )

    return DoctorReport(
        n_rows=n,
        columns=list(frame.columns),
        events_per_eid=dict(sorted(events_per_eid.items())),
        events_per_action=dict(sorted(events_per_action.items(), key=lambda kv: -kv[1])),
        unmapped_rows=unmapped_rows,
        unmapped_event_ids=dict(sorted(unmapped_event_ids.items())),
        null_rate=null_rate,
        time_min=time_min,
        time_max=time_max,
        hosts=dict(sorted(hosts.items(), key=lambda kv: -kv[1])),
        duplicate_record_ids=duplicate_record_ids,
        warnings=warnings,
    )


def format_report(report: DoctorReport, *, max_null_cols: int = 40) -> str:
    """Render a DoctorReport as a compact, human-readable text block."""
    lines: list[str] = []
    lines.append(f"rows: {report.n_rows:,}")
    if report.time_min is not None:
        lines.append(f"time range: {report.time_min}  ->  {report.time_max}")
    lines.append("")

    lines.append("events per EID:")
    for eid, count in report.events_per_eid.items():
        flag = "" if eid in KNOWN_EVENT_IDS else "  <- UNMAPPED"
        lines.append(f"  {eid:>6}: {count:>10,}{flag}")

    if report.events_per_action:
        lines.append("")
        lines.append("events per action:")
        for action, count in report.events_per_action.items():
            lines.append(f"  {action:>16}: {count:>10,}")

    lines.append("")
    pct = 100 * report.unmapped_fraction
    lines.append(f"unmapped rows: {report.unmapped_rows:,} ({pct:.1f}%)")

    lines.append("")
    lines.append(f"hosts ({len(report.hosts)}):")
    for host, count in list(report.hosts.items())[:20]:
        lines.append(f"  {host}: {count:,}")

    # Only surface columns that actually have nulls -- a clean column is noise.
    dirty = {c: r for c, r in report.null_rate.items() if r > 0}
    if dirty:
        lines.append("")
        lines.append("null rate (columns with any nulls):")
        for col, rate in sorted(dirty.items(), key=lambda kv: -kv[1])[:max_null_cols]:
            lines.append(f"  {col:>22}: {rate:6.1%}")

    if report.warnings:
        lines.append("")
        lines.append("WARNINGS:")
        for w in report.warnings:
            lines.append(f"  ! {w}")

    return "\n".join(lines)


def doctor_file(path: str | Path, *, max_null_cols: int = 40) -> DoctorReport:
    """Read a Parquet event store and return its DoctorReport."""
    frame = pd.read_parquet(path)
    return build_report(frame)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Report data-quality diagnostics for an ingested/normalized Parquet."
    )
    parser.add_argument("parquet", type=Path, help="event store (ingest or normalize output)")
    args = parser.parse_args(argv)

    report = doctor_file(args.parquet)
    print(format_report(report))
    # Non-zero exit if nothing parsed, so `make doctor` fails loudly in CI on bad data.
    return 0 if report.n_rows > 0 else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
