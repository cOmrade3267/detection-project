"""label: attach labels from a run log to normalized events (time-window rule).

Labels are never inferred from event content -- they come from the lab run log
(`labels.csv`, one row per session/test). An event is labeled by the row whose
`host` matches the event's host and whose `[start_utc, end_utc]` contains the
event timestamp; it inherits that row's label, technique_id, source and
session_id. Events matching no window are **unlabeled** (setup, prerequisite
downloads, idle time: activity nobody vouched for) and are excluded from
training and evaluation downstream; they are NOT assumed benign. Where a benign
and a malicious window overlap, malicious wins. See docs/lab-setup.md s5.

Pure pandas; unit-testable with small frames.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

UNLABELED = "unlabeled"
REQUIRED_COLUMNS = {"session_id", "host", "label", "start_utc", "end_utc"}
# Per-run metadata carried from the run log onto each matched event, so later
# splits can hold out a host / Sysmon config / Defender state without re-running
# collection (L1, L4). `notes` stays in the run log only.
META_COLUMNS = ["run_id", "atomic_test_number", "defender_state",
                "sysmon_config", "os_version", "user_type"]
OPTIONAL_COLUMNS = {"source", "technique_id", "notes", *META_COLUMNS}
# Fields written onto events (source handled separately for its default).
_CARRY_FIELDS = ["technique_id", "session_id", *META_COLUMNS]
_STRING_FIELDS = ["label", "source", *_CARRY_FIELDS]


def load_labels(path: str | Path) -> pd.DataFrame:
    """Read a run-log CSV and validate its columns."""
    labels = pd.read_csv(path)
    _validate_labels(labels)
    return labels


def _validate_labels(labels: pd.DataFrame) -> None:
    missing = REQUIRED_COLUMNS - set(labels.columns)
    if missing:
        raise ValueError(f"labels is missing required column(s): {sorted(missing)}")


def attach_labels(
    events: pd.DataFrame,
    labels: pd.DataFrame,
    *,
    default_label: str = UNLABELED,
    default_source: str | None = None,
) -> pd.DataFrame:
    """Return events with label/technique_id/source/session_id filled from `labels`.

    Malicious windows are applied after benign ones, so on any overlap the
    malicious label wins. Events in no window get ``default_label`` (``unlabeled``
    by default, so setup noise is never silently counted as benign).
    """
    _validate_labels(labels)
    out = events.copy()
    ts = pd.to_datetime(out["timestamp"], utc=True, errors="coerce")
    host = out["host"].astype("object") if "host" in out.columns else pd.Series(
        [pd.NA] * len(out), index=out.index, dtype="object"
    )

    # Initialise to defaults (overwritten per matching window below).
    out["label"] = default_label
    out["source"] = default_source
    for col in _CARRY_FIELDS:
        out[col] = pd.NA

    lab = labels.copy()
    for col in OPTIONAL_COLUMNS:
        if col not in lab.columns:
            lab[col] = pd.NA
    lab["win_start"] = pd.to_datetime(lab["start_utc"], utc=True, errors="coerce")
    lab["win_end"] = pd.to_datetime(lab["end_utc"], utc=True, errors="coerce")
    # Apply benign windows first, malicious last, so malicious overwrites overlap.
    lab["win_order"] = lab["label"].map({"benign": 0, "malicious": 1}).fillna(0)
    lab = lab.sort_values(["win_order", "win_start"], kind="stable")

    for row in lab.itertuples(index=False):
        mask = (host == row.host) & ts.between(row.win_start, row.win_end, inclusive="both")
        if not mask.any():
            continue
        out.loc[mask, "label"] = row.label
        out.loc[mask, "source"] = row.source if pd.notna(row.source) else default_source
        for col in _CARRY_FIELDS:
            out.loc[mask, col] = getattr(row, col)

    for col in _STRING_FIELDS:
        out[col] = out[col].astype("string")
    return out


def label_file(
    events_path: str | Path,
    labels_path: str | Path,
    out_path: str | Path,
    *,
    default_label: str = UNLABELED,
    default_source: str | None = None,
) -> str:
    """Read a normalized Parquet + labels CSV, attach labels, write the result."""
    events = pd.read_parquet(events_path)
    labels = load_labels(labels_path)
    out = attach_labels(events, labels, default_label=default_label,
                        default_source=default_source)
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    out.to_parquet(out_path, index=False)
    return str(out_path)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Attach run-log labels to normalized events.")
    parser.add_argument("events", help="normalized Parquet from `detect.normalize`")
    parser.add_argument("labels", help="run-log CSV (see docs/lab-setup.md s5)")
    parser.add_argument("out", help="output labeled Parquet")
    parser.add_argument("--default-source", default=None,
                        help="source for events outside every window (e.g. lab)")
    parser.add_argument("--default-label", default=UNLABELED,
                        choices=[UNLABELED, "benign", "malicious"],
                        help="label for events outside every window (default: unlabeled, "
                             "which is excluded from training/evaluation)")
    args = parser.parse_args(argv)

    out = label_file(args.events, args.labels, args.out,
                     default_label=args.default_label, default_source=args.default_source)
    labeled = pd.read_parquet(out)
    counts = labeled["label"].value_counts().to_dict()
    print(f"labeled {len(labeled)} events {counts}; wrote {out}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    import sys

    raise SystemExit(main(sys.argv[1:]))
