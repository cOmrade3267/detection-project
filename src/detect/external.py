"""external: ingest Chainsaw / Hayabusa output as the SigmaHQ rules-only baseline.

Chainsaw (WithSecure) and Hayabusa (Yamato Security) run the SigmaHQ corpus over
.evtx and emit JSON. We parse that into a common alert table and join it back to
our normalized events on (host, event_record_id) to recover process_guid, so the
external baseline is scored on the same per-process units as our rules/model.

The tools are installed by the user (not a Python dependency). Parsers are
tolerant of field-name differences across versions; tests use captured sample
output, so no binary is required. See docs/design.md s8.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pandas as pd

EXTERNAL_ALERT_COLUMNS = [
    "tool", "timestamp", "host", "event_record_id", "event_id",
    "level", "rule_title", "technique_id",
]

_TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


def _techniques(*values: Any) -> list[str]:
    """Collect normalized ATT&CK technique ids from arbitrary strings/lists."""
    found: list[str] = []
    stack = list(values)
    while stack:
        v = stack.pop()
        if isinstance(v, (list, tuple)):
            stack.extend(v)
        elif isinstance(v, str):
            found.extend(m.upper() for m in _TID_RE.findall(v))
    # de-dup, keep order
    seen: dict[str, None] = {}
    for t in found:
        seen.setdefault(t, None)
    return list(seen)


def _first(d: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return None


def _rows_to_frame(rows: list[dict[str, Any]]) -> pd.DataFrame:
    """Explode per-alert technique lists into one row per (alert, technique)."""
    out: list[dict[str, Any]] = []
    for r in rows:
        techs = r.pop("_techniques", []) or [None]
        for t in techs:
            out.append({**r, "technique_id": t})
    frame = pd.DataFrame(out, columns=EXTERNAL_ALERT_COLUMNS)
    frame["event_record_id"] = pd.to_numeric(frame["event_record_id"], errors="coerce").astype("Int64")
    frame["event_id"] = pd.to_numeric(frame["event_id"], errors="coerce").astype("Int64")
    for c in ("tool", "host", "level", "rule_title", "technique_id"):
        frame[c] = frame[c].astype("string")
    return frame


def parse_chainsaw(data: list[dict[str, Any]]) -> pd.DataFrame:
    """Parse `chainsaw hunt --json` detections into the common alert schema."""
    rows = []
    for d in data:
        doc = (d.get("document") or {}).get("data")
        if not isinstance(doc, dict):
            doc = {"Event": d["Event"]} if "Event" in d else {}
        system = (doc.get("Event") or {}).get("System") or {}
        eid = system.get("EventID")
        if isinstance(eid, dict):
            eid = eid.get("#text")
        rows.append({
            "tool": "chainsaw",
            "timestamp": _first(d, "timestamp", "Timestamp"),
            "host": system.get("Computer"),
            "event_record_id": system.get("EventRecordID"),
            "event_id": eid,
            "level": _first(d, "level", "Level"),
            "rule_title": _first(d, "name", "title", "Name"),
            "_techniques": _techniques(d.get("tags"), d.get("Tags"), d.get("sigma")),
        })
    return _rows_to_frame(rows)


def parse_hayabusa(data: list[dict[str, Any]]) -> pd.DataFrame:
    """Parse `hayabusa json-timeline` records into the common alert schema."""
    rows = []
    for r in data:
        rows.append({
            "tool": "hayabusa",
            "timestamp": _first(r, "Timestamp", "timestamp"),
            "host": _first(r, "Computer", "computer"),
            "event_record_id": _first(r, "RecordID", "RecordId", "record_id"),
            "event_id": _first(r, "EventID", "EventId", "event_id"),
            "level": _first(r, "Level", "level"),
            "rule_title": _first(r, "RuleTitle", "rule_title", "Title"),
            "_techniques": _techniques(
                r.get("MitreTags"), r.get("MitreTechniques"), r.get("MitreAttack"),
                r.get("MitreTactics"),
            ),
        })
    return _rows_to_frame(rows)


_PARSERS = {"chainsaw": parse_chainsaw, "hayabusa": parse_hayabusa}


def _read_json_or_jsonl(path: str | Path) -> list[dict[str, Any]]:
    text = Path(path).read_text().strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]


def load_external_alerts(path: str | Path, tool: str) -> pd.DataFrame:
    """Load a Chainsaw/Hayabusa output file (JSON array or JSONL)."""
    if tool not in _PARSERS:
        raise ValueError(f"unknown tool '{tool}'; expected one of {sorted(_PARSERS)}")
    return _PARSERS[tool](_read_json_or_jsonl(path))


def alerts_to_process(alerts: pd.DataFrame, events: pd.DataFrame) -> pd.DataFrame:
    """Join external alerts to events on (host, event_record_id) -> per-process rows.

    Columns: process_guid, alerted(=True), n_alerts, techniques, tools. Alerts
    that don't map to a process (event absent, or event has no process_guid) are
    dropped from the per-process view.
    """
    cols = ["process_guid", "alerted", "n_alerts", "techniques", "tools"]
    if alerts.empty or events.empty:
        return pd.DataFrame(columns=cols)

    ev = events[["host", "event_record_id", "process_guid"]].copy()
    ev["event_record_id"] = pd.to_numeric(ev["event_record_id"], errors="coerce").astype("Int64")
    ev["host"] = ev["host"].astype("string")
    a = alerts.copy()
    a["host"] = a["host"].astype("string")

    merged = a.merge(ev, on=["host", "event_record_id"], how="inner")
    merged = merged[merged["process_guid"].notna()]
    if merged.empty:
        return pd.DataFrame(columns=cols)

    def _join_unique(s: pd.Series) -> str:
        return ",".join(sorted({str(x) for x in s.dropna()}))

    grouped = merged.groupby("process_guid")
    out = pd.DataFrame({
        "n_alerts": grouped.size(),
        "techniques": grouped["technique_id"].apply(_join_unique),
        "tools": grouped["tool"].apply(_join_unique),
    }).reset_index()
    out["alerted"] = True
    return out[cols]
