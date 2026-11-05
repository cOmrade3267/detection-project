"""normalize: ingest output -> one common schema (one row per event).

Why: Sysmon (EID 1/3/7/11/13/22) and Security (4688) describe the same actions
with different field names. A single wide, mostly-nullable schema keyed by a
normalized ``action`` verb lets rules and features be written once and lets
process-centric joins (by ``process_guid``) span event types. See
docs/design.md for the trade-off vs. per-type tables.

Design notes:
- A per-(provider, event_id) mapper fills only the fields its action uses.
- EventData is read via ``event_data()``, which handles both the named-object
  form and the list-of-Data form, so we don't depend on one serializer.
- Label columns (label, technique_id, source, session_id) exist on the schema
  but are populated later from the lab run log, never inferred here.
- All functions are pure and operate on dicts, so they unit-test without any
  .evtx file or parser.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from typing import Any

import pandas as pd

from .ingest import TIMESTAMP_DTYPE

# Common-schema columns and dtypes. Routing + action, then process context,
# then per-action fields, then (empty) label columns.
SCHEMA: dict[str, str] = {
    # routing
    "timestamp": TIMESTAMP_DTYPE,
    "host": "string",
    "provider": "string",
    "channel": "string",
    "event_id": "Int64",
    "event_record_id": "Int64",
    "action": "string",
    # process context
    "process_guid": "string",
    "process_id": "Int64",
    "image": "string",
    "command_line": "string",
    "user": "string",
    "integrity_level": "string",
    "hashes": "string",
    "parent_process_guid": "string",
    "parent_process_id": "Int64",
    "parent_image": "string",
    "parent_command_line": "string",
    # network (EID 3)
    "protocol": "string",
    "src_ip": "string",
    "src_port": "Int64",
    "dest_ip": "string",
    "dest_port": "Int64",
    "dest_hostname": "string",
    # image load (EID 7)
    "image_loaded": "string",
    "signed": "string",
    "signature": "string",
    # file create (EID 11)
    "target_filename": "string",
    # registry (EID 13)
    "registry_target": "string",
    "registry_details": "string",
    # dns (EID 22)
    "dns_query": "string",
    "dns_results": "string",
    # labels (filled later from the lab run log, not inferred here)
    "label": "string",
    "technique_id": "string",
    "source": "string",
    "session_id": "string",
}

INT_COLUMNS = {c for c, t in SCHEMA.items() if t == "Int64"}


def event_data(event: dict[str, Any]) -> dict[str, Any]:
    """Return EventData as a flat ``{name: value}`` dict.

    Handles the named-object form ``{"Image": ...}`` and the list-of-Data form
    ``{"Data": [{"@Name": "Image", "#text": ...}]}`` (and a few attribute-key
    spellings) that different renderers emit.
    """
    ed = (event.get("Event") or {}).get("EventData")
    if ed is None:
        return {}
    if isinstance(ed, dict):
        data = ed.get("Data")
        if isinstance(data, list):
            out: dict[str, Any] = {}
            for item in data:
                if isinstance(item, dict):
                    name = item.get("@Name") or item.get("#attributes", {}).get("Name")
                    if name is not None:
                        out[name] = item.get("#text")
            return out
        # Named-object form: EventData keys are already the field names.
        return {k: v for k, v in ed.items() if k != "#attributes"}
    return {}


# --- per-action mappers: each returns the action-specific fields -------------


def _map_process_create(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "action": "process_create",
        "process_guid": d.get("ProcessGuid"),
        "process_id": d.get("ProcessId"),
        "image": d.get("Image"),
        "command_line": d.get("CommandLine"),
        "user": d.get("User"),
        "integrity_level": d.get("IntegrityLevel"),
        "hashes": d.get("Hashes"),
        "parent_process_guid": d.get("ParentProcessGuid"),
        "parent_process_id": d.get("ParentProcessId"),
        "parent_image": d.get("ParentImage"),
        "parent_command_line": d.get("ParentCommandLine"),
    }


def _map_network_connect(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "action": "network_connect",
        "process_guid": d.get("ProcessGuid"),
        "process_id": d.get("ProcessId"),
        "image": d.get("Image"),
        "user": d.get("User"),
        "protocol": d.get("Protocol"),
        "src_ip": d.get("SourceIp"),
        "src_port": d.get("SourcePort"),
        "dest_ip": d.get("DestinationIp"),
        "dest_port": d.get("DestinationPort"),
        "dest_hostname": d.get("DestinationHostname"),
    }


def _map_image_load(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "action": "image_load",
        "process_guid": d.get("ProcessGuid"),
        "image": d.get("Image"),
        "image_loaded": d.get("ImageLoaded"),
        "signed": d.get("Signed"),
        "signature": d.get("Signature"),
        "hashes": d.get("Hashes"),
    }


def _map_file_create(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "action": "file_create",
        "process_guid": d.get("ProcessGuid"),
        "image": d.get("Image"),
        "target_filename": d.get("TargetFilename"),
    }


def _map_registry_set(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "action": "registry_set",
        "process_guid": d.get("ProcessGuid"),
        "image": d.get("Image"),
        "registry_target": d.get("TargetObject"),
        "registry_details": d.get("Details"),
    }


def _map_dns_query(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "action": "dns_query",
        "process_guid": d.get("ProcessGuid"),
        "image": d.get("Image"),
        "dns_query": d.get("QueryName"),
        "dns_results": d.get("QueryResults"),
    }


def _map_security_4688(d: dict[str, Any]) -> dict[str, Any]:
    # Security 4688 names differ from Sysmon; map onto the same process fields.
    return {
        "action": "process_create",
        "process_id": d.get("NewProcessId"),
        "image": d.get("NewProcessName"),
        "command_line": d.get("CommandLine"),
        "user": d.get("SubjectUserName"),
        "integrity_level": d.get("TokenElevationType"),
        "parent_process_id": d.get("ProcessId"),
        "parent_image": d.get("ParentProcessName"),
    }


SYSMON = "Microsoft-Windows-Sysmon"
# Dispatch keyed by (provider_prefix, event_id). Sysmon matches by provider +
# EID; Security 4688 matches by EID regardless of the provider string.
_MAPPERS: dict[tuple[str | None, int], Callable[[dict[str, Any]], dict[str, Any]]] = {
    (SYSMON, 1): _map_process_create,
    (SYSMON, 3): _map_network_connect,
    (SYSMON, 7): _map_image_load,
    (SYSMON, 11): _map_file_create,
    (SYSMON, 13): _map_registry_set,
    (SYSMON, 22): _map_dns_query,
    (None, 4688): _map_security_4688,
}


def _event_id_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize_record(row: dict[str, Any]) -> dict[str, Any]:
    """Map one ingest row (promoted fields + ``event_json``) to the common schema.

    Unmapped event types get ``action='unknown'`` with routing fields still
    filled, so nothing is silently dropped (``event_json`` from ingest carries
    the rest).
    """
    raw = row.get("event_json")
    try:
        event = json.loads(raw) if isinstance(raw, str) else (raw or {})
    except (json.JSONDecodeError, TypeError):
        event = {}

    eid = _event_id_int(row.get("event_id"))
    provider = row.get("provider")
    mapper = _MAPPERS.get((provider, eid)) or _MAPPERS.get((None, eid))

    record: dict[str, Any] = {col: None for col in SCHEMA}
    record.update(
        timestamp=row.get("timestamp"),
        host=row.get("computer"),
        provider=provider,
        channel=row.get("channel"),
        event_id=eid,
        event_record_id=row.get("event_record_id"),
        action="unknown",
    )
    if mapper is not None:
        record.update(mapper(event_data(event)))
    return record


def normalize_frame(frame: pd.DataFrame) -> pd.DataFrame:
    """Normalize an ingest DataFrame into the common schema with stable dtypes."""
    rows = [normalize_record(r) for r in frame.to_dict(orient="records")]
    out = pd.DataFrame(rows, columns=list(SCHEMA))
    out["timestamp"] = pd.to_datetime(out["timestamp"], utc=True, errors="coerce").astype(
        TIMESTAMP_DTYPE
    )
    for col, dtype in SCHEMA.items():
        if col == "timestamp":
            continue
        if col in INT_COLUMNS:
            out[col] = pd.to_numeric(out[col], errors="coerce").astype("Int64")
        else:
            out[col] = out[col].astype(dtype)
    return out


def normalize_records(records: Iterable[dict[str, Any]]) -> pd.DataFrame:
    """Normalize an iterable of ingest row dicts (convenience for tests/streaming)."""
    return normalize_frame(pd.DataFrame(list(records)))


def normalize_file(in_path: str, out_path: str) -> str:
    """Read an ingest Parquet file, normalize it, and write the common-schema Parquet."""
    from pathlib import Path

    frame = pd.read_parquet(in_path)
    out = normalize_frame(frame)
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    out.to_parquet(out_path, index=False)
    return out_path


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Normalize an ingest Parquet to the common schema.")
    parser.add_argument("infile", help="input Parquet from `detect.ingest`")
    parser.add_argument("outfile", help="output normalized Parquet")
    args = parser.parse_args(argv)
    out = normalize_file(args.infile, args.outfile)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    import sys

    raise SystemExit(main(sys.argv[1:]))
