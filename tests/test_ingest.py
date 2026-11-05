"""Tests for detect.ingest.

The pure helpers (extract_common_fields, records_to_frame, write_parquet) are
tested with synthetic records -- no native parser required. The real .evtx path
is covered by an integration test that is skipped unless a sample file is
present under tests/fixtures/ (see tests/fixtures/README.md).
"""

import json
from pathlib import Path

import pandas as pd
import pytest

from detect import ingest

FIXTURES = Path(__file__).parent / "fixtures"


def _record(event: dict, record_id: int = 1, timestamp: str = "2021-03-01T12:00:00Z") -> dict:
    """Shape a raw record the way pyevtx-rs emits it (data = JSON string)."""
    return {"event_record_id": record_id, "timestamp": timestamp, "data": json.dumps(event)}


SYSMON_PROC_CREATE = {
    "Event": {
        "System": {
            "Provider": {"#attributes": {"Name": "Microsoft-Windows-Sysmon", "Guid": "..."}},
            "EventID": 1,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Computer": "WIN-LAB01",
        },
        "EventData": {"Image": "C:\\Windows\\System32\\cmd.exe"},
    }
}


def test_extract_promotes_routing_fields_and_keeps_full_event():
    row = ingest.extract_common_fields(_record(SYSMON_PROC_CREATE))
    assert row["event_record_id"] == 1
    assert row["provider"] == "Microsoft-Windows-Sysmon"
    assert row["event_id"] == 1
    assert row["channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert row["computer"] == "WIN-LAB01"
    # Full event preserved for normalize.py.
    assert json.loads(row["event_json"])["Event"]["EventData"]["Image"].endswith("cmd.exe")


def test_extract_handles_eventid_dict_form():
    event = {"Event": {"System": {"EventID": {"#text": "4688", "Qualifiers": "0"}}}}
    row = ingest.extract_common_fields(_record(event))
    assert row["event_id"] == "4688"


def test_extract_missing_fields_become_none_not_error():
    row = ingest.extract_common_fields({"event_record_id": 9, "timestamp": "x", "data": "{}"})
    assert row["provider"] is None
    assert row["event_id"] is None
    assert row["computer"] is None


def test_extract_malformed_json_does_not_raise():
    row = ingest.extract_common_fields({"event_record_id": 2, "timestamp": "t", "data": "{bad"})
    assert row["provider"] is None
    assert row["event_json"] == "{bad"  # raw string preserved as-is


def test_records_to_frame_is_typed_and_sorted():
    frame = ingest.records_to_frame([_record(SYSMON_PROC_CREATE)])
    assert list(frame.columns) == list(ingest.COLUMNS)
    assert str(frame["event_id"].dtype) == "Int64"
    assert str(frame["timestamp"].dtype) == "datetime64[ns, UTC]"
    assert str(frame["provider"].dtype) == "string"


def test_records_to_frame_empty_keeps_schema():
    frame = ingest.records_to_frame([])
    assert len(frame) == 0
    assert list(frame.columns) == list(ingest.COLUMNS)
    assert str(frame["timestamp"].dtype) == "datetime64[ns, UTC]"


def test_write_parquet_roundtrip(tmp_path):
    frame = ingest.records_to_frame([_record(SYSMON_PROC_CREATE)])
    out = ingest.write_parquet(frame, tmp_path / "nested" / "events.parquet")
    assert out.exists()
    back = pd.read_parquet(out)
    assert back.loc[0, "provider"] == "Microsoft-Windows-Sysmon"
    assert back.loc[0, "event_id"] == 1


# --- Integration: real parser, gated on a sample file ------------------------

_samples = sorted(FIXTURES.glob("*.evtx")) if FIXTURES.exists() else []


@pytest.mark.skipif(not _samples, reason="no sample .evtx under tests/fixtures/")
def test_ingest_real_evtx_file(tmp_path):
    out = ingest.ingest_file(_samples[0], tmp_path / "events.parquet")
    frame = pd.read_parquet(out)
    assert len(frame) > 0
    assert list(frame.columns) == list(ingest.COLUMNS)
    assert frame["event_id"].notna().any()
