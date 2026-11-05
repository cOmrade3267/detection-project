"""Tests for detect.doctor (data-quality report). Synthetic frames only."""

import pandas as pd

from detect import doctor


def _normalized(rows):
    """Build a minimal normalized-shape frame from partial row dicts."""
    cols = {
        "timestamp": pd.NaT, "host": None, "event_id": pd.NA,
        "event_record_id": pd.NA, "action": None, "process_guid": None,
    }
    frame = pd.DataFrame([{**cols, **r} for r in rows])
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True)
    frame["event_id"] = frame["event_id"].astype("Int64")
    frame["event_record_id"] = frame["event_record_id"].astype("Int64")
    return frame


def test_counts_per_eid_and_action():
    frame = _normalized([
        {"event_id": 1, "action": "process_create", "event_record_id": 1, "host": "h1"},
        {"event_id": 1, "action": "process_create", "event_record_id": 2, "host": "h1"},
        {"event_id": 3, "action": "network_connect", "event_record_id": 3, "host": "h1"},
    ])
    r = doctor.build_report(frame)
    assert r.n_rows == 3
    assert r.events_per_eid == {1: 2, 3: 1}
    assert r.events_per_action["process_create"] == 2
    assert r.unmapped_rows == 0


def test_unmapped_event_ids_flagged():
    frame = _normalized([
        {"event_id": 1, "action": "process_create", "event_record_id": 1, "host": "h"},
        {"event_id": 4624, "action": "unknown", "event_record_id": 2, "host": "h"},
        {"event_id": 5156, "action": "unknown", "event_record_id": 3, "host": "h"},
    ])
    r = doctor.build_report(frame)
    assert set(r.unmapped_event_ids) == {4624, 5156}
    assert r.unmapped_rows == 2
    assert any("unmapped" in w.lower() for w in r.warnings)


def test_duplicate_record_ids_warned():
    frame = _normalized([
        {"event_id": 1, "action": "process_create", "event_record_id": 7, "host": "h"},
        {"event_id": 1, "action": "process_create", "event_record_id": 7, "host": "h"},
    ])
    r = doctor.build_report(frame)
    assert r.duplicate_record_ids == 1
    assert any("duplicate" in w.lower() for w in r.warnings)


def test_null_rate_computed():
    frame = _normalized([
        {"event_id": 1, "action": "process_create", "event_record_id": 1, "host": "h",
         "process_guid": "{p1}"},
        {"event_id": 1, "action": "process_create", "event_record_id": 2, "host": "h",
         "process_guid": None},
    ])
    r = doctor.build_report(frame)
    assert r.null_rate["process_guid"] == 0.5


def test_single_timestamp_warns():
    frame = _normalized([
        {"event_id": 1, "action": "process_create", "event_record_id": 1, "host": "h",
         "timestamp": "2021-03-01T12:00:00Z"},
        {"event_id": 1, "action": "process_create", "event_record_id": 2, "host": "h",
         "timestamp": "2021-03-01T12:00:00Z"},
    ])
    r = doctor.build_report(frame)
    assert r.time_min == r.time_max
    assert any("timestamp" in w for w in r.warnings)


def test_works_on_raw_ingest_shape():
    """Doctor runs before normalize, keying off computer/event_id, no action col."""
    frame = pd.DataFrame({
        "event_record_id": pd.array([1, 2], dtype="Int64"),
        "event_id": pd.array([1, 9999], dtype="Int64"),
        "computer": ["h", "h"],
    })
    r = doctor.build_report(frame)
    assert r.events_per_eid == {1: 1, 9999: 1}
    assert 9999 in r.unmapped_event_ids
    assert r.hosts == {"h": 2}


def test_empty_frame_is_warned_not_crashed():
    frame = _normalized([
        {"event_id": 1, "action": "process_create", "event_record_id": 1, "host": "h"},
    ]).iloc[0:0]  # keep the schema, drop all rows
    r = doctor.build_report(frame)
    assert r.n_rows == 0
    assert any("empty" in w for w in r.warnings)


def test_format_report_renders():
    frame = _normalized([
        {"event_id": 1, "action": "process_create", "event_record_id": 1, "host": "h",
         "timestamp": "2021-03-01T12:00:00Z"},
    ])
    text = doctor.format_report(doctor.build_report(frame))
    assert "events per EID" in text
    assert "rows: 1" in text
