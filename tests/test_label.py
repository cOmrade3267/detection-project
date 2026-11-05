"""Tests for detect.label (time-window labeling from the run log)."""

import pandas as pd
import pytest

from detect import label


def _events():
    # Two hosts; events at various times.
    rows = [
        ("lab01", "2021-03-01T12:00:30Z", 1),   # inside malicious window on lab01
        ("lab01", "2021-03-01T13:30:00Z", 2),   # inside benign window on lab01
        ("lab01", "2021-03-01T20:00:00Z", 3),   # outside every window
        ("lab02", "2021-03-01T12:00:30Z", 4),   # same time as #1 but different host
    ]
    return pd.DataFrame(
        [{"host": h, "timestamp": t, "event_record_id": r,
          "label": None, "technique_id": None, "source": None, "session_id": None}
         for h, t, r in rows]
    )


def _labels():
    return pd.DataFrame([
        {"session_id": "mal-1", "host": "lab01", "source": "lab", "label": "malicious",
         "technique_id": "T1059.001", "start_utc": "2021-03-01T12:00:00Z",
         "end_utc": "2021-03-01T12:01:00Z"},
        {"session_id": "ben-1", "host": "lab01", "source": "lab", "label": "benign",
         "technique_id": "", "start_utc": "2021-03-01T13:00:00Z",
         "end_utc": "2021-03-01T14:00:00Z"},
    ])


def test_event_inside_malicious_window_is_labeled():
    out = label.attach_labels(_events(), _labels()).set_index("event_record_id")
    assert out.loc[1, "label"] == "malicious"
    assert out.loc[1, "technique_id"] == "T1059.001"
    assert out.loc[1, "session_id"] == "mal-1"
    assert out.loc[1, "source"] == "lab"


def test_event_inside_benign_window_is_benign():
    out = label.attach_labels(_events(), _labels()).set_index("event_record_id")
    assert out.loc[2, "label"] == "benign"
    assert out.loc[2, "session_id"] == "ben-1"


def test_event_outside_all_windows_gets_default():
    out = label.attach_labels(_events(), _labels(), default_source="lab").set_index("event_record_id")
    assert out.loc[3, "label"] == "benign"
    assert pd.isna(out.loc[3, "session_id"])
    assert out.loc[3, "source"] == "lab"  # default applied


def test_host_mismatch_is_not_labeled_by_other_host_window():
    out = label.attach_labels(_events(), _labels()).set_index("event_record_id")
    # Same timestamp as the malicious event but on lab02 -> no window -> benign default.
    assert out.loc[4, "label"] == "benign"
    assert pd.isna(out.loc[4, "technique_id"])


def test_malicious_wins_on_overlap():
    events = pd.DataFrame([{"host": "lab01", "timestamp": "2021-03-01T12:00:30Z",
                            "event_record_id": 1, "label": None, "technique_id": None,
                            "source": None, "session_id": None}])
    # Benign and malicious windows both cover the event.
    labels = pd.DataFrame([
        {"session_id": "ben", "host": "lab01", "source": "lab", "label": "benign",
         "technique_id": "", "start_utc": "2021-03-01T12:00:00Z", "end_utc": "2021-03-01T12:01:00Z"},
        {"session_id": "mal", "host": "lab01", "source": "lab", "label": "malicious",
         "technique_id": "T1105", "start_utc": "2021-03-01T12:00:00Z", "end_utc": "2021-03-01T12:01:00Z"},
    ])
    out = label.attach_labels(events, labels)
    assert out.loc[0, "label"] == "malicious"
    assert out.loc[0, "technique_id"] == "T1105"


def test_missing_optional_columns_are_tolerated():
    events = _events()
    labels = pd.DataFrame([{"session_id": "s1", "host": "lab01", "label": "malicious",
                            "start_utc": "2021-03-01T12:00:00Z", "end_utc": "2021-03-01T12:01:00Z"}])
    out = label.attach_labels(events, labels, default_source="lab").set_index("event_record_id")
    assert out.loc[1, "label"] == "malicious"
    assert pd.isna(out.loc[1, "technique_id"])  # no technique_id column -> NA
    assert out.loc[1, "source"] == "lab"        # falls back to default


def test_label_columns_are_string_dtype():
    out = label.attach_labels(_events(), _labels())
    for col in ("label", "technique_id", "source", "session_id"):
        assert str(out[col].dtype) == "string"


def test_missing_required_column_raises():
    bad = pd.DataFrame([{"host": "lab01", "label": "malicious"}])  # no start/end/session
    with pytest.raises(ValueError, match="required column"):
        label.attach_labels(_events(), bad)


def test_label_file_roundtrip(tmp_path):
    _events().to_parquet(tmp_path / "events.parquet", index=False)
    _labels().to_csv(tmp_path / "labels.csv", index=False)
    out = label.label_file(tmp_path / "events.parquet", tmp_path / "labels.csv",
                           tmp_path / "labeled.parquet", default_source="lab")
    labeled = pd.read_parquet(out)
    assert (labeled["label"] == "malicious").sum() == 1
    assert set(labeled["source"].dropna()) == {"lab"}


def test_attach_labels_carries_run_metadata_onto_events():
    """L1/L4: per-run metadata (defender/sysmon/os/user/run_id) flows to events."""
    events = pd.DataFrame([{
        "host": "lab01", "timestamp": "2021-03-01T12:00:30Z", "event_record_id": 1,
        "label": None, "technique_id": None, "source": None, "session_id": None,
    }])
    labels = pd.DataFrame([{
        "run_id": "r0007", "session_id": "mal-1", "host": "lab01", "source": "lab",
        "label": "malicious", "technique_id": "T1059.001", "atomic_test_number": "1",
        "defender_state": "off", "sysmon_config": "swift", "os_version": "win11-23h2",
        "user_type": "standard",
        "start_utc": "2021-03-01T12:00:00Z", "end_utc": "2021-03-01T12:01:00Z",
    }])
    out = label.attach_labels(events, labels)
    row = out.iloc[0]
    assert row["label"] == "malicious"
    assert row["run_id"] == "r0007"
    assert row["defender_state"] == "off"
    assert row["sysmon_config"] == "swift"
    assert row["os_version"] == "win11-23h2"
    assert row["user_type"] == "standard"
    assert row["atomic_test_number"] == "1"


def test_attach_labels_works_without_metadata_columns():
    """Minimal labels.csv (no metadata columns) still validates and labels."""
    events = pd.DataFrame([{
        "host": "h", "timestamp": "2021-03-01T12:00:30Z", "event_record_id": 1,
        "label": None, "technique_id": None, "source": None, "session_id": None,
    }])
    labels = pd.DataFrame([{
        "session_id": "s", "host": "h", "label": "malicious",
        "start_utc": "2021-03-01T12:00:00Z", "end_utc": "2021-03-01T12:01:00Z",
    }])
    out = label.attach_labels(events, labels)
    assert out.loc[0, "label"] == "malicious"
    assert pd.isna(out.loc[0, "defender_state"])  # absent metadata -> NA, no crash
