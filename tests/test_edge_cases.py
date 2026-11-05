"""Phase 5 edge cases: empty input, missing columns, malformed events,
timezone handling, duplicate record ids -- the inputs real data throws that the
happy-path tests don't. Kept in one place so the contract is easy to review.
"""

import json

import numpy as np
import pandas as pd
import pytest

from detect import doctor, external, ingest, label, normalize
from detect.features import FeatureBuilder
from detect.model import IsolationForestDetector, select_features

# --- timezone handling -------------------------------------------------------


@pytest.mark.parametrize(
    "ts,expected_hour",
    [
        ("2021-03-01T12:00:00Z", 12),                 # Z
        ("2021-03-01T12:00:00.123456Z UTC", 12),      # pyevtx-rs Z-UTC + fractional
        ("2021-03-01T07:00:00-05:00", 12),            # offset -> same instant as 12:00Z
        ("2021-03-01 12:00:00", 12),                  # naive -> assumed UTC
    ],
)
def test_ingest_timestamp_variants_parse_to_utc(ts, expected_hour):
    # Real .evtx from one tool use one timestamp format; test each on its own.
    frame = ingest.records_to_frame([{"event_record_id": 1, "timestamp": ts, "data": "{}"}])
    assert frame["timestamp"].notna().all()
    assert str(frame["timestamp"].dtype) == "datetime64[ns, UTC]"
    assert frame.loc[0, "timestamp"].hour == expected_hour


def test_ingest_unparseable_timestamp_becomes_nat_not_error():
    frame = ingest.records_to_frame([
        {"event_record_id": 1, "timestamp": "not-a-date", "data": "{}"},
    ])
    assert pd.isna(frame.loc[0, "timestamp"])  # coerced, no raise


# --- malformed events --------------------------------------------------------


def test_normalize_malformed_json_does_not_raise():
    row = {"event_record_id": 1, "timestamp": "2021-03-01T12:00:00Z",
           "provider": "Microsoft-Windows-Sysmon", "event_id": 1,
           "channel": "x", "computer": "h", "event_json": "{broken"}
    out = normalize.normalize_record(row)
    assert out["action"] == "process_create"  # mapper runs on empty data
    assert out["image"] is None               # nothing to map, no crash


def test_normalize_missing_eventdata_maps_to_nulls():
    event = {"Event": {"System": {"EventID": 1}}}  # no EventData at all
    row = {"event_record_id": 1, "timestamp": "2021-03-01T12:00:00Z",
           "provider": "Microsoft-Windows-Sysmon", "event_id": 1,
           "channel": "x", "computer": "h", "event_json": json.dumps(event)}
    out = normalize.normalize_record(row)
    assert out["action"] == "process_create"
    assert out["process_guid"] is None


def test_normalize_covers_remaining_sysmon_mappers():
    """image_load / file_create / registry_set / dns_query map their key fields."""
    cases = {
        7: ({"ImageLoaded": r"C:\x\evil.dll", "Signed": "false"}, "image_load", "image_loaded"),
        11: ({"TargetFilename": r"C:\Temp\drop.exe"}, "file_create", "target_filename"),
        13: ({"TargetObject": r"HKLM\Run\x", "Details": "evil.exe"}, "registry_set", "registry_target"),
        22: ({"QueryName": "evil.example", "QueryResults": "1.2.3.4"}, "dns_query", "dns_query"),
    }
    for eid, (data, action, keyfield) in cases.items():
        event = {"Event": {"System": {"EventID": eid}, "EventData": data}}
        row = {"event_record_id": 1, "timestamp": "2021-03-01T12:00:00Z",
               "provider": "Microsoft-Windows-Sysmon", "event_id": eid,
               "channel": "x", "computer": "h", "event_json": json.dumps(event)}
        out = normalize.normalize_record(row)
        assert out["action"] == action
        assert out[keyfield] is not None


# --- duplicate record ids ----------------------------------------------------


def test_duplicate_record_ids_survive_normalize_and_are_flagged():
    event = {"Event": {"System": {"EventID": 1}, "EventData": {"Image": r"C:\a.exe"}}}
    base = {"timestamp": "2021-03-01T12:00:00Z", "provider": "Microsoft-Windows-Sysmon",
            "event_id": 1, "channel": "x", "computer": "h", "event_json": json.dumps(event)}
    frame = pd.DataFrame([{**base, "event_record_id": 7}, {**base, "event_record_id": 7}])
    norm = normalize.normalize_frame(frame)
    assert len(norm) == 2  # both kept, not silently deduped
    report = doctor.build_report(norm)
    assert report.duplicate_record_ids == 1  # doctor surfaces the collision


# --- empty input -------------------------------------------------------------


def test_empty_through_features_and_doctor():
    empty = normalize.normalize_frame(pd.DataFrame(columns=[
        "event_record_id", "timestamp", "provider", "event_id",
        "channel", "computer", "event_json",
    ]))
    feats = FeatureBuilder().fit_transform(empty)
    assert len(feats) == 0
    assert doctor.build_report(empty).n_rows == 0


def test_external_empty_input_returns_empty():
    assert external.parse_chainsaw([]).empty
    events = pd.DataFrame({"host": [], "event_record_id": pd.array([], dtype="Int64"),
                           "process_guid": []})
    assert external.alerts_to_process(external.parse_chainsaw([]), events).empty


# --- missing columns ---------------------------------------------------------


@pytest.mark.filterwarnings("ignore:Skipping features without any observed values")
def test_select_features_fills_absent_columns_with_nan():
    X = select_features(pd.DataFrame({"cmdline_length": [3.0]}))
    assert X["net_conn_count"].isna().all()  # absent feature -> NaN, not KeyError
    # The imputer in the detector then handles the NaN column end-to-end.
    df = pd.DataFrame({"cmdline_length": np.arange(30.0), "label": ["benign"] * 30})
    det = IsolationForestDetector().fit_on_benign(df)
    assert np.isfinite(det.anomaly_score(df)).all()


def test_label_missing_host_column_defaults_all_benign():
    events = pd.DataFrame({"timestamp": ["2021-03-01T12:00:00Z"]})  # no host column
    labels = pd.DataFrame([{"session_id": "s1", "host": "h", "label": "malicious",
                            "start_utc": "2021-03-01T00:00:00Z", "end_utc": "2021-03-02T00:00:00Z"}])
    out = label.attach_labels(events, labels, default_label="benign")
    assert out.loc[0, "label"] == "benign"  # no host -> no window matches


# --- label time windows ------------------------------------------------------


def test_label_window_boundaries_and_no_overlap():
    events = pd.DataFrame({
        "host": ["h", "h", "h"],
        "timestamp": ["2021-03-01T09:59:59Z",  # just before window
                      "2021-03-01T10:00:00Z",  # exactly on start (inclusive)
                      "2021-03-01T12:00:01Z"],  # after window
    })
    labels = pd.DataFrame([{"session_id": "s1", "host": "h", "label": "malicious",
                            "technique_id": "T1059.001",
                            "start_utc": "2021-03-01T10:00:00Z", "end_utc": "2021-03-01T12:00:00Z"}])
    out = label.attach_labels(events, labels)
    assert out["label"].tolist() == ["unlabeled", "malicious", "unlabeled"]
    assert out.loc[1, "technique_id"] == "T1059.001"


def test_label_malicious_wins_on_overlap():
    events = pd.DataFrame({"host": ["h"], "timestamp": ["2021-03-01T11:00:00Z"]})
    labels = pd.DataFrame([
        {"session_id": "s", "host": "h", "label": "benign",
         "start_utc": "2021-03-01T10:00:00Z", "end_utc": "2021-03-01T12:00:00Z"},
        {"session_id": "s", "host": "h", "label": "malicious",
         "start_utc": "2021-03-01T10:30:00Z", "end_utc": "2021-03-01T11:30:00Z"},
    ])
    out = label.attach_labels(events, labels)
    assert out.loc[0, "label"] == "malicious"  # malicious applied last, wins
