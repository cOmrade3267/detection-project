"""Tests for detect.external (Chainsaw/Hayabusa ingestion) + evaluate wiring."""

import json

import numpy as np
import pandas as pd

from detect import external

# --- captured-shape sample output (no binary required) ----------------------

CHAINSAW = [{
    "name": "Encoded PowerShell Command",
    "level": "high",
    "timestamp": "2021-03-01T12:00:00Z",
    "tags": ["attack.execution", "attack.t1059.001"],
    "document": {"kind": "evtx", "data": {"Event": {"System": {
        "Computer": "lab01", "EventRecordID": "101", "EventID": 1}}}},
}]

HAYABUSA = [{
    "Timestamp": "2021-03-01 12:00:00.000 +00:00",
    "Computer": "lab01", "Channel": "Sysmon", "EventID": 1, "Level": "high",
    "RuleTitle": "Mshta Remote Payload", "RecordID": 202,
    "MitreTactics": ["Defense Evasion"], "MitreTags": ["T1218.005"],
}]


def test_parse_chainsaw():
    df = external.parse_chainsaw(CHAINSAW)
    assert list(df.columns) == external.EXTERNAL_ALERT_COLUMNS
    row = df.iloc[0]
    assert row["tool"] == "chainsaw"
    assert row["host"] == "lab01"
    assert row["event_record_id"] == 101
    assert row["technique_id"] == "T1059.001"
    assert str(df["event_record_id"].dtype) == "Int64"


def test_parse_hayabusa():
    df = external.parse_hayabusa(HAYABUSA)
    row = df.iloc[0]
    assert row["tool"] == "hayabusa"
    assert row["host"] == "lab01"
    assert row["event_record_id"] == 202
    assert row["technique_id"] == "T1218.005"


def test_technique_extraction_dedup_and_case():
    assert external._techniques(["attack.t1059.001", "T1059.001"]) == ["T1059.001"]
    assert external._techniques("note T1105 and t1105") == ["T1105"]
    assert external._techniques(None, [], "no ids here") == []


def test_alert_with_no_technique_becomes_na_row():
    data = [{"name": "Some rule", "document": {"data": {"Event": {"System": {
        "Computer": "h", "EventRecordID": 5, "EventID": 1}}}}}]
    df = external.parse_chainsaw(data)
    assert len(df) == 1
    assert pd.isna(df.loc[0, "technique_id"])


def test_load_external_alerts_json_and_jsonl(tmp_path):
    (tmp_path / "cs.json").write_text(json.dumps(CHAINSAW))
    (tmp_path / "hb.jsonl").write_text("\n".join(json.dumps(r) for r in HAYABUSA))
    assert external.load_external_alerts(tmp_path / "cs.json", "chainsaw").iloc[0]["tool"] == "chainsaw"
    assert external.load_external_alerts(tmp_path / "hb.jsonl", "hayabusa").iloc[0]["tool"] == "hayabusa"


def test_alerts_to_process_joins_on_record_id():
    alerts = external.parse_chainsaw(CHAINSAW)
    events = pd.DataFrame({
        "host": ["lab01", "lab01"],
        "event_record_id": pd.array([101, 102], dtype="Int64"),
        "process_guid": ["{p1}", "{p2}"],
    })
    rolled = external.alerts_to_process(alerts, events)
    assert len(rolled) == 1
    assert rolled.iloc[0]["process_guid"] == "{p1}"
    assert rolled.iloc[0]["n_alerts"] == 1
    assert "T1059.001" in rolled.iloc[0]["techniques"]
    assert "chainsaw" in rolled.iloc[0]["tools"]


def test_alerts_to_process_drops_unmapped():
    alerts = external.parse_chainsaw(CHAINSAW)  # record 101 on lab01
    events = pd.DataFrame({"host": ["lab01"], "event_record_id": pd.array([999], dtype="Int64"),
                           "process_guid": ["{p}"]})
    assert external.alerts_to_process(alerts, events).empty


def test_evaluate_includes_external_approach():
    import sys
    sys.path.insert(0, "tests")
    from test_evaluate import RULES_DIR, _events

    from detect import evaluate

    events = _events()
    # Fabricate external alerts hitting the malicious process_create events (EID 1).
    mal = events[(events["label"] == "malicious") & (events["action"] == "process_create")]
    ext = pd.DataFrame({
        "tool": "chainsaw", "timestamp": mal["timestamp"].to_numpy(),
        "host": mal["host"].to_numpy(),
        "event_record_id": mal["event_record_id"].to_numpy(),
        "event_id": 1, "level": "high", "rule_title": "x",
        "technique_id": mal["technique_id"].to_numpy(),
    })
    result = evaluate.run_evaluation(events, rules_dir=RULES_DIR, test_size=0.4, n_boot=50, external_alerts=ext)
    assert "External Sigma (Chainsaw/Hayabusa)" in set(result.summary["approach"])
    ext_all = result.summary[(result.summary["approach"] == "External Sigma (Chainsaw/Hayabusa)")
                             & (result.summary["split"] == "all")].iloc[0]
    assert np.isfinite(ext_all["recall"])
