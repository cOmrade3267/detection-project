"""Tests for the SSRF web/proxy rules (detect.rules engine, rules/web)."""

from pathlib import Path

import pandas as pd

from detect.rules import RuleEngine

WEB_RULES = Path(__file__).parent.parent / "rules" / "web"

_COLS = ["action", "app", "method", "url", "dest_host", "dest_ip", "req_auth_present",
         "process_guid", "event_record_id", "timestamp", "technique_id"]


def ev(**kw):
    row = {c: None for c in _COLS}
    row["timestamp"] = "2025-01-01T00:00:00Z"
    row["action"] = "http_outbound"
    row.update(kw)
    return row


def frame(rows):
    return pd.DataFrame(rows, columns=_COLS)


def test_ssrf_rules_load():
    engine = RuleEngine.from_dir(WEB_RULES)
    assert {r.id for r in engine.rules} == {"ssrf-cloud-metadata", "ssrf-outbound-auth-leak"}


def test_positive_cloud_metadata_by_ip():
    engine = RuleEngine.from_dir(WEB_RULES)
    alerts = engine.scan(frame([ev(
        app="verdaccio", method="GET", dest_ip="169.254.169.254",
        url="http://169.254.169.254/latest/meta-data/iam/", req_auth_present="true",
        event_record_id=1)]))
    assert "ssrf-cloud-metadata" in alerts["rule_id"].tolist()
    assert alerts.loc[alerts["rule_id"] == "ssrf-cloud-metadata", "technique_id"].iloc[0] == "T1552.005"


def test_positive_internal_auth_leak():
    engine = RuleEngine.from_dir(WEB_RULES)
    alerts = engine.scan(frame([ev(
        app="verdaccio", method="GET", dest_ip="10.5.5.5",
        url="http://10.5.5.5/pkg/evil-1.0.0.tgz", req_auth_present="true",
        event_record_id=2)]))
    assert alerts["rule_id"].tolist() == ["ssrf-outbound-auth-leak"]


def test_negative_public_registry_fetch():
    engine = RuleEngine.from_dir(WEB_RULES)
    # Normal uplink fetch to a public registry with auth -> not internal, not metadata.
    alerts = engine.scan(frame([ev(
        app="verdaccio", method="GET", dest_ip="104.16.20.5",
        dest_host="registry.npmjs.org", url="https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        req_auth_present="true", event_record_id=3)]))
    assert alerts.empty


def test_negative_internal_without_auth():
    engine = RuleEngine.from_dir(WEB_RULES)
    # Internal destination but no Authorization header forwarded -> no credential leak.
    alerts = engine.scan(frame([ev(
        dest_ip="192.168.1.10", url="http://192.168.1.10/health", req_auth_present="false",
        event_record_id=4)]))
    assert alerts.empty


def test_public_ip_in_172_range_not_flagged():
    engine = RuleEngine.from_dir(WEB_RULES)
    # 172.15.x is public (private is 172.16-31); must not match the internal regex.
    alerts = engine.scan(frame([ev(
        dest_ip="172.15.0.1", req_auth_present="true", event_record_id=5)]))
    assert alerts.empty
