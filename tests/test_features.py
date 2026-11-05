"""Tests for detect.features (pure; synthetic normalized events)."""


import pandas as pd
import pytest

from detect import features
from detect.features import FeatureBuilder, shannon_entropy

_EVENT_COLS = [
    "timestamp", "host", "session_id", "source", "action", "process_guid",
    "process_id", "image", "command_line", "integrity_level",
    "parent_process_guid", "parent_image", "dest_ip", "dest_port",
    "label", "technique_id",
]


def ev(**kw):
    row = {c: None for c in _EVENT_COLS}
    row["timestamp"] = kw.pop("timestamp", "2021-03-01T12:00:00Z")
    row.update(kw)
    return row


def frame(rows):
    return pd.DataFrame(rows, columns=_EVENT_COLS)


# --- entropy -----------------------------------------------------------------

def test_entropy_known_values():
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("ab") == pytest.approx(1.0)
    assert shannon_entropy("") == 0.0
    assert shannon_entropy(None) == 0.0
    assert shannon_entropy(float("nan")) == 0.0


# --- command-line / image features ------------------------------------------

def test_process_create_cmdline_and_image_flags():
    rows = [ev(
        action="process_create", process_guid="{p1}",
        image=r"C:\Users\a\AppData\Local\Temp\certutil.exe",
        command_line="certutil.exe -encodedcommand ZABpAHIA -nop -w hidden",
        integrity_level="High", parent_image=r"C:\Windows\explorer.exe",
        label="malicious", technique_id="T1140",
    )]
    out = FeatureBuilder().fit_transform(frame(rows)).set_index("process_guid")
    r = out.loc["{p1}"]
    assert r["cmdline_has_encoded"] == 1
    assert r["cmdline_has_noprofile"] == 1
    assert r["cmdline_has_hidden"] == 1
    assert r["is_lolbin"] == 1
    assert r["image_suspicious_path"] == 1
    assert r["integrity_ordinal"] == 3
    assert r["cmdline_entropy"] > 0
    assert r["label"] == "malicious"
    assert r["technique_id"] == "T1140"


# --- network aggregation -----------------------------------------------------

def test_network_aggregation_counts_and_uncommon_ports():
    rows = [
        ev(action="process_create", process_guid="{p2}", image=r"C:\evil.exe",
           parent_image=r"C:\Windows\explorer.exe"),
        ev(action="network_connect", process_guid="{p2}", dest_ip="10.0.0.5", dest_port=443),
        ev(action="network_connect", process_guid="{p2}", dest_ip="10.0.0.6", dest_port=4444),
        ev(action="network_connect", process_guid="{p2}", dest_ip="10.0.0.6", dest_port=4444),
    ]
    r = FeatureBuilder().fit_transform(frame(rows)).set_index("process_guid").loc["{p2}"]
    assert r["net_conn_count"] == 3
    assert r["net_distinct_dest_ip"] == 2
    assert r["net_distinct_dest_port"] == 2
    assert r["net_uncommon_port_count"] == 2  # 4444 x2; 443 is common


# --- learned rarity (leakage-sensitive) -------------------------------------

def test_parent_child_rarity_higher_for_unseen_pair():
    train = frame([
        ev(action="process_create", process_guid=f"{{c{i}}}",
           image=r"C:\Windows\System32\cmd.exe", parent_image=r"C:\Windows\explorer.exe")
        for i in range(20)
    ])
    builder = FeatureBuilder().fit(train)

    common = frame([ev(action="process_create", process_guid="{x}",
                       image=r"C:\Windows\System32\cmd.exe", parent_image=r"C:\Windows\explorer.exe")])
    rare = frame([ev(action="process_create", process_guid="{y}",
                     image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                     parent_image=r"C:\Program Files\Microsoft Office\winword.exe")])

    r_common = builder.transform(common).set_index("process_guid").loc["{x}", "parent_child_rarity"]
    r_rare = builder.transform(rare).set_index("process_guid").loc["{y}", "parent_child_rarity"]
    assert r_rare > r_common


def test_transform_before_fit_raises():
    with pytest.raises(RuntimeError, match="before fit"):
        FeatureBuilder().transform(frame([ev(action="process_create", process_guid="{z}")]))


# --- lineage / fan-out -------------------------------------------------------

def test_child_process_fanout_counted():
    rows = [
        ev(action="process_create", process_guid="{parent}", image=r"C:\a.exe"),
        ev(action="process_create", process_guid="{k1}", parent_process_guid="{parent}", image=r"C:\b.exe"),
        ev(action="process_create", process_guid="{k2}", parent_process_guid="{parent}", image=r"C:\c.exe"),
    ]
    out = FeatureBuilder().fit_transform(frame(rows)).set_index("process_guid")
    assert out.loc["{parent}", "child_process_count"] == 2
    assert out.loc["{k1}", "child_process_count"] == 0


# --- schema / shape ----------------------------------------------------------

def test_output_schema_and_numeric_features():
    rows = [ev(action="process_create", process_guid="{p}", image=r"C:\a.exe",
               parent_image=r"C:\Windows\explorer.exe")]
    out = FeatureBuilder().fit_transform(frame(rows))
    assert list(out.columns) == features.IDENT_COLUMNS + features.LABEL_COLUMNS + features.FEATURE_COLUMNS
    for col in features.FEATURE_COLUMNS:
        assert pd.api.types.is_numeric_dtype(out[col]), col


def test_empty_events_returns_empty_with_schema():
    out = FeatureBuilder().fit(frame([ev(action="process_create", process_guid="{p}")])).transform(
        frame([])
    )
    assert len(out) == 0
    assert list(out.columns) == features.IDENT_COLUMNS + features.LABEL_COLUMNS + features.FEATURE_COLUMNS
