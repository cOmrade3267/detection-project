"""Tests for detect.normalize (pure, no .evtx/parser needed)."""

import json

from detect import normalize


def _ingest_row(event: dict, *, provider="Microsoft-Windows-Sysmon", event_id=1,
                computer="WIN-LAB01", record_id=1, timestamp="2021-03-01T12:00:00Z") -> dict:
    """Shape a row the way detect.ingest emits (promoted fields + event_json)."""
    return {
        "event_record_id": record_id,
        "timestamp": timestamp,
        "provider": provider,
        "event_id": event_id,
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": computer,
        "event_json": json.dumps(event),
    }


def _sysmon(event_id: int, data: dict) -> dict:
    return {"Event": {"System": {"EventID": event_id}, "EventData": data}}


def test_process_create_maps_parent_and_child():
    event = _sysmon(1, {
        "ProcessGuid": "{g-1}", "ProcessId": "4321",
        "Image": r"C:\Windows\System32\cmd.exe", "CommandLine": "cmd /c whoami",
        "User": "LAB\\alice", "IntegrityLevel": "High",
        "ParentImage": r"C:\Windows\explorer.exe", "ParentProcessId": "900",
    })
    row = normalize.normalize_record(_ingest_row(event, event_id=1))
    assert row["action"] == "process_create"
    assert row["process_guid"] == "{g-1}"
    assert row["image"].endswith("cmd.exe")
    assert row["command_line"] == "cmd /c whoami"
    assert row["parent_image"].endswith("explorer.exe")
    assert row["host"] == "WIN-LAB01"


def test_network_connect_maps_destination():
    event = _sysmon(3, {
        "ProcessGuid": "{g-2}", "Image": r"C:\evil.exe", "Protocol": "tcp",
        "DestinationIp": "10.0.0.5", "DestinationPort": "445",
        "DestinationHostname": "dc01",
    })
    row = normalize.normalize_record(_ingest_row(event, event_id=3))
    assert row["action"] == "network_connect"
    assert row["dest_ip"] == "10.0.0.5"
    assert row["dest_port"] == "445"  # stringified pre-frame; coerced in normalize_frame
    assert row["dest_hostname"] == "dc01"


def test_security_4688_maps_onto_process_fields():
    event = {"Event": {"System": {"EventID": 4688}, "EventData": {
        "NewProcessName": r"C:\Windows\System32\net.exe",
        "NewProcessId": "0x1a4", "SubjectUserName": "alice",
        "ParentProcessName": r"C:\Windows\System32\cmd.exe",
    }}}
    row = normalize.normalize_record(
        _ingest_row(event, provider="Microsoft-Windows-Security-Auditing", event_id=4688)
    )
    assert row["action"] == "process_create"
    assert row["image"].endswith("net.exe")
    assert row["parent_image"].endswith("cmd.exe")


def test_unknown_event_is_kept_with_routing_fields():
    event = {"Event": {"System": {"EventID": 4104}}}
    row = normalize.normalize_record(
        _ingest_row(event, provider="Microsoft-Windows-PowerShell", event_id=4104)
    )
    assert row["action"] == "unknown"
    assert row["event_id"] == 4104
    assert row["host"] == "WIN-LAB01"
    assert row["image"] is None  # no mapper, but nothing crashes


def test_event_data_list_of_data_form():
    event = {"Event": {"System": {"EventID": 1}, "EventData": {"Data": [
        {"@Name": "Image", "#text": r"C:\Windows\System32\cmd.exe"},
        {"@Name": "CommandLine", "#text": "cmd /c dir"},
    ]}}}
    row = normalize.normalize_record(_ingest_row(event, event_id=1))
    assert row["image"].endswith("cmd.exe")
    assert row["command_line"] == "cmd /c dir"


def test_normalize_frame_types_and_coercion():
    import pandas as pd

    event = _sysmon(3, {"DestinationIp": "10.0.0.5", "DestinationPort": "445"})
    frame = normalize.normalize_frame(pd.DataFrame([_ingest_row(event, event_id=3)]))
    assert list(frame.columns) == list(normalize.SCHEMA)
    assert str(frame["dest_port"].dtype) == "Int64"
    assert frame.loc[0, "dest_port"] == 445
    assert str(frame["timestamp"].dtype) == "datetime64[ns, UTC]"
    assert str(frame["action"].dtype) == "string"


def test_normalize_frame_empty_keeps_schema():
    import pandas as pd

    frame = normalize.normalize_frame(pd.DataFrame(columns=[
        "event_record_id", "timestamp", "provider", "event_id",
        "channel", "computer", "event_json",
    ]))
    assert len(frame) == 0
    assert list(frame.columns) == list(normalize.SCHEMA)
    assert str(frame["timestamp"].dtype) == "datetime64[ns, UTC]"
