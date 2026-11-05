"""Standard-SigmaHQ-format loading: the documented subset in docs/sigma-support.md.

These assert that a rule written the way SigmaHQ writes them -- Windows field
names, logsource.category, attack.* tags, `N of` conditions -- loads and matches
against our normalized events without being rewritten into our native format.
"""

import warnings

import pytest

from detect.rules import RuleEngine, load_rule

# The exact rule printed in docs/sigma-support.md -- kept in sync by this test.
SIGMA_YAML_FROM_DOC = """
title: Suspicious Rundll32 Activity
id: sigma-rundll32
tags: [attack.defense_evasion, attack.t1218.011]
logsource: {product: windows, category: process_creation}
detection:
  selection_img:
    Image|endswith: '\\rundll32.exe'
  selection_cli:
    CommandLine|contains: ['javascript:', 'url.dll,OpenURL']
  condition: all of selection_*
level: high
"""

# A rule shaped exactly like a SigmaHQ process_creation rule.
SIGMA_RULE = {
    "title": "Suspicious Rundll32 Activity",
    "id": "sigma-rundll32",
    "status": "test",
    "tags": ["attack.defense_evasion", "attack.t1218.011"],
    "logsource": {"product": "windows", "category": "process_creation"},
    "detection": {
        "selection_img": {"Image|endswith": "\\rundll32.exe"},
        "selection_cli": {"CommandLine|contains": ["javascript:", "url.dll,OpenURL"]},
        "condition": "all of selection_*",
    },
    "level": "high",
}


def _proc(**kw):
    base = {"action": "process_create", "image": None, "command_line": None}
    base.update(kw)
    return base


def test_sigma_tags_and_category_and_fieldmap():
    rule = load_rule(SIGMA_RULE)
    assert rule.technique_id == "T1218.011"       # from attack.* tag
    assert rule.logsource_action == "process_create"  # from logsource.category
    # Windows field names were mapped onto our schema and match our events.
    assert rule.match(_proc(
        image=r"C:\Windows\System32\rundll32.exe",
        command_line="rundll32.exe javascript:alert(1)",
    ))


def test_sigma_logsource_scopes_to_action():
    rule = load_rule(SIGMA_RULE)
    # Same field values but a network event: logsource scoping must suppress it.
    assert not rule.match({
        "action": "network_connect",
        "image": r"C:\Windows\System32\rundll32.exe",
        "command_line": "rundll32.exe javascript:alert(1)",
    })


def test_sigma_all_of_requires_every_selection():
    rule = load_rule(SIGMA_RULE)
    # Matches selection_img but not selection_cli -> `all of selection_*` fails.
    assert not rule.match(_proc(
        image=r"C:\Windows\System32\rundll32.exe",
        command_line="rundll32.exe legitimate.dll,Entry",
    ))


def test_sigma_one_of_them():
    doc = dict(SIGMA_RULE, detection={**SIGMA_RULE["detection"], "condition": "1 of selection_*"})
    rule = load_rule(doc)
    assert rule.match(_proc(image=r"x\rundll32.exe", command_line="nothing special"))


def test_sigma_list_of_maps_is_or_of_and_groups():
    doc = {
        "title": "t", "id": "lom", "logsource": {"category": "process_creation"},
        "detection": {
            "selection": [
                {"Image|endswith": "\\a.exe", "User": "SYSTEM"},
                {"Image|endswith": "\\b.exe"},
            ],
            "condition": "selection",
        },
    }
    rule = load_rule(doc)
    assert rule.match(_proc(image=r"x\a.exe", user="SYSTEM"))   # first group (both)
    assert not rule.match(_proc(image=r"x\a.exe", user="alice"))  # first group incomplete
    assert rule.match(_proc(image=r"x\b.exe"))                  # second group


def test_sigma_null_matches_absent_field():
    doc = {
        "title": "t", "id": "nullrule", "logsource": {"category": "process_creation"},
        "detection": {"selection": {"CommandLine": None}, "condition": "selection"},
    }
    rule = load_rule(doc)
    assert rule.match(_proc(image="x", command_line=None))
    assert not rule.match(_proc(image="x", command_line="something"))


def test_unsupported_modifier_rejected_at_load():
    doc = {
        "title": "t", "id": "b64", "logsource": {"category": "process_creation"},
        "detection": {"selection": {"CommandLine|base64|contains": "whoami"},
                      "condition": "selection"},
    }
    with pytest.raises(ValueError, match="unsupported Sigma modifier"):
        load_rule(doc)


def test_numeric_quantifier_two_of_rejected():
    doc = dict(SIGMA_RULE, detection={**SIGMA_RULE["detection"], "condition": "2 of selection_*"})
    with pytest.raises(ValueError, match="unsupported quantifier"):
        load_rule(doc)


def test_unmapped_pascalcase_field_warns():
    doc = {
        "title": "t", "id": "unmapped", "logsource": {"category": "process_creation"},
        "detection": {"selection": {"OriginalFileName": "x.exe"}, "condition": "selection"},
    }
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        load_rule(doc)
    assert any("OriginalFileName" in str(w.message) for w in caught)


def test_standard_sigma_yaml_loads_from_dir(tmp_path):
    """The whole file path: .yml on disk -> yaml.safe_load -> RuleEngine."""
    (tmp_path / "rundll32.yml").write_text(SIGMA_YAML_FROM_DOC)
    engine = RuleEngine.from_dir(tmp_path)
    assert len(engine.rules) == 1
    rule = engine.rules[0]
    assert rule.technique_id == "T1218.011"
    assert rule.logsource_action == "process_create"
    assert rule.match(_proc(
        image=r"C:\Windows\System32\rundll32.exe",
        command_line="rundll32.exe url.dll,OpenURL http://evil/x",
    ))


def test_condition_unknown_target_raises():
    doc = {
        "title": "t", "id": "x", "logsource": {"category": "process_creation"},
        "detection": {"selection": {"Image": "x"}, "condition": "all of filter_*"},
    }
    with pytest.raises(ValueError, match="no such selection block"):
        load_rule(doc)
