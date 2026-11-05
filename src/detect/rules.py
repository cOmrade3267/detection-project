"""rules: a small Sigma-style rule engine (Baseline A).

Reads YAML rules from a directory and matches them against normalized
common-schema events. It loads both our own native rules and a documented subset
of standard SigmaHQ YAML, so a SigmaHQ-format rule can run unchanged. A scoped
subset keeps the engine small, dependency-light, and license-clean (SigmaHQ is a
reference for ideas only -- CLAUDE.md s3; we do not vendor its rules). pySigma
was rejected: it converts rules to SIEM queries rather than executing them on a
DataFrame, so it would add a heavy dependency and still need an executor. See
docs/sigma-support.md for the exact supported feature matrix, and docs/design.md.

Supported:
- detection: named selection blocks; a block (map) is AND over its field specs,
  a list value is OR, a list-of-maps selection is OR of AND-groups, and
  `field|all` makes a list AND.
- field names: standard-Sigma Windows names (Image, CommandLine, DestinationIp,
  ...) are mapped to our schema columns (SIGMA_FIELD_MAP); our own names pass
  through. An unmapped PascalCase field is warned about at load time.
- modifiers: contains / startswith / endswith / re / all / default equals
  (string compares case-insensitive); `field: null` matches an absent field.
  Any other modifier (base64, cidr, windash, lt/gt, ...) is rejected at load.
- logsource: `logsource.category` scopes the rule to one action (process_create,
  network_connect, ...) via SIGMA_CATEGORY_MAP.
- tags: `attack.tNNNN[.NNN]` tags populate the technique id.
- condition: and/or/not/parentheses over block names, plus Sigma's `all of them`,
  `1 of them`, `any of them`, and `all|1|any of <prefix>*`. Evaluated with a
  restricted AST walk -- never eval(). `N of` with N>=2 is not supported.
"""

from __future__ import annotations

import ast
import fnmatch
import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd
import yaml

ALERT_COLUMNS = [
    "rule_id", "rule_title", "technique_id", "level",
    "process_guid", "event_record_id", "timestamp", "action", "image",
]

_STRING_OPS = {"contains", "startswith", "endswith", "re"}
# Modifiers this engine implements. Anything else in a `field|...` key (base64,
# cidr, windash, lt/gt, cased, ...) is rejected at load time -- we do not claim
# full Sigma support, so we fail loudly rather than silently mismatch.
_SUPPORTED_MODIFIERS = _STRING_OPS | {"all"}

# Standard-Sigma (Windows/Sysmon) field names -> our normalized schema columns.
# Lets a rule written against SigmaHQ field names run on our events unchanged.
# Fields absent here pass through literally (our own snake_case names, or web-log
# fields); a PascalCase field with no mapping is warned about at load time.
SIGMA_FIELD_MAP: dict[str, str] = {
    "Image": "image",
    "CommandLine": "command_line",
    "ParentImage": "parent_image",
    "ParentCommandLine": "parent_command_line",
    "ProcessGuid": "process_guid",
    "ProcessId": "process_id",
    "ParentProcessGuid": "parent_process_guid",
    "ParentProcessId": "parent_process_id",
    "User": "user",
    "IntegrityLevel": "integrity_level",
    "Hashes": "hashes",
    "DestinationIp": "dest_ip",
    "DestinationPort": "dest_port",
    "DestinationHostname": "dest_hostname",
    "SourceIp": "src_ip",
    "SourcePort": "src_port",
    "Protocol": "protocol",
    "ImageLoaded": "image_loaded",
    "Signed": "signed",
    "Signature": "signature",
    "TargetFilename": "target_filename",
    "TargetObject": "registry_target",
    "Details": "registry_details",
    "QueryName": "dns_query",
    "QueryResults": "dns_results",
    "Computer": "host",
    "Channel": "channel",
    "EventID": "event_id",
}

# Standard-Sigma logsource.category -> our normalized `action`. A category rule
# is then scoped to that action (enforced in Rule.match), matching Sigma's intent
# that a process_creation rule never fires on a network event.
SIGMA_CATEGORY_MAP: dict[str, str] = {
    "process_creation": "process_create",
    "network_connection": "network_connect",
    "image_load": "image_load",
    "file_event": "file_create",
    "registry_set": "registry_set",
    "registry_event": "registry_set",
    "dns_query": "dns_query",
}


def _match_one(event_val: Any, spec_val: Any, op: str) -> bool:
    ev_missing = event_val is None or (isinstance(event_val, float) and pd.isna(event_val))
    if spec_val is None:
        # Sigma: `field: null` matches only when the field is absent/null.
        return ev_missing
    if ev_missing:
        return False
    s = str(event_val).lower()
    t = str(spec_val).lower()
    if op == "equals":
        return s == t
    if op == "contains":
        return t in s
    if op == "startswith":
        return s.startswith(t)
    if op == "endswith":
        return s.endswith(t)
    if op == "re":
        return re.search(str(spec_val), str(event_val), re.IGNORECASE) is not None
    raise ValueError(f"unknown operator: {op}")


@dataclass
class FieldSpec:
    field: str
    op: str
    values: list[Any]
    require_all: bool  # `field|all`: AND across values instead of OR

    def match(self, event: dict[str, Any]) -> bool:
        ev = event.get(self.field)
        results = (_match_one(ev, v, self.op) for v in self.values)
        return all(results) if self.require_all else any(results)


@dataclass
class Selection:
    """A Sigma search identifier: OR across groups, AND within a group.

    A selection written as a map is one group (all specs AND together). A
    selection written as a *list of maps* (standard Sigma) is several groups ORed
    together -- each map is itself an AND of its specs.
    """

    groups: list[list[FieldSpec]]

    def match(self, event: dict[str, Any]) -> bool:
        return any(all(spec.match(event) for spec in group) for group in self.groups)


@dataclass
class Rule:
    id: str
    title: str
    technique_id: str | None
    level: str | None
    selections: dict[str, Selection]
    condition: ast.expr
    logsource_action: str | None = field(default=None)
    source_path: str | None = field(default=None)

    def match(self, event: dict[str, Any]) -> bool:
        # A category-scoped Sigma rule only applies to its log source.
        if self.logsource_action is not None and event.get("action") != self.logsource_action:
            return False
        block_vals = {name: sel.match(event) for name, sel in self.selections.items()}
        return _eval_condition(self.condition, block_vals)


def _parse_field_key(key: str) -> tuple[str, str, bool]:
    """'Image|endswith' -> ('image', 'endswith', False); 'CommandLine|contains|all' -> (.., True).

    Translates a standard-Sigma Windows field name to our schema column and
    rejects any modifier we don't implement (so unsupported Sigma syntax fails at
    load, never silently).
    """
    parts = key.split("|")
    name = SIGMA_FIELD_MAP.get(parts[0], parts[0])
    mods = parts[1:]
    unsupported = [m for m in mods if m not in _SUPPORTED_MODIFIERS]
    if unsupported:
        raise ValueError(
            f"field '{key}' uses unsupported Sigma modifier(s) {unsupported}; "
            "see docs/sigma-support.md"
        )
    require_all = "all" in mods
    ops = [m for m in mods if m in _STRING_OPS]
    if len(ops) > 1:
        raise ValueError(f"field '{key}' has multiple operators: {ops}")
    return name, (ops[0] if ops else "equals"), require_all


def _build_specs(block: dict[str, Any]) -> list[FieldSpec]:
    specs = []
    for key, value in block.items():
        name, op, require_all = _parse_field_key(key)
        values = value if isinstance(value, list) else [value]
        specs.append(FieldSpec(field=name, op=op, values=values, require_all=require_all))
    return specs


def _build_selection(block: dict[str, Any] | list[dict[str, Any]]) -> Selection:
    """Build a Selection from a map (one AND group) or a list of maps (OR groups)."""
    if isinstance(block, list):
        groups = [_build_specs(m) for m in block if isinstance(m, dict)]
    else:
        groups = [_build_specs(block)]
    return Selection(groups=groups)


def _compile_condition(expr: str) -> ast.expr:
    node = ast.parse(expr, mode="eval").body
    _validate_condition(node)
    return node


def _validate_condition(node: ast.AST) -> None:
    if isinstance(node, ast.BoolOp):
        for v in node.values:
            _validate_condition(v)
    elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        _validate_condition(node.operand)
    elif isinstance(node, ast.Name):
        return
    else:
        # Rule-syntax error, not a type error -> ValueError is intended.
        raise ValueError(f"unsupported condition expression: {ast.dump(node)}")  # noqa: TRY004


def _eval_condition(node: ast.AST, vals: dict[str, bool]) -> bool:
    if isinstance(node, ast.BoolOp):
        results = [_eval_condition(v, vals) for v in node.values]
        return all(results) if isinstance(node.op, ast.And) else any(results)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _eval_condition(node.operand, vals)
    if isinstance(node, ast.Name):
        return bool(vals.get(node.id, False))
    raise ValueError(f"unsupported condition expression: {ast.dump(node)}")


_TAG_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
# No trailing \b: a word boundary would land before a trailing '*' and drop it
# from the captured pattern (e.g. 'selection_*' -> 'selection_').
_OF_RE = re.compile(r"\b(all|any|\d+)\s+of\s+([A-Za-z0-9_*]+)")


def _technique_from_tags(tags: Any) -> str | None:
    """Pull the first ``attack.tNNNN[.NNN]`` tag out of a Sigma ``tags`` list."""
    if not isinstance(tags, list):
        return None
    for tag in tags:
        m = _TAG_RE.search(str(tag))
        if m:
            return m.group(1).upper()
    return None


def _logsource_action(logsource: Any) -> str | None:
    """Map a Sigma ``logsource.category`` to our normalized action, if known."""
    if not isinstance(logsource, dict):
        return None
    category = logsource.get("category")
    return SIGMA_CATEGORY_MAP.get(str(category)) if category else None


def _expand_sigma_condition(condition: str, block_names: list[str]) -> str:
    """Rewrite Sigma's ``N of ...`` shorthand into a plain boolean expression.

    Supports ``all of them`` / ``1 of them`` / ``any of them`` and the wildcard
    forms ``all of selection_*`` / ``1 of selection_*``. ``all`` becomes an AND
    over the matching identifiers, ``1``/``any`` an OR. A numeric quantifier >= 2
    (e.g. ``2 of them``) is rejected -- our boolean AST can't express a count.
    The result is a plain and/or/not expression the restricted compiler accepts.
    """

    def repl(match: re.Match[str]) -> str:
        quant, target = match.group(1), match.group(2)
        if target == "them":
            names = list(block_names)
        elif "*" in target:
            names = [b for b in block_names if fnmatch.fnmatchcase(b, target)]
        else:
            names = [b for b in block_names if b == target]
        if not names:
            raise ValueError(f"condition refers to '{target}' but no such selection block")
        if quant == "all":
            joiner = " and "
        elif quant in ("any", "1"):
            joiner = " or "
        else:
            raise ValueError(
                f"unsupported quantifier '{quant} of ...'; only 'all of', "
                "'1 of' and 'any of' are supported (see docs/sigma-support.md)"
            )
        return "(" + joiner.join(names) + ")"

    return _OF_RE.sub(repl, condition)


def _warn_unmapped_fields(selections: dict[str, Selection], rule_id: str) -> None:
    """Warn about PascalCase (Windows) field names we have no mapping for.

    Our schema is snake_case and web-rule fields are lowercase, so an uppercase
    leading letter after mapping is a reliable sign of an unmapped Sigma field --
    it would silently never match, which a reviewer would (rightly) flag.
    """
    unmapped = {
        spec.field
        for sel in selections.values()
        for group in sel.groups
        for spec in group
        if spec.field[:1].isupper()
    }
    if unmapped:
        warnings.warn(
            f"rule '{rule_id}' references field(s) {sorted(unmapped)} with no mapping "
            "to the normalized schema; they will not match. See docs/sigma-support.md",
            RuntimeWarning,
            stacklevel=3,
        )


def load_rule(doc: dict[str, Any], source_path: str | None = None) -> Rule:
    """Compile one rule doc (our native format or standard SigmaHQ YAML).

    Standard Sigma is supported for a documented subset: ``tags`` -> technique,
    ``logsource.category`` -> action scope, Windows field names -> schema
    columns, and the ``N of`` condition shorthand. See docs/sigma-support.md.
    """
    rule_id = str(doc.get("id") or doc.get("title"))
    detection = doc.get("detection") or {}
    condition = detection.get("condition")
    if condition is None:
        raise ValueError(f"rule '{rule_id}' has no detection.condition")
    selections = {
        name: _build_selection(block)
        for name, block in detection.items()
        if name != "condition" and isinstance(block, (dict, list))
    }
    _warn_unmapped_fields(selections, rule_id)
    expanded = _expand_sigma_condition(str(condition), list(selections))
    return Rule(
        id=rule_id,
        title=str(doc.get("title") or doc.get("id")),
        technique_id=doc.get("technique") or _technique_from_tags(doc.get("tags")),
        level=doc.get("level"),
        selections=selections,
        condition=_compile_condition(expanded),
        logsource_action=_logsource_action(doc.get("logsource")),
        source_path=source_path,
    )


class RuleEngine:
    """Holds compiled rules and scans normalized events into alerts."""

    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules

    @classmethod
    def from_dir(cls, path: str | Path) -> RuleEngine:
        rules: list[Rule] = []
        for p in sorted(Path(path).glob("*.y*ml")):
            doc = yaml.safe_load(p.read_text())
            if doc:
                rules.append(load_rule(doc, source_path=str(p)))
        return cls(rules)

    def scan(self, events: pd.DataFrame) -> pd.DataFrame:
        """Return one alert row per (rule, matching event)."""
        alerts: list[dict[str, Any]] = []
        for event in events.to_dict(orient="records"):
            for rule in self.rules:
                if rule.match(event):
                    alerts.append({
                        "rule_id": rule.id,
                        "rule_title": rule.title,
                        "technique_id": rule.technique_id,
                        "level": rule.level,
                        "process_guid": event.get("process_guid"),
                        "event_record_id": event.get("event_record_id"),
                        "timestamp": event.get("timestamp"),
                        "action": event.get("action"),
                        "image": event.get("image"),
                    })
        return pd.DataFrame(alerts, columns=ALERT_COLUMNS)


def alerts_by_process(alerts: pd.DataFrame) -> pd.DataFrame:
    """Roll event-level alerts up to one row per process (the model's unit).

    Columns: process_guid, alerted(=True), n_alerts, techniques (comma-joined),
    rules (comma-joined). Rows with no process_guid are dropped.
    """
    cols = ["process_guid", "alerted", "n_alerts", "techniques", "rules"]
    if alerts.empty:
        return pd.DataFrame(columns=cols)
    df = alerts[alerts["process_guid"].notna()]
    if df.empty:
        return pd.DataFrame(columns=cols)

    def _join_unique(s: pd.Series) -> str:
        return ",".join(sorted({str(x) for x in s.dropna()}))

    grouped = df.groupby("process_guid")
    out = pd.DataFrame({
        "n_alerts": grouped.size(),
        "techniques": grouped["technique_id"].apply(_join_unique),
        "rules": grouped["rule_id"].apply(_join_unique),
    }).reset_index()
    out["alerted"] = True
    return out[cols]


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Scan normalized events with Sigma-style rules.")
    parser.add_argument("events", help="normalized Parquet from `detect.normalize`")
    parser.add_argument("alerts_out", help="output alerts Parquet")
    parser.add_argument("--rules-dir", default="rules", help="directory of rule YAMLs")
    args = parser.parse_args(argv)

    engine = RuleEngine.from_dir(args.rules_dir)
    alerts = engine.scan(pd.read_parquet(args.events))
    Path(args.alerts_out).parent.mkdir(parents=True, exist_ok=True)
    alerts.to_parquet(args.alerts_out, index=False)
    print(f"{len(engine.rules)} rules -> {len(alerts)} alerts; wrote {args.alerts_out}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    import sys

    raise SystemExit(main(sys.argv[1:]))
