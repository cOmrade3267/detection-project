"""rules: a small Sigma-style rule engine (Baseline A).

Reads YAML rules from a directory and matches them against normalized
common-schema events. A deliberately scoped subset of Sigma is supported so the
engine stays small, dependency-light, and license-clean (SigmaHQ is a reference
for ideas only -- CLAUDE.md s3). See docs/design.md s5.

Supported:
- detection: named selection blocks; a block is AND over its field specs, a list
  value is OR, and `field|all` makes a list AND.
- modifiers: contains / startswith / endswith / re / default equals
  (string compares are case-insensitive).
- condition: boolean expression over block names (and/or/not/parentheses),
  evaluated with a restricted AST walk -- never eval().
"""

from __future__ import annotations

import ast
import re
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


def _match_one(event_val: Any, spec_val: Any, op: str) -> bool:
    if event_val is None or (isinstance(event_val, float) and pd.isna(event_val)):
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
    specs: list[FieldSpec]

    def match(self, event: dict[str, Any]) -> bool:
        return all(spec.match(event) for spec in self.specs)


@dataclass
class Rule:
    id: str
    title: str
    technique_id: str | None
    level: str | None
    selections: dict[str, Selection]
    condition: ast.expr
    source_path: str | None = field(default=None)

    def match(self, event: dict[str, Any]) -> bool:
        block_vals = {name: sel.match(event) for name, sel in self.selections.items()}
        return _eval_condition(self.condition, block_vals)


def _parse_field_key(key: str) -> tuple[str, str, bool]:
    """'image|endswith' -> ('image', 'endswith', False); 'cl|contains|all' -> (.., True)."""
    parts = key.split("|")
    name = parts[0]
    mods = parts[1:]
    require_all = "all" in mods
    ops = [m for m in mods if m in _STRING_OPS]
    if len(ops) > 1:
        raise ValueError(f"field '{key}' has multiple operators: {ops}")
    return name, (ops[0] if ops else "equals"), require_all


def _build_selection(block: dict[str, Any]) -> Selection:
    specs = []
    for key, value in block.items():
        name, op, require_all = _parse_field_key(key)
        values = value if isinstance(value, list) else [value]
        specs.append(FieldSpec(field=name, op=op, values=values, require_all=require_all))
    return Selection(specs=specs)


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


def load_rule(doc: dict[str, Any], source_path: str | None = None) -> Rule:
    detection = doc.get("detection") or {}
    condition = detection.get("condition")
    if condition is None:
        raise ValueError(f"rule '{doc.get('id', doc.get('title'))}' has no detection.condition")
    selections = {
        name: _build_selection(block)
        for name, block in detection.items()
        if name != "condition" and isinstance(block, dict)
    }
    return Rule(
        id=str(doc.get("id") or doc.get("title")),
        title=str(doc.get("title") or doc.get("id")),
        technique_id=doc.get("technique"),
        level=doc.get("level"),
        selections=selections,
        condition=_compile_condition(str(condition)),
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
