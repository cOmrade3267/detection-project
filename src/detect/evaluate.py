"""evaluate: turn the pipeline into reproducible numbers (`make evaluate`).

Runs the full comparison on a labeled normalized event set:
  split (leakage-safe) -> features (fit on train) -> models (fit on train benign)
  -> score test -> rules on test -> metrics.

Metrics (per approach, per split): alert count, precision, recall, F1, PR-AUC
(not accuracy -- classes are imbalanced), and false positives per 10k benign
events-of-interest. Plus per-technique recall (the blind-spot table) and a
combined rules-OR-model approach at a fixed alert budget. Lab and public splits
are reported separately. See docs/design.md.

Every number here comes from a run on real data; nothing is hard-coded. The
README stays TODO until `make evaluate` is run on the lab + public datasets.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

from . import attack_map
from .features import FeatureBuilder
from .model import IsolationForestDetector, ZScoreBaseline, alerts_at_budget
from .rules import RuleEngine, alerts_by_process
from .split import assert_no_leakage, session_split

MALICIOUS = "malicious"
BENIGN = "benign"


# --- metric primitives (each independently testable) -------------------------

def binary_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, float]:
    """precision / recall / f1 / confusion counts; NaN where undefined."""
    y_true = np.asarray(y_true, dtype=bool)
    y_pred = np.asarray(y_pred, dtype=bool)
    tp = int(np.sum(y_true & y_pred))
    fp = int(np.sum(~y_true & y_pred))
    fn = int(np.sum(y_true & ~y_pred))
    tn = int(np.sum(~y_true & ~y_pred))
    precision = tp / (tp + fp) if (tp + fp) else np.nan
    recall = tp / (tp + fn) if (tp + fn) else np.nan
    f1 = (2 * precision * recall / (precision + recall)
          if precision and recall and not np.isnan(precision) and not np.isnan(recall) else np.nan)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": precision, "recall": recall, "f1": f1}


def fp_per_10k_benign(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    """False positives per 10,000 benign rows -- the SOC-relevant volume metric."""
    y_true = np.asarray(y_true, dtype=bool)
    y_pred = np.asarray(y_pred, dtype=bool)
    n_benign = int(np.sum(~y_true))
    if n_benign == 0:
        return np.nan
    fp = int(np.sum(~y_true & y_pred))
    return fp / n_benign * 10_000


def pr_auc(y_true: np.ndarray, scores: np.ndarray) -> float:
    """Average precision (PR-AUC). NaN unless both classes are present."""
    y_true = np.asarray(y_true, dtype=bool)
    if y_true.all() or not y_true.any():
        return np.nan
    return float(average_precision_score(y_true, np.asarray(scores, dtype="float64")))


# --- evaluation result container --------------------------------------------

@dataclass
class EvaluationResult:
    summary: pd.DataFrame            # approach x split metrics
    per_technique: pd.DataFrame      # approach x technique recall (overall test)
    eval_table: pd.DataFrame         # per-process scores + preds (for inspection)
    budget: int


# --- the pipeline ------------------------------------------------------------

def _norm_scores(x: np.ndarray) -> np.ndarray:
    x = np.asarray(x, dtype="float64")
    lo, hi = np.nanmin(x), np.nanmax(x)
    return (x - lo) / (hi - lo) if hi > lo else np.zeros_like(x)


def run_evaluation(
    events: pd.DataFrame,
    *,
    rules_dir: str | Path = "rules",
    test_size: float = 0.25,
    random_state: int = 42,
    budget: int | None = None,
) -> EvaluationResult:
    events = events.copy()
    events["timestamp"] = pd.to_datetime(events["timestamp"], utc=True, errors="coerce")

    train_idx, test_idx = session_split(events, test_size=test_size, random_state=random_state)
    assert_no_leakage(events, train_idx, test_idx)
    train_events = events.iloc[train_idx]
    test_events = events.iloc[test_idx]

    builder = FeatureBuilder().fit(train_events)
    train_feats = builder.transform(train_events)
    test_feats = builder.transform(test_events)
    if test_feats.empty:
        raise ValueError("No processes in the test split; need process_create events.")

    iforest = IsolationForestDetector(random_state=random_state).fit_on_benign(train_feats)
    rarity = ZScoreBaseline().fit_on_benign(train_feats)

    engine = RuleEngine.from_dir(rules_dir)
    rolled = alerts_by_process(engine.scan(test_events)).set_index("process_guid")

    guid = test_feats["process_guid"]
    rule_n = rolled["n_alerts"].reindex(guid).fillna(0).to_numpy() if not rolled.empty else np.zeros(len(guid))

    ev = pd.DataFrame({
        "process_guid": guid.to_numpy(),
        "label": test_feats["label"].astype("object").to_numpy(),
        "technique_id": test_feats["technique_id"].astype("object").to_numpy(),
        "source": test_feats["source"].astype("object").to_numpy(),
        "model_score": iforest.anomaly_score(test_feats),
        "rarity_score": rarity.anomaly_score(test_feats),
        "rule_score": rule_n.astype("float64"),
        "rule_alert": rule_n > 0,
    })

    if budget is None:
        budget = int(ev["rule_alert"].sum()) or max(1, round(0.01 * len(ev)))

    model_pred = alerts_at_budget(ev["model_score"].to_numpy(), budget)
    rarity_pred = alerts_at_budget(ev["rarity_score"].to_numpy(), budget)
    combined_pred = ev["rule_alert"].to_numpy() | model_pred
    combined_score = _norm_scores(ev["model_score"].to_numpy()) + ev["rule_alert"].to_numpy().astype(float)

    approaches = {
        "Rules (A)": (ev["rule_alert"].to_numpy(), ev["rule_score"].to_numpy()),
        "Rarity (B)": (rarity_pred, ev["rarity_score"].to_numpy()),
        "Isolation Forest": (model_pred, ev["model_score"].to_numpy()),
        "Combined (rules OR IF)": (combined_pred, combined_score),
    }

    splits = {"all": ev.index.to_numpy()}
    for src in ("lab", "public"):
        mask = (ev["source"] == src).to_numpy()
        if mask.any():
            splits[src] = np.where(mask)[0]

    rows = []
    for name, (pred, score) in approaches.items():
        for split_name, idx in splits.items():
            y = (ev["label"].to_numpy()[idx] == MALICIOUS)
            p = np.asarray(pred)[idx]
            m = binary_metrics(y, p)
            rows.append({
                "approach": name, "split": split_name,
                "n_alerts": int(p.sum()),
                "precision": m["precision"], "recall": m["recall"], "f1": m["f1"],
                "fp_per_10k": fp_per_10k_benign(y, p),
                "pr_auc": pr_auc(y, np.asarray(score)[idx]),
                "tp": m["tp"], "fp": m["fp"], "fn": m["fn"],
            })
    summary = pd.DataFrame(rows)

    # Per-technique recall on the overall test set, one column per approach.
    tech = None
    for name, (pred, _score) in approaches.items():
        r = attack_map.per_technique_recall(ev, np.asarray(pred))[
            ["technique_id", "technique_name", "n_malicious", "recall"]
        ].rename(columns={"recall": name})
        tech = r if tech is None else tech.merge(
            r[["technique_id", name]], on="technique_id", how="outer"
        )
    per_technique = tech if tech is not None else pd.DataFrame()

    return EvaluationResult(summary=summary, per_technique=per_technique, eval_table=ev, budget=budget)


# --- reporting ---------------------------------------------------------------

def write_reports(result: EvaluationResult, outdir: str | Path) -> dict[str, Path]:
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    result.summary.to_csv(out / "summary.csv", index=False)
    written["summary_csv"] = out / "summary.csv"

    md = ["# Evaluation results", "",
          f"Fixed alert budget: **{result.budget}** processes.", "",
          "## Metrics by approach and split", "",
          result.summary.round(4).to_markdown(index=False), "",
          "## Per-technique recall (overall test)", "",
          (result.per_technique.round(4).to_markdown(index=False)
           if not result.per_technique.empty else "_No malicious processes in test._"),
          ""]
    (out / "results.md").write_text("\n".join(md))
    written["results_md"] = out / "results.md"

    if not result.per_technique.empty:
        result.per_technique.to_csv(out / "per_technique_recall.csv", index=False)
        written["per_technique_csv"] = out / "per_technique_recall.csv"
        fig = _maybe_write_figure(result, out / "per_technique_recall.png")
        if fig is not None:
            written["figure"] = fig
    return written


def _maybe_write_figure(result: EvaluationResult, path: Path) -> Path | None:
    """Grouped bar chart of per-technique recall; skipped if matplotlib absent."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return None

    approaches = [c for c in result.per_technique.columns
                  if c not in ("technique_id", "technique_name", "n_malicious")]
    df = result.per_technique
    labels = [f"{t}\n{n}" for t, n in zip(df["technique_id"], df["technique_name"], strict=False)]
    x = np.arange(len(df))
    width = 0.8 / max(1, len(approaches))
    # Okabe-Ito colorblind-safe categorical palette.
    palette = ["#0072B2", "#E69F00", "#009E73", "#CC79A7", "#56B4E9", "#D55E00"]

    fig, ax = plt.subplots(figsize=(max(6, 1.6 * len(df)), 4.5))
    for i, name in enumerate(approaches):
        ax.bar(x + i * width, df[name].fillna(0).to_numpy(), width,
               label=name, color=palette[i % len(palette)])
    ax.set_xticks(x + width * (len(approaches) - 1) / 2)
    ax.set_xticklabels(labels, fontsize=8)
    ax.set_ylabel("Recall")
    ax.set_ylim(0, 1.05)
    ax.set_title("Per-technique recall by approach")
    ax.legend(fontsize=8, frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)
    return path


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Evaluate rules + model on labeled normalized events.")
    parser.add_argument("events", help="normalized, labeled Parquet from `detect.normalize`")
    parser.add_argument("--outdir", default="artifacts", help="directory for tables/figures")
    parser.add_argument("--rules-dir", default="rules")
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--budget", type=int, default=None)
    args = parser.parse_args(argv)

    events = pd.read_parquet(args.events)
    result = run_evaluation(events, rules_dir=args.rules_dir, test_size=args.test_size, budget=args.budget)
    written = write_reports(result, args.outdir)
    print(result.summary.round(4).to_string(index=False))
    print(f"\nwrote: {', '.join(str(p) for p in written.values())}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    import sys

    raise SystemExit(main(sys.argv[1:]))
