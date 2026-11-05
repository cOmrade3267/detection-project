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

from . import attack_map, external
from .features import FEATURE_COLUMNS, FEATURE_GROUPS, FeatureBuilder
from .model import (
    IsolationForestDetector,
    LOFDetector,
    ZScoreBaseline,
    select_features,
    threshold_at_rate,
)
from .rules import RuleEngine, alerts_by_process
from .split import assert_no_leakage, session_split

MALICIOUS = "malicious"
BENIGN = "benign"
DEFAULT_BUDGET_PER_10K = 100  # alert budget used to set each model's threshold


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


def bootstrap_ci(
    y_true: np.ndarray,
    groups: np.ndarray,
    approaches: dict[str, tuple[np.ndarray, np.ndarray]],
    *,
    metrics: tuple[str, ...] = ("recall", "precision", "fp_per_10k", "pr_auc"),
    n_boot: int = 1000,
    seed: int = 42,
) -> pd.DataFrame:
    """95% bootstrap CIs for each approach's metrics, resampling whole SESSIONS.

    A single test set gives one number per metric; a reviewer wants to know how
    stable it is. We resample sessions (not rows) with replacement so the
    interval reflects between-session variance -- the real source of noise when
    there are few hosts/sessions -- rather than pretending every process is
    independent. Returns one row per (approach, metric) with lo/hi (2.5/97.5
    percentiles) and the point estimate.
    """
    y_true = np.asarray(y_true, dtype=bool)
    groups = np.asarray(groups, dtype=object)
    uniq = np.unique(groups)
    idx_by_group = {g: np.where(groups == g)[0] for g in uniq}
    rng = np.random.default_rng(seed)

    def _metric(name: str, y: np.ndarray, pred: np.ndarray, score: np.ndarray) -> float:
        if name == "recall":
            return binary_metrics(y, pred)["recall"]
        if name == "precision":
            return binary_metrics(y, pred)["precision"]
        if name == "fp_per_10k":
            return fp_per_10k_benign(y, pred)
        if name == "pr_auc":
            return pr_auc(y, score)
        raise ValueError(f"unknown metric {name}")

    # Pre-draw resamples once (same session draws for every approach -> comparable).
    draws = [rng.choice(uniq, size=len(uniq), replace=True) for _ in range(n_boot)]
    samples = [np.concatenate([idx_by_group[g] for g in d]) for d in draws]

    rows = []
    for name, (pred, score) in approaches.items():
        pred = np.asarray(pred)
        score = np.asarray(score)
        for metric in metrics:
            point = _metric(metric, y_true, pred, score)
            vals = np.array(
                [_metric(metric, y_true[s], pred[s], score[s]) for s in samples],
                dtype="float64",
            )
            vals = vals[np.isfinite(vals)]
            lo, hi = (np.percentile(vals, [2.5, 97.5]) if len(vals) else (np.nan, np.nan))
            rows.append({
                "approach": name, "metric": metric, "point": point,
                "ci_lo": lo, "ci_hi": hi, "n_boot": len(vals),
            })
    return pd.DataFrame(rows)


# --- evaluation result container --------------------------------------------

@dataclass
class EvaluationResult:
    summary: pd.DataFrame            # approach x split metrics
    per_technique: pd.DataFrame      # approach x technique recall (overall test)
    eval_table: pd.DataFrame         # per-process scores + preds + explanation
    explanations: pd.DataFrame       # per-alert top features + matching rules
    ci: pd.DataFrame                 # bootstrap 95% CIs (approach x metric), overall test
    ablation: pd.DataFrame           # drop-one-feature-group ablation of the IF
    thresholds: dict[str, float]     # model -> validation-chosen score cut
    budget_per_10k: int              # alert budget the thresholds target


# --- the pipeline ------------------------------------------------------------

def _norm_scores(x: np.ndarray) -> np.ndarray:
    x = np.asarray(x, dtype="float64")
    lo, hi = np.nanmin(x), np.nanmax(x)
    return (x - lo) / (hi - lo) if hi > lo else np.zeros_like(x)


def _benign(feats: pd.DataFrame) -> pd.DataFrame:
    return feats[feats["label"].astype("object") == BENIGN]


def _carve_validation(
    train_events: pd.DataFrame, *, val_size: float, random_state: int
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Split train into fit/validation by session for threshold selection.

    Falls back to (train, empty) when train has too few sessions to split, in
    which case thresholds are picked in-sample on the fit set (documented
    optimism; real lab data has enough benign sessions for a true held-out val).
    """
    te = train_events.reset_index(drop=True)
    try:
        fit_idx, val_idx = session_split(te, test_size=val_size, random_state=random_state)
    except (ValueError, IndexError):
        # Too few sessions to split -> no held-out validation (see docstring).
        return train_events, train_events.iloc[0:0]
    if len(val_idx) == 0 or len(fit_idx) == 0:
        return train_events, train_events.iloc[0:0]
    return te.iloc[fit_idx], te.iloc[val_idx]


def _threshold(model, val_feats: pd.DataFrame, fit_feats: pd.DataFrame, rate: float) -> float:
    """Pick a score cut on validation benign, falling back to fit benign."""
    vb = _benign(val_feats)
    ref = vb if len(vb) else _benign(fit_feats)
    if len(ref) == 0:
        ref = fit_feats
    return threshold_at_rate(model.anomaly_score(ref), rate)


def _explain(
    test_feats: pd.DataFrame, fit_feats: pd.DataFrame, rules_by_guid: pd.Series, top_n: int = 3
) -> pd.DataFrame:
    """Per-process triage context: the features most elevated vs. benign, + rules.

    Standardize test features by the benign mean/std (learned on the fit set),
    then name the top-`top_n` features by positive z. Gives an analyst "why" for
    each alert -- the contributing features and any matching rule ids.
    """
    from sklearn.impute import SimpleImputer
    from sklearn.preprocessing import StandardScaler

    fb = _benign(fit_feats)
    ref = fb if len(fb) else fit_feats
    Xb = select_features(ref)
    imp = SimpleImputer(strategy="median").fit(Xb)
    scaler = StandardScaler().fit(imp.transform(Xb))
    Z = scaler.transform(imp.transform(select_features(test_feats)))

    rows = []
    for i, guid in enumerate(test_feats["process_guid"].to_numpy()):
        z = Z[i]
        order = np.argsort(z)[::-1][:top_n]
        top = [f"{FEATURE_COLUMNS[j]}(+{z[j]:.1f}σ)" for j in order if np.isfinite(z[j]) and z[j] > 0]
        rules = rules_by_guid.get(guid, "")
        rows.append({"process_guid": guid, "top_features": ", ".join(top), "rules": rules or ""})
    return pd.DataFrame(rows)


def run_ablation(
    fit_feats: pd.DataFrame,
    val_feats: pd.DataFrame,
    ev: pd.DataFrame,
    test_feats: pd.DataFrame,
    *,
    groups: dict[str, list[str]],
    rate: float,
    random_state: int,
) -> pd.DataFrame:
    """Drop one feature group at a time, refit the Isolation Forest, re-measure.

    Shows which signals the model actually relies on: a group whose removal
    barely moves PR-AUC/recall isn't pulling its weight; a big drop means it is.
    Each ablated model is thresholded on validation exactly like the full model,
    so the comparison is apples-to-apples. The 'full (none dropped)' row is the
    reference.
    """
    from .features import FEATURE_COLUMNS as ALL

    y = (ev["label"].to_numpy() == MALICIOUS)
    rows = []
    for dropped, cols in [("full (none dropped)", [])] + [(g, groups[g]) for g in groups]:
        keep = [c for c in ALL if c not in set(cols)]
        det = IsolationForestDetector(random_state=random_state, feature_columns=keep)
        det.fit_on_benign(fit_feats)
        thr = _threshold(det, val_feats, fit_feats, rate)
        score = det.anomaly_score(test_feats)
        pred = score >= thr
        m = binary_metrics(y, pred)
        rows.append({
            "dropped_group": dropped, "n_features": len(keep),
            "recall": m["recall"], "precision": m["precision"],
            "pr_auc": pr_auc(y, score), "fp_per_10k": fp_per_10k_benign(y, pred),
        })
    out = pd.DataFrame(rows)
    # Delta in PR-AUC vs. the full model (negative = dropping that group hurt).
    full_pr = out.loc[0, "pr_auc"]
    out["pr_auc_delta_vs_full"] = out["pr_auc"] - full_pr
    return out


def run_evaluation(
    events: pd.DataFrame,
    *,
    rules_dir: str | Path = "rules",
    test_size: float = 0.25,
    val_size: float = 0.25,
    random_state: int = 42,
    budget_per_10k: int = DEFAULT_BUDGET_PER_10K,
    n_boot: int = 1000,
    external_alerts: pd.DataFrame | None = None,
) -> EvaluationResult:
    events = events.copy()
    events["timestamp"] = pd.to_datetime(events["timestamp"], utc=True, errors="coerce")

    train_idx, test_idx = session_split(events, test_size=test_size, random_state=random_state)
    assert_no_leakage(events, train_idx, test_idx)
    train_events = events.iloc[train_idx]
    test_events = events.iloc[test_idx]

    # Carve a validation split from train; thresholds are set here, never on test.
    fit_events, val_events = _carve_validation(
        train_events, val_size=val_size, random_state=random_state
    )

    builder = FeatureBuilder().fit(fit_events)
    fit_feats = builder.transform(fit_events)
    val_feats = builder.transform(val_events) if len(val_events) else fit_feats.iloc[0:0]
    test_feats = builder.transform(test_events)
    if test_feats.empty:
        raise ValueError("No processes in the test split; need process_create events.")

    iforest = IsolationForestDetector(random_state=random_state).fit_on_benign(fit_feats)
    lof = LOFDetector().fit_on_benign(fit_feats)
    rarity = ZScoreBaseline().fit_on_benign(fit_feats)

    rate = budget_per_10k / 10_000.0
    thresholds = {
        "Isolation Forest": _threshold(iforest, val_feats, fit_feats, rate),
        "Local Outlier Factor": _threshold(lof, val_feats, fit_feats, rate),
        "Rarity (B)": _threshold(rarity, val_feats, fit_feats, rate),
    }

    engine = RuleEngine.from_dir(rules_dir)
    rolled = alerts_by_process(engine.scan(test_events)).set_index("process_guid")

    guid = test_feats["process_guid"]
    rule_n = rolled["n_alerts"].reindex(guid).fillna(0).to_numpy() if not rolled.empty else np.zeros(len(guid))
    rules_by_guid = rolled["rules"] if not rolled.empty else pd.Series(dtype="object")

    model_score = iforest.anomaly_score(test_feats)
    lof_score = lof.anomaly_score(test_feats)
    rarity_score = rarity.anomaly_score(test_feats)

    # Bootstrap resamples over sessions, so carry the group key per process.
    group = test_feats["session_id"].astype("object")
    group = group.where(group.notna(), test_feats["host"].astype("object")).to_numpy()

    ev = pd.DataFrame({
        "process_guid": guid.to_numpy(),
        "label": test_feats["label"].astype("object").to_numpy(),
        "technique_id": test_feats["technique_id"].astype("object").to_numpy(),
        "source": test_feats["source"].astype("object").to_numpy(),
        "group": group,
        "model_score": model_score,
        "lof_score": lof_score,
        "rarity_score": rarity_score,
        "rule_score": rule_n.astype("float64"),
        "rule_alert": rule_n > 0,
    })

    # Predictions: each model alerts where its test score clears the VALIDATION cut.
    model_pred = model_score >= thresholds["Isolation Forest"]
    lof_pred = lof_score >= thresholds["Local Outlier Factor"]
    rarity_pred = rarity_score >= thresholds["Rarity (B)"]
    combined_pred = ev["rule_alert"].to_numpy() | model_pred
    combined_score = _norm_scores(model_score) + ev["rule_alert"].to_numpy().astype(float)

    # External SigmaHQ baseline (Chainsaw/Hayabusa), mapped to the test processes.
    ext_n = None
    if external_alerts is not None and not external_alerts.empty:
        ext_roll = external.alerts_to_process(external_alerts, test_events)
        if not ext_roll.empty:
            ext_roll = ext_roll.set_index("process_guid")
            ext_n = ext_roll["n_alerts"].reindex(guid).fillna(0).to_numpy()
        else:
            ext_n = np.zeros(len(guid))

    approaches = {
        "Rules (A)": (ev["rule_alert"].to_numpy(), ev["rule_score"].to_numpy()),
    }
    if ext_n is not None:
        approaches["External Sigma (Chainsaw/Hayabusa)"] = (ext_n > 0, ext_n.astype(float))
    approaches["Rarity (B)"] = (rarity_pred, rarity_score)
    approaches["Isolation Forest"] = (model_pred, model_score)
    approaches["Local Outlier Factor"] = (lof_pred, lof_score)
    approaches["Combined (rules OR IF)"] = (combined_pred, combined_score)

    # Explainability + an any-alert flag on the per-process table.
    explanations = _explain(test_feats, fit_feats, rules_by_guid)
    ev["alerted_any"] = (
        ev["rule_alert"].to_numpy() | model_pred | lof_pred | rarity_pred
    )
    ev = ev.merge(explanations, on="process_guid", how="left")

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

    # Bootstrap CIs on the overall test split, resampling sessions.
    y_all = (ev["label"].to_numpy() == MALICIOUS)
    ci = bootstrap_ci(y_all, ev["group"].to_numpy(), approaches, n_boot=n_boot, seed=random_state)

    # Ablation: drop each feature group from the Isolation Forest and re-measure.
    ablation = run_ablation(
        fit_feats, val_feats, ev, test_feats,
        groups=FEATURE_GROUPS, rate=rate, random_state=random_state,
    )

    alerted = ev.loc[
        ev["alerted_any"], ["process_guid", "label", "technique_id", "top_features", "rules"]
    ].copy()
    return EvaluationResult(
        summary=summary,
        per_technique=per_technique,
        eval_table=ev,
        explanations=alerted,
        ci=ci,
        ablation=ablation,
        thresholds=thresholds,
        budget_per_10k=budget_per_10k,
    )


# --- reporting ---------------------------------------------------------------

def write_reports(result: EvaluationResult, outdir: str | Path) -> dict[str, Path]:
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    result.summary.to_csv(out / "summary.csv", index=False)
    written["summary_csv"] = out / "summary.csv"

    thr = " · ".join(f"{k}: {v:.3f}" for k, v in result.thresholds.items())
    md = ["# Evaluation results", "",
          (f"Alert budget: **{result.budget_per_10k}** per 10k processes "
           "(thresholds chosen on a validation split, not on test)."), "",
          f"Validation-chosen score thresholds — {thr}", "",
          "## Metrics by approach and split", "",
          result.summary.round(4).to_markdown(index=False), "",
          "## Per-technique recall (overall test)", "",
          (result.per_technique.round(4).to_markdown(index=False)
           if not result.per_technique.empty else "_No malicious processes in test._"),
          "", "## 95% confidence intervals (bootstrap over sessions, overall test)", "",
          (result.ci.round(4).to_markdown(index=False)
           if not result.ci.empty else "_No CIs._"),
          "", "## Ablation — drop one feature group (Isolation Forest, overall test)", "",
          (result.ablation.round(4).to_markdown(index=False)
           if not result.ablation.empty else "_No ablation._"),
          "", "## Sample alert explanations (top contributing features + rules)", "",
          (result.explanations.head(20).to_markdown(index=False)
           if not result.explanations.empty else "_No alerts._"),
          ""]
    (out / "results.md").write_text("\n".join(md))
    written["results_md"] = out / "results.md"

    if not result.ci.empty:
        result.ci.to_csv(out / "confidence_intervals.csv", index=False)
        written["ci_csv"] = out / "confidence_intervals.csv"

    if not result.ablation.empty:
        result.ablation.to_csv(out / "ablation.csv", index=False)
        written["ablation_csv"] = out / "ablation.csv"

    if not result.explanations.empty:
        result.explanations.to_csv(out / "alert_explanations.csv", index=False)
        written["explanations_csv"] = out / "alert_explanations.csv"

    if not result.per_technique.empty:
        result.per_technique.to_csv(out / "per_technique_recall.csv", index=False)
        written["per_technique_csv"] = out / "per_technique_recall.csv"
        fig = _maybe_write_figure(result, out / "per_technique_recall.png")
        if fig is not None:
            written["figure"] = fig
    return written


README_TABLE_START = "<!-- RESULTS_TABLE_START -->"
README_TABLE_END = "<!-- RESULTS_TABLE_END -->"


def format_results_table(summary: pd.DataFrame) -> str:
    """Build the README results table (overall-test split) as GitHub markdown."""
    allsplit = summary[summary["split"] == "all"]

    def f(x: object) -> str:
        return "—" if pd.isna(x) else f"{float(x):.3f}"

    lines = ["| Approach | Recall | Precision | PR-AUC | FP / 10k benign |",
             "|---|---|---|---|---|"]
    for _, r in allsplit.iterrows():
        lines.append(
            f"| {r['approach']} | {f(r['recall'])} | {f(r['precision'])} "
            f"| {f(r['pr_auc'])} | {f(r['fp_per_10k'])} |"
        )
    return "\n".join(lines)


def update_readme_table(readme_path: str | Path, summary: pd.DataFrame) -> bool:
    """Replace the marked results table in the README from a summary frame.

    Only the block between the START/END markers is touched, so the surrounding
    prose is preserved. Returns False (no-op) if the markers are absent. This is
    how `make evaluate` keeps the headline table in sync with the measured
    numbers -- the numbers are never hand-written (CLAUDE.md rule 1).
    """
    path = Path(readme_path)
    text = path.read_text()
    if README_TABLE_START not in text or README_TABLE_END not in text:
        return False
    pre = text.split(README_TABLE_START)[0]
    post = text.split(README_TABLE_END)[1]
    table = format_results_table(summary)
    path.write_text(f"{pre}{README_TABLE_START}\n\n{table}\n\n{README_TABLE_END}{post}")
    return True


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
    parser.add_argument("--val-size", type=float, default=0.25,
                        help="fraction of TRAIN held out as validation for thresholds")
    parser.add_argument("--budget-per-10k", type=int, default=DEFAULT_BUDGET_PER_10K,
                        help="alert budget per 10k processes (sets model thresholds on validation)")
    parser.add_argument("--n-boot", type=int, default=1000,
                        help="bootstrap resamples for confidence intervals")
    parser.add_argument("--readme", default="README.md",
                        help="README whose results table is refreshed from summary.csv")
    parser.add_argument("--no-update-readme", action="store_true",
                        help="do not rewrite the README results table")
    parser.add_argument("--external", default=None,
                        help="Chainsaw/Hayabusa output file to include as the SigmaHQ baseline")
    parser.add_argument("--external-tool", choices=["chainsaw", "hayabusa"], default=None)
    args = parser.parse_args(argv)

    external_alerts = None
    if args.external:
        if not args.external_tool:
            parser.error("--external requires --external-tool {chainsaw,hayabusa}")
        external_alerts = external.load_external_alerts(args.external, args.external_tool)

    events = pd.read_parquet(args.events)
    result = run_evaluation(events, rules_dir=args.rules_dir, test_size=args.test_size,
                            val_size=args.val_size, budget_per_10k=args.budget_per_10k,
                            n_boot=args.n_boot, external_alerts=external_alerts)
    written = write_reports(result, args.outdir)
    print(result.summary.round(4).to_string(index=False))
    print(f"\nwrote: {', '.join(str(p) for p in written.values())}")

    if not args.no_update_readme and Path(args.readme).exists():
        if update_readme_table(args.readme, result.summary):
            print(f"updated results table in {args.readme}")
        else:
            print(f"note: {args.readme} has no RESULTS_TABLE markers; left unchanged")
    return 0


if __name__ == "__main__":  # pragma: no cover
    import sys

    raise SystemExit(main(sys.argv[1:]))
