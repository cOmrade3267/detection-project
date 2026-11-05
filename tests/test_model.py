"""Tests for detect.model (Isolation Forest + z-score baseline)."""

import numpy as np
import pandas as pd
import pytest

from detect.features import FEATURE_COLUMNS
from detect.model import (
    IsolationForestDetector,
    ZScoreBaseline,
    alerts_at_budget,
    select_features,
)


def make_features(n_normal=120, n_outlier=3, seed=0, nan=False):
    """Tight benign cluster + a few extreme outliers, over all feature columns."""
    rng = np.random.default_rng(seed)
    normal = np.abs(rng.normal(0.0, 1.0, size=(n_normal, len(FEATURE_COLUMNS))))
    outlier = np.full((n_outlier, len(FEATURE_COLUMNS)), 50.0)
    X = np.vstack([normal, outlier])
    df = pd.DataFrame(X, columns=FEATURE_COLUMNS)
    df["label"] = ["benign"] * n_normal + ["malicious"] * n_outlier
    if nan:
        df.loc[0, "integrity_ordinal"] = np.nan
    return df, n_normal, n_outlier


def test_isolation_forest_scores_outliers_above_normals():
    df, n_normal, n_out = make_features()
    det = IsolationForestDetector().fit_on_benign(df)
    scores = det.anomaly_score(df)
    assert scores[-n_out:].min() > np.median(scores[:n_normal])


def test_zscore_baseline_scores_outliers_above_normals():
    df, n_normal, n_out = make_features()
    base = ZScoreBaseline().fit_on_benign(df)
    scores = base.anomaly_score(df)
    assert scores[-n_out:].min() > np.median(scores[:n_normal])


def test_isolation_forest_is_reproducible():
    df, _, _ = make_features()
    s1 = IsolationForestDetector(random_state=42).fit(df).anomaly_score(df)
    s2 = IsolationForestDetector(random_state=42).fit(df).anomaly_score(df)
    assert np.allclose(s1, s2)


def test_nan_features_do_not_crash():
    df, _, _ = make_features(nan=True)
    det = IsolationForestDetector().fit_on_benign(df)
    assert np.isfinite(det.anomaly_score(df)).all()
    base = ZScoreBaseline().fit_on_benign(df)
    assert np.isfinite(base.anomaly_score(df)).all()


def test_score_before_fit_raises():
    df, _, _ = make_features()
    with pytest.raises(RuntimeError, match="before fit"):
        IsolationForestDetector().anomaly_score(df)
    with pytest.raises(RuntimeError, match="before fit"):
        ZScoreBaseline().anomaly_score(df)


def test_fit_on_empty_raises():
    empty = pd.DataFrame(columns=FEATURE_COLUMNS)
    with pytest.raises(ValueError, match="empty"):
        IsolationForestDetector().fit(empty)


def test_alerts_at_budget_selects_top_scores():
    scores = np.array([0.1, 0.9, 0.5, 0.8, 0.2])
    mask = alerts_at_budget(scores, budget=2)
    assert mask.tolist() == [False, True, False, True, False]
    assert alerts_at_budget(scores, budget=0).sum() == 0
    assert alerts_at_budget(scores, budget=99).sum() == 5  # clamped to n


def test_alerts_budget_flags_the_outliers():
    df, _, n_out = make_features()
    det = IsolationForestDetector().fit_on_benign(df)
    mask = alerts_at_budget(det.anomaly_score(df), budget=n_out)
    assert mask[-n_out:].all()  # the 3 planted outliers are the top-3 alerts


def test_save_load_roundtrip(tmp_path):
    df, _, _ = make_features()
    det = IsolationForestDetector().fit_on_benign(df)
    path = det.save(tmp_path / "models" / "iforest.joblib")
    assert path.exists()
    loaded = IsolationForestDetector.load(path)
    assert np.allclose(loaded.anomaly_score(df), det.anomaly_score(df))


def test_select_features_handles_missing_column():
    df = pd.DataFrame({"cmdline_length": [10, 20]})  # only one feature present
    X = select_features(df)
    assert list(X.columns) == FEATURE_COLUMNS
    assert X["net_conn_count"].isna().all()  # absent -> NaN column
    assert str(X["cmdline_length"].dtype) == "float64"
