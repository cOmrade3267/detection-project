"""model: unsupervised anomaly detection over the per-process feature matrix.

Three detectors with the same interface (fit / fit_on_benign / anomaly_score,
higher = more anomalous), so evaluation compares them on equal footing:

- IsolationForestDetector -- the primary model. Learns the benign manifold and
  flags outliers; few hyper-parameters, scale-invariant, near log-linear.
- LOFDetector -- Local Outlier Factor (novelty mode). A density/distance method
  with a different inductive bias than IF: it flags points in low-density
  regions relative to their local neighbourhood, catching anomalies IF's axis-
  aligned splits can miss. Distance-based, so it is scaled (IF is not).
- ZScoreBaseline -- the trivial "how unusual is this row" score the ML model
  must beat (mean absolute z across features).

All impute missing values with a median learned on TRAIN only, so scoring never
peeks at test statistics. Thresholds are chosen on a *validation* split at a
fixed alert budget (`threshold_at_rate`), never on test; `alerts_at_budget` is
the simpler top-k selector used for same-volume comparisons. See docs/design.md.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.neighbors import LocalOutlierFactor
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .features import FEATURE_COLUMNS


def select_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract the model feature columns as floats (missing cols -> NaN column)."""
    cols = {}
    for c in FEATURE_COLUMNS:
        cols[c] = pd.to_numeric(df[c], errors="coerce") if c in df.columns else np.nan
    return pd.DataFrame(cols, index=df.index, columns=FEATURE_COLUMNS).astype("float64")


def _benign_mask(df: pd.DataFrame) -> np.ndarray:
    if "label" not in df.columns:
        return np.ones(len(df), dtype=bool)
    return (df["label"].astype("object") == "benign").to_numpy()


class IsolationForestDetector:
    """Isolation Forest with a train-fit median imputer. Higher score = anomalous."""

    def __init__(self, n_estimators: int = 200, contamination="auto", random_state: int = 42,
                 max_samples="auto") -> None:
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.max_samples = max_samples
        self.pipeline_: Pipeline | None = None

    def fit(self, features: pd.DataFrame) -> IsolationForestDetector:
        X = select_features(features)
        if len(X) == 0:
            raise ValueError("Cannot fit on an empty feature set.")
        self.pipeline_ = Pipeline([
            ("impute", SimpleImputer(strategy="median")),
            ("iforest", IsolationForest(
                n_estimators=self.n_estimators,
                contamination=self.contamination,
                random_state=self.random_state,
                max_samples=self.max_samples,
            )),
        ])
        self.pipeline_.fit(X)
        return self

    def fit_on_benign(self, features: pd.DataFrame) -> IsolationForestDetector:
        """Fit on benign rows only (the unsupervised ideal); fall back to all rows."""
        benign = features[_benign_mask(features)]
        return self.fit(benign if len(benign) else features)

    def anomaly_score(self, features: pd.DataFrame) -> np.ndarray:
        if self.pipeline_ is None:
            raise RuntimeError("anomaly_score() called before fit().")
        X = select_features(features)
        # score_samples: higher = more normal. Negate so higher = more anomalous.
        return -self.pipeline_.score_samples(X)

    def save(self, path: str | Path) -> Path:
        import joblib

        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, out)
        return out

    @staticmethod
    def load(path: str | Path) -> IsolationForestDetector:
        import joblib

        return joblib.load(path)


class LOFDetector:
    """Local Outlier Factor (novelty mode). Higher score = more anomalous.

    Distance-based, so features are median-imputed *and* standardized on TRAIN
    before fitting; without scaling, large-range features (cmdline_length,
    counts) would dominate the neighbourhood distances.
    """

    def __init__(self, n_neighbors: int = 20, contamination="auto") -> None:
        self.n_neighbors = n_neighbors
        self.contamination = contamination
        self.pipeline_: Pipeline | None = None

    def fit(self, features: pd.DataFrame) -> LOFDetector:
        X = select_features(features)
        if len(X) == 0:
            raise ValueError("Cannot fit on an empty feature set.")
        # n_neighbors must be < n_samples; clamp for tiny splits.
        k = max(1, min(self.n_neighbors, len(X) - 1))
        self.pipeline_ = Pipeline([
            ("impute", SimpleImputer(strategy="median")),
            ("scale", StandardScaler()),
            ("lof", LocalOutlierFactor(
                n_neighbors=k, contamination=self.contamination, novelty=True,
            )),
        ])
        self.pipeline_.fit(X)
        return self

    def fit_on_benign(self, features: pd.DataFrame) -> LOFDetector:
        benign = features[_benign_mask(features)]
        return self.fit(benign if len(benign) else features)

    def anomaly_score(self, features: pd.DataFrame) -> np.ndarray:
        if self.pipeline_ is None:
            raise RuntimeError("anomaly_score() called before fit().")
        X = select_features(features)
        # novelty LOF score_samples: higher = more normal. Negate for anomaly.
        return -self.pipeline_.score_samples(X)

    def save(self, path: str | Path) -> Path:
        import joblib

        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, out)
        return out

    @staticmethod
    def load(path: str | Path) -> LOFDetector:
        import joblib

        return joblib.load(path)


class ZScoreBaseline:
    """Baseline B: anomaly score = mean absolute z across features (train stats)."""

    def __init__(self) -> None:
        self.imputer_: SimpleImputer | None = None
        self.scaler_: StandardScaler | None = None

    def fit(self, features: pd.DataFrame) -> ZScoreBaseline:
        X = select_features(features)
        if len(X) == 0:
            raise ValueError("Cannot fit on an empty feature set.")
        self.imputer_ = SimpleImputer(strategy="median").fit(X)
        self.scaler_ = StandardScaler().fit(self.imputer_.transform(X))
        return self

    def fit_on_benign(self, features: pd.DataFrame) -> ZScoreBaseline:
        benign = features[_benign_mask(features)]
        return self.fit(benign if len(benign) else features)

    def anomaly_score(self, features: pd.DataFrame) -> np.ndarray:
        if self.scaler_ is None or self.imputer_ is None:
            raise RuntimeError("anomaly_score() called before fit().")
        X = select_features(features)
        z = self.scaler_.transform(self.imputer_.transform(X))
        return np.abs(z).mean(axis=1)


def threshold_at_rate(val_scores: np.ndarray, rate: float) -> float:
    """Pick the score threshold that alerts on a fraction ``rate`` of VALIDATION rows.

    This is how a fixed alert budget is set *without touching test*: fit on
    train-benign, score a held-out validation set, and take the (1 - rate)
    quantile of those scores as the cut. Applying this fixed threshold to test
    (alerting where ``score >= threshold``) then yields an honest alert rate --
    the test scores never influence the cut.

    ``rate`` is clamped to [0, 1]; rate<=0 -> +inf (alert on nothing),
    rate>=1 -> -inf (alert on everything). The realized fraction is approximately
    ``rate`` (ties at the threshold are all alerted on).
    """
    scores = np.asarray(val_scores, dtype="float64")
    scores = scores[np.isfinite(scores)]
    if rate <= 0 or len(scores) == 0:
        return float("inf")
    if rate >= 1:
        return float("-inf")
    # (1 - rate) quantile, picking a real data value: alerting with `>=` on it
    # flags about a `rate` fraction of the validation rows.
    return float(np.quantile(scores, 1.0 - rate, method="higher"))


def alerts_at_budget(scores: np.ndarray, budget: int) -> np.ndarray:
    """Boolean mask selecting the top-`budget` highest scores (ties broken by order).

    This is how rules and model are compared at equal alert volume in evaluation.
    """
    scores = np.asarray(scores, dtype="float64")
    n = len(scores)
    budget = max(0, min(budget, n))
    mask = np.zeros(n, dtype=bool)
    if budget:
        top = np.argsort(scores, kind="stable")[::-1][:budget]
        mask[top] = True
    return mask


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Fit the Isolation Forest on a features Parquet.")
    parser.add_argument("features", help="training features Parquet from `detect.features`")
    parser.add_argument("model_out", help="output model path (joblib)")
    parser.add_argument("--all-rows", action="store_true",
                        help="fit on all rows instead of benign-only")
    args = parser.parse_args(argv)

    feats = pd.read_parquet(args.features)
    det = IsolationForestDetector()
    det.fit(feats) if args.all_rows else det.fit_on_benign(feats)
    out = det.save(args.model_out)
    print(f"fit IsolationForest on {len(feats)} processes; wrote {out}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    import sys

    raise SystemExit(main(sys.argv[1:]))
