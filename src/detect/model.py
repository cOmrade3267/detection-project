"""model: unsupervised anomaly detection over the per-process feature matrix.

Two detectors with the same interface (fit / anomaly_score, higher = more
anomalous):

- IsolationForestDetector -- the primary model. Learns the benign manifold and
  flags outliers; few hyper-parameters, scale-invariant, near log-linear.
- ZScoreBaseline -- the trivial "how unusual is this row" score the ML model
  must beat (mean absolute z across features).

Both impute missing values with a median learned on TRAIN only, so scoring never
peeks at test statistics. Thresholding is deferred to evaluation at a fixed
alert budget (`alerts_at_budget`). See docs/design.md s4.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
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
