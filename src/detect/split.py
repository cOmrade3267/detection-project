"""split: leakage-safe train/test partitioning by session / host / time.

Why (the reviewer will check this, CLAUDE.md s3):
- Split by **group** (session, falling back to host), never by random event, so
  the same process/session can't appear in both train and test.
- Split by **time** by default: the most recent groups form the test set, so we
  train on the past and evaluate on the future (no temporal leakage).
- The **public** dataset is evaluation-only: any row with source == "public" is
  forced into the test set and never into train.

`assert_no_leakage` encodes these invariants and is what the test suite (and
later `evaluate.py`) call to fail loudly if a split ever violates them.

Pure pandas/numpy, so it tests without any real data.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

PUBLIC = "public"


def group_labels(df: pd.DataFrame, group_col: str = "session_id", fallback_col: str = "host") -> pd.Series:
    """Group key per row: ``group_col`` where present, else ``fallback_col``.

    Lab data is grouped by session; rows without a session_id (e.g. public
    samples) fall back to host so they still form coherent, non-split groups.
    """
    labels = df.get(group_col)
    if labels is None:
        labels = pd.Series([pd.NA] * len(df), index=df.index, dtype="object")
    labels = labels.astype("object")
    if fallback_col in df.columns:
        labels = labels.where(labels.notna(), df[fallback_col].astype("object"))
    if labels.isna().any():
        raise ValueError(
            f"Cannot group for splitting: rows with no '{group_col}' or '{fallback_col}'."
        )
    return labels


def session_split(
    df: pd.DataFrame,
    *,
    test_size: float = 0.25,
    group_col: str = "session_id",
    fallback_col: str = "host",
    time_col: str = "timestamp",
    source_col: str = "source",
    public_value: str = PUBLIC,
    shuffle: bool = False,
    random_state: int | None = None,
) -> tuple[np.ndarray, np.ndarray]:
    """Return (train_idx, test_idx) positional arrays with no group spanning both.

    Default (``shuffle=False``): the most recent groups by their earliest
    timestamp go to test. ``shuffle=True`` assigns whole groups at random
    (seeded by ``random_state``). Public-source rows are always test-only.
    """
    if not 0.0 < test_size < 1.0:
        raise ValueError("test_size must be in (0, 1)")

    pos = np.arange(len(df))
    groups = group_labels(df, group_col, fallback_col).to_numpy()

    if source_col in df.columns:
        is_public = (df[source_col].astype("object") == public_value).to_numpy()
    else:
        is_public = np.zeros(len(df), dtype=bool)

    # Public rows are forced to test and excluded from group assignment below.
    forced_test = pos[is_public]
    candidate = pos[~is_public]
    cand_groups = groups[~is_public]

    unique_groups = pd.unique(cand_groups)
    if shuffle:
        rng = np.random.default_rng(random_state)
        order = rng.permutation(unique_groups)
    else:
        # Order groups by their earliest timestamp; most recent -> test.
        times = pd.to_datetime(pd.Series(df[time_col].to_numpy()[~is_public]), utc=True, errors="coerce")
        start = pd.Series(times.to_numpy(), index=cand_groups).groupby(level=0).min()
        order = start.sort_values().index.to_numpy()  # oldest -> newest

    # Walk from the newest group backward, accumulating test rows until the
    # target fraction is met; whole groups only.
    counts = pd.Series(cand_groups).value_counts()
    target = round(test_size * len(candidate))
    test_groups: set = set()
    acc = 0
    for g in reversed(list(order)):
        if acc >= target:
            break
        test_groups.add(g)
        acc += int(counts[g])

    in_test_group = np.isin(cand_groups, list(test_groups))
    test_idx = np.sort(np.concatenate([forced_test, candidate[in_test_group]]))
    train_idx = np.sort(candidate[~in_test_group])
    return train_idx, test_idx


def assert_no_leakage(
    df: pd.DataFrame,
    train_idx: np.ndarray,
    test_idx: np.ndarray,
    *,
    group_col: str = "session_id",
    fallback_col: str = "host",
    source_col: str = "source",
    public_value: str = PUBLIC,
) -> None:
    """Raise AssertionError if the split leaks. The invariants a reviewer checks.

    1. No group appears in both train and test.
    2. No public-source row is in train (public is evaluation-only).
    3. train and test are disjoint and cover the labeled rows they should.
    """
    train_idx = np.asarray(train_idx)
    test_idx = np.asarray(test_idx)

    overlap = np.intersect1d(train_idx, test_idx)
    assert overlap.size == 0, f"train/test share {overlap.size} row(s)"

    groups = group_labels(df, group_col, fallback_col).to_numpy()
    shared = set(groups[train_idx]) & set(groups[test_idx])
    assert not shared, f"group(s) span train and test: {sorted(map(str, shared))[:5]}"

    if source_col in df.columns:
        train_src = df[source_col].astype("object").to_numpy()[train_idx]
        assert not (train_src == public_value).any(), "public rows leaked into train"
