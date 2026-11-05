"""Tests for detect.split — the no-leakage guarantee a reviewer checks."""

import numpy as np
import pandas as pd
import pytest

from detect import split


def _frame():
    """Four lab sessions over four days + a public (eval-only) session."""
    rows = []
    for day, sess in enumerate(["s1", "s2", "s3", "s4"], start=1):
        for i in range(5):
            rows.append({
                "session_id": sess, "host": "lab01", "source": "lab",
                "timestamp": f"2021-03-0{day}T12:0{i}:00Z",
                "label": "benign" if i else "malicious",
            })
    for i in range(5):  # public, eval-only
        rows.append({
            "session_id": None, "host": "pub-host", "source": "public",
            "timestamp": f"2021-01-0{i + 1}T00:00:00Z", "label": "malicious",
        })
    return pd.DataFrame(rows)


def test_split_has_no_group_leakage():
    df = _frame()
    train, test = split.session_split(df, test_size=0.25)
    split.assert_no_leakage(df, train, test)  # raises if leaked


def test_time_split_puts_most_recent_sessions_in_test():
    df = _frame()
    train, test = split.session_split(df, test_size=0.25)
    # s4 is the newest lab session -> must be in test; s1 (oldest) -> train.
    assert "s4" in set(df["session_id"].to_numpy()[test])
    assert "s1" in set(df["session_id"].to_numpy()[train])


def test_public_rows_are_test_only():
    df = _frame()
    train, test = split.session_split(df, test_size=0.25)
    assert (df["source"].to_numpy()[test] == "public").any()
    assert not (df["source"].to_numpy()[train] == "public").any()


def test_shuffle_split_is_seeded_and_group_clean():
    df = _frame()
    a = split.session_split(df, test_size=0.5, shuffle=True, random_state=7)
    b = split.session_split(df, test_size=0.5, shuffle=True, random_state=7)
    assert np.array_equal(a[1], b[1])  # reproducible
    split.assert_no_leakage(df, *a)


def test_assert_no_leakage_catches_group_leak():
    df = _frame()
    # Leak a GROUP without sharing any row: session s1 split across both sides.
    s1 = np.where(df["session_id"].to_numpy() == "s1")[0]
    s2 = np.where(df["session_id"].to_numpy() == "s2")[0]
    train = np.concatenate([s1[:2], s2])  # some s1 rows + all s2
    test = s1[2:]                          # other s1 rows -> same group, no row overlap
    assert not np.intersect1d(train, test).size  # guard: not a row-overlap case
    with pytest.raises(AssertionError, match="span train and test"):
        split.assert_no_leakage(df, train, test)


def test_assert_catches_public_in_train():
    df = _frame()
    pub = np.where(df["source"].to_numpy() == "public")[0]
    lab = np.where(df["source"].to_numpy() == "lab")[0]
    with pytest.raises(AssertionError, match="public rows leaked"):
        split.assert_no_leakage(df, train_idx=np.concatenate([lab, pub]), test_idx=np.array([], dtype=int))
