"""Scaffold smoke test: the package imports and exposes a version.

Real tests (parser, features, rule hits/misses, no-leakage split) come later.
"""

import detect


def test_package_imports():
    assert detect.__version__
