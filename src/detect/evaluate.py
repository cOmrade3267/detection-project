"""evaluate: produce every reproducible number and figure (`make evaluate`).

Why: the project's definition of done is that `make evaluate` regenerates each
value in the README. Metrics: precision, recall, F1, PR-AUC (not accuracy —
classes are imbalanced), recall per ATT&CK technique, and false positives per
10,000 benign events. Evaluated on the lab split AND the public held-out set,
reported separately. Includes the leave-one-feature-out ablation.

TODO: implement. No logic yet (scaffold).
"""
