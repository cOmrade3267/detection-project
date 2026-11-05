"""model: unsupervised anomaly detection (Isolation Forest) + simple baseline.

Why unsupervised: in production there is little labeled attack data, so we
learn "normal" from the benign set and flag outliers. Isolation Forest is the
primary model; a frequency/z-score rarity score (Baseline B) exists so the ML
model has to beat something simple. Optionally compare LOF / one-class SVM.

TODO: implement. No logic yet (scaffold).
"""
