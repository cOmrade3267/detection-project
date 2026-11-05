"""features: normalized events -> per-process / per-window feature tables.

Why: the anomaly model and baselines score behavior, not raw events. Start
small and justify each feature (CLAUDE.md s4): parent-child rarity, command-
line length/entropy/encoded-flags, LOLBin + unusual parent, integrity level,
network fan-out, burstiness, image-path anomalies.

Leakage rule enforced elsewhere: frequency/rarity stats and scalers are fit on
TRAINING data only.

TODO: implement. No logic yet (scaffold).
"""
