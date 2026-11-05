"""attack_map: MITRE ATT&CK technique metadata and per-technique recall.

Why: evaluation is reported *per technique* (which techniques each approach
misses), so alerts and labeled malicious processes need a technique id and a
human-readable name. This module owns the id->name registry for the techniques
the project uses and the per-technique recall computation evaluate.py calls.

Keep the registry small and explicit (only techniques we actually label/detect)
so there is nothing to verify against a remote source at runtime.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

# id -> name for the techniques referenced by our rules and lab runs. Extend as
# the Atomic Red Team coverage grows. Names follow the ATT&CK catalog.
TECHNIQUES: dict[str, str] = {
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1105": "Ingress Tool Transfer",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1218.005": "System Binary Proxy Execution: Mshta",
    "T1218.010": "System Binary Proxy Execution: Regsvr32",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1552.005": "Unsecured Credentials: Cloud Instance Metadata API",
    "T1090": "Proxy",
}


def technique_name(technique_id: str | None) -> str:
    """Human-readable name for a technique id, or the id itself if unknown."""
    if technique_id is None or (isinstance(technique_id, float) and pd.isna(technique_id)):
        return "unknown"
    return TECHNIQUES.get(str(technique_id), str(technique_id))


def per_technique_recall(
    labels: pd.DataFrame,
    predicted: np.ndarray,
    *,
    label_col: str = "label",
    technique_col: str = "technique_id",
    malicious_value: str = "malicious",
) -> pd.DataFrame:
    """Recall for each technique among malicious processes.

    Returns one row per technique present in the malicious set, with the
    technique id, name, malicious count, detected count, and recall. Sorted by
    recall ascending so the biggest blind spots are at the top.
    """
    cols = ["technique_id", "technique_name", "n_malicious", "n_detected", "recall"]
    mal = labels[label_col].astype("object") == malicious_value
    if not mal.any():
        return pd.DataFrame(columns=cols)

    pred = np.asarray(predicted, dtype=bool)
    sub = pd.DataFrame({
        "technique_id": labels.loc[mal, technique_col].astype("object").fillna("unknown").to_numpy(),
        "detected": pred[mal.to_numpy()],
    })
    grouped = sub.groupby("technique_id")
    out = grouped.agg(n_malicious=("detected", "size"), n_detected=("detected", "sum")).reset_index()
    out["recall"] = out["n_detected"] / out["n_malicious"]
    out["technique_name"] = out["technique_id"].map(technique_name)
    return out[cols].sort_values(["recall", "n_malicious"], ascending=[True, False]).reset_index(drop=True)
