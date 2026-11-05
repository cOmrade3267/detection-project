"""features: normalized events -> one feature row per process.

Why per-process: an analyst triages processes ("is this process malicious?"),
so the model and rules score a process_guid, aggregating all of its events
(process_create + network/file/image/registry/dns). See docs/design.md.

Leakage rule in code: FeatureBuilder.fit() learns frequency tables (parent->
child pair rarity) on TRAINING events only; .transform() applies them. Intrinsic
features (entropy, counts, path flags) depend only on the row and cannot leak.

Pure pandas/numpy; unit-testable with synthetic normalized frames.
"""

from __future__ import annotations

import math
import re
from collections import Counter

import numpy as np
import pandas as pd

# LOLBins commonly abused for execution/proxying (CLAUDE.md s4). Lowercase bases.
LOLBINS = {
    "certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe",
    "bitsadmin.exe", "cscript.exe", "wscript.exe", "installutil.exe", "msbuild.exe",
}

# Directories that normal software rarely executes *from* (staging/dropper spots).
_SUSPICIOUS_DIR = re.compile(r"\\(?:temp|tmp|appdata|downloads|programdata|public)\\", re.IGNORECASE)

# Common destination ports; anything else counts toward "uncommon ports".
COMMON_PORTS = {20, 21, 22, 23, 25, 53, 67, 68, 80, 88, 110, 123, 135, 137, 138,
                139, 143, 161, 389, 443, 445, 465, 514, 587, 636, 993, 995, 3268,
                3269, 3389, 5985, 5986}

# PowerShell / obfuscation markers. Non-capturing groups so pandas str.contains
# doesn't warn; -enc requires at least "-enc" to avoid matching a bare "-e".
_RE_ENCODED = re.compile(r"-enc(?:odedcommand)?\b", re.IGNORECASE)
_RE_NOPROFILE = re.compile(r"-nop(?:rofile)?\b", re.IGNORECASE)
_RE_HIDDEN = re.compile(r"-w(?:indowstyle)?\s+hidden\b", re.IGNORECASE)
_RE_BASE64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

_INTEGRITY_ORDER = {
    "untrusted": 0, "low": 1, "medium": 2, "high": 3, "system": 4,
}

IDENT_COLUMNS = ["process_guid", "host", "session_id", "source", "start_time", "image"]
LABEL_COLUMNS = ["label", "technique_id"]
# Every feature, with the attacker behavior it is meant to capture. This is the
# source of truth for the design doc and the interview walkthrough; a test
# asserts FEATURE_COLUMNS and FEATURE_DOC stay in lockstep so no feature ships
# without a written justification (CLAUDE.md rule 2 / Phase 3).
FEATURE_DOC: dict[str, str] = {
    "cmdline_length": "Very long command lines often carry encoded payloads or packed one-liners; benign admin commands are short.",
    "cmdline_entropy": "High Shannon entropy flags base64/obfuscated content vs. readable commands (T1027).",
    "cmdline_has_encoded": "PowerShell -EncodedCommand hides script text — a classic execution/obfuscation marker (T1059.001).",
    "cmdline_has_noprofile": "-NoProfile forces a clean, predictable env; common in automated/malicious PowerShell launchers.",
    "cmdline_has_hidden": "-WindowStyle Hidden runs with no visible window — user-invisible execution (T1564.003).",
    "cmdline_has_base64": "A long base64 run in the command line indicates an embedded encoded payload (T1027).",
    "is_lolbin": "Execution via a living-off-the-land binary (certutil/mshta/rundll32/...) abused to proxy download/exec (T1218/T1105).",
    "image_suspicious_path": "Execution from Temp/AppData/Downloads/ProgramData — staging/dropper spots normal software rarely runs from.",
    "integrity_ordinal": "Process integrity level; an unexpectedly elevated/SYSTEM token for a user image can signal privilege abuse (T1548).",
    "parent_child_rarity": "How rare this parent->child image pair is in benign data; rare lineages (winword->powershell) are strong signals.",
    "child_process_count": "Process fan-out; one process spawning many children signals scripting/automation or post-exploitation.",
    "net_conn_count": "Outbound connection volume; beaconing/exfil/scanning raise it well above benign norms.",
    "net_distinct_dest_ip": "Many distinct destinations from one process suggests scanning or lateral spread.",
    "net_distinct_dest_port": "Many distinct ports suggests scanning or port-knocking.",
    "net_uncommon_port_count": "Connections to non-standard ports (e.g. 4444) are typical of C2 / reverse shells.",
    "dns_query_count": "High DNS volume per process can indicate DNS tunneling or DGA-style beaconing (T1071.004).",
    "file_create_count": "Bulk file creation can indicate payload drops or ransomware-style mass writes.",
    "image_load_count": "Unusual module-load volume can indicate injection or DLL side-loading (T1574.002).",
    "registry_set_count": "Many registry writes can indicate persistence or defense tampering (T1547/T1112).",
    "event_count": "Total per-process activity volume; anomalous overall profiles deviate from the benign cluster.",
    "duration_seconds": "Process lifetime; both fire-and-forget and unusually long-lived processes deviate from benign norms.",
    "events_per_minute": "Burstiness; a short, dense burst of activity is typical of automated attack steps vs. steady human use.",
}
FEATURE_COLUMNS = list(FEATURE_DOC)


def shannon_entropy(s: str | None) -> float:
    """Shannon entropy (bits/char) of a string; 0.0 for empty/missing/non-string."""
    if not isinstance(s, str) or not s:
        return 0.0
    n = len(s)
    counts = Counter(s)
    return float(-sum((c / n) * math.log2(c / n) for c in counts.values()))


def _basename(path: str | None) -> str | None:
    if not isinstance(path, str) or not path:
        return None
    return re.split(r"[\\/]", path)[-1].lower()


def _integrity_ordinal(level: str | None) -> float:
    if not isinstance(level, str):
        return np.nan
    return _INTEGRITY_ORDER.get(level.strip().lower(), np.nan)


class FeatureBuilder:
    """Builds per-process features. Frequency features are fit on train only."""

    def __init__(self) -> None:
        self.pair_counts_: Counter = Counter()
        self.n_train_procs_: int = 0
        self.fitted_: bool = False

    # --- fit: learn only what must come from the training distribution ------
    def fit(self, events: pd.DataFrame) -> FeatureBuilder:
        pc = self._process_create_rows(events)
        pairs = [
            (_basename(p), _basename(i))
            for p, i in zip(pc["parent_image"], pc["image"], strict=False)
        ]
        self.pair_counts_ = Counter(pairs)
        self.n_train_procs_ = len(pc)
        self.fitted_ = True
        return self

    def _pair_rarity(self, parent_image: str | None, image: str | None) -> float:
        # Higher = rarer. -log((count+1)/(N+1)); unseen pairs -> max rarity.
        freq = self.pair_counts_.get((_basename(parent_image), _basename(image)), 0)
        return float(-math.log((freq + 1) / (self.n_train_procs_ + 1)))

    @staticmethod
    def _process_create_rows(events: pd.DataFrame) -> pd.DataFrame:
        pc = events[events["action"] == "process_create"]
        pc = pc[pc["process_guid"].notna()].drop_duplicates("process_guid", keep="first")
        return pc

    # --- transform: apply learned stats + compute intrinsic features --------
    def transform(self, events: pd.DataFrame) -> pd.DataFrame:
        if not self.fitted_:
            raise RuntimeError("FeatureBuilder.transform() called before fit().")

        df = events[events["process_guid"].notna()].copy()
        if df.empty:
            return pd.DataFrame(columns=IDENT_COLUMNS + LABEL_COLUMNS + FEATURE_COLUMNS)

        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
        guids = pd.Index(df["process_guid"].unique(), name="process_guid")

        pc = self._process_create_rows(df).set_index("process_guid")
        # child fan-out: how many process_create events name this guid as parent.
        child_counts = (
            pc["parent_process_guid"].value_counts() if "parent_process_guid" in pc else pd.Series(dtype=int)
        )

        # Per-action event counts.
        action_counts = (
            df.groupby(["process_guid", "action"]).size().unstack(fill_value=0)
        )

        def acount(name: str) -> pd.Series:
            return action_counts[name] if name in action_counts else pd.Series(0, index=guids)

        net = df[df["action"] == "network_connect"]
        net_conn = net.groupby("process_guid").size()
        net_ip = net.groupby("process_guid")["dest_ip"].nunique()
        net_port = net.groupby("process_guid")["dest_port"].nunique()
        uncommon = net[~net["dest_port"].isin(COMMON_PORTS)].groupby("process_guid").size()

        tmin = df.groupby("process_guid")["timestamp"].min()
        tmax = df.groupby("process_guid")["timestamp"].max()
        event_count = df.groupby("process_guid").size()
        duration = (tmax - tmin).dt.total_seconds()

        # Labels: malicious wins; technique = first non-null in the process.
        is_mal = df.assign(_m=df["label"].eq("malicious")).groupby("process_guid")["_m"].max()
        is_ben = df.assign(_b=df["label"].eq("benign")).groupby("process_guid")["_b"].max()
        technique = df.groupby("process_guid")["technique_id"].first()

        def first_str(col: str) -> pd.Series:
            return df.groupby("process_guid")[col].first() if col in df else pd.Series(index=guids, dtype="object")

        out = pd.DataFrame(index=guids)
        # identifiers
        out["host"] = first_str("host")
        out["session_id"] = first_str("session_id")
        out["source"] = first_str("source")
        out["start_time"] = tmin
        out["image"] = pc["image"].reindex(guids)

        # command-line features (from process_create row)
        cmd = pc["command_line"].reindex(guids)
        out["cmdline_length"] = cmd.fillna("").str.len()
        out["cmdline_entropy"] = cmd.map(shannon_entropy)
        out["cmdline_has_encoded"] = cmd.fillna("").str.contains(_RE_ENCODED).astype(int)
        out["cmdline_has_noprofile"] = cmd.fillna("").str.contains(_RE_NOPROFILE).astype(int)
        out["cmdline_has_hidden"] = cmd.fillna("").str.contains(_RE_HIDDEN).astype(int)
        out["cmdline_has_base64"] = cmd.fillna("").str.contains(_RE_BASE64).astype(int)

        # image features
        img = pc["image"].reindex(guids)
        out["is_lolbin"] = img.map(lambda p: int(_basename(p) in LOLBINS))
        out["image_suspicious_path"] = img.fillna("").str.contains(_SUSPICIOUS_DIR).astype(int)

        # lineage
        out["integrity_ordinal"] = pc["integrity_level"].reindex(guids).map(_integrity_ordinal)
        out["parent_child_rarity"] = [
            self._pair_rarity(p, i)
            for p, i in zip(pc["parent_image"].reindex(guids), img, strict=False)
        ]
        out["child_process_count"] = child_counts.reindex(guids).fillna(0).astype(int)

        # network
        out["net_conn_count"] = net_conn.reindex(guids).fillna(0).astype(int)
        out["net_distinct_dest_ip"] = net_ip.reindex(guids).fillna(0).astype(int)
        out["net_distinct_dest_port"] = net_port.reindex(guids).fillna(0).astype(int)
        out["net_uncommon_port_count"] = uncommon.reindex(guids).fillna(0).astype(int)

        # per-action volumes
        out["dns_query_count"] = acount("dns_query").reindex(guids).fillna(0).astype(int)
        out["file_create_count"] = acount("file_create").reindex(guids).fillna(0).astype(int)
        out["image_load_count"] = acount("image_load").reindex(guids).fillna(0).astype(int)
        out["registry_set_count"] = acount("registry_set").reindex(guids).fillna(0).astype(int)

        # volume / burst
        out["event_count"] = event_count.reindex(guids).fillna(0).astype(int)
        dur = duration.reindex(guids).fillna(0.0)
        out["duration_seconds"] = dur
        out["events_per_minute"] = np.where(
            dur > 0, out["event_count"] / (dur / 60.0), out["event_count"].astype(float)
        )

        # labels
        label = pd.Series(pd.NA, index=guids, dtype="object")
        label = label.mask(is_ben.reindex(guids).fillna(False), "benign")
        label = label.mask(is_mal.reindex(guids).fillna(False), "malicious")
        out["label"] = label
        out["technique_id"] = technique.reindex(guids)

        out = out.reset_index()
        return out[IDENT_COLUMNS + LABEL_COLUMNS + FEATURE_COLUMNS]

    def fit_transform(self, events: pd.DataFrame) -> pd.DataFrame:
        return self.fit(events).transform(events)


def build_features_file(in_path: str, out_path: str) -> str:
    """Read a normalized Parquet, build features, write them. Exploration only.

    This fits rarity on the WHOLE input. The leakage-safe path (fit on the train
    split, transform train and test) lives in the training/eval pipeline, which
    splits first. See docs/design.md and detect.split.
    """
    from pathlib import Path

    events = pd.read_parquet(in_path)
    out = FeatureBuilder().fit_transform(events)
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    out.to_parquet(out_path, index=False)
    return out_path


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Build per-process features from normalized events.")
    parser.add_argument("infile", help="normalized Parquet from `detect.normalize`")
    parser.add_argument("outfile", help="output features Parquet")
    args = parser.parse_args(argv)
    print("note: rarity fit on the whole input (exploration). Use the train pipeline "
          "for leakage-safe features.")
    out = build_features_file(args.infile, args.outfile)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    import sys

    raise SystemExit(main(sys.argv[1:]))
