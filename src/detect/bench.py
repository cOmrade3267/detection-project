"""bench: a reproducible SYNTHETIC scale benchmark (L6) — NOT detection quality.

Measures how the pipeline's throughput and memory scale with event volume, so a
reviewer sees real numbers instead of a hand-wave about "scale". Everything here
is **synthetic data, clearly labeled as such** (CLAUDE.md rule 2 / the scale-
benchmark exemption): it is never mixed into detection-quality evaluation. The
numbers are **single-machine**, not a fleet — see docs/scaling.md for the design
discussion this benchmark grounds.

Per scale factor (1x / 10x / 100x of a base event count) it reports, for each
stage (ingest frame-build, Parquet write, normalize, features, model fit, model
score): wall-clock seconds, throughput (events/sec or processes/sec), and peak
process RSS (Linux). It also prototypes **per-host incremental scoring**: fit
once, score new batches without refitting, and measure it against the cost of a
refit.

Run: `make scale-benchmark` (or `python -m detect.bench --base 10000`).
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from . import ingest, normalize
from .features import FeatureBuilder
from .model import IsolationForestDetector

EVENTS_PER_PROCESS = 5
_PAGE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096

_IMAGES = [
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    r"C:\Windows\explorer.exe",
    r"C:\Windows\System32\svchost.exe",
    r"C:\Users\u\AppData\Local\Temp\installer.exe",
]
_PARENT = r"C:\Windows\explorer.exe"


# --- peak-RSS sampler (Linux /proc) -----------------------------------------

class _PeakRSS(threading.Thread):
    """Background sampler of resident memory; peak over the window in MiB."""

    def __init__(self, interval: float = 0.01) -> None:
        super().__init__(daemon=True)
        self.interval = interval
        # NOT `_stop`: threading.Thread has an internal _stop() that join() calls on
        # Python 3.12/3.13, so shadowing it with an Event breaks join().
        self._halt = threading.Event()
        self.peak_bytes = 0

    def _rss(self) -> int:
        try:
            with open("/proc/self/statm") as fh:
                resident_pages = int(fh.read().split()[1])
            return resident_pages * _PAGE
        except (OSError, IndexError, ValueError):
            return 0  # non-Linux / unreadable -> memory reported as 0

    def run(self) -> None:
        while not self._halt.is_set():
            self.peak_bytes = max(self.peak_bytes, self._rss())
            self._halt.wait(self.interval)

    def stop(self) -> float:
        self.peak_bytes = max(self.peak_bytes, self._rss())
        self._halt.set()
        self.join(timeout=1)
        return self.peak_bytes / (1024 * 1024)


def _measure(fn):
    """Run fn, returning (result, seconds, peak_rss_mb)."""
    sampler = _PeakRSS()
    sampler.start()
    t0 = time.perf_counter()
    result = fn()
    seconds = time.perf_counter() - t0
    peak = sampler.stop()
    return result, seconds, peak


# --- synthetic data (clearly synthetic) -------------------------------------

def _iso(epoch: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def _rec(rid: int, epoch: int, event: dict) -> dict:
    return {"event_record_id": rid, "timestamp": _iso(epoch), "data": json.dumps(event)}


def _sysmon(eid: int, host: str, data: dict) -> dict:
    return {"Event": {"System": {
        "Provider": {"#attributes": {"Name": "Microsoft-Windows-Sysmon"}},
        "EventID": eid, "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": host}, "EventData": data}}


def synth_records(n_events: int, n_hosts: int = 1, seed: int = 0) -> tuple[list[dict], dict[str, str]]:
    """Build synthetic ingest-shaped records; return (records, label_by_guid).

    ~1 in 50 processes is 'malicious' (encoded-PowerShell-like) so the model has
    both classes; the rest are benign. Each process emits a process_create plus a
    few network/file events. This is a *workload generator*, not realistic attack
    data — it exists to push volume through the real pipeline code.
    """
    rng = np.random.default_rng(seed)
    n_hosts = max(1, n_hosts)
    n_proc = max(1, n_events // EVENTS_PER_PROCESS)
    records: list[dict] = []
    labels: dict[str, str] = {}
    rid = 0
    for p in range(n_proc):
        guid = f"{{{p:08x}-0000-0000-0000-000000000000}}"
        host = f"H{p % n_hosts:03d}"
        mal = (p % 50 == 0)
        labels[guid] = "malicious" if mal else "benign"
        image = _IMAGES[1] if mal else _IMAGES[p % len(_IMAGES)]
        cmd = ("powershell -nop -w hidden -enc " + "A" * 40) if mal else f"cmd /c dir {p}"
        t0 = 1_600_000_000 + p * 60
        rid += 1
        records.append(_rec(rid, t0, _sysmon(1, host, {
            "ProcessGuid": guid, "ProcessId": p, "Image": image, "CommandLine": cmd,
            "ParentImage": _PARENT, "ParentProcessGuid": "{parent}", "IntegrityLevel": "Medium",
            "User": "lab\\u"})))
        for k in range(EVENTS_PER_PROCESS - 1):
            rid += 1
            if k % 2 == 0:
                records.append(_rec(rid, t0 + k + 1, _sysmon(3, host, {
                    "ProcessGuid": guid, "Image": image, "Protocol": "tcp",
                    "DestinationIp": f"10.0.{int(rng.integers(0, 255))}.{int(rng.integers(0, 255))}",
                    "DestinationPort": int(rng.choice([80, 443, 445, 4444, 8080]))})))
            else:
                records.append(_rec(rid, t0 + k + 1, _sysmon(11, host, {
                    "ProcessGuid": guid, "Image": image,
                    "TargetFilename": rf"C:\Users\u\AppData\Local\Temp\f{p}_{k}.tmp"})))
    return records, labels


def _features_for(n_events: int, n_hosts: int, seed: int) -> pd.DataFrame:
    """Full synthetic chain records -> normalize -> labels -> per-process features."""
    records, labels = synth_records(n_events, n_hosts, seed)
    norm = normalize.normalize_frame(ingest.records_to_frame(records))
    norm["label"] = norm["process_guid"].map(labels).fillna("benign").astype("string")
    return FeatureBuilder().fit_transform(norm)


# --- the benchmark -----------------------------------------------------------

@dataclass
class StageResult:
    scale: int
    stage: str
    n_events: int
    n_processes: int
    seconds: float
    throughput_per_s: float
    peak_rss_mb: float


def _run_one_scale(scale: int, base: int, n_hosts: int, seed: int, tmp: Path) -> list[StageResult]:
    n_target = base * scale
    records, labels = synth_records(n_target, n_hosts, seed)  # setup (not timed)
    n_events = len(records)

    out: list[StageResult] = []

    def add(stage: str, secs: float, peak: float, unit_n: int) -> None:
        out.append(StageResult(scale, stage, n_events, n_proc, secs,
                               unit_n / secs if secs > 0 else float("nan"), peak))

    # ingest: parse JSON + build typed frame
    frame, secs, peak = _measure(lambda: ingest.records_to_frame(records))
    n_proc = max(1, n_events // EVENTS_PER_PROCESS)
    add("ingest_frame", secs, peak, n_events)

    # parquet write
    _, secs, peak = _measure(lambda: ingest.write_parquet(frame, tmp / f"ing_{scale}.parquet"))
    add("parquet_write", secs, peak, n_events)

    # normalize
    norm, secs, peak = _measure(lambda: normalize.normalize_frame(frame))
    add("normalize", secs, peak, n_events)

    norm["label"] = norm["process_guid"].map(labels).fillna("benign").astype("string")

    # features (one row per process)
    feats, secs, peak = _measure(lambda: FeatureBuilder().fit_transform(norm))
    n_proc = len(feats)
    add("features", secs, peak, n_events)

    # model fit (benign only) + score
    det_holder = {}
    _, secs, peak = _measure(
        lambda: det_holder.__setitem__("d", IsolationForestDetector().fit_on_benign(feats)))
    add("model_fit", secs, peak, n_proc)
    det = det_holder["d"]
    _, secs, peak = _measure(lambda: det.anomaly_score(feats))
    add("model_score", secs, peak, n_proc)

    return out


def run_scale_benchmark(base: int = 10_000, factors=(1, 10, 100), n_hosts: int = 4,
                        seed: int = 0, tmp: Path | None = None) -> pd.DataFrame:
    import tempfile

    tmpdir = Path(tmp) if tmp else Path(tempfile.mkdtemp(prefix="detect-bench-"))
    tmpdir.mkdir(parents=True, exist_ok=True)
    rows: list[StageResult] = []
    for f in factors:
        rows.extend(_run_one_scale(int(f), base, n_hosts, seed, tmpdir))
    return pd.DataFrame([r.__dict__ for r in rows])


def run_incremental_benchmark(base: int = 10_000, n_batches: int = 5, n_hosts: int = 4,
                              seed: int = 0) -> tuple[pd.DataFrame, float]:
    """Fit once, score new batches without refitting; contrast with a refit cost."""
    feats0 = _features_for(base, n_hosts, seed)
    det = IsolationForestDetector().fit_on_benign(feats0)  # train once
    _, refit_seconds, _ = _measure(
        lambda: IsolationForestDetector().fit_on_benign(feats0))  # cost of one refit

    rows = []
    for b in range(n_batches):
        feats_b = _features_for(base, n_hosts, seed + 1 + b)
        _, secs, peak = _measure(lambda fb=feats_b: det.anomaly_score(fb))
        rows.append({"batch": b, "n_processes": len(feats_b), "score_seconds": secs,
                     "throughput_proc_s": len(feats_b) / secs if secs > 0 else float("nan"),
                     "peak_rss_mb": peak})
    return pd.DataFrame(rows), refit_seconds


# --- reporting ---------------------------------------------------------------

def _env_header() -> list[str]:
    return [
        "# Scale benchmark (SYNTHETIC data, single machine — NOT detection quality)",
        "",
        "> Synthetic workload only (CLAUDE.md rule 2). Measures throughput/memory,",
        "> not detection accuracy. Single machine, not a fleet — see docs/scaling.md.",
        "",
        "**How to read these numbers:** this is a *synthetic benchmark on one",
        "machine*. Never place these beside the detection-quality results — they are",
        "a different kind of evidence. It is a **single run with no warm-up**, so at",
        "the small (1×) size fixed startup overhead dominates and a stage can look",
        "*faster* at 10×/100× than at 1×; read the **trend across scales**, not one",
        "cell, and re-run for stable figures. Throughput is machine-specific.",
        "",
        f"- machine: {platform.platform()}",
        f"- python: {platform.python_version()}  ·  CPUs: {os.cpu_count()}",
        f"- generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        "",
    ]


def write_report(scale_df: pd.DataFrame, incr_df: pd.DataFrame, refit_seconds: float,
                 outdir: str | Path) -> dict[str, Path]:
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    scale_df.to_csv(out / "scale_benchmark.csv", index=False)
    incr_df.to_csv(out / "scale_incremental.csv", index=False)

    md = _env_header()
    md += ["## Throughput and memory by stage and scale", "",
           scale_df.round(4).to_markdown(index=False), "",
           "## Per-host incremental scoring (fit once, score new batches)", "",
           (f"Cost of one refit on the base batch: **{refit_seconds:.4f} s** — "
            "incremental scoring avoids it per batch below."), "",
           incr_df.round(4).to_markdown(index=False), ""]
    (out / "scale_benchmark.md").write_text("\n".join(md))
    return {"csv": out / "scale_benchmark.csv", "incr_csv": out / "scale_incremental.csv",
            "md": out / "scale_benchmark.md"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Synthetic scale benchmark (L6).")
    parser.add_argument("--base", type=int, default=10_000, help="base event count (1x)")
    parser.add_argument("--factors", default="1,10,100", help="comma list of scale factors")
    parser.add_argument("--batches", type=int, default=5, help="incremental scoring batches")
    parser.add_argument("--hosts", type=int, default=4)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--outdir", default="artifacts")
    args = parser.parse_args(argv)

    factors = tuple(int(x) for x in args.factors.split(","))
    scale_df = run_scale_benchmark(args.base, factors, args.hosts, args.seed)
    incr_df, refit = run_incremental_benchmark(args.base, args.batches, args.hosts, args.seed)
    written = write_report(scale_df, incr_df, refit, args.outdir)

    print(scale_df.round(3).to_string(index=False))
    print(f"\nwrote: {', '.join(str(p) for p in written.values())}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
