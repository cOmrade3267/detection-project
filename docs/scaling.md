# Scaling to millions of hosts — a design discussion

> **This is a design discussion, not something built here.** The repo is a
> single-host, batch pipeline. This page explains how the design would change
> for fleet scale, which is the question a hyper-scale host-defense team asks.
> Nothing below is implemented; where the current code already does the right
> thing in miniature, it's called out.
>
> **Measured counterpart:** `make scale-benchmark` (`src/detect/bench.py`) runs a
> reproducible **synthetic** benchmark — ingest/normalize/feature throughput,
> peak memory, and model-scoring latency at 1×/10×/100× event volume, plus a
> fit-once-score-many incremental prototype. It is a **single machine, not a
> fleet**, and synthetic workload data only (never detection-quality numbers).
> It grounds the claims below in real timings instead of hand-waving.

## What the current design assumes

Batch `.evtx` → Parquet, all features in pandas in memory, one model fit on a
collected window, thresholds chosen on a validation split. Fine for a lab;
wrong for millions of hosts emitting billions of events a day.

## What changes at scale

### 1. Ingestion: batch files → streaming
Replace `.evtx` batch conversion with a streaming pipe (agent → Kafka / Event
Hubs). Normalize to the common schema **at the edge/agent** so the wire format
is already typed, partitioned by host. Needs backpressure, at-least-once
delivery, and dedup on `(host, event_record_id)` — the same key `external.py`
already joins on. The streaming ingest keeps peak memory bounded per shard,
which the current chunked `ParquetWriter` prototypes in miniature.

### 2. Storage: a lake + a feature store
Land raw events in a columnar lake (Parquet/Iceberg/Delta) partitioned by
date/host with a TTL. Compute per-process features into a **feature store** with
an offline table (for training/backtests) and an online table (for scoring at
ingest), so the exact same feature code serves both and training/serving skew is
avoided.

### 3. Baselines: one global model → per-cohort
A single global "normal" is wrong: a domain controller, a developer workstation,
and a build server have radically different benign behavior, and a global model
drowns in their variance. Fit **per-cohort baselines** — cohort by role / image
profile / OU — and update them incrementally with time decay. This is the single
biggest change from the lab design. The leakage discipline stays: fit on a host
or cohort's past, score its present, never mix.

### 4. Serving: score at ingest, retrain offline
Score each process in near-real-time with a lightweight model (Isolation Forest
or the rarity baseline are cheap) loaded per cohort; retrain in batch offline and
**canary** new models before fleet rollout. Monitor feature and score **drift**
per cohort, because benign behavior shifts (patch days, new software) and a stale
baseline turns into an alert storm. The **fit-once-score-many** pattern this
relies on is prototyped and measured by `make scale-benchmark` (train once, score
new batches without refitting — the per-batch scoring cost is far below a refit).

### 5. Thresholds and the alert budget, fleet-wide
The validation-chosen budget generalizes: give each cohort an alerts-per-10k
budget and allocate a global SOC budget across cohorts. Close the loop with
**analyst dispositions** (true/false positive feedback) to move from purely
unsupervised toward semi-supervised, re-tuning thresholds on confirmed outcomes —
never on the live test stream.

### 6. Cost and latency
- **Tiered detection:** run cheap signals first (rules, rarity) on every event;
  reserve the heavier model for processes that already look unusual. Most events
  are benign and should be cheap.
- **Sampling:** keep all malicious-adjacent and a sample of benign for training;
  storing every benign feature row forever is the dominant cost.
- **Latency budget:** feature computation per event must fit the streaming SLA;
  features needing a wide time window (burstiness, fan-out) use windowed
  aggregates in the stream processor, not a full re-scan.

### 7. Poisoning and robustness at scale
Online per-host baselines are exposed to training-data poisoning
(`threat-model.md`): an attacker who behaves "normally" during baseline updates
teaches the model to accept them. Mitigations: vetted/held-back baseline windows,
robust statistics, change-point detection on the baseline itself, and
human-in-the-loop approval for large baseline shifts.

## What stays the same

The parts that are already right don't change: the **per-process unit**, the
**feature definitions** (`FEATURE_DOC`), **leakage discipline** (split by
host/session/time, fit on the past), the **metrics** (PR-AUC, FP per 10k,
per-technique recall), **explainable alerts**, and **rules OR model**. The lab
is a faithful small model of the real system — which is the point of building it
before claiming anything about scale.
