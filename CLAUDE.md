# Project: Behavioral Detection Pipeline for Windows Host Telemetry

> This is the project's design brief and working rules for the AI assistant. Keep it updated. (Symlink or copy to `AGENTS.md` / `.cursorrules` if another IDE needs it.)

## 0. Purpose and rules for the AI assistant

I am a CS (cyber security) student building this to apply for a Microsoft Security Research internship (advanced threat detection, ML and behavioral profiling, hyper-scale host defense). The project must be **real, reproducible and defensible in an interview**.

Hard rules:
1. **Never invent metrics.** Any number that ends up in the README or my CV must come from a script run that I can re-run. Leave placeholders (`TODO`) until measured.
2. **Explain before you code.** For every module, give me a short explanation of why the design is chosen so I can defend it in an interview.
3. **Do not copy rules or code from other repos.** Reference SigmaHQ, Chainsaw, Hayabusa for ideas and baselines only. Respect licenses (SigmaHQ rules: DRL 1.1; EVTX-ATTACK-SAMPLES: GPL-3.0).
4. **Verify dataset facts** (file counts, paths, labels) by inspecting the actual files, not from memory.
5. Keep it simple: Python 3.11+, pandas, scikit-learn, pytest. No heavy frameworks.

## 1. One-line pitch

Ingest Windows Sysmon/Security event logs, build per-process behavioral features, detect attacker behavior with (a) hand-written Sigma-style rules and (b) an unsupervised anomaly model, map alerts to MITRE ATT&CK, and **evaluate against Chainsaw/Hayabusa as a rules-only baseline** with precision, recall and false-positive volume.

## 2. Research questions (what the project actually answers)

1. How much attack behavior does a pure rules approach (Sigma via Chainsaw/Hayabusa) miss, per ATT&CK technique?
2. Does a behavioral anomaly model catch some of the misses, and at what false-positive cost?
3. Does combining both (rules OR model) beat either alone at a fixed alert budget?

## 3. Data (the critical design decision)

**Problem:** public attack-sample repos contain mostly attack-only logs. Precision and false-positive rate cannot be measured without benign data, and a model trained on attack-only data is meaningless.

**Plan: build my own labeled dataset, use public samples as an extra test set.**

- **Lab (own data):** Windows VM (I already built and hardened a Windows Server AD VM) with Sysmon installed using a community base config. Generate:
  - *Benign:* 1 to 2 weeks (or scripted sessions) of normal use: browsing, Office, software installs, admin PowerShell, scheduled tasks, Windows Update.
  - *Malicious:* run Atomic Red Team tests for chosen ATT&CK techniques, snapshot-revert between runs, record the **start/end timestamps and technique ID of every test** as labels.
  - Do this only in an isolated VM with no bridged network.
- **Public test set (held out, never trained on):**
  - EVTX-ATTACK-SAMPLES (sbousseaden), hayabusa-sample-evtx (Yamato Security). Verify file lists locally.
  - OTRF Security-Datasets: check the current repo state before relying on it.
- **Labeling schema:** one row per event or per process-window with `label` (benign/malicious), `technique_id`, `source` (lab/public), `host`, `session_id`.

**Leakage rules (a reviewer will check):**
- Split by **session/host/time**, never by random event.
- Fit scalers and encoders on training data only.
- The public set is evaluation-only.

## 4. Architecture

```
raw .evtx
   |
   v
[ingest]  evtx -> JSON/Parquet (use the Rust `evtx_dump` or `python-evtx`; pick one, justify)
   |
   v
[normalize]  Sysmon EID 1/3/7/11/13/22 + Security 4688/4624 -> common schema
   |
   v
[features]  per process / per time window (pandas)
   |            \
   v             v
[rules]       [model]  Isolation Forest (+ simple frequency baseline)
   \             /
    v           v
   [alerts + ATT&CK mapping]
          |
          v
   [evaluate]  vs. Chainsaw / Hayabusa baseline
```

### Feature ideas (start small, justify each)
- Parent-child process pair rarity (frequency in the benign set).
- Command-line length, Shannon entropy, presence of base64/`-enc`, `-nop`, `-w hidden`.
- LOLBin execution flags (certutil, mshta, rundll32, regsvr32, wmic) plus unusual parent.
- Process integrity level / user vs. typical for that image.
- Network connections per process in a window (Sysmon EID 3): count, distinct destinations, rare ports.
- Burstiness: events per minute, new-process fan-out.
- Image-path anomalies (execution from Temp, AppData, Downloads).

### Models
1. **Baseline A:** rules only (hand-written Sigma + Chainsaw/Hayabusa with SigmaHQ rules as the external reference).
2. **Baseline B:** simple frequency or z-score rarity score (so the ML model has to beat something simple).
3. **Model:** Isolation Forest on the features (explain why unsupervised: little labeled attack data in production). Optionally compare with Local Outlier Factor or one-class SVM.
4. **Combined:** rules OR model at a fixed alert budget.

### Evaluation (all numbers must be reproducible)
- Precision, recall, F1, and **PR-AUC** (not accuracy, classes are imbalanced).
- **Recall per ATT&CK technique** (a heatmap or table: which techniques each approach misses).
- **False positives per 10,000 benign events**, the SOC-relevant metric.
- Evaluate on the lab split and separately on the public held-out set; report both.
- Ablation: which features matter (drop one at a time).
- Save everything via a single `make evaluate` that regenerates tables and figures.

## 5. Repo layout

```
.
├── README.md              # pitch, results table, how to reproduce, limitations
├── AGENTS.md              # this file
├── pyproject.toml
├── Makefile               # ingest, features, train, evaluate, test
├── data/                  # gitignored; scripts/README explain how to obtain
├── docs/
│   ├── lab-setup.md       # VM, Sysmon config, Atomic Red Team procedure, labeling
│   └── design.md          # decisions and tradeoffs
├── src/detect/
│   ├── ingest.py
│   ├── normalize.py
│   ├── features.py
│   ├── rules.py           # simple Sigma-like rule engine or pySigma backend
│   ├── model.py
│   ├── attack_map.py
│   └── evaluate.py
├── rules/                 # my own Sigma rules (YAML), each with test events
├── tests/                 # pytest: parser, features, rule hits/misses, no-leakage split
└── notebooks/             # optional exploration only
```

## 6. Small add-on: detections for my own research

Connect this project to my vulnerability findings (Verdaccio SSRF; credential-leak pattern):
- Write 2 to 3 original Sigma rules under `rules/` for SSRF-to-internal/metadata fetch patterns (web or proxy log fields), each with a positive and negative test log in `tests/`.
- In `docs/`, one page: "From vulnerability to detection," describing the Verdaccio finding and how these rules would catch the exploit. Do not include anything under NDA (private program findings stay out).
- Keep it small (about 10% of the work).

## 7. Milestones (about 3 weeks, part time)

| Week | Deliverable |
|---|---|
| 1 | Lab VM + Sysmon; benign collection started; Atomic Red Team runs for 10 to 15 techniques with labels; `ingest` + `normalize` working on public samples; tests |
| 2 | Features, rules, and both baselines; Chainsaw/Hayabusa baseline run on the same data; first evaluation table |
| 3 | Isolation Forest and combined approach; per-technique recall; ablation; Sigma add-on; README, limitations, `make evaluate` reproducible |

If time is short: cut to ~8 techniques, one model (Isolation Forest), one baseline (Chainsaw), and skip the ablation.

## 8. Definition of done

- `make evaluate` reproduces every number in the README.
- README has: problem, approach, a results table, a per-technique recall figure, honest **limitations** (single lab, small benign set, techniques covered), and how to reproduce.
- Tests pass, no data leakage (a test enforces the split).
- I can explain every feature, the model choice, and every number in a 5-minute interview walkthrough.

## 9. CV bullet (fill in only from real results)

> Built a Windows behavioral detection pipeline (Python, pandas, scikit-learn) on Sysmon telemetry from a self-built lab plus public attack samples; combined Sigma rules with an Isolation Forest anomaly model and benchmarked against Chainsaw/Hayabusa: **[recall X% vs Y% baseline at Z false positives per 10k events across N ATT&CK techniques]**. github.com/...

## 10. Suggested first prompts for the AI IDE

1. "Read AGENTS.md. Scaffold the repo layout and a Makefile with empty targets, plus pyproject.toml with pinned dependencies. No logic yet."
2. "Write `ingest.py` to convert .evtx to Parquet with the Rust evtx_dump or python-evtx, with a pytest using a small sample file. Explain which you chose and why."
3. "Write `docs/lab-setup.md` describing the Sysmon install, an Atomic Red Team run procedure, and the labeling format (technique ID, start/end timestamps)."
4. "Write `normalize.py` for Sysmon EID 1, 3, 7, 11, 13, 22 and Security 4688 into one schema; add tests."
5. "Write a session-based train/test split with a test that fails on leakage."
