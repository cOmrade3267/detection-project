# Behavioral Detection Pipeline — task runner.
# Targets are intentionally empty stubs for now (scaffold only, no logic yet).
# Each prints what it will do so the pipeline order is self-documenting.

.DEFAULT_GOAL := help
.PHONY: help setup lock ingest doctor normalize label features rules train evaluate test coverage lint clean smoke all

help:  ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

VENV := .venv
PY := $(VENV)/bin/python

setup:  ## Create a venv and install the package with dev extras
	python3 -m venv $(VENV)
	$(PY) -m pip install -U pip
	$(PY) -m pip install -e '.[dev]'

lock:  ## Freeze exact installed versions to requirements.lock (reproducibility)
	$(PY) -m pip freeze --exclude-editable > requirements.lock
	@echo "wrote requirements.lock"

ingest: EVTX ?=
ingest: OUT ?=
ingest:  ## .evtx -> Parquet  (usage: make ingest EVTX=in.evtx OUT=out.parquet)
	@test -n "$(EVTX)" && test -n "$(OUT)" || { echo "usage: make ingest EVTX=<in.evtx> OUT=<out.parquet>"; exit 2; }
	$(PY) -m detect.ingest "$(EVTX)" "$(OUT)"

doctor: IN ?=
doctor:  ## Data-quality report (usage: make doctor IN=events.parquet)
	@test -n "$(IN)" || { echo "usage: make doctor IN=<ingest-or-normalized.parquet>"; exit 2; }
	$(PY) -m detect.doctor "$(IN)"

normalize: IN ?=
normalize: OUT ?=
normalize:  ## Common schema  (usage: make normalize IN=raw.parquet OUT=norm.parquet)
	@test -n "$(IN)" && test -n "$(OUT)" || { echo "usage: make normalize IN=<raw.parquet> OUT=<norm.parquet>"; exit 2; }
	$(PY) -m detect.normalize "$(IN)" "$(OUT)"

label: IN ?=
label: LABELS ?=
label: OUT ?=
label: SRC ?=
label:  ## Attach run-log labels  (usage: make label IN=norm.parquet LABELS=labels.csv OUT=labeled.parquet [SRC=lab])
	@test -n "$(IN)" && test -n "$(LABELS)" && test -n "$(OUT)" || { echo "usage: make label IN=<norm.parquet> LABELS=<labels.csv> OUT=<labeled.parquet> [SRC=lab]"; exit 2; }
	$(PY) -m detect.label "$(IN)" "$(LABELS)" "$(OUT)" $(if $(SRC),--default-source "$(SRC)",)

features: IN ?=
features: OUT ?=
features:  ## Per-process features  (usage: make features IN=norm.parquet OUT=feat.parquet)
	@test -n "$(IN)" && test -n "$(OUT)" || { echo "usage: make features IN=<norm.parquet> OUT=<feat.parquet>"; exit 2; }
	$(PY) -m detect.features "$(IN)" "$(OUT)"

rules: IN ?=
rules: OUT ?=
rules:  ## Sigma-style rule scan  (usage: make rules IN=norm.parquet OUT=alerts.parquet)
	@test -n "$(IN)" && test -n "$(OUT)" || { echo "usage: make rules IN=<norm.parquet> OUT=<alerts.parquet>"; exit 2; }
	$(PY) -m detect.rules "$(IN)" "$(OUT)" --rules-dir rules

train: FEATURES ?=
train: MODEL ?=
train:  ## Fit Isolation Forest  (usage: make train FEATURES=feat.parquet MODEL=models/iforest.joblib)
	@test -n "$(FEATURES)" && test -n "$(MODEL)" || { echo "usage: make train FEATURES=<feat.parquet> MODEL=<model.joblib>"; exit 2; }
	$(PY) -m detect.model "$(FEATURES)" "$(MODEL)"

evaluate: EVENTS ?=
evaluate: OUTDIR ?= artifacts
evaluate: EXTERNAL ?=
evaluate: ETOOL ?=
evaluate:  ## Regenerate result tables + figure  (usage: make evaluate EVENTS=norm.parquet [EXTERNAL=hunt.json ETOOL=chainsaw])
	@test -n "$(EVENTS)" || { echo "usage: make evaluate EVENTS=<normalized-labeled.parquet> [OUTDIR=artifacts] [EXTERNAL=<out.json> ETOOL=chainsaw|hayabusa]"; exit 2; }
	$(PY) -m detect.evaluate "$(EVENTS)" --outdir "$(OUTDIR)" --rules-dir rules $(if $(EXTERNAL),--external "$(EXTERNAL)" --external-tool "$(ETOOL)",)

test:  ## Run the pytest suite
	$(PY) -m pytest

coverage:  ## Run the suite with a coverage report
	$(PY) -m pytest --cov=detect --cov-report=term-missing

lint:  ## Lint with ruff
	$(PY) -m ruff check .

clean:  ## Remove regenerated artifacts
	rm -rf artifacts figures models

smoke:  ## Run the label-free pipeline on the committed fixture (CI sanity check)
	@tmp=$$(mktemp -d); set -e; \
	$(PY) -m detect.ingest tests/fixtures/sysmon.evtx $$tmp/raw.parquet; \
	$(PY) -m detect.normalize $$tmp/raw.parquet $$tmp/norm.parquet; \
	$(PY) -m detect.doctor $$tmp/norm.parquet; \
	$(PY) -m detect.features $$tmp/norm.parquet $$tmp/feat.parquet; \
	$(PY) -m detect.rules $$tmp/norm.parquet $$tmp/alerts.parquet --rules-dir rules; \
	rm -rf $$tmp; echo "smoke OK"

ALL_RUN := data/_run
all: EVTX ?=
all: LABELS ?=
all: OUTDIR ?= artifacts
all:  ## Full pipeline raw .evtx -> results (usage: make all EVTX=f.evtx LABELS=labels.csv)
	@test -n "$(EVTX)" && test -n "$(LABELS)" || { echo "usage: make all EVTX=<f.evtx> LABELS=<labels.csv> [OUTDIR=artifacts]"; echo "  (no labels yet? run 'make smoke' for a pipeline sanity check)"; exit 2; }
	$(PY) -m detect.ingest "$(EVTX)" "$(ALL_RUN)/raw.parquet"
	$(PY) -m detect.normalize "$(ALL_RUN)/raw.parquet" "$(ALL_RUN)/norm.parquet"
	$(PY) -m detect.doctor "$(ALL_RUN)/norm.parquet"
	$(PY) -m detect.label "$(ALL_RUN)/norm.parquet" "$(LABELS)" "$(ALL_RUN)/labeled.parquet"
	$(PY) -m detect.evaluate "$(ALL_RUN)/labeled.parquet" --outdir "$(OUTDIR)" --rules-dir rules
	@echo "done -> $(OUTDIR)/ (results.md, summary.csv, ...) and README table updated"
