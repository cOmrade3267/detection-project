# Behavioral Detection Pipeline — task runner.
# Targets are intentionally empty stubs for now (scaffold only, no logic yet).
# Each prints what it will do so the pipeline order is self-documenting.

.DEFAULT_GOAL := help
.PHONY: help setup lock ingest normalize features train evaluate test lint clean all

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

normalize: IN ?=
normalize: OUT ?=
normalize:  ## Common schema  (usage: make normalize IN=raw.parquet OUT=norm.parquet)
	@test -n "$(IN)" && test -n "$(OUT)" || { echo "usage: make normalize IN=<raw.parquet> OUT=<norm.parquet>"; exit 2; }
	$(PY) -m detect.normalize "$(IN)" "$(OUT)"

features:  ## Build per-process / per-window feature tables
	@echo "TODO: implement src/detect/features.py"

train:  ## Fit the Isolation Forest (+ baselines)
	@echo "TODO: implement src/detect/model.py"

evaluate:  ## Regenerate every results table and figure (reproducibility gate)
	@echo "TODO: implement src/detect/evaluate.py"

test:  ## Run the pytest suite
	$(PY) -m pytest

lint:  ## Lint with ruff
	$(PY) -m ruff check .

clean:  ## Remove regenerated artifacts
	rm -rf artifacts figures models

all: ingest normalize features train evaluate  ## Full pipeline
