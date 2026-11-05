# Behavioral Detection Pipeline — task runner.
# Targets are intentionally empty stubs for now (scaffold only, no logic yet).
# Each prints what it will do so the pipeline order is self-documenting.

.DEFAULT_GOAL := help
.PHONY: help setup ingest normalize features train evaluate test lint clean all

help:  ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

setup:  ## Create a venv and install the package with dev extras
	@echo "TODO: python -m venv .venv && .venv/bin/pip install -e '.[dev]'"

ingest:  ## .evtx -> JSON/Parquet (raw event store)
	@echo "TODO: implement src/detect/ingest.py"

normalize:  ## Map Sysmon/Security EIDs -> common schema
	@echo "TODO: implement src/detect/normalize.py"

features:  ## Build per-process / per-window feature tables
	@echo "TODO: implement src/detect/features.py"

train:  ## Fit the Isolation Forest (+ baselines)
	@echo "TODO: implement src/detect/model.py"

evaluate:  ## Regenerate every results table and figure (reproducibility gate)
	@echo "TODO: implement src/detect/evaluate.py"

test:  ## Run the pytest suite
	@echo "TODO: pytest"

lint:  ## Lint with ruff
	@echo "TODO: ruff check ."

clean:  ## Remove regenerated artifacts
	@echo "TODO: rm -rf artifacts figures models"

all: ingest normalize features train evaluate  ## Full pipeline
