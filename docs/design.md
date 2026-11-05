# Design decisions and trade-offs

> TODO. Record each non-obvious decision so it is defensible in an interview:
>
> - `.evtx` parser choice (Rust `evtx_dump` vs. `python-evtx`) and why.
> - Common schema: which fields, how Sysmon and Security EIDs map onto it.
> - Feature set and the justification for each feature (and what was dropped).
> - Why Isolation Forest (vs. LOF / one-class SVM) and the frequency baseline.
> - Train/test split strategy and how leakage is prevented + tested.
> - Evaluation metric choices (PR-AUC, FP/10k benign) and why not accuracy.
