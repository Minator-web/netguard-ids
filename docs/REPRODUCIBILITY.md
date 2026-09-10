# Reproducibility guide

## Environment

- Python 3.10 or newer
- Fixed default random seed: 42
- Dependencies declared in `pyproject.toml`
- Public datasets are excluded from Git because of their size and licensing

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[ml,pcap]"
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Expected data layout

```text
data/
├── UNSW_NB15_training-set.csv
├── UNSW_NB15_testing-set.csv
├── CIC-IDS2017/
│   └── **/*.csv
└── TON_IoT_Train_Test_Network.csv
```

Use the official dataset distributions. Do not commit dataset files, generated
models, packet captures, or reports containing sensitive traffic.

## Experiment order

Run commands in this order because later stages depend on artifacts created by
earlier stages:

```powershell
.\.venv\Scripts\python.exe -m netguard_ids.ml_cli train-unsw
.\.venv\Scripts\python.exe -m netguard_ids.ml_cli calibrate-unsw
.\.venv\Scripts\python.exe -m netguard_ids.ml_cli cross-dataset
.\.venv\Scripts\python.exe -m netguard_ids.ml_cli benchmark-models
.\.venv\Scripts\python.exe -m netguard_ids.ml_cli analyze-drift
.\.venv\Scripts\python.exe -m netguard_ids.ml_cli robust-preprocessing
.\.venv\Scripts\python.exe -m netguard_ids.ml_cli evaluate-ton
```

`robust-preprocessing` creates `artifacts/robust-preprocessing.joblib`.
`evaluate-ton` must load that unchanged artifact. Deleting it and retraining
after inspecting ToN-IoT would invalidate the locked confirmation protocol.

## Generated outputs

- `artifacts/*.joblib`: fitted pipelines and locked thresholds
- `reports/*.json`: complete machine-readable metrics
- `reports/*.md`: human-readable experiment summaries
- `reports/*.html`: rule-based incident dashboard

Generated outputs are ignored by Git. Curated full-run results are transcribed
into versioned documents under `docs/` with dataset sizes and limitations.

## Integrity checks

Before reporting a run:

1. Confirm the command did not use a row-limit option.
2. Record the exact source and target row counts.
3. Keep the default seed or report the changed value.
4. Verify that target labels were not used for fitting or threshold selection.
5. Run the complete test suite and retain the generated JSON metrics locally.
