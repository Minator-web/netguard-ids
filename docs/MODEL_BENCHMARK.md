# Cross-dataset model benchmark

Version 0.7 compares three classifier families under one controlled protocol:

- SGD classifier with logistic loss: fast linear baseline
- Random Forest: bagged nonlinear decision trees
- Histogram Gradient Boosting: boosted nonlinear decision trees

## Fair-comparison controls

Every model receives the same ten harmonized features and the same seeded UNSW
fit/validation rows. Each model gets its own threshold selected only from its
UNSW validation predictions at a target false-positive rate of 10%.

All frozen models are then evaluated on the same CIC-IDS2017 rows. The CIC CSV
files are read once in chunks, which keeps memory and disk overhead practical.

## Run

```powershell
.\.venv\Scripts\python.exe -m netguard_ids.ml_cli benchmark-models
```

Outputs:

- `artifacts/model-benchmark.joblib`: all fitted pipelines and thresholds
- `reports/model-benchmark.json`: complete machine-readable results
- `reports/model-benchmark.md`: compact comparison table

The report includes balanced accuracy, macro F1, FPR, FNR, ROC AUC, fitting
time, and target inference throughput.

## Interpretation rule

The CIC results may describe how the prespecified models transferred, but they
must not be repeatedly used to tune hyperparameters. Selecting a winner from
CIC and claiming its CIC score as final would bias the evaluation. A third
untouched dataset is required to confirm any model choice suggested by this
exploratory benchmark.
