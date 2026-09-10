# Source-only robust preprocessing

NetGuard 0.9 tests whether source-fitted preprocessing can reduce sensitivity
to dataset shift. It compares the same SGD logistic classifier with three
preprocessing strategies:

- `standard`: median imputation and standard scaling (the existing baseline)
- `robust`: median imputation and robust scaling using the source 10th–90th percentiles
- `quantile_normal`: median imputation and a source-fitted quantile-to-normal mapping

## Leakage control

Every transformer is fitted only on the UNSW fit partition. Each alert
threshold is calibrated only on the UNSW validation partition. The candidate
with the highest source-validation macro F1 is selected before any CIC file is
read; balanced accuracy and lower FPR are deterministic tie-breakers.

CIC labels are then used only for final descriptive evaluation of the locked
pipelines. A method that performs best on CIC but was not selected on UNSW must
not be declared the winner. Changing the choice based on CIC performance would
turn CIC into a validation dataset and require a third untouched test dataset.

## Run

```powershell
.\.venv\Scripts\python.exe -m netguard_ids.ml_cli robust-preprocessing
```

For a quick software check, limit the target rows:

```powershell
.\.venv\Scripts\python.exe -m netguard_ids.ml_cli robust-preprocessing --max-cic-rows 10000
```

Do not publish limited-run scores as the full experiment. The complete run
writes:

- `reports/robust-preprocessing.json`
- `reports/robust-preprocessing.md`
- `artifacts/robust-preprocessing.joblib`

Robust preprocessing can reduce the influence of outliers and heavy tails, but
it cannot by itself correct different traffic composition, conditional shift,
label shift, capture-tool artifacts, or incompatible attack definitions.
