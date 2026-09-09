# Threshold calibration

NetGuard 0.5 separates model fitting, threshold selection, and final testing:

1. The official UNSW-NB15 training split is divided into fit and validation sets.
2. The classifier and preprocessing pipeline are fitted only on the fit set.
3. The highest-recall threshold satisfying the target validation false-positive
   rate is selected on validation predictions.
4. Both the default 0.5 threshold and selected threshold are evaluated once on
   the untouched official test split.

Run the reproducible experiment on Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe -m netguard_ids.ml_cli calibrate-unsw
```

Useful options:

```powershell
.\.venv\Scripts\python.exe -m netguard_ids.ml_cli calibrate-unsw --target-fpr 0.05 --validation-size 0.20 --seed 42
```

Outputs:

- `artifacts/unsw-calibrated.joblib`: fitted pipeline and selected threshold
- `reports/unsw-calibration.json`: complete machine-readable metrics
- `reports/unsw-calibration.md`: human-readable comparison

## Interpretation

The target applies to validation data, not to future or test traffic. A higher
test false-positive rate does not mean the experiment failed; it demonstrates
that the class or feature distribution changed between splits. Lowering false
positives generally increases false negatives, so report both rates together
with attack recall and macro F1.

Do not repeatedly change the threshold after inspecting test results. Doing so
would tune against the test set and make the reported final evaluation biased.
