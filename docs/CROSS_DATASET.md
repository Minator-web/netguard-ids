# Cross-dataset evaluation protocol

NetGuard 0.6 measures whether a binary detector learned from UNSW-NB15 transfers
to CIC-IDS2017 without target-domain tuning.

## Data placement

Keep the official files in the ignored `data/` directory:

```text
data/
├── UNSW_NB15_training-set.csv
└── CIC-IDS2017/
    ├── Monday-WorkingHours.pcap_ISCX.csv
    └── ...remaining MachineLearningCSV files...
```

Use CSV files from the official CIC-IDS2017 `MachineLearningCSV.zip` archive.

## Leakage controls

1. Split the official UNSW training data into fit and validation subsets.
2. Fit preprocessing and the classifier only on the UNSW fit subset.
3. Select the alert threshold only on UNSW validation predictions.
4. Apply the frozen pipeline and threshold to CIC-IDS2017.
5. Use CIC labels only to calculate final target-domain metrics.

No CIC row participates in fitting, imputation, scaling, feature selection, or
threshold selection.

## Shared feature mapping

| Common feature | UNSW-NB15 | CIC-IDS2017 | Conversion |
| --- | --- | --- | --- |
| Duration | `dur` | `Flow Duration` | CIC microseconds to seconds |
| Forward packets | `spkts` | `Total Fwd Packets` | None |
| Backward packets | `dpkts` | `Total Backward Packets` | None |
| Forward bytes | `sbytes` | `Total Length of Fwd Packets` | None |
| Backward bytes | `dbytes` | `Total Length of Bwd Packets` | None |
| Packets/second | `rate` | `Flow Packets/s` | None |
| Forward bytes/second | Derived | Derived | Bytes divided by seconds |
| Backward bytes/second | Derived | Derived | Bytes divided by seconds |
| Forward mean IAT | `sinpkt` | `Fwd IAT Mean` | CIC microseconds to milliseconds |
| Backward mean IAT | `dinpkt` | `Bwd IAT Mean` | CIC microseconds to milliseconds |

Forward/backward and source/destination direction are treated as equivalent for
this baseline. That approximation, different flow generators, different label
definitions, and collection-environment shift are explicit limitations.

## Run

```powershell
.\.venv\Scripts\python.exe -m netguard_ids.ml_cli cross-dataset
```

Outputs are written to `artifacts/unsw-to-cic-model.joblib`,
`reports/cross-dataset-metrics.json`, and
`reports/cross-dataset-summary.md`. Report balanced accuracy, macro F1, ROC AUC,
false-positive rate, false-negative rate, and the target-minus-source gap.
