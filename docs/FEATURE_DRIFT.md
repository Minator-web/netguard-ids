# Feature-drift analysis

Version 0.8 diagnoses marginal distribution shift across the ten harmonized
flow features used by the cross-dataset models. It does not use CIC-IDS2017
labels.

## Metrics

- Population Stability Index (PSI): source-decile bin redistribution
- Kolmogorov-Smirnov statistic: maximum empirical-CDF separation
- Missing rate: fraction of unavailable or non-finite values
- Standardized median shift: target-minus-source median divided by source IQR

The conventional PSI labels used by the report are `<0.10` low, `0.10-0.25`
moderate, and `>=0.25` high. These are operational heuristics and must not be
treated as universal statistical laws. With large samples, KS p-values become
tiny for small differences, so practical interpretation should emphasize the
KS statistic rather than statistical significance alone.

## Reproducible sampling

The complete CIC dataset is scanned in chunks. Each target row receives a
seeded random priority and the lowest priorities are retained, producing a
uniform reservoir sample without knowing the target row count in advance. The
default sample contains up to 200,000 source and 200,000 target rows. Missing
rates and total target row counts are calculated over the full target data.

## Run

```powershell
.\.venv\Scripts\python.exe -m netguard_ids.ml_cli analyze-drift
```

Optional controls:

```powershell
.\.venv\Scripts\python.exe -m netguard_ids.ml_cli analyze-drift --sample-rows 100000 --seed 42
```

Outputs:

- `reports/feature-drift.json`: complete metrics and metadata
- `reports/feature-drift.md`: features ranked by PSI

PSI and KS measure each feature separately. They do not capture correlations,
conditional shift, label shift, or interactions learned by a classifier.
