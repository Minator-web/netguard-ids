# Full-dataset feature-drift results

This report records the reproducible NetGuard 0.8 analysis from UNSW-NB15 to
CIC-IDS2017. The command scanned all 2,830,743 target rows and retained a
seeded 200,000-row target sample for distribution comparisons. No CIC labels
were used.

## Data used

- UNSW-NB15 source rows: 175,341
- CIC-IDS2017 target rows scanned: 2,830,743
- Source sample rows: 175,341
- Target sample rows: 200,000
- Shared features: 10

## Results

| Feature | PSI | PSI severity | KS | Median shift / source IQR | Source missing | Target missing |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| forward_bytes | 2.8618 | high | 0.6703 | -0.2822 | 0.0000 | 0.0000 |
| forward_bytes_per_second | 2.4287 | high | 0.4218 | -0.0065 | 0.0152 | 0.0011 |
| packets_per_second | 1.9576 | high | 0.3652 | -0.0163 | 0.0152 | 0.0011 |
| forward_iat_mean_ms | 1.7709 | high | 0.3538 | -0.0046 | 0.0000 | 0.0000 |
| forward_packets | 1.1589 | high | 0.3234 | 0.0000 | 0.0000 | 0.0000 |
| duration_seconds | 1.1294 | high | 0.3760 | 0.0446 | 0.0000 | 0.0000 |
| backward_packets | 0.7764 | high | 0.3213 | 0.0000 | 0.0000 | 0.0000 |
| backward_iat_mean_ms | 0.2901 | high | 0.1596 | -0.0001 | 0.0000 | 0.0000 |
| backward_bytes_per_second | 0.2697 | high | 0.2238 | 0.2201 | 0.0152 | 0.0011 |
| backward_bytes | 0.1501 | moderate | 0.2312 | -0.0381 | 0.0000 | 0.0000 |

Nine of the ten shared features exceed the heuristic high-drift PSI threshold
of 0.25. `forward_bytes` has both the largest PSI (2.8618) and KS separation
(0.6703). The only feature below the high-drift threshold is
`backward_bytes`, which still has moderate drift.

## Interpretation

The result supplies a plausible distribution-level explanation for the earlier
cross-dataset generalization gap: the source validation macro F1 was 0.7361,
while target macro F1 was 0.4494. It does not prove that any individual feature
caused the performance loss, because these are marginal tests and do not
measure feature interactions, conditional shift, or label shift.

The small standardized median shifts for several features do not contradict
their high PSI or KS values. Medians summarize only the center, whereas PSI and
KS can detect redistribution across the rest of a feature's distribution.

## Reproduction

```powershell
.\.venv\Scripts\python.exe -m netguard_ids.ml_cli analyze-drift
```

The generated machine-readable record is `reports/feature-drift.json`. PSI
severity cutoffs are diagnostic heuristics, not universal statistical laws.
