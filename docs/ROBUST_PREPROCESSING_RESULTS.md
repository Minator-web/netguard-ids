# Full-dataset robust-preprocessing results

This report records the complete NetGuard 0.9 source-only preprocessing
experiment from UNSW-NB15 to CIC-IDS2017. All 2,830,743 CIC target rows were
evaluated.

## Selection protocol

- UNSW fit rows: 140,272
- UNSW validation rows: 35,069
- CIC target-test rows: 2,830,743
- Target validation FPR: 10%
- Candidate selected using UNSW only: `quantile_normal`
- Selection locked before target evaluation: yes

The pipelines, alert thresholds, and candidate selection used only UNSW fit
and validation data. CIC labels were used only after the selection was locked,
for final descriptive evaluation.

## Results

| Preprocessing | Source selected | Threshold | Source macro F1 | Source FPR | Target macro F1 | Target FPR | Target FNR | Target ROC AUC |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| standard | no | 0.594426 | 0.7361 | 0.0999 | 0.4494 | 0.5443 | 0.4038 | 0.5655 |
| robust | no | 0.916451 | 0.5049 | 0.0985 | 0.5086 | 0.2269 | 0.7531 | 0.3791 |
| quantile_normal | yes | 0.662862 | 0.7711 | 0.1000 | 0.5433 | 0.3850 | 0.4163 | 0.6012 |

## Locked selection versus baseline

The source-selected `quantile_normal` pipeline improved over standard scaling
on both source validation and the untouched target evaluation:

| Metric | Standard | Quantile-normal | Change |
| --- | ---: | ---: | ---: |
| Source macro F1 | 0.7361 | 0.7711 | +0.0350 |
| Target macro F1 | 0.4494 | 0.5433 | +0.0939 |
| Target FPR | 0.5443 | 0.3850 | -0.1593 |
| Target FNR | 0.4038 | 0.4163 | +0.0125 |
| Target ROC AUC | 0.5655 | 0.6012 | +0.0357 |

The target macro-F1 generalization gap narrowed from -0.2867 with standard
scaling to -0.2278 with quantile-normal preprocessing. The false-positive rate
fell by 15.93 percentage points, with a 1.25-point increase in the
false-negative rate.

## Interpretation

The result supports the limited claim that a source-fitted quantile transform
improved this locked UNSW-to-CIC evaluation relative to the existing standard
scaling baseline. It is especially useful that the same candidate was selected
from UNSW validation and produced the strongest CIC macro F1 among the tested
preprocessing methods.

Robust scaling illustrates why a single metric is insufficient: it reduced
target FPR to 0.2269, but target FNR rose to 0.7531 and ROC AUC fell to 0.3791.
It therefore cannot be described as the best mitigation.

This is not evidence of universal cross-dataset robustness. CIC has now been
observed repeatedly, so it must not be used to revise this decision. The locked
`quantile_normal` pipeline requires evaluation on a third untouched dataset
before making a broader model-selection claim.
