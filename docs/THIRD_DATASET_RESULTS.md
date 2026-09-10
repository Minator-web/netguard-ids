# Full ToN-IoT third-dataset results

This report records the complete NetGuard 1.0 evaluation on the 211,043-row
ToN-IoT Network train/test dataset. The standard baseline and the previously
source-selected `quantile_normal` pipeline were loaded unchanged from the v0.9
artifact.

## Locked protocol

- Target rows: 211,043
- Source-selected pipeline: `quantile_normal`
- Directly mapped features: 5
- Derived features: 3
- Unavailable features filled by source-fitted imputers: 2
- Model or threshold fitting on ToN-IoT: no

The ToN-IoT labels were used only for this final evaluation. No model,
transformer, feature mapping, candidate selection, or threshold was changed in
response to the target results.

## Results

| Pipeline | Role | Threshold | Balanced accuracy | Macro F1 | FPR | FNR | ROC AUC |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| standard | baseline | 0.594426 | 0.5496 | 0.5440 | 0.6309 | 0.2699 | 0.5268 |
| quantile_normal | source-selected | 0.662862 | 0.4103 | 0.3956 | 0.6481 | 0.5313 | 0.4557 |

## Source-selected minus baseline

| Metric | Standard | Quantile-normal | Change |
| --- | ---: | ---: | ---: |
| Balanced accuracy | 0.5496 | 0.4103 | -0.1393 |
| Macro F1 | 0.5440 | 0.3956 | -0.1484 |
| False-positive rate | 0.6309 | 0.6481 | +0.0172 |
| False-negative rate | 0.2699 | 0.5313 | +0.2614 |
| ROC AUC | 0.5268 | 0.4557 | -0.0711 |

## Interpretation

The CIC-IDS2017 improvement did not replicate on the third dataset. Compared
with standard scaling, the locked quantile-normal pipeline reduced macro F1 by
0.1484, increased FPR by 1.72 percentage points, increased FNR by 26.14 points,
and reduced ROC AUC by 0.0711.

The baseline ROC AUC of 0.5268 is only slightly above random ranking, while the
quantile-normal ROC AUC of 0.4557 is below 0.5. Neither pipeline is suitable for
operational deployment on ToN-IoT traffic. The result rejects the broader claim
that source-fitted quantile normalization is a generally reliable solution to
cross-dataset shift.

The defensible conclusion is narrower: quantile-normal preprocessing improved
the locked UNSW-to-CIC experiment, but that benefit was target-dependent and
failed to generalize to ToN-IoT.

## Limitations

ToN-IoT supplies only eight of the ten model inputs directly or by derivation.
The two IAT features are filled by imputers fitted on UNSW data. In addition,
traffic composition, collection tooling, direction semantics, attack types,
and label definitions differ across datasets. These factors may contribute to
the failure, but the current experiment does not isolate their causal effects.
