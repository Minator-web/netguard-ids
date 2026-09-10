# Experiment summary

## Research question

How well does a lightweight flow-based intrusion detector generalize when the
target traffic was collected outside its training dataset, and can source-only
preprocessing improve that transfer without target-label leakage?

## Evaluation sequence

| Stage | Source information used | Target | Purpose |
| --- | --- | --- | --- |
| Baseline | UNSW fit and validation | CIC-IDS2017 | Measure initial generalization gap |
| Model benchmark | UNSW fit and validation | CIC-IDS2017 | Compare three model families under one protocol |
| Drift diagnosis | UNSW features; unlabeled CIC features | CIC-IDS2017 | Measure marginal feature shift |
| Mitigation | UNSW fit and validation | CIC-IDS2017 | Lock a source-selected preprocessing strategy |
| Confirmation | Saved v0.9 artifact only | ToN-IoT | Test whether the improvement replicates |

## Main results

| Dataset and role | Pipeline | Macro F1 | Balanced accuracy | FPR | FNR | ROC AUC |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| UNSW source validation | Standard | 0.7361 | 0.7852 | 0.0999 | 0.3298 | 0.9062 |
| CIC external target | Standard | 0.4494 | 0.5260 | 0.5443 | 0.4038 | 0.5655 |
| CIC external target | Quantile-normal | 0.5433 | — | 0.3850 | 0.4163 | 0.6012 |
| ToN-IoT confirmation | Standard | 0.5440 | 0.5496 | 0.6309 | 0.2699 | 0.5268 |
| ToN-IoT confirmation | Quantile-normal | 0.3956 | 0.4103 | 0.6481 | 0.5313 | 0.4557 |

The recorded v0.9 console summary did not include CIC balanced accuracy for
the quantile-normal pipeline, so this table deliberately leaves that value
blank rather than reconstructing it.

## Findings

1. Standard scaling suffered a CIC macro-F1 generalization gap of about 0.287.
2. Nine of ten shared UNSW/CIC features exceeded the heuristic high-drift PSI
   threshold, providing a distribution-level explanation for poor transfer.
3. More complex tree models achieved source macro F1 above 0.93 but transferred
   worse than the linear baseline.
4. Quantile-normal preprocessing was selected using only UNSW validation and
   improved CIC macro F1 by 0.0939 while reducing FPR by 15.93 percentage points.
5. That improvement failed to replicate on ToN-IoT: macro F1 fell by 0.1484
   relative to standard scaling and ROC AUC fell below 0.5.

## Defensible conclusion

Source-fitted quantile normalization improved one locked UNSW-to-CIC transfer,
but the benefit was target-dependent and did not generalize to ToN-IoT. The
results do not support operational deployment or a universal robustness claim.

## Threats to validity

- Dataset collection environments, attack definitions, and class prevalence differ.
- Cross-dataset direction semantics are approximate.
- UNSW and CIC share ten defensibly mapped features; ToN-IoT supplies or permits
  derivation of eight, while two IAT inputs require source-fitted imputation.
- Marginal PSI and KS tests do not establish which feature caused an error.
- CIC was observed before the ToN-IoT confirmation and must not be reused to
  justify additional target-specific selection.
