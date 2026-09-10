# Full model-benchmark results

## Experimental controls

- Date: 2026-09-10
- Source domain: UNSW-NB15 official training split
- Target domain: all CIC-IDS2017 MachineLearningCSV rows
- UNSW fit rows: 140,272
- UNSW validation rows: 35,069
- CIC target-test rows: 2,830,743
- Shared features: 10
- Target source-validation FPR: 0.10
- Random seed: 42

All models used identical source fit/validation rows and features. Each model's
threshold was selected only on its UNSW validation predictions. CIC labels were
used only for the final descriptive evaluation.

## Results

| Model | Threshold | Source macro F1 | Source FPR | Target macro F1 | Target FPR | Target FNR | Target ROC AUC | Rows/sec |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| SGD Logistic | 0.594426 | 0.7361 | 0.0999 | 0.4494 | 0.5443 | 0.4038 | 0.5655 | 5,330,349 |
| Random Forest | 0.408621 | 0.9356 | 0.1000 | 0.3013 | 0.8038 | 0.2700 | 0.4020 | 516,394 |
| Histogram Gradient Boosting | 0.399097 | 0.9326 | 0.0998 | 0.4291 | 0.3592 | 0.7868 | 0.4261 | 261,843 |

Rows per second measures model prediction time and excludes CSV reading and
feature conversion. It is hardware-dependent, but the within-run comparison
uses the same machine and target rows.

## Interpretation

The nonlinear models achieved source macro F1 above 0.93, substantially higher
than the linear baseline's 0.7361. That advantage did not transfer. Random
Forest produced the lowest target macro F1 and incorrectly flagged 80.38% of
benign target flows. Histogram Gradient Boosting reduced target FPR to 35.92%
but missed 78.68% of target attacks.

SGD Logistic had the highest target macro F1, the only target ROC AUC above 0.5,
and the highest inference throughput. This is a descriptive result rather than
a confirmed model-selection decision. Its target FPR of 54.43% and FNR of
40.38% remain unsuitable for operational use.

The tree models' target ROC AUC values below 0.5 indicate that some learned
source-domain relationships changed direction in the target domain. Merely
changing the threshold cannot repair this ranking failure. The gap between
excellent source validation and weak target performance is evidence of dataset
overfitting and substantial domain shift.

## Research conclusion

Greater within-dataset model complexity did not improve cross-dataset
generalization. None of the three models is deployable on CIC-IDS2017 under this
protocol. Further hyperparameter tuning against CIC would contaminate the
target evaluation; any mitigation or model suggested by these results must be
confirmed on a third untouched dataset.
