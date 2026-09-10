# Full cross-dataset results

## Experiment

- Date: 2026-09-09
- Source domain: UNSW-NB15 official training split
- Target domain: all CIC-IDS2017 MachineLearningCSV files
- UNSW fit rows: 140,272
- UNSW validation rows: 35,069
- CIC target-test rows: 2,830,743
- Shared features: 10
- Selected threshold: 0.594426
- Target source-validation FPR: 0.10
- Random seed: 42

The classifier, preprocessing statistics, and threshold were fitted or selected
using only UNSW-NB15 data. CIC-IDS2017 labels were used only to calculate the
final target-domain metrics.

## Results

| Domain | Balanced accuracy | Macro F1 | FPR | FNR | ROC AUC |
| --- | ---: | ---: | ---: | ---: | ---: |
| UNSW validation | 0.7852 | 0.7361 | 0.0999 | 0.3298 | 0.9062 |
| CIC target test | 0.5260 | 0.4494 | 0.5443 | 0.4038 | 0.5655 |

Target-minus-source generalization gaps:

- Macro F1: -0.2868
- Balanced accuracy: -0.2592
- False-positive rate: +0.4444

## Interpretation

The large increase in false-positive rate means the UNSW-trained detector
incorrectly classified 54.43% of benign CIC flows as attacks at the untouched
source-selected threshold. The CIC ROC AUC of 0.5655 is only modestly above the
random-ranking reference of 0.5, so the problem is not merely one poorly chosen
threshold. The model's ranking itself transferred poorly to the target domain.

The result provides evidence of dataset shift caused by differences in traffic,
collection environments, flow exporters, feature distributions, and attack
definitions. It also shows the cost of reducing both datasets to ten defensibly
mapped features: even the UNSW source validation false-negative rate was 32.98%.

These numbers must not be presented as production IDS performance. They are a
reproducible baseline showing why strong within-dataset scores do not establish
cross-dataset generalization.

## Reproduction environment

- Python 3.14.7
- pandas 3.0.5
- scikit-learn 1.9.0
- joblib 1.6.0

Run:

```powershell
.\.venv\Scripts\python.exe -m netguard_ids.ml_cli cross-dataset
```
