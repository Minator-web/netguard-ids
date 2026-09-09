# Research Roadmap

The project combines a transparent rule-based detector with an interpretable
flow-based machine-learning baseline. The research version will compare these
approaches under realistic deployment constraints.

## Research question

How well do lightweight and explainable intrusion-detection models generalize
to traffic captured outside their training dataset?

## Planned experiments

1. Add dataset adapters that normalize common flow features from UNSW-NB15 and CIC-IDS2017.
2. Compare the existing Logistic Regression baseline with Random Forest and LightGBM.
3. Evaluate both within-dataset and cross-dataset performance.
4. Report macro F1, per-class recall, false-positive rate, inference latency,
   peak memory usage, and calibration error.
5. Explain predictions with SHAP and compare explanations across datasets.
6. Release preprocessing code, fixed random seeds, dependency versions, and
   result tables required to reproduce every experiment.

## Claim discipline

NetGuard is an educational and research prototype, not a replacement for a
production IDS. Results must be reported without overstating real-world
generalization.
