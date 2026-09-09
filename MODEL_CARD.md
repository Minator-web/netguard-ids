# NetGuard ML Baseline — Model Card

## Purpose

This model is an educational baseline for classifying normalized network flows.
It is designed to make preprocessing, training, evaluation, and prediction
reproducible before experiments with public intrusion-detection datasets.

## Model

- Class-balanced multinomial Logistic Regression
- Standard scaling for numeric features
- One-hot encoding for transport protocol
- Fixed and recorded random seed

## Current training data

The repository includes a generator for synthetic `benign`, `port_scan`, and
`syn_flood` flows. These rows are deliberately separable and exist only for
software testing. They do not represent production traffic.

## Intended use

- Reproducible cybersecurity education
- Baseline comparisons on authorized public datasets
- Defensive experimentation on networks the operator may monitor

## Prohibited interpretation

A high score on the synthetic demo dataset is not evidence of real-world attack
detection. The model must not be used as the sole basis for blocking traffic,
attributing attacks, or making operational security decisions.

## Planned validation

The research version will use documented versions of UNSW-NB15 and
CIC-IDS2017, leakage-aware splits, cross-dataset evaluation, per-class recall,
false-positive analysis, inference latency, and calibration measurements.
