# Machine-learning experiment protocol

## Baseline objective

Version 0.3 provides a reproducible supervised-learning pipeline for labelled
network flows. Logistic Regression is used as an interpretable baseline before
more complex models are introduced.

## Input schema

The CSV input must contain these fields:

| Field | Meaning |
| --- | --- |
| `duration_ms` | Flow duration in milliseconds |
| `packet_count` | Total packets in the flow/window |
| `total_bytes` | Total transferred bytes |
| `avg_packet_size` | Mean packet size |
| `syn_count` | TCP SYN packets |
| `ack_count` | TCP ACK packets |
| `unique_dst_ports` | Unique destination ports contacted |
| `dst_port` | Primary destination port |
| `protocol` | Transport protocol, such as TCP or UDP |
| `label` | Ground-truth class; training only |

## Reproducibility controls

- Fixed random seed, default `42`
- Stratified train/test split
- Preprocessing and model saved together in one scikit-learn Pipeline
- Class-balanced Logistic Regression
- Machine-readable metrics and confusion matrix
- Explicit feature order stored with the model artifact

## Reporting rules

Accuracy is insufficient for imbalanced intrusion-detection datasets. Every
experiment must report macro F1, per-class precision and recall, false-positive
behavior, the confusion matrix, dataset version, split strategy, and seed.

The bundled generator creates synthetic data only to test code paths. It is not
a benchmark and its scores must not appear as a real-world research result.

## Planned real-data stages

1. Implement a documented adapter for UNSW-NB15.
2. Implement a documented adapter for CIC-IDS2017.
3. Establish within-dataset baselines without data leakage.
4. Map a conservative shared feature set across both datasets.
5. Train on one dataset and test on the other.
6. Measure inference latency and peak memory consumption.
7. Add calibrated probabilities and SHAP-based explanations.
