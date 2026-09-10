# Changelog

## 0.7.0 - 2026-09-10

- Compare SGD Logistic, Random Forest, and Histogram Gradient Boosting models.
- Use identical UNSW fit/validation rows and ten shared features for every model.
- Calibrate each threshold independently using only UNSW validation predictions.
- Read CIC-IDS2017 once and evaluate all models on the same target rows.
- Report fit time, target inference throughput, and generalization gaps.
- Warn that CIC results are exploratory and require a third dataset for confirmation.
- Add an end-to-end three-model benchmark test.
- Document the complete 2,830,743-row benchmark results and tradeoffs.

## 0.6.0 - 2026-09-09

- Add a chunked CIC-IDS2017 CSV adapter for memory-safe evaluation.
- Harmonize ten defensible flow features and their units across datasets.
- Train and select the alert threshold using only UNSW-NB15 data.
- Evaluate unchanged on CIC-IDS2017 and report the generalization gap.
- Export dataset-level metrics, per-file row counts, limitations, and a summary.
- Add tests covering CIC column normalization and the cross-dataset pipeline.
- Document the reproducible 2,830,743-row full-dataset result and limitations.

## 0.5.0 - 2026-09-09

- Add validation-only threshold selection for the binary UNSW-NB15 model.
- Set a target validation false-positive rate without consulting test labels.
- Compare default and calibrated thresholds on the untouched official test split.
- Save the selected threshold with the trained pipeline for reproducible inference.
- Export a Markdown comparison and add an end-to-end calibration test.

## 0.4.0 - 2026-09-09

- Add an adapter for the official UNSW-NB15 training and testing files.
- Add binary and ten-class experiment modes.
- Preserve the official split and exclude identifier and target leakage.
- Report balanced accuracy, macro/weighted F1, false-positive rate, per-class
  metrics, and confusion matrices.
- Export a human-readable Markdown experiment summary and model coefficients.
- Add an end-to-end UNSW adapter test.

## 0.3.0 - 2026-09-09

- Add a reproducible flow-based Logistic Regression baseline.
- Add deterministic synthetic data generation for pipeline testing.
- Export accuracy, macro F1, per-class metrics, and confusion matrices.
- Save preprocessing and classification as one reusable model artifact.
- Add CSV prediction support and an end-to-end ML test.
- Document the required dataset schema and research reporting rules.

## 0.2.0 - 2026-09-09

- Add authorized live packet capture through Scapy.
- Print alerts to the terminal as they are detected.
- Generate a standalone responsive HTML security dashboard.
- Add Windows/Npcap setup and interface-selection documentation.
- Add dashboard output-escaping tests.

## 0.1.0 - 2026-09-09

- Add stateful port-scan and SYN-flood detection.
- Add sensitive-port monitoring and configurable allowlists.
- Add JSONL and PCAP readers, JSON reports, tests, and CI.
