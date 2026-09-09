# Changelog

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
