# Research roadmap

## Research question

How well do lightweight and explainable intrusion-detection models generalize
to traffic captured outside their training dataset?

## Completed

1. Built explainable rules for port scans, SYN floods, and sensitive services.
2. Added JSONL, PCAP/PCAPNG, and authorized live-capture paths.
3. Added UNSW-NB15, CIC-IDS2017, and ToN-IoT dataset adapters.
4. Preserved source-only fitting and validation-based threshold calibration.
5. Compared linear, random-forest, and histogram-gradient-boosting models.
6. Measured feature drift without CIC labels.
7. Locked a source-selected mitigation before target evaluation.
8. Tested that mitigation unchanged on a third dataset and recorded the failed
   replication.

## Next research work

1. Add confidence intervals using a pre-specified flow-level bootstrap.
2. Analyze errors by attack category without changing the locked classifier.
3. Measure peak memory and end-to-end runtime consistently across datasets.
4. Compare explanations across domains using a fixed interpretation protocol.
5. Package the methodology and limitations as a short research manuscript.

## Claim discipline

NetGuard is an educational and research prototype, not a replacement for a
production IDS. Future experiments must preserve the distinction between
exploratory targets, validation data, and untouched confirmation datasets.
