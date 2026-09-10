# NetGuard IDS v1.0.0

NetGuard v1.0.0 is the first research-complete release of the project. It
combines an explainable rule-based IDS with a reproducible study of
cross-dataset generalization.

## Highlights

- Stateful port-scan, SYN-flood, and sensitive-service rules
- JSONL, PCAP/PCAPNG, and authorized live-capture input
- Structured JSON reporting and standalone HTML dashboard
- UNSW-NB15 binary and multiclass baselines
- Validation-only threshold calibration
- Complete 2,830,743-row CIC-IDS2017 external evaluation
- Three-model benchmark and label-free feature-drift analysis
- Source-only robust-preprocessing experiment
- Locked 211,043-row confirmation on ToN-IoT Network
- Twelve automated regression tests

## Main conclusion

Quantile-normal preprocessing improved CIC macro F1 from 0.4494 to 0.5433,
but the locked pipeline failed to replicate that benefit on ToN-IoT, where its
macro F1 was 0.3956 versus 0.5440 for standard scaling. The project therefore
documents target-dependent robustness rather than claiming a universal fix.

## Safety

This release is a defensive research prototype. It must not be used as the
sole basis for blocking traffic, attributing attacks, or making operational
security decisions.
