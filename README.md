# NetGuard IDS

NetGuard is a lightweight and explainable network intrusion detection system.
It analyzes normalized network events or PCAP captures, detects suspicious
behavior with auditable rules, and produces a machine-readable incident report.

This repository is the reproducible baseline for a planned study of
cross-dataset generalization in network intrusion detection.

## Current capabilities

- Stateful TCP port-scan detection
- SYN-flood detection within a sliding time window
- Monitoring of sensitive services such as SSH and RDP
- JSON configuration for thresholds and IP allowlists
- JSONL and optional PCAP/PCAPNG input
- Authorized live packet capture with real-time terminal alerts
- Structured JSON incident reports
- Standalone dark-mode HTML dashboard
- Reproducible flow-based machine-learning baseline
- Accuracy, macro F1, per-class metrics, and confusion matrix export
- Validation-only alert-threshold calibration with untouched test evaluation
- Automated unit tests and GitHub Actions

## Quick start

Python 3.10 or newer is required.

```bash
python -m venv .venv
```

On Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
python -m pip install -e .
netguard samples/demo_events.jsonl
```

On Linux or macOS:

```bash
source .venv/bin/activate
python -m pip install -e .
netguard samples/demo_events.jsonl
```

The report is written to `reports/report.json`.
The browser dashboard is written to `reports/dashboard.html`.

## Live capture

Install the packet-capture extra:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[pcap]"
```

Then open PowerShell as Administrator and capture for 30 seconds:

```powershell
.\.venv\Scripts\python.exe -m netguard_ids.cli --live --duration 30
```

Open the resulting dashboard:

```powershell
start reports\dashboard.html
```

Windows live capture requires Npcap. Interface selection and troubleshooting
are covered in [`docs/WINDOWS_LIVE_CAPTURE.md`](docs/WINDOWS_LIVE_CAPTURE.md).

## Analyze a PCAP file

PCAP support is optional and uses Scapy:

```bash
python -m pip install -e ".[pcap]"
netguard data/capture.pcap --output reports/capture-report.json
```

Only analyze traffic that you own or are authorized to inspect. Large PCAP
files and sensitive captures are excluded from Git by default.

## Event format

Each JSONL line represents one network event:

```json
{"timestamp": 1720000000.0, "src_ip": "192.168.1.50", "dst_ip": "192.168.1.10", "src_port": 51000, "dst_port": 22, "protocol": "TCP", "flags": "S", "size_bytes": 60}
```

## Run tests

```bash
python -m unittest discover -s tests -v
```

## Machine-learning baseline

Install the optional ML dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[ml]"
```

Generate deterministic synthetic data to verify the pipeline:

```powershell
.\.venv\Scripts\python.exe -m netguard_ids.ml_cli generate-demo
```

Train and evaluate the baseline:

```powershell
.\.venv\Scripts\python.exe -m netguard_ids.ml_cli train --dataset data\demo_flows.csv
```

Run predictions:

```powershell
.\.venv\Scripts\python.exe -m netguard_ids.ml_cli predict --model artifacts\netguard-model.joblib --input data\demo_flows.csv
```

The generated demo data is synthetic and deliberately separable. Its scores
only confirm that the software pipeline works; they must never be reported as
evidence that the model performs well on real network traffic. See
[`docs/ML_EXPERIMENTS.md`](docs/ML_EXPERIMENTS.md) for the research protocol.

## UNSW-NB15 real-data baseline

Download the official `UNSW_NB15_training-set.csv` and
`UNSW_NB15_testing-set.csv` files into `data/`. Dataset files are ignored by
Git and must not be committed to this repository.

Run the binary baseline on the complete official split:

```powershell
.\.venv\Scripts\python.exe -m netguard_ids.ml_cli train-unsw
```

For the ten-class experiment:

```powershell
.\.venv\Scripts\python.exe -m netguard_ids.ml_cli train-unsw --task multiclass --model artifacts\unsw-multiclass.joblib --metrics reports\unsw-multiclass.json --summary reports\unsw-multiclass.md
```

The command preserves the supplied training/testing split, handles missing and
categorical values inside the saved pipeline, and reports accuracy, balanced
accuracy, macro F1, weighted F1, per-class metrics, and a confusion matrix.
See [`docs/UNSW_NB15.md`](docs/UNSW_NB15.md).

### Calibrate the binary alert threshold

The default binary model produced a high false-positive rate on the official
test split. Select a threshold on a held-out part of the training split, then
compare it once on the untouched official test split:

```powershell
.\.venv\Scripts\python.exe -m netguard_ids.ml_cli calibrate-unsw
```

The default target is a validation false-positive rate of 10%. Change it with
`--target-fpr`, for example `--target-fpr 0.05`. The generated Markdown report
compares false-positive rate, false-negative rate, attack recall, and macro F1.
The test set never participates in threshold selection; a different test FPR
is therefore possible and is useful evidence of distribution shift. See
[`docs/THRESHOLD_CALIBRATION.md`](docs/THRESHOLD_CALIBRATION.md).

## Research direction

The next research milestone adds a CIC-IDS2017 adapter and shared flow
features. The main focus will be cross-dataset performance,
false positives, explainability, and resource cost rather than accuracy alone.
See [`docs/RESEARCH_ROADMAP.md`](docs/RESEARCH_ROADMAP.md).

## Ethics and limitations

NetGuard is intended for defensive security research and authorized network
monitoring. The current rules are a baseline and may generate false positives.
Do not use the output as the sole basis for operational security decisions.

## License

MIT
