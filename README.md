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

## Research direction

The next milestone adds flow extraction and reproducible ML experiments on
UNSW-NB15 and CIC-IDS2017. The main focus will be cross-dataset performance,
false positives, explainability, and resource cost rather than accuracy alone.
See [`docs/RESEARCH_ROADMAP.md`](docs/RESEARCH_ROADMAP.md).

## Ethics and limitations

NetGuard is intended for defensive security research and authorized network
monitoring. The current rules are a baseline and may generate false positives.
Do not use the output as the sole basis for operational security decisions.

## License

MIT
