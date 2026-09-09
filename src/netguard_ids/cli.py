from __future__ import annotations

import argparse
from pathlib import Path

from .detector import RuleEngine
from .readers import read_jsonl, read_pcap
from .report import build_report, save_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze network events with NetGuard IDS")
    parser.add_argument("input", help="Input .jsonl, .pcap, or .pcapng file")
    parser.add_argument("--rules", default="config/rules.json", help="Rule configuration path")
    parser.add_argument("--output", default="reports/report.json", help="JSON report path")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    input_path = Path(args.input)
    if input_path.suffix.lower() == ".jsonl":
        events = read_jsonl(input_path)
    elif input_path.suffix.lower() in {".pcap", ".pcapng"}:
        events = read_pcap(input_path)
    else:
        raise SystemExit("Input must be a .jsonl, .pcap, or .pcapng file")

    engine = RuleEngine.from_file(args.rules)
    alerts = []
    processed = 0
    for event in events:
        processed += 1
        alerts.extend(engine.process(event))

    report = build_report(alerts, processed)
    save_report(report, args.output)
    print(f"Processed {processed} events; generated {len(alerts)} alerts.")
    print(f"Report: {Path(args.output).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

