from __future__ import annotations

import argparse
from pathlib import Path

from .dashboard import save_dashboard
from .detector import RuleEngine
from .readers import capture_live, read_jsonl, read_pcap
from .report import build_report, save_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze network events with NetGuard IDS")
    parser.add_argument("input", nargs="?", help="Input .jsonl, .pcap, or .pcapng file")
    parser.add_argument("--live", action="store_true", help="Capture live traffic")
    parser.add_argument("--interface", help="Capture interface name; default lets Scapy choose")
    parser.add_argument("--duration", type=float, default=30, help="Live capture seconds (default: 30)")
    parser.add_argument("--count", type=int, default=0, help="Stop after this many captured packets")
    parser.add_argument("--rules", default="config/rules.json", help="Rule configuration path")
    parser.add_argument("--output", default="reports/report.json", help="JSON report path")
    parser.add_argument(
        "--dashboard", default="reports/dashboard.html", help="HTML dashboard path"
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.live == bool(args.input):
        raise SystemExit("Choose exactly one input file or --live")

    engine = RuleEngine.from_file(args.rules)
    alerts = []
    processed = 0

    def process_event(event) -> None:
        nonlocal processed
        processed += 1
        new_alerts = engine.process(event)
        alerts.extend(new_alerts)
        for alert in new_alerts:
            print(
                f"[{alert.severity.upper()}] {alert.rule_id} "
                f"{alert.src_ip} -> {alert.dst_ip}: {alert.description}"
            )

    if args.live:
        print(
            f"Capturing authorized traffic for {args.duration:g} seconds"
            + (f" on {args.interface}" if args.interface else "")
            + "... Press Ctrl+C to stop."
        )
        try:
            capture_live(
                process_event,
                interface=args.interface,
                timeout=args.duration if args.duration > 0 else None,
                packet_count=args.count,
            )
        except KeyboardInterrupt:
            print("Capture stopped by user.")
        except (OSError, PermissionError, RuntimeError) as exc:
            raise SystemExit(f"Live capture failed: {exc}") from exc
    else:
        input_path = Path(args.input)
        if input_path.suffix.lower() == ".jsonl":
            events = read_jsonl(input_path)
        elif input_path.suffix.lower() in {".pcap", ".pcapng"}:
            events = read_pcap(input_path)
        else:
            raise SystemExit("Input must be a .jsonl, .pcap, or .pcapng file")
        for event in events:
            process_event(event)

    report = build_report(alerts, processed)
    save_report(report, args.output)
    save_dashboard(report, args.dashboard)
    print(f"Processed {processed} events; generated {len(alerts)} alerts.")
    print(f"Report: {Path(args.output).resolve()}")
    print(f"Dashboard: {Path(args.dashboard).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
