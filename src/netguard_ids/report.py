from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .models import Alert


def build_report(alerts: list[Alert], processed_events: int) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "processed_events": processed_events,
        "alert_count": len(alerts),
        "alerts_by_rule": dict(Counter(alert.rule_id for alert in alerts)),
        "alerts_by_severity": dict(Counter(alert.severity for alert in alerts)),
        "alerts": [alert.to_dict() for alert in alerts],
    }


def save_report(report: dict, path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2), encoding="utf-8")

