from __future__ import annotations

import json
from collections import defaultdict, deque
from pathlib import Path

from .models import Alert, NetworkEvent


class RuleEngine:
    """Small stateful IDS engine with transparent, auditable rules."""

    def __init__(self, rules: dict):
        self.rules = rules
        self._port_activity: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._syn_activity: dict[str, deque[float]] = defaultdict(deque)
        self._last_alert: dict[tuple[str, str], float] = {}

    @classmethod
    def from_file(cls, path: str | Path) -> RuleEngine:
        with Path(path).open(encoding="utf-8") as handle:
            return cls(json.load(handle))

    def process(self, event: NetworkEvent) -> list[Alert]:
        alerts: list[Alert] = []
        alerts.extend(self._detect_port_scan(event))
        alerts.extend(self._detect_syn_flood(event))
        alerts.extend(self._detect_sensitive_port(event))
        return alerts

    def _ready(self, rule_id: str, src_ip: str, timestamp: float, cooldown: float) -> bool:
        key = (rule_id, src_ip)
        previous = self._last_alert.get(key, float("-inf"))
        if timestamp - previous < cooldown:
            return False
        self._last_alert[key] = timestamp
        return True

    def _detect_port_scan(self, event: NetworkEvent) -> list[Alert]:
        config = self.rules["port_scan"]
        if not config.get("enabled") or event.protocol != "TCP":
            return []

        activity = self._port_activity[event.src_ip]
        activity.append((event.timestamp, event.dst_port))
        cutoff = event.timestamp - float(config["window_seconds"])
        while activity and activity[0][0] < cutoff:
            activity.popleft()

        ports = sorted({port for _, port in activity})
        threshold = int(config["unique_ports"])
        if len(ports) < threshold or not self._ready(
            "PORT_SCAN", event.src_ip, event.timestamp, float(config["cooldown_seconds"])
        ):
            return []

        return [Alert(
            timestamp=event.timestamp,
            rule_id="PORT_SCAN",
            severity="high",
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            description=f"Source contacted {len(ports)} unique TCP ports inside the time window.",
            evidence={"unique_port_count": len(ports), "ports": ports},
        )]

    def _detect_syn_flood(self, event: NetworkEvent) -> list[Alert]:
        config = self.rules["syn_flood"]
        is_initial_syn = event.protocol == "TCP" and "S" in event.flags and "A" not in event.flags
        if not config.get("enabled") or not is_initial_syn:
            return []

        activity = self._syn_activity[event.src_ip]
        activity.append(event.timestamp)
        cutoff = event.timestamp - float(config["window_seconds"])
        while activity and activity[0] < cutoff:
            activity.popleft()

        threshold = int(config["syn_packets"])
        if len(activity) < threshold or not self._ready(
            "SYN_FLOOD", event.src_ip, event.timestamp, float(config["cooldown_seconds"])
        ):
            return []

        return [Alert(
            timestamp=event.timestamp,
            rule_id="SYN_FLOOD",
            severity="critical",
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            description=f"Observed {len(activity)} initial SYN packets inside the time window.",
            evidence={"syn_packet_count": len(activity)},
        )]

    def _detect_sensitive_port(self, event: NetworkEvent) -> list[Alert]:
        config = self.rules["sensitive_ports"]
        ports = {int(port) for port in config.get("ports", [])}
        allowlist = set(config.get("allowlist", []))
        if (
            not config.get("enabled")
            or event.dst_port not in ports
            or event.src_ip in allowlist
            or not self._ready(
                "SENSITIVE_PORT",
                event.src_ip,
                event.timestamp,
                float(config["cooldown_seconds"]),
            )
        ):
            return []

        return [Alert(
            timestamp=event.timestamp,
            rule_id="SENSITIVE_PORT",
            severity="medium",
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            description=f"Connection attempt to monitored port {event.dst_port}.",
            evidence={"destination_port": event.dst_port, "protocol": event.protocol},
        )]

