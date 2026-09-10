from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True, slots=True)
class NetworkEvent:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    flags: str = ""
    size_bytes: int = 0

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> NetworkEvent:
        required = {"timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol"}
        missing = required.difference(value)
        if missing:
            raise ValueError(f"Missing event fields: {', '.join(sorted(missing))}")
        return cls(
            timestamp=float(value["timestamp"]),
            src_ip=str(value["src_ip"]),
            dst_ip=str(value["dst_ip"]),
            src_port=int(value["src_port"]),
            dst_port=int(value["dst_port"]),
            protocol=str(value["protocol"]).upper(),
            flags=str(value.get("flags", "")).upper(),
            size_bytes=int(value.get("size_bytes", 0)),
        )


@dataclass(frozen=True, slots=True)
class Alert:
    timestamp: float
    rule_id: str
    severity: str
    src_ip: str
    dst_ip: str
    description: str
    evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["timestamp_iso"] = datetime.fromtimestamp(
            self.timestamp, tz=timezone.utc
        ).isoformat()
        return result

