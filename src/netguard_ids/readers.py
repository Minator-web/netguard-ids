from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
import json

from .models import NetworkEvent


def read_jsonl(path: str | Path) -> Iterator[NetworkEvent]:
    with Path(path).open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                yield NetworkEvent.from_dict(json.loads(line))
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                raise ValueError(f"Invalid event at line {line_number}: {exc}") from exc


def read_pcap(path: str | Path) -> Iterator[NetworkEvent]:
    try:
        from scapy.all import IP, TCP, UDP, PcapReader  # type: ignore
    except ImportError as exc:
        raise RuntimeError("PCAP support requires: pip install '.[pcap]'") from exc

    with PcapReader(str(path)) as packets:
        for packet in packets:
            if IP not in packet or (TCP not in packet and UDP not in packet):
                continue
            transport = packet[TCP] if TCP in packet else packet[UDP]
            protocol = "TCP" if TCP in packet else "UDP"
            flags = str(packet[TCP].flags) if TCP in packet else ""
            yield NetworkEvent(
                timestamp=float(packet.time),
                src_ip=str(packet[IP].src),
                dst_ip=str(packet[IP].dst),
                src_port=int(transport.sport),
                dst_port=int(transport.dport),
                protocol=protocol,
                flags=flags,
                size_bytes=len(packet),
            )

