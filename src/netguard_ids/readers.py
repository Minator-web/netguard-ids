from __future__ import annotations

from collections.abc import Callable, Iterator
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


def _load_scapy():
    try:
        from scapy.all import IP, TCP, UDP, PcapReader, sniff  # type: ignore
    except ImportError as exc:
        raise RuntimeError("Packet capture support requires: pip install '.[pcap]'") from exc
    return IP, TCP, UDP, PcapReader, sniff


def packet_to_event(packet) -> NetworkEvent | None:
    IP, TCP, UDP, _, _ = _load_scapy()
    if IP not in packet or (TCP not in packet and UDP not in packet):
        return None

    transport = packet[TCP] if TCP in packet else packet[UDP]
    protocol = "TCP" if TCP in packet else "UDP"
    flags = str(packet[TCP].flags) if TCP in packet else ""
    return NetworkEvent(
        timestamp=float(packet.time),
        src_ip=str(packet[IP].src),
        dst_ip=str(packet[IP].dst),
        src_port=int(transport.sport),
        dst_port=int(transport.dport),
        protocol=protocol,
        flags=flags,
        size_bytes=len(packet),
    )


def read_pcap(path: str | Path) -> Iterator[NetworkEvent]:
    _, _, _, PcapReader, _ = _load_scapy()
    with PcapReader(str(path)) as packets:
        for packet in packets:
            event = packet_to_event(packet)
            if event is not None:
                yield event


def capture_live(
    handler: Callable[[NetworkEvent], None],
    interface: str | None = None,
    timeout: float | None = 30,
    packet_count: int = 0,
) -> int:
    """Capture authorized live traffic and pass supported packets to ``handler``."""
    _, _, _, _, sniff = _load_scapy()
    processed = 0

    def on_packet(packet) -> None:
        nonlocal processed
        event = packet_to_event(packet)
        if event is not None:
            processed += 1
            handler(event)

    sniff(
        iface=interface,
        prn=on_packet,
        store=False,
        timeout=timeout,
        count=max(0, packet_count),
    )
    return processed
