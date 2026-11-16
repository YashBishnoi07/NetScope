from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class FlowRecord:
    key: str
    src: str
    dst: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = "OTHER"
    packets: int = 0
    bytes_total: int = 0
    duration: float = 0.0
    last_seen: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "src": self.src,
            "dst": self.dst,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packets": self.packets,
            "bytes_total": self.bytes_total,
            "duration": self.duration,
            "last_seen": self.last_seen,
        }


class FlowTracker:
    def __init__(self) -> None:
        self.flows: dict[str, FlowRecord] = {}

    def update(self, packet: dict[str, Any]) -> FlowRecord:
        key = packet.get("flow_key") or f"{packet.get('src')}->{packet.get('dst')}"
        flow = self.flows.get(key)
        if flow is None:
            flow = FlowRecord(
                key=key,
                src=packet.get("src", ""),
                dst=packet.get("dst", ""),
                src_port=packet.get("src_port"),
                dst_port=packet.get("dst_port"),
                protocol=packet.get("protocol", "OTHER"),
            )
            self.flows[key] = flow
        flow.packets += 1
        flow.bytes_total += int(packet.get("length", 0))
        flow.last_seen = float(packet.get("timestamp", 0.0))
        flow.duration = max(flow.duration, flow.last_seen)
        return flow
