from __future__ import annotations

import time
from collections import Counter, defaultdict, deque
from typing import Any

from .models import PacketRecord, StatsOverview


class PacketAggregator:
    def __init__(self, max_packets: int = 20000) -> None:
        self.max_packets = max_packets
        self.buffer: deque[PacketRecord] = deque(maxlen=max_packets)
        self.protocol_counts: Counter[str] = Counter()
        self.protocol_bytes: Counter[str] = Counter()
        self.hosts: set[str] = set()
        self.flows: dict[str, dict[str, Any]] = defaultdict(dict)
        self.total_packets = 0
        self.total_bytes = 0
        self.dropped_packets = 0

    def record(self, packet: PacketRecord) -> None:
        self.buffer.append(packet)
        self.total_packets += 1
        self.total_bytes += packet.length
        self.protocol_counts[packet.protocol] += 1
        self.protocol_bytes[packet.protocol] += packet.length
        self.hosts.add(packet.src)
        self.hosts.add(packet.dst)

        if packet.flow_key:
            flow = self.flows.setdefault(packet.flow_key, {"packets": 0, "bytes": 0, "duration": 0.0})
            flow["packets"] = int(flow.get("packets", 0)) + 1
            flow["bytes"] = int(flow.get("bytes", 0)) + packet.length
            flow["duration"] = max(float(flow.get("duration", 0.0)), float(packet.timestamp))

    def protocol_distribution(self) -> dict[str, float]:
        total = sum(self.protocol_counts.values())
        if total == 0:
            return {}
        return {protocol: count / total for protocol, count in sorted(self.protocol_counts.items())}

    def protocol_activity(self) -> list[dict[str, Any]]:
        if not self.protocol_counts:
            return []

        rows = []
        for protocol, count in sorted(self.protocol_counts.items(), key=lambda item: (-item[1], item[0])):
            rows.append({
                "protocol": protocol,
                "count": count,
                "bytes": int(self.protocol_bytes.get(protocol, 0)),
            })
        return rows

    def bandwidth_series(self, points: int = 10, window_seconds: int = 10) -> list[dict[str, float]]:
        if not self.buffer:
            return [{"time": idx, "bytes": 0.0} for idx in range(points)]

        now = time.time()
        buckets: dict[int, int] = {idx: 0 for idx in range(points)}
        for packet in self.buffer:
            bucket_index = int((now - packet.timestamp) / max(1, window_seconds / points))
            bucket_index = max(0, min(points - 1, bucket_index))
            buckets[bucket_index] = buckets.get(bucket_index, 0) + packet.length

        return [{"time": idx, "bytes": float(buckets[idx])} for idx in range(points)]

    def overview(self) -> StatsOverview:
        return StatsOverview(
            packets_total=self.total_packets,
            bytes_total=self.total_bytes,
            packet_rate=0.0,
            bandwidth_bps=0.0,
            active_flows=len(self.flows),
            unique_hosts=len(self.hosts),
            alerts_last_hour=0,
            dropped_packets=self.dropped_packets,
        )

    def recent_packets(self, limit: int = 50) -> list[dict[str, Any]]:
        items = list(self.buffer)[-limit:]
        return [
            {
                "id": packet.id,
                "timestamp": packet.timestamp,
                "src": packet.src,
                "dst": packet.dst,
                "src_port": packet.src_port,
                "dst_port": packet.dst_port,
                "protocol": packet.protocol,
                "transport": packet.transport,
                "length": packet.length,
                "info": packet.info,
                "flow_key": packet.flow_key,
            }
            for packet in items
        ]


PacketSummary = dict[str, Any]
