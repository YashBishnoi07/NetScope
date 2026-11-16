from __future__ import annotations

from collections import defaultdict
from typing import Any


class DetectorEngine:
    def __init__(self) -> None:
        self.port_hits: dict[str, set[int]] = defaultdict(set)
        self.syn_counts: dict[str, list[float]] = defaultdict(list)
        self.icmp_counts: dict[str, list[float]] = defaultdict(list)
        self.arp_seen: dict[str, str] = {}
        self.dns_tunnel_count: dict[str, int] = defaultdict(int)

    def analyze(self, packet: dict[str, Any]) -> list[dict[str, Any]]:
        alerts: list[dict[str, Any]] = []
        src = packet.get("src", "")
        dst = packet.get("dst", "")
        protocol = packet.get("protocol", "")

        if protocol == "TCP" and packet.get("dst_port") is not None:
            self.port_hits[src].add(int(packet["dst_port"]))
            if len(self.port_hits[src]) >= 3:
                alerts.append({
                    "id": len(alerts) + 1,
                    "timestamp": packet["timestamp"],
                    "severity": "medium",
                    "type": "port_scan",
                    "message": f"Possible port scan from {src}",
                    "src": src,
                    "dst": dst,
                })

        if protocol == "TCP" and packet.get("info", "").startswith("SYN"):
            self.syn_counts[dst].append(float(packet["timestamp"]))
            recent = [t for t in self.syn_counts[dst] if packet["timestamp"] - t < 2.0]
            self.syn_counts[dst] = recent
            if len(recent) >= 20:
                alerts.append({
                    "id": len(alerts) + 1,
                    "timestamp": packet["timestamp"],
                    "severity": "high",
                    "type": "syn_flood",
                    "message": f"SYN flood pattern against {dst}",
                    "src": src,
                    "dst": dst,
                })

        if protocol == "ICMP":
            self.icmp_counts[dst].append(float(packet["timestamp"]))
            recent = [t for t in self.icmp_counts[dst] if packet["timestamp"] - t < 1.0]
            self.icmp_counts[dst] = recent
            if len(recent) >= 15:
                alerts.append({
                    "id": len(alerts) + 1,
                    "timestamp": packet["timestamp"],
                    "severity": "high",
                    "type": "icmp_flood",
                    "message": f"ICMP flood detected against {dst}",
                    "src": src,
                    "dst": dst,
                })

        if protocol == "ARP":
            key = packet.get("flow_key", "")
            if key and packet.get("src", ""):
                prior = self.arp_seen.get(packet.get("dst", ""))
                if prior and prior != packet.get("src"):
                    alerts.append({
                        "id": len(alerts) + 1,
                        "timestamp": packet["timestamp"],
                        "severity": "critical",
                        "type": "arp_spoofing",
                        "message": f"ARP spoofing suspected for {packet.get('dst')}",
                        "src": src,
                        "dst": dst,
                    })
                self.arp_seen[packet.get("dst", "")] = packet.get("src", "")

        if protocol == "DNS":
            domain = packet.get("info", "").split()[-1] if packet.get("info") else ""
            if domain and len(domain) > 25:
                self.dns_tunnel_count[domain] += 1
                if self.dns_tunnel_count[domain] >= 2:
                    alerts.append({
                        "id": len(alerts) + 1,
                        "timestamp": packet["timestamp"],
                        "severity": "medium",
                        "type": "dns_tunneling",
                        "message": f"DNS tunneling-like behavior for {domain}",
                        "src": src,
                        "dst": dst,
                    })

        return alerts
