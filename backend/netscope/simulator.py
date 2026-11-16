from __future__ import annotations

import random
import time
from pathlib import Path
from typing import Any

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, get_if_list, rdpcap, sniff


def _resolve_pcap_path(path: str | None) -> Path:
    if not path:
        return (Path(__file__).resolve().parent.parent / "data" / "demo_capture.pcap").resolve()
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = (Path(__file__).resolve().parent.parent / candidate).resolve()
    return candidate


def _pcap_packets(path: str | None, count: int | None = None, bpf_filter: str | None = None) -> list[dict[str, Any]]:
    pcap_path = _resolve_pcap_path(path)
    if not pcap_path.exists():
        return generate_synthetic_packets(count=count or 8)

    packets: list[dict[str, Any]] = []
    pcap_packets = rdpcap(str(pcap_path))
    if count is not None:
        pcap_packets = pcap_packets[:count]

    for index, packet in enumerate(pcap_packets):
        raw = bytes(packet)
        src = getattr(packet[IP], "src", "unknown") if IP in packet else getattr(packet, "src", "unknown")
        dst = getattr(packet[IP], "dst", "unknown") if IP in packet else getattr(packet, "dst", "unknown")
        src_port = None
        dst_port = None
        if TCP in packet:
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
        elif UDP in packet:
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)
        packets.append({
            "raw": raw,
            "timestamp": time.time() + index * 0.1,
            "interface": str(pcap_path),
            "protocol": "TCP" if TCP in packet else "UDP" if UDP in packet else "HTTP" if IP in packet else "LIVE",
            "src": src,
            "dst": dst,
            "src_port": src_port,
            "dst_port": dst_port,
            "length": len(raw),
            "info": "replayed pcap packet",
            "flow_key": None,
        })
    if not packets:
        return generate_synthetic_packets(count=count or 8)
    return packets


def capture_packets(source: str = "simulator", interface: str | None = None, count: int = 8, bpf_filter: str | None = None) -> list[dict[str, Any]]:
    source_name = (source or "simulator").lower()
    if source_name in {"simulator", "synthetic", "demo"}:
        return generate_synthetic_packets(count=count)
    if source_name in {"pcap", "replay", "file"}:
        return _pcap_packets(interface, count=count, bpf_filter=bpf_filter)

    iface = interface or "eth0"
    if iface in {"simulator", "demo_capture.pcap"}:
        return generate_synthetic_packets(count=count)
    available_interfaces = [item for item in get_if_list() if item]
    if not available_interfaces:
        raise ValueError("No live network interfaces are available for capture on this host.")
    if iface not in available_interfaces:
        raise ValueError(f"Interface '{iface}' is not available. Choose one of: {', '.join(available_interfaces)}")

    try:
        packets = sniff(iface=iface, count=count, timeout=1, filter=bpf_filter or None, store=1)
        if not packets:
            return generate_synthetic_packets(count=count)
        return [{
            "raw": bytes(packet),
            "timestamp": time.time(),
            "interface": iface,
            "protocol": "LIVE",
            "src": getattr(packet, "src", "unknown"),
            "dst": getattr(packet, "dst", "unknown"),
            "length": len(packet),
            "info": "captured live packet",
        } for packet in packets]
    except Exception as exc:
        raise ValueError(f"Live capture failed for interface '{iface}': {exc}") from exc


def generate_synthetic_packets(count: int = 25) -> list[dict[str, Any]]:
    packets: list[dict[str, Any]] = []
    for i in range(count):
        if i % 8 == 0:
            packet = Ether()/IP(src="10.0.0.5", dst="10.0.0.10")/TCP(sport=54321, dport=443, flags="S")
            packets.append({
                "raw": bytes(packet),
                "timestamp": time.time() + i * 0.1,
                "interface": "simulator",
                "protocol": "TCP",
                "src": "10.0.0.5",
                "dst": "10.0.0.10",
                "src_port": 54321,
                "dst_port": 443,
                "info": "SYN",
                "length": len(packet),
                "flow_key": "10.0.0.5:54321->10.0.0.10:443",
            })
        elif i % 8 == 1:
            packet = Ether()/IP(src="10.0.0.20", dst="10.0.0.11")/ICMP(type=8, id=100, seq=1)/b"ping"
            packets.append({
                "raw": bytes(packet),
                "timestamp": time.time() + i * 0.1,
                "interface": "simulator",
                "protocol": "ICMP",
                "src": "10.0.0.20",
                "dst": "10.0.0.11",
                "length": len(packet),
                "info": "Echo request",
                "flow_key": "10.0.0.20->10.0.0.11",
            })
        elif i % 8 == 2:
            packet = Ether()/IP(src="10.0.0.30", dst="10.0.0.99")/UDP(sport=5353, dport=53)/DNS(id=0x1122, qr=0, qd=DNSQR(qname="verylongsubdomain" + ".".join(["x"] * 8) + ".example.com", qtype="A"))
            packets.append({
                "raw": bytes(packet),
                "timestamp": time.time() + i * 0.1,
                "interface": "simulator",
                "protocol": "DNS",
                "src": "10.0.0.30",
                "dst": "10.0.0.99",
                "src_port": 5353,
                "dst_port": 53,
                "info": f"Standard query 0x1122 A {packet[DNSQR].qname.decode()}",
                "length": len(packet),
                "flow_key": "10.0.0.30:5353->10.0.0.99:53",
            })
        elif i % 8 == 3:
            packet = Ether()/ARP(op=2, hwsrc="aa:bb:cc:dd:ee:ff", psrc="10.0.0.8", hwdst="00:11:22:33:44:55", pdst="10.0.0.9")
            packets.append({
                "raw": bytes(packet),
                "timestamp": time.time() + i * 0.1,
                "interface": "simulator",
                "protocol": "ARP",
                "src": "10.0.0.8",
                "dst": "10.0.0.9",
                "length": len(packet),
                "info": "ARP reply",
                "flow_key": "10.0.0.8->10.0.0.9",
            })
        else:
            host_a = random.choice(["10.0.0.1", "10.0.0.2", "10.0.0.3"])
            host_b = random.choice(["10.0.0.10", "10.0.0.11", "10.0.0.12"])
            packet = Ether()/IP(src=host_a, dst=host_b)/TCP(sport=50000 + i, dport=80, flags="PA")/b"GET / HTTP/1.1\r\nHost: demo.local\r\n\r\n"
            packets.append({
                "raw": bytes(packet),
                "timestamp": time.time() + i * 0.1,
                "interface": "simulator",
                "protocol": "HTTP",
                "src": host_a,
                "dst": host_b,
                "src_port": 50000 + i,
                "dst_port": 80,
                "info": "GET / HTTP/1.1",
                "length": len(packet),
                "flow_key": f"{host_a}:{50000 + i}->{host_b}:80",
            })
    return packets
