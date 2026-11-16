from __future__ import annotations

import binascii
import re
from typing import Any

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, IPv6, TCP, UDP, Ether

from .models import PacketRecord


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace")
        except Exception:
            return ""
    return str(value)


def _extract_http_details(packet: Any) -> dict[str, Any]:
    if TCP not in packet:
        return {}

    payload = bytes(packet[TCP].payload)
    if not payload:
        return {}

    text = payload.decode("latin-1", errors="replace")
    if not text:
        return {}

    headers = text.split("\r\n\r\n", 1)
    head = headers[0]
    request_line = head.split("\r\n", 1)[0]
    if not request_line:
        return {}

    if request_line.startswith("HTTP/"):
        match = re.match(r"HTTP/(?P<version>\d\.\d)\s+(?P<status>\d{3})\s*(?P<reason>.*)", request_line)
        if match:
            return {
                "message": match.group(0),
                "status": int(match.group("status")),
                "reason": match.group("reason").strip(),
                "version": match.group("version"),
            }
        return {"message": request_line}

    parts = request_line.split()
    if len(parts) >= 3:
        method, path, version = parts[:3]
        header_dict = {}
        for header_line in head.split("\r\n")[1:]:
            if ":" in header_line:
                key, value = header_line.split(":", 1)
                header_dict[key.strip().lower()] = value.strip()
        return {
            "method": method,
            "path": path,
            "version": version,
            "host": header_dict.get("host", ""),
            "user_agent": header_dict.get("user-agent", ""),
        }

    return {"message": request_line}


def _extract_dns_details(packet: Any) -> dict[str, Any]:
    if DNS not in packet:
        return {}

    dns = packet[DNS]
    qname = ""
    if DNSQR in packet:
        qname = _safe_text(packet[DNSQR].qname).rstrip(".")

    details: dict[str, Any] = {
        "id": int(dns.id),
        "qr": int(getattr(dns, "qr", 0)),
        "opcode": int(getattr(dns, "opcode", 0)),
        "qname": qname,
    }
    if getattr(dns, "ancount", 0):
        answers = []
        answers_list = getattr(dns, "an", []) if hasattr(dns, "an") else []
        for answer in answers_list:
            answers.append(_safe_text(getattr(answer, "rrname", "")))
        if answers:
            details["answers"] = answers
    return details


def _extract_tls_details(packet: Any) -> dict[str, Any]:
    if TCP not in packet:
        return {}

    payload = bytes(packet[TCP].payload)
    if len(payload) < 6 or payload[0] != 0x16 or payload[1] != 0x03:
        return {}

    version = f"0x{payload[1]:02x}{payload[2]:02x}"
    handshake_type = payload[5]
    record_type = payload[0]
    details = {
        "record_type": record_type,
        "version": version,
        "handshake_type": handshake_type,
    }

    if handshake_type == 1:
        details["handshake"] = "ClientHello"
    elif handshake_type == 2:
        details["handshake"] = "ServerHello"
    else:
        details["handshake"] = f"Type {handshake_type}"

    return details


def _packet_info(packet: Any) -> str:
    if DNS in packet:
        dns = packet[DNS]
        qname_text = ""
        if DNSQR in packet:
            qname_text = _safe_text(packet[DNSQR].qname)
        if qname_text:
            qname_text = qname_text.rstrip(".")
            return f"Standard query 0x{dns.id:x} A {qname_text}"
        return f"DNS response 0x{dns.id:x}"
    if TCP in packet:
        tcp = packet[TCP]
        payload = bytes(tcp.payload)
        if payload:
            text = payload.decode("latin-1", errors="replace")
            if text.startswith("GET ") or text.startswith("POST ") or text.startswith("PUT ") or text.startswith("DELETE ") or text.startswith("HEAD ") or text.startswith("OPTIONS "):
                first_line = text.split("\r\n", 1)[0]
                return first_line
            if text.startswith("HTTP/"):
                first_line = text.split("\r\n", 1)[0]
                return first_line
            if payload.startswith(b"\x16\x03"):
                return "TLS handshake"
        flags = tcp.flags
        return f"{tcp.sport} → {tcp.dport} [{flags}] Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window} Len={len(tcp.payload) or 0}"
    if UDP in packet:
        udp = packet[UDP]
        return f"{udp.sport} → {udp.dport} Len={len(udp.payload) or 0}"
    if ICMP in packet:
        return "Echo request"
    if ARP in packet:
        arp = packet[ARP]
        if arp.op == 1:
            return f"Who has {arp.pdst}? Tell {arp.psrc}"
        return f"{arp.psrc} is at {arp.hwsrc}"
    if IP in packet:
        ip = packet[IP]
        return f"IP {ip.src} → {ip.dst}"
    if IPv6 in packet:
        ip = packet[IPv6]
        return f"IPv6 {ip.src} → {ip.dst}"
    return "Packet"


def _protocol_details(packet: Any) -> dict[str, Any]:
    details: dict[str, Any] = {}
    if DNS in packet:
        details["dns"] = _extract_dns_details(packet)
    if TCP in packet:
        payload = bytes(packet[TCP].payload)
        if payload and payload.startswith(b"\x16\x03"):
            details["tls"] = _extract_tls_details(packet)
        http_details = _extract_http_details(packet)
        if http_details:
            details["http"] = http_details
    return details


def decode_packet(raw: bytes, timestamp: float, interface: str | None, packet_id: int) -> PacketRecord:
    try:
        packet = Ether(raw)
    except Exception as exc:  # pragma: no cover - defensive guard
        return PacketRecord(
            id=packet_id,
            timestamp=timestamp,
            src="malformed",
            dst="malformed",
            protocol="Malformed",
            transport="OTHER",
            length=len(raw),
            info=f"Malformed packet: {exc}",
            flow_key=None,
            layers=[{"name": "Malformed", "fields": [{"name": "error", "value": str(exc)}]}],
            raw_hex=binascii.hexlify(raw).decode("ascii"),
        )

    src = packet[Ether].src if Ether in packet else "unknown"
    dst = packet[Ether].dst if Ether in packet else "unknown"
    protocol = "OTHER"
    transport = None
    src_port = None
    dst_port = None
    flow_key = None

    if IP in packet:
        ip = packet[IP]
        src = ip.src
        dst = ip.dst
        protocol = "IPv4"
        if TCP in packet:
            protocol = "TCP"
            transport = "TCP"
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
            flow_key = f"{ip.src}:{src_port}->{ip.dst}:{dst_port}"
        elif UDP in packet:
            protocol = "UDP"
            transport = "UDP"
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)
            flow_key = f"{ip.src}:{src_port}->{ip.dst}:{dst_port}"
        elif ICMP in packet:
            protocol = "ICMP"
            transport = "ICMP"
            flow_key = f"{ip.src}->{ip.dst}"
    elif IPv6 in packet:
        ip = packet[IPv6]
        src = ip.src
        dst = ip.dst
        protocol = "IPv6"
        if TCP in packet:
            transport = "TCP"
            protocol = "TCP"
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
            flow_key = f"{ip.src}:{src_port}->{ip.dst}:{dst_port}"
        elif UDP in packet:
            transport = "UDP"
            protocol = "UDP"
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)
            flow_key = f"{ip.src}:{src_port}->{ip.dst}:{dst_port}"
        elif ICMP in packet:
            transport = "ICMPv6"
            protocol = "ICMP"
            flow_key = f"{ip.src}->{ip.dst}"
    elif ARP in packet:
        protocol = "ARP"
        flow_key = f"{packet[ARP].psrc}->{packet[ARP].pdst}"

    info = _packet_info(packet)
    layers = [{"name": "Ethernet", "fields": [{"name": "src", "value": src}, {"name": "dst", "value": dst}]}]
    if IP in packet:
        layers.append({"name": "IPv4", "fields": [{"name": "src", "value": packet[IP].src}, {"name": "dst", "value": packet[IP].dst}]})
    if IPv6 in packet:
        layers.append({"name": "IPv6", "fields": [{"name": "src", "value": packet[IPv6].src}, {"name": "dst", "value": packet[IPv6].dst}]})
    if TCP in packet:
        layers.append({"name": "TCP", "fields": [{"name": "src_port", "value": packet[TCP].sport}, {"name": "dst_port", "value": packet[TCP].dport}]})
    if UDP in packet:
        layers.append({"name": "UDP", "fields": [{"name": "src_port", "value": packet[UDP].sport}, {"name": "dst_port", "value": packet[UDP].dport}]})
    if DNS in packet:
        qname = packet[DNSQR].qname if DNSQR in packet else ""
        qname_text = _safe_text(qname).rstrip(".")
        layers.append({"name": "DNS", "fields": [{"name": "qname", "value": qname_text}]})

    return PacketRecord(
        id=packet_id,
        timestamp=timestamp,
        src=src,
        dst=dst,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        transport=transport,
        length=len(raw),
        info=info,
        flow_key=flow_key,
        details=_protocol_details(packet),
        layers=layers,
        raw_hex=binascii.hexlify(raw).decode("ascii"),
    )
