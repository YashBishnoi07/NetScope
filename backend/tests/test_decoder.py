from scapy.all import DNS, DNSQR, IP, Raw, TCP, UDP, Ether

from netscope.decoder import decode_packet


def test_decode_tcp_packet() -> None:
    packet = Ether() / IP(src="10.0.0.5", dst="10.0.0.10") / TCP(sport=54321, dport=443, flags="S", seq=1, ack=0)
    decoded = decode_packet(bytes(packet), 1710000000.0, "eth0", 1)
    assert decoded.protocol == "TCP"
    assert decoded.src == "10.0.0.5"
    assert decoded.dst == "10.0.0.10"
    assert decoded.src_port == 54321
    assert decoded.dst_port == 443
    assert "Seq=1" in decoded.info


def test_decode_dns_packet() -> None:
    packet = Ether() / IP(src="10.0.0.2", dst="8.8.8.8") / UDP(sport=50000, dport=53) / DNS(id=0x1234, qr=0, qd=DNSQR(qname="example.com", qtype="A"))
    decoded = decode_packet(bytes(packet), 1710000001.0, "eth0", 2)
    assert decoded.protocol == "UDP"
    assert decoded.dst_port == 53
    assert "example.com" in decoded.info


def test_decode_http_packet_metadata() -> None:
    payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: NetScope\r\n\r\n"
    packet = Ether() / IP(src="10.0.0.3", dst="10.0.0.4") / TCP(sport=50000, dport=80, flags="PA", seq=7, ack=0) / Raw(load=payload)
    decoded = decode_packet(bytes(packet), 1710000002.0, "eth0", 3)
    assert decoded.protocol == "TCP"
    assert decoded.details["http"]["method"] == "GET"
    assert decoded.details["http"]["host"] == "example.com"


def test_decode_tls_packet_metadata() -> None:
    tls_payload = b"\x16\x03\x01\x00\x20\x01\x00\x00\x1c\x03\x01\x00\x18\x00\x00\x00\x00"
    packet = Ether() / IP(src="10.0.0.5", dst="10.0.0.6") / TCP(sport=49152, dport=443, flags="PA", seq=10, ack=0) / Raw(load=tls_payload)
    decoded = decode_packet(bytes(packet), 1710000003.0, "eth0", 4)
    assert decoded.protocol == "TCP"
    assert decoded.details["tls"]["handshake"] == "ClientHello"


def test_decode_malformed_packet() -> None:
    decoded = decode_packet(b"\x00\x01\x02\x03garbage", 1710000004.0, "eth0", 5)
    assert decoded.protocol == "Malformed"
    assert "Malformed packet" in decoded.info
