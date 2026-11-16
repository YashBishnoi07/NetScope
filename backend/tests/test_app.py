import time
from pathlib import Path

from fastapi.testclient import TestClient

from netscope.app import aggregator, app, flow_tracker
from netscope.models import PacketRecord

client = TestClient(app)


def test_health_endpoint() -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["ok"] is True


def test_capture_status() -> None:
    response = client.get("/api/v1/capture/status")
    assert response.status_code == 200
    assert "state" in response.json()


def test_capture_start_rejects_invalid_live_interface() -> None:
    response = client.post("/api/v1/capture/start", json={"source": "live", "interface": "definitely_not_real"})
    assert response.status_code == 400
    assert "not available" in response.json()["detail"]


def test_capture_start_and_stop() -> None:
    start = client.post("/api/v1/capture/start", json={"source": "simulator"})
    assert start.status_code == 200
    assert start.json()["state"] == "running"

    stop = client.post("/api/v1/capture/stop")
    assert stop.status_code == 200
    assert stop.json()["state"] == "idle"

    live_start = client.post("/api/v1/capture/start", json={"source": "live", "interface": "simulator"})
    assert live_start.status_code == 200
    assert live_start.json()["source"] == "live"
    client.post("/api/v1/capture/stop")


def test_interface_list_endpoint() -> None:
    response = client.get("/api/v1/interfaces")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
    assert response.json()


def test_validate_filter_endpoint() -> None:
    response = client.post("/api/v1/filters/validate", json={"filter": "tcp and port 443"})
    assert response.status_code == 200
    assert response.json()["valid"] is True

    invalid = client.post("/api/v1/filters/validate", json={"filter": "tcp && exec"})
    assert invalid.status_code == 400


def test_packet_search_and_history_endpoints() -> None:
    aggregator.buffer.clear()
    packet = PacketRecord(
        id=7,
        timestamp=1700000100.0,
        src="10.0.0.9",
        dst="10.0.0.18",
        src_port=1111,
        dst_port=80,
        protocol="TCP",
        transport="TCP",
        length=128,
        info="GET /",
        flow_key="10.0.0.9:1111->10.0.0.18:80",
    )
    aggregator.buffer.append(packet)

    search = client.get("/api/v1/packets", params={"search": "10.0.0.9", "limit": 10})
    assert search.status_code == 200
    assert search.json()["items"][0]["src"] == "10.0.0.9"

    history = client.get("/api/v1/history", params={"limit": 5})
    assert history.status_code == 200
    assert isinstance(history.json(), list)


def test_upload_pcap_endpoint() -> None:
    pcap_path = Path(__file__).resolve().parent.parent / "data" / "demo_capture.pcap"
    with pcap_path.open("rb") as handle:
        response = client.post("/api/v1/capture/upload-pcap", files={"file": ("demo_capture.pcap", handle.read(), "application/vnd.tcpdump.pcap")})
    assert response.status_code == 200
    assert response.json()["source"] == "pcap"
    assert response.json()["path"].endswith(".pcap")


def test_protocol_stats_endpoints() -> None:
    aggregator.buffer.clear()
    dnstest = PacketRecord(
        id=11,
        timestamp=1700000400.0,
        src="10.0.0.9",
        dst="8.8.8.8",
        src_port=1111,
        dst_port=53,
        protocol="UDP",
        transport="UDP",
        length=64,
        info="Standard query A example.com",
        flow_key="10.0.0.9:1111->8.8.8.8:53",
        details={"dns": {"qr": 0, "qname": "example.com"}},
    )
    httptest = PacketRecord(
        id=12,
        timestamp=1700000401.0,
        src="10.0.0.4",
        dst="10.0.0.5",
        src_port=50000,
        dst_port=80,
        protocol="TCP",
        transport="TCP",
        length=256,
        info="GET /",
        flow_key="10.0.0.4:50000->10.0.0.5:80",
        details={"http": {"method": "GET", "path": "/", "host": "example.com"}},
    )
    tls_test = PacketRecord(
        id=13,
        timestamp=1700000402.0,
        src="10.0.0.5",
        dst="10.0.0.4",
        src_port=443,
        dst_port=50000,
        protocol="TCP",
        transport="TCP",
        length=256,
        info="TLS handshake",
        flow_key="10.0.0.5:443->10.0.0.4:50000",
        details={"tls": {"version": "0x0301", "handshake": "ClientHello"}},
    )
    aggregator.buffer.extend([dnstest, httptest, tls_test])

    dns_response = client.get("/api/v1/stats/dns")
    assert dns_response.status_code == 200
    assert dns_response.json()["queries"] == 1

    http_response = client.get("/api/v1/stats/http")
    assert http_response.status_code == 200
    assert http_response.json()["requests"] == 1
    assert http_response.json()["tls_handshakes"] == 1


def test_settings_persistence() -> None:
    response = client.post(
        "/api/v1/settings",
        json={"detector_port_scan_threshold": 12, "detector_syn_flood_threshold": 16},
    )
    assert response.status_code == 200
    assert response.json()["detector_port_scan_threshold"] == 12

    persisted = client.get("/api/v1/settings")
    assert persisted.status_code == 200
    assert persisted.json()["detector_port_scan_threshold"] == 12


def test_packet_export_endpoints() -> None:
    aggregator.buffer.clear()
    aggregator.buffer.append(
        PacketRecord(
            id=99,
            timestamp=1700000500.0,
            src="10.0.0.20",
            dst="10.0.0.21",
            src_port=40000,
            dst_port=443,
            protocol="TCP",
            transport="TCP",
            length=120,
            info="EXPORT TEST",
            flow_key="10.0.0.20:40000->10.0.0.21:443",
        )
    )

    json_response = client.get("/api/v1/export/packets", params={"format": "json"})
    assert json_response.status_code == 200
    assert isinstance(json_response.json(), list)
    assert json_response.json()[0]["src"] == "10.0.0.20"

    csv_response = client.get("/api/v1/export/packets", params={"format": "csv"})
    assert csv_response.status_code == 200
    assert "src,dst" in csv_response.text
    assert "10.0.0.20" in csv_response.text


def test_alert_summary_endpoint() -> None:
    response = client.get("/api/v1/stats/alerts")
    assert response.status_code == 200
    data = response.json()
    assert "by_severity" in data
    assert "timeline" in data
    assert isinstance(data["timeline"], list)


def test_host_summary_endpoint() -> None:
    response = client.get("/api/v1/stats/hosts")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
    if response.json():
        assert "host" in response.json()[0]


def test_top_talkers_endpoint() -> None:
    aggregator.buffer.clear()
    aggregator.buffer.extend([
        PacketRecord(
            id=101,
            timestamp=1700000600.0,
            src="10.0.0.15",
            dst="10.0.0.16",
            src_port=50000,
            dst_port=80,
            protocol="TCP",
            transport="TCP",
            length=128,
            info="GET /",
            flow_key="10.0.0.15:50000->10.0.0.16:80",
        ),
        PacketRecord(
            id=102,
            timestamp=1700000601.0,
            src="10.0.0.16",
            dst="10.0.0.15",
            src_port=80,
            dst_port=50000,
            protocol="TCP",
            transport="TCP",
            length=256,
            info="HTTP 200",
            flow_key="10.0.0.16:80->10.0.0.15:50000",
        ),
    ])

    response = client.get("/api/v1/stats/top-talkers")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert any(item["host"] == "10.0.0.15" for item in data)
    assert any(item["host"] == "10.0.0.16" for item in data)


def test_suspicious_sources_endpoint() -> None:
    response = client.get("/api/v1/stats/suspicious-sources")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_suspicious_destinations_endpoint() -> None:
    client.post(
        "/api/v1/alerts/clear",
    )
    client.post(
        "/api/v1/alerts/clear",
    )
    response = client.get("/api/v1/stats/suspicious-destinations")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_threat_summary_endpoint() -> None:
    response = client.get("/api/v1/stats/threats")
    assert response.status_code == 200
    data = response.json()
    assert "by_type" in data
    assert "top_sources" in data
    assert "total" in data


def test_protocol_activity_endpoint() -> None:
    response = client.get("/api/v1/stats/protocol-activity")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    if data:
        assert "protocol" in data[0]
        assert "count" in data[0]


def test_time_window_filtering() -> None:
    aggregator.buffer.clear()
    now = time.time()
    aggregator.buffer.extend([
        PacketRecord(
            id=201,
            timestamp=now - 60,
            src="10.0.0.40",
            dst="10.0.0.41",
            src_port=1111,
            dst_port=80,
            protocol="TCP",
            transport="TCP",
            length=64,
            info="window test 1",
            flow_key="10.0.0.40:1111->10.0.0.41:80",
        ),
        PacketRecord(
            id=202,
            timestamp=now - 6 * 3600,
            src="10.0.0.42",
            dst="10.0.0.41",
            src_port=1112,
            dst_port=80,
            protocol="TCP",
            transport="TCP",
            length=32,
            info="window test 2",
            flow_key="10.0.0.42:1112->10.0.0.41:80",
        ),
    ])

    response = client.get("/api/v1/stats/protocol-activity", params={"window_hours": 2})
    assert response.status_code == 200
    payload = response.json()
    assert payload and payload[0]["count"] == 1


def test_port_summary_endpoint() -> None:
    response = client.get("/api/v1/stats/ports")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_alert_clear_endpoint() -> None:
    client.post("/api/v1/alerts/clear")
    response = client.get("/api/v1/alerts")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_packet_detail_and_flow_detail_endpoints() -> None:
    aggregator.buffer.clear()
    flow_tracker.flows.clear()

    packet = PacketRecord(
        id=1,
        timestamp=1700000000.0,
        src="10.0.0.5",
        dst="10.0.0.10",
        src_port=1234,
        dst_port=443,
        protocol="TCP",
        transport="TCP",
        length=128,
        info="SYN",
        flow_key="10.0.0.5:1234->10.0.0.10:443",
    )
    aggregator.buffer.append(packet)
    flow_tracker.flows[packet.flow_key] = type('FlowStub', (), {'to_dict': lambda self: {'key': packet.flow_key, 'src': packet.src, 'dst': packet.dst, 'packets': 1}})()

    packet_response = client.get("/api/v1/packets/1")
    assert packet_response.status_code == 200
    assert packet_response.json()["id"] == 1

    flow_response = client.get("/api/v1/flows/10.0.0.5:1234->10.0.0.10:443")
    assert flow_response.status_code == 200
    assert flow_response.json()["key"] == "10.0.0.5:1234->10.0.0.10:443"
