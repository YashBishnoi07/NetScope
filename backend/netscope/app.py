from __future__ import annotations

import asyncio
import time
from collections import Counter
from typing import Any

from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, Response, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel
from scapy.all import get_if_list, rdpcap

from .aggregator import PacketAggregator
from .config import get_settings
from .database import DatabaseRepository
from .decoder import decode_packet
from .detector import DetectorEngine
from .filters import sanitize_bpf_filter
from .flow import FlowTracker
from .models import AlertItem, PacketPage, StatsOverview
from .services import service_name
from .sessions import SessionManager
from .simulator import capture_packets

settings = get_settings()
app = FastAPI(title="NetScope")
cors_origins = [origin.strip() for origin in settings.cors_origins.split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1):(\d+)",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

runtime = {
    "state": "idle",
    "source": "simulator",
    "interface": None,
    "uploaded_pcap_path": None,
    "packets_seen": 0,
    "packets_per_second": 0.0,
    "queue_depth": 0,
    "drops": 0,
    "started_at": None,
    "alerts": [],
    "packets": [],
    "overview": StatsOverview(),
    "websockets": [],
    "simulator_task": None,
    "active_session_id": None,
    "filter": "",
    "last_error": None,
}

aggregator = PacketAggregator(max_packets=settings.packet_buffer_size)
detector = DetectorEngine()
flow_tracker = FlowTracker()
database = DatabaseRepository()
session_manager = SessionManager()


class CaptureStartRequest(BaseModel):
    source: str = "simulator"
    interface: str | None = None
    bpf_filter: str | None = None
    speed: float = 1.0
    scenarios: list[str] | None = None


async def _broadcast_loop() -> None:
    while True:
        await asyncio.sleep(0.5)
        if runtime["state"] != "running":
            continue
        snapshot = {
            "type": "stats",
            "data": {
                "status": runtime["state"],
                "packets_seen": runtime["packets_seen"],
                "packets_per_second": runtime["packets_per_second"],
                "overview": runtime["overview"].model_dump(),
            },
        }
        for ws in runtime.get("websockets", []):
            try:
                await ws.send_json(snapshot)
            except Exception:
                pass


async def _record_host_activity(packet: dict[str, Any]) -> None:
    for host in (packet.get("src"), packet.get("dst")):
        if not host:
            continue
        base = await database.upsert_host(host, {
            "host": host,
            "first_seen": min(float(packet.get("timestamp", time.time())), float(packet.get("timestamp", time.time()))),
            "last_seen": float(packet.get("timestamp", time.time())),
            "packet_count": 1,
            "bytes_total": int(packet.get("length", 0)),
            "protocols": {packet.get("protocol", "OTHER"): 1},
        })
        base["packet_count"] = int(base.get("packet_count", 0)) + 1
        base["bytes_total"] = int(base.get("bytes_total", 0)) + int(packet.get("length", 0))
        base["last_seen"] = float(packet.get("timestamp", time.time()))
        protocols = dict(base.get("protocols", {}))
        protocol = packet.get("protocol", "OTHER")
        protocols[protocol] = int(protocols.get(protocol, 0)) + 1
        base["protocols"] = protocols
        await database.upsert_host(host, base)


def _prune_alerts() -> None:
    retention_hours = max(1, int(getattr(settings, "alert_retention_hours", 24)))
    retention_seconds = retention_hours * 3600
    cutoff = time.time() - retention_seconds
    runtime["alerts"] = [alert for alert in runtime["alerts"] if float(alert.get("timestamp", 0)) >= cutoff]
    if len(runtime["alerts"]) > int(getattr(settings, "capture_queue_limit", 500)):
        runtime["alerts"] = runtime["alerts"][-int(getattr(settings, "capture_queue_limit", 500)):]


def _filtered_packets(window_hours: float | None = None) -> list[Any]:
    packets = list(aggregator.buffer)
    if window_hours is None:
        return packets
    cutoff = time.time() - max(0.0, float(window_hours)) * 3600
    return [packet for packet in packets if float(packet.timestamp) >= cutoff]


def _protocol_insights(window_hours: float | None = None) -> dict[str, Any]:
    packets = _filtered_packets(window_hours)
    dns_queries = 0
    dns_responses = 0
    dns_domains: Counter[str] = Counter()
    http_requests = 0
    http_responses = 0
    http_paths: Counter[str] = Counter()
    tls_handshakes = 0
    tls_versions: Counter[str] = Counter()

    for packet in packets:
        details = packet.details or {}
        dns_details = details.get("dns") or {}
        if dns_details:
            if int(dns_details.get("qr", 0)) == 0:
                dns_queries += 1
            else:
                dns_responses += 1
            qname = dns_details.get("qname")
            if qname:
                dns_domains[qname] += 1

        http_details = details.get("http") or {}
        if http_details:
            if "method" in http_details:
                http_requests += 1
                path = http_details.get("path")
                if path:
                    http_paths[path] += 1
            elif "status" in http_details:
                http_responses += 1

        tls_details = details.get("tls") or {}
        if tls_details:
            tls_handshakes += 1
            version = tls_details.get("version")
            if version:
                tls_versions[str(version)] += 1

    return {
        "dns": {
            "queries": dns_queries,
            "responses": dns_responses,
            "top_domains": [
                {"domain": domain, "count": count}
                for domain, count in dns_domains.most_common(5)
            ],
        },
        "http": {
            "requests": http_requests,
            "responses": http_responses,
            "tls_handshakes": tls_handshakes,
            "top_paths": [
                {"path": path, "count": count}
                for path, count in http_paths.most_common(5)
            ],
            "top_tls_versions": [
                {"version": version, "count": count}
                for version, count in tls_versions.most_common(5)
            ],
        },
    }


async def _run_simulator() -> None:
    runtime["state"] = "running"
    runtime["started_at"] = time.time()
    packet_id = max(1, len(runtime["packets"]) + 1)
    try:
        while runtime["state"] == "running":
            try:
                packets = capture_packets(
                    source=runtime["source"],
                    interface=runtime.get("interface") or None,
                    count=8,
                    bpf_filter=runtime.get("filter") or None,
                )
            except ValueError as exc:
                runtime["state"] = "idle"
                runtime["last_error"] = str(exc)
                break

            for item in packets:
                packet = decode_packet(item["raw"], item["timestamp"], item["interface"], packet_id)
                packet_dump = packet.model_dump()
                aggregator.record(packet)
                flow_tracker.update(packet_dump)
                runtime["packets_seen"] += 1
                runtime["packets"].append(packet_dump)
                runtime["packets"] = runtime["packets"][-500:]
                runtime["overview"] = aggregator.overview()
                runtime["overview"].packet_rate = max(0.0, runtime["packets_seen"] / max(1.0, time.time() - runtime["started_at"]))
                runtime["overview"].bandwidth_bps = max(0.0, aggregator.total_bytes / max(1.0, time.time() - runtime["started_at"]))
                await _record_host_activity(packet_dump)

                for alert in detector.analyze(packet_dump):
                    alert_payload = {
                        "id": len(runtime["alerts"]) + 1,
                        "timestamp": time.time(),
                        "severity": alert["severity"],
                        "type": alert["type"],
                        "message": alert["message"],
                        "src": alert["src"],
                        "dst": alert["dst"],
                    }
                    runtime["alerts"].append(alert_payload)
                    _prune_alerts()
                    asyncio.create_task(database.add_alert(alert_payload))
                packet_id += 1
            await asyncio.sleep(0.5)
            runtime["packets_per_second"] = max(0.0, runtime["packets_seen"] / max(1.0, time.time() - runtime["started_at"]))
    except asyncio.CancelledError:
        runtime["state"] = "idle"
        raise
    finally:
        runtime["simulator_task"] = None


@app.on_event("startup")
async def startup_event() -> None:
    runtime["websockets"] = []
    runtime["alerts"] = await database.list_alerts(20)
    stored_settings = await database.get_settings()
    for key, value in stored_settings.items():
        if hasattr(settings, key):
            setattr(settings, key, value)
    asyncio.create_task(_broadcast_loop())


@app.get("/api/v1/health")
async def health() -> dict[str, Any]:
    return {"ok": True, "status": runtime["state"], "uptime": time.time() - (runtime["started_at"] or time.time())}


@app.get("/api/v1/interfaces")
async def interfaces() -> list[str]:
    candidates = []
    try:
        candidates = [iface for iface in get_if_list() if iface]
    except Exception:
        candidates = []

    extras = ["simulator", "demo_capture.pcap"]
    ordered = []
    for iface in candidates + extras:
        if iface not in ordered:
            ordered.append(iface)
    return ordered or ["eth0", "lo", "wlan0", "simulator", "demo_capture.pcap"]


@app.get("/api/v1/pcap/demo")
async def demo_pcap_path() -> dict[str, Any]:
    return {"path": "data/demo_capture.pcap", "source": "pcap"}


@app.post("/api/v1/capture/upload-pcap")
async def upload_pcap(file: UploadFile = File(...)) -> dict[str, Any]:
    if file.filename is None or not file.filename.lower().endswith(".pcap"):
        raise HTTPException(status_code=400, detail="Please upload a .pcap file")

    upload_dir = Path(__file__).resolve().parent.parent / "data" / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    saved_name = f"{uuid4().hex}_{file.filename}"
    saved_path = upload_dir / saved_name
    payload = await file.read()
    saved_path.write_bytes(payload)

    try:
        rdpcap(str(saved_path))
    except Exception as exc:
        saved_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail=f"Invalid PCAP file: {exc}") from exc

    runtime["uploaded_pcap_path"] = str(saved_path)
    runtime["source"] = "pcap"
    runtime["interface"] = str(saved_path)
    return {"ok": True, "filename": file.filename, "path": str(saved_path), "source": "pcap"}


@app.get("/api/v1/capture/status")
async def capture_status() -> dict[str, Any]:
    return {
        "state": runtime["state"],
        "source": runtime["source"],
        "packets_seen": runtime["packets_seen"],
        "packets_per_second": runtime["packets_per_second"],
        "queue_depth": runtime["queue_depth"],
        "drops": runtime["drops"],
        "started_at": runtime["started_at"],
        "last_error": runtime.get("last_error"),
        "interface": runtime.get("interface"),
    }


@app.post("/api/v1/capture/start")
async def capture_start(payload: CaptureStartRequest) -> dict[str, Any]:
    if runtime["state"] == "running":
        return {"ok": True, "state": runtime["state"], "session_id": runtime.get("active_session_id")}

    try:
        runtime["filter"] = sanitize_bpf_filter(payload.bpf_filter)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    runtime["last_error"] = None
    source_name = (payload.source or "simulator").lower()
    if source_name in {"live", "interface", "nic", "network"}:
        source_name = "live"

    if source_name == "pcap" and not payload.interface:
        payload.interface = runtime.get("uploaded_pcap_path") or "data/demo_capture.pcap"

    if source_name == "live":
        available_interfaces = [iface for iface in get_if_list() if iface]
        selected_interface = payload.interface or settings.default_interface or (available_interfaces[0] if available_interfaces else "simulator")
        if selected_interface in {"simulator", "demo_capture.pcap"}:
            selected_interface = "simulator"
        elif available_interfaces and selected_interface not in available_interfaces:
            raise HTTPException(
                status_code=400,
                detail=f"Interface '{selected_interface}' is not available. Choose one of: {', '.join(available_interfaces)}",
            )
        elif not available_interfaces:
            raise HTTPException(status_code=400, detail="No live network interfaces are available for capture on this host.")

    runtime["state"] = "running"
    runtime["source"] = source_name
    runtime["interface"] = payload.interface or settings.default_interface or ("simulator" if source_name == "simulator" else "demo_capture.pcap")
    if source_name == "live":
        runtime["interface"] = payload.interface or settings.default_interface or (get_if_list()[0] if get_if_list() else "simulator")
    runtime["started_at"] = time.time()
    session = session_manager.create(source=runtime["source"], interface=runtime["interface"])
    session.state = "running"
    session.started_at = runtime["started_at"]
    session.counters = {"packets_seen": 0}
    runtime["active_session_id"] = session.session_id
    runtime["simulator_task"] = asyncio.create_task(_run_simulator())
    return {"ok": True, "state": runtime["state"], "source": runtime["source"], "session_id": session.session_id}


@app.post("/api/v1/capture/stop")
async def capture_stop() -> dict[str, Any]:
    runtime["state"] = "idle"
    task = runtime.get("simulator_task")
    if task is not None and not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    runtime["simulator_task"] = None
    if runtime.get("active_session_id"):
        session = session_manager.get(runtime["active_session_id"])
        if session is not None:
            session.state = "stopped"
    for session in session_manager.active_sessions.values():
        if session.state != "stopped":
            session.state = "stopped"
    runtime["active_session_id"] = None
    return {"ok": True, "state": runtime["state"]}


@app.post("/api/v1/capture/pause")
async def capture_pause() -> dict[str, Any]:
    runtime["state"] = "paused"
    if runtime.get("active_session_id"):
        session = session_manager.get(runtime["active_session_id"])
        if session is not None:
            session.state = "paused"
    return {"ok": True, "state": runtime["state"]}


@app.post("/api/v1/capture/resume")
async def capture_resume() -> dict[str, Any]:
    if runtime["state"] in {"idle", "paused"} and (runtime.get("simulator_task") is None or runtime["simulator_task"].done()):
        runtime["state"] = "running"
        runtime["started_at"] = time.time()
        runtime["simulator_task"] = asyncio.create_task(_run_simulator())
    else:
        runtime["state"] = "running"
    if runtime.get("active_session_id"):
        session = session_manager.get(runtime["active_session_id"])
        if session is not None:
            session.state = "running"
    return {"ok": True, "state": runtime["state"]}


@app.get("/api/v1/stats/overview")
async def stats_overview() -> StatsOverview:
    return runtime["overview"]


@app.get("/api/v1/stats/protocols")
async def stats_protocols() -> dict[str, float]:
    return aggregator.protocol_distribution()


@app.get("/api/v1/stats/protocol-activity")
async def stats_protocol_activity(window_hours: float | None = None) -> list[dict[str, Any]]:
    packets = _filtered_packets(window_hours)
    counts: Counter[str] = Counter()
    bytes_by_protocol: Counter[str] = Counter()
    for packet in packets:
        counts[packet.protocol] += 1
        bytes_by_protocol[packet.protocol] += int(packet.length or 0)

    rows = []
    for protocol, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        rows.append({
            "protocol": protocol,
            "count": count,
            "bytes": int(bytes_by_protocol.get(protocol, 0)),
        })
    return rows


@app.get("/api/v1/stats/bandwidth")
async def stats_bandwidth(window_hours: float | None = None) -> list[dict[str, float]]:
    packets = _filtered_packets(window_hours)
    if not packets:
        return [{"time": idx, "bytes": 0.0} for idx in range(10)]

    now = time.time()
    points = 10
    buckets: dict[int, int] = {idx: 0 for idx in range(points)}
    if window_hours is None:
        window_seconds = max(1, 10)
    else:
        window_seconds = max(1, int(float(window_hours) * 3600))

    for packet in packets:
        elapsed = max(0, now - float(packet.timestamp))
        index = min(points - 1, int((elapsed / max(1, window_seconds / points))))
        buckets[index] = buckets.get(index, 0) + int(packet.length or 0)

    return [{"time": idx, "bytes": float(buckets[idx])} for idx in range(points)]


@app.get("/api/v1/stats/ports")
async def stats_ports(window_hours: float | None = None) -> list[dict[str, Any]]:
    port_data: dict[int, int] = {}
    for packet in _filtered_packets(window_hours):
        if packet.src_port is not None:
            port_data[packet.src_port] = port_data.get(packet.src_port, 0) + 1
        if packet.dst_port is not None:
            port_data[packet.dst_port] = port_data.get(packet.dst_port, 0) + 1

    entries = []
    for port, count in sorted(port_data.items(), key=lambda item: (-item[1], item[0]))[:10]:
        entries.append({"port": port, "count": count, "service": service_name(port)})
    return entries


@app.get("/api/v1/stats/dns")
async def stats_dns(window_hours: float | None = None) -> dict[str, Any]:
    return _protocol_insights(window_hours)["dns"]


@app.get("/api/v1/stats/http")
async def stats_http(window_hours: float | None = None) -> dict[str, Any]:
    return _protocol_insights(window_hours)["http"]


@app.get("/api/v1/stats/alerts")
async def stats_alerts(window_hours: float | None = None) -> dict[str, Any]:
    recent = await database.list_alerts(100)
    items = recent if recent else runtime["alerts"][-100:]
    if window_hours is not None:
        cutoff = time.time() - max(0.0, float(window_hours)) * 3600
        items = [item for item in items if float(item.get("timestamp", 0)) >= cutoff]
    by_severity = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for item in items:
        severity = str(item.get("severity", "low")).lower()
        if severity in by_severity:
            by_severity[severity] += 1

    timeline: list[dict[str, int | str]] = []
    if items:
        now = time.time()
        window = max(1.0, float(window_hours or 12.0))
        start = now - (window * 3600)
        for index in range(12):
            bucket_start = start + (index * (window * 3600 / 12))
            bucket_end = bucket_start + (window * 3600 / 12)
            count = sum(
                1
                for item in items
                if float(item.get("timestamp", 0)) >= bucket_start and float(item.get("timestamp", 0)) < bucket_end
            )
            timeline.append({
                "bucket": time.strftime("%H:%M", time.localtime(bucket_start)),
                "count": count,
            })

    return {
        "by_severity": by_severity,
        "timeline": timeline,
    }


@app.get("/api/v1/packets")
async def packets(limit: int = 20, cursor: int | None = None, search: str | None = None, protocol: str | None = None) -> PacketPage:
    items = aggregator.buffer if cursor is None else [p for p in aggregator.buffer if p.id > cursor]
    normalized_search = (search or "").strip().lower()
    filtered = []
    for packet in items:
        if normalized_search:
            haystack = " ".join([
                packet.src,
                packet.dst,
                str(packet.src_port or ""),
                str(packet.dst_port or ""),
                packet.protocol,
                packet.info,
            ]).lower()
            if normalized_search not in haystack:
                continue
        if protocol and packet.protocol.upper() != protocol.upper():
            continue
        filtered.append(packet)
    payload = list(filtered)[-limit:]
    return PacketPage(items=[packet.model_dump() for packet in payload], next_cursor=payload[-1].id if payload else None)


@app.get("/api/v1/history")
async def history(limit: int = 10) -> list[dict[str, Any]]:
    records = []
    for packet in list(aggregator.buffer)[-limit:]:
        records.append({
            "id": packet.id,
            "timestamp": packet.timestamp,
            "src": packet.src,
            "dst": packet.dst,
            "protocol": packet.protocol,
            "info": packet.info,
            "length": packet.length,
        })
    return records


@app.get("/api/v1/export/packets", response_model=None)
async def export_packets(format: str = "json") -> Response:
    packets = [packet.model_dump() for packet in aggregator.buffer]
    normalized = (format or "json").lower()

    if normalized == "csv":
        import csv
        import io

        fieldnames = [
            "id", "timestamp", "src", "dst", "src_port", "dst_port",
            "protocol", "transport", "length", "info", "flow_key"
        ]
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=fieldnames)
        writer.writeheader()
        for packet in packets:
            row = {field: packet.get(field, "") for field in fieldnames}
            writer.writerow(row)
        return PlainTextResponse(
            content=buffer.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=netScope_packets.csv"},
        )

    return JSONResponse(content=packets, headers={"Content-Disposition": "attachment; filename=netScope_packets.json"})


@app.get("/api/v1/packets/{packet_id}")
async def packet_detail(packet_id: int) -> dict[str, Any]:
    for packet in reversed(aggregator.buffer):
        if packet.id == packet_id:
            return packet.model_dump()
    raise HTTPException(status_code=404, detail=f"Packet {packet_id} not found")


@app.get("/api/v1/alerts")
async def alerts(severity: str | None = None) -> list[AlertItem]:
    _prune_alerts()
    recent = await database.list_alerts(20)
    items = recent if recent else runtime["alerts"][-20:]
    normalized = (severity or settings.alert_severity_filter or "all").lower()
    if normalized == "all":
        return [AlertItem(**item) for item in items]
    return [AlertItem(**item) for item in items if (item.get("severity") or "").lower() == normalized]


@app.post("/api/v1/alerts/clear")
async def clear_alerts() -> dict[str, Any]:
    runtime["alerts"].clear()
    await database.clear_alerts()
    return {"ok": True, "cleared": True}


@app.get("/api/v1/hosts")
async def hosts() -> list[dict[str, Any]]:
    records = await database.list_hosts()
    if records:
        return records
    return [{"host": host, "packet_count": 0, "bytes_total": 0, "protocols": {}} for host in sorted(aggregator.hosts)]


@app.get("/api/v1/stats/hosts")
async def stats_hosts() -> list[dict[str, Any]]:
    records = await database.list_hosts()
    host_map: dict[str, dict[str, Any]] = {}
    for record in records:
        host = str(record.get("host") or "").strip()
        if not host:
            continue
        aggregate = host_map.setdefault(host, {
            "host": host,
            "packet_count": 0,
            "bytes_total": 0,
            "protocols": {},
        })
        aggregate["packet_count"] = int(aggregate.get("packet_count", 0)) + int(record.get("packet_count", 0))
        aggregate["bytes_total"] = int(aggregate.get("bytes_total", 0)) + int(record.get("bytes_total", 0))
        for protocol, count in (record.get("protocols") or {}).items():
            aggregate["protocols"][str(protocol)] = int(aggregate["protocols"].get(str(protocol), 0)) + int(count)

    for packet in aggregator.buffer:
        for host in (packet.src, packet.dst):
            if not host:
                continue
            aggregate = host_map.setdefault(host, {"host": host, "packet_count": 0, "bytes_total": 0, "protocols": {}})
            aggregate["packet_count"] = int(aggregate.get("packet_count", 0)) + 1
            aggregate["bytes_total"] = int(aggregate.get("bytes_total", 0)) + int(packet.length)
            protocol_name = str(packet.protocol)
            aggregate["protocols"][protocol_name] = int(aggregate["protocols"].get(protocol_name, 0)) + 1

    return sorted(
        host_map.values(),
        key=lambda item: (-int(item.get("packet_count", 0)), -int(item.get("bytes_total", 0)), str(item.get("host", ""))),
    )[:10]


@app.get("/api/v1/stats/top-talkers")
async def stats_top_talkers(window_hours: float | None = None) -> list[dict[str, Any]]:
    talkers: dict[str, dict[str, Any]] = {}
    packets = _filtered_packets(window_hours)
    for packet in packets:
        for host in (packet.src, packet.dst):
            if not host:
                continue
            current = talkers.setdefault(host, {"host": host, "packets": 0, "bytes": 0})
            current["packets"] = int(current.get("packets", 0)) + 1
            current["bytes"] = int(current.get("bytes", 0)) + int(packet.length or 0)

    return sorted(
        talkers.values(),
        key=lambda item: (-int(item.get("packets", 0)), -int(item.get("bytes", 0)), str(item.get("host", ""))),
    )[:8]


@app.get("/api/v1/stats/threats")
async def stats_threats(window_hours: float | None = None) -> dict[str, Any]:
    items = await database.list_alerts(100)
    if not items:
        items = runtime["alerts"][-100:]
    if window_hours is not None:
        cutoff = time.time() - max(0.0, float(window_hours)) * 3600
        items = [item for item in items if float(item.get("timestamp", 0)) >= cutoff]

    by_type: dict[str, int] = {}
    by_source: dict[str, int] = {}
    for item in items:
        alert_type = str(item.get("type") or "other").lower()
        source = str(item.get("src") or "unknown")
        by_type[alert_type] = int(by_type.get(alert_type, 0)) + 1
        by_source[source] = int(by_source.get(source, 0)) + 1

    ranked_sources = [
        {"source": source, "count": count}
        for source, count in sorted(by_source.items(), key=lambda entry: (-entry[1], entry[0]))[:5]
    ]
    return {
        "by_type": by_type,
        "top_sources": ranked_sources,
        "total": len(items),
    }


@app.get("/api/v1/stats/suspicious-sources")
async def stats_suspicious_sources(window_hours: float | None = None) -> list[dict[str, Any]]:
    items = await database.list_alerts(100)
    if not items:
        items = runtime["alerts"][-100:]
    if window_hours is not None:
        cutoff = time.time() - max(0.0, float(window_hours)) * 3600
        items = [item for item in items if float(item.get("timestamp", 0)) >= cutoff]

    severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    by_source: dict[str, dict[str, Any]] = {}
    for item in items:
        source = str(item.get("src") or "unknown").strip()
        if not source:
            continue
        record = by_source.setdefault(source, {"source": source, "count": 0, "severity": "low"})
        record["count"] = int(record.get("count", 0)) + 1
        current = str(item.get("severity") or "low").lower()
        if severity_rank.get(current, 0) > severity_rank.get(str(record.get("severity") or "low").lower(), 0):
            record["severity"] = current

    return [
        {
            "source": source,
            "count": record["count"],
            "severity": record["severity"],
        }
        for source, record in sorted(
            by_source.items(),
            key=lambda entry: (-int(entry[1]["count"]), -severity_rank.get(str(entry[1]["severity"]).lower(), 0), entry[0]),
        )[:6]
    ]


@app.get("/api/v1/stats/suspicious-destinations")
async def stats_suspicious_destinations(window_hours: float | None = None) -> list[dict[str, Any]]:
    items = await database.list_alerts(100)
    if not items:
        items = runtime["alerts"][-100:]
    if window_hours is not None:
        cutoff = time.time() - max(0.0, float(window_hours)) * 3600
        items = [item for item in items if float(item.get("timestamp", 0)) >= cutoff]

    severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    by_destination: dict[str, dict[str, Any]] = {}
    for item in items:
        destination = str(item.get("dst") or "unknown").strip()
        if not destination:
            continue
        record = by_destination.setdefault(destination, {"destination": destination, "count": 0, "severity": "low"})
        record["count"] = int(record.get("count", 0)) + 1
        current = str(item.get("severity") or "low").lower()
        if severity_rank.get(current, 0) > severity_rank.get(str(record.get("severity") or "low").lower(), 0):
            record["severity"] = current

    return [
        {
            "destination": destination,
            "count": record["count"],
            "severity": record["severity"],
        }
        for destination, record in sorted(
            by_destination.items(),
            key=lambda entry: (-int(entry[1]["count"]), -severity_rank.get(str(entry[1]["severity"]).lower(), 0), entry[0]),
        )[:6]
    ]


@app.get("/api/v1/sessions")
async def sessions() -> list[dict[str, Any]]:
    return [session.to_dict() for session in session_manager.active_sessions.values()]


@app.post("/api/v1/filters/validate")
async def validate_filter(payload: dict[str, str]) -> dict[str, Any]:
    filter_value = payload.get("filter") or payload.get("bpf_filter") or ""
    try:
        cleaned = sanitize_bpf_filter(filter_value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"valid": True, "value": cleaned}


@app.get("/api/v1/flows")
async def flows() -> list[dict[str, Any]]:
    return [flow.to_dict() for flow in flow_tracker.flows.values()]


@app.get("/api/v1/flows/{flow_key}")
async def flow_detail(flow_key: str) -> dict[str, Any]:
    flow = flow_tracker.flows.get(flow_key)
    if flow is None:
        raise HTTPException(status_code=404, detail=f"Flow {flow_key} not found")
    return flow.to_dict()


@app.websocket("/api/v1/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await websocket.accept()
    runtime["websockets"].append(websocket)
    try:
        await websocket.send_json({
            "type": "snapshot",
            "data": {
                "status": runtime["state"],
                "overview": runtime["overview"].model_dump(),
                "alerts": runtime["alerts"][-5:],
            },
        })
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in runtime["websockets"]:
            runtime["websockets"].remove(websocket)


@app.get("/api/v1/settings")
async def settings_route() -> dict[str, Any]:
    persisted = await database.get_settings()
    return {
        "detector_port_scan_threshold": persisted.get("detector_port_scan_threshold", settings.detector_port_scan_threshold),
        "detector_syn_flood_threshold": persisted.get("detector_syn_flood_threshold", settings.detector_syn_flood_threshold),
        "detector_arp_spoof_threshold": persisted.get("detector_arp_spoof_threshold", settings.detector_arp_spoof_threshold),
        "detector_icmp_flood_threshold": persisted.get("detector_icmp_flood_threshold", settings.detector_icmp_flood_threshold),
        "detector_dns_tunnel_threshold": persisted.get("detector_dns_tunnel_threshold", settings.detector_dns_tunnel_threshold),
        "alert_severity_filter": persisted.get("alert_severity_filter", settings.alert_severity_filter),
        "alert_retention_hours": persisted.get("alert_retention_hours", settings.alert_retention_hours),
        "capture_queue_limit": persisted.get("capture_queue_limit", settings.capture_queue_limit),
    }


@app.post("/api/v1/settings")
async def update_settings(payload: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "detector_port_scan_threshold",
        "detector_syn_flood_threshold",
        "detector_arp_spoof_threshold",
        "detector_icmp_flood_threshold",
        "detector_dns_tunnel_threshold",
        "alert_severity_filter",
        "alert_retention_hours",
        "capture_queue_limit",
    }
    updates = {key: value for key, value in payload.items() if key in allowed}
    if updates:
        await database.save_settings(updates)
        for key, value in updates.items():
            if hasattr(settings, key):
                setattr(settings, key, value)
    return {"ok": True, **updates}


@app.get("/")
async def base() -> dict[str, str]:
    return {"message": "NetScope API"}
