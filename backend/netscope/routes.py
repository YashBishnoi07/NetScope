from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from .app import aggregator, runtime

router = APIRouter(prefix="/api/v1")


@router.get("/stats/overview")
async def stats_overview() -> dict[str, Any]:
    return {
        "packets_total": aggregator.total_packets,
        "bytes_total": aggregator.total_bytes,
        "packet_rate": runtime["packets_per_second"],
        "bandwidth_bps": runtime["overview"].bandwidth_bps,
        "active_flows": len(aggregator.flows),
        "unique_hosts": len(aggregator.hosts),
        "alerts_last_hour": len(runtime["alerts"]),
        "dropped_packets": aggregator.dropped_packets,
    }
