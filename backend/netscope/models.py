from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class PacketSummary(BaseModel):
    id: int
    timestamp: float
    src: str
    dst: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = "OTHER"
    transport: str | None = None
    length: int = 0
    info: str = ""
    flow_key: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class PacketRecord(PacketSummary):
    layers: list[dict[str, Any]] = Field(default_factory=list)
    raw_hex: str = ""


class AlertItem(BaseModel):
    id: int
    timestamp: float
    severity: str
    type: str
    message: str
    src: str | None = None
    dst: str | None = None


class StatsOverview(BaseModel):
    packets_total: int = 0
    bytes_total: int = 0
    packet_rate: float = 0.0
    bandwidth_bps: float = 0.0
    active_flows: int = 0
    unique_hosts: int = 0
    alerts_last_hour: int = 0
    dropped_packets: int = 0


class CaptureStatus(BaseModel):
    state: str = "idle"
    source: str = "simulator"
    packets_seen: int = 0
    packets_per_second: float = 0.0
    queue_depth: int = 0
    drops: int = 0
    started_at: float | None = None


class PacketPage(BaseModel):
    items: list[PacketSummary]
    next_cursor: int | None = None


class AlertPage(BaseModel):
    items: list[AlertItem]
    next_cursor: int | None = None
