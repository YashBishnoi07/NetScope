from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CaptureSession:
    session_id: str
    source: str = "simulator"
    interface: str | None = None
    state: str = "idle"
    started_at: float | None = None
    counters: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "source": self.source,
            "interface": self.interface,
            "state": self.state,
            "started_at": self.started_at,
            "counters": self.counters,
        }


class SessionManager:
    def __init__(self) -> None:
        self.active_sessions: dict[str, CaptureSession] = {}

    def create(self, *, source: str, interface: str | None = None) -> CaptureSession:
        session = CaptureSession(session_id=f"session-{len(self.active_sessions) + 1}", source=source, interface=interface)
        self.active_sessions[session.session_id] = session
        return session

    def get(self, session_id: str) -> CaptureSession | None:
        return self.active_sessions.get(session_id)

    def stop(self, session_id: str) -> CaptureSession | None:
        session = self.active_sessions.get(session_id)
        if session is not None:
            session.state = "stopped"
        return session
