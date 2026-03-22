from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ExecutionState:
    session_status: str = "not_started"
    backend: str | None = None
    target: str | None = None
    args: list[str] = field(default_factory=list)
    cwd: str | None = None
    stop_reason: str | None = None
    exit_code: int | None = None
    exit_signal: str | None = None
    pc: str | None = None
    current_thread_id: str | None = None
    registers: dict[str, str] = field(default_factory=dict)
    memory_maps: list[dict[str, Any]] = field(default_factory=list)
    last_snapshot_id: str | None = None
    last_event_id: str | None = None
    trace_head: int = 0
    capabilities: dict[str, bool] = field(default_factory=dict)
    recent_events: list[dict[str, Any]] = field(default_factory=list)
    ingestion_stats: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_status": self.session_status,
            "backend": self.backend,
            "target": self.target,
            "args": list(self.args),
            "cwd": self.cwd,
            "stop_reason": self.stop_reason,
            "exit_code": self.exit_code,
            "exit_signal": self.exit_signal,
            "pc": self.pc,
            "current_thread_id": self.current_thread_id,
            "registers": dict(self.registers),
            "memory_maps": list(self.memory_maps),
            "last_snapshot_id": self.last_snapshot_id,
            "last_event_id": self.last_event_id,
            "trace_head": self.trace_head,
            "capabilities": dict(self.capabilities),
            "recent_events": list(self.recent_events),
            "ingestion_stats": dict(self.ingestion_stats),
        }
