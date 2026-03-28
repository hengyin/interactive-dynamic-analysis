from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ExecutionState:
    session_status: str = "not_started"
    backend: str | None = None
    launched_qemu_user_path: str | None = None
    instrumentation_rpc_socket_path: str | None = None
    rpc_protocol_version: int | None = None
    rpc_capabilities: dict[str, bool] = field(default_factory=dict)
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
    last_rpc_method: str | None = None
    last_rpc_timeout: float | None = None
    last_rpc_params: dict[str, Any] = field(default_factory=dict)
    last_rpc_status: str | None = None
    last_rpc_error: str | None = None
    rpc_history: list[dict[str, Any]] = field(default_factory=list)
    last_stop_transition: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_status": self.session_status,
            "backend": self.backend,
            "launched_qemu_user_path": self.launched_qemu_user_path,
            "instrumentation_rpc_socket_path": self.instrumentation_rpc_socket_path,
            "rpc_protocol_version": self.rpc_protocol_version,
            "rpc_capabilities": dict(self.rpc_capabilities),
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
            "last_rpc_method": self.last_rpc_method,
            "last_rpc_timeout": self.last_rpc_timeout,
            "last_rpc_params": dict(self.last_rpc_params),
            "last_rpc_status": self.last_rpc_status,
            "last_rpc_error": self.last_rpc_error,
            "rpc_history": list(self.rpc_history),
            "last_stop_transition": dict(self.last_stop_transition),
        }
