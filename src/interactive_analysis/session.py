from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .annotations import Annotation
from .backends.base import BackendAdapter
from .errors import InvalidStateError
from .snapshot import Snapshot
from .state import ExecutionState


@dataclass(slots=True)
class SessionConfig:
    backend_name: str = "qemu_user_instrumented"
    max_recent_events: int = 1024
    max_trace_entries: int = 4096
    max_memory_read: int = 256
    max_disassembly_instructions: int = 64


@dataclass(slots=True)
class AnalysisSession:
    backend: BackendAdapter
    config: SessionConfig = field(default_factory=SessionConfig)
    state: ExecutionState = field(default_factory=ExecutionState)
    snapshots: dict[str, Snapshot] = field(default_factory=dict)
    annotations: dict[str, list[Annotation]] = field(default_factory=dict)

    def start(
        self,
        target: str,
        args: list[str] | None = None,
        cwd: str | None = None,
        qemu_config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self.state.session_status not in {"not_started", "closed"}:
            raise InvalidStateError("session already started")
        call_args = list(args or [])
        self.backend.start(target=target, args=call_args, cwd=cwd, qemu_config=qemu_config)
        self.state.session_status = "idle"
        self.state.backend = self.config.backend_name
        self.state.target = target
        self.state.args = call_args
        self.state.cwd = cwd
        self.state.capabilities = self.backend.capabilities()
        return self._response("start", {"target": target})

    def resume(self, timeout: float = 5.0) -> dict[str, Any]:
        return self._forward("resume", self.backend.resume(timeout))

    def pause(self, timeout: float = 5.0) -> dict[str, Any]:
        return self._forward("pause", self.backend.pause(timeout))

    def run_until_event(self, event_types: list[str], timeout: float = 5.0) -> dict[str, Any]:
        return self._forward("run_until_event", self.backend.run_until_event(event_types, timeout))

    def run_until_address(self, address: str, timeout: float = 5.0) -> dict[str, Any]:
        return self._forward("run_until_address", self.backend.run_until_address(address, timeout))

    def step(self, count: int = 1, timeout: float = 5.0) -> dict[str, Any]:
        return self._forward("step", self.backend.step(count, timeout))

    def advance_basic_blocks(self, count: int = 1, timeout: float = 5.0) -> dict[str, Any]:
        return self._forward("advance_basic_blocks", self.backend.advance_basic_blocks(count, timeout))

    def get_registers(self, names: list[str] | None = None) -> dict[str, Any]:
        return self._forward("get_registers", self.backend.get_registers(names))

    def read_memory(self, address: str, size: int) -> dict[str, Any]:
        if size > self.config.max_memory_read:
            raise InvalidStateError(f"memory read exceeds max of {self.config.max_memory_read} bytes")
        return self._forward("read_memory", self.backend.read_memory(address, size))

    def disassemble(self, address: str, count: int = 16) -> dict[str, Any]:
        if count > self.config.max_disassembly_instructions:
            raise InvalidStateError(
                f"disassembly request exceeds max of {self.config.max_disassembly_instructions} instructions"
            )
        return self._forward("disassemble", self.backend.disassemble(address, count))

    def list_memory_maps(self) -> dict[str, Any]:
        return self._forward("list_memory_maps", self.backend.list_memory_maps())

    def take_snapshot(self, name: str | None = None) -> dict[str, Any]:
        response = self._forward("take_snapshot", self.backend.take_snapshot(name))
        snapshot_result = response["result"]
        snapshot = Snapshot(
            snapshot_id=snapshot_result["snapshot_id"],
            name=snapshot_result.get("name"),
            created_at=float(snapshot_result["created_at"]),
            pc=snapshot_result.get("pc"),
            thread_id=snapshot_result.get("thread_id"),
            event_id=snapshot_result.get("event_id"),
            metadata=dict(snapshot_result.get("metadata") or {}),
        )
        self.snapshots[snapshot.snapshot_id] = snapshot
        self.state.last_snapshot_id = snapshot.snapshot_id
        return response

    def restore_snapshot(self, snapshot_id: str) -> dict[str, Any]:
        return self._forward("restore_snapshot", self.backend.restore_snapshot(snapshot_id))

    def diff_snapshots(self, left_id: str, right_id: str) -> dict[str, Any]:
        return self._forward("diff_snapshots", self.backend.diff_snapshots(left_id, right_id))

    def get_recent_events(
        self,
        limit: int = 100,
        event_types: list[str] | None = None,
    ) -> dict[str, Any]:
        return self._forward("get_recent_events", self.backend.get_recent_events(limit, event_types))

    def get_trace(self, limit: int = 100) -> dict[str, Any]:
        return self._forward("get_trace", self.backend.get_trace(limit))

    def annotate(
        self,
        address: str,
        note: str,
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        annotation = Annotation(
            annotation_id=f"a-{sum(len(items) for items in self.annotations.values()) + 1}",
            address=address,
            note=note,
            tags=list(tags or []),
        )
        self.annotations.setdefault(address, []).append(annotation)
        return self._response("annotate", annotation.to_dict())

    def list_annotations(self, address: str | None = None) -> dict[str, Any]:
        if address is None:
            values = [item.to_dict() for items in self.annotations.values() for item in items]
        else:
            values = [item.to_dict() for item in self.annotations.get(address, [])]
        return self._response("list_annotations", {"annotations": values})

    def get_state(self) -> dict[str, Any]:
        self.state.capabilities = self.backend.capabilities()
        backend_state = self.backend.get_state()
        self._merge_state(backend_state)
        return self._response("get_state", self.state.to_dict())

    def capabilities(self) -> dict[str, Any]:
        return self._response("capabilities", {"capabilities": self.backend.capabilities()})

    def close(self) -> dict[str, Any]:
        self.backend.close()
        self.state.session_status = "closed"
        return self._response("close", {})

    def _forward(self, command: str, payload: dict[str, Any]) -> dict[str, Any]:
        self._merge_state(payload.get("state") or {})
        return self._response(command, payload.get("result") or {})

    def _merge_state(self, payload: dict[str, Any]) -> None:
        for key, value in payload.items():
            if hasattr(self.state, key):
                setattr(self.state, key, value)

    def _response(self, command: str, result: dict[str, Any]) -> dict[str, Any]:
        return {
            "ok": True,
            "command": command,
            "state": self.state.to_dict(),
            "result": result,
        }
