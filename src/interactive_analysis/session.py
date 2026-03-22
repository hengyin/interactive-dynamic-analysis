from __future__ import annotations

import subprocess
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
    breakpoints: list[int] = field(default_factory=list)

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
        self._merge_state(self.backend.get_state())
        return self._response("start", {"target": target})

    def resume(self, timeout: float = 5.0) -> dict[str, Any]:
        return self._forward("resume", self.backend.resume(timeout))

    def pause(self, timeout: float = 5.0) -> dict[str, Any]:
        if self.state.session_status in {"not_started", "closed"}:
            raise InvalidStateError("session is not started")
        if self.state.session_status in {"idle", "paused"}:
            self.state.session_status = "paused"
            return self._response("pause", {"status": "paused", "noop": True})
        return self._forward("pause", self.backend.pause(timeout))

    def run_until_event(self, event_types: list[str], timeout: float = 5.0) -> dict[str, Any]:
        return self._forward("run_until_event", self.backend.run_until_event(event_types, timeout))

    def run_until_address(self, address: str, timeout: float = 5.0) -> dict[str, Any]:
        return self._forward("run_until_address", self.backend.run_until_address(address, timeout))

    def step(self, count: int = 1, timeout: float = 5.0) -> dict[str, Any]:
        return self._forward("step", self.backend.step(count, timeout))

    def advance_basic_blocks(self, count: int = 1, timeout: float = 5.0) -> dict[str, Any]:
        return self._forward("advance_basic_blocks", self.backend.advance_basic_blocks(count, timeout))

    def bp_add(self, address: str) -> dict[str, Any]:
        normalized = str(address).strip()
        if normalized == "":
            raise InvalidStateError("breakpoint address must be non-empty")
        value = self._parse_address(normalized)
        if value not in self.breakpoints:
            self.breakpoints.append(value)
        return self._response("bp_add", {"address": hex(value), "breakpoints": [hex(item) for item in self.breakpoints]})

    def bp_del(self, address: str) -> dict[str, Any]:
        normalized = str(address).strip()
        if normalized == "":
            raise InvalidStateError("breakpoint address must be non-empty")
        value = self._parse_address(normalized)
        if value in self.breakpoints:
            self.breakpoints.remove(value)
        return self._response("bp_del", {"address": hex(value), "breakpoints": [hex(item) for item in self.breakpoints]})

    def bp_clear(self) -> dict[str, Any]:
        self.breakpoints.clear()
        return self._response("bp_clear", {"breakpoints": []})

    def bp_list(self) -> dict[str, Any]:
        return self._response("bp_list", {"breakpoints": [hex(item) for item in self.breakpoints]})

    def bp_run(self, timeout: float = 5.0, max_steps: int = 10000) -> dict[str, Any]:
        if not self.breakpoints:
            raise InvalidStateError("no breakpoints configured")
        if max_steps < 0:
            raise InvalidStateError("max_steps must be >= 0")
        ordered = sorted(set(self.breakpoints))
        current_pc: int | None = self._parse_optional_address(self.state.pc)
        if current_pc is None:
            registers = self.get_registers(["rip", "eip", "pc"])["result"].get("registers", {})
            for key in ("rip", "eip", "pc"):
                value = registers.get(key)
                parsed = self._parse_optional_address(value)
                if parsed is not None:
                    current_pc = parsed
                    break
        if current_pc is not None and current_pc in ordered:
            return self._response("bp_run", {"matched_address": hex(current_pc), "selected_address": hex(current_pc), "breakpoints": [hex(item) for item in ordered], "steps": 0})

        if current_pc is not None:
            forward = [bp for bp in ordered if bp >= current_pc]
            selected = forward[0] if forward else ordered[0]
        else:
            selected = ordered[0]

        direct = self.run_until_address(hex(selected), timeout=timeout)
        matched = direct["result"].get("matched_address")
        if not isinstance(matched, str):
            matched = hex(selected)
        return self._response(
            "bp_run",
            {
                "matched_address": matched.lower(),
                "selected_address": hex(selected),
                "breakpoints": [hex(item) for item in ordered],
                "steps": 0,
            },
        )

    def write_stdin(self, data: str) -> dict[str, Any]:
        return self._forward("write_stdin", self.backend.write_stdin(data))

    def read_stdout(self, cursor: int = 0, max_chars: int = 4096) -> dict[str, Any]:
        return self._forward("read_stdout", self.backend.read_stdout(cursor, max_chars))

    def read_stderr(self, cursor: int = 0, max_chars: int = 4096) -> dict[str, Any]:
        return self._forward("read_stderr", self.backend.read_stderr(cursor, max_chars))

    def symbols(self, max_count: int = 500, name_filter: str | None = None) -> dict[str, Any]:
        if max_count < 1:
            raise InvalidStateError("max_count must be >= 1")
        target = self.state.target
        if not isinstance(target, str) or target == "":
            raise InvalidStateError("session target is not available")
        elf_type = self._read_elf_type(target)
        load_base = 0
        if elf_type == "DYN":
            maps_result = self.list_memory_maps()["result"]
            regions = maps_result.get("maps", {}).get("regions", [])
            target_name = target.rsplit("/", 1)[-1]
            candidates: list[int] = []
            for region in regions:
                if not isinstance(region, dict):
                    continue
                name = str(region.get("name") or "")
                start = region.get("start")
                if not isinstance(start, str):
                    continue
                if target_name in name:
                    try:
                        candidates.append(int(start, 16))
                    except ValueError:
                        continue
            if not candidates:
                raise InvalidStateError("unable to resolve PIE load base from memory maps")
            load_base = min(candidates)
        symbols = self._read_elf_symbols(target, elf_type=elf_type, load_base=load_base, max_count=max_count, name_filter=name_filter)
        return self._response(
            "symbols",
            {
                "target": target,
                "elf_type": elf_type,
                "load_base": hex(load_base),
                "symbols": symbols,
            },
        )

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
        self._merge_state(self.backend.get_state())
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

    @staticmethod
    def _parse_address(address: str) -> int:
        try:
            return int(address, 0)
        except Exception as exc:  # noqa: BLE001
            raise InvalidStateError(f"invalid address: {address!r}") from exc

    @staticmethod
    def _parse_optional_address(value: Any) -> int | None:
        if not isinstance(value, str):
            return None
        try:
            return int(value, 0)
        except Exception:
            return None

    @staticmethod
    def _read_elf_type(target: str) -> str:
        result = subprocess.run(
            ["readelf", "-h", target],
            check=True,
            capture_output=True,
            text=True,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Type:"):
                if "DYN" in line:
                    return "DYN"
                if "EXEC" in line:
                    return "EXEC"
                break
        return "EXEC"

    @staticmethod
    def _read_elf_symbols(
        target: str,
        *,
        elf_type: str,
        load_base: int,
        max_count: int,
        name_filter: str | None,
    ) -> list[dict[str, Any]]:
        result = subprocess.run(
            ["readelf", "-Ws", target],
            check=True,
            capture_output=True,
            text=True,
        )
        items: list[dict[str, Any]] = []
        current_table: str | None = None
        needle = name_filter.lower() if isinstance(name_filter, str) and name_filter else None
        for raw in result.stdout.splitlines():
            line = raw.strip()
            if line.startswith("Symbol table '"):
                start = line.find("'") + 1
                end = line.find("'", start)
                current_table = line[start:end] if start > 0 and end > start else None
                continue
            if not line or line.startswith("Num:") or ":" not in line:
                continue
            parts = line.split(None, 7)
            if len(parts) < 8:
                continue
            value, size, sym_type, bind, vis, ndx, name = parts[1], parts[2], parts[3], parts[4], parts[5], parts[6], parts[7]
            if needle and needle not in name.lower():
                continue
            if ndx == "UND":
                loaded_address = None
            else:
                try:
                    symbol_addr = int(value, 16)
                except ValueError:
                    continue
                loaded_address = symbol_addr if elf_type == "EXEC" else load_base + symbol_addr
            items.append(
                {
                    "name": name,
                    "table": current_table,
                    "value": f"0x{value.lower()}",
                    "loaded_address": None if loaded_address is None else hex(loaded_address),
                    "size": int(size) if size.isdigit() else 0,
                    "type": sym_type,
                    "bind": bind,
                    "visibility": vis,
                    "section": ndx,
                }
            )
            if len(items) >= max_count:
                break
        return items
