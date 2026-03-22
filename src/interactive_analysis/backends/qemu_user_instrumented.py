from __future__ import annotations

import time
from collections import deque
from pathlib import Path
from typing import Any

from ..errors import InvalidStateError, SessionTimeoutError, UnsupportedOperationError
from ..instrumentation import InstrumentationClient, InstrumentationRpcClient, trace_entry_from_event
from ..models import MemoryMapSnapshot, MemoryReadResult, RegisterSnapshot
from ..qemu_user import QemuUserLaunchConfig, QemuUserProcessRunner
from ..qmp import QmpClient, QmpController
from .base import BackendCapabilities


class QemuUserInstrumentedBackend:
    """Backend for an instrumented qemu-user target, with optional QMP support."""

    def __init__(
        self,
        qmp_client: QmpClient | None = None,
        instrumentation_client: InstrumentationClient | None = None,
        instrumentation_rpc_client: InstrumentationRpcClient | None = None,
        process_runner: QemuUserProcessRunner | None = None,
    ) -> None:
        self._capabilities = BackendCapabilities(
            pause_resume=True,
            read_registers=True,
            read_memory=True,
            disassemble=False,
            list_memory_maps=True,
            take_snapshot=False,
            restore_snapshot=False,
            trace_basic_block=True,
            trace_branch=True,
            trace_memory=True,
            trace_syscall=True,
            run_until_address=True,
            single_step=False,
        )
        self._qmp = qmp_client
        self._controller = QmpController(qmp_client) if qmp_client is not None else None
        self._instrumentation = instrumentation_client
        self._instrumentation_rpc = instrumentation_rpc_client
        self._process_runner = process_runner
        self._started = False
        self._state: dict[str, Any] = {
            "session_status": "not_started",
            "backend": "qemu_user_instrumented",
            "recent_events": [],
            "ingestion_stats": {},
            "capabilities": self._capabilities.to_dict(),
        }
        self._trace: deque[dict[str, Any]] = deque(maxlen=4096)
        self._snapshots: dict[str, dict[str, Any]] = {}

    def start(
        self,
        target: str,
        args: list[str],
        cwd: str | None,
        qemu_config: dict[str, Any] | None = None,
    ) -> None:
        qemu_config = dict(qemu_config or {})
        if qemu_config.get("launch"):
            if self._process_runner is None:
                self._process_runner = QemuUserProcessRunner()
            launch_config = QemuUserLaunchConfig.from_target(
                target=target,
                args=args,
                cwd=cwd,
                qemu_config=qemu_config,
            )
            self._process_runner.start(launch_config)
        if self._qmp is None:
            socket_path = qemu_config.get("qmp_socket_path")
            if socket_path:
                self._qmp = QmpClient(socket_path=socket_path, timeout=float(qemu_config.get("qmp_timeout", 2.0)))
                self._controller = QmpController(self._qmp)
        if self._instrumentation is None:
            socket_path = qemu_config.get("instrumentation_socket_path")
            if socket_path:
                self._instrumentation = InstrumentationClient(
                    socket_path=socket_path,
                    max_events=int(qemu_config.get("max_recent_events", 1024)),
                    timeout=float(qemu_config.get("instrumentation_timeout", 0.1)),
                )
        if self._instrumentation_rpc is None:
            socket_path = qemu_config.get("instrumentation_rpc_socket_path")
            if socket_path:
                self._instrumentation_rpc = InstrumentationRpcClient(
                    socket_path=socket_path,
                    timeout=float(qemu_config.get("instrumentation_rpc_timeout", 2.0)),
                )
        if self._instrumentation is None:
            self._capabilities.trace_basic_block = False
            self._capabilities.trace_branch = False
            self._capabilities.trace_memory = False
            self._capabilities.trace_syscall = False
            self._capabilities.run_until_address = False
            self._capabilities.single_step = False
        overrides = qemu_config.get("capabilities_override")
        if overrides:
            for key, value in dict(overrides).items():
                if hasattr(self._capabilities, key):
                    setattr(self._capabilities, key, bool(value))
        if qemu_config.get("launch"):
            if self._instrumentation is not None:
                socket_path = getattr(self._instrumentation, "socket_path", None)
                if socket_path:
                    self._wait_for_socket_path(
                        socket_path,
                        timeout=float(qemu_config.get("launch_connect_timeout", 5.0)),
                    )
            if self._instrumentation_rpc is not None:
                socket_path = getattr(self._instrumentation_rpc, "socket_path", None)
                if socket_path:
                    self._wait_for_socket_path(
                        socket_path,
                        timeout=float(qemu_config.get("launch_connect_timeout", 5.0)),
                    )
        try:
            if self._controller is not None:
                self._controller.connect()
            if self._instrumentation is not None:
                self._instrumentation.connect()
            if self._instrumentation_rpc is not None:
                self._instrumentation_rpc.connect()
        except Exception as exc:
            process_summary = None
            if self._process_runner is not None:
                process_summary = self._process_runner.exited_summary()
            if process_summary is not None:
                raise InvalidStateError(f"{exc}; {process_summary}") from exc
            raise
        self._state.update(
            {
                "session_status": "idle",
                "target": target,
                "args": list(args),
                "cwd": cwd,
                "recent_events": [],
                "ingestion_stats": self._instrumentation.stats.to_dict() if self._instrumentation is not None else {},
                "capabilities": self._capabilities.to_dict(),
            }
        )
        self._started = True

    def resume(self, timeout: float) -> dict[str, Any]:
        del timeout
        self._require_started()
        if self._instrumentation_rpc is not None:
            self._rpc_request("resume")
        elif self._controller is not None:
            self._controller.resume()
        else:
            raise UnsupportedOperationError("backend does not have a control channel configured")
        self._state["session_status"] = "running"
        return self._response({})

    def pause(self, timeout: float) -> dict[str, Any]:
        del timeout
        self._require_started()
        if self._instrumentation_rpc is not None:
            self._rpc_request("pause")
        elif self._controller is not None:
            self._controller.pause()
        else:
            raise UnsupportedOperationError("backend does not have a control channel configured")
        self._state["session_status"] = "paused"
        return self._response({})

    def run_until_event(self, event_types: list[str], timeout: float) -> dict[str, Any]:
        self._require_started()
        if self._instrumentation is None:
            raise UnsupportedOperationError("backend does not have an instrumentation event channel configured")
        start_seq = self._instrumentation.latest_seq()
        self.resume(timeout)
        try:
            matched = self._instrumentation.wait_for_event(event_types, timeout, min_seq_exclusive=start_seq)
        except TimeoutError as exc:
            raise SessionTimeoutError(str(exc)) from exc
        self.pause(timeout)
        try:
            pause_event = self._instrumentation.wait_for_event(
                ["execution_paused"],
                timeout,
                min_seq_exclusive=int(matched["seq"]),
            )
        except TimeoutError as exc:
            raise SessionTimeoutError("timed out waiting for execution_paused acknowledgement") from exc
        self._state.update(
            {
                "session_status": "paused",
                "pc": pause_event.get("pc") or matched.get("pc"),
                "current_thread_id": matched.get("thread_id"),
                "last_event_id": matched.get("event_id"),
            }
        )
        self._record_trace(matched)
        self._record_trace(pause_event)
        self._refresh_recent_events()
        return self._response({"matched_event": matched})

    def run_until_address(self, address: str, timeout: float) -> dict[str, Any]:
        self._require_started()
        if not self._capabilities.run_until_address:
            raise UnsupportedOperationError("backend does not support run_until_address")
        if self._instrumentation is None:
            current_pc = self._state.get("pc")
            if isinstance(current_pc, str) and current_pc.lower() == address.lower():
                self._state["session_status"] = "paused"
                self._state["pc"] = current_pc.lower()
                return self._response({"matched_address": current_pc.lower(), "status": "paused", "pc": current_pc.lower()})
            result = self._rpc_request("resume_until_address", {"address": address})
            status = result.get("status")
            if isinstance(status, str):
                self._state["session_status"] = status
            pc = result.get("pc")
            if isinstance(pc, str):
                self._state["pc"] = pc
            return self._response({"matched_address": address, **result})
        if self._instrumentation is None:
            raise UnsupportedOperationError("backend does not have an instrumentation event channel configured")
        start_seq = self._instrumentation.latest_seq()
        self.resume(timeout)
        try:
            matched = self._instrumentation.wait_for_address(address, timeout, min_seq_exclusive=start_seq)
        except TimeoutError as exc:
            raise SessionTimeoutError(str(exc)) from exc
        self.pause(timeout)
        try:
            pause_event = self._instrumentation.wait_for_event(
                ["execution_paused"],
                timeout,
                min_seq_exclusive=int(matched["seq"]),
            )
        except TimeoutError as exc:
            raise SessionTimeoutError("timed out waiting for execution_paused acknowledgement") from exc
        self._state.update(
            {
                "session_status": "paused",
                "pc": pause_event.get("pc") or matched.get("pc"),
                "current_thread_id": matched.get("thread_id"),
                "last_event_id": matched.get("event_id"),
            }
        )
        self._record_trace(matched)
        self._record_trace(pause_event)
        self._refresh_recent_events()
        return self._response({"matched_event": matched})

    def step(self, count: int, timeout: float) -> dict[str, Any]:
        del timeout
        self._require_started()
        if not self._capabilities.single_step:
            raise UnsupportedOperationError("backend does not support single stepping")
        return self._response({"count": count})

    def advance_basic_blocks(self, count: int, timeout: float) -> dict[str, Any]:
        del timeout
        self._require_started()
        result = self._rpc_request("resume_until_basic_block", {"count": count})
        status = result.get("status")
        if isinstance(status, str):
            self._state["session_status"] = status
        pc = result.get("pc")
        if isinstance(pc, str):
            self._state["pc"] = pc
        return self._response(result)

    def get_registers(self, names: list[str] | None = None) -> dict[str, Any]:
        self._require_started()
        snapshot = RegisterSnapshot.from_rpc_result(self._rpc_request("get_registers", {"names": list(names or [])}))
        self._state["registers"] = snapshot.registers
        pc = snapshot.registers.get("pc") or snapshot.registers.get("rip") or snapshot.registers.get("eip")
        if pc is not None:
            self._state["pc"] = pc
        return self._response(snapshot.to_dict())

    def read_memory(self, address: str, size: int) -> dict[str, Any]:
        self._require_started()
        result = MemoryReadResult.from_rpc_result(self._rpc_request("read_memory", {"address": address, "size": size}))
        return self._response(result.to_dict())

    def disassemble(self, address: str, count: int) -> dict[str, Any]:
        self._require_started()
        if not self._capabilities.disassemble:
            raise UnsupportedOperationError("backend does not support disassembly")
        return self._response(self._rpc_request("disassemble", {"address": address, "count": count}))

    def list_memory_maps(self) -> dict[str, Any]:
        self._require_started()
        maps = MemoryMapSnapshot.from_rpc_result(self._rpc_request("list_memory_maps"))
        self._state["memory_maps"] = maps.to_dict()["regions"]
        return self._response({"maps": maps.to_dict()})

    def take_snapshot(self, name: str | None = None) -> dict[str, Any]:
        self._require_started()
        if not self._capabilities.take_snapshot:
            raise UnsupportedOperationError("backend does not support snapshots")
        if self._controller is None:
            raise UnsupportedOperationError("snapshot support requires a backend control channel")
        snapshot_id = name or f"s-{len(self._snapshots) + 1}"
        self._controller.save_snapshot(snapshot_id)
        snapshot = {
            "snapshot_id": snapshot_id,
            "name": name,
            "created_at": time.time(),
            "pc": self._state.get("pc"),
            "thread_id": self._state.get("current_thread_id"),
            "event_id": self._state.get("last_event_id"),
            "metadata": {"reason": "manual"},
        }
        self._snapshots[snapshot_id] = snapshot
        self._state["last_snapshot_id"] = snapshot_id
        return self._response(snapshot)

    def restore_snapshot(self, snapshot_id: str) -> dict[str, Any]:
        self._require_started()
        if not self._capabilities.restore_snapshot:
            raise UnsupportedOperationError("backend does not support snapshot restore")
        if self._controller is None:
            raise UnsupportedOperationError("snapshot restore requires a backend control channel")
        self._controller.load_snapshot(snapshot_id)
        snapshot = self._snapshots.get(snapshot_id, {"snapshot_id": snapshot_id})
        self._state["last_snapshot_id"] = snapshot_id
        return self._response(snapshot)

    def diff_snapshots(self, left_id: str, right_id: str) -> dict[str, Any]:
        left = self._snapshots.get(left_id)
        right = self._snapshots.get(right_id)
        if left is None or right is None:
            raise ValueError("snapshot id not found")
        changed: dict[str, Any] = {}
        for key in {"pc", "thread_id", "event_id"}:
            if left.get(key) != right.get(key):
                changed[key] = {"left": left.get(key), "right": right.get(key)}
        return self._response({"left_id": left_id, "right_id": right_id, "changed_fields": changed})

    def get_recent_events(
        self,
        limit: int = 100,
        event_types: list[str] | None = None,
    ) -> dict[str, Any]:
        self._require_started()
        if self._instrumentation is None:
            raise UnsupportedOperationError("backend does not have an instrumentation event channel configured")
        events = self._instrumentation.get_recent_events(limit=limit, event_types=event_types)
        self._state["recent_events"] = events
        self._state["ingestion_stats"] = self._instrumentation.stats.to_dict()
        return self._response({"events": events})

    def get_trace(self, limit: int) -> dict[str, Any]:
        self._require_started()
        trace = list(self._trace)[-limit:]
        return self._response({"trace": trace})

    def configure_event_filters(
        self,
        event_types: list[str] | None = None,
        address_ranges: list[tuple[str, str]] | None = None,
    ) -> dict[str, Any]:
        self._require_started()
        if self._instrumentation is None:
            raise UnsupportedOperationError("backend does not have an instrumentation event channel configured")
        config = self._instrumentation.configure_filters(event_types, address_ranges)
        return self._response({"filters": config})

    def get_state(self) -> dict[str, Any]:
        if self._instrumentation_rpc is not None and self._started:
            try:
                status = self._instrumentation_rpc.request("query_status")
            except Exception:
                status = None
            if status and "status" in status:
                self._state["session_status"] = status["status"]
        elif self._controller is not None and self._started:
            try:
                status = self._controller.query_status()
            except Exception:
                status = None
            if status and "status" in status:
                self._state["session_status"] = status["status"]
        if self._instrumentation is not None:
            self._refresh_recent_events()
        return dict(self._state)

    def capabilities(self) -> dict[str, bool]:
        return self._capabilities.to_dict()

    def close(self) -> None:
        if self._instrumentation is not None:
            self._instrumentation.close()
        if self._instrumentation_rpc is not None:
            self._instrumentation_rpc.close()
        if self._controller is not None:
            self._controller.close()
        if self._process_runner is not None:
            self._process_runner.close()
        self._started = False
        self._state["session_status"] = "closed"

    def _response(self, result: dict[str, Any]) -> dict[str, Any]:
        if self._instrumentation is not None:
            self._refresh_recent_events()
        return {"state": dict(self._state), "result": result}

    def _record_trace(self, event: dict[str, Any]) -> None:
        entry = trace_entry_from_event(len(self._trace), event)
        self._trace.append(entry)
        self._state["trace_head"] = len(self._trace)

    def _refresh_recent_events(self) -> None:
        if self._instrumentation is None:
            return
        self._state["recent_events"] = self._instrumentation.get_recent_events(limit=10)
        self._state["ingestion_stats"] = self._instrumentation.stats.to_dict()

    def _require_started(self) -> None:
        if not self._started:
            raise InvalidStateError("backend has not been started")

    def _require_rpc(self) -> InstrumentationRpcClient:
        if self._instrumentation_rpc is None:
            raise UnsupportedOperationError("backend does not have an instrumentation RPC channel configured")
        return self._instrumentation_rpc

    def _rpc_request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        rpc = self._require_rpc()
        try:
            return rpc.request(method, params)
        except Exception as exc:
            process_summary = None
            if self._process_runner is not None:
                process_summary = self._process_runner.exited_summary()
            if process_summary is not None:
                raise InvalidStateError(f"{exc}; {process_summary}") from exc
            raise

    @staticmethod
    def _wait_for_socket_path(socket_path: str, timeout: float) -> None:
        deadline = time.time() + timeout
        path = Path(socket_path)
        while time.time() < deadline:
            if path.exists():
                return
            time.sleep(0.05)
        raise SessionTimeoutError(f"timed out waiting for socket: {socket_path}")
