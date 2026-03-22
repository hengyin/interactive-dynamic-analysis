from __future__ import annotations

import pytest

from interactive_analysis.backends.qemu_user_instrumented import QemuUserInstrumentedBackend
from interactive_analysis.errors import InvalidStateError, SessionTimeoutError


class FakeQmpClient:
    def __init__(self) -> None:
        self.commands: list[tuple[str, dict | None]] = []

    def connect(self) -> dict:
        return {"QMP": {}}

    def execute(self, command: str, arguments: dict | None = None) -> dict:
        self.commands.append((command, arguments))
        if command == "human-monitor-command":
            return {"command-line": arguments["command-line"]}
        return {}

    def close(self) -> None:
        return None


class FakeQmpClientWithStatus(FakeQmpClient):
    def execute(self, command: str, arguments: dict | None = None) -> dict:
        self.commands.append((command, arguments))
        if command == "query-status":
            return {"status": "paused"}
        return super().execute(command, arguments)


class FakeInstrumentationClient:
    def __init__(self) -> None:
        self.stats = type("Stats", (), {"to_dict": lambda self: {"events_received": 1}})()
        self.connected = False
        self._pause_requested = False
        self._latest_seq = 0

    def connect(self) -> None:
        self.connected = True

    def latest_seq(self) -> int | None:
        return self._latest_seq

    def wait_for_event(self, event_types: list[str], timeout: float, min_seq_exclusive: int | None = None) -> dict:
        assert timeout == 1.0
        if event_types == ["execution_paused"]:
            assert self._pause_requested is True
            assert min_seq_exclusive == 1
            self._pause_requested = False
            self._latest_seq = 99
            return {
                "event_id": "e-pause",
                "seq": 99,
                "type": "execution_paused",
                "timestamp": 1.1,
                "pc": "0x401000",
                "thread_id": "1",
                "cpu_id": 0,
                "payload": {"reason": "user"},
            }
        assert event_types == ["branch"]
        assert min_seq_exclusive == 0
        self._latest_seq = 1
        return {
            "event_id": "e-1",
            "seq": 1,
            "type": "branch",
            "timestamp": 1.0,
            "pc": "0x401000",
            "thread_id": "1",
            "cpu_id": 0,
            "payload": {"target": "0x401010", "taken": True},
        }

    def wait_for_address(self, address: str, timeout: float, min_seq_exclusive: int | None = None) -> dict:
        assert timeout == 1.0
        assert min_seq_exclusive == 0
        self._latest_seq = 2
        return {
            "event_id": "e-2",
            "seq": 2,
            "type": "basic_block",
            "timestamp": 2.0,
            "pc": address,
            "thread_id": "1",
            "cpu_id": 0,
            "payload": {"start": address, "end": address, "instruction_count": 1},
        }

    def get_recent_events(self, limit: int = 100, event_types: list[str] | None = None) -> list[dict]:
        del limit, event_types
        return [
            {
                "event_id": "e-1",
                "seq": 1,
                "type": "branch",
                "timestamp": 1.0,
                "pc": "0x401000",
                "thread_id": "1",
                "cpu_id": 0,
                "payload": {"target": "0x401010", "taken": True},
            }
        ]

    def configure_filters(self, event_types=None, address_ranges=None) -> dict:
        return {"event_types": event_types or [], "address_ranges": address_ranges or []}

    def close(self) -> None:
        return None


class FakeInstrumentationRpcClient:
    def __init__(self, instrumentation_client: FakeInstrumentationClient | None = None) -> None:
        self.connected = False
        self.requests: list[tuple[str, dict]] = []
        self.instrumentation_client = instrumentation_client

    def connect(self) -> None:
        self.connected = True

    def request(self, method: str, params: dict | None = None) -> dict:
        params = dict(params or {})
        self.requests.append((method, params))
        if method == "resume":
            return {}
        if method == "pause":
            if self.instrumentation_client is not None:
                self.instrumentation_client._pause_requested = True
            return {}
        if method == "resume_until_basic_block":
            return {"status": "paused", "blocks_executed": params["count"], "pc": "0x401010"}
        if method == "resume_until_address":
            return {"status": "paused", "pc": params["address"]}
        if method == "query_status":
            return {"status": "paused"}
        if method == "get_registers":
            return {"registers": {"rax": "0x1", "rbx": "0x2", "rip": "0x401000"}}
        if method == "read_memory":
            return {"address": params["address"], "size": params["size"], "bytes": "0102"}
        if method == "disassemble":
            return {
                "instructions": [
                    {
                        "address": params["address"],
                        "size": 3,
                        "bytes": "4889e5",
                        "text": "mov rbp, rsp",
                    },
                    {
                        "address": "0x401003",
                        "size": 1,
                        "bytes": "90",
                        "text": "nop",
                    },
                ]
            }
        if method == "list_memory_maps":
            return {"regions": [{"start": "0x400000", "end": "0x401000", "perm": "r-x"}]}
        raise AssertionError(f"unexpected method: {method}")

    def close(self) -> None:
        return None


class FakeProcessRunner:
    def __init__(self) -> None:
        self.started = False
        self.closed = False
        self.config = None
        self.summary: str | None = None

    def start(self, config) -> object:
        self.started = True
        self.config = config
        return object()

    def close(self) -> None:
        self.closed = True

    def exited_summary(self) -> str | None:
        return self.summary


class FailingInstrumentationRpcClient(FakeInstrumentationRpcClient):
    def request(self, method: str, params: dict | None = None) -> dict:
        self.requests.append((method, dict(params or {})))
        raise RuntimeError("instrumentation RPC connection closed")


class TimeoutInstrumentationClient(FakeInstrumentationClient):
    def wait_for_event(self, event_types: list[str], timeout: float, min_seq_exclusive: int | None = None) -> dict:
        del min_seq_exclusive
        raise TimeoutError("timed out waiting for event types: ['branch']")


def test_backend_run_until_event_updates_state() -> None:
    instrumentation = FakeInstrumentationClient()
    rpc = FakeInstrumentationRpcClient(instrumentation)
    backend = QemuUserInstrumentedBackend(
        qmp_client=FakeQmpClient(),
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {"capabilities_override": {"run_until_address": True}})

    result = backend.run_until_event(["branch"], timeout=1.0)

    assert result["result"]["matched_event"]["event_id"] == "e-1"
    assert result["state"]["session_status"] == "paused"
    assert result["state"]["pc"] == "0x401000"
    assert result["state"]["recent_events"][0]["event_id"] == "e-1"
    assert rpc.requests[:2] == [("resume", {}), ("pause", {})]


def test_backend_start_allows_rpc_only_mode() -> None:
    rpc = FakeInstrumentationRpcClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=rpc,
    )

    backend.start(
        "target.bin",
        [],
        None,
        {
            "capabilities_override": {
                "pause_resume": False,
                "list_memory_maps": False,
                "run_until_address": False,
            }
        },
    )

    state = backend.get_state()
    registers = backend.get_registers(["rip", "rax"])

    assert state["session_status"] == "paused"
    assert state["capabilities"]["trace_branch"] is False
    assert state["capabilities"]["pause_resume"] is False
    assert registers["result"]["registers"]["rip"] == "0x401000"


def test_backend_advance_basic_blocks_uses_rpc_method() -> None:
    rpc = FakeInstrumentationRpcClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {"capabilities_override": {"run_until_address": True}})

    result = backend.advance_basic_blocks(1, timeout=1.0)

    assert rpc.requests[-1] == ("resume_until_basic_block", {"count": 1})
    assert result["result"]["blocks_executed"] == 1
    assert result["state"]["pc"] == "0x401010"


def test_backend_run_until_address_uses_rpc_in_rpc_only_mode() -> None:
    rpc = FakeInstrumentationRpcClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {"capabilities_override": {"run_until_address": True}})

    result = backend.run_until_address("0x401000", timeout=1.0)

    assert rpc.requests[-1] == ("resume_until_address", {"address": "0x401000"})
    assert result["result"]["matched_address"] == "0x401000"
    assert result["state"]["pc"] == "0x401000"


def test_backend_run_until_address_returns_immediately_when_already_at_address() -> None:
    rpc = FakeInstrumentationRpcClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {"capabilities_override": {"run_until_address": True}})
    backend.get_registers(["rip"])

    result = backend.run_until_address("0x401000", timeout=1.0)

    assert rpc.requests == [("get_registers", {"names": ["rip"]})]
    assert result["result"]["matched_address"] == "0x401000"
    assert result["state"]["pc"] == "0x401000"


def test_backend_disassemble_uses_rpc_in_rpc_only_mode() -> None:
    rpc = FakeInstrumentationRpcClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {"capabilities_override": {"disassemble": True}})

    result = backend.disassemble("0x401000", 2)

    assert rpc.requests[-1] == ("disassemble", {"address": "0x401000", "count": 2})
    assert result["result"]["instructions"][0]["address"] == "0x401000"
    assert result["result"]["instructions"][1]["text"] == "nop"


def test_backend_rpc_failure_includes_process_exit_summary() -> None:
    rpc = FailingInstrumentationRpcClient()
    process_runner = FakeProcessRunner()
    process_runner.summary = "qemu-user exited with code 139; stderr: ia-rpc: matched stop address"
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=rpc,
        process_runner=process_runner,
    )
    backend.start("target.bin", [], None, {"capabilities_override": {"run_until_address": True}})

    with pytest.raises(InvalidStateError, match="qemu-user exited with code 139"):
        backend.run_until_address("0x401000", timeout=1.0)


def test_backend_get_recent_events_returns_event_shape_not_trace_shape() -> None:
    instrumentation = FakeInstrumentationClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=FakeQmpClient(),
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=FakeInstrumentationRpcClient(instrumentation),
    )
    backend.start("target.bin", [], None, {})
    backend.run_until_event(["branch"], timeout=1.0)

    result = backend.get_recent_events()

    assert result["result"]["events"][0]["event_id"] == "e-1"
    assert "payload" in result["result"]["events"][0]
    assert "index" not in result["result"]["events"][0]


def test_backend_trace_returns_trace_shape() -> None:
    instrumentation = FakeInstrumentationClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=FakeQmpClient(),
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=FakeInstrumentationRpcClient(instrumentation),
    )
    backend.start("target.bin", [], None, {})
    backend.run_until_event(["branch"], timeout=1.0)

    result = backend.get_trace(limit=10)

    assert result["result"]["trace"][0]["event_id"] == "e-1"
    assert result["result"]["trace"][0]["index"] == 0
    assert "payload" not in result["result"]["trace"][0]
    assert result["result"]["trace"][1]["type"] == "execution_paused"


def test_backend_take_snapshot_records_snapshot_id() -> None:
    instrumentation = FakeInstrumentationClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=FakeQmpClient(),
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=FakeInstrumentationRpcClient(instrumentation),
    )
    backend.start("target.bin", [], None, {})

    with pytest.raises(Exception):
        backend.take_snapshot("snap-1")


def test_backend_run_until_event_wraps_timeouts() -> None:
    backend = QemuUserInstrumentedBackend(
        qmp_client=FakeQmpClient(),
        instrumentation_client=TimeoutInstrumentationClient(),
        instrumentation_rpc_client=FakeInstrumentationRpcClient(),
    )
    backend.start("target.bin", [], None, {})

    with pytest.raises(SessionTimeoutError):
        backend.run_until_event(["branch"], timeout=1.0)


def test_backend_configure_filters_returns_ranges() -> None:
    instrumentation = FakeInstrumentationClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=FakeQmpClient(),
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=FakeInstrumentationRpcClient(instrumentation),
    )
    backend.start("target.bin", [], None, {})

    result = backend.configure_event_filters(
        event_types=["branch"],
        address_ranges=[("0x401000", "0x401100")],
    )

    assert result["result"]["filters"]["event_types"] == ["branch"]
    assert result["result"]["filters"]["address_ranges"] == [("0x401000", "0x401100")]


def test_backend_get_state_queries_qmp_status() -> None:
    instrumentation = FakeInstrumentationClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=FakeQmpClientWithStatus(),
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=FakeInstrumentationRpcClient(instrumentation),
    )
    backend.start("target.bin", [], None, {})

    state = backend.get_state()

    assert state["session_status"] == "paused"


def test_backend_resume_uses_rpc_control_when_available() -> None:
    instrumentation = FakeInstrumentationClient()
    rpc = FakeInstrumentationRpcClient(instrumentation)
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {})

    result = backend.resume(timeout=1.0)

    assert result["state"]["session_status"] == "running"
    assert rpc.requests[0] == ("resume", {})


def test_backend_start_can_launch_qemu_user_process() -> None:
    runner = FakeProcessRunner()
    instrumentation = FakeInstrumentationClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=FakeInstrumentationRpcClient(instrumentation),
        process_runner=runner,
    )

    backend.start(
        "target.bin",
        ["arg1"],
        "/tmp/work",
        {
            "launch": True,
            "qemu_user_path": "/usr/bin/qemu-x86_64",
            "instrumentation_socket_path": "/tmp/events.sock",
            "instrumentation_rpc_socket_path": "/tmp/rpc.sock",
        },
    )

    assert runner.started is True
    assert runner.config.target == "target.bin"
    assert runner.config.args == ["arg1"]
    assert runner.config.cwd == "/tmp/work"


def test_backend_get_registers_uses_rpc_channel() -> None:
    instrumentation = FakeInstrumentationClient()
    rpc = FakeInstrumentationRpcClient(instrumentation)
    backend = QemuUserInstrumentedBackend(
        qmp_client=FakeQmpClient(),
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {})

    result = backend.get_registers(["rax"])

    assert result["result"]["registers"] == {"rax": "0x1", "rbx": "0x2", "rip": "0x401000"}
    assert rpc.requests[0] == ("get_registers", {"names": ["rax"]})
    assert result["state"]["registers"]["rip"] == "0x401000"
    assert result["state"]["pc"] == "0x401000"


def test_backend_read_memory_uses_rpc_channel() -> None:
    instrumentation = FakeInstrumentationClient()
    rpc = FakeInstrumentationRpcClient(instrumentation)
    backend = QemuUserInstrumentedBackend(
        qmp_client=FakeQmpClient(),
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {})

    result = backend.read_memory("0x401000", 2)

    assert result["result"] == {"address": "0x401000", "size": 2, "bytes": "0102"}
    assert rpc.requests[0] == ("read_memory", {"address": "0x401000", "size": 2})


def test_backend_list_memory_maps_uses_rpc_channel() -> None:
    instrumentation = FakeInstrumentationClient()
    rpc = FakeInstrumentationRpcClient(instrumentation)
    backend = QemuUserInstrumentedBackend(
        qmp_client=FakeQmpClient(),
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {})

    result = backend.list_memory_maps()

    assert result["result"]["maps"] == {"regions": [{"start": "0x400000", "end": "0x401000", "perm": "r-x", "name": None}]}
    assert rpc.requests[0] == ("list_memory_maps", {})
    assert result["state"]["memory_maps"] == [{"start": "0x400000", "end": "0x401000", "perm": "r-x", "name": None}]
