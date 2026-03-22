from __future__ import annotations

import pytest

from interactive_analysis.errors import InvalidStateError
from interactive_analysis.session import AnalysisSession


class FakeBackend:
    def __init__(self) -> None:
        self.pc_seq = ["0x1000", "0x1004", "0x1008", "0x100c"]
        self.idx = 0
        self.step_calls = 0
        self.run_until_calls = 0
        self.pause_calls = 0

    def start(self, target, args, cwd, qemu_config=None):  # noqa: ANN001
        del target, args, cwd, qemu_config

    def resume(self, timeout):  # noqa: ANN001
        del timeout
        return {"state": {"session_status": "running"}, "result": {}}

    def pause(self, timeout):  # noqa: ANN001
        del timeout
        self.pause_calls += 1
        return {"state": {"session_status": "paused"}, "result": {}}

    def run_until_event(self, event_types, timeout):  # noqa: ANN001
        del event_types, timeout
        return {"state": {}, "result": {}}

    def run_until_address(self, address, timeout):  # noqa: ANN001
        self.run_until_calls += 1
        del timeout
        return {"state": {"pc": address, "session_status": "paused"}, "result": {"matched_address": address}}

    def step(self, count, timeout):  # noqa: ANN001
        del timeout
        self.step_calls += 1
        self.idx = min(self.idx + count, len(self.pc_seq) - 1)
        pc = self.pc_seq[self.idx]
        return {"state": {"pc": pc, "session_status": "paused"}, "result": {"pc": pc, "count": count}}

    def advance_basic_blocks(self, count, timeout):  # noqa: ANN001
        del count, timeout
        return {"state": {}, "result": {}}

    def write_stdin(self, data):  # noqa: ANN001
        del data
        return {"state": {}, "result": {}}

    def read_stdout(self, cursor=0, max_chars=4096):  # noqa: ANN001
        del cursor, max_chars
        return {"state": {}, "result": {"data": "", "cursor": 0, "eof": False}}

    def read_stderr(self, cursor=0, max_chars=4096):  # noqa: ANN001
        del cursor, max_chars
        return {"state": {}, "result": {"data": "", "cursor": 0, "eof": False}}

    def get_registers(self, names=None):  # noqa: ANN001
        del names
        return {"state": {"pc": self.pc_seq[self.idx]}, "result": {"registers": {"rip": self.pc_seq[self.idx]}}}

    def read_memory(self, address, size):  # noqa: ANN001
        del address, size
        return {"state": {}, "result": {}}

    def disassemble(self, address, count):  # noqa: ANN001
        del address, count
        return {"state": {}, "result": {}}

    def list_memory_maps(self):
        return {"state": {}, "result": {}}

    def take_snapshot(self, name=None):  # noqa: ANN001
        del name
        return {"state": {}, "result": {}}

    def restore_snapshot(self, snapshot_id):  # noqa: ANN001
        del snapshot_id
        return {"state": {}, "result": {}}

    def diff_snapshots(self, left_id, right_id):  # noqa: ANN001
        del left_id, right_id
        return {"state": {}, "result": {}}

    def get_recent_events(self, limit=100, event_types=None):  # noqa: ANN001
        del limit, event_types
        return {"state": {}, "result": {}}

    def get_trace(self, limit):  # noqa: ANN001
        del limit
        return {"state": {}, "result": {}}

    def configure_event_filters(self, event_types=None, address_ranges=None):  # noqa: ANN001
        del event_types, address_ranges
        return {"state": {}, "result": {}}

    def get_state(self):
        return {"session_status": "paused", "pc": self.pc_seq[self.idx], "capabilities": self.capabilities()}

    def capabilities(self):
        return {
            "pause_resume": True,
            "read_registers": True,
            "read_memory": True,
            "disassemble": True,
            "list_memory_maps": True,
            "take_snapshot": False,
            "restore_snapshot": False,
            "trace_basic_block": False,
            "trace_branch": False,
            "trace_memory": False,
            "trace_syscall": False,
            "run_until_address": True,
            "single_step": True,
        }

    def close(self):
        return None


def test_session_bp_run_multiple_breakpoints_selects_nearest_forward() -> None:
    session = AnalysisSession(backend=FakeBackend())
    session.state.session_status = "paused"
    session.state.pc = "0x1004"
    session.bp_add("0x1008")
    session.bp_add("0x2000")

    result = session.bp_run(timeout=1.0, max_steps=10)

    assert result["result"]["matched_address"] == "0x1008"
    assert result["result"]["selected_address"] == "0x1008"
    assert result["result"]["steps"] == 0
    assert session.backend.run_until_calls == 1
    assert session.backend.step_calls == 0


def test_session_bp_run_multiple_breakpoints_wraps_to_first_when_all_behind() -> None:
    session = AnalysisSession(backend=FakeBackend())
    session.state.session_status = "paused"
    session.state.pc = "0x9000"
    session.bp_add("0x3000")
    session.bp_add("0x2000")

    result = session.bp_run(timeout=1.0, max_steps=2)

    assert result["result"]["selected_address"] == "0x2000"
    assert result["result"]["matched_address"] == "0x2000"


def test_session_bp_run_single_breakpoint_uses_run_until_address() -> None:
    backend = FakeBackend()
    session = AnalysisSession(backend=backend)
    session.state.session_status = "paused"
    session.bp_add("0x1008")

    result = session.bp_run(timeout=1.0, max_steps=10)

    assert result["result"]["matched_address"] == "0x1008"
    assert backend.run_until_calls == 1
    assert backend.step_calls == 0


def test_session_pause_noop_when_idle_or_paused() -> None:
    backend = FakeBackend()
    session = AnalysisSession(backend=backend)
    session.state.session_status = "idle"

    first = session.pause(timeout=1.0)
    assert first["result"]["noop"] is True
    assert first["state"]["session_status"] == "paused"
    assert backend.pause_calls == 0

    second = session.pause(timeout=1.0)
    assert second["result"]["noop"] is True
    assert second["state"]["session_status"] == "paused"
    assert backend.pause_calls == 0


def test_session_pause_raises_when_not_started() -> None:
    session = AnalysisSession(backend=FakeBackend())
    with pytest.raises(InvalidStateError, match="session is not started"):
        session.pause(timeout=1.0)
