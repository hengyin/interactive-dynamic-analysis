from __future__ import annotations

from interactive_analysis.errors import InvalidStateError
from interactive_analysis.mcp_server import InteractiveAnalysisMcpServer


class FakeSession:
    def __init__(self) -> None:
        self.started = False
        self.last_qemu_config = None
        self.close_calls = 0
        self.stdin_written = ""
        self.stdout_cursors: list[int] = []
        self.stderr_cursors: list[int] = []

    def start(self, target, args=None, cwd=None, qemu_config=None):  # noqa: ANN001
        if self.started:
            raise InvalidStateError("session already started")
        self.started = True
        self.last_qemu_config = qemu_config
        return {"ok": True, "command": "start", "result": {"target": target}}

    def close(self):
        self.started = False
        self.close_calls += 1
        return {"ok": True, "command": "close", "result": {}}

    def capabilities(self):
        return {"ok": True, "command": "capabilities", "result": {"capabilities": {"read_memory": True}}}

    def get_state(self):
        return {"ok": True, "command": "get_state", "result": {"session_status": "paused"}}

    def symbols(self, max_count=500, name_filter=None):  # noqa: ANN001
        return {
            "ok": True,
            "command": "symbols",
            "result": {
                "target": "/tmp/a.out",
                "elf_type": "EXEC",
                "load_base": "0x0",
                "symbols": [{"name": "main", "loaded_address": "0x401000"}],
                "max_count": max_count,
                "name_filter": name_filter,
            },
        }

    def resume(self, timeout=5.0):  # noqa: ANN001
        return {"ok": True, "command": "resume", "result": {"timeout": timeout}}

    def pause(self, timeout=5.0):  # noqa: ANN001
        return {"ok": True, "command": "pause", "result": {"timeout": timeout}}

    def get_registers(self, names=None):  # noqa: ANN001
        return {"ok": True, "command": "get_registers", "result": {"registers": {"rip": "0x401000"}}}

    def disassemble(self, address, count=16):  # noqa: ANN001
        return {"ok": True, "command": "disassemble", "result": {"instructions": [{"address": address, "size": count}]}}

    def read_memory(self, address, size):  # noqa: ANN001
        return {"ok": True, "command": "read_memory", "result": {"address": address, "size": size, "bytes": "00"}}

    def list_memory_maps(self):
        return {"ok": True, "command": "list_memory_maps", "result": {"maps": {"regions": []}}}

    def run_until_address(self, address, timeout=5.0):  # noqa: ANN001
        return {"ok": True, "command": "run_until_address", "result": {"matched_address": address, "timeout": timeout}}

    def step(self, count=1, timeout=5.0):  # noqa: ANN001
        return {"ok": True, "command": "step", "result": {"count": count, "timeout": timeout}}

    def advance_basic_blocks(self, count=1, timeout=5.0):  # noqa: ANN001
        return {"ok": True, "command": "advance_basic_blocks", "result": {"count": count, "timeout": timeout}}

    def write_stdin(self, data):  # noqa: ANN001
        self.stdin_written += data
        return {"ok": True, "command": "write_stdin", "result": {"written": len(data)}}

    def read_stdout(self, cursor=0, max_chars=4096):  # noqa: ANN001
        self.stdout_cursors.append(cursor)
        return {"ok": True, "command": "read_stdout", "result": {"data": "abc", "cursor": cursor + 3, "eof": False, "max_chars": max_chars}}

    def read_stderr(self, cursor=0, max_chars=4096):  # noqa: ANN001
        self.stderr_cursors.append(cursor)
        return {"ok": True, "command": "read_stderr", "result": {"data": "", "cursor": cursor, "eof": False, "max_chars": max_chars}}

    def bp_add(self, address):  # noqa: ANN001
        return {"ok": True, "command": "bp_add", "result": {"address": address, "breakpoints": [address]}}

    def bp_del(self, address):  # noqa: ANN001
        return {"ok": True, "command": "bp_del", "result": {"address": address, "breakpoints": []}}

    def bp_list(self):
        return {"ok": True, "command": "bp_list", "result": {"breakpoints": []}}

    def bp_clear(self):
        return {"ok": True, "command": "bp_clear", "result": {"breakpoints": []}}

    def bp_run(self, timeout=5.0, max_steps=10000):  # noqa: ANN001
        del max_steps
        return {
            "ok": True,
            "command": "bp_run",
            "result": {"matched_address": "0x401000", "selected_address": "0x401000", "steps": 0, "timeout": timeout},
        }

def _server() -> InteractiveAnalysisMcpServer:
    return InteractiveAnalysisMcpServer(session_factory=FakeSession)


def test_mcp_initialize() -> None:
    server = _server()
    response = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert response is not None
    assert response["result"]["serverInfo"]["name"] == "dynamiq"
    assert "tools" in response["result"]["capabilities"]


def test_mcp_tools_list_contains_short_names() -> None:
    server = _server()
    response = server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    assert response is not None
    names = {item["name"] for item in response["result"]["tools"]}
    assert "start" in names
    assert "step" in names
    assert "run" in names
    assert "syms" in names
    assert "pause" in names
    assert "send_bytes" in names
    assert "send_line" in names
    assert "stdout" in names
    assert "bp_add" in names
    assert "bp_list" in names
    assert "stdin" not in names
    assert "stdin_file" not in names
    assert "until" not in names
    assert "bp_run" not in names


def test_mcp_tool_call_start() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "start",
                "arguments": {"target": "/tmp/a.out", "args": ["x"], "qemu_config": {}},
            },
        }
    )
    assert response is not None
    result = response["result"]
    assert result["isError"] is False
    assert result["structuredContent"]["result"]["target"] == "/tmp/a.out"


def test_mcp_tool_call_start_defaults_launch_true() -> None:
    fake = FakeSession()
    server = InteractiveAnalysisMcpServer(session_factory=lambda: fake)
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tools/call",
            "params": {
                "name": "start",
                "arguments": {"target": "/tmp/a.out"},
            },
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    assert fake.last_qemu_config == {"launch": True}


def test_mcp_tool_call_start_auto_restarts_existing_session() -> None:
    fake = FakeSession()
    server = InteractiveAnalysisMcpServer(session_factory=lambda: fake)
    first = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 41,
            "method": "tools/call",
            "params": {"name": "start", "arguments": {"target": "/tmp/a.out"}},
        }
    )
    assert first is not None and first["result"]["isError"] is False
    second = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {"name": "start", "arguments": {"target": "/tmp/b.out"}},
        }
    )
    assert second is not None
    assert second["result"]["isError"] is False
    assert fake.close_calls == 1


def test_mcp_server_shutdown_closes_active_session() -> None:
    fake = FakeSession()
    server = InteractiveAnalysisMcpServer(session_factory=lambda: fake)
    server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 51,
            "method": "tools/call",
            "params": {"name": "start", "arguments": {"target": "/tmp/a.out"}},
        }
    )
    server.shutdown()
    assert fake.close_calls == 1


def test_mcp_tool_call_unknown_tool_returns_error() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "nope", "arguments": {}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is True


def test_mcp_tool_call_send_bytes() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 55,
            "method": "tools/call",
            "params": {"name": "send_bytes", "arguments": {"data": "abc"}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    assert response["result"]["structuredContent"]["result"]["written"] == 3


def test_mcp_tool_call_send_line_appends_newline() -> None:
    fake = FakeSession()
    server = InteractiveAnalysisMcpServer(session_factory=lambda: fake)
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 56,
            "method": "tools/call",
            "params": {"name": "send_line", "arguments": {"line": "hello"}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    assert fake.stdin_written == "hello\n"


def test_mcp_tool_call_send_line_without_line_sends_newline_only() -> None:
    fake = FakeSession()
    server = InteractiveAnalysisMcpServer(session_factory=lambda: fake)
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 57,
            "method": "tools/call",
            "params": {"name": "send_line", "arguments": {}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    assert fake.stdin_written == "\n"


def test_mcp_tool_call_send_file(tmp_path) -> None:  # noqa: ANN001
    fake = FakeSession()
    server = InteractiveAnalysisMcpServer(session_factory=lambda: fake)
    payload = tmp_path / "payload.txt"
    payload.write_text("A\nB", encoding="utf-8")

    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 575,
            "method": "tools/call",
            "params": {
                "name": "send_file",
                "arguments": {"path": str(payload), "append_newline": True},
            },
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    assert fake.stdin_written == "A\nB\n"
    assert response["result"]["structuredContent"]["written"] == 4


def test_mcp_stdout_uses_internal_cursor_progression() -> None:
    fake = FakeSession()
    server = InteractiveAnalysisMcpServer(session_factory=lambda: fake)
    first = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 58,
            "method": "tools/call",
            "params": {"name": "stdout", "arguments": {"max_chars": 16}},
        }
    )
    second = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 59,
            "method": "tools/call",
            "params": {"name": "stdout", "arguments": {"max_chars": 16}},
        }
    )
    assert first is not None and second is not None
    assert fake.stdout_cursors == [0, 3]


def test_mcp_tool_call_resume() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"name": "run", "arguments": {"timeout": 1.5}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    assert response["result"]["structuredContent"]["command"] == "resume"


def test_mcp_tool_call_run_uses_breakpoint_when_configured() -> None:
    class BreakpointSession(FakeSession):
        def bp_list(self):
            return {"ok": True, "command": "bp_list", "result": {"breakpoints": ["0x401000"]}}

    server = InteractiveAnalysisMcpServer(session_factory=BreakpointSession)
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 601,
            "method": "tools/call",
            "params": {"name": "run", "arguments": {"timeout": 1.5}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    assert response["result"]["structuredContent"]["command"] == "bp_run"


def test_mcp_tool_call_bp_add() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 81,
            "method": "tools/call",
            "params": {"name": "bp_add", "arguments": {"address": "0x401000"}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    assert response["result"]["structuredContent"]["result"]["address"] == "0x401000"


def test_mcp_tool_call_syms() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 91,
            "method": "tools/call",
            "params": {"name": "syms", "arguments": {"max_count": 10, "name_filter": "main"}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    assert response["result"]["structuredContent"]["result"]["symbols"][0]["name"] == "main"
