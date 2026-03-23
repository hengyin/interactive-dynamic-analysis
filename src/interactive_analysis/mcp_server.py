from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .backends.qemu_user_instrumented import QemuUserInstrumentedBackend
from .errors import InvalidStateError, SessionTimeoutError
from .session import AnalysisSession


JSON = dict[str, Any]

MCP_PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "dynamiq"
SERVER_VERSION = "0.1.0"


@dataclass(slots=True)
class ToolSpec:
    name: str
    description: str
    input_schema: JSON

    def to_mcp(self) -> JSON:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


class InteractiveAnalysisMcpServer:
    def __init__(self, session_factory: Callable[[], AnalysisSession] | None = None) -> None:
        self._session_factory = session_factory or (lambda: AnalysisSession(backend=QemuUserInstrumentedBackend()))
        self._session: AnalysisSession | None = None
        self._stdout_cursor = 0
        self._stderr_cursor = 0
        self._tools: dict[str, ToolSpec] = {tool.name: tool for tool in self._build_tools()}

    def handle_request(self, request: JSON) -> JSON | None:
        method = request.get("method")
        request_id = request.get("id")
        params = request.get("params")
        params_dict = params if isinstance(params, dict) else {}

        if not isinstance(method, str):
            if request_id is None:
                return None
            return self._error(request_id, -32600, "invalid request: method must be a string")

        if method == "initialize":
            if request_id is None:
                return None
            return self._ok(
                request_id,
                {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                    "capabilities": {"tools": {}},
                },
            )

        if method == "notifications/initialized":
            return None

        if method == "tools/list":
            if request_id is None:
                return None
            return self._ok(request_id, {"tools": [tool.to_mcp() for tool in self._tools.values()]})

        if method == "tools/call":
            if request_id is None:
                return None
            name = params_dict.get("name")
            arguments = params_dict.get("arguments")
            if not isinstance(name, str):
                return self._error(request_id, -32602, "tools/call: missing tool name")
            if arguments is None:
                arguments_dict: JSON = {}
            elif isinstance(arguments, dict):
                arguments_dict = arguments
            else:
                return self._error(request_id, -32602, "tools/call: arguments must be an object")
            return self._ok(request_id, self._call_tool(name, arguments_dict))

        if method == "ping":
            if request_id is None:
                return None
            return self._ok(request_id, {})

        if request_id is None:
            return None
        return self._error(request_id, -32601, f"method not found: {method}")

    def _ensure_session(self) -> AnalysisSession:
        if self._session is None:
            self._session = self._session_factory()
        return self._session

    def _call_tool(self, name: str, arguments: JSON) -> JSON:
        if name not in self._tools:
            return self._tool_error(f"unknown tool: {name}")

        try:
            if name == "start":
                session = self._ensure_session()
                qemu_config = self._parse_object(arguments, "qemu_config", default={})
                qemu_config.setdefault("launch", True)
                target_value = arguments.get("target")
                if not isinstance(target_value, str) or target_value.strip() == "":
                    return self._tool_error(
                        "start requires non-empty string argument `target` "
                        '(example: {"target":"/home/heng/work2/KPRCA_00021"})'
                    )
                target = target_value.strip()
                # Reject malformed placeholder-like targets early to avoid
                # entering launch/connect timeout paths.
                if not self._looks_like_path_token(target):
                    return self._tool_error(
                        "start target appears malformed. "
                        "Provide a real target path."
                    )
                args = self._parse_string_list(arguments, "args", default=[])
                cwd = self._parse_optional_string(arguments, "cwd", default=None)
                try:
                    result = session.start(
                        target=target,
                        args=args,
                        cwd=cwd,
                        qemu_config=qemu_config,
                    )
                except InvalidStateError as exc:
                    if "session already started" not in str(exc):
                        raise
                    session.close()
                    result = session.start(
                        target=target,
                        args=args,
                        cwd=cwd,
                        qemu_config=qemu_config,
                    )
                self._reset_stream_cursors()
                return self._tool_ok(result)

            if name == "close":
                session = self._ensure_session()
                result = session.close()
                self._reset_stream_cursors()
                return self._tool_ok(result)

            if name == "caps":
                return self._tool_ok(self._ensure_session().capabilities())
            if name == "state":
                return self._tool_ok(self._ensure_session().get_state())
            if name == "syms":
                max_count = self._parse_int(arguments, "max_count", default=500, minimum=1)
                name_filter = self._parse_optional_string(arguments, "name_filter", default=None)
                return self._tool_ok(
                    self._ensure_session().symbols(
                        max_count=max_count,
                        name_filter=name_filter,
                    )
                )
            if name == "run":
                session = self._ensure_session()
                timeout = self._parse_positive_float(arguments, "timeout", default=5.0)
                bp_list_result = session.bp_list()
                breakpoints = bp_list_result.get("result", {}).get("breakpoints", [])
                try:
                    if isinstance(breakpoints, list) and len(breakpoints) > 0:
                        return self._tool_ok(session.bp_run(timeout=timeout))
                    return self._tool_ok(session.resume(timeout=timeout))
                except SessionTimeoutError as exc:
                    return self._tool_timeout(command="run", timeout=timeout, message=str(exc))
            if name == "pause":
                timeout = self._parse_positive_float(arguments, "timeout", default=5.0)
                try:
                    return self._tool_ok(self._ensure_session().pause(timeout=timeout))
                except SessionTimeoutError as exc:
                    return self._tool_timeout(command="pause", timeout=timeout, message=str(exc))
            if name == "regs":
                names = self._parse_optional_string_list(arguments, "names", default=None)
                return self._tool_ok(self._ensure_session().get_registers(names))
            if name == "disasm":
                address = self._parse_nonempty_string(arguments, "address")
                count = self._parse_int(arguments, "count", default=16, minimum=1)
                return self._tool_ok(
                    self._ensure_session().disassemble(
                        address=address,
                        count=count,
                    )
                )
            if name == "mem":
                address = self._parse_nonempty_string(arguments, "address")
                size = self._parse_int(arguments, "size", required=True, minimum=0)
                return self._tool_ok(
                    self._ensure_session().read_memory(
                        address=address,
                        size=size,
                    )
                )
            if name == "maps":
                return self._tool_ok(self._ensure_session().list_memory_maps())
            if name == "step":
                count = self._parse_int(arguments, "count", default=1, minimum=1)
                timeout = self._parse_positive_float(arguments, "timeout", default=5.0)
                return self._tool_ok(
                    self._ensure_session().step(
                        count=count,
                        timeout=timeout,
                    )
                )
            if name == "bb":
                count = self._parse_int(arguments, "count", default=1, minimum=1)
                timeout = self._parse_positive_float(arguments, "timeout", default=5.0)
                return self._tool_ok(
                    self._ensure_session().advance_basic_blocks(
                        count=count,
                        timeout=timeout,
                    )
                )
            if name == "bp_add":
                address = self._parse_nonempty_string(arguments, "address")
                return self._tool_ok(self._ensure_session().bp_add(address=address))
            if name == "bp_del":
                address = self._parse_nonempty_string(arguments, "address")
                return self._tool_ok(self._ensure_session().bp_del(address=address))
            if name == "bp_list":
                return self._tool_ok(self._ensure_session().bp_list())
            if name == "bp_clear":
                return self._tool_ok(self._ensure_session().bp_clear())
            if name == "send_bytes":
                data = arguments.get("data")
                data_hex = arguments.get("data_hex")
                if data is not None and data_hex is not None:
                    return self._tool_error("send_bytes accepts either `data` or `data_hex`, not both")
                if data_hex is not None:
                    if not isinstance(data_hex, str) or data_hex.strip() == "":
                        return self._tool_error(
                            "send_bytes `data_hex` must be a non-empty hex string "
                            '(example: {"data_hex":"040000000680ffffffffffff"})'
                        )
                    compact = "".join(data_hex.split())
                    if compact.startswith(("0x", "0X")):
                        compact = compact[2:]
                    try:
                        payload = bytes.fromhex(compact)
                    except ValueError:
                        return self._tool_error("send_bytes `data_hex` must contain only hex byte pairs")
                    if len(payload) == 0:
                        return self._tool_error("send_bytes decoded payload is empty")
                    return self._tool_ok(self._ensure_session().write_stdin(data=payload))
                if not isinstance(data, str) or data == "":
                    return self._tool_error(
                        "send_bytes requires non-empty string argument `data` or `data_hex` "
                        '(example: {"data":"1\\n"} or {"data_hex":"4142430a"})'
                    )
                return self._tool_ok(self._ensure_session().write_stdin(data=data))
            if name == "send_line":
                line = arguments.get("line", "")
                if not isinstance(line, str):
                    return self._tool_error(
                        "send_line requires string argument `line` "
                        '(example: {"line":"1"})'
                    )
                return self._tool_ok(self._ensure_session().write_stdin(data=f"{line}\n"))
            if name == "send_file":
                path_value = arguments.get("path")
                if not isinstance(path_value, str) or path_value.strip() == "":
                    return self._tool_error(
                        "send_file requires non-empty string argument `path` "
                        '(example: {"path":"/tmp/pov_input.txt"})'
                    )
                append_newline = self._parse_bool(arguments, "append_newline", default=False)
                path = Path(path_value)
                if not path.exists() or not path.is_file():
                    return self._tool_error(f"send_file path is not a readable file: {path_value}")
                total_written = 0
                session = self._ensure_session()
                with path.open("rb") as fp:
                    while True:
                        chunk = fp.read(4096)
                        if not chunk:
                            break
                        write_result = session.write_stdin(data=chunk)
                        total_written += int(write_result["result"].get("written", 0))
                if append_newline:
                    write_result = session.write_stdin(data=b"\n")
                    total_written += int(write_result["result"].get("written", 0))
                return self._tool_ok({"written": total_written, "path": str(path), "append_newline": append_newline})
            if name == "stdout":
                max_chars = self._parse_int(arguments, "max_chars", default=4096, minimum=1)
                wait_ms = self._parse_int(arguments, "wait_ms", default=150, minimum=0)
                result = self._read_stream_with_wait(
                    read_fn=self._ensure_session().read_stdout,
                    cursor=self._stdout_cursor,
                    max_chars=max_chars,
                    wait_ms=wait_ms,
                )
                payload = result.get("result") if isinstance(result, dict) else None
                if isinstance(payload, dict):
                    cursor = payload.get("cursor")
                    if isinstance(cursor, int) and cursor >= 0:
                        self._stdout_cursor = cursor
                return self._tool_ok(result)
            if name == "stderr":
                max_chars = self._parse_int(arguments, "max_chars", default=4096, minimum=1)
                wait_ms = self._parse_int(arguments, "wait_ms", default=150, minimum=0)
                result = self._read_stream_with_wait(
                    read_fn=self._ensure_session().read_stderr,
                    cursor=self._stderr_cursor,
                    max_chars=max_chars,
                    wait_ms=wait_ms,
                )
                payload = result.get("result") if isinstance(result, dict) else None
                if isinstance(payload, dict):
                    cursor = payload.get("cursor")
                    if isinstance(cursor, int) and cursor >= 0:
                        self._stderr_cursor = cursor
                return self._tool_ok(result)
            return self._tool_error(f"tool not implemented: {name}")
        except KeyError as exc:
            return self._tool_error(f"missing required argument: {exc.args[0]}")
        except Exception as exc:  # noqa: BLE001
            return self._tool_error(str(exc))

    def shutdown(self) -> None:
        if self._session is None:
            return
        try:
            self._session.close()
        except Exception:
            pass
        self._session = None
        self._reset_stream_cursors()

    def _reset_stream_cursors(self) -> None:
        self._stdout_cursor = 0
        self._stderr_cursor = 0

    @staticmethod
    def _parse_object(arguments: JSON, key: str, default: dict[str, Any] | None = None) -> dict[str, Any]:
        if key not in arguments:
            return dict(default or {})
        value = arguments.get(key)
        if not isinstance(value, dict):
            raise ValueError(f"{key} must be an object")
        return dict(value)

    @staticmethod
    def _parse_optional_string(arguments: JSON, key: str, default: str | None = None) -> str | None:
        if key not in arguments:
            return default
        value = arguments.get(key)
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError(f"{key} must be a string or null")
        return value

    @staticmethod
    def _parse_nonempty_string(arguments: JSON, key: str) -> str:
        value = arguments.get(key)
        if not isinstance(value, str) or value.strip() == "":
            raise ValueError(f"{key} must be a non-empty string")
        return value

    @staticmethod
    def _parse_string_list(arguments: JSON, key: str, default: list[str] | None = None) -> list[str]:
        if key not in arguments:
            return list(default or [])
        value = arguments.get(key)
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ValueError(f"{key} must be an array of strings")
        return list(value)

    @staticmethod
    def _parse_optional_string_list(arguments: JSON, key: str, default: list[str] | None = None) -> list[str] | None:
        if key not in arguments:
            return default
        value = arguments.get(key)
        if value is None:
            return None
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ValueError(f"{key} must be an array of strings")
        return list(value)

    @staticmethod
    def _parse_int(
        arguments: JSON,
        key: str,
        default: int | None = None,
        required: bool = False,
        minimum: int | None = None,
    ) -> int:
        if key not in arguments:
            if required:
                raise KeyError(key)
            if default is None:
                raise ValueError(f"{key} is required")
            value = default
        else:
            value = arguments.get(key)
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"{key} must be an integer")
        if minimum is not None and value < minimum:
            raise ValueError(f"{key} must be >= {minimum}")
        return value

    @staticmethod
    def _parse_positive_float(arguments: JSON, key: str, default: float) -> float:
        value = arguments.get(key, default)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{key} must be a number")
        parsed = float(value)
        if parsed <= 0:
            raise ValueError(f"{key} must be > 0")
        return parsed

    @staticmethod
    def _parse_bool(arguments: JSON, key: str, default: bool) -> bool:
        if key not in arguments:
            return default
        value = arguments.get(key)
        if not isinstance(value, bool):
            raise ValueError(f"{key} must be a boolean")
        return value

    @staticmethod
    def _looks_like_path_token(value: str) -> bool:
        # Accept common path-ish inputs (absolute/relative/POSIX/Windows-ish)
        # and reject punctuation-only placeholders (",", "[]", "{}", etc.).
        allowed_extra = {"/", "\\", ".", "_", "-", ":"}
        return any(ch.isalnum() or ch in allowed_extra for ch in value)

    @staticmethod
    def _read_stream_with_wait(
        read_fn: Callable[..., JSON],
        cursor: int,
        max_chars: int,
        wait_ms: int,
    ) -> JSON:
        if wait_ms < 0:
            raise ValueError("wait_ms must be >= 0")
        result = read_fn(cursor=cursor, max_chars=max_chars)
        payload = result.get("result")
        if not isinstance(payload, dict):
            return result
        data = payload.get("data")
        eof = bool(payload.get("eof"))
        current_cursor = payload.get("cursor")
        if isinstance(data, str) and data != "":
            return result
        if eof:
            return result
        if not isinstance(current_cursor, int) or current_cursor < 0:
            return result
        deadline = time.monotonic() + (wait_ms / 1000.0)
        poll_interval = 0.02
        while time.monotonic() < deadline:
            time.sleep(poll_interval)
            result = read_fn(cursor=current_cursor, max_chars=max_chars)
            payload = result.get("result")
            if not isinstance(payload, dict):
                return result
            data = payload.get("data")
            eof = bool(payload.get("eof"))
            next_cursor = payload.get("cursor")
            if isinstance(data, str) and data != "":
                return result
            if eof:
                return result
            if isinstance(next_cursor, int) and next_cursor >= 0:
                current_cursor = next_cursor
        return result

    @staticmethod
    def _tool_ok(payload: JSON) -> JSON:
        # Always include machine-readable JSON for text-only clients.
        text = json.dumps(
            {
                "ok": bool(payload.get("ok", True)),
                "command": payload.get("command", "tool"),
                "result": payload.get("result", {}),
            },
            sort_keys=True,
        )
        return {
            "content": [{"type": "text", "text": text}],
            "structuredContent": payload,
            "isError": False,
        }

    @staticmethod
    def _tool_error(message: str) -> JSON:
        return {
            "content": [{"type": "text", "text": message}],
            "isError": True,
        }

    @staticmethod
    def _tool_timeout(command: str, timeout: float, message: str) -> JSON:
        payload = {
            "ok": False,
            "command": command,
            "result": {"timed_out": True, "timeout": timeout, "message": message},
        }
        return {
            "content": [{"type": "text", "text": json.dumps(payload, sort_keys=True)}],
            "structuredContent": payload,
            "isError": False,
        }

    @staticmethod
    def _ok(request_id: Any, result: JSON) -> JSON:
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> JSON:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}

    @staticmethod
    def _build_tools() -> list[ToolSpec]:
        return [
            ToolSpec(
                name="start",
                description=(
                    "Start an analysis session for a target binary. "
                    "After start, session is typically paused. "
                    "Recommended next steps: syms -> bp_add (using loaded_address) -> run."
                ),
                input_schema={
                    "type": "object",
                    "description": "Session launch options.",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Absolute path to the guest binary to execute.",
                            "minLength": 1,
                        },
                        "args": {
                            "type": "array",
                            "description": "Command-line arguments passed to the guest binary.",
                            "items": {"type": "string"},
                            "default": [],
                        },
                        "cwd": {
                            "type": ["string", "null"],
                            "description": "Working directory for process launch.",
                            "default": None,
                        },
                        "qemu_config": {
                            "type": "object",
                            "description": (
                                "Optional backend launch settings. "
                                "If omitted, launch defaults to true."
                            ),
                            "properties": {
                                "launch": {
                                    "type": "boolean",
                                    "description": "Whether backend should launch qemu-user.",
                                    "default": True,
                                },
                                "qemu_user_path": {
                                    "type": "string",
                                    "description": "Path to qemu-x86_64 binary.",
                                },
                                "launch_connect_timeout": {
                                    "type": "number",
                                    "exclusiveMinimum": 0,
                                    "description": "Seconds to wait for RPC socket connectivity.",
                                },
                                "instrumentation_rpc_socket_path": {
                                    "type": "string",
                                    "description": "UNIX socket path for instrumentation RPC.",
                                },
                            },
                            "additionalProperties": True,
                            "default": {},
                        },
                    },
                    "required": ["target"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="close",
                description="Close the active analysis session.",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            ToolSpec(
                name="caps",
                description="Return backend capabilities.",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            ToolSpec(
                name="state",
                description=(
                    "Return full session state. "
                    "Use this to confirm session_status transitions (idle/paused/running/exited)."
                ),
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            ToolSpec(
                name="syms",
                description=(
                    "List ELF symbols and resolve runtime loaded addresses for THIS session. "
                    "Always use returned loaded_address for breakpoints; do not hardcode addresses across sessions."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "max_count": {"type": "integer", "minimum": 1, "default": 500},
                        "name_filter": {"type": ["string", "null"]},
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="run",
                description=(
                    "Run target execution. If breakpoints are configured, run until next breakpoint; "
                    "otherwise plain resume. "
                    "For interactive targets: run -> read stdout/stderr -> send input -> run. "
                    "A timeout is returned as non-fatal timed_out=true (not an MCP error)."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "timeout": {
                            "type": "number",
                            "exclusiveMinimum": 0,
                            "description": "RPC timeout in seconds.",
                            "default": 5.0,
                        }
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="pause",
                description="Pause target execution.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "timeout": {
                            "type": "number",
                            "exclusiveMinimum": 0,
                            "description": "RPC timeout in seconds.",
                            "default": 5.0,
                        }
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="regs",
                description="Read selected registers (or default set).",
                input_schema={
                    "type": "object",
                    "properties": {
                        "names": {
                            "type": "array",
                            "description": "Optional register names to read. If omitted, backend defaults are used.",
                            "items": {"type": "string"},
                        }
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="disasm",
                description="Disassemble code at a guest address.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Guest virtual address (hex string)."},
                        "count": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Maximum number of instructions to decode.",
                            "default": 16,
                        },
                    },
                    "required": ["address"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="mem",
                description="Read guest memory bytes.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Guest virtual address (hex string)."},
                        "size": {
                            "type": "integer",
                            "minimum": 0,
                            "description": "Number of bytes to read.",
                        },
                    },
                    "required": ["address", "size"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="maps",
                description="List current memory map regions.",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            ToolSpec(
                name="step",
                description="Single-step a number of instructions.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "count": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Instruction count to step.",
                            "default": 1,
                        },
                        "timeout": {
                            "type": "number",
                            "exclusiveMinimum": 0,
                            "description": "Maximum wait in seconds.",
                            "default": 5.0,
                        },
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="bb",
                description="Advance by a number of basic blocks.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "count": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Number of basic blocks to execute before pausing.",
                            "default": 1,
                        },
                        "timeout": {
                            "type": "number",
                            "exclusiveMinimum": 0,
                            "description": "Maximum wait in seconds.",
                            "default": 5.0,
                        },
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="bp_add",
                description=(
                    "Add a persistent breakpoint address. "
                    "Use syms.loaded_address from current session; avoid guessed static/base+offset addresses."
                ),
                input_schema={
                    "type": "object",
                    "properties": {"address": {"type": "string", "minLength": 1}},
                    "required": ["address"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="bp_del",
                description="Remove a persistent breakpoint address.",
                input_schema={
                    "type": "object",
                    "properties": {"address": {"type": "string", "minLength": 1}},
                    "required": ["address"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="bp_list",
                description="List configured persistent breakpoints.",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            ToolSpec(
                name="bp_clear",
                description="Clear all configured persistent breakpoints.",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            ToolSpec(
                name="send_bytes",
                description=(
                    "Pwntools-style raw send. Write data to target stdin immediately. "
                    "Session must be active (idle/running/paused). "
                    "Use `data` for text or `data_hex` for exact raw bytes."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "data": {
                            "type": "string",
                            "description": "Text data to write (UTF-8 encoding).",
                            "minLength": 1,
                        },
                        "data_hex": {
                            "type": "string",
                            "description": "Exact raw bytes encoded as hex (supports optional leading 0x).",
                            "minLength": 1,
                        },
                    },
                    "anyOf": [{"required": ["data"]}, {"required": ["data_hex"]}],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="send_line",
                description=(
                    "Pwntools-style line send. Appends a single '\\n' and writes to stdin. "
                    "If `line` is omitted, sends only newline. "
                    "Session must be active (idle/running/paused). "
                    "For menu flows, prefer send_line over send_bytes."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "line": {
                            "type": "string",
                            "description": "Line content without trailing newline.",
                            "default": "",
                        }
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="send_file",
                description=(
                    "Stream a local file's raw bytes into target stdin using fixed internal chunks. "
                    "Session must be active (idle/running/paused). "
                    "Use this for large payloads that are too long for a single send_bytes call."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Absolute or relative path to local input file.",
                            "minLength": 1,
                        },
                        "append_newline": {
                            "type": "boolean",
                            "description": "Append a final newline after file contents.",
                            "default": False,
                        },
                    },
                    "required": ["path"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="stdout",
                description=(
                    "Read next buffered stdout chunk (server maintains cursor internally). "
                    "Calls briefly wait for fresh output to reduce run/read races."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "max_chars": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Maximum characters to return in this chunk.",
                            "default": 4096,
                        },
                        "wait_ms": {
                            "type": "integer",
                            "minimum": 0,
                            "description": "Optional wait budget (ms) for new output before returning empty.",
                            "default": 150,
                        },
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="stderr",
                description=(
                    "Read next buffered stderr chunk (server maintains cursor internally). "
                    "Calls briefly wait for fresh output to reduce run/read races."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "max_chars": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Maximum characters to return in this chunk.",
                            "default": 4096,
                        },
                        "wait_ms": {
                            "type": "integer",
                            "minimum": 0,
                            "description": "Optional wait budget (ms) for new output before returning empty.",
                            "default": 150,
                        },
                    },
                    "additionalProperties": False,
                },
            ),
        ]


def run_stdio(server: InteractiveAnalysisMcpServer) -> int:
    try:
        for raw in sys.stdin:
            raw = raw.strip()
            if not raw:
                continue
            try:
                request = json.loads(raw)
            except json.JSONDecodeError:
                response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
            else:
                if not isinstance(request, dict):
                    response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}
                else:
                    response = server.handle_request(request)
            if response is not None:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
    finally:
        server.shutdown()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Interactive Dynamic Analysis MCP server (stdio)")
    parser.add_argument("--transport", choices=["stdio"], default="stdio")
    parser.parse_args()
    server = InteractiveAnalysisMcpServer()
    return run_stdio(server)


if __name__ == "__main__":
    raise SystemExit(main())
