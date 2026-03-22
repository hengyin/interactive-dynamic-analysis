from __future__ import annotations

import fcntl
import os
import pty
import shutil
import subprocess
import tty
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def resolve_qemu_user_path(qemu_config: dict[str, Any]) -> str:
    configured = qemu_config.get("qemu_user_path")
    if configured:
        return str(configured)
    preferred = Path.home() / "git" / "qemu" / "build-ia" / "qemu-x86_64"
    if preferred.exists():
        return str(preferred)
    discovered = shutil.which("qemu-x86_64")
    if discovered is not None:
        return discovered
    return "qemu-x86_64"


@dataclass(slots=True)
class QemuUserLaunchConfig:
    qemu_user_path: str = "qemu-x86_64"
    target: str = ""
    args: list[str] = field(default_factory=list)
    cwd: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    instrumentation_event_socket: str | None = None
    instrumentation_rpc_socket: str | None = None
    extra_args: list[str] = field(default_factory=list)
    inherit_stderr: bool = False

    @classmethod
    def from_target(
        cls,
        target: str,
        args: list[str] | None = None,
        cwd: str | None = None,
        qemu_config: dict[str, Any] | None = None,
    ) -> "QemuUserLaunchConfig":
        qemu_config = dict(qemu_config or {})
        return cls(
            qemu_user_path=resolve_qemu_user_path(qemu_config),
            target=target,
            args=list(args or []),
            cwd=cwd,
            env={str(key): str(value) for key, value in dict(qemu_config.get("env") or {}).items()},
            instrumentation_event_socket=qemu_config.get("instrumentation_socket_path"),
            instrumentation_rpc_socket=qemu_config.get("instrumentation_rpc_socket_path"),
            extra_args=[str(item) for item in list(qemu_config.get("qemu_args") or [])],
            inherit_stderr=bool(qemu_config.get("inherit_stderr", False)),
        )

    def command(self) -> list[str]:
        command = [self.qemu_user_path]
        command.extend(self.extra_args)
        command.append(self.target)
        command.extend(self.args)
        return command

    def environment(self) -> dict[str, str]:
        env = os.environ.copy()
        env.update(self.env)
        if self.instrumentation_event_socket:
            env["IA_EVENT_SOCKET"] = self.instrumentation_event_socket
        if self.instrumentation_rpc_socket:
            env["IA_RPC_SOCKET"] = self.instrumentation_rpc_socket
        return env

    def to_backend_config(self, launch: bool = True) -> dict[str, Any]:
        return {
            "launch": launch,
            "qemu_user_path": self.qemu_user_path,
            "instrumentation_socket_path": self.instrumentation_event_socket,
            "instrumentation_rpc_socket_path": self.instrumentation_rpc_socket,
            "qemu_args": list(self.extra_args),
            "env": dict(self.env),
            "inherit_stderr": self.inherit_stderr,
        }


class QemuUserProcessRunner:
    def __init__(self) -> None:
        self._process: subprocess.Popen[bytes] | None = None
        self._config: QemuUserLaunchConfig | None = None
        self._stdout_buffer = ""
        self._stderr_buffer = ""
        self._stdout_master_fd: int | None = None
        self._stdout_slave_fd: int | None = None

    @property
    def running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    @property
    def process(self) -> subprocess.Popen[bytes] | None:
        return self._process

    @property
    def config(self) -> QemuUserLaunchConfig | None:
        return self._config

    def start(self, config: QemuUserLaunchConfig) -> subprocess.Popen[bytes]:
        if self.running:
            raise RuntimeError("qemu-user process is already running")
        self._config = config
        self._stdout_buffer = ""
        self._stderr_buffer = ""
        self._close_stdout_pty()
        stdout_master, stdout_slave = pty.openpty()
        tty.setraw(stdout_master)
        tty.setraw(stdout_slave)
        self._stdout_master_fd = stdout_master
        self._stdout_slave_fd = stdout_slave
        try:
            self._process = subprocess.Popen(
                config.command(),
                cwd=config.cwd,
                env=config.environment(),
                stdin=subprocess.PIPE,
                stdout=stdout_slave,
                stderr=None if config.inherit_stderr else subprocess.PIPE,
                text=False,
            )
        except Exception:
            self._close_stdout_pty()
            raise
        self._close_stdout_slave_fd()
        if self._stdout_master_fd is not None:
            self._set_nonblocking(self._stdout_master_fd)
        if self._process.stderr is not None:
            self._set_nonblocking(self._process.stderr.fileno())
        return self._process

    def close(self) -> None:
        if self._process is None:
            return
        if self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=2.0)
        self._close_stdout_pty()
        self._process = None
        self._config = None

    def write_stdin(self, data: str) -> int:
        if self._process is None or self._process.stdin is None:
            raise RuntimeError("stdin is not available")
        if self._process.poll() is not None:
            raise RuntimeError("qemu-user process is not running")
        try:
            written = self._process.stdin.write(data.encode("utf-8", errors="replace"))
            self._process.stdin.flush()
        except BrokenPipeError as exc:
            raise RuntimeError("stdin is closed (target likely exited)") from exc
        return int(written or 0)

    def read_stdout(self, cursor: int = 0, max_chars: int = 4096) -> dict[str, Any]:
        self._drain_available_output()
        return self._read_stream("stdout", cursor, max_chars)

    def read_stderr(self, cursor: int = 0, max_chars: int = 4096) -> dict[str, Any]:
        self._drain_available_output()
        return self._read_stream("stderr", cursor, max_chars)

    def exited_summary(self) -> str | None:
        if self._process is None:
            return None
        returncode = self._process.poll()
        if returncode is None:
            return None
        self._drain_available_output()
        stderr = self._stderr_buffer.strip()
        stdout = self._stdout_buffer.strip()
        parts = [f"qemu-user exited with code {returncode}"]
        if stderr:
            parts.append(f"stderr: {stderr}")
        elif stdout:
            parts.append(f"stdout: {stdout}")
        return "; ".join(parts)

    def _drain_available_output(self) -> None:
        if self._process is None:
            return
        if self._stdout_master_fd is not None:
            self._drain_stream_fd(self._stdout_master_fd, "stdout")
        if self._process.stderr is not None:
            self._drain_stream_fd(self._process.stderr.fileno(), "stderr")

    def _drain_stream_fd(self, fd: int, stream_name: str) -> None:
        while True:
            try:
                raw = os.read(fd, 4096)
            except BlockingIOError:
                return
            except OSError:
                return
            if not raw:
                return
            chunk = raw.decode("utf-8", errors="replace")
            if stream_name == "stdout":
                self._stdout_buffer += chunk
            else:
                self._stderr_buffer += chunk

    def _read_stream(self, stream_name: str, cursor: int, max_chars: int) -> dict[str, Any]:
        if cursor < 0:
            raise ValueError("cursor must be >= 0")
        if max_chars < 1:
            raise ValueError("max_chars must be >= 1")
        if stream_name == "stdout":
            payload = self._stdout_buffer
        else:
            payload = self._stderr_buffer
        if cursor > len(payload):
            cursor = len(payload)
        end = min(len(payload), cursor + max_chars)
        data = payload[cursor:end]
        eof = self._process is None or self._process.poll() is not None
        return {"data": data, "cursor": end, "eof": eof}

    def _close_stdout_slave_fd(self) -> None:
        if self._stdout_slave_fd is None:
            return
        try:
            os.close(self._stdout_slave_fd)
        except OSError:
            pass
        self._stdout_slave_fd = None

    def _close_stdout_pty(self) -> None:
        self._close_stdout_slave_fd()
        if self._stdout_master_fd is None:
            return
        try:
            os.close(self._stdout_master_fd)
        except OSError:
            pass
        self._stdout_master_fd = None

    @staticmethod
    def _set_nonblocking(fd: int) -> None:
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
