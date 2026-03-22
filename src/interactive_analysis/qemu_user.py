from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from typing import Any


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
            qemu_user_path=str(qemu_config.get("qemu_user_path", "qemu-x86_64")),
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
        self._process: subprocess.Popen[str] | None = None
        self._config: QemuUserLaunchConfig | None = None

    @property
    def running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    @property
    def process(self) -> subprocess.Popen[str] | None:
        return self._process

    def start(self, config: QemuUserLaunchConfig) -> subprocess.Popen[str]:
        if self.running:
            raise RuntimeError("qemu-user process is already running")
        self._config = config
        self._process = subprocess.Popen(
            config.command(),
            cwd=config.cwd,
            env=config.environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=None if config.inherit_stderr else subprocess.PIPE,
            text=True,
        )
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
        self._process = None
        self._config = None

    def exited_summary(self) -> str | None:
        if self._process is None:
            return None
        returncode = self._process.poll()
        if returncode is None:
            return None
        stderr = ""
        if self._process.stderr is not None:
            try:
                stderr = self._process.stderr.read().strip()
            except Exception:
                stderr = ""
        stdout = ""
        if self._process.stdout is not None:
            try:
                stdout = self._process.stdout.read().strip()
            except Exception:
                stdout = ""
        parts = [f"qemu-user exited with code {returncode}"]
        if stderr:
            parts.append(f"stderr: {stderr}")
        elif stdout:
            parts.append(f"stdout: {stdout}")
        return "; ".join(parts)
