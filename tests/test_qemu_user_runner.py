from __future__ import annotations

from interactive_analysis.qemu_user import QemuUserLaunchConfig


def test_qemu_user_launch_config_builds_command_and_env() -> None:
    config = QemuUserLaunchConfig.from_target(
        target="./bin/sample",
        args=["a", "b"],
        cwd="/tmp/work",
        qemu_config={
            "qemu_user_path": "/usr/bin/qemu-x86_64",
            "qemu_args": ["-strace"],
            "instrumentation_socket_path": "/tmp/events.sock",
            "instrumentation_rpc_socket_path": "/tmp/rpc.sock",
            "env": {"FOO": "bar"},
        },
    )

    assert config.command() == ["/usr/bin/qemu-x86_64", "-strace", "./bin/sample", "a", "b"]
    env = config.environment()
    assert env["FOO"] == "bar"
    assert env["IA_EVENT_SOCKET"] == "/tmp/events.sock"
    assert env["IA_RPC_SOCKET"] == "/tmp/rpc.sock"
