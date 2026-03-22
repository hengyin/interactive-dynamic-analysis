from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

import pytest

from interactive_analysis.backends.qemu_user_instrumented import QemuUserInstrumentedBackend


def _compile_stdin_echo_binary(workdir: Path) -> Path:
    gcc = shutil.which("gcc")
    if gcc is None:
        pytest.skip("gcc is required for live stdin roundtrip test")
    source = workdir / "stdin_echo.c"
    binary = workdir / "stdin_echo"
    source.write_text(
        (
            "#include <stdio.h>\n"
            "#include <unistd.h>\n"
            "\n"
            "int main(void) {\n"
            "    char buf[256];\n"
            "    if (fgets(buf, sizeof(buf), stdin) == NULL) {\n"
            "        return 2;\n"
            "    }\n"
            "    printf(\"ECHO:%s\", buf);\n"
            "    fflush(stdout);\n"
            "    usleep(200000);\n"
            "    return 0;\n"
            "}\n"
        ),
        encoding="utf-8",
    )
    subprocess.run([gcc, str(source), "-O0", "-g", "-o", str(binary)], check=True)
    return binary


@pytest.mark.live_qemu
def test_live_qemu_stdin_roundtrip(tmp_path: Path) -> None:
    binary = _compile_stdin_echo_binary(tmp_path)
    backend = QemuUserInstrumentedBackend()

    qemu_user_path = str(Path.home() / "git" / "qemu" / "build-ia" / "qemu-x86_64")
    if not Path(qemu_user_path).exists():
        discovered = shutil.which("qemu-x86_64")
        if discovered is None:
            pytest.skip("qemu-x86_64 not found")
        qemu_user_path = discovered

    backend.start(
        target=str(binary),
        args=[],
        cwd=str(tmp_path),
        qemu_config={
            "launch": True,
            "qemu_user_path": qemu_user_path,
            "launch_connect_timeout": 5.0,
        },
    )
    try:
        backend.resume(timeout=1.0)
        backend.write_stdin("ping\n")
        cursor = 0
        seen = ""
        deadline = time.time() + 3.0
        while time.time() < deadline:
            out = backend.read_stdout(cursor=cursor, max_chars=4096)["result"]
            cursor = int(out["cursor"])
            chunk = str(out["data"])
            if chunk:
                seen += chunk
                if "ECHO:ping" in seen:
                    break
            time.sleep(0.05)

        assert "ECHO:ping" in seen
    finally:
        backend.close()

