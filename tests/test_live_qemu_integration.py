from __future__ import annotations

import pytest

from interactive_analysis.backends.qemu_user_instrumented import QemuUserInstrumentedBackend


@pytest.mark.live_qemu
def test_live_qemu_backend_smoke(live_qemu_start_kwargs: dict[str, object]) -> None:
    backend = QemuUserInstrumentedBackend()
    backend.start(**live_qemu_start_kwargs)

    caps = backend.capabilities()
    regs = backend.get_registers()
    maps = backend.list_memory_maps()
    state = backend.get_state()
    backend.close()

    assert caps["read_registers"] is True
    assert "registers" in regs["result"]
    assert "maps" in maps["result"]
    assert state["backend"] == "qemu_user_instrumented"
