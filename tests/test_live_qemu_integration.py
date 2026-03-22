from __future__ import annotations

from pathlib import Path

import pytest

from interactive_analysis.backends.qemu_user_instrumented import QemuUserInstrumentedBackend


@pytest.mark.live_qemu
def test_live_qemu_backend_rpc_run_until_address(live_qemu_start_kwargs: dict[str, object]) -> None:
    backend = QemuUserInstrumentedBackend()
    backend.start(**live_qemu_start_kwargs)
    try:
        caps = backend.capabilities()
        regs = backend.get_registers(["rip"])
        rip = regs["result"]["registers"]["rip"]
        disassembly = backend.disassemble(rip, count=8)
        instructions = disassembly["result"]["instructions"]
        assert len(instructions) >= 2
        target_address = str(instructions[min(3, len(instructions) - 1)]["address"])

        stop = backend.run_until_address(target_address, timeout=5.0)
        regs_after = backend.get_registers(["rip"])
        state = backend.get_state()

        assert caps["read_registers"] is True
        assert caps["disassemble"] is True
        assert caps["run_until_address"] is True
        assert state["rpc_protocol_version"] == 1
        assert state["rpc_capabilities"]["read_registers"] is True
        assert state["rpc_capabilities"]["run_until_address"] is True
        assert stop["result"]["matched"] is True
        assert stop["result"]["matched_pc"] == target_address
        assert stop["result"]["pc"] == target_address
        assert regs_after["result"]["registers"]["rip"] == target_address
        assert state["pc"] == target_address
        assert state["backend"] == "qemu_user_instrumented"
    finally:
        backend.close()


@pytest.mark.live_qemu
def test_live_qemu_backend_list_memory_maps_schema(live_qemu_start_kwargs: dict[str, object]) -> None:
    backend = QemuUserInstrumentedBackend()
    backend.start(**live_qemu_start_kwargs)
    try:
        result = backend.list_memory_maps()
        maps = result["result"]["maps"]
        regions = maps["regions"]

        assert isinstance(regions, list)
        assert len(regions) > 0
        first = regions[0]
        assert {"start", "end", "perm", "name"} <= set(first.keys())
        assert isinstance(first["start"], str) and first["start"].startswith("0x")
        assert isinstance(first["end"], str) and first["end"].startswith("0x")
        assert isinstance(first["perm"], str) and len(first["perm"]) == 3
        assert first["name"] is None or isinstance(first["name"], str)

        target = str(Path(live_qemu_start_kwargs["target"]).resolve())
        names = {region.get("name") for region in regions if isinstance(region.get("name"), str)}
        assert target in names or "[stack]" in names
    finally:
        backend.close()


@pytest.mark.live_qemu
def test_live_qemu_backend_single_step(live_qemu_start_kwargs: dict[str, object]) -> None:
    backend = QemuUserInstrumentedBackend()
    backend.start(**live_qemu_start_kwargs)
    try:
        caps = backend.capabilities()
        assert caps["single_step"] is True

        rip = backend.get_registers(["rip"])["result"]["registers"]["rip"]
        disassembly = backend.disassemble(rip, count=2)
        instructions = disassembly["result"]["instructions"]
        assert len(instructions) >= 2
        next_pc = str(instructions[1]["address"])

        step = backend.step(1, timeout=5.0)
        regs_after = backend.get_registers(["rip"])

        assert step["result"]["status"] == "paused"
        assert step["result"]["executed"] == 1
        assert step["result"]["pc"] == next_pc
        assert regs_after["result"]["registers"]["rip"] == next_pc
    finally:
        backend.close()
