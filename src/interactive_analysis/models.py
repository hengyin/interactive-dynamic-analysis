from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .errors import EventValidationError
from .events import normalize_address


@dataclass(slots=True)
class RegisterSnapshot:
    registers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_rpc_result(cls, payload: dict[str, Any]) -> "RegisterSnapshot":
        raw_registers = payload.get("registers")
        if not isinstance(raw_registers, dict):
            raise EventValidationError("register RPC result must contain a registers object")
        normalized: dict[str, str] = {}
        for name, value in raw_registers.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise EventValidationError("register names and values must be strings")
            normalized[name] = value.lower() if value.startswith(("0x", "0X")) else value
        return cls(registers=normalized)

    def to_dict(self) -> dict[str, Any]:
        return {"registers": dict(self.registers)}


@dataclass(slots=True)
class MemoryRegion:
    start: str
    end: str
    perm: str
    name: str | None = None
    path: str | None = None
    offset: str | None = None
    inode: int | None = None

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "MemoryRegion":
        perm = payload.get("perm")
        if not isinstance(perm, str):
            raise EventValidationError("memory map region perm must be a string")
        name = payload.get("name")
        if name is not None and not isinstance(name, str):
            raise EventValidationError("memory map region name must be a string or null")
        path = payload.get("path")
        if path is not None and not isinstance(path, str):
            raise EventValidationError("memory map region path must be a string or null")
        offset = payload.get("offset")
        if offset is not None and not isinstance(offset, str):
            raise EventValidationError("memory map region offset must be a string or null")
        inode = payload.get("inode")
        if inode is not None and not isinstance(inode, int):
            raise EventValidationError("memory map region inode must be an integer or null")
        return cls(
            start=normalize_address(payload.get("start")),
            end=normalize_address(payload.get("end")),
            perm=perm,
            name=name,
            path=path,
            offset=offset,
            inode=inode,
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "start": self.start,
            "end": self.end,
            "perm": self.perm,
            "name": self.name,
        }
        if self.path is not None:
            payload["path"] = self.path
        if self.offset is not None:
            payload["offset"] = self.offset
        if self.inode is not None:
            payload["inode"] = self.inode
        return payload


@dataclass(slots=True)
class MemoryMapSnapshot:
    regions: list[MemoryRegion] = field(default_factory=list)

    @classmethod
    def from_rpc_result(cls, payload: dict[str, Any]) -> "MemoryMapSnapshot":
        raw_regions = payload.get("regions")
        if not isinstance(raw_regions, list):
            raise EventValidationError("memory map RPC result must contain a regions list")
        return cls(regions=[MemoryRegion.from_dict(item) for item in raw_regions])

    def to_dict(self) -> dict[str, Any]:
        return {"regions": [item.to_dict() for item in self.regions]}


@dataclass(slots=True)
class MemoryReadResult:
    address: str
    size: int
    bytes: str

    @classmethod
    def from_rpc_result(cls, payload: dict[str, Any]) -> "MemoryReadResult":
        address = normalize_address(payload.get("address"))
        size = payload.get("size")
        value = payload.get("bytes")
        if not isinstance(size, int):
            raise EventValidationError("memory read RPC result size must be an integer")
        if size < 0 or size > 256:
            raise EventValidationError("memory read RPC result size must be between 0 and 256")
        if not isinstance(value, str):
            raise EventValidationError("memory read RPC result bytes must be a hex string")
        if len(value) % 2 != 0:
            raise EventValidationError("memory read RPC result bytes must have even length")
        return cls(address=address, size=size, bytes=value.lower())

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "size": self.size,
            "bytes": self.bytes,
        }
