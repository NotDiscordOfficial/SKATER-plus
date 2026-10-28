#!/usr/bin/env python3
"""Rebase the reproducibly linked Thumb ECDHE payload into expanded oss.cro."""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB, Cs


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "build" / "payload-oldbase" / "payload-injected.bin"
OUTPUT = ROOT / "build" / "payload-repro" / "payload-static.bin"
SOURCE_SHA256 = "2952E748268E910D65389124F1236D97A5C561812B2E6B6095D447CFD6746B64"
OLD_BASE = 0x0016EFD8
NEW_BASE = 0x00145950
TEXT_END = 0x00170008


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def thumb_bl(source: int, target: int) -> bytes:
    displacement = target - (source + 4)
    if displacement & 1 or not -(1 << 22) <= displacement < (1 << 22):
        raise ValueError(f"Thumb BL out of range: 0x{source:X} -> 0x{target:X}")
    first = 0xF000 | ((displacement >> 12) & 0x7FF)
    second = 0xF800 | ((displacement >> 1) & 0x7FF)
    return struct.pack("<HH", first, second)


def main() -> None:
    payload = bytearray(SOURCE.read_bytes())
    actual_hash = sha256(payload)
    if actual_hash != SOURCE_SHA256:
        raise SystemExit(
            f"unexpected old-base payload SHA-256: {actual_hash}; expected {SOURCE_SHA256}"
        )

    old_end = OLD_BASE + len(payload)
    delta = NEW_BASE - OLD_BASE
    disassembler = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    external_calls: list[tuple[int, int]] = []
    for instruction in disassembler.disasm(payload[: TEXT_END - OLD_BASE], OLD_BASE):
        if instruction.mnemonic != "bl":
            continue
        try:
            target = int(instruction.op_str.lstrip("#"), 16)
        except ValueError:
            continue
        if OLD_BASE <= target < old_end:
            continue
        offset = instruction.address - OLD_BASE
        payload[offset : offset + 4] = thumb_bl(instruction.address + delta, target)
        external_calls.append((instruction.address + delta, target))

    rebased_pointers: list[tuple[int, int, int]] = []
    for offset in range(0, len(payload) - 3, 4):
        value = struct.unpack_from("<I", payload, offset)[0]
        bare = value & ~1
        if OLD_BASE <= bare < old_end:
            new_value = value + delta
            struct.pack_into("<I", payload, offset, new_value)
            rebased_pointers.append((offset, value, new_value))

    if len(external_calls) != 16:
        raise SystemExit(f"expected 16 external calls, found {len(external_calls)}")
    if len(rebased_pointers) != 5:
        raise SystemExit(f"expected 5 local pointers, found {len(rebased_pointers)}")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_bytes(payload)
    print(f"external_calls={len(external_calls)} local_pointers={len(rebased_pointers)}")
    print(f"output={OUTPUT} size=0x{len(payload):X} sha256={sha256(payload)}")


if __name__ == "__main__":
    main()
