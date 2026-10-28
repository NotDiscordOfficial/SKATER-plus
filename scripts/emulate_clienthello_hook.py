#!/usr/bin/env python3
"""Execute the actual Thumb hook in Unicorn with the real call-site registers."""

from __future__ import annotations

import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

from unicorn import Uc, UC_ARCH_ARM, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_MODE_THUMB
from unicorn.arm_const import (
    UC_ARM_REG_CPSR, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0,
    UC_ARM_REG_R1, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6,
    UC_ARM_REG_R7, UC_ARM_REG_SP,
)

CODE = 0x01000000
DATA = 0x02000000
STACK = 0x02100000
STOP = 0x03000000
HOOK = (ROOT / "payload" / "clienthello_hook.bin").read_bytes()
ORIGINAL = bytes.fromhex(
    "00230000000d000c000a06010501040103010201"
    "000f00010133740000"
)
REPLACEMENT = bytes.fromhex(
    "000d0006000404030401"
    "000a000400020017"
    "000b00020100"
    "000f000101"
)


def run(tail: bytes, ciphers: bytes, session_id: bytes = b"",
        captured_handshake: bytes | None = None) -> tuple[bytes, int, bytes]:
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    for base, size in ((CODE, 0x1000), (DATA, 0x4000),
                       (STACK, 0x2000), (STOP, 0x1000)):
        uc.mem_map(base, size)
    uc.mem_write(CODE, HOOK)
    ssl = DATA + 0x100
    init_buf = DATA + 0x200
    hello = DATA + 0x400
    if captured_handshake is None:
        orig = hello + 41 + len(session_id) + len(ciphers) + 2
        end = orig + 2 + 26 + len(tail)
        uc.mem_write(orig - 2, b"\x01\x00" + b"\x00\x00" + bytes(26) + tail)
    else:
        assert captured_handshake[0] == 1
        session_length = captured_handshake[38]
        suites_at = 39 + session_length
        suite_length = int.from_bytes(captured_handshake[suites_at:suites_at + 2], "big")
        orig = hello + suites_at + 2 + suite_length + 2
        end = orig + 2 + int.from_bytes(captured_handshake[orig - hello:orig - hello + 2], "big")
        assert captured_handshake[end - hello - len(tail):end - hello] == tail
        uc.mem_write(hello, captured_handshake)
    uc.mem_write(ssl + 0x3C, struct.pack("<I", init_buf))
    uc.mem_write(init_buf + 4, struct.pack("<I", hello))
    assert len(ciphers) % 2 == 0 and len(ciphers) <= 255
    assert len(session_id) <= 32
    if captured_handshake is None:
        uc.mem_write(hello + 38, bytes([len(session_id)]) + session_id
                     + struct.pack(">H", len(ciphers)) + ciphers)
    sp = STACK + 0x1000
    uc.mem_write(sp + 8, struct.pack("<I", orig))
    # Real call-site shape: r4 has been reused as a small temporary (0x1210
    # in the crash); r5 is s+0x100 from the function prologue.
    saved = [0x1210, ssl + 0x100, 0x33333333, 0x44444444]
    for reg, value in zip((UC_ARM_REG_R4, UC_ARM_REG_R5,
                           UC_ARM_REG_R6, UC_ARM_REG_R7), saved):
        uc.reg_write(reg, value)
    uc.reg_write(UC_ARM_REG_CPSR, 0x30)
    uc.reg_write(UC_ARM_REG_R1, end)
    uc.reg_write(UC_ARM_REG_SP, sp)
    uc.reg_write(UC_ARM_REG_LR, STOP | 1)
    stopped = {"ok": False}

    def stop(engine: Uc, address: int, _size: int, _user: object) -> None:
        if address == STOP:
            stopped["ok"] = True
            engine.emu_stop()

    uc.hook_add(UC_HOOK_CODE, stop)
    def invalid(engine: Uc, access: int, address: int, size: int,
                value: int, _user: object) -> bool:
        print(f"invalid access={access} address=0x{address:08X} size={size} "
              f"pc=0x{engine.reg_read(UC_ARM_REG_PC):08X} "
              f"r1=0x{engine.reg_read(UC_ARM_REG_R1):08X} "
              f"sp=0x{engine.reg_read(UC_ARM_REG_SP):08X}")
        return False
    uc.hook_add(UC_HOOK_MEM_INVALID, invalid)
    uc.emu_start(CODE | 1, STOP + 4, count=3000)
    assert stopped["ok"]
    assert uc.reg_read(UC_ARM_REG_SP) == sp
    assert [uc.reg_read(reg) for reg in
            (UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7)] == saved
    result = bytes(uc.mem_read(end - len(tail), len(tail)))
    return (result, uc.reg_read(UC_ARM_REG_R0),
            bytes(uc.mem_read(hello + 41 + len(session_id), len(ciphers))))


assert len(ORIGINAL) == len(REPLACEMENT) == 29
legacy = bytes.fromhex("c030c02f00390033")
patched, length, ciphers = run(ORIGINAL, legacy)
assert patched == REPLACEMENT, (patched.hex(), REPLACEMENT.hex())
assert length == 57, length
assert ciphers == bytes.fromhex("c030c02fc02cc02b"), ciphers.hex()
patched, length, ciphers = run(ORIGINAL, bytes.fromhex("0033c02f0039c030"))
assert patched == REPLACEMENT
assert ciphers == bytes.fromhex("c02bc02fc02cc030"), ciphers.hex()
long_list = bytes.fromhex(
    "c030c02f009d009c003d0035000a00390033"
)
patched, length, ciphers = run(ORIGINAL, long_list)
assert patched == REPLACEMENT
assert ciphers == long_list[:-4] + bytes.fromhex("c02cc02b"), ciphers.hex()
assert bytes.fromhex("009d009c003d0035") in ciphers
large_list = bytes.fromhex("009d009c003d0035000a") * 12 + bytes.fromhex("00330039")
patched, length, ciphers = run(ORIGINAL, large_list, bytes(range(32)))
assert patched == REPLACEMENT
assert ciphers == large_list, ciphers.hex()
unchanged, length, ciphers = run(b"\x12\x34" + ORIGINAL[2:], legacy)
assert unchanged == b"\x12\x34" + ORIGINAL[2:]
assert length == 57
assert ciphers == legacy
print("PASS Thumb hook executes, rewrites exact tail, returns length, preserves callee registers")
print("PASS offered 0033/0039 are rewritten independent of order; RSA fallback remains")
print("PASS overlong suite list is left unchanged by the bounded scan")
