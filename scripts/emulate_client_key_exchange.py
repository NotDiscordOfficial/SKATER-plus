#!/usr/bin/env python3
"""Execute the injected ClientKeyExchange path with deterministic crypto stubs."""

from __future__ import annotations

import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
from unicorn import Uc, UC_ARCH_ARM, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_MODE_THUMB
from unicorn.arm_const import (
    UC_ARM_REG_CPSR, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0,
    UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4,
    UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_SP,
)

# Load the committed payload at its linked CRO text address. All calls into
# the stock module are intercepted below, so no private browser image is needed.
PAYLOAD_OFFSET = 0x145950
TEXT = bytes(PAYLOAD_OFFSET) + (ROOT / "payload" / "payload-rsa-ecdsa.bin").read_bytes()
BASE = 0x01000000
MEM = 0x02000000
STACK = 0x02100000
SP = STACK + 0x10000
SSL = MEM + 0x1000
SESSION = MEM + 0x2000
SESS_CERT = MEM + 0x3000
DH = MEM + 0x4000
BN = MEM + 0x5000
METHOD = MEM + 0x6000
METHOD_TABLE = MEM + 0x7000
OUTPUT = MEM + 0x8000
CALLBACK = 0x03000000
FINISH = BASE + 0xBE108

uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
for base, size in ((BASE, (len(TEXT)+0xFFF)&~0xFFF), (MEM, 0x10000),
                   (STACK, 0x20000), (CALLBACK, 0x1000)):
    uc.mem_map(base, size)
uc.mem_write(BASE, TEXT)
def word(addr: int, value: int) -> None:
    uc.mem_write(addr, struct.pack("<I", value))

word(SSL+8, METHOD)
word(SSL+0xC0, SESSION)
word(SESSION+0x98, SESS_CERT)
word(SESS_CERT+0x70, DH)
word(DH+0x14, BN)
word(METHOD+0x64, METHOD_TABLE)
word(METHOD_TABLE+0x0C, CALLBACK | 1)
word(SP+0x290, OUTPUT)
word(SP+0x2A0, 0xDEADBEEF)
uc.reg_write(UC_ARM_REG_CPSR, 0x30)
uc.reg_write(UC_ARM_REG_R0, 0x80)
uc.reg_write(UC_ARM_REG_R5, SSL)
uc.reg_write(UC_ARM_REG_R6, SSL+0xC0)
uc.reg_write(UC_ARM_REG_SP, SP)

seen: list[str] = []
targets = {
    BASE+0xBA15A: "num_bits", BASE+0xBA070: "bn2bin",
    BASE+0xB8CDC: "random", BASE+0x145AC8: "ecdh",
    BASE+0xABCC8: "dh_free", CALLBACK: "master_secret",
}

def hook(engine: Uc, address: int, _size: int, _user: object) -> None:
    if address == FINISH:
        seen.append("finish")
        engine.emu_stop()
        return
    name = targets.get(address)
    if name is None:
        return
    seen.append(name)
    r0 = engine.reg_read(UC_ARM_REG_R0)
    r1 = engine.reg_read(UC_ARM_REG_R1)
    r2 = engine.reg_read(UC_ARM_REG_R2)
    r3 = engine.reg_read(UC_ARM_REG_R3)
    if name == "num_bits":
        assert r0 == BN
        result = 511
    elif name == "bn2bin":
        assert r0 == BN
        engine.mem_write(r1, bytes(range(64)))
        result = 64
    elif name == "random":
        assert r1 == 32
        engine.mem_write(r0, (2).to_bytes(32, "big"))
        result = 1
    elif name == "ecdh":
        assert bytes(engine.mem_read(r0, 32)) == (2).to_bytes(32, "big")
        assert bytes(engine.mem_read(r1, 64)) == bytes(range(64))
        engine.mem_write(r2, bytes(range(0x40, 0x80)))
        engine.mem_write(r3, bytes(range(0x80, 0xA0)))
        result = 1
    elif name == "master_secret":
        assert r0 == SSL and r1 == SESSION+0x14 and r3 == 32
        assert bytes(engine.mem_read(r2, 32)) == bytes(range(0x80, 0xA0))
        result = 1
    else:
        assert r0 == DH
        result = 0
    engine.reg_write(UC_ARM_REG_R0, result)
    engine.reg_write(UC_ARM_REG_PC, engine.reg_read(UC_ARM_REG_LR))

def invalid(engine: Uc, access: int, address: int, size: int,
            value: int, _user: object) -> bool:
    print(f"invalid access={access} address=0x{address:X} "
          f"pc=0x{engine.reg_read(UC_ARM_REG_PC):X} "
          f"r0=0x{engine.reg_read(UC_ARM_REG_R0):X} "
          f"sp=0x{engine.reg_read(UC_ARM_REG_SP):X} seen={seen}", flush=True)
    return False

uc.hook_add(UC_HOOK_CODE, hook)
uc.hook_add(UC_HOOK_MEM_INVALID, invalid)
uc.emu_start((BASE+0x1459DC)|1, FINISH+4, count=1000)
assert seen == ["num_bits", "bn2bin", "random", "ecdh", "master_secret", "dh_free", "finish"], seen
assert bytes(uc.mem_read(OUTPUT, 66)) == b"\x41\x04" + bytes(range(0x40, 0x80))
assert struct.unpack("<I", uc.mem_read(SESS_CERT+0x70, 4))[0] == 0
assert struct.unpack("<I", uc.mem_read(SESSION+0x10, 4))[0] == 1
assert uc.reg_read(UC_ARM_REG_R4) == 66
print("PASS ClientKeyExchange writes 65-byte uncompressed P-256 point")
print("PASS master-secret callback receives 32-byte shared secret")
print("PASS peer DH object is detached and released before stock continuation")
