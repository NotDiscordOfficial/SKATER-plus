#!/usr/bin/env python3
"""Assemble an order-independent ssl3_get_cipher_by_char replacement."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analysis-deps"))

from keystone import KS_ARCH_ARM, KS_MODE_LITTLE_ENDIAN, KS_MODE_THUMB, Ks


ADDRESS = 0x76530
CAPACITY = 0x30  # existing function body up to its relocated table literal
OUTPUT = ROOT / "payload" / "cipher_lookup_linear.bin"

ASSEMBLY = r"""
    push    {lr}
    ldrb    r2, [r0]
    ldrb    r3, [r0, #1]
    lsls    r2, r2, #8
    orrs    r2, r3
    movs    r3, #3
    lsls    r3, r3, #24
    orrs    r2, r3
    ldr     r0, [pc, #0x1c]
    movs    r1, #0x47
loop:
    ldr     r3, [r0, #8]
    cmp     r3, r2
    beq     found
    adds    r0, #0x30
    subs    r1, #1
    bne     loop
    movs    r0, #0
found:
    pop     {pc}
"""

assembler = Ks(KS_ARCH_ARM, KS_MODE_THUMB | KS_MODE_LITTLE_ENDIAN)
encoded, statements = assembler.asm(ASSEMBLY, ADDRESS)
payload = bytes(encoded)
if len(payload) > CAPACITY:
    raise SystemExit(f"payload is {len(payload)} bytes; capacity is {CAPACITY}")
payload = payload.ljust(CAPACITY, b"\x00")
OUTPUT.write_bytes(payload)
print(f"statements={statements} size={len(payload)} output={OUTPUT}")
