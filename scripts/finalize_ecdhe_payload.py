#!/usr/bin/env python3
"""Install the ECDSA-aware key-exchange hook and verify the release payload."""

from __future__ import annotations

import hashlib
from pathlib import Path

from keystone import KS_ARCH_ARM, KS_MODE_LITTLE_ENDIAN, KS_MODE_THUMB, Ks


ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "build" / "payload-repro" / "payload-static.bin"
OUTPUT = ROOT / "build" / "payload-repro" / "payload-rsa-ecdsa.bin"
EXPECTED_SHA256 = "FEBEF0050C39711FAE40EE447F7B16BDD4B2168CEC908D0596F463EBFE7FEFB9"
ADDRESS = 0x145950
SLOT_SIZE = 0x8C
SEND_POINT_OFFSET = 0xAA
SEND_FREE_OFFSET = 0x164


ASSEMBLY = r"""
    ldr     r0, [sp, #0x24]
    cmp     r0, #0x80
    beq     ecdhe
    lsls    r2, r0, #23
    bmi     stock_rsa
    bl      0x000BBDDA
stock_rsa:
    bl      0x000BBD78

ecdhe:
    cmp     r4, #69
    blo     bad
    ldr     r0, [sp, #0x14]
    ldrh    r1, [r0, #0]
    cmp     r1, #3
    bne     bad
    ldrb    r1, [r0, #2]
    cmp     r1, #0x17
    bne     bad
    ldrb    r1, [r0, #3]
    cmp     r1, #65
    bne     bad

    bl      0x000ABD5C
    cmp     r0, #0
    beq     bad
    mov     r7, r0

    ldr     r0, [sp, #0x14]
    adds    r0, #5
    movs    r1, #64
    movs    r2, #0
    bl      0x000BA0AA
    cmp     r0, #0
    beq     free_dh
    str     r0, [r7, #0x14]

    ldr     r1, [r6]
    adds    r1, #0x80
    ldr     r1, [r1, #0x18]
    str     r7, [r1, #0x70]
    ldr     r0, [sp, #0x4c]
    cmp     r0, #0x40
    bne     rsa_cert
    adds    r1, #0x3c
rsa_cert:
    ldr     r0, [r1, #0x0c]
    bl      0x000B9B68
    cmp     r0, #0
    beq     detach
    str     r0, [sp, #8]

    movs    r0, #69
    str     r0, [sp, #0x20]
    ldr     r1, [sp, #0x14]
    adds    r1, #69
    str     r1, [sp, #0x14]
    subs    r4, #69
    bl      0x000BC04C

detach:
    ldr     r1, [r6]
    adds    r1, #0x80
    ldr     r1, [r1, #0x18]
    movs    r0, #0
    str     r0, [r1, #0x70]
free_dh:
    mov     r0, r7
    bl      0x000ABCC8
bad:
    bl      0x000BBCCC
"""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def main() -> None:
    payload = bytearray(INPUT.read_bytes())
    assembler = Ks(KS_ARCH_ARM, KS_MODE_THUMB | KS_MODE_LITTLE_ENDIAN)
    send_free, _ = assembler.asm("bl 0x000ABCC8", ADDRESS + SEND_FREE_OFFSET)
    expected_send_free = bytes(send_free)
    point_load = payload[SEND_POINT_OFFSET : SEND_POINT_OFFSET + 2]
    free_call = payload[SEND_FREE_OFFSET : SEND_FREE_OFFSET + 4]
    if point_load not in (bytes.fromhex("a768"), bytes.fromhex("6769")):
        raise SystemExit("unexpected send-hook DH.pub_key load")
    if free_call not in (bytes.fromhex("5ef720f9"), expected_send_free):
        raise SystemExit("unexpected send-hook free call")
    payload[SEND_POINT_OFFSET : SEND_POINT_OFFSET + 2] = bytes.fromhex("6769")
    payload[SEND_FREE_OFFSET : SEND_FREE_OFFSET + 4] = expected_send_free
    encoded, statements = assembler.asm(ASSEMBLY, ADDRESS)
    hook = bytes(encoded)
    if len(hook) > SLOT_SIZE or len(hook) & 1:
        raise SystemExit(f"invalid hook size 0x{len(hook):X}")
    payload[:SLOT_SIZE] = hook + bytes.fromhex("00bf") * ((SLOT_SIZE - len(hook)) // 2)

    actual_hash = sha256(payload)
    if actual_hash != EXPECTED_SHA256:
        raise SystemExit(
            f"unexpected final payload SHA-256: {actual_hash}; expected {EXPECTED_SHA256}"
        )
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_bytes(payload)
    print(f"statements={statements} hook_size=0x{len(hook):X}")
    print(f"output={OUTPUT} size=0x{len(payload):X} sha256={actual_hash}")


if __name__ == "__main__":
    main()
