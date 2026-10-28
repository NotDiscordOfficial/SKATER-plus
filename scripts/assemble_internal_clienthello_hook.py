#!/usr/bin/env python3
"""Build the in-OpenSSL ClientHello cipher/extension rewrite hook."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

from keystone import KS_ARCH_ARM, KS_MODE_LITTLE_ENDIAN, KS_MODE_THUMB, Ks


OUTPUT = ROOT / "payload" / "clienthello_hook.bin"

ASSEMBLY = r"""
    /* In the real client-extension function, r1 is the end pointer and
       caller stack+8 is the two-byte extensions-length field. */
    ldr     r0, [sp, #8]
    push    {r4, r5, r6, r7, lr}
    mov     r5, r0
    mov     r6, r1

    /* Replace the fixed 29-byte tail following variable-length SNI.  Validate
       both ends so an unexpected layout is left byte-for-byte unchanged. */
    mov     r7, r6
    subs    r7, #29
    cmp     r7, r5
    blo     finish
    ldrb    r0, [r7]
    cmp     r0, #0
    bne     finish
    ldrb    r0, [r7, #1]
    cmp     r0, #0x23
    bne     finish
    ldrb    r0, [r7, #25]
    cmp     r0, #0x33
    bne     finish
    ldrb    r0, [r7, #26]
    cmp     r0, #0x74
    bne     finish
    adr     r1, replacement
    movs    r2, #29
copy_tail:
    ldrb    r0, [r1]
    strb    r0, [r7]
    adds    r1, #1
    adds    r7, #1
    subs    r2, #1
    bne     copy_tail

    /* The cipher vector ends immediately before the compression bytes
       01 00 and the extension-length field at r5.  Find its length field
       backwards within the 38 bytes safely covered by every ClientHello
       prefix.  This avoids relying on SSL internal-structure offsets. */
    mov     r4, r5
    subs    r4, #2
    ldrb    r0, [r4]
    cmp     r0, #1
    bne     finish
    ldrb    r0, [r4, #1]
    cmp     r0, #0
    bne     finish
    movs    r2, #4
find_vector:
    mov     r1, r4
    subs    r1, r1, r2
    subs    r1, #2
    ldrb    r0, [r1]
    cmp     r0, #0
    bne     next_vector
    ldrb    r0, [r1, #1]
    cmp     r0, r2
    beq     found_vector
next_vector:
    adds    r2, #2
    cmp     r2, #38
    bls     find_vector
    b       finish
found_vector:
    adds    r1, #2
    /* Retain C02F/C030 and RSA-GCM for sites such as Yahoo; only change
       the active DHE-RSA CBC slots 0033/0039 to C02B/C02C. */
scan_suites:
    cmp     r1, r4
    bhs     finish
    ldrb    r2, [r1]
    cmp     r2, #0
    bne     next_suite
    ldrb    r2, [r1, #1]
    cmp     r2, #0x33
    beq     suite_128
    cmp     r2, #0x39
    bne     next_suite
    movs    r2, #0x2c
    b       write_suite
suite_128:
    movs    r2, #0x2b
write_suite:
    strb    r2, [r1, #1]
    movs    r2, #0xc0
    strb    r2, [r1]
next_suite:
    adds    r1, #2
    b       scan_suites

finish:
    subs    r0, r6, r5
    pop     {r4, r5, r6, r7, pc}

    .align 2
replacement:
    /* Two SHA-256 signature pairs make the replacement exactly 29 bytes.
       RSA is required by the advertised ECDHE-RSA suites; ECDSA also matches
       the ECDHE-ECDSA records added to the local cipher table. */
    .byte 0x00,0x0d,0x00,0x06,0x00,0x04,0x04,0x03,0x04,0x01
    .byte 0x00,0x0a,0x00,0x04,0x00,0x02,0x00,0x17
    .byte 0x00,0x0b,0x00,0x02,0x01,0x00
    .byte 0x00,0x0f,0x00,0x01,0x01
    .balign 4
"""

assembler = Ks(KS_ARCH_ARM, KS_MODE_THUMB | KS_MODE_LITTLE_ENDIAN)
encoded, statements = assembler.asm(ASSEMBLY, 0)
payload = bytes(encoded)
OUTPUT.write_bytes(payload)
print(f"statements={statements}")
print(f"size=0x{len(payload):X}")
print(f"output={OUTPUT}")

