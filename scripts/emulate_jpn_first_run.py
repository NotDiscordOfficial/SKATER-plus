#!/usr/bin/env python3
"""Exercise the Japanese first-run hooks in an isolated ARM11 Thumb VM."""

from __future__ import annotations

from unicorn import Uc, UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_THUMB
from unicorn.arm_const import (
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R6,
    UC_ARM_REG_SP,
)

from build_regional_tls_packages import (
    JPN_RESPONSE_HOOK,
    JPN_RESPONSE_HOOK_OFFSET,
    JPN_RESPONSE_PAYLOAD,
    JPN_RESPONSE_PAYLOAD_OFFSET,
    JPN_ZERO_LENGTH,
    JPN_ZERO_LENGTH_OFFSET,
)


BASE = 0x100000
STACK = 0x400000
DATA = 0x500000
GET_DOWNLOAD_SIZE_STATE = 0x306480


def machine() -> Uc:
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    uc.mem_map(BASE, 0x210000)
    uc.mem_write(BASE + JPN_ZERO_LENGTH_OFFSET, JPN_ZERO_LENGTH)
    uc.mem_write(BASE + JPN_RESPONSE_HOOK_OFFSET, JPN_RESPONSE_HOOK)
    uc.mem_write(BASE + JPN_RESPONSE_PAYLOAD_OFFSET, JPN_RESPONSE_PAYLOAD)
    uc.mem_map(STACK, 0x1000)
    uc.mem_map(DATA, 0x2000)
    uc.reg_write(UC_ARM_REG_SP, STACK + 0x800)
    return uc


def run_until(uc: Uc, entry: int, stop: int, downloaded: int = 0) -> None:
    reached = False

    def hook(current: Uc, address: int, _size: int, _opaque: object) -> None:
        nonlocal reached
        if address == GET_DOWNLOAD_SIZE_STATE:
            output = current.reg_read(UC_ARM_REG_R1)
            current.mem_write(output, downloaded.to_bytes(4, "little"))
            current.reg_write(UC_ARM_REG_R0, 0)
            current.reg_write(UC_ARM_REG_PC, current.reg_read(UC_ARM_REG_LR))
        elif address == stop:
            reached = True
            current.emu_stop()

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(entry | 1, BASE + 0x210000, count=100000)
    if not reached:
        raise AssertionError(f"expected stop 0x{stop:X} was not reached")


def check_zero_length() -> None:
    uc = machine()
    run_until(
        uc,
        BASE + JPN_ZERO_LENGTH_OFFSET,
        0x166D3C,
    )
    assert uc.reg_read(UC_ARM_REG_R6) == 4096


def check_body(body: bytes, expected: int) -> None:
    uc = machine()
    sp = uc.reg_read(UC_ARM_REG_SP)
    uc.mem_write(DATA, body)
    uc.mem_write(sp + 0x38, DATA.to_bytes(4, "little"))
    uc.mem_write(sp + 0x3C, len(body).to_bytes(4, "little"))
    run_until(
        uc,
        BASE + JPN_RESPONSE_HOOK_OFFSET,
        0x166E0A,
        len(body),
    )
    assert uc.reg_read(UC_ARM_REG_R0) == expected


def main() -> None:
    check_zero_length()
    check_body(b"regist_ok", 1)
    check_body(b"<html><body>regist_ok</body></html>", 1)
    check_body(b"<html><body>arid_error</body></html>", 0)
    check_body(b"regist_o", 0)
    check_body((b"x" * 4087) + b"regist_ok", 1)
    check_body((b"x" * 4096) + b"regist_ok", 0)
    print("PASS Japanese first-run hooks: bounded response and token checks")


if __name__ == "__main__":
    main()
