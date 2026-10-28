#!/usr/bin/env python3
"""Build the CRR needed by the patched base-browser CRO.

The input is a user-supplied 0x1000-byte SKATER static.crr.  Only the first
CRO identity entry is changed; no CRR file is stored in this repository.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_IDENTITY = bytes.fromhex(
    "61F2858086E6DAF21B8025F566256EC38E603E7D29426EE2F54BEF8F3108F695"
)
FIXED_IDENTITIES = (
    bytes.fromhex("6C0D715C217CC4CB373DC6921B6F0DB92475A340F6CBE04F78030C368F1214AB"),
    bytes.fromhex("EF7D94ED9B64B16A3047D461645CCE450C5F624187B95852636E0B0278682C8E"),
    bytes.fromhex("F502949C4A9AA608EC2340ED2EA55A089EAC08CAEF7D2EFE17006436A4090F78"),
)
OUTPUT_SHA256 = "86712C50A3E4C6256D8CC81A4B61331D6E9A1C46676941E0064289FF811F5422"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=ROOT / "input" / "static.crr")
    parser.add_argument("--output", type=Path, default=ROOT / "build" / "tlsfix.crr")
    args = parser.parse_args()

    source = bytearray(args.input.read_bytes())
    if len(source) != 0x1000:
        raise RuntimeError(f"unexpected CRR size 0x{len(source):X}")
    table_offset, count = struct.unpack_from("<II", source, 0x350)
    if table_offset != 0x360 or count != 4:
        raise RuntimeError(
            f"unexpected CRR table offset/count: 0x{table_offset:X}/{count}"
        )
    actual_fixed = tuple(
        bytes(source[table_offset + 32 * index:table_offset + 32 * (index + 1)])
        for index in range(1, 4)
    )
    if actual_fixed != FIXED_IDENTITIES:
        raise RuntimeError("unsupported CRR: fixed identity entries differ")

    source[table_offset:table_offset + 32] = OUTPUT_IDENTITY
    output = bytes(source)
    actual_hash = sha256(output)
    if actual_hash != OUTPUT_SHA256:
        raise RuntimeError(
            f"patched CRR hash mismatch: {actual_hash}; expected {OUTPUT_SHA256}"
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(output)
    print(f"output={args.output} sha256={actual_hash}")


if __name__ == "__main__":
    main()
