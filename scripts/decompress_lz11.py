#!/usr/bin/env python3
"""Decompress Nintendo LZ11 streams."""

from __future__ import annotations

import argparse
from pathlib import Path


def decompress(data: bytes) -> bytes:
    if not data or data[0] != 0x11:
        raise ValueError("Not an LZ11 stream")
    size = int.from_bytes(data[1:4], "little")
    pos = 4
    if size == 0:
        size = int.from_bytes(data[4:8], "little")
        pos = 8
    out = bytearray()
    while len(out) < size:
        flags = data[pos]
        pos += 1
        for bit in range(7, -1, -1):
            if len(out) >= size:
                break
            if not (flags & (1 << bit)):
                out.append(data[pos])
                pos += 1
                continue

            first = data[pos]
            pos += 1
            indicator = first >> 4
            if indicator == 0:
                second, third = data[pos], data[pos + 1]
                pos += 2
                length = ((first & 0x0F) << 4 | (second >> 4)) + 0x11
                displacement = ((second & 0x0F) << 8 | third) + 1
            elif indicator == 1:
                second, third, fourth = data[pos], data[pos + 1], data[pos + 2]
                pos += 3
                length = ((first & 0x0F) << 12 | second << 4 | (third >> 4)) + 0x111
                displacement = ((third & 0x0F) << 8 | fourth) + 1
            else:
                second = data[pos]
                pos += 1
                length = indicator + 1
                displacement = ((first & 0x0F) << 8 | second) + 1

            if displacement > len(out):
                raise ValueError(f"Invalid displacement {displacement} at input 0x{pos:X}")
            for _ in range(length):
                out.append(out[-displacement])
                if len(out) >= size:
                    break
    return bytes(out)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    result = decompress(args.input.read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(result)
    print(f"{args.input.name}: {args.input.stat().st_size} -> {len(result)} bytes")


if __name__ == "__main__":
    main()
