#!/usr/bin/env python3
"""Insert page-aligned space before CRO rodata and extend its text segment.

The transform preserves every byte except the inserted area, absolute file
offsets that must move, the text-segment size, and the four CRO hashes.
It is intentionally specific to documented CRO0 tables and validates every
offset before writing a candidate.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path


def u32(buf: bytes | bytearray, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def p32(buf: bytearray, off: int, value: int) -> None:
    struct.pack_into("<I", buf, off, value)


def moved(value: int, insertion: int, delta: int) -> int:
    return value + delta if value >= insertion and value != 0 else value


def table(buf: bytes | bytearray, off_field: int, count_field: int) -> tuple[int, int]:
    return u32(buf, off_field), u32(buf, count_field)


def check_range(size: int, off: int, length: int, label: str) -> None:
    if off < 0 or length < 0 or off + length > size:
        raise ValueError(f"{label} outside file: 0x{off:X}+0x{length:X} > 0x{size:X}")


def rewrite_hashes(buf: bytearray) -> None:
    code = u32(buf, 0xB0)
    module = u32(buf, 0xC0)
    data = u32(buf, 0xB8)
    data_size = u32(buf, 0xBC)
    bounds = ((0x80, code), (code, module), (module, data), (data, data + data_size))
    for index, (start, end) in enumerate(bounds):
        check_range(len(buf), start, end - start, f"hash region {index}")
        buf[index * 0x20:(index + 1) * 0x20] = hashlib.sha256(buf[start:end]).digest()


def lz11_literals(data: bytes) -> bytes:
    """Encode a valid, deliberately simple LZ11 stream using literal groups."""
    if len(data) > 0xFFFFFF:
        raise ValueError("input too large for short LZ11 header")
    out = bytearray((0x11, len(data) & 0xFF, (len(data) >> 8) & 0xFF,
                     (len(data) >> 16) & 0xFF))
    for pos in range(0, len(data), 8):
        out.append(0)
        out.extend(data[pos:pos + 8])
    return bytes(out)


def transform(source: bytes, delta: int, payload: bytes) -> tuple[bytes, dict[str, int]]:
    if source[0x80:0x84] != b"CRO0":
        raise ValueError("input is not CRO0")
    if delta <= 0 or delta % 0x1000:
        raise ValueError("insert size must be a positive multiple of 0x1000")
    if u32(source, 0x90) != len(source):
        raise ValueError("CRO file-size field does not match physical size")

    segment_off, segment_count = table(source, 0xC8, 0xCC)
    check_range(len(source), segment_off, segment_count * 12, "segment table")
    segments = [struct.unpack_from("<III", source, segment_off + i * 12)
                for i in range(segment_count)]
    text_indexes = [i for i, (_, size, kind) in enumerate(segments) if kind == 0 and size]
    ro_indexes = [i for i, (_, size, kind) in enumerate(segments) if kind == 1 and size]
    if len(text_indexes) != 1 or not ro_indexes:
        raise ValueError("expected exactly one non-empty text segment and at least one rodata segment")
    text_i = text_indexes[0]
    text_start, text_size, _ = segments[text_i]
    insertion = min(segments[i][0] for i in ro_indexes)
    text_end = text_start + text_size
    if text_end > insertion:
        raise ValueError("text overlaps insertion point")
    capacity = insertion + delta - text_end
    if len(payload) > capacity:
        raise ValueError(f"payload 0x{len(payload):X} exceeds executable capacity 0x{capacity:X}")

    out = bytearray(source[:insertion] + (b"\x00" * delta) + source[insertion:])

    # Header fields containing absolute file offsets.
    for field in (0x84, 0xB0, 0xB8, 0xC0, 0xC8, 0xD0, 0xD8, 0xE0,
                  0xE8, 0xF0, 0xF8, 0x100, 0x108, 0x110, 0x118, 0x120,
                  0x128, 0x130):
        p32(out, field, moved(u32(source, field), insertion, delta))
    p32(out, 0x90, len(source) + delta)
    p32(out, 0xB4, u32(source, 0xB4) + delta)

    # Segment table moved as a whole. Shift stored file offsets and extend text
    # only far enough to cover the injected payload.
    new_segment_off = segment_off + delta
    for i, (off, size, kind) in enumerate(segments):
        new_off = moved(off, insertion, delta) if kind != 3 else off
        new_size = size
        if i == text_i:
            new_size = text_size + len(payload)
        struct.pack_into("<III", out, new_segment_off + i * 12, new_off, new_size, kind)

    # File-offset fields embedded in metadata tables.
    def patch_entries(off_field: int, count_field: int, stride: int, members: tuple[int, ...]) -> None:
        old_off, count = table(source, off_field, count_field)
        if count == 0:
            return
        check_range(len(source), old_off, count * stride, f"table@0x{off_field:X}")
        new_off = moved(old_off, insertion, delta)
        for i in range(count):
            for member in members:
                old_value = u32(source, old_off + i * stride + member)
                p32(out, new_off + i * stride + member, moved(old_value, insertion, delta))

    patch_entries(0xD0, 0xD4, 8, (0,))          # named exports: name
    patch_entries(0xF0, 0xF4, 20, (0, 4, 12))   # import module: name/indexed/anon
    patch_entries(0x100, 0x104, 8, (0, 4))      # named import: name/patch list
    patch_entries(0x108, 0x10C, 8, (4,))        # indexed import: patch list
    patch_entries(0x110, 0x114, 8, (4,))        # anonymous import: patch list
    patch_entries(0x120, 0x124, 8, (0,))        # unknown relocation base

    payload_off = text_end
    out[payload_off:payload_off + len(payload)] = payload
    rewrite_hashes(out)

    # Final structural checks.
    if u32(out, 0x90) != len(out):
        raise AssertionError("output size mismatch")
    for index in range(4):
        starts = (0x80, u32(out, 0xB0), u32(out, 0xC0), u32(out, 0xB8))
        ends = (u32(out, 0xB0), u32(out, 0xC0), u32(out, 0xB8),
                u32(out, 0xB8) + u32(out, 0xBC))
        expected = hashlib.sha256(out[starts[index]:ends[index]]).digest()
        if out[index * 0x20:(index + 1) * 0x20] != expected:
            raise AssertionError(f"hash {index} mismatch")

    return bytes(out), {
        "insertion": insertion,
        "payload_offset": payload_off,
        "payload_segment_offset": payload_off - text_start,
        "capacity": capacity,
        "new_text_size": text_size + len(payload),
        "new_file_size": len(out),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--insert", type=lambda x: int(x, 0), default=0x2000)
    parser.add_argument("--payload", type=Path)
    parser.add_argument("--lz11-output", type=Path)
    args = parser.parse_args()
    payload = args.payload.read_bytes() if args.payload else b""
    result, info = transform(args.input.read_bytes(), args.insert, payload)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(result)
    if args.lz11_output:
        args.lz11_output.parent.mkdir(parents=True, exist_ok=True)
        args.lz11_output.write_bytes(lz11_literals(result))
    for key, value in info.items():
        print(f"{key}=0x{value:X}")
    print(f"sha256={hashlib.sha256(result).hexdigest().upper()}")
    if args.lz11_output:
        print(f"lz11={args.lz11_output} size=0x{args.lz11_output.stat().st_size:X}")


if __name__ == "__main__":
    main()
