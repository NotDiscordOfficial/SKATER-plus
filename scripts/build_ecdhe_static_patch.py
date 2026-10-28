#!/usr/bin/env python3
"""Build the static New 3DS browser ECDHE-RSA experiment.

This expands the executable CRO segment, injects the Thumb P-256 payload,
redirects the two OpenSSL client key-exchange decision points, and repurposes
the existing DHE-GCM cipher records as ECDHE-RSA-GCM records.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from expand_cro_text import rewrite_hashes, transform
from lz11_codec import compress as lz11_compress


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "input" / "oss.cro"
PAYLOAD = ROOT / "payload" / "payload-rsa-ecdsa.bin"
CLIENTHELLO_HOOK = ROOT / "payload" / "clienthello_hook.bin"
CIPHER_LOOKUP = ROOT / "payload" / "cipher_lookup_linear.bin"
OUT_DIR = ROOT / "build"
RAW_OUT = OUT_DIR / "oss-tls12.cro"
LEX_OUT = OUT_DIR / "oss-tls12.cro.lex"
SOURCE_SHA256 = "BDD428C371717B0741CCFC118BABB355BFB6D2F3585BACE2E4DDEEE2723C87DE"
RAW_SHA256 = "46DFD13D1C24434BFEB165EB7EC899C21A0AC66F6264BCEB7B29E78413F174E8"
LEX_SHA256 = "48A5882C7A31B1365160468808695587DC58AF977F7AEDD08A8B115772D3BC9A"
STOCK_CIPHER_LOOKUP = bytes.fromhex(
    "00b50178427803208db000060902081810430290064947226846e1f777fe00280"
    "2d00168002900d100200db000bd0000"
)


def replace_exact(buf: bytearray, off: int, old: bytes, new: bytes) -> None:
    actual = bytes(buf[off:off + len(old)])
    if actual != old:
        raise RuntimeError(f"unexpected bytes at 0x{off:X}: {actual.hex()} != {old.hex()}")
    if len(old) != len(new):
        raise ValueError("replacement must preserve size")
    buf[off:off + len(new)] = new


def thumb_bl(source_rel: int, target_rel: int) -> bytes:
    displacement = target_rel - (source_rel + 4)
    if displacement & 1 or not -(1 << 22) <= displacement < (1 << 22):
        raise ValueError(f"Thumb BL out of range: 0x{source_rel:X} -> 0x{target_rel:X}")
    first = 0xF000 | ((displacement >> 12) & 0x7FF)
    second = 0xF800 | ((displacement >> 1) & 0x7FF)
    return first.to_bytes(2, "little") + second.to_bytes(2, "little")


def retarget_internal_relocation(
    buf: bytearray,
    output_offset: int,
    referred_segment: int,
    addend: int,
) -> None:
    """Retarget one existing absolute CRO relocation by its output address."""
    reloc_off, reloc_count = struct.unpack_from("<II", buf, 0x128)
    matches = []
    for index in range(reloc_count):
        entry = reloc_off + index * 12
        encoded_output, patch_type = struct.unpack_from("<IB", buf, entry)
        if (encoded_output & 0xF) == 0 and (encoded_output >> 4) == output_offset:
            matches.append((entry, patch_type))
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one relocation for text+0x{output_offset:X}, got {len(matches)}"
        )
    entry, patch_type = matches[0]
    if patch_type != 2:
        raise RuntimeError(f"unexpected relocation type {patch_type} at 0x{entry:X}")
    buf[entry + 5] = referred_segment
    struct.pack_into("<I", buf, entry + 8, addend)


def append_payload_relocations(buf: bytearray) -> bytearray:
    """Add CRO loader relocations for the payload's five local pointers."""
    reloc_off = struct.unpack_from("<I", buf, 0x128)[0]
    reloc_count = struct.unpack_from("<I", buf, 0x12C)[0]
    insertion = reloc_off + reloc_count * 12
    old_bss_size = struct.unpack_from("<I", buf, 0x94)[0]
    pointer_relocs = (
        (0x145950 + 0x504, 0, 0x146984),
        (0x145950 + 0xEC4, 0, 0x146980),
        (0x145950 + 0x10D4, 0, 0x146231),
        (0x145950 + 0x10D8, 0, 0x146385),
        (0x145950 + 0x10DC, 0, 0x145CAD),
        # micro-ecc's zero-initialized g_rng_function pointer.
        (0x145950 + 0x5D0, 3, old_bss_size),
        (0x145950 + 0xEBC, 3, old_bss_size),
        (0x145950 + 0xF84, 3, old_bss_size),
    )
    entries = bytearray()
    for output_offset, referred_segment, addend in pointer_relocs:
        # CroSegmentOffset: low nibble is output segment index (text=0).
        entries += struct.pack(
            "<IBBBBI", output_offset << 4, 2, referred_segment, 0, 0, addend
        )

    old = bytes(buf)
    out = bytearray(old[:insertion] + entries + old[insertion:])
    delta = len(entries)

    # Header fields that are physical file offsets.
    for field in (0x84, 0xB0, 0xB8, 0xC0, 0xC8, 0xD0, 0xD8, 0xE0,
                  0xE8, 0xF0, 0xF8, 0x100, 0x108, 0x110, 0x118, 0x120,
                  0x128, 0x130):
        value = struct.unpack_from("<I", old, field)[0]
        if value >= insertion and value != 0:
            struct.pack_into("<I", out, field, value + delta)
    struct.pack_into("<I", out, 0x90, len(out))
    struct.pack_into("<I", out, 0x12C, reloc_count + len(pointer_relocs))

    # The segment table itself is before the insertion. Move physical segment
    # offsets at/after the inserted relocation entries (normally data only).
    segment_off = struct.unpack_from("<I", out, 0xC8)[0]
    segment_count = struct.unpack_from("<I", out, 0xCC)[0]
    for index in range(segment_count):
        entry = segment_off + index * 12
        file_offset = struct.unpack_from("<I", out, entry)[0]
        kind = struct.unpack_from("<I", out, entry + 8)[0]
        if kind != 3 and file_offset >= insertion and file_offset != 0:
            struct.pack_into("<I", out, entry, file_offset + delta)
        if kind == 3:
            struct.pack_into("<I", out, entry + 4, old_bss_size + 4)
    struct.pack_into("<I", out, 0x94, old_bss_size + 4)

    # Verify the appended records before hashes are recalculated.
    new_reloc_off = struct.unpack_from("<I", out, 0x128)[0]
    appended = new_reloc_off + reloc_count * 12
    if out[appended:appended + delta] != entries:
        raise AssertionError("payload relocation entries were not appended intact")
    return out


def main() -> None:
    source = SOURCE.read_bytes()
    source_sha = hashlib.sha256(source).hexdigest().upper()
    if source_sha != SOURCE_SHA256:
        raise RuntimeError(
            f"unsupported oss.cro {source_sha}; expected {SOURCE_SHA256}"
        )
    # The linked image begins at segment offset 0x145950. The original text
    # ends at 0x14594C, so preserve the linker's four-byte alignment gap.
    payload = PAYLOAD.read_bytes()
    clienthello_hook = CLIENTHELLO_HOOK.read_bytes()
    cipher_lookup = CIPHER_LOOKUP.read_bytes()
    if len(cipher_lookup) != 0x30:
        raise RuntimeError("linear cipher lookup must occupy exactly 0x30 bytes")
    clienthello_hook_rel = 0x145950 + len(payload)
    sigid_table_rel = clienthello_hook_rel + len(clienthello_hook)
    if sigid_table_rel & 3:
        raise RuntimeError("signature-id lookup table is not word aligned")
    # tls12_lookup {EVP_PKEY nid, TLS signature id}.  Keep the stock RSA
    # mapping and add EVP_PKEY_EC/NID_X9_62_id_ecPublicKey -> ECDSA.  This is
    # data in the expanded text mapping, not executable hook code.
    sigid_table = struct.pack("<IIII", 6, 1, 408, 3)
    # Keep the expanded text segment byte-for-byte the same size as the last
    # bootable candidate.  The old executable helper occupied 18 bytes; the
    # replacement table occupies 16.  The two-byte tail padding prevents the
    # CRO/module allocation layout from changing during this isolated fix.
    injected = b"\x00" * 4 + payload + clienthello_hook + sigid_table + b"\x00\x00"
    expanded, info = transform(source, 0x2000, injected)
    out = bytearray(expanded)

    # ssl3_get_cipher_by_char originally uses bsearch over ssl3_ciphers.  The
    # four repurposed records below necessarily make that old, fixed-size
    # table non-monotonic (00A1, C02B, C02C, 00A4), so bsearch cannot find the
    # new suites.  Replace only this 0x30-byte lookup body with a bounded linear
    # scan.  Its existing relocated table literal at text+0x76560 is retained.
    replace_exact(
        out,
        0x766B0,
        STOCK_CIPHER_LOOKUP,
        cipher_lookup,
    )

    # Nintendo built tls12_get_sigid with a one-entry table.  Make the stock
    # function search two entries and redirect its existing literal relocation
    # to the read-only table above.  The call site at 0xBC0AE remains stock.
    replace_exact(out, 0x8B992, bytes.fromhex("0122"), bytes.fromhex("0222"))
    retarget_internal_relocation(out, 0x8B81C, 0, sigid_table_rel)

    # TLS_DHE_RSA_WITH_AES_128/256_GCM -> ECDHE_RSA equivalents. Data moved
    # by 0x2000 because the executable expansion was inserted before rodata.
    replace_exact(out, 0x1CD258, bytes.fromhex("9E000003"), bytes.fromhex("2FC00003"))
    replace_exact(out, 0x1CD25C, bytes.fromhex("08000000"), bytes.fromhex("80000000"))
    replace_exact(out, 0x1CD288, bytes.fromhex("9F000003"), bytes.fromhex("30C00003"))
    replace_exact(out, 0x1CD28C, bytes.fromhex("08000000"), bytes.fromhex("80000000"))

    # Preserve the active DHE-RSA CBC 0033/0039 records; the outgoing hook
    # rewrites those advertised slots only, after OpenSSL builds its list.
    # Repurpose the otherwise unused DHE-DSS-GCM
    # records as the real ECDHE-ECDSA records used to parse ServerHello.
    replace_exact(out, 0x1CD318, bytes.fromhex("A2000003"), bytes.fromhex("2BC00003"))
    replace_exact(out, 0x1CD31C, bytes.fromhex("08000000"), bytes.fromhex("80000000"))
    replace_exact(out, 0x1CD320, bytes.fromhex("02000000"), bytes.fromhex("40000000"))
    replace_exact(out, 0x1CD348, bytes.fromhex("A3000003"), bytes.fromhex("2CC00003"))
    replace_exact(out, 0x1CD34C, bytes.fromhex("08000000"), bytes.fromhex("80000000"))
    replace_exact(out, 0x1CD350, bytes.fromhex("02000000"), bytes.fromhex("40000000"))

    # ssl3_get_server_hello: the wire hook advertises c02b/c02f after the
    # internal stack was built, so sk_SSL_CIPHER_find cannot see that pair.
    # Keep all earlier known/disabled-cipher checks and bypass only this final
    # offered-stack pointer check.  BGE and B below have the same target.
    replace_exact(out, 0xBCE62, bytes.fromhex("08DA"), bytes.fromhex("08E0"))

    # ssl3_get_key_exchange: replace BPL+CMP at file 0xBBEF6.
    replace_exact(
        out,
        0xBBEF6,
        bytes.fromhex("30D5022C"),
        thumb_bl(0xBBD76, 0x145950),
    )
    # ssl3_send_client_key_exchange: replace LSLS+CMP at file 0xBDDCE.
    replace_exact(
        out,
        0xBDDCE,
        bytes.fromhex("C1070029"),
        thumb_bl(0xBDC4E, 0x1459DC),
    )

    # ssl_add_clienthello_tlsext: rewrite the fixed extension tail inside
    # OpenSSL, before ssl3_do_write hashes the ClientHello.  The earlier
    # 0xBF87A site belongs to ssl_add_serverhello_tlsext and never runs in the
    # browser's client path.
    replace_exact(
        out,
        0xBF73C,
        bytes.fromhex("0298081A"),
        thumb_bl(0xBF5BC, clienthello_hook_rel),
    )

    # Deliberately leave the stock tls12_get_sigid call at 0xBC0AE intact.
    if out[0xBC22E:0xBC232] != bytes.fromhex("CFF7ADFB"):
        raise RuntimeError("stock tls12_get_sigid call was unexpectedly modified")

    out = append_payload_relocations(out)
    rewrite_hashes(out)
    # Preserve the original CRR-listed CRO identity. Luma permits patched
    # contents, while a newly calculated identity is not present in CRR.
    out[:0x80] = source[:0x80]
    if out[:0x80] != source[:0x80]:
        raise AssertionError("CRO identity hashes changed")
    raw = bytes(out)
    raw_sha = hashlib.sha256(raw).hexdigest().upper()
    if raw_sha != RAW_SHA256:
        raise RuntimeError(f"patched CRO hash mismatch: {raw_sha}")
    compressed = lz11_compress(raw)
    lex_sha = hashlib.sha256(compressed).hexdigest().upper()
    if lex_sha != LEX_SHA256:
        raise RuntimeError(f"compressed CRO hash mismatch: {lex_sha}")

    RAW_OUT.parent.mkdir(parents=True, exist_ok=True)
    RAW_OUT.write_bytes(raw)
    LEX_OUT.write_bytes(compressed)

    print(f"payload_file=0x{info['payload_offset']:X}")
    print(f"payload_segment=0x{info['payload_segment_offset']:X}")
    print(f"clienthello_hook_segment=0x{clienthello_hook_rel:X}")
    print(f"sigid_table_segment=0x{sigid_table_rel:X}")
    print(f"payload_size=0x{len(injected):X}")
    print(f"capacity=0x{info['capacity']:X}")
    print(f"raw_sha256={raw_sha}")
    print(f"lz11_sha256={lex_sha}")
    print(f"raw={RAW_OUT} size=0x{RAW_OUT.stat().st_size:X}")
    print(f"lz11={LEX_OUT} size=0x{LEX_OUT.stat().st_size:X}")


if __name__ == "__main__":
    main()
