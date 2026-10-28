#!/usr/bin/env python3
"""Rebuild regional SKATER executable IPS patches from user-owned dumps.

Place the supported decompressed code images in an input directory as
JPN.code.bin, USA.code.bin, KOR.code.bin, and EUR.code.bin.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PATCH_DIR = ROOT / "patches"

OLD_CRO = b"oss.cro.lex"
NEW_CRO = b"os2.cro.lex"
OLD_CRR = b".crr/static.crr"
NEW_CRR = b".crr/tlsfix.crr"
OLD_GOOGLE = b"http://www.google.com/search?client=ds&ie=utf-8&oe=utf-8&q=%s"
OLD_UA = (
    b"Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) "
    b"AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 "
    b"Mobile/10A403 Safari/8536.25"
)
NEW_UA = (
    b"Mozilla/5.0 (iPhone; CPU iPhone OS 7_0 like Mac OS X) "
    b"AppleWebKit/536.26 (KHTML, like Gecko) Version/7.0 "
    b"Mobile/11A465 Safari/8536.25"
)

# JPN revision 10178 official first-run registration compatibility.
JPN_REGISTRATION_URL_OFFSET = 0x67280
JPN_OLD_REGISTRATION_URL = b"https://sec.ifilter.jp/if/ars/regist.php\0"
JPN_NEW_REGISTRATION_URL = b"http://sec.ifilter.jp/if/ars/regist.php\0\0"
JPN_SKIP_TLS_OFFSET = 0x669E0
JPN_ZERO_LENGTH_OFFSET = 0x66D64
JPN_RESPONSE_HOOK_OFFSET = 0x66DF8
JPN_RESPONSE_PAYLOAD_OFFSET = 0x669E4
JPN_ZERO_LENGTH = bytes.fromhex("01263603e8e7c046c046")
JPN_RESPONSE_HOOK = bytes.fromhex("f4e5c046")
JPN_RESPONSE_PAYLOAD = bytes.fromhex(
    "06a805a904aa9ff14aed002819db0e99059a002915d0092a13d301231b039a42"
    "0fd8083a52180b680848834206d14b680748834202d10b7a6b2b04d001319142"
    "f1d30020efe10120ede100007265676973745f6f"
)

REGIONS = {
    "JPN": {
        "luma_title": "0004003000008802",
        "update_title": "0004003020008802",
        "source_sha256": "8B06E7D18DF8D9DFFFF161D26D3213A2C474888C35491CF0C96C709931C8D914",
        "output_sha256": "7F61C754757192D242228E71D932FD60C5C33325341F6C0E1FA5F1B2E851AC7A",
        "google": b"https://www.google.co.jp/search?q=%s&client=safari",
    },
    "USA": {
        "luma_title": "0004003000009402",
        "update_title": "0004003020009402",
        "source_sha256": "B2BD118F99D7FAF424A720B63004F92EDB299354989BA143EFA42B50144CE41C",
        "output_sha256": "1D9AD1106DF8FDB5A0DCB7F821F3822C1B2B4A74EE083BA9B472B149AF1CB6E3",
        "google": b"https://www.google.com/search?q=%s&client=safari",
    },
    "KOR": {
        "luma_title": "000400300000AE02",
        "update_title": "000400302000AE02",
        "source_sha256": "7308CE1B326AECA2A5BF468D7ACF661F5B5135E7F77A6FE355C8EF41D00158B4",
        "output_sha256": "D2700A6FE9D5E9E8B9742223268EC24FFE2B263B1BE9E9F2E35CF0AABAE49AED",
        "google": b"https://www.google.co.kr/search?q=%s&client=safari",
    },
    "EUR": {
        "luma_title": "0004003000009D02",
        "update_title": "0004003020009D02",
        "source_sha256": "748A5C276D3729F59BDD61541FC66DC5F78C23776BEABB982839522ABC729F28",
        "output_sha256": "1BBFF52D750F581363FAA6D040A298E87588BB4456408E0DC06B800FFA1A8705",
        "google": b"https://www.google.com/search?q=%s&client=safari",
    },
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def replace_once(data: bytes, old: bytes, new: bytes, name: str) -> bytes:
    count = data.count(old)
    if count != 1:
        raise RuntimeError(f"{name}: expected one match, found {count}")
    if len(old) != len(new):
        raise RuntimeError(f"{name}: size-changing replacement")
    return data.replace(old, new, 1)


def patch_jpn_registration(source: bytes) -> bytes:
    guards = {
        JPN_REGISTRATION_URL_OFFSET: JPN_OLD_REGISTRATION_URL,
        JPN_SKIP_TLS_OFFSET: bytes.fromhex("1bf070fb"),
        JPN_ZERO_LENGTH_OFFSET: bytes.fromhex("f8f00cfd049bf2a2efe7"),
        JPN_RESPONSE_HOOK_OFFSET: bytes.fromhex("0f990e98"),
    }
    for offset, expected in guards.items():
        if source[offset:offset + len(expected)] != expected:
            raise RuntimeError(f"JPN first-run guard failed at 0x{offset:X}")

    out = bytearray(source)
    out[JPN_REGISTRATION_URL_OFFSET:
        JPN_REGISTRATION_URL_OFFSET + len(JPN_NEW_REGISTRATION_URL)] = (
            JPN_NEW_REGISTRATION_URL
        )
    out[JPN_SKIP_TLS_OFFSET:JPN_SKIP_TLS_OFFSET + 4] = bytes.fromhex("2ee0c046")
    out[JPN_ZERO_LENGTH_OFFSET:JPN_ZERO_LENGTH_OFFSET + len(JPN_ZERO_LENGTH)] = (
        JPN_ZERO_LENGTH
    )
    out[JPN_RESPONSE_HOOK_OFFSET:
        JPN_RESPONSE_HOOK_OFFSET + len(JPN_RESPONSE_HOOK)] = JPN_RESPONSE_HOOK
    out[JPN_RESPONSE_PAYLOAD_OFFSET:
        JPN_RESPONSE_PAYLOAD_OFFSET + len(JPN_RESPONSE_PAYLOAD)] = (
            JPN_RESPONSE_PAYLOAD
        )
    return bytes(out)


def patch_code(source: bytes, google: bytes, region: str | None = None) -> bytes:
    if len(google) > len(OLD_GOOGLE):
        raise RuntimeError("Google URL does not fit the stock field")
    google_field = google + b"\0" * (len(OLD_GOOGLE) - len(google))
    # The browser update's CRR authorizes the update CRO identity, while the
    # patched module deliberately preserves the base CRO identity. Load the
    # locally generated matching CRR under a separate LayeredFS name.
    out = replace_once(source, OLD_CRR, NEW_CRR, "CRR path")
    out = replace_once(out, OLD_CRO, NEW_CRO, "CRO path")
    out = replace_once(out, OLD_GOOGLE, google_field, "Google URL")
    out = replace_once(out, OLD_UA, NEW_UA, "user agent")
    if region == "JPN":
        out = patch_jpn_registration(out)
    return out


def diff_runs(before: bytes, after: bytes) -> list[tuple[int, bytes]]:
    if len(before) != len(after):
        raise RuntimeError("IPS source/output lengths differ")
    runs: list[tuple[int, bytes]] = []
    start: int | None = None
    for index, (left, right) in enumerate(zip(before, after)):
        if left != right and start is None:
            start = index
        if left == right and start is not None:
            runs.append((start, after[start:index]))
            start = None
    if start is not None:
        runs.append((start, after[start:]))
    return runs


def make_ips(before: bytes, after: bytes) -> bytes:
    out = bytearray(b"PATCH")
    for offset, payload in diff_runs(before, after):
        if offset > 0xFFFFFF or len(payload) > 0xFFFF:
            raise RuntimeError("IPS record out of range")
        out += offset.to_bytes(3, "big")
        out += len(payload).to_bytes(2, "big")
        out += payload
    return bytes(out + b"EOF")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, default=ROOT / "input")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "build" / "regional")
    parser.add_argument("--emit-code", action="store_true",
                        help="also write patched code.bin files (ignored by Git)")
    args = parser.parse_args()

    for region, info in REGIONS.items():
        source_path = args.input_dir / f"{region}.code.bin"
        source = source_path.read_bytes()
        actual_source = sha(source)
        if actual_source != info["source_sha256"]:
            raise RuntimeError(
                f"{region}: unsupported code image {actual_source}; "
                f"expected {info['source_sha256']}"
            )
        patched = patch_code(source, info["google"], region)
        if sha(patched) != info["output_sha256"]:
            raise RuntimeError(f"{region}: patched output hash mismatch")
        ips = make_ips(source, patched)
        committed = (PATCH_DIR / region / "code.ips").read_bytes()
        if ips != committed:
            raise RuntimeError(f"{region}: generated IPS differs from committed patch")

        output = args.output_dir / region
        output.mkdir(parents=True, exist_ok=True)
        (output / "code.ips").write_bytes(ips)
        if args.emit_code:
            (output / "code.bin").write_bytes(patched)
        print(
            f"PASS {region} luma_title={info['luma_title']} "
            f"update_title={info['update_title']} "
            f"code={info['output_sha256']} ips={sha(ips)}"
        )


if __name__ == "__main__":
    main()
