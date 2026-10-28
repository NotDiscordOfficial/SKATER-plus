#!/usr/bin/env python3
"""Reject private dumps and complete reconstructed files from the public tree."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_PREFIXES = ("input/", "build/", "backups/", "dist/", "patcher/build/", ".codex/", ".agents/", ".yomiyasu/")
FORBIDDEN_SUFFIXES = (".cia", ".3dsx", ".cci", ".dmp", ".elf", ".smdh", ".code.bin", ".cro", ".cro.lex")
FORBIDDEN_EXACT = {"patcher/exheader.bin", "docs/publishing.md", "docs/publishing.ja.md"}
ALLOWED_SUFFIX_EXCEPTIONS = {"payload/certificate-bridge/ec_bridge.elf"}
KNOWN_COMPLETE_HASHES = {
    "8B06E7D18DF8D9DFFFF161D26D3213A2C474888C35491CF0C96C709931C8D914",
    "B2BD118F99D7FAF424A720B63004F92EDB299354989BA143EFA42B50144CE41C",
    "7308CE1B326AECA2A5BF468D7ACF661F5B5135E7F77A6FE355C8EF41D00158B4",
    "748A5C276D3729F59BDD61541FC66DC5F78C23776BEABB982839522ABC729F28",
    "7F61C754757192D242228E71D932FD60C5C33325341F6C0E1FA5F1B2E851AC7A",
    "1D9AD1106DF8FDB5A0DCB7F821F3822C1B2B4A74EE083BA9B472B149AF1CB6E3",
    "D2700A6FE9D5E9E8B9742223268EC24FFE2B263B1BE9E9F2E35CF0AABAE49AED",
    "1BBFF52D750F581363FAA6D040A298E87588BB4456408E0DC06B800FFA1A8705",
    "BDD428C371717B0741CCFC118BABB355BFB6D2F3585BACE2E4DDEEE2723C87DE",
    "EBECAE6102C521D86124E9154695F4E787B8ED336D1184C3632793232DE05214",
    "86712C50A3E4C6256D8CC81A4B61331D6E9A1C46676941E0064289FF811F5422",
    "3D7E053FB7B8AD425AB7C0AE4523B837163CA9D436F8BFE43C8FE730636D04E2",
    "77D8B6985442F74BDAD3655FD16D871BAFC0240AB4CF0B2902F1E089FCEB6865",
}


def tracked_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
    )
    return [name.decode("utf-8") for name in result.stdout.split(b"\0") if name]


def main() -> None:
    failures: list[str] = []
    for name in tracked_files():
        normalized = name.replace("\\", "/")
        lower = normalized.lower()
        if lower.startswith(FORBIDDEN_PREFIXES) or lower in FORBIDDEN_EXACT:
            failures.append(f"forbidden private path: {normalized}")
            continue
        if lower.endswith(FORBIDDEN_SUFFIXES) and normalized not in ALLOWED_SUFFIX_EXCEPTIONS:
            failures.append(f"forbidden build/full-file artifact: {normalized}")
            continue
        path = ROOT / name
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest().upper()
            if digest in KNOWN_COMPLETE_HASHES:
                failures.append(f"known complete browser file: {normalized}")
    if failures:
        raise SystemExit("\n".join(failures))
    print(f"PASS public tree: {len(tracked_files())} tracked files")


if __name__ == "__main__":
    main()
