#!/bin/sh
set -eu

tool_prefix="${DEVKITARM:-/opt/devkitpro/devkitARM}/bin/arm-none-eabi-"
cc="${tool_prefix}gcc"
objcopy="${tool_prefix}objcopy"
expected_version="16.1.0"
actual_version="$($cc -dumpfullversion)"
if [ "$actual_version" != "$expected_version" ]; then
    echo "unsupported arm-none-eabi-gcc: $actual_version (expected $expected_version)" >&2
    exit 1
fi

out="build/payload-oldbase"
mkdir -p "$out"
cflags="-Os -mthumb -march=armv6k -mtune=mpcore -mfloat-abi=soft -mtp=soft -ffunction-sections -fdata-sections -fno-builtin -fno-stack-protector -fshort-enums"
defs="-DuECC_PLATFORM=0 -DuECC_SUPPORTS_secp160r1=0 -DuECC_SUPPORTS_secp192r1=0 -DuECC_SUPPORTS_secp224r1=0 -DuECC_SUPPORTS_secp256k1=0 -DuECC_SUPPORT_COMPRESSED_POINT=0"

# shellcheck disable=SC2086
$cc $cflags $defs -Ipayload -Ivendor/micro-ecc -c payload/ecdh.c -o "$out/ecdh.o"
# shellcheck disable=SC2086
$cc $cflags $defs -Ipayload -Ivendor/micro-ecc -c vendor/micro-ecc/uECC.c -o "$out/uECC.o"
$cc -c -mthumb -march=armv6k -mfloat-abi=soft payload/hooks.S -o "$out/hooks.o"
$cc -nostdlib -Wl,--gc-sections,-Map="$out/payload.map",-T,payload/payload-oldbase.ld \
    "$out/hooks.o" "$out/ecdh.o" "$out/uECC.o" -lgcc -o "$out/payload.elf"
$objcopy -O binary "$out/payload.elf" "$out/payload-injected.bin"

python - "$out/payload-injected.bin" <<'PY'
import hashlib
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
actual = hashlib.sha256(path.read_bytes()).hexdigest().upper()
expected = "2952E748268E910D65389124F1236D97A5C561812B2E6B6095D447CFD6746B64"
if actual != expected:
    raise SystemExit(f"unexpected old-base payload SHA-256: {actual}; expected {expected}")
print(f"{path}: SHA-256 {actual}")
PY
