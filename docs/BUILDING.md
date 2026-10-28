# Building SKATER+

[日本語](BUILDING.ja.md)

## Build the patcher

The committed runtime assets are ready to use. With devkitARM, libctru, and
makerom and the devkitPro `3ds-mbedtls` package installed, build both
applications without extracting browser files:

```text
make -C patcher
make -C patcher cia MAKEROM=makerom
python scripts/package_releases.py
```

## Regenerate browser patches

Put the supported files extracted from your own system in `input/`:

| File | SHA-256 |
| --- | --- |
| `JPN.code.bin` | `8B06E7D18DF8D9DFFFF161D26D3213A2C474888C35491CF0C96C709931C8D914` |
| `USA.code.bin` | `B2BD118F99D7FAF424A720B63004F92EDB299354989BA143EFA42B50144CE41C` |
| `KOR.code.bin` | `7308CE1B326AECA2A5BF468D7ACF661F5B5135E7F77A6FE355C8EF41D00158B4` |
| `EUR.code.bin` | `748A5C276D3729F59BDD61541FC66DC5F78C23776BEABB982839522ABC729F28` |
| `oss.cro` | `BDD428C371717B0741CCFC118BABB355BFB6D2F3585BACE2E4DDEEE2723C87DE` |

Also provide the matching 0x1000-byte `static.crr`. Rebuilding the root bundle
requires the supported stock `rootca.pem`.

Run from the repository root:

```powershell
python scripts/build_regional_tls_packages.py --input-dir input
python scripts/verify_regional_tls_build.py --input-dir input
python scripts/build_ecdhe_static_patch.py
python scripts/build_certificate_bridge.py
python scripts/build_matching_crr.py
pwsh -File scripts/build_rootca_bundle.ps1 -StockPath input/rootca.pem -OutputPath build/rootca.pem
python scripts/build_runtime_assets.py
```

`package_releases.py` packages the patcher CIA and 3DSX.
`--include-local-full-files` is available only for local testing.

Root-bundle rebuild alone:

```powershell
pwsh -File scripts/build_rootca_bundle.ps1 -StockPath input/rootca.pem -OutputPath build/rootca.pem
```

Important final hashes:

| Output | SHA-256 |
| --- | --- |
| `build/oss-skaterplus.cro.lex` | `6E56DEE5073BE333F6438C4C53C10EB26AC38AE064275B4931681179985B988D` |
| `build/tlsfix.crr` | `86712C50A3E4C6256D8CC81A4B61331D6E9A1C46676941E0064289FF811F5422` |
| `build/rootca.pem` | `77D8B6985442F74BDAD3655FD16D871BAFC0240AB4CF0B2902F1E089FCEB6865` |

The scripts stop on an unsupported input, changed patch site, or mismatched
output.

`build_runtime_assets.py` updates the deltas under `patcher/romfs/assets/`.
After regenerating them, rebuild the patcher using the commands above.
