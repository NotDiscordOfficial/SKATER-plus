[日本語](https://github.com/shima0625/SKATER-plus/blob/v0.1.0/RELEASE_NOTES.ja.md)

> [!CAUTION]
> Most of this release's code and documentation was created with generative AI
> assistance.

Initial release for the New Nintendo 3DS Internet Browser.

## Highlights

- Adds TLS 1.2, ECDHE-RSA/ECDHE-ECDSA AES-GCM, and P-256/P-384 certificate verification.
- Adds 25 current public root certificates.
- Imports additional self-signed CA roots from SD, with fingerprint confirmation.
- Removes imported CA roots individually and offers patcher CIA uninstall from all main/error screens.
- Sets the CIA ticket and TMD version to 0.1.0.
- Uses an iOS 7-era mobile Safari user agent and an HTTPS Google search endpoint.
- Repairs the official Japanese first-run setup.
- Supports JPN, USA, KOR, and EUR/AUS from one patcher.
- Checks Luma3DS game patching at startup and explains how to enable it.

## Tested status

JPN passed real-hardware testing, including on-console installation, removal
without reboot, and a fresh Wikipedia TLS regression test. USA, KOR, and
EUR/AUS launch and load the patch in Azahar, but still require real-hardware
TLS confirmation.

The new game-patching setting check has been built successfully but still
needs a real-hardware check with the setting both enabled and disabled.
RSA and EC test CA import and HTTPS access passed real-hardware testing.
Individual root removal passes host tests; its on-console UI still needs testing.

Google search requires an authenticated Google account. China, Taiwan, Old
Nintendo 3DS, and the SPIDER browser are not supported.

Assets: `skater-plus-patcher.cia` and `skater-plus-patcher.3dsx`.
See the [README](https://github.com/shima0625/SKATER-plus#install) for installation.
