# Compatibility

[日本語](COMPATIBILITY.ja.md)

| Region | Environment | Confirmed | Remaining |
| --- | --- | --- | --- |
| JPN | New 3DS hardware | Official first-run; Wikipedia TLS 1.2; Google signed-in search; Yahoo; mobile UA; certificate display; on-console install and removal without reboot | Broader site coverage |
| USA | Azahar Plus | Browser launch and mobile UA | TLS on hardware |
| KOR | Azahar Plus | Browser launch and mobile UA | TLS on hardware |
| EUR/AUS | Azahar | IPS and CRO/CRR loading; mobile UA | TLS on hardware |

JPN passed a fresh Wikipedia regression on 2026-10-24. In Azahar, USA and KOR
still returned 1035 on TLS 1.2 sites. Emulator loading is useful for region and
patch-site checks, but is not proof of the real SKATER/OpenSSL runtime path.

CN/TW are excluded because SKATER targets New 3DS while those regions only
have the Old 3DS browser environment. SPIDER is a different browser and is not
supported.

## Testing another region

Use a New 3DS with the target region's browser and record the console model,
region, system version, Luma version, browser title ID/version, URL and result.
Use the same network and correct console date for before/after comparisons.

1. Record the unpatched browser's result first.
2. Install SKATER+ using the CIA or 3DSX. Confirm the detected region and test
   Wikipedia, Yahoo.com and the mobile user agent. Test Google search only
   with an already signed-in account.
3. Open the certificate details for a working HTTPS page. Record the exact
   error code for a failing page and whether it also fails without SKATER+.
4. Import a test CA, reopen the patcher, and confirm patch detection still
   works. Check duplicate import and cancellation. Remove the patch and
   confirm the browser launches again.

USA, EUR/AUS and KOR hardware testers can all use the same patcher. This is the
shortest way to extend the hardware test matrix without changing your own
console's region. Share the CIA/3DSX and test results, rather than browser dumps.

Azahar remains useful for launch, UA, patch loading and debugging. Error 1035
alone does not identify the cause of a TLS failure. Before drawing a conclusion,
trace whether the patched CRO executes and compare ClientHello, the negotiated
cipher and certificate errors. Selecting SSL LLE alone does not demonstrate
that the browser's bundled CRO ran correctly.
