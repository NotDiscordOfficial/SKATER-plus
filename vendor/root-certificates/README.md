# Certificate-source snapshot

`mozilla-cacert-2026-09-25.pem` is the 2026-09-25 curl CA Extract snapshot,
converted from Mozilla's trust store. The converted bundle is licensed under
MPL 2.0, like the Mozilla source. Source, revision archive, and license:

- https://curl.se/docs/caextract.html
- https://www.mozilla.org/MPL/2.0/

`sectigo-e46.pem` is the public Sectigo Public Server Authentication Root E46
certificate obtained from the issuing CA. Its source URL is recorded in the
generated bundle.

These files are build inputs. `scripts/build_rootca_bundle.ps1` selects a
fixed subset and verifies every input and output hash. The Nintendo stock root
bundle is not included.
