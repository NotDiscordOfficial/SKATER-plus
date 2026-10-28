# 第三者ライセンス

[English](THIRD_PARTY_NOTICES.md)

SKATER+は、次の第三者素材を使用または参照します。

- Mbed TLS 2.28.8：証明書検証ブリッジと、devkitProの`3ds-mbedtls`経由でSD証明書取り込みに使用（Apache-2.0）
- micro-ecc：ECDHE処理で使用（BSD 2-Clause）
- Mozilla CA Certificate Program data：ルート証明書の元データ（MPL 2.0）
- Sectigo Public Server Authentication Root E46：Sectigoが公開するルート証明書

完全なライセンスは`vendor/mbedtls/LICENSE`と`vendor/micro-ecc/LICENSE.txt`、
証明書の出典は`vendor/root-certificates/README.md`にあります。

SKATER+はLuma3DS、OpenSSL、Nintendo 3DSシステムと相互運用しますが、これらの開発元や
権利者がSKATER+を推奨または承認しているわけではありません。任天堂の標準ファイルは
本リポジトリに含めません。
