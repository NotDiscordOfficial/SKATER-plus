# 証明書

[English](CERTIFICATES.md)

SKATER+は証明書の署名検証とホスト名検証を無効にしません。

標準ブラウザーは多くの証明書チェーンを読めますが、一部の楕円曲線処理と現在の
信頼済みルートが不足しています。そこで、次の3段階で補います。

1. 修正済みOpenSSL CROがTLS通信と通常の証明書検証を担当します。
2. 不足するP-256/P-384公開鍵の解析とECDSA署名検証だけをMbed TLSへ渡します。
3. 選別した現在のルート証明書を`rootca.pem`へ追加します。

## 独自のルート証明書を追加

1. 自己署名CA証明書を`sd:/3ds/skater-plus-patcher/certs/`へ置きます。
   PEM形式で1ファイル1証明書とし、拡張子は小文字の`.pem`または`.crt`にします。
   DER形式、秘密鍵、複数証明書入りのファイルは取り込めません。
2. SKATER+導入後にパッチャーを起動し、**Y**を押します。
3. 表示された名義とDERのSHA-256を認証局の公開情報と照合し、**A**で追加、**B**でスキップします。
4. ブラウザーを閉じて開き直します。

Mbed TLSでCA属性、証明書署名の用途、自己署名を検証します。ただし、形式や署名が正しくても、
その認証局を信頼してよいとは限りません。追加した認証局はブラウザーで開くすべてのサイトに影響します。
重複はスキップします。上限は追加4件、入力1ファイル8KiB、合計16KiBです。
ブラウザーのメモリ制約を考慮した制限で、すべての証明書での動作を保証する測定値ではありません。

変更後の証明書束のハッシュを記録するため、追加後もパッチ検出と削除が使えます。
SKATER+を削除するとブラウザー用に追加した証明書も消えますが、`certs/`の元ファイルは残ります。

1件だけ削除するにはパッチャーで**L**を押し、**上下キー**で選び、名義とSHA-256を確認して**A**を押します。
標準の証明書と他の追加済み証明書は残ります。削除後はブラウザーを開き直してください。

## 追加するルート証明書

実機試験済みの証明書束には、次の25件を追加しています。

- Security Communication RootCA2
- COMODO RSA Certification Authority
- USERTrust RSA Certification Authority
- IdenTrust Commercial Root CA 1
- ISRG Root X1
- Amazon Root CA 1
- Amazon Root CA 2
- SSL.com Root Certification Authority RSA
- SSL.com EV Root Certification Authority RSA R2
- GlobalSign Root CA - R6
- Microsoft RSA Root Certificate Authority 2017
- NAVER Global Root Certification Authority
- GlobalSign Root R46
- HARICA TLS RSA Root CA 2021
- GTS Root R1
- DigiCert TLS RSA4096 Root G5
- Sectigo Public Server Authentication Root R46
- Sectigo Public Server Authentication Root E46
- SSL.com TLS RSA Root CA 2022
- Telekom Security TLS RSA Root 2023
- SecureSign Root CA14
- TrustAsia TLS RSA Root CA
- SwissSign RSA TLS Root CA 2022 - 1
- OISTE Server Root RSA G1
- Telia RSA TLS Root CA v3

Mbed TLSはソケット、HTTP、TLS状態管理を担当しません。OpenSSLを全面的に置き換えず、
不足するEC処理だけを補う構成です。これにより、SKATER固有のOpenSSL ABIと既存のTLS経路を
維持しながら、現在の証明書チェーンを検証できます。

証明書の入力とハッシュは`scripts/build_rootca_bundle.ps1`で固定しています。出典とライセンスは
`vendor/root-certificates/README.md`と`THIRD_PARTY_NOTICES.ja.md`に記録しています。

ルート追加は信頼の起点を増やすだけです。有効期限、ホスト名、署名、プロトコル、暗号方式の
検査を回避するものではありません。
