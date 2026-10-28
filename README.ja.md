# SKATER+

[English](README.md)

> [!CAUTION]
> **このプロジェクトのコードと文書は、大部分を生成AIの支援で作成しています。**
> 日本版では実機試験を行っていますが、AI生成部分を含むことを前提に、ソースと
> 配布物を確認してから使用してください。ほかの地域版は実験段階です。

New Nintendo 3DSインターネットブラウザー（SKATER）の互換性パッチです。
TLS 1.2、現在のルート証明書、Webサイト互換修正、日本版の初回登録修正をまとめています。

Luma3DSが起動時にSDカード上のパッチを適用します。

## ダウンロード

- [CIA](https://github.com/shima0625/SKATER-plus/releases/latest/download/skater-plus-patcher.cia)
- [3DSX](https://github.com/shima0625/SKATER-plus/releases/latest/download/skater-plus-patcher.3dsx)

<a href="https://github.com/shima0625/SKATER-plus/releases/latest/download/skater-plus-patcher.cia"><img src="docs/images/cia-qr.png" alt="" width="240" height="240"></a>

## 機能

- ECDHE-RSA/ECDHE-ECDSA AES-GCMを使うTLS 1.2
- P-256/P-384の証明書とハンドシェイク署名の検証
- [ルート証明書を25件追加](docs/CERTIFICATES.ja.md)
- パッチャーからSD上のルート証明書を追加
- iOS 7世代のMobile Safari UAとHTTPS版Google検索
- 日本版の公式初回設定を修正

Google検索には現在ログインが必要です。標準のiOS 6 UAはサポート対象外と判定されます。
修正後のiOS 7世代UAではログイン済みの環境で検索できることを確認しています。

## 仕組み

```text
SKATER起動
  -> code.ipsがファイル名、UA、Google URL、日本版初回処理を変更
  -> Lumaが標準OpenSSL CROの代わりにos2.cro.lexを読み込む
  -> tlsfix.crrが差し替えCROの識別情報を許可
  -> CROがTLS 1.2 ClientHelloを送り、ECDHEを実行
  -> 証明書ブリッジがP-256/P-384証明書を検証
  -> rootca.pemが現在の認証局を追加
```

通信、TLS状態管理、通常の証明書検証は、SKATER付属のOpenSSL 1.0.2が引き続き担当します。
Mbed TLSは古いOpenSSLに足りない楕円曲線公開鍵の解析とP-256/P-384 ECDSA検証だけを
補います。既存のTLS処理を保ったまま不足部分だけを追加するため、両者を併用しています。

暗号スイート表では4件の既存枠をECDHE用に転用しています。その結果、表の並びが
二分探索の前提を満たさなくなるため、暗号スイートIDの検索だけを最大71件の線形探索へ
変更しています。最悪時の比較回数は増えますが、対象は小さな固定長表で、通信本文の処理には
使いません。検索範囲も71件に固定しています。公開値である暗号スイートIDを扱うため、
位置による検索時間の差が秘密情報を漏らす用途にもなりません。

日本版の初回修正は任天堂公式の`sec.ifilter.jp`へ接続します。標準の登録クライアントが
現在のHTTPSへ接続できないため、ここだけHTTPを使います。初回登録時の端末識別子と応答は
暗号化されないので、信頼できるネットワークで実行してください。

## TLS 1.3について

現在のパッチを少し拡張するだけではTLS 1.3に対応できません。TLS 1.3ではClientHelloだけでなく、
鍵導出、ハンドシェイク、トランスクリプト、レコード鍵の仕組みまで変わります。

対応するには、OpenSSL 1.0.2を新しいOpenSSLまたはMbed TLSへほぼ全面的に置き換え、
SKATER独自のソケット、メモリ、スレッド、CRO ABI、証明書表示へ接続し直す必要があります。
現在もCROの拡張、関数フック、暗号表、ECDHE、証明書処理を改変していますが、既存のTLS状態機械と
ABIは維持しています。TLS 1.3化は既存のTLS実装を交換する作業で、別プロジェクト相当です。

RAM、コード容量、安定性の負担も大きいため、SKATER+ではTLS 1.2の対応範囲を広げる方が現実的です。
[OpenSSL公式TLS資料](https://docs.openssl.org/1.1.1/man7/ssl/)と
[Mbed TLSのTLS 1.3設計資料](https://github.com/Mbed-TLS/mbedtls/blob/development/docs/architecture/tls13-support.md)も参照してください。

## 対応状況

| 地域 | Lumaフォルダー | 状況 |
| --- | --- | --- |
| JPN | `0004003000008802` | 実機で初回設定、Wikipedia、Google、Yahoo、証明書、UAを確認 |
| USA | `0004003000009402` | Azaharで起動・UA確認。TLSは実機未確認 |
| KOR | `000400300000AE02` | Azaharで起動・UA確認。TLSは実機未確認 |
| EUR/AUS | `0004003000009D02` | Azaharで起動・UA確認。TLSは実機未確認 |

中国・台湾版とOld Nintendo 3DSのSPIDERは対象外です。詳細は
[互換性記録](docs/COMPATIBILITY.ja.md)を参照してください。

## インストール

New Nintendo 3DS系本体、最新の地域別ブラウザー更新、最新版Luma3DSが必要です。

1. 起動時に<kbd>Select</kbd>を押し、**Enable game patching**を有効にして、<kbd>Start</kbd>で保存します。
   パッチャーも起動時にこの設定を確認します。
2. `skater-plus-patcher.cia`をHOMEメニューから起動するか、
   `skater-plus-patcher.3dsx`をHomebrew Launcherから起動します。
3. <kbd>A</kbd>を押します。地域（日本・北米・欧州/豪州・韓国）は自動判定されます。
   本体内の公式ブラウザーファイルを検証してから、SD上にLumaパッチを生成します。
4. CIA版では、インストール後にパッチャーを残すか削除するか選べます。3DSX版ではそのまま終了します。
5. ブラウザーを起動し、利用したいサイトで動作を確認します。

削除する場合はパッチャーを再度起動し、**Remove patch**を選びます。削除後の再起動は不要です。
同じ場所に別のファイルがある場合はバックアップしますが、自動では復元しません。

パッチャーCIA自体は、未適用時・適用済み時・エラー画面のいずれでも<kbd>X</kbd>から削除できます。

ルート証明書を追加するには、PEM形式の証明書を1件ずつ`.pem`または`.crt`ファイルにして
`sd:/3ds/skater-plus-patcher/certs/`へ置きます。パッチ導入済みの状態でパッチャーを起動し、
<kbd>Y</kbd>を押して各証明書の名義とSHA-256を確認します。
詳細は[証明書](docs/CERTIFICATES.ja.md#独自のルート証明書を追加)を参照してください。
追加済み証明書を個別に削除する場合は<kbd>L</kbd>を押します。

## スクリーンショット

| Wikipedia | Google | Yahoo.com |
| --- | --- | --- |
| ![HTTPS版Wikipedia](docs/images/wikipedia.png) | ![Google検索](docs/images/google.png) | ![Yahoo.com](docs/images/yahoo-com.png) |

## ビルド

パッチャーのビルドには同梱の実行用アセットを使います。ブラウザーパッチを再生成する場合は本体から取得したファイルが必要です。
詳しくは[ビルド](docs/BUILDING.ja.md)と[証明書](docs/CERTIFICATES.ja.md)を参照してください。

## 制限

- 実機確認済みは日本版だけです。
- JavaScript、HTML/CSS、コーデック、未対応TLS機能により開けないサイトがあります。
- Google側の仕様は今後変わる可能性があります。

不具合報告には本体地域・機種、システム/Luma版、タイトルID、URL、エラー番号、
未適用時の結果を含めてください。ブラウザーのダンプはアップロードしないでください。

## ライセンス

独自コードはMITです。第三者ライセンスは
[THIRD_PARTY_NOTICES.ja.md](THIRD_PARTY_NOTICES.ja.md)を参照してください。
