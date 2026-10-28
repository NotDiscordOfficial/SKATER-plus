[English](https://github.com/shima0625/SKATER-plus/blob/v0.1.0/RELEASE_NOTES.md)

> [!CAUTION]
> このリリースのコードと文書は、大部分を生成AIの支援で作成しています。

New Nintendo 3DSインターネットブラウザー向けの初回リリースです。

- TLS 1.2、ECDHE-RSA/ECDHE-ECDSA AES-GCM、P-256/P-384検証を追加
- 現在のルート証明書を25件追加
- SD上の自己署名CA証明書を、SHA-256の確認付きで追加
- 追加証明書の個別削除と、各メイン画面・エラー画面からのパッチャーCIA削除に対応
- CIAのチケットとTMDにバージョン0.1.0を設定
- iOS 7世代UA、HTTPS版Google検索、日本版初回設定を修正
- 1つのパッチャーでJPN/USA/KOR/EUR-AUSに対応
- 起動時にLuma3DSのGame patching設定を確認し、無効なら設定手順を表示

日本版は本体上での導入、再起動なしの削除、TLS通信を実機確認済みです。他地域はエミュレーターで起動・読込を確認していますが、
実機TLS確認が必要です。Google検索にはログインが必要です。CN/TW、Old 3DS、SPIDERには
対応しません。

新しいGame patching設定の判定はビルド済みですが、有効・無効それぞれの実機確認が必要です。
RSA・ECの試験CAの取り込みとHTTPS接続は実機確認済みです。
証明書の個別削除はホスト試験に成功しています。本体上の操作画面は未確認です。

配布ファイルはCIAと3DSXです。
