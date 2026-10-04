<h1 align="center">
  <img src="./assets/lvau-wordmark.svg" alt="Lvau" width="340">
</h1>

<p align="center"><strong>ローカルファイルを暗号化する。</strong></p>

<p align="center"><a href="README.md">English</a> · 日本語</p>

<p align="center">
  <a href="https://github.com/lasder-ca/lvau/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/lasder-ca/lvau/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="MIT" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
</p>

Lvauは、ローカルファイル暗号化のための実験的なRustワークスペースです。CLI、再利用可能な暗号ライブラリ、バージョン管理された`.lvau`形式、ネイティブGUI、自己展開アーカイブの試作を含みます。現在のリリースは**0.5.0**です。

> [!NOTE]
> **AI利用について:** Lvauは、開発の約半分でAIツールを利用しています。

> [!WARNING]
> Lvauは第三者による正式なセキュリティ監査を完了しておらず、1.0より前に形式が変わる可能性があります。重要なデータへ使う前に、[SECURITY.md](SECURITY.md)と[脅威モデル](docs/THREAT_MODEL.md)を確認してください。

## クイックスタート

```sh
lvau-cli encrypt --password --in-file secret.txt --out-file secret.txt.lvau
lvau-cli inspect --in-file secret.txt.lvau
lvau-cli verify --password --in-file secret.txt.lvau
lvau-cli decrypt --password --in-file secret.txt.lvau --out-file secret.restored.txt
```

ローカルの自動処理では、読み取り権限を制限したパスワードファイルを使います。

```sh
printf '%s' '十分に強いパスフレーズへ置換' > password.txt
chmod 600 password.txt
lvau-cli encrypt \
  --in-file secret.txt \
  --out-file secret.txt.lvau \
  --password-file password.txt
```

Windowsでは、Lvauを実行するアカウントだけが読めるようにパスワードファイルのACLを制限してください。パスワード、秘密鍵、シード、復旧共有、認証情報をGitへ追加しないでください。

## Lvauでできること

| 機能 | 状態 |
|---|---|
| XChaCha20-Poly1305、Argon2id、HKDF-SHA256によるパスワード暗号化 | テスト可能 |
| ストリーミング暗号化と認証付き検証 | テスト可能 |
| ペイロードを復号しない公開情報の検査 | テスト可能 |
| 暗号化された目録を持つディレクトリバンドル | テスト可能 |
| Ed25519による著者署名 | テスト可能 |
| 検査、検証、事前確認、レポート、ポリシー確認のJSON出力 | スキーマversion 1 |
| 単一ファイル形式v3（`LV3-XC20P`、パスワード・X25519 HPKE・ML-KEM-768受信者） | 実験的 |
| 層化v3ペイロードスイート（`LV3-AESGCMSIV-XC20P`、パスワード・A4受信者ファイル） | 実験的 |
| v3受信者/パスワード更新とpassword-v3 root key rotation | 実験的 |
| ハイブリッド受信者暗号化と多段プロファイル | 実験的 |
| 承認メタデータ、復旧機能、GUI、自己展開アーカイブ | 実験的 |

既定の書き込み形式はv2です。実験的なv3には`--format v3 --suite lv3-xc20p`を指定します。
層化ペイロードスイート`--format v3 --suite lv3-aesgcmsiv-xc20p`（内側AES-256-GCM-SIV＋
外側XChaCha20-Poly1305）はパスワードファイルと`--recipient-suite ml-kem-768`（A4）
受信者でも明示的なopt-inです。X25519-HPKE（A3）は単層のままです。
パスワード入力はArgon2idによる鍵保護です。`--pub-key`または`--recipient-group`では
既定でX25519 HPKEを使い、`--recipient-suite ml-kem-768`でrevision A4の純粋なML-KEM-768、
`--recipient-suite hybrid-x25519-mlkem`で実験的な二重ラップslot（どちらの秘密要素でも
開ける。KEMコンバイナではない：どちらか一方が破られるとファイル鍵が漏れる）を
選べます。いずれも既存のハイブリッド鍵ファイル内の該当コンポーネントだけを使用します。
HPKE Base modeは送信者を認証せず、送信者に受信者の秘密鍵保有を証明しません。
ML-KEMも匿名KEMであり、送信者を識別しません。
ML-KEM実装も独立監査済みではありません。

`rekey add-recipient`、`remove-recipient`、`change-password`は既存パスワードまたは受信者秘密鍵で
A4のroot-wrap slotだけを更新し、payload frameは再暗号化しません。更新で使用した資格情報を
削除した結果、検証に使えるslotが残らない場合は更新を拒否します。`rekey rotate-root`はlegacy
password-v3を完全に復号・再暗号化します。slot削除では古いファイルコピーや既に取得された
認証情報を失効できません。
`rekey convert-a3`はA3秘密鍵と、その他すべての旧受信者公開鍵を含む`--recipient-group`で
A3をA4へ変換します。現在の秘密鍵に対応する公開鍵は自動で保持され、A3受信者全員を
カバーしない場合は拒否されます。変換元ファイルは変更せず、暗号化payload frameもそのままコピーします。
v3は形式未固定で独立レビューも未完了です。バンドルと多層暗号化には対応していません。

## 自動処理とNelo連携

自動処理向けJSONの正確な対応範囲は[JSON出力契約](docs/JSON_OUTPUT.md)を確認してください。

[Nelo](https://github.com/lasder-ca/Nelo)は、HTTPリクエストの寿命に`lvau-cli`プロセスを結び付けられます。[Nelo連携ガイド](docs/integrations/NELO.md)を確認してください。

## ブランド素材

- [`assets/lvau-wordmark.svg`](./assets/lvau-wordmark.svg) — READMEや横長の表示に使う基本ワードマーク。
- [`assets/lvau-icon.svg`](./assets/lvau-icon.svg) — Lvauモノグラムを使った角丸の製品・アプリアイコン。
- [`assets/lvau-symbol.svg`](./assets/lvau-symbol.svg) — 小さい表示向けの透明背景・単色モノグラム。
- [`assets/favicon.svg`](./assets/favicon.svg) — ブラウザや極小表示向けの高コントラストアイコン。

新しいブランドは、暖かいオフホワイトとほぼ黒のニュートラルな単色構成です。必要なSVGはライト・ダーク表示に対応し、すべてパスで構成しているため外部フォントには依存しません。

## ソースからビルド

```sh
git clone https://github.com/lasder-ca/lvau.git
cd lvau
cargo build --locked --workspace --release
```

実行ファイルは`target/release/`へ生成されます。正確なオプションは`lvau-cli <command> --help`で確認してください。

## セキュリティ上の境界

Lvauが保護できるのは、パスワード、秘密鍵、利用端末が安全に保たれている場合のペイロードの機密性と完全性です。マルウェア、キーロガー、侵害されたOS、弱いパスワード、盗まれた鍵、悪意のある出力先、すべての認証情報の紛失からは保護できません。実験的なv3 HPKE Base modeは受信者秘密鍵を持つ者への機密性を提供しますが、送信者に受信者の鍵保有を証明せず、送信者も認証しません。v3 ML-KEM-768は匿名KEMを使うLvau固有の鍵ラップ構成であり、送信者を認証せず、HPKEでもありません。

形式v2/v1の構造と移行方法は[形式ドキュメント](docs/FORMAT.md)、v3は[仕様ドラフト](docs/FORMAT_V3_DRAFT.md)を確認してください。

## ワークスペース

| クレート | 役割 |
|---|---|
| `lvau-protocol` | envelopeと目録のシリアライズ型 |
| `lvau-core` | 暗号処理、解析、ファイル、バンドル、署名、ポリシー、復旧 |
| `lvau-cli` | コマンドラインと自動処理向け出力 |
| `lvau-gui` | `lvau-core`を使う実験的なネイティブGUI |
| `lvau-stub` | 実験的な自己展開アーカイブ |

## 開発

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo build --locked --workspace --release
cargo tree --duplicates
cargo run --locked --quiet --package lvau-cli -- self-test
```

## ライセンス

[MIT License](LICENSE)で公開しています。
