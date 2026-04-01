# kojuto

パッケージのインストール・インポート時の不審な syscall を検知するサプライチェーン攻撃検知ツール。PyPI と npm に対応。

## 概要

kojuto は、パッケージを強化された Docker コンテナ内でインストール・インポートし、strace（または eBPF）で syscall を監視することで、サプライチェーン攻撃を検知します。

## 仕組み

1. **ダウンロード** — パッケージをホストにダウンロード（ネットワーク許可）
2. **隔離実行** — ネットワーク隔離された Docker コンテナでインストール実行
3. **インストール監視** — `connect`, `sendto`, `sendmsg`, `execve`, `openat`, `rename` syscall を記録
4. **インポート監視** — Linux / Windows / macOS の 3 つの OS ID でパッケージをインポートし、プラットフォーム依存のペイロードを検知
5. **レポート** — 検知結果を JSON で出力

`openat` により認証情報ファイルへのアクセス（`.ssh/`、`.aws/`、`/etc/shadow`）を検知し、`rename` により信頼されたバイナリの差し替えを検知します。`sendfile` はコマンドベースのヒューリスティクスを迂回するファイル転送経路の記録に使用されます。

正規のパッケージは通常、インストール・インポート時に予期しない外部通信、無関係なプロセスの生成、認証情報ファイルへのアクセス、信頼されたバイナリの変更を行いません。そのような活動を検出した場合は「要確認」として報告します。

## インストール

```bash
git clone https://github.com/RalianENG/kojuto.git
cd kojuto
make build

# サンドボックスイメージをビルド
make sandbox-image
```

## 使い方

```bash
# PyPI パッケージをスキャン
kojuto scan requests

# npm パッケージをスキャン
kojuto scan lodash -e npm

# 依存ファイルから一括スキャン
kojuto scan -f requirements.txt
kojuto scan -f package.json

# 特定バージョンを指定
kojuto scan requests --version 2.31.0

# JSON レポートをファイルに出力
kojuto scan requests -o report.json

# eBPF を明示的に使用（connect のみ、root + kernel 5.8+ が必要）
sudo kojuto scan requests --probe-method ebpf

# パッケージごとのタイムアウトを設定
kojuto scan requests --timeout 10m
```

### フラグ

| フラグ | 説明 |
|------|------|
| `-v, --version` | スキャンするバージョン（デフォルト: 最新） |
| `-o, --output` | 出力ファイルパス（デフォルト: 標準出力） |
| `-e, --ecosystem` | `pypi` / `npm`（デフォルト: `pypi`） |
| `-f, --file` | 依存ファイルを指定してスキャン（`requirements.txt`、`package.json`、任意の `*.txt`/`*.json`） |
| `--probe-method` | `auto` / `ebpf` / `strace` / `strace-container`（デフォルト: `auto`） |
| `--timeout` | パッケージごとのタイムアウト（デフォルト: `5m`） |

### 終了コード

| コード | 意味 |
|--------|------|
| 0 | クリーン — 不審な活動なし |
| 1 | エラー — スキャン失敗 |
| 2 | 要確認 — 不審なイベント検出、またはプローブデータ欠損 |

## ドキュメント

- [設計仕様書](SPECIFICATION.md)

## セキュリティ

[SECURITY.md](../SECURITY.md) を参照してください。

## ライセンス

[MIT](../LICENSE)