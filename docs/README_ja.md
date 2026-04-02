# kojuto

パッケージのインストール・インポート時の不審な syscall を検知するサプライチェーン攻撃検知ツール。PyPI と npm に対応。

## 概要

kojuto は、パッケージを強化された Docker コンテナ内でインストール・インポートし、strace（または eBPF）で syscall を監視することで、サプライチェーン攻撃を検知します。

## 仕組み

1. **ダウンロード** — パッケージをホストにダウンロード（ネットワーク許可）
2. **隔離実行** — ネットワーク隔離された Docker コンテナでインストール実行
3. **インストール監視** — `connect`, `sendto`, `sendmsg`, `sendmmsg`, `bind`, `listen`, `accept`, `execve`, `openat`, `rename`, `sendfile` syscall を記録
4. **インポート監視** — Linux / Windows / macOS の 3 つの OS ID で、`libfaketime` により時刻を +30 日進めた状態でパッケージをインポートし、プラットフォーム依存・日付依存のペイロードを検知
5. **レポート** — 検知結果を JSON で出力

サンドボックスには、マルウェアの動作を誘発するためのリアルなアーティファクトが配置されます：

- 偽の認証情報ファイル（`~/.ssh/id_rsa`、`~/.aws/credentials`、`~/.git-credentials` 等）
- CI・開発者環境変数（`CI=true`、`GITHUB_TOKEN`、`AWS_ACCESS_KEY_ID` 等）

全ての値はスキャンごとに `crypto/rand` でランダム生成され、シグネチャベースの回避を防止します。

`openat` により認証情報ファイルへのアクセス（`.ssh/`、`.gnupg/`、`.aws/`、`/etc/shadow`、`/proc/self/environ`、`.netrc`、`.git-credentials`、`.docker/config.json`、`.config/gh/`）を検知し、`rename` により信頼されたバイナリの差し替えを検知し、`bind`/`listen`/`accept` によりバックドアサーバーの設置を検知します。DNS トンネリング検知は `sendto` ペイロードからクエリドメインを抽出し、高エントロピーなサブドメインによるデータ流出を検出します。`sendfile` はフォレンジック目的で trace に含まれますが、構造化イベントとしてはパースされません。

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

# eBPF を明示的に使用（全 syscall 対応; root または capabilities + kernel 5.8+ が必要）
sudo kojuto scan requests --probe-method ebpf

# sudo なしで eBPF を使用（capabilities 付与後）
sudo ./scripts/setup-caps.sh ./kojuto
./kojuto scan requests --probe-method ebpf

# gVisor ランタイムで強化隔離（/proc/1/cgroup, mountinfo を隠蔽）
kojuto scan requests --runtime runsc

# パッケージごとのタイムアウトを設定
kojuto scan requests --timeout 10m

# スキャン後にバージョン固定ファイルを生成（全パッケージがクリーンの場合のみ）
kojuto scan -f requirements.txt --pin requirements-locked.txt
kojuto scan -f package.json -e npm --pin package-pinned.json

# ローカルのパッケージファイルをスキャン（マルウェアサンプル分析用）
kojuto scan --local ./malware-1.0.0.whl
kojuto scan --local ./evil-pkg-2.0.0.tgz -e npm

# ディレクトリ内のパッケージをスキャン
kojuto scan --local ./samples/
```

### フラグ

| フラグ | 説明 |
|------|------|
| `-v, --version` | スキャンするバージョン（デフォルト: 最新） |
| `-o, --output` | 出力ファイルパス（デフォルト: 標準出力） |
| `-e, --ecosystem` | `pypi` / `npm`（デフォルト: `pypi`） |
| `-f, --file` | 依存ファイルを指定してスキャン（`requirements.txt`、`package.json`、任意の `*.txt`/`*.json`） |
| `--pin` | 全パッケージがクリーンの場合にバージョン固定ファイルを出力（`-f` 必須） |
| `--local` | ローカルのパッケージファイル（`.whl`、`.tgz`）またはディレクトリをスキャン |
| `--runtime` | コンテナランタイム: デフォルト（runc）または `runsc`（gVisor） |
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

## 設計思想

kojuto は受動的な syscall 監視だけに頼りません。マルウェアの動作を能動的に誘発する環境を構築します：

- **ハニーポット認証情報** — 窃取ロジックを誘発する偽のファイルとトークン
- **CI 環境シグナル** — CI 環境でのみ発火するペイロードを活性化する環境変数
- **時刻シフト実行** — `libfaketime` で時計を進め、日付ゲートの時限爆弾を検知
- **マルチ OS ID** — OS 依存のペイロードを検知するプラットフォームシミュレーション

このアプローチにより、無菌なサンドボックスでは休眠したままの環境依存型・遅延実行型のサプライチェーン攻撃を検知します。

## セキュリティ

[SECURITY.md](../SECURITY.md) を参照してください。

## ライセンス

[MIT](../LICENSE)