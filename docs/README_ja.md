# kojuto

パッケージインストール時の不審な外部通信を検知するサプライチェーン攻撃検知ツール。

## 概要

kojuto は、PyPI パッケージをネットワーク遮断された Docker コンテナ内でインストールし、eBPF（または strace）で syscall を監視することで、サプライチェーン攻撃を検知します。

## 仕組み

1. **ダウンロード** — パッケージをホストにダウンロード（ネットワーク許可）
2. **隔離実行** — `--network=none` の Docker コンテナでインストール実行
3. **監視** — eBPF で `connect(2)` 等の syscall を記録
4. **レポート** — 検知結果を JSON で出力

正規のパッケージはインストール時に外部通信しないため、通信の試みがあれば「要確認」として報告します。

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
sudo kojuto scan requests

# 特定バージョンを指定
sudo kojuto scan requests --version 2.31.0

# JSON レポートをファイルに出力
sudo kojuto scan requests -o report.json

# strace フォールバック（eBPF 不要）
./kojuto scan requests --probe-method strace

# タイムアウトを設定
sudo kojuto scan requests --timeout 10m
```

### フラグ

| フラグ | 説明 |
|------|------|
| `-v, --version` | スキャンするバージョン（デフォルト: 最新） |
| `-o, --output` | 出力ファイルパス（デフォルト: 標準出力） |
| `--probe-method` | `auto` / `ebpf` / `strace` / `strace-container`（デフォルト: `auto`） |
| `--timeout` | スキャンのタイムアウト（デフォルト: `5m`） |

## ドキュメント

- [Quick Start](QUICKSTART.md)
- [設計仕様書](SPECIFICATION.md)

## コントリビュート

[CONTRIBUTING.md](../CONTRIBUTING.md) を参照してください。

## セキュリティ

[SECURITY.md](../SECURITY.md) を参照してください。

## ライセンス

[MIT](../LICENSE)
