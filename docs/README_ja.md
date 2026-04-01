# kojuto

パッケージインストール時の不審な外部通信を検知するサプライチェーン攻撃検知ツール。

## 概要

kojuto は、PyPI / npm パッケージをネットワーク遮断された Docker コンテナ内でインストール・インポートし、eBPF（または strace）で syscall を監視することで、サプライチェーン攻撃を検知します。

## 仕組み

1. **ダウンロード** — パッケージをホストにダウンロード（ネットワーク許可）
2. **隔離実行** — `--network=none` の Docker コンテナでインストール実行
3. **監視** — eBPF で `connect(2)` 等の syscall を記録
4. **レポート** — 検知結果を JSON / SARIF で出力

正規のパッケージはインストール時に外部通信しないため、通信の試みがあれば「要確認」として報告します。

## インストール

```bash
git clone https://github.com/kojuto/kojuto.git
cd kojuto
make build
```

## 使い方

```bash
# PyPI パッケージをスキャン
sudo kojuto scan requests

# 特定バージョンを指定
sudo kojuto scan requests --version 2.31.0

# JSON レポートをファイルに出力
sudo kojuto scan requests -o report.json
```

## 対応状況

| 機能 | 状態 |
|---|---|
| PyPI インストール時検知 | v0.1 |
| インポート時検知 | v0.2 |
| npm サポート | v0.3 |
| 既知パターンDB / SARIF | v0.4 |
| 関数ロード時検知 | v0.5 |

## ライセンス

MIT License
