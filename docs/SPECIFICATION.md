# サプライチェーン攻撃検知ツール 設計仕様書

## 1. 概要

### プロジェクトの目的

パッケージのインストール時・インポート時に発生する外部通信を検知し、サプライチェーン攻撃を実行前に発見するOSSツール。

### スコープ

| 対象 | 内容 |
|---|---|
| **In Scope** | インストール時・インポート時の外部通信検知 |
| **Out of Scope** | 静的解析レイヤー（GuardDogに委譲） |
| **Out of Scope (v1)** | 任意の関数実行時の検知 |

### サポートエコシステム

- PyPI（Python）
- npm（Node.js）

---

## 2. 検知対象

### フェーズと通信発生源

| フェーズ | PyPI | npm |
|---|---|---|
| インストール時 | `setup.py` / build hooks / `cmdclass` | `package.json` の `postinstall` スクリプト |
| インポート時 | `__init__.py` のモジュールロード | `require()` / `import` 時の `index.js` |

### 監視するsyscall

| syscall | 検知対象 | 攻撃例 |
|---|---|---|
| `connect(2)` | 外部TCP/UDP接続 | C2サーバーへのデータ送信 |
| `sendto(2)` | DNSクエリ | DNSトンネリング、ドメイン名へのデータ埋め込み |
| `execve(2)` | 外部コマンド起動 | `curl` / `wget` をシェル経由で呼ぶパターン |
| `openat(2)` | 機密ファイルアクセス | `~/.ssh`、`.env`、kubeconfig の読み取り後に外伝 |

---

## 3. アーキテクチャ

```
CLI (cobra)
  │
  ├─ Downloader       パッケージのダウンロードとキャッシュ
  │
  ├─ Sandbox          Dockerコンテナによる隔離実行
  │   ├─ network=none  外部通信を完全遮断
  │   ├─ read-only rootfs + tmpfs
  │   └─ no-new-privileges
  │
  ├─ eBPF Probe       ホストカーネルからsyscallを監視
  │   └─ プロセスツリーを追跡してパッケージ起因を判定
  │
  ├─ Analyzer         イベントの分類・リスク判定
  │   └─ 既知パターンDBとの秤量（アノテーション付与）
  │
  └─ Reporter         JSON / SARIF 出力
```

### 実行フロー

1. パッケージをホストでダウンロード・キャッシュ（ネットワーク許可）
2. network遮断コンテナでインストール実行 + eBPFで監視
3. network遮断コンテナでインポート実行 + 同上で記録
4. レポート生成

---

## 4. 技術スタック

| レイヤー | 技術 | 理由 |
|---|---|---|
| 言語 | Go (統一) | 単一バイナリ配布、eBPFバインディングの充実 |
| eBPF probe | `cilium/ebpf` + `bpf2go` | ビルド時にバイトコードを取り込み、カーネルヘッダ不要 |
| eBPF Cコード | C (`.c` ファイル) | BPFプログラム本体はC必須。`bpf2go` で自動生成 |
| CLI | `cobra` | Go標準的なCLIフレームワーク |
| Sandbox | Docker | 隔離の実績、CI環境でのデフォルト利用可 |
| 出力フォーマット | JSON / SARIF | SARIF は GitHub Code Scanning 互換 |

---

## 5. マイルストーン

```
v0.1  PyPI インストール時のみ、Linux のみ
      └─ connect(2) の試みをレポート出力

v0.2  インポート時フェーズを追加
      └─ execve(2) 監視でサブプロセスを追跡

v0.3  npm サポート追加

v0.4  既知パターンDB + アノテーション出力
      └─ SARIF 出力 → GitHub Actions でそのまま使えるアクション化

v0.5  関数ロードフェーズ追加
      └─ エクスポート関数をゼロ引数で呼び出し、実行時通信を検知
```
