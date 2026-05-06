# kojuto

パッケージインストールのための EDR — インストール・インポート時の syscall を監視し、サプライチェーン攻撃を検知します。PyPI と npm に対応。

## 概要

kojuto は、パッケージを強化された Docker コンテナ内でインストール・インポートし、strace（または eBPF）で syscall を監視することで、サプライチェーン攻撃を検知します。

## 仕組み

1. **ダウンロード** — パッケージをホストにダウンロード（ネットワーク許可）
2. **隔離実行** — ネットワーク隔離された Docker コンテナでインストール実行
3. **インストール監視** — `connect`, `sendto`, `sendmsg`, `sendmmsg`, `bind`, `listen`, `accept`/`accept4`, `execve`, `openat`, `rename`/`renameat`/`renameat2`, `mmap`, `mprotect`, `unlink`/`unlinkat`, `sendfile`, `ptrace` syscall を記録。audit hook により `compile`/`exec`/`import`（Python PEP 578）および `eval`/`Function`/`vm`（Node.js `--require`）の動的コード実行を検知
4. **インポート監視** — Linux / Windows / macOS の 3 つの OS ID で、`libfaketime` により時刻を +30〜180 日（ランダム）進めた状態でパッケージをインポートし、プラットフォーム依存・日付依存のペイロードを検知
5. **レポート** — 検知結果を JSON で出力

サンドボックスには、マルウェアの動作を誘発するためのリアルなアーティファクトが配置されます：

- 偽の認証情報ファイル（`~/.ssh/id_rsa`、`~/.aws/credentials`、`~/.git-credentials` 等）
- CI・開発者環境変数（`CI=true`、`GITHUB_TOKEN`、`AWS_ACCESS_KEY_ID` 等）

全ての値はスキャンごとに `crypto/rand` でランダム生成され、シグネチャベースの回避を防止します。

`openat` により認証情報ファイル（SSH/GPG 鍵、クラウド認証情報、暗号資産ウォレット、ブラウザデータ等 ~60 パス、`kojuto.yml` でカスタマイズ可能）へのアクセスを検知し、`/home/` ディレクトリへの書き込みをホワイトリスト方式で検知します（pip/npm は site-packages と `/usr/local/bin` にのみ書き込むため、ホームディレクトリへの書き込みは全て不正）。`rename` により信頼されたバイナリの差し替えを、`bind`/`listen`/`accept` によりバックドアサーバーの設置を検知します。`mmap`/`mprotect` により PROT_WRITE+PROT_EXEC の同時指定（シェルコード注入）を検知します。`unlink` はファイル作成→実行→削除の 3 点相関によりアンチフォレンジック（ペイロード自己削除）を検知します。DNS トンネリング検知は `sendto` ペイロードからクエリドメインを抽出し、高エントロピーなサブドメインによるデータ流出を検出します。`/proc/self/status`、`/proc/self/mountinfo`、`/sys/class/net` 等の読み取りをサンドボックス検知の回避行為として検知します（`/proc/self/maps`・`/proc/self/cgroup` は誤検知が多いためデフォルトでは無効、必要なら `kojuto.yml` の `include` で有効化）。`ptrace(PTRACE_TRACEME)` によりアンチデバッグ回避を検知します。

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

# gVisor はデフォルトで自動検出（利用可能なら runsc、なければ runc）
# 明示的に gVisor ランタイムを指定
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
| `--runtime` | コンテナランタイム: `auto`（デフォルト、gVisor 利用可能なら使用）、`runsc`、`runc` |
| `--probe-method` | `auto` / `ebpf` / `strace` / `strace-container`（デフォルト: `auto`） |
| `--timeout` | パッケージごとのタイムアウト（デフォルト: `5m`） |
| `--config` | 設定ファイルのパス（デフォルト: カレントディレクトリの `kojuto.yml`） |
| `--strict` | 設定ファイルの `sensitive_paths.exclude` を無視（CLI デフォルト: `false`、GitHub Action は CI セーフティのためデフォルトで `true`） |

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
- **時刻シフト実行** — `libfaketime` で時計を +30〜180 日（ランダム）進め、日付ゲートの時限爆弾を検知
- **マルチ OS ID** — OS 依存のペイロードを検知するプラットフォームシミュレーション

このアプローチにより、無菌なサンドボックスでは休眠したままの環境依存型・遅延実行型のサプライチェーン攻撃を検知します。

## 検知ベンチマーク

[Datadog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) からランダムに 300 件を抽出して検証（seed=42、再現可能）。

| 指標 | 結果 |
|------|------|
| 真陽性率 | **100%**（インストール可能な悪性パッケージ 61/61 検知） |
| 偽陽性率 | **0%**（正常 70 パッケージで誤検知なし） |
| バッチスクリーニング速度 | **PyPI 50 パッケージを 98 秒**（単一サンドボックス） |

300 件中 238 件は依存パッケージが既に PyPI から削除されておりインストール不可（アーカイブ済みマルウェアの特性）。インストールに成功した 61 件は全て検知。

### 検知した攻撃カテゴリ

| カテゴリ | 検知例 | 検知手法 |
|----------|--------|----------|
| C2 通信 (`c2_communication`) | `aiogram-types-v3` → `147.45.124.42:80` | `connect`/`sendto` による非 loopback IP への接続 |
| データ窃取 (`data_exfiltration`) | Discord/Telegram/Pastebin への DNS 解決 | `sendto` port 53 で既知の窃取サービスを解決 |
| 認証情報アクセス (`credential_access`) | `axios-attack-demo` → `.ssh/id_rsa`, `.solana/id.json` | `openat`（SSH、クラウド、暗号資産ウォレット、ブラウザデータ等 60+ パス） |
| コード実行 (`code_execution`) | `advpruebitaa` → `/tmp/ld.py` | `execve`（`-c`/`-e` フラグ、`/tmp`・`/dev/shm` からの実行） |
| メモリ実行 (`memory_execution`) | `ctypes.mmap(RWX)` シェルコード注入 | `mmap`/`mprotect` で PROT_WRITE+PROT_EXEC の同時指定 |
| バイナリハイジャック (`binary_hijacking`) | `rename /tmp/evil /usr/local/bin/python3` | `rename` による信頼バイナリの差し替え |
| バックドア (`backdoor`) | `bind` + `listen` + `accept` | インストール中のサーバソケット操作 |
| 永続化 (`persistence`) | `.bashrc`、`.config/systemd/user/`、`/home/` への書き込み | `openat` のホームディレクトリ書き込み検知（ホワイトリスト方式） |
| DNS トンネリング (`dns_tunneling`) | 高エントロピーサブドメインクエリ、DoH 接続 | `sendto` port 53 エントロピー > 3.5、既知 DoH サーバへの `connect` |
| 回避行為 (`evasion`) | `ptrace(PTRACE_TRACEME)`、`/proc/self/status`、`/sys/class/net` の読み取り | ptrace 自己チェック、サンドボックス検知の `/proc`/`/sys` 読み取り |
| アンチフォレンジック (`anti_forensics`) | `/tmp/payload` 作成→実行→削除 | `unlink` と `openat(O_CREAT)` + `execve` の 3 点相関 |
| 動的コード実行 (`dynamic_code_execution`) | `eval(base64(...))`、`new Function()`、`vm.runInNewContext()` | audit hook: Python PEP 578（`compile`/`exec`）、Node.js `--require`（`eval`/`Function`/`vm`） |

### 設定

機密パスパターンは `kojuto.yml` でカスタマイズ可能（[`kojuto.example.yml`](../kojuto.example.yml) 参照）:

```yaml
sensitive_paths:
  include:
    - "/.config/custom-app/"
  exclude:
    - "/.bashrc"   # パッケージが正当にシェル設定を読む場合
```

## 既知の制限事項

kojuto は syscall レベルで悪性挙動を検知します。以下の攻撃ベクトルは検知範囲外です：

- **Python の `eval`/`exec`、Node.js の `Function()`** — audit hook（Python PEP 578、Node.js `--require`）により部分的に検知可能。ただし `ctypes` による hook 無効化や hook 存在検知による回避が可能
- **環境変数の読み取り** — `os.environ.get()` は syscall を生成しない純粋メモリ操作（ハニーポット値を設置して影響を緩和）
- **W^X シェルコード** — `mmap(RW)` → `mprotect(RX)` は V8 JIT と区別不能（同時 RWX は検知可能）
- **関数呼び出しゲート型ペイロード** — import フェーズではトップレベルコードのみ実行、関数呼び出しは行わない
- **低エントロピー DNS トンネリング** — 辞書エンコードされたデータは Shannon エントロピーヒューリスティックを回避（`--network=none` で緩和）
- **strace/network-none 検知** — `/proc/self/status` の TracerPid や `/sys/class/net` がサンドボックスを暴露（読み取りは `evasion` として検知するが、strace ベースでは防止不可）

詳細は [SECURITY.md](../SECURITY.md) を参照してください。

## セキュリティ

[SECURITY.md](../SECURITY.md) を参照してください。

## ライセンス

[MIT](../LICENSE)