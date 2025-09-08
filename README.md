# BLNCS - Bitcoin Lightning Network Control System

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

**軽量で実用的なBitcoin Lightning Network管理ツール**

Pythonで作られた、シンプルで使いやすいLightning Network管理CLI/APIツールです。

---

## 主な機能

### 基本機能
- **Lightning Node接続**: LND、Core Lightning、Eclairに対応
- **ウォレット管理**: 残高確認、取引履歴、統計表示
- **チャネル管理**: チャネル開設・閉鎖、状態監視
- **支払い機能**: インボイス作成・支払い、手数料最適化
- **システム監視**: ヘルスチェック、パフォーマンス監視

### CLI機能
- **豊富なコマンド**: 20以上の実用的コマンド
- **設定管理**: YAML設定ファイルサポート
- **ログ・履歴**: 取引履歴と統計情報
- **バックアップ**: システムデータのバックアップ・復元
- **診断機能**: 接続テスト、システム診断

---

## システム要件

- **Python**: 3.8以上
- **OS**: Linux, macOS, Windows
- **メモリ**: 512MB以上
- **ディスク**: 50MB以上

### 対応Lightning実装
- **LND**: v0.15.0以上
- **Core Lightning**: v0.11.0以上
- **Eclair**: v0.7.0以上

---

## インストール

### 1. システム要件

- Python 3.8以上
- pip パッケージマネージャー
- Lightning Network ノード (本番環境用、オプション)

### 2. インストール手順

```bash
# リポジトリをクローン
git clone https://github.com/yourusername/blncs.git
cd blncs

# 依存関係をインストール
pip install -r requirements.txt

# BLNCSをインストール
pip install -e .
```

### 3. 初期設定

```bash
# 設定を初期化
python -m blncs.cli.main setup
```

### 4. 動作確認

```bash
# システム状態確認
python -m blncs.cli.main status

# テスト実行
python run_quick_tests.py
```

## クイックスタート

### 基本的な使用方法

```bash
# ノード情報表示
python -m blncs.cli.main info

# 残高確認
python -m blncs.cli.main balance

# チャネル一覧
python -m blncs.cli.main channels

# ヘルスチェック
python -m blncs.cli.main health
```

### 支払い機能

```bash
# インボイス作成 (1000 satoshi)
python -m blncs.cli.main invoice 1000 --memo "テスト支払い"

# 支払い実行
python -m blncs.cli.main pay <lightning_invoice>
```

---

## 主要コマンド

| コマンド | 説明 |
|----------|------|
| `status` | システム状態確認 |
| `info` | ノード情報表示 |
| `balance` | 残高確認 |
| `channels` | チャネル一覧 |
| `invoice <amount>` | インボイス作成 |
| `pay <invoice>` | 支払い実行 |
| `health` | ヘルスチェック |
| `setup` | 初期設定 |
| `backup` | バックアップ作成 |

### その他の機能

```bash
# バックアップ作成
python -m blncs.cli.main backup create

# 取引履歴
python -m blncs.cli.main history

# システム最適化
python -m blncs.cli.main optimize

# 監視開始
python -m blncs.cli.main monitor

# クイック状況確認
python -m blncs.cli.main quick-status
```

---

## 設定

設定ファイル例 (`config/config.yaml`):

```yaml
# Lightning Node設定
lightning:
  host: localhost
  port: 8080
  network: testnet  # mainnet, testnet, regtest
  cert_path: ~/.lnd/tls.cert
  macaroon_path: ~/.lnd/data/chain/bitcoin/testnet/readonly.macaroon

# ログ設定
logging:
  level: INFO
  file_enabled: true

# 監視設定
monitoring:
  enabled: true
  interval: 60
```

### 環境変数

```bash
# Lightning Node設定
export LN_HOST=localhost
export LN_PORT=10009
export LN_NETWORK=testnet
export LN_MACAROON_PATH=/path/to/readonly.macaroon

# ログレベル
export LOG_LEVEL=INFO
```

## Dockerでの実行

```bash
# Dockerイメージビルド
docker build -t blncs:latest .

# Docker Composeで実行
docker-compose up -d
```

## トラブルシューティング

### よくある問題

#### 接続エラー
```bash
# 接続設定確認
python -m blncs.cli.main health

# 設定ファイル確認
cat config/config.yaml
```

#### 認証エラー
```bash
# Macaroonファイルのパーミッション確認
ls -la ~/.lnd/data/chain/bitcoin/testnet/
```

#### デバッグ情報
```bash
# 詳細ログで実行
python -m blncs.cli.main --verbose status

# テスト実行
python run_quick_tests.py
```

## セキュリティ

- 設定ファイルでのAPI認証サポート
- IPホワイトリスト機能
- レート制限機能
- セキュアな設定管理

## 監視機能

```bash
# 監視開始
python -m blncs.cli.main monitor

# ヘルスチェック
python -m blncs.cli.main health

# システム統計
python -m blncs.cli.main stats
```

## サポート

- **GitHub Issues**: バグレポート・機能リクエスト
- **ドキュメント**: `docs/` ディレクトリを参照
- **テスト**: `python run_quick_tests.py` で動作確認

## 更新履歴

### v1.0.0
- 初回リリース
- Lightning Network基本機能
- CLIインターフェース
- 設定管理
- ヘルスチェック機能

## ライセンス

MIT License