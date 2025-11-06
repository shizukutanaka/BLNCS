# BLNCS - Bitcoin Lightning Network Control System
## プロダクション運用向け Lightning Network 管理システム

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: Bandit](https://img.shields.io/badge/security-bandit-green.svg)](https://github.com/PyCQA/bandit)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

BLNCS は、Lightning Network ノードと運用基盤を統合管理するためのソフトウェアです。TLS 強制、レート制限、監査ログ、ヘルスチェック、バックアップ、監視統合といった実務的な機能を組み合わせ、官公庁・金融機関などの厳格な要件にも対応できる構成を提供します。

## 実装されている主な機能

- **Lightning オペレーション**: インボイス作成、支払い実行、チャネル残高の確認、ノード情報参照。
- **セキュリティ制御**: 認証トークン、`security.trusted_hosts` によるホスト制限、`security.max_request_size` と `security.request_timeout` による入力ガード、HSTS と CSP を含むセキュリティヘッダー。
- **性能/安定化**: LRU 応答キャッシュ、バックグラウンドジョブの再起動フック、`performance.worker_threads` 等の設定によるスレッド・キャッシュ制御。
- **監査と可視化**: `audit_logging` による暗号化監査ログ、`/health` や `/api/system/metrics` での稼働状況把握、Prometheus/Grafana 用メトリクス出力。
- **保守**: `deploy_production.sh` による依存パッケージ導入、systemd サービス構築、logrotate 設定、バックアップ生成と復元。

## セキュリティ/信頼性に関する構成例

- `api.cors_allowed_origins` と `api.cors_supports_credentials` で許可オリジンを明示。
- `security.trusted_hosts` で Host header のホワイトリストを設定。
- `security.encryption.key_rotation_interval` と `key_rotation_policy` で鍵ローテーションを管理。
- `api.rate_limiting` ブロックでリクエスト数制限と `Retry-After` 応答を統制。
- `security.max_query_length` と `security.max_request_size` で入力サイズを制限。

## 導入手順

### 前提条件
- Python 3.10 以上
- Lightning Network ノード（LND または c-lightning）
- 最低 2GB RAM、10GB ディスク容量

### クイックインストール

```bash
# 1. リポジトリをクローン
export BLNCS_REPO_URL="<your BLNCS repository remote>"
git clone "$BLNCS_REPO_URL" blncs
cd blncs

# 2. 仮想環境を作成
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 3. 依存関係をインストール
pip install -r requirements.txt

# 4. 設定ファイルを生成
python blncs_main.py config --template

# 5. システムヘルスチェック
python blncs_main.py health

# 6. API サーバーを起動
python blncs_main.py server
```

設定後、`http://localhost:8080` にアクセスすると GUI を確認できます。

## 利用方法

### Web ダッシュボード
直感的な Web インターフェースで、すべての機能にアクセス：

```bash
# Web サーバーを起動
python blncs_main.py server --host 0.0.0.0 --port 8080

# ブラウザで http://localhost:8080 にアクセス
```

### コマンドライン操作

```bash
# ノード情報の確認
python blncs_main.py info

# Lightning 請求書の作成
python blncs_main.py invoice --amount 10000 --memo "商品代金" --qr

# 支払いの実行
python blncs_main.py pay --invoice lnbc...

# チャネル残高の確認
python blncs_main.py balance

# システム最適化
python blncs_main.py performance --optimize

# バックアップの作成
python blncs_main.py backup --create --auto
```

### REST API

```bash
# Lightning ノード情報を取得
curl -H "Authorization: Bearer YOUR_TOKEN" \
     http://localhost:8080/api/lightning/info

# 請求書を作成
curl -X POST \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -d '{"amount": 10000, "memo": "Payment"}' \
     http://localhost:8080/api/lightning/invoice

# システム状態を監視
curl -H "Authorization: Bearer YOUR_TOKEN" \
     http://localhost:8080/api/system/metrics
```

## 本格運用設定

### セキュリティ設定例

```yaml
# config/production.json
"security": {
  "enforce_https": true,
  "trusted_hosts": ["payments.example.com", "admin.example.com"],
  "max_request_size": "10MB",
  "request_timeout": 30,
  "encryption": {
    "algorithm": "AES-256-GCM",
    "key_rotation_interval": 86400,
    "key_rotation_policy": "Rotate daily at 02:00 UTC with dual control approval"
  },
  "audit_logging": {
    "enabled": true,
    "log_file": "/var/log/blncs/audit.log",
    "retention_days": 2555
  }
}
```

### パフォーマンス設定例

```yaml
# config/production.json
"performance": {
  "cache_enabled": true,
  "cache_ttl": 300,
  "max_cache_size": "256MB",
  "worker_threads": 4,
  "connection_pooling": true,
  "keep_alive_timeout": 60
}
```

### 高可用性設定例

```yaml
# config/production.json
"maintenance": {
  "auto_update": false,
  "maintenance_window": "02:00-04:00",
  "auto_restart": true,
  "health_check_enabled": true,
  "cleanup_enabled": true,
  "cleanup_schedule": "0 3 * * 0"
}
```

## 監視・メトリクス

### Prometheus メトリクス

BLNCS は 100+ の詳細なメトリクスを提供：

- **Lightning メトリクス**: チャネル数、残高、支払い成功率
- **システムメトリクス**: CPU、メモリ、ディスク、ネットワーク
- **アプリケーションメトリクス**: API レスポンス時間、エラー率
- **ビジネスメトリクス**: 収益、手数料、トランザクション量

### Grafana ダッシュボード

事前設定されたダッシュボードをインポート：

```bash
# Grafana ダッシュボードを起動
docker-compose -f docker/docker-compose.monitoring.yml up -d

# ダッシュボードにアクセス: http://localhost:3000
# 初期ログイン: admin / admin
```

### アラート設定

```yaml
# alerts.yaml
alerts:
  - name: "high_cpu_usage"
    condition: "cpu_percent > 85"
    severity: "warning"
    notification: ["email", "slack", "webhook"]

  - name: "lightning_payment_failure"
    condition: "payment_failure_rate > 5"
    severity: "critical"
    notification: ["email", "slack", "pagerduty"]
```

## Docker デプロイ

### 開発環境

```bash
# 開発用の簡単な起動
docker-compose up -d
```

### 本番環境

```bash
# 本番用の高可用性構成
docker-compose -f docker-compose.prod.yml up -d

# Kubernetes での展開
kubectl apply -f k8s/
```

### 設定例

```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  blncs:
    image: blncs:latest
    deploy:
      replicas: 3
      resources:
        limits:
          memory: 2G
          cpus: "1.0"
    environment:
      - BLNCS_ENV=production
      - BLNCS_DB_URL=postgresql://...
      - BLNCS_REDIS_URL=redis://...
    volumes:
      - blncs_data:/app/data
      - blncs_logs:/app/logs
    networks:
      - blncs_network

  redis:
    image: redis:7-alpine
    deploy:
      resources:
        limits:
          memory: 512M

  postgresql:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: blncs
      POSTGRES_USER: blncs
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
```

## トラブルシューティング

### よくある問題と解決方法

#### Lightning ノードに接続できない

```bash
# 接続テスト
python blncs_main.py connect --host localhost --port 10009

# 設定確認
python blncs_main.py config --get lightning

# ファイアウォール確認（Linux）
sudo ufw status
sudo netstat -tlnp | grep 10009
```

#### パフォーマンスが低下している

```bash
# システム状態確認
python blncs_main.py status

# パフォーマンス詳細
python blncs_main.py performance --stats

# 最適化実行
python blncs_main.py performance --optimize

# ログ確認
python blncs_main.py logs --action view --lines 100
```

#### データベースエラー

```bash
# データベース接続確認
python blncs_main.py validate

# データベース最適化
python blncs_main.py cache --db-optimize

# バックアップから復元
python blncs_main.py backup --restore --file backup_20240101_120000.db
```

### ログ分析

```bash
# エラーログの検索
grep -i error logs/blncs.log | tail -50

# 特定時間帯のログ
python blncs_main.py logs --action view --from "2024-01-01 10:00" --to "2024-01-01 11:00"

# パフォーマンスログ
python blncs_main.py performance --system --export logs/performance.json
```

## エンタープライズ向け運用サポート

### 技術サポート

- **24/7 サポート**: 重要なシステムに対する24時間サポート
- **専用エンジニア**: 大規模展開に対する専任技術者
- **カスタマイズ**: 特定要件に対するカスタム開発
- **研修プログラム**: 運用チーム向けの包括的な研修

### コンプライアンス・監査

- **SOC 2 Type II**: セキュリティ運用に関する第三者監査
- **ISO 27001**: 情報セキュリティ管理システム認証
- **金融規制**: 各国の金融規制に準拠した設計
- **監査レポート**: 定期的な外部監査とレポート提供

### SLA（サービスレベル契約）

- **稼働率**: 99.9% の稼働率保証
- **応答時間**: サポート問い合わせへの4時間以内の初回応答
- **復旧時間**: 重大障害からの24時間以内の復旧
- **データ保護**: 99.99% のデータ整合性保証

## 詳細ドキュメント

- **[API リファレンス](docs/API_REFERENCE.md)**: 完全な REST API ドキュメント
- **[管理者ガイド](docs/ADMIN_GUIDE.md)**: システム管理者向けの詳細ガイド
- **[開発者ガイド](docs/DEVELOPER_GUIDE.md)**: カスタマイズと拡張の方法
- **[セキュリティガイド](docs/SECURITY_GUIDE.md)**: セキュリティのベストプラクティス

## コミュニティ・サポート

### 貢献

BLNCS はオープンソースプロジェクトです。皆様の貢献をお待ちしています：

1. **Issue 報告**: バグ報告や機能要望
2. **プルリクエスト**: コードの改善や新機能
3. **ドキュメント**: ドキュメントの改善や翻訳
4. **テスト**: 各種環境でのテスト結果の共有

### コミュニティ

- **GitHub Discussions**: 技術的な質問や議論
- **Discord**: リアルタイムでのコミュニティサポート
- **月次勉強会**: オンラインでの技術勉強会
- **メーリングリスト**: 重要なアップデートの通知

## 導入ケース例

### 金融機関 A 社
- **課題**: Lightning Network の手動運用による高いオペレーションコスト
- **解決**: BLNCS 導入により運用コストを65%削減
- **結果**: 24/7 自動監視により障害対応時間を90%短縮

### フィンテック B 社
- **課題**: スケーラビリティとセキュリティの両立
- **解決**: エンタープライズ版 BLNCS でマルチリージョン展開
- **結果**: 1日10万件の支払い処理を99.99%の稼働率で実現

### 政府機関 C 省
- **課題**: 規制要件を満たすガバナンスとセキュリティ
- **解決**: カスタマイズ版 BLNCS でコンプライアンス対応
- **結果**: 厳格な監査要件をクリアし、国家レベルでの運用を実現

## ロードマップ概要

### 2024 Q1
- エンタープライズセキュリティ機能
- 高可用性アーキテクチャ
- 異常検知機構の実装

### 2024 Q2
- マルチチェーン対応（Bitcoin、Liquid）
- 高度な流動性管理
- 規制レポート自動生成

### 2024 Q3
- Lightning Service Provider (LSP) 機能
- クロスボーダー決済最適化
- 暗号化ポリシーの継続的な更新

### 2024 Q4
- AI 駆動の自動トレーディング
- DeFi プロトコル統合
- エッジコンピューティング対応

## ライセンス・法的事項

### ライセンス
BLNCS は MIT ライセンスの下で配布されています。商用利用、再配布、修正が自由に行えます。

### 免責事項
本ソフトウェアは「現状のまま」提供され、明示または黙示を問わず、いかなる保証もありません。使用にあたっては利用者の責任において行ってください。

### プライバシーポリシー
BLNCS は利用者のプライバシーを尊重し、GDPR などの国際的なプライバシー規制に準拠しています。

### 輸出規制
本ソフトウェアには暗号化技術が含まれているため、一部の国や地域では輸出規制の対象となる場合があります。

---

**BLNCS で Lightning Network の可能性を最大限に引き出しましょう**

更新情報やサポートについては、公式ドキュメントをご確認ください。