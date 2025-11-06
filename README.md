# BLNCS – Bitcoin Lightning Network Control System

## ⚡ 最新アップデート / Latest Updates

### 2025年10月 - システム回復機能と設定管理の大幅強化
- **🔧 Lightning Network自動回復システム**: ノード障害、チャネル接続問題、ピア接続エラーを自動検知・回復
- **⚙️ 統一設定管理システム**: 環境変数、YAMLファイル、デフォルト値の優先順位管理
- **🔌 Lightning API統合**: LND互換の包括的なAPI実装
- **🌐 国際化システム**: 50言語対応のgettextベース多言語サポート
- **🧪 テスト環境改善**: pytest設定と自動テストスクリプト

**詳細は [IMPROVEMENT_IMPLEMENTATION_REPORT.md](./IMPROVEMENT_IMPLEMENTATION_REPORT.md) を参照**

---

## 概要 / Overview
### 日本語
BLNCSは、Lightning Networkノードの運用・監視・保守を一元管理するソフトウェアです。CLI、FlaskベースのREST API、Tkinterダッシュボードを組み合わせ、ローカル検証から本番稼働まで同じ構成で扱えます。50言語対応の国際化システム、構成ファイルのホットリロード、役割別ログ出力、監視エンドポイントを備え、グローバルな業務システムに組み込みやすい構成となっています。

### English
BLNCS is an integrated control system for Bitcoin Lightning Network infrastructure. It ships with a command-line interface, a Flask REST API, and a Tkinter dashboard so operators can deploy, monitor, and maintain nodes using a single toolset. With comprehensive internationalization support for 50+ languages, unified configuration management, structured logging, and health endpoints help teams align with operational governance requirements across global deployments.

## クイックスタート / Quick Start
### 日本語
1. Python 3.10以上を用意します。
2. 社内配布リポジトリまたは提供パッケージから本ソースを取得し、作業ディレクトリに展開します。
3. 仮想環境を作成して依存関係を導入します。
```bash
python -m venv .venv
. .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```
4. 設定テンプレートを生成し、稼働状況を確認します。
```bash
python blncs_main.py config --template
python blncs_main.py status
```

### English
1. Ensure Python 3.10 or newer is installed.
2. Obtain the BLNCS source package from your internal distribution and place it in the working directory.
3. Create a virtual environment and install dependencies.
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```
4. Generate the baseline configuration and verify the system.
```bash
python blncs_main.py config --template
python blncs_main.py status
```

## 主要コンポーネント / Core Components
- `blncs_main.py`: CLIエントリーポイント。状態確認、設定管理、バックアップ、診断、セキュリティ補助コマンドを提供します。
- `blncs/api/unified_rest_api.py`: Flask REST API。`/health`や`/api/system/*`を公開し、CORSやHTTPS強制を設定ファイルで制御できます。
- `blncs/gui/dashboard_gui.py`: Tkinterダッシュボード。RESTポーリングとWebSocket通知で運用状況を可視化します。
- `blncs/gui/net_utils.py`: GUI用HTTP/WSユーティリティ。再試行設定とタイムアウトを一元管理します。
- `blncs/core/system_recovery.py`: **🆕 Lightning Network自動回復システム**。ノード障害や接続問題を自動検知・回復します。
- `blncs/core/lightning_api.py`: **🆕 統一Lightning API**。LND/CLN互換の包括的なAPIを提供します。
- `blncs/core/unified_config.py`: **🆕 統一設定管理**。環境変数・YAMLファイル・デフォルト値の優先順位管理。
- `config/`: JSON構成ファイル群。`BLNCS_ENV`環境変数で読み込むファイルを切り替えます。
- `logs/` と `backups/`: ログとバックアップの出力先。アクセス権限は最小限に保ってください。

## システム要件 / System Requirements
- Python 3.10 以上
- OS: Windows 10/11, macOS 13+, Linux (Ubuntu 22.04 LTS, RHEL 9 相当)
- CPU: 開発用途で2コア以上、本番運用で4コア以上
- メモリ: 開発用途で4 GB以上、本番運用で8 GB以上
- ストレージ: 10 GB以上の空き容量 (ログ・バックアップ保管領域を除く)

## 設定 / Configuration
### 日本語
1. `config/development.json`を基に`config/production.json`を作成します。
2. `BLNCS_ENV=production` を設定し、本番用設定を読み込ませます。
3. 機密情報は `BLNCS_API_AUTHENTICATION_JWT_SECRET` などの環境変数で注入します。
4. `security.trusted_hosts` と `security.enforce_https` を有効化し、TLS終端リバースプロキシから `X-Forwarded-Proto` を受け取る構成にします。

### **🆕 統一設定管理システム**
BLNCS v2.0では、設定管理が大幅に強化されました：
- **優先順位ベースの設定マージ**: 環境変数 → ローカル設定 → 環境別設定 → デフォルト設定
- **YAML/JSON対応**: `config/*.yaml` または `config/*.json` 形式をサポート
- **設定バリデーション**: 起動時に設定値の妥当性を自動検証
- **ホットリロード**: 設定変更を反映するためにシステム再起動不要（開発環境）

**設定ファイル例** (`config/production.yaml`):
```yaml
api:
  host: "0.0.0.0"
  port: 3000
  cors_enabled: true

lightning:
  network: "mainnet"
  host: "localhost"
  port: 10009

monitoring:
  enabled: true
  interval_seconds: 300

security:
  enforce_https: true
  trusted_hosts: ["api.yourdomain.com"]
```

### English
1. Copy `config/development.json` to `config/production.json` and adjust values per environment.
2. Export `BLNCS_ENV=production` so the application loads the production profile.
3. Provide secrets through environment variables, for example `BLNCS_API_AUTHENTICATION_JWT_SECRET`.
4. Enable `security.trusted_hosts` and `security.enforce_https`, and forward `X-Forwarded-Proto=https` from your TLS reverse proxy.

#### CORSとHTTPS設定例 / Example
```json
{
  "api": {
    "cors_enabled": true,
    "cors_allowed_origins": ["https://admin.example"],
    "cors_supports_credentials": true
  },
  "security": {
    "trusted_hosts": ["admin.example"],
    "enforce_https": true,
    "request_timeout": 60,
    "max_request_size": "10MB"
  }
}
```

## 🌐 国際化 / Internationalization

BLNCSは50言語以上の多言語対応をサポートしており、グローバルな運用環境での利用に最適化されています。

### 対応言語 / Supported Languages
- 日本語 (Japanese) - ja
- 英語 (English) - en (デフォルト)
- スペイン語 (Spanish) - es
- フランス語 (French) - fr
- ドイツ語 (German) - de
- 中国語 (Chinese) - zh
- 韓国語 (Korean) - ko
- ポルトガル語 (Portuguese) - pt
- ロシア語 (Russian) - ru
- アラビア語 (Arabic) - ar

### 言語設定 / Language Configuration

#### 環境変数による設定 / Environment Variable
```bash
# 日本語
export BLNCS_LOCALE=ja

# 英語
export BLNCS_LOCALE=en

# スペイン語
export BLNCS_LOCALE=es
```

#### 設定ファイルによる設定 / Configuration File
```json
{
  "i18n": {
    "locale": "ja",
    "fallback_locale": "en"
  }
}
```

#### APIリクエストによる設定 / API Request
```bash
# Accept-Languageヘッダー
curl -H "Accept-Language: ja" http://localhost:3000/api/lightning/info

# クエリパラメータ
curl "http://localhost:3000/api/lightning/info?lang=ja"
```

### 翻訳管理 / Translation Management

#### 翻訳ファイルの初期化 / Initialize Translations
```bash
# 初回セットアップ時のみ実行
python scripts/generate_translations.py --init
```

#### 翻訳ファイルの更新 / Update Translations
```bash
# ソースコードから新しいメッセージを抽出して翻訳ファイルを更新
python scripts/generate_translations.py --update
```

#### 翻訳の編集 / Edit Translations
各言語のPOファイルを編集：
```bash
# 日本語翻訳の編集
vim locale/ja/LC_MESSAGES/blncs.po

# 英語翻訳の編集
vim locale/en/LC_MESSAGES/blncs.po
```

### 開発者向け / For Developers

#### 翻訳関数の使用 / Using Translation Functions
```python
from blncs import _

# シンプルなメッセージ
message = _("Hello, World!")

# パラメータを含むメッセージ
error_msg = _("Error: %s") % error_code

# 複数形
count_msg = _("Found %d item") if count == 1 else _("Found %d items") % count
```

#### 新しいメッセージの追加 / Adding New Messages
1. ソースコードに翻訳関数を使用
2. 翻訳テンプレートを更新: `python scripts/generate_translations.py --update`
3. 各言語の翻訳を追加
4. 翻訳をコンパイル

詳細は [`docs/I18N_GUIDE.md`](./docs/I18N_GUIDE.md) を参照してください。

## 運用 / Operations
- APIサーバー起動: `python blncs_main.py server --host 127.0.0.1 --port 3000`
- Uvicorn常駐: `uvicorn blncs.api.unified_rest_api:create_app --host 0.0.0.0 --port 3000 --workers 4`
- ダッシュボード起動: `python blncs_gui.py --api-base http://127.0.0.1:3000`
- バックアップ作成: `python blncs_main.py backup --create`
- バックアップ一覧: `python blncs_main.py backup --list`
- セキュリティ診断: `python blncs_main.py audit check`
- **🆕 システム回復開始**: `python blncs_main.py recovery start` （Lightning Network自動監視・回復）
- **🆕 システム診断**: `python blncs_main.py recovery diagnostics` （Lightningノード状態チェック）
- **🆕 回復状態確認**: `python blncs_main.py recovery status` （回復履歴と統計情報）

CLIの一部コマンドは `--auth-token` による認証を要求します。運用手順書でトークン配布と失効の管理プロセスを定義してください。

## セキュリティ対策 / Security Hardening
- `security.enforce_https` を有効にし、HTTPアクセスはリバースプロキシで遮断します。
- `api.cors_allowed_origins` には完全修飾オリジンのみを設定し、無効な値は設定しないでください。
- `api.rate_limiting` を必要に応じて有効化し、`requests_per_minute` と `burst_size` を利用者数に合わせて調整します。
- 監査ログは `logs/` 配下に日次で出力されます。変更検知のために外部ストレージへの複製やハッシュ検証を導入してください。
- `config/` と `backups/` は運用担当者のみ書き込み可能にし、他ユーザーには読み取り権限を与えないでください。

## 性能と安定性 / Performance and Reliability
- REST APIは `_response_cache` によるLRUキャッシュを持ち、GETレスポンスの再利用で応答遅延を抑えます。
- `blncs/gui/net_utils.py` のHTTPセッションはリトライとデフォルトタイムアウトを内包しており、通信断時に指数バックオフで再試行します。
- **🆕 Lightning Network自動回復**: `blncs/core/system_recovery.py` がノード障害・チャネル問題・ピア接続エラーを自動検知し、以下の回復アクションを実行：
  - Lightningノードの自動再起動
  - ピア接続の再確立
  - チャネル状態の検証と修復
  - ブロックチェーン同期の確認
  - 失敗した支払いのクリーンアップ
- `python blncs_main.py performance --stats` でCPUやメモリの簡易指標を取得できます。定期監視の上、閾値超過時はスケールアップまたはプロセス調整を行ってください。

## モニタリング / Monitoring
- `/health` を監視ツールからポーリングし、`status` フィールドで状態を判定します。
- `/api/system/metrics` や `/api/system/performance` のJSONレスポンスを用いて外部APMやSIEMに連携します。
- WebSocket通知が必要な場合は `blncs/api/websocket_server.py` の `notify_clients` を利用し、社内の通知基盤へ転送します。

## 個人使用向け機能 / Personal Use Features

BLNCSは個人使用に最適化された機能を提供します。簡単セットアップ、セキュリティ、性能最適化を重視しています。

### 簡単セットアップ
- **1コマンドで起動**: `python blncs_personal.py start`
- **対話型セットアップ**: 初心者でも安心のウィザード形式
- **モックモード**: 実際のLightningノード不要でテスト可能

### セキュリティ
- **自動トークン生成**: 初回起動時に安全なアクセストークンを自動生成
- **localhost専用モード**: デフォルトで外部アクセスを遮断
- **暗号化**: データベースと通信を自動暗号化
- **セキュアファイル**: トークンファイルは自動的に所有者のみ読取可能（600パーミッション）

### パフォーマンス最適化
- **自動最適化**: システム負荷に応じてキャッシュサイズやデータベース接続を自動調整
- **メモリ効率**: 個人使用に最適化され、100MB以下のメモリで動作
- **高速キャッシュ**: よく使う操作は自動キャッシュで高速化
- **軽量データベース**: SQLiteで追加インストール不要

### 個人向けコマンド

```bash
# サーバー起動
python blncs_personal.py start

# トークン管理
python blncs_personal.py tokens
python blncs_personal.py token my-token

# Lightning操作
python blncs_personal.py info
python blncs_personal.py balance
python blncs_personal.py invoice 10000 "Coffee payment"
```

### 個人向けセキュリティベストプラクティス

1. **トークンを安全に保管**: トークンは`~/.blncs/auth.json`に保存されます。バックアップ時は暗号化してください。
2. **定期的なトークンローテーション**:
   ```bash
   python blncs_personal.py revoke old-token
   python blncs_personal.py token new-token
   ```
3. **バックアップの暗号化**:
   ```bash
   gpg --encrypt ~/.blncs/backups/backup_*.db
   ```
4. **ファイアウォール設定**:
   ```bash
   # Linux: localhostのみ許可
   sudo ufw deny 3000
   sudo ufw allow from 127.0.0.1 to any port 3000
   ```

## プロダクション運用向け機能 / Production Features

BLNCSは企業レベルの運用要件に対応する機能を提供します。セキュリティ、監視、信頼性を重視しています。

### セキュリティ制御
- **認証トークン**: JWTベースの認証システム
- **ホスト制限**: `security.trusted_hosts` によるホスト制限
- **入力ガード**: `security.max_request_size` と `security.request_timeout` による入力ガード
- **セキュリティヘッダー**: HSTS と CSP を含むセキュリティヘッダー
- **監査ログ**: 暗号化監査ログ

### パフォーマンス/安定化
- **LRU 応答キャッシュ**: 応答の再利用で遅延を抑える
- **バックグラウンドジョブ**: 再起動フック付き
- **スレッド・キャッシュ制御**: `performance.worker_threads` 等の設定

### 監視と可視化
- **ヘルスチェック**: `/health` や `/api/system/metrics` で稼働状況把握
- **Prometheusメトリクス**: 100+ の詳細なメトリクス提供
- **Grafanaダッシュボード**: 事前設定されたダッシュボード

### プロダクション設定例

```json
{
  "security": {
    "enforce_https": true,
    "trusted_hosts": ["payments.example.com", "admin.example.com"],
    "max_request_size": "10MB",
    "request_timeout": 30,
    "audit_logging": {
      "enabled": true,
      "log_file": "/var/log/blncs/audit.log",
      "retention_days": 2555
    }
  },
  "performance": {
    "cache_enabled": true,
    "cache_ttl": 300,
    "max_cache_size": "256MB",
    "worker_threads": 4
  }
}
```

### 高可用性設定例

```json
{
  "maintenance": {
    "auto_update": false,
    "maintenance_window": "02:00-04:00",
    "auto_restart": true,
    "health_check_enabled": true,
    "cleanup_enabled": true,
    "cleanup_schedule": "0 3 * * 0"
  }
}
## テスト / Testing
```bash
python -m pytest --maxfail=1 --disable-warnings -q
```
GUI関連テストはTkinterをスタブ化して実行されます。ヘッドレス環境では `pytest -k "gui"` を条件付きで利用してください。

## 参考ドキュメント / Additional Documentation
- `docs/DEPLOYMENT_GUIDE_UNIFIED.md`: 導入・運用手順
- `docs/API_REFERENCE_UNIFIED.md`: REST API詳細
- `docs/TROUBLESHOOTING.md`: 障害対応ガイド
- `docs/I18N_GUIDE.md`: 国際化 (i18n) ガイド
- `README_PERSONAL.md`: 個人利用向けチュートリアル
- `README_PRODUCTION.md`: 本番運用設計ガイド


All API endpoints (except `/health`) require JWT authentication:

```bash
# Obtain token (implement your auth endpoint)
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"pass"}'

# Use token in requests
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:3000/api/lightning/info
```

### Core Endpoints

#### Lightning Operations

```bash
# Get node info
GET /api/lightning/info

# Get balance
GET /api/lightning/balance

# Create invoice
POST /api/lightning/invoice
{
  "amount": 1000,
  "memo": "Payment description"
}

# Pay invoice
POST /api/lightning/pay
{
  "payment_request": "lnbc..."
}

# Decode invoice
POST /api/lightning/decode
{
  "payment_request": "lnbc..."
}
```

#### System Management

```bash
# Create backup
POST /api/system/backup

# Get metrics
GET /api/system/metrics

# Optimize system
POST /api/system/optimize
```

## Development

### Running Tests

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest

# Run with coverage
pytest --cov=blncs --cov-report=html

# Run specific test file
pytest tests/test_unified_comprehensive.py -v
```

### Code Quality

```bash
# Format code
black blncs/

# Lint code
flake8 blncs/

# Type checking
mypy blncs/

# Security audit
bandit -r blncs/
```

## Troubleshooting

### Common Issues

**Connection Refused**
```bash
# Check if service is running
systemctl status blncs

# Check logs
journalctl -u blncs -f

# Verify port
netstat -tlnp | grep 3000
```

**Database Connection Failed**
```bash
# Test database connection
python -c "from blncs.core.unified_database import UnifiedDatabase; db = UnifiedDatabase(); print('Connected')"

# Check credentials
echo $BLNCS_DATABASE_URL

# Run migrations
python blncs_main.py db migrate
```

**High Memory Usage**
```bash
# Check resource usage
python blncs_main.py system status

# Optimize database
python blncs_main.py db optimize

# Clear cache
curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:3000/api/cache/clear
```

## Documentation

- **API Reference**: `docs/API_REFERENCE.md`
- **Deployment Guide**: `docs/DEPLOYMENT_GUIDE_UNIFIED.md`
- **Internationalization Guide**: `docs/I18N_GUIDE.md`
- **Quick Start**: `docs/QUICK_START.md`
- **System Architecture**: `SYSTEM_ARCHITECTURE.md`
- **Performance Guide**: `PERFORMANCE_GUIDE.md`

## Contributing

We welcome contributions! Please see `CONTRIBUTING.md` for guidelines.

### Development Process

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## License

This project is licensed under the MIT License - see `LICENSE` file for details.

## Acknowledgments

- Lightning Network Daemon (LND) team
- Core Lightning (CLN) team
- Bitcoin development community
- All contributors and supporters

## Support

### Community Support
- **Issues**: GitHub Issues for bug reports and feature requests
- **Discussions**: GitHub Discussions for questions and community support
- **Documentation**: Comprehensive docs in `docs/` directory

### Enterprise Support
- **Priority Support**: Dedicated support channel
- **Custom Development**: Feature development and customization
- **SLA Guarantees**: 24/7 support with guaranteed response times
- **Training**: Team training and onboarding
- **Contact**: enterprise@yourdomain.com

---

**Built for the Lightning Network community**

**Security Notice**: This is production-grade software designed for mission-critical infrastructure. Always review security settings and perform thorough testing before production deployment.

### High Performance
- **Optimized Caching**: Intelligent response caching with LRU eviction
- **Connection Pooling**: Efficient database connection management
- **Circuit Breakers**: Automatic failover and retry logic
- **Performance Profiling**: Real-time bottleneck detection and optimization
- **Resource Monitoring**: CPU, memory, disk, and network usage tracking

### Production Resilience
- **Disaster Recovery**: Automated backups with verification and point-in-time recovery
- **Health Monitoring**: Comprehensive health checks and alerting
- **Graceful Degradation**: Fault tolerance with automatic failover
- **Error Recovery**: Intelligent retry logic with exponential backoff
- **Database Optimization**: Query performance monitoring and automatic tuning

### Compliance & Governance
- **SOC 2 Type II**: Trust Services Criteria compliance
- **GDPR**: Data protection and privacy controls
- **PCI-DSS**: Payment card industry security standards
- **Audit Trail**: Complete operation history with tamper detection
- **Compliance Reporting**: Automated compliance status reports

## System Requirements

### Minimum
- **OS**: Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+) or Windows 10/11
- **CPU**: 2 cores
- **RAM**: 4 GB
- **Storage**: 20 GB SSD
- **Network**: 100 Mbps
- **Python**: 3.10+

### Recommended (Production)
- **OS**: Linux (Ubuntu 22.04 LTS or RHEL 9)
- **CPU**: 4+ cores
- **RAM**: 8 GB+
- **Storage**: 50 GB+ NVMe SSD
- **Network**: 1 Gbps with redundancy
- **Python**: 3.11+

## Quick Start

### 1. Installation

```bash
# Clone repository
git clone https://github.com/yourusername/BLNCS.git
cd BLNCS

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Initialize translations (first time only)
python scripts/generate_translations.py --init

# Set language to Japanese
export BLNCS_LOCALE=ja

# Verify installation
python blncs_main.py --version
```

### 2. Configuration

Create production configuration:

```bash
# Copy example configuration
cp config/development.json config/production.json

# Edit configuration
nano config/production.json
```

**Essential Configuration** (`config/production.json`):

```json
{
  "version": "2.0.0",
  "environment": "production",
  "lightning": {
    "network": "mainnet",
    "host": "localhost",
    "port": 10009,
    "macaroon_path": "/path/to/admin.macaroon",
    "tls_cert_path": "/path/to/tls.cert"
  },
  "api": {
    "enabled": true,
    "host": "0.0.0.0",
    "port": 3000,
    "cors_enabled": true,
    "cors_allowed_origins": ["https://yourdomain.com"],
    "rate_limiting": {
      "enabled": true,
      "requests_per_minute": 100,
      "burst_size": 150
    }
  },
  "security": {
    "trusted_hosts": ["yourdomain.com", "api.yourdomain.com"],
    "enforce_https": true,
    "max_request_size": "10MB",
    "request_timeout": 30,
    "ip_whitelist": []
  },
  "database": {
    "url": "postgresql://user:pass@localhost/blncs",
    "pool_size": 10,
    "max_overflow": 20
  },
  "logging": {
    "level": "INFO",
    "output": "file",
    "file_path": "logs/blncs.log",
    "max_bytes": 10485760,
    "backup_count": 10
  },
  "backup": {
    "enabled": true,
    "retention_days": 30,
    "destinations": {
      "local": {
        "enabled": true,
        "path": "backups"
      }
    }
  }
}
```

### 3. Environment Variables

Set critical environment variables:

```bash
# Production environment
export BLNCS_ENV=production

# Security (REQUIRED for production)
export BLNCS_API_AUTHENTICATION_JWT_SECRET="your-secure-random-secret-here"
export BLNCS_SECURITY_ENFORCE_HTTPS=true

# Database (if not in config)
export BLNCS_DATABASE_URL="postgresql://user:pass@localhost/blncs"

# Logging
export BLNCS_LOG_LEVEL=INFO
```

### 4. Database Setup

```bash
# Initialize database
python blncs_main.py db init

# Run migrations
python blncs_main.py db migrate

# Verify database
python blncs_main.py db status
```

### 5. Start Server

```bash
# Start API server
python blncs_main.py server

# Or with uvicorn for production
uvicorn blncs.api.unified_rest_api:create_app --host 0.0.0.0 --port 3000 --workers 4
```

Access the API at: `http://localhost:3000`

### 6. Health Check

```bash
# Check system health
curl http://localhost:3000/health

# Expected response:
{
  "status": "healthy",
  "timestamp": 1704067200.0,
  "checks": {
    "database": "ok",
    "cache": "ok",
    "lightning": "available"
  }
}
```

## 🐳 Docker Deployment

### Quick Start

```bash
# Build image
docker build -t blncs:latest .

# Run container
docker run -d \
  --name blncs \
  -p 3000:3000 \
  -e BLNCS_ENV=production \
  -e BLNCS_API_AUTHENTICATION_JWT_SECRET="your-secret" \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  blncs:latest

# View logs
docker logs -f blncs
```

### Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

**docker-compose.yml**:

```yaml
version: '3.8'

services:
  blncs:
    image: blncs:latest
    ports:
      - "3000:3000"
    environment:
      - BLNCS_ENV=production
      - BLNCS_DATABASE_URL=postgresql://blncs:password@postgres:5432/blncs
    volumes:
      - ./config:/app/config
      - ./data:/app/data
      - ./logs:/app/logs
    depends_on:
      - postgres
      - redis
    restart: unless-stopped

  postgres:
    image: postgres:16-alpine
    environment:
      - POSTGRES_DB=blncs
      - POSTGRES_USER=blncs
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    restart: unless-stopped

volumes:
  postgres_data:
```

## ☸️ Kubernetes Deployment

```bash
# Create namespace
kubectl create namespace blncs

# Deploy application
kubectl apply -f k8s/deployment.yaml

# Verify deployment
kubectl get pods -n blncs
kubectl logs -f deployment/blncs -n blncs

# Access service
kubectl port-forward service/blncs 3000:3000 -n blncs
```

## Security Hardening

### 1. TLS/HTTPS Setup

Use reverse proxy (nginx or Caddy) for TLS termination:

**Nginx Configuration** (`/etc/nginx/sites-available/blncs`):

```nginx
server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 2. Firewall Configuration

```bash
# Allow SSH
ufw allow 22/tcp

# Allow HTTPS
ufw allow 443/tcp

# Block direct API access
ufw deny 3000/tcp

# Enable firewall
ufw enable
```

### 3. Security Scanning

```bash
# Run security scan
python blncs_main.py security scan

# View security report
cat compliance_reports/security_scan_latest.json

# Check for vulnerable dependencies
safety check -r requirements.txt
```

## Monitoring & Observability

### Health Monitoring

```bash
# Check health endpoint
curl http://localhost:3000/health

# Get detailed metrics
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:3000/api/system/metrics
```

### Performance Profiling

```bash
# View performance metrics
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:3000/api/system/performance

# Export performance report
python blncs_main.py performance report --output=performance.json
```

### Audit Logs

```bash
# View audit logs
tail -f logs/audit/audit-$(date +%Y-%m-%d).jsonl

# Query specific events
python blncs_main.py audit query --type=payment_sent --limit=100
```

## 🔄 Backup & Recovery

### Automated Backups

```bash
# Create backup
curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:3000/api/system/backup

# List backups
python blncs_main.py backup list

# Verify backup integrity
python blncs_main.py backup verify <backup_id>
```

### Restore from Backup

```bash
# Restore specific backup
python blncs_main.py backup restore <backup_id> --path=/restore/location

# Restore latest backup
python blncs_main.py backup restore --latest --path=/restore/location
```

## 📈 API Reference

### Authentication

All API endpoints (except `/health`) require JWT authentication:

```bash
# Obtain token (implement your auth endpoint)
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"pass"}'

# Use token in requests
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:3000/api/lightning/info
```

### Core Endpoints

#### Lightning Operations

```bash
# Get node info
GET /api/lightning/info

# Get balance
GET /api/lightning/balance

# Create invoice
POST /api/lightning/invoice
{
  "amount": 1000,
  "memo": "Payment description"
}

# Pay invoice
POST /api/lightning/pay
{
  "payment_request": "lnbc..."
}

# Decode invoice
POST /api/lightning/decode
{
  "payment_request": "lnbc..."
}
```

#### System Management

```bash
# Create backup
POST /api/system/backup

# Get metrics
GET /api/system/metrics

# Optimize system
POST /api/system/optimize
```

## 🧪 Development

### Running Tests

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest

# Run with coverage
pytest --cov=blncs --cov-report=html

# Run specific test file
pytest tests/test_unified_comprehensive.py -v
```

### Code Quality

```bash
# Format code
black blncs/

# Lint code
flake8 blncs/

# Type checking
mypy blncs/

# Security audit
bandit -r blncs/
```

## 🐛 Troubleshooting

### Common Issues

**Connection Refused**
```bash
# Check if service is running
systemctl status blncs

# Check logs
journalctl -u blncs -f

# Verify port
netstat -tlnp | grep 3000
```

**Database Connection Failed**
```bash
# Test database connection
python -c "from blncs.core.unified_database import UnifiedDatabase; db = UnifiedDatabase(); print('Connected')"

# Check credentials
echo $BLNCS_DATABASE_URL

# Run migrations
python blncs_main.py db migrate
```

**High Memory Usage**
```bash
# Check resource usage
python blncs_main.py system status

# Optimize database
python blncs_main.py db optimize

# Clear cache
curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:3000/api/cache/clear
```

## 📚 Documentation

- **API Reference**: `docs/API_REFERENCE.md`
- **Deployment Guide**: `docs/DEPLOYMENT_GUIDE_UNIFIED.md`
- **Quick Start**: `docs/QUICK_START.md`
- **System Architecture**: `SYSTEM_ARCHITECTURE.md`
- **Performance Guide**: `PERFORMANCE_GUIDE.md`

## 🤝 Contributing

We welcome contributions! Please see `CONTRIBUTING.md` for guidelines.

### Development Process

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📜 License

This project is licensed under the MIT License - see `LICENSE` file for details.

## 🙏 Acknowledgments

- Lightning Network Daemon (LND) team
- Core Lightning (CLN) team
- Bitcoin development community
- All contributors and supporters

## 📞 Support

### Community Support
- **Issues**: GitHub Issues for bug reports and feature requests
- **Discussions**: GitHub Discussions for questions and community support
- **Documentation**: Comprehensive docs in `docs/` directory

### Enterprise Support
- **Priority Support**: Dedicated support channel
- **Custom Development**: Feature development and customization
- **SLA Guarantees**: 24/7 support with guaranteed response times
- **Training**: Team training and onboarding
- **Contact**: enterprise@yourdomain.com

---

**Built for the Lightning Network community**

**Security Notice**: This is production-grade software designed for mission-critical infrastructure. Always review security settings and perform thorough testing before production deployment.
