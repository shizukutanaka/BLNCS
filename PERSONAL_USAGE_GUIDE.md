# BLNCS 個人使用ガイド / Personal Usage Guide

BLNCSを個人で最大限活用するためのガイドです。

## クイックスタート / Quick Start

### 1. インストール

```bash
cd BLNCS
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. セットアップ

```bash
# 対話型セットアップウィザード
python blncs_personal.py setup

# または手動で開始
python blncs_personal.py start
```

### 3. 動作確認

```bash
# ステータス確認
python blncs_personal.py status

# ノード情報表示
python blncs_personal.py info

# 残高確認
python blncs_personal.py balance
```

## 個人使用の最適化ポイント / Personal Optimizations

### ✅ セキュリティ最大化

**1. 自動生成された認証トークン**
```bash
# トークン一覧
python blncs_personal.py tokens

# 新規トークン作成（読み取り専用）
python blncs_personal.py token backup --read-only

# トークン作成（フルアクセス、有効期限30日）
python blncs_personal.py token mobile --expires 30
```

**2. ローカルホスト専用設定**
```json
// config/personal.json
{
  "api": {
    "host": "127.0.0.1",  // ローカルのみアクセス可能
    "authentication": {
      "localhost_bypass": true,  // localhostから認証不要
      "require_token_for_writes": true  // 書き込みは認証必須
    }
  }
}
```

**3. 暗号化**
- データベース暗号化: 自動有効
- 通信暗号化: localhost使用時はオーバーヘッド削減のため無効
- パスワード: PBKDF2 + SHA-256

### ✅ パフォーマンス最適化

**1. メモリキャッシュ**
```json
{
  "cache": {
    "enabled": true,
    "type": "memory",      // 高速メモリキャッシュ
    "max_size": 1000,      // 最大1000エントリ
    "ttl": 300             // 5分TTL
  }
}
```

**2. データベース設定**
```json
{
  "database": {
    "url": "sqlite:///~/.blncs/blncs.db",  // 軽量SQLite
    "pool_size": 5,                         // 個人用に最適化
    "auto_backup": true                     // 自動バックアップ
  }
}
```

**3. API応答の最適化**
- 自動キャッシュ: GET リクエストは自動的にキャッシュ
- 圧縮: 大きなレスポンスを自動圧縮
- 並列処理: 非同期処理で高速化

### ✅ 機能最大化

**1. Lightning操作**

```bash
# インボイス作成
python blncs_personal.py invoice 10000 "Coffee payment"

# API経由でも可能
curl http://127.0.0.1:3000/api/lightning/invoice \
  -H "Content-Type: application/json" \
  -d '{"amount": 10000, "memo": "Coffee payment"}'
```

**2. 自動バックアップ**
```json
{
  "backup": {
    "enabled": true,
    "auto_backup": true,
    "interval_hours": 24,       // 毎日自動バックアップ
    "retention_days": 30,       // 30日間保持
    "compress": true,           // 圧縮して容量削減
    "destinations": {
      "local": {
        "enabled": true,
        "path": "~/.blncs/backups"
      }
    }
  }
}
```

**3. リアルタイム通知**
```json
{
  "notifications": {
    "enabled": true,
    "channels": {
      "console": {
        "enabled": true,
        "events": [
          "payment_received",
          "payment_sent",
          "invoice_settled",
          "error"
        ]
      }
    }
  }
}
```

**4. WebSocket対応**
```javascript
// リアルタイム更新
const ws = new WebSocket('ws://127.0.0.1:3001');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Event:', data.type, data.payload);
};
```

## 使用例 / Usage Examples

### シナリオ1: モックモードでテスト

```bash
# モックLightningクライアントで起動
python blncs_personal.py start --mock

# テストインボイス作成
python blncs_personal.py invoice 1000 "Test"

# ノード情報確認
python blncs_personal.py info
```

### シナリオ2: 実際のLNDノードと接続

```bash
# セットアップウィザードで設定
python blncs_personal.py setup

# config/personal.jsonを編集
{
  "lightning": {
    "network": "mainnet",
    "host": "localhost",
    "port": 10009,
    "mock_mode": false,
    "macaroon_path": "~/.lnd/data/chain/bitcoin/mainnet/admin.macaroon",
    "tls_cert_path": "~/.lnd/tls.cert"
  }
}

# 起動
python blncs_personal.py start
```

### シナリオ3: 外部アクセス（高度）

```bash
# nginx/Caddyでリバースプロキシ設定
# /etc/caddy/Caddyfile:
lightning.yourdomain.com {
    reverse_proxy 127.0.0.1:3000
}

# config/personal.jsonで許可
{
  "security": {
    "trusted_hosts": [
      "localhost",
      "lightning.yourdomain.com"
    ],
    "enforce_https": true
  },
  "api": {
    "authentication": {
      "localhost_bypass": false,  // 外部アクセス時は認証必須
      "require_token_for_reads": true
    }
  }
}
```

## セキュリティベストプラクティス / Security Best Practices

### 🔒 必須設定

1. **トークン管理**
   - トークンは`~/.blncs/auth.json`に保存（パーミッション600）
   - 定期的にトークンをローテーション
   - 不要なトークンは即座に削除

2. **バックアップ暗号化**
   ```bash
   # バックアップファイルも暗号化
   gpg --encrypt ~/.blncs/backups/backup_*.tar.gz
   ```

3. **ログ監視**
   ```bash
   # 異常アクセスを監視
   python blncs_personal.py logs | grep -i "error\|fail\|unauthorized"
   ```

4. **ファイアウォール**
   ```bash
   # localhostのみ許可（Linux/macOS）
   sudo ufw deny 3000
   sudo ufw allow from 127.0.0.1 to any port 3000
   ```

### 🛡️ 推奨設定

1. **2要素認証（将来実装予定）**
2. **IP制限**
   ```json
   {
     "security": {
       "ip_whitelist": [
         "127.0.0.1",
         "192.168.1.100"  // 自分のローカルIP
       ]
     }
   }
   ```

3. **レート制限**
   ```json
   {
     "api": {
       "rate_limiting": {
         "enabled": true,
         "requests_per_minute": 100
       }
     }
   }
   ```

## 高度な設定 / Advanced Configuration

### カスタムプラグイン

```python
# plugins/my_plugin.py
from blncs.core.plugin_system import Plugin

class MyPlugin(Plugin):
    def on_payment_received(self, payment):
        # カスタム処理
        print(f"Payment received: {payment.amount} sats")

    def on_invoice_created(self, invoice):
        # カスタム処理
        pass
```

### Webhooks

```json
{
  "features": {
    "webhooks": {
      "enabled": true,
      "endpoints": [
        {
          "url": "https://myapp.com/webhook",
          "events": ["payment_received", "invoice_settled"],
          "secret": "your-webhook-secret"
        }
      ]
    }
  }
}
```

### メトリクス収集

```json
{
  "monitoring": {
    "enabled": true,
    "collect_metrics": true,
    "prometheus_enabled": true,
    "prometheus_port": 9090
  }
}
```

## トラブルシューティング / Troubleshooting

### 問題: サーバーが起動しない

```bash
# ポート使用状況確認
netstat -tlnp | grep 3000

# 別のポートで起動
python blncs_personal.py start --port 3001
```

### 問題: Lightning ノードに接続できない

```bash
# TLS証明書確認
openssl x509 -in ~/.lnd/tls.cert -text -noout

# マカロンパーミッション確認
ls -la ~/.lnd/data/chain/bitcoin/mainnet/admin.macaroon

# 接続テスト
curl --insecure https://localhost:8080/v1/getinfo
```

### 問題: 認証エラー

```bash
# トークン再生成
python blncs_personal.py token new-token

# 認証無効化（テスト用）
python blncs_personal.py start --no-auth
```

### 問題: データベースエラー

```bash
# データベースリセット（警告: データ消失）
rm ~/.blncs/blncs.db
python blncs_personal.py start

# バックアップから復元
cp ~/.blncs/backups/backup_latest.db ~/.blncs/blncs.db
```

## パフォーマンスチューニング / Performance Tuning

### メモリ使用量削減

```json
{
  "cache": {
    "max_size": 500,        // キャッシュサイズを削減
    "compress_large_values": true
  },
  "database": {
    "pool_size": 3          // 接続プール削減
  }
}
```

### 高速化

```json
{
  "performance": {
    "enable_caching": true,
    "cache_api_responses": true,
    "async_processing": true,
    "optimize_queries": true
  }
}
```

## よくある質問 / FAQ

**Q: 複数デバイスで使用できますか？**
A: はい。トークンを複数デバイスで共有するか、デバイスごとにトークンを生成してください。

**Q: スマートフォンからアクセスできますか？**
A: リバースプロキシ（Caddy/nginx）を設定し、HTTPSで公開すれば可能です。セキュリティ設定を必ず見直してください。

**Q: バックアップは自動ですか？**
A: はい。デフォルトで24時間ごとに自動バックアップされます。

**Q: どのくらいのディスク容量が必要ですか？**
A: データベース: 10-50MB、ログ: 50-100MB、バックアップ: 100-500MB（30日分）

**Q: CPU/メモリ使用量は？**
A: アイドル時: CPU <1%, メモリ ~100MB。高負荷時: CPU <10%, メモリ ~200MB

## サポート / Support

### コミュニティ
- GitHub Issues: バグレポート・機能リクエスト
- Discussions: 質問・議論

### ドキュメント
- [API Reference](docs/API_REFERENCE.md)
- [Production Guide](docs/PRODUCTION_GUIDE.md)
- [System Architecture](SYSTEM_ARCHITECTURE.md)

---

**個人使用での楽しいLightning体験を！⚡**
