# BLNCS Personal Edition - 個人使用版

**Lightning Networkを個人で簡単・安全・高速に管理**

BLNCSは企業向けにも使える堅牢性を持ちながら、個人での使いやすさを最大限に追求したLightning Network管理システムです。

## 特徴 / Features

### 簡単セットアップ
- **1コマンドで起動**: `python blncs_personal.py start`
- **対話型セットアップ**: 初心者でも安心のウィザード形式
- **モックモード**: 実際のLightningノード不要でテスト可能

### 最大限のセキュリティ
- **自動トークン生成**: 初回起動時に安全なアクセストークンを自動生成
- **localhost専用モード**: デフォルトで外部アクセスを遮断
- **暗号化**: データベースと通信を自動暗号化
- **セキュアファイル**: トークンファイルは自動的に所有者のみ読取可能（600パーミッション）

### 最適化されたパフォーマンス
- **自動最適化**: システム負荷に応じてキャッシュサイズやデータベース接続を自動調整
- **メモリ効率**: 個人使用に最適化され、100MB以下のメモリで動作
- **高速キャッシュ**: よく使う操作は自動キャッシュで高速化
- **軽量データベース**: SQLiteで追加インストール不要

### 充実の機能
- **Lightning操作**: インボイス作成、支払い、残高確認
- **リアルタイム通知**: 支払い受信時に即座に通知
- **自動バックアップ**: データを毎日自動バックアップ
- **WebSocket対応**: リアルタイムでUI更新可能
- **REST API**: 全機能をAPIで操作可能

## クイックスタート

### 1. インストール

```bash
git clone <repository-url>
cd BLNCS
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. セットアップ（初回のみ）

```bash
python blncs_personal.py setup
```

対話型ウィザードが起動し、以下を設定します：
- Lightningノード接続（またはモックモード）
- APIポート番号
- セキュリティ設定

### 3. 起動

```bash
python blncs_personal.py start
```

これだけで完了！ブラウザで `http://127.0.0.1:3000/health` にアクセスして動作確認できます。

## 基本的な使い方

### サーバー管理

```bash
# サーバー起動
python blncs_personal.py start

# サーバー起動（認証なし・開発用）
python blncs_personal.py start --no-auth

# サーバー起動（モックモード）
python blncs_personal.py start --mock

# 状態確認
python blncs_personal.py status

# ログ確認
python blncs_personal.py logs
```

### トークン管理

```bash
# トークン一覧
python blncs_personal.py tokens

# 新しいトークン作成
python blncs_personal.py token my-token

# 読み取り専用トークン作成
python blncs_personal.py token readonly --read-only

# 有効期限付きトークン（30日）
python blncs_personal.py token mobile --expires 30

# トークン削除
python blncs_personal.py revoke my-token
```

### Lightning操作

```bash
# ノード情報表示
python blncs_personal.py info

# 残高確認
python blncs_personal.py balance

# インボイス作成（10,000 sats）
python blncs_personal.py invoice 10000 "Coffee payment"
```

### API使用例

```bash
# ヘルスチェック（認証不要）
curl http://127.0.0.1:3000/health

# ノード情報取得
curl -H "Authorization: Bearer YOUR_TOKEN" \
     http://127.0.0.1:3000/api/lightning/info

# インボイス作成
curl -X POST http://127.0.0.1:3000/api/lightning/invoice \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"amount": 10000, "memo": "Test payment"}'

# 残高確認
curl -H "Authorization: Bearer YOUR_TOKEN" \
     http://127.0.0.1:3000/api/lightning/balance
```

## セキュリティ設定

### デフォルトのセキュリティ

BLNCSは個人使用でも最大限のセキュリティを提供：

1. **localhost専用**: デフォルトで`127.0.0.1`からのみアクセス可能
2. **トークン認証**: 安全な32バイトのランダムトークン
3. **ファイル暗号化**: トークンファイルは所有者のみ読取可能
4. **データベース暗号化**: SQLiteデータベースを自動暗号化
5. **HTTPS不要**: localhostのみなのでTLS不要（オーバーヘッド削減）

### localhost bypass（便利機能）

デフォルトで有効になっている機能：
- `127.0.0.1`からのアクセスは認証不要（読み取り操作のみ）
- 書き込み操作（支払い、インボイス作成等）は常に認証必須

この設定により、ローカルでの開発が便利になりつつ、重要な操作は保護されます。

### 外部アクセスを許可する場合

**注意**: セキュリティリスクを理解した上で実施してください。

1. リバースプロキシ（Caddy推奨）を設定:

```bash
# /etc/caddy/Caddyfile
lightning.yourdomain.com {
    reverse_proxy 127.0.0.1:3000
}
```

2. `config/personal.json`を編集:

```json
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
      "localhost_bypass": false,
      "require_token_for_reads": true
    }
  }
}
```

3. トークンを安全に管理し、必要に応じてローテーション

## パフォーマンス最適化

### 自動最適化機能

BLNCSは使用状況に応じて自動的に最適化します：

- **CPU使用率が高い**: ワーカースレッド数を削減
- **メモリ使用率が高い**: キャッシュサイズを削減、ガベージコレクション実行
- **CPU使用率が低い**: ワーカースレッド数を増加、キャッシュサイズを拡大
- **メモリに余裕**: キャッシュサイズを拡大して応答速度向上

### 手動チューニング

`config/personal.json`で細かく調整可能：

```json
{
  "cache": {
    "max_size": 1000,          // キャッシュエントリ数
    "ttl": 300                 // キャッシュ有効期限（秒）
  },
  "database": {
    "pool_size": 5             // DB接続プール数
  },
  "performance": {
    "enable_caching": true,    // キャッシュ有効化
    "async_processing": true,  // 非同期処理
    "optimize_queries": true   // クエリ最適化
  }
}
```

### パフォーマンス指標

個人使用での典型的なパフォーマンス：

- **起動時間**: < 2秒
- **メモリ使用量**: 50-100MB（アイドル時）
- **API応答時間**: < 10ms（キャッシュヒット時）
- **データベースクエリ**: < 5ms平均
- **CPU使用率**: < 1%（アイドル時）、< 10%（高負荷時）

## 高度な機能

### WebSocketでリアルタイム更新

```javascript
const ws = new WebSocket('ws://127.0.0.1:3001');

ws.onopen = () => {
  console.log('Connected to BLNCS');
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);

  if (data.type === 'payment_received') {
    console.log('Payment received:', data.payload.amount, 'sats');
  }
};
```

### カスタムプラグイン

```python
# plugins/my_plugin.py
from blncs.core.plugin_system import Plugin

class NotificationPlugin(Plugin):
    def on_payment_received(self, payment):
        # デスクトップ通知を送信
        import subprocess
        subprocess.run([
            'notify-send',
            'Lightning Payment',
            f'Received {payment.amount} sats'
        ])
```

### Webhooks

外部サービスに通知を送信：

```json
{
  "features": {
    "webhooks": {
      "enabled": true,
      "endpoints": [
        {
          "url": "https://myapp.com/webhook",
          "events": ["payment_received"],
          "secret": "your-secret-key"
        }
      ]
    }
  }
}
```

## トラブルシューティング

### ポートが使用中

```bash
# 別のポートで起動
python blncs_personal.py start --port 3001
```

### トークンを忘れた

```bash
# 新しいトークン作成
python blncs_personal.py token new-token

# または認証を無効化（開発用）
python blncs_personal.py start --no-auth
```

### Lightning ノード接続エラー

```bash
# モックモードで起動（実ノード不要）
python blncs_personal.py start --mock

# 接続設定確認
cat config/personal.json | grep -A 10 "lightning"
```

### データベースエラー

```bash
# データベース再作成（警告：データ消失）
rm ~/.blncs/blncs.db
python blncs_personal.py start

# バックアップから復元
cp ~/.blncs/backups/backup_*.db ~/.blncs/blncs.db
```

## ファイル構成

```
~/.blncs/
├── auth.json           # 認証トークン（自動生成）
├── blncs.db           # データベース
├── encryption.key     # 暗号化キー
├── logs/              # ログファイル
│   └── blncs.log
└── backups/           # 自動バックアップ
    ├── backup_2024-01-01.db
    └── backup_2024-01-02.db

config/
└── personal.json      # 設定ファイル
```

## システム要件

### 最小要件
- Python 3.10以上
- 512MB RAM
- 1GB ディスク空き容量
- Linux/macOS/Windows（WSL）

### 推奨環境
- Python 3.11以上
- 1GB RAM以上
- 5GB ディスク空き容量
- SSD推奨

## よくある質問

**Q: Lightningノードがなくても使えますか？**
A: はい。`--mock`フラグでモックモードで起動でき、テスト用の仮想Lightningノードとして動作します。

**Q: 複数デバイスから使えますか？**
A: トークンを共有すれば可能です。または各デバイスで別々のトークンを発行できます。

**Q: スマートフォンからアクセスできますか？**
A: リバースプロキシとHTTPS設定をすれば可能ですが、セキュリティに十分注意してください。

**Q: 自動バックアップはどこに保存されますか？**
A: デフォルトで`~/.blncs/backups/`に保存され、30日間保持されます。

**Q: メモリ使用量を減らせますか？**
A: `config/personal.json`でキャッシュサイズとDB接続プールを削減できます。

**Q: mainnetで使えますか？**
A: はい。セットアップ時にmainnetを選択するか、`config/personal.json`で`network: "mainnet"`に設定してください。

## セキュリティのベストプラクティス

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

5. **定期的なログ監視**:
   ```bash
   python blncs_personal.py logs | grep -i "error\|unauthorized"
   ```

## サポート

### ドキュメント
- [完全ガイド](PERSONAL_USAGE_GUIDE.md) - 詳細な使用方法
- [API リファレンス](docs/API_REFERENCE.md) - API仕様
- [システムアーキテクチャ](SYSTEM_ARCHITECTURE.md) - 内部構造

### コミュニティ
- GitHub Issues - バグレポート・機能リクエスト
- Discussions - 質問・議論

---

**楽しいLightning体験を！**

BLNCSで安全・簡単・高速なLightning Network管理を始めましょう。
