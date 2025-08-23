# BLNCS - Bitcoin Lightning Routing Control System

**ワンクリックで Lightning Network ルーティングを最適化**

```bash
pip install blrcs
blrcs start
# Lightning ルーティングが自動的に最適化されます
```

## 主な機能

### Lightning Network 最適化
- **ワンクリックルーティング** - 複雑な設定不要
- **自動チャネル管理** - チャネルバランスを自動調整
- **手数料最適化** - 最適な手数料を自動計算
- **ルート探索** - 最短・最安ルートを瞬時に発見

### リアルタイム監視
- **チャネル状態モニタリング** - 全チャネルの健全性を監視
- **支払い成功率追跡** - ルーティング成功率を表示
- **収益分析** - ルーティング手数料収益をリアルタイム表示

### 簡単設定
- **LND自動接続** - LNDノードに自動接続
- **REST API対応** - 既存システムとの統合が簡単
- **WebSocket通信** - リアルタイム更新

## インストール

### 必要要件
- Python 3.8+
- LNDノード (v0.15.0+)
- 2GB以上のRAM

### クイックスタート

```bash
# インストール
pip install blrcs

# LND設定ファイルを指定して起動
blrcs start --lnd-dir ~/.lnd

# または環境変数で設定
export LND_DIR=~/.lnd
blrcs start
```

## Version

Current version: v0.0.1 (Alpha Release)

## ライセンス

MIT License - 詳細は[LICENSE](LICENSE)ファイルを参照

---

*BLNCS - Bitcoin Lightning Network のルーティングを簡単に*