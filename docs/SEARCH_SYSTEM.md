# BLNCS Search System

多言語・多ソース統合検索システム

## 概要

BLNCS Search Systemは、YouTube、Google Scholar、arXiv、Semantic Scholar、Google/Bingウェブ検索、GitHub、Stack Overflowなどの複数の検索ソースを統合した高度な検索システムです。

## 特徴

- 🌐 **多言語対応**: 日本語、英語、中国語、韓国語など50言語以上に対応
- 🔍 **多ソース統合**: 動画、論文、ウェブ、コード、Q&Aなど様々なコンテンツを横断検索
- ⚡ **高性能**: 非同期処理とインテリジェントキャッシングで高速検索
- 🎯 **インテリジェントランキング**: TF-IDF、BM25、セマンティック検索による精度の高い結果
- 🔒 **安全検索**: 各プロバイダーの安全検索機能に対応
- 📊 **分析機能**: 検索ログ分析と人気検索トレンド表示
- 🚀 **API/CLI対応**: REST APIとコマンドラインインターフェースを提供

## インストール

### 必要条件

- Python 3.8+
- 各種APIキー（任意）

### インストール方法

```bash
# BLNCSをクローン
git clone https://github.com/your-org/blncs.git
cd blncs

# 仮想環境を作成・有効化
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# 依存関係をインストール
pip install -r requirements.txt
pip install -r requirements-optional.txt  # 検索機能用

# APIキーを設定（任意）
export YOUTUBE_API_KEY="your_youtube_api_key"
export GOOGLE_API_KEY="your_google_api_key"
export GOOGLE_SEARCH_ENGINE_ID="your_search_engine_id"
# ... 他のAPIキーも同様に
```

## セットアップ

### 1. APIキーの取得

各検索プロバイダーのAPIキーを取得してください：

| プロバイダー | 必要APIキー | 取得方法 |
|-------------|------------|----------|
| YouTube | YouTube Data API v3 | Google Cloud Console |
| Google Scholar | Custom Search API | Google Cloud Console |
| Google Web | Custom Search API | Google Cloud Console |
| Bing Web | Bing Search API | Azure Portal |
| GitHub | Personal Access Token | GitHub Settings |
| arXiv | 不要（パブリックAPI） | - |
| Semantic Scholar | 不要（パブリックAPI） | - |

### 2. 設定の確認

```bash
# セットアップガイドを実行
python -m blncs.search.setup_guide

# 設定を検証
python -c "
from blncs.search.search_config_manager import get_search_config_manager
config = get_search_config_manager()
print('Configuration Summary:')
summary = config.get_config_summary()
for key, value in summary.items():
    print(f'  {key}: {value}')
"
```

## 使用方法

### コマンドラインインターフェース (CLI)

#### 基本検索

```bash
# すべてのプロバイダーで検索
blncs search "machine learning"

# 特定プロバイダーで検索
blncs search "blockchain" --provider google_scholar --limit 10

# 日本語で検索
blncs search "ブロックチェーン" --provider all --lang ja

# 動画検索
blncs search "python tutorial" --provider youtube --limit 5

# GitHubリポジトリ検索
blncs search "lightning network" --provider github --limit 10

# JSON形式で出力
blncs search "artificial intelligence" --json
```

#### 検索提案

```bash
# 検索提案を取得
blncs search suggestions "machine"

# 人気の検索を表示
blncs search popular --days 7 --limit 20

# 検索システムのステータス確認
blncs search status
```

#### インタラクティブモード

```bash
# インタラクティブCLIを起動
blncs

# インタラクティブモードで検索
blncs> search "quantum computing" --provider all --limit 5
blncs> search suggestions "block"
blncs> help search
```

### Python API

#### 基本使用法

```python
from blncs.search.advanced_search_engine import SearchManager, SearchType, SearchProvider, Language

# 検索マネージャーを作成
manager = SearchManager()
manager.initialize_search_system()

# ローカル検索
results = manager.perform_search(
    query_text="Lightning Network",
    search_type=SearchType.FULL_TEXT,
    limit=10
)

for result in results:
    print(f"{result.title}: {result.score:.3f}")
    print(f"  {result.content_snippet[:100]}...")

# 外部検索
youtube_results = manager.perform_external_search(
    query_text="blockchain tutorial",
    provider=SearchProvider.YOUTUBE,
    limit=5,
    language=Language.EN
)

for result in youtube_results:
    print(f"📺 {result.title}")
    print(f"   {result.content_snippet[:150]}...")

# 統一検索（ローカル + 外部）
all_results = manager.perform_unified_search(
    query_text="machine learning",
    include_external=True,
    limit=15,
    language=Language.AUTO
)

for provider, results in all_results.items():
    print(f"\n{provider.upper()} ({len(results)} results):")
    for result in results[:3]:  # 各プロバイダー上位3件
        print(f"  • {result.title}")
```

#### 多言語検索

```python
from blncs.search.multilingual_search import get_multilingual_search_engine

engine = get_multilingual_search_engine()

# 言語検出
detected = engine.get_search_languages("こんにちは世界")
print(f"Detected languages: {[lang.value for lang, score in detected]}")

# クエリ正規化
normalized = engine.normalize_query(
    "Machine Learning Technology",
    [Language.EN, Language.JA, Language.ZH]
)

for lang, processed in normalized.items():
    print(f"{lang.value}: {processed}")
```

### REST API

#### APIサーバー起動

```bash
# APIサーバーを起動
python -m blncs.search.search_api

# または
python -c "
from blncs.search.search_api import SearchAPI
api = SearchAPI()
api.initialize_search_system()
api.start_server(port=8001)
"
```

#### APIエンドポイント

| エンドポイント | メソッド | 説明 |
|-------------|----------|------|
| `/` | GET | API情報 |
| `/search` | GET | 検索実行 |
| `/search/suggestions` | GET | 検索提案 |
| `/search/popular` | GET | 人気検索 |
| `/search/status` | GET | システムステータス |
| `/search/providers` | GET | 利用可能プロバイダー |

#### API使用例

```bash
# 基本検索
curl "http://localhost:8001/search?query=machine%20learning&limit=5"

# 特定プロバイダー検索
curl "http://localhost:8001/search?query=blockchain&provider=google_scholar&lang=ja"

# 検索提案
curl "http://localhost:8001/search/suggestions?query=machine&limit=10"

# 人気検索
curl "http://localhost:8001/search/popular?days=7"

# システムステータス
curl "http://localhost:8001/search/status"
```

## 設定

### 設定ファイル

`config/search_config.json`で詳細設定が可能です：

```json
{
  "api_keys": {
    "youtube_api_key": "your_key",
    "google_api_key": "your_key",
    "google_search_engine_id": "your_id"
  },
  "rate_limits": {
    "requests_per_minute": 60,
    "requests_per_hour": 1000
  },
  "providers": {
    "youtube": {
      "enabled": true,
      "max_results": 20,
      "region_code": "JP"
    },
    "google_scholar": {
      "enabled": true,
      "max_results": 20
    }
  }
}
```

### 環境変数

| 環境変数 | 説明 | デフォルト |
|---------|------|-----------|
| YOUTUBE_API_KEY | YouTube Data APIキー | - |
| GOOGLE_API_KEY | Google Custom Search APIキー | - |
| GOOGLE_SEARCH_ENGINE_ID | Google Search Engine ID | - |
| BING_API_KEY | Bing Search APIキー | - |
| GITHUB_TOKEN | GitHub Personal Access Token | - |

## 高度な機能

### カスタム検索フィルタ

```python
from blncs.search.advanced_search_engine import SearchQuery, SearchType

# フィルタ付き検索
query = SearchQuery(
    query_text="python",
    search_type=SearchType.FULL_TEXT,
    filters={
        "tags": ["machine-learning", "tutorial"],
        "date_from": "2023-01-01",
        "language": "en"
    },
    limit=20
)

results = manager.search_engine.search(query)
```

### 検索コールバック

```python
def my_search_callback(query, results):
    print(f"Search completed: {len(results)} results for '{query.query_text}'")

# コールバックを登録
manager.search_engine.add_search_callback(my_search_callback)
```

### キャッシュ管理

```python
# キャッシュ設定の変更
config_manager = get_search_config_manager()
config_manager.update_cache_settings(
    enabled=True,
    ttl_minutes=120,  # 2時間
    max_cache_size=2000
)

# キャッシュ統計の確認
stats = manager.search_engine.external_search_manager.get_search_stats()
print(f"Cache size: {stats['cache_size']}")
```

## テスト

### 単体テスト実行

```bash
# 検索機能のテストを実行
python -m pytest tests/unit/test_search_system.py -v

# 特定のテストクラスを実行
python -m pytest tests/unit/test_search_system.py::TestSearchManager -v

# モックを使った外部APIテスト
python -m pytest tests/unit/test_search_system.py::TestExternalSearchManager -v
```

### パフォーマンステスト

```bash
# ベンチマーク実行
python -c "
import time
from blncs.search.advanced_search_engine import SearchManager

manager = SearchManager()
manager.initialize_search_system()

# パフォーマンス測定
start_time = time.time()
results = manager.perform_search('Lightning Network', limit=100)
end_time = time.time()

print(f'Search completed in {end_time - start_time:.3f} seconds')
print(f'Found {len(results)} results')
"
```

## トラブルシューティング

### 一般的な問題

1. **APIキーが設定されていない**
   ```bash
   # 設定を確認
   python -c "from blncs.search.search_config_manager import get_search_config_manager; print(get_search_config_manager().get_config_summary())"
   ```

2. **レート制限エラー**
   - 各APIのレート制限を確認してください
   - 設定ファイルでレート制限を調整してください

3. **検索結果が空**
   - クエリが適切か確認してください
   - プロバイダーが有効か確認してください
   - ネットワーク接続を確認してください

4. **言語検出が不正確**
   - 多言語テキストの場合、明示的に言語を指定してください
   - 設定ファイルでデフォルト言語を変更してください

### ログ確認

```bash
# デバッグログを有効化
export BLNCS_LOG_LEVEL=DEBUG

# ログファイル確認
tail -f blncs.log | grep -i search
```

## 貢献

### 開発環境セットアップ

```bash
# 開発依存関係をインストール
pip install -r requirements-dev.txt

# 事前コミットフックをセットアップ
pre-commit install

# テストを実行
python -m pytest tests/ -v

# コードフォーマット
black blncs/search/
isort blncs/search/
```

### 新しい検索プロバイダーの追加

1. `SearchProvider`列挙型に新しいプロバイダーを追加
2. `ExternalSearchManager`クラスに検索メソッドを実装
3. 設定ファイルにプロバイダー設定を追加
4. 単体テストを作成
5. ドキュメントを更新

## ライセンス

このプロジェクトはMITライセンスの下で公開されています。

## サポート

- 📖 [ドキュメント](docs/search/)
- 🐛 [バグ報告](https://github.com/your-org/blncs/issues)
- 💬 [ディスカッション](https://github.com/your-org/blncs/discussions)
- 📧 [連絡先](mailto:support@blncs.org)

## バージョン履歴

### v1.0.0
- 初回リリース
- YouTube, Google Scholar, arXiv, Semantic Scholar統合
- 多言語検索対応
- REST API提供
- CLI統合

---

**BLNCS Search System** - 知識の海を探索する究極のツール
