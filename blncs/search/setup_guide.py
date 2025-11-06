"""
検索機能設定例 for BLNCS
環境変数と設定ファイルの例
"""

import os

# 環境変数でAPIキーを設定（推奨）
# export YOUTUBE_API_KEY="your_youtube_api_key_here"
# export GOOGLE_API_KEY="your_google_api_key_here"
# export GOOGLE_SEARCH_ENGINE_ID="your_google_search_engine_id_here"
# export BING_API_KEY="your_bing_api_key_here"
# export GITHUB_TOKEN="your_github_token_here"
# export SEMANTIC_SCHOLAR_API_KEY="your_semantic_scholar_api_key_here"

# または、.envファイルで設定
# YOUTUBE_API_KEY=your_youtube_api_key_here
# GOOGLE_API_KEY=your_google_api_key_here
# GOOGLE_SEARCH_ENGINE_ID=your_google_search_engine_id_here
# BING_API_KEY=your_bing_api_key_here
# GITHUB_TOKEN=your_github_token_here
# SEMANTIC_SCHOLAR_API_KEY=your_semantic_scholar_api_key_here

# 設定ファイルの例（config/search_config.json）
EXAMPLE_CONFIG = {
    "api_keys": {
        "youtube_api_key": os.getenv("YOUTUBE_API_KEY", ""),
        "google_api_key": os.getenv("GOOGLE_API_KEY", ""),
        "google_search_engine_id": os.getenv("GOOGLE_SEARCH_ENGINE_ID", ""),
        "bing_api_key": os.getenv("BING_API_KEY", ""),
        "github_token": os.getenv("GITHUB_TOKEN", ""),
        "semantic_scholar_api_key": os.getenv("SEMANTIC_SCHOLAR_API_KEY", "")
    },

    "rate_limits": {
        "requests_per_minute": 60,
        "requests_per_hour": 1000,
        "requests_per_day": 10000
    },

    "cache_settings": {
        "enabled": True,
        "ttl_minutes": 60,
        "max_cache_size": 1000
    },

    "search_settings": {
        "default_max_results": 10,
        "default_language": "auto",
        "safe_search": True,
        "timeout_seconds": 30
    },

    "providers": {
        "youtube": {
            "enabled": True,
            "max_results": 20,
            "region_code": "JP",
            "safe_search": "strict"
        },

        "google_scholar": {
            "enabled": True,
            "max_results": 20,
            "language": "en",
            "sort_by": "relevance"
        },

        "arxiv": {
            "enabled": True,
            "max_results": 20,
            "sort_by": "relevance",
            "categories": ["cs.AI", "cs.LG", "cs.CL"]
        },

        "semantic_scholar": {
            "enabled": True,
            "max_results": 20,
            "fields": ["title", "abstract", "authors", "year", "venue"]
        },

        "google_web": {
            "enabled": True,
            "max_results": 10,
            "country": "jp",
            "language": "ja",
            "safe_search": "active"
        },

        "bing_web": {
            "enabled": True,
            "max_results": 10,
            "market": "ja-JP",
            "safe_search": "strict"
        },

        "github": {
            "enabled": True,
            "max_results": 20,
            "sort_by": "best-match",
            "language": "python",
            "stars": ">100"
        },

        "stack_overflow": {
            "enabled": True,
            "max_results": 20,
            "sort_by": "relevance",
            "tags": ["python", "machine-learning", "blockchain"]
        }
    }
}

# APIキー取得方法の説明
API_KEY_GUIDE = {
    "youtube_api_key": {
        "description": "YouTube Data API v3",
        "url": "https://console.developers.google.com/",
        "steps": [
            "Google Cloud Consoleでプロジェクトを作成",
            "YouTube Data API v3を有効化",
            "APIキーを生成",
            "制限を設定（オプション）"
        ]
    },

    "google_api_key": {
        "description": "Google Custom Search API",
        "url": "https://console.developers.google.com/",
        "steps": [
            "Google Cloud Consoleでプロジェクトを作成",
            "Custom Search JSON APIを有効化",
            "APIキーを生成"
        ]
    },

    "google_search_engine_id": {
        "description": "Google Custom Search Engine ID",
        "url": "https://cse.google.com/",
        "steps": [
            "Google Custom Search Engineを作成",
            "検索対象サイトを設定（またはウェブ全体）",
            "Search Engine IDを取得"
        ]
    },

    "bing_api_key": {
        "description": "Bing Search API",
        "url": "https://portal.azure.com/",
        "steps": [
            "Azure Portalでアカウントを作成",
            "Bing Search APIリソースを作成",
            "APIキーを取得"
        ]
    },

    "github_token": {
        "description": "GitHub Personal Access Token",
        "url": "https://github.com/settings/tokens",
        "steps": [
            "GitHubアカウントでログイン",
            "Personal Access Tokensページにアクセス",
            "新しいトークンを作成（repo権限が必要）"
        ]
    },

    "semantic_scholar_api_key": {
        "description": "Semantic Scholar API Key",
        "url": "https://www.semanticscholar.org/",
        "steps": [
            "Semantic Scholar APIドキュメントを確認",
            "APIキーを取得（研究目的の場合）"
        ]
    }
}

def print_setup_instructions():
    """セットアップ手順を表示"""
    print("🔍 BLNCS Search System Setup Guide")
    print("=" * 40)

    print("\n1. 環境変数を設定してください:")
    print("   export YOUTUBE_API_KEY='your_youtube_api_key'")
    print("   export GOOGLE_API_KEY='your_google_api_key'")
    print("   export GOOGLE_SEARCH_ENGINE_ID='your_search_engine_id'")
    print("   # 他のAPIキーも同様に設定")

    print("\n2. 利用可能なAPIキー:")
    for key, info in API_KEY_GUIDE.items():
        print(f"\n   📋 {key}:")
        print(f"      説明: {info['description']}")
        print(f"      URL: {info['url']}")
        print("      セットアップ手順:")
        for step in info['steps']:
            print(f"        - {step}")

    print("\n3. 設定を検証:")
    print("   python -c 'from blncs.search.search_config_manager import get_search_config_manager; print(get_search_config_manager().get_config_summary())'")

    print("\n4. 検索機能をテスト:")
    print("   # CLIからテスト")
    print("   python -m blncs.cli.enhanced_cli search 'machine learning' --provider all --limit 5")
    print("")
    print("   # Pythonからテスト")
    print("   from blncs.search.advanced_search_engine import SearchManager")
    print("   manager = SearchManager()")
    print("   manager.initialize_search_system()")
    print("   results = manager.perform_search('Lightning Network', limit=5)")
    print("   for result in results:")
    print("       print(f'{result.title}: {result.score}')")

    print("\n5. 検索APIサーバーを起動（オプション）:")
    print("   python -m blncs.search.search_api")

    print("\n✨ セットアップ完了！")


if __name__ == "__main__":
    print_setup_instructions()
