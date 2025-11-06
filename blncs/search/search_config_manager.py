"""
検索設定管理システム for BLNCS
APIキー、レート制限、キャッシュ設定などを管理
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class SearchConfigManager:
    """検索設定マネージャー"""

    def __init__(self, config_dir: str = "config"):
        """
        初期化
        Args:
            config_dir: 設定ディレクトリ
        """
        self.config_dir = Path(config_dir)
        self.config_file = self.config_dir / "search_config.json"
        self.default_config = self._get_default_config()
        self.config = self._load_config()

    def _get_default_config(self) -> Dict[str, Any]:
        """デフォルト設定を取得"""
        return {
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
                    "region_code": "JP"
                },
                "google_scholar": {
                    "enabled": True,
                    "max_results": 20
                },
                "arxiv": {
                    "enabled": True,
                    "max_results": 20,
                    "sort_by": "relevance"
                },
                "semantic_scholar": {
                    "enabled": True,
                    "max_results": 20
                },
                "google_web": {
                    "enabled": True,
                    "max_results": 10,
                    "country": "jp"
                },
                "bing_web": {
                    "enabled": True,
                    "max_results": 10,
                    "market": "ja-JP"
                },
                "github": {
                    "enabled": True,
                    "max_results": 20,
                    "sort_by": "best-match"
                },
                "stack_overflow": {
                    "enabled": True,
                    "max_results": 20,
                    "sort_by": "relevance"
                }
            }
        }

    def _load_config(self) -> Dict[str, Any]:
        """設定を読み込み"""
        if not self.config_file.exists():
            logger.info("Creating default search configuration")
            self.config_dir.mkdir(parents=True, exist_ok=True)
            self._save_config(self.default_config)
            return self.default_config

        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                user_config = json.load(f)

            # デフォルト設定とマージ
            merged_config = self._deep_merge(self.default_config, user_config)
            self._save_config(merged_config)
            return merged_config

        except Exception as e:
            logger.error(f"Error loading search config: {e}")
            return self.default_config

    def _save_config(self, config: Dict[str, Any]):
        """設定を保存"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Error saving search config: {e}")

    def _deep_merge(self, base: Dict[str, Any], update: Dict[str, Any]) -> Dict[str, Any]:
        """ディープマージ"""
        result = base.copy()
        for key, value in update.items():
            if isinstance(value, dict) and key in result and isinstance(result[key], dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def get_api_key(self, provider: str) -> Optional[str]:
        """APIキーを取得"""
        return self.config["api_keys"].get(provider)

    def set_api_key(self, provider: str, api_key: str):
        """APIキーを設定"""
        if provider not in self.config["api_keys"]:
            logger.warning(f"Unknown API provider: {provider}")
            return

        self.config["api_keys"][provider] = api_key
        self._save_config(self.config)
        logger.info(f"API key set for {provider}")

    def get_provider_config(self, provider: str) -> Dict[str, Any]:
        """プロバイダー設定を取得"""
        return self.config["providers"].get(provider, {})

    def is_provider_enabled(self, provider: str) -> bool:
        """プロバイダーが有効かチェック"""
        return self.get_provider_config(provider).get("enabled", False)

    def enable_provider(self, provider: str, enabled: bool = True):
        """プロバイダーの有効/無効を切り替え"""
        if provider in self.config["providers"]:
            self.config["providers"][provider]["enabled"] = enabled
            self._save_config(self.config)
            logger.info(f"Provider {provider} {'enabled' if enabled else 'disabled'}")

    def get_cache_settings(self) -> Dict[str, Any]:
        """キャッシュ設定を取得"""
        return self.config["cache_settings"]

    def update_cache_settings(self, **kwargs):
        """キャッシュ設定を更新"""
        for key, value in kwargs.items():
            if key in self.config["cache_settings"]:
                self.config["cache_settings"][key] = value
        self._save_config(self.config)

    def get_search_settings(self) -> Dict[str, Any]:
        """検索設定を取得"""
        return self.config["search_settings"]

    def update_search_settings(self, **kwargs):
        """検索設定を更新"""
        for key, value in kwargs.items():
            if key in self.config["search_settings"]:
                self.config["search_settings"][key] = value
        self._save_config(self.config)

    def validate_config(self) -> Dict[str, Any]:
        """設定の検証"""
        issues = []

        # APIキーの検証
        for provider, key in self.config["api_keys"].items():
            if not key and self.is_provider_enabled(provider):
                issues.append(f"Missing API key for {provider}")

        # レート制限の検証
        for limit_name, limit_value in self.config["rate_limits"].items():
            if not isinstance(limit_value, int) or limit_value <= 0:
                issues.append(f"Invalid rate limit: {limit_name}")

        # プロバイダー設定の検証
        for provider, settings in self.config["providers"].items():
            if not isinstance(settings.get("enabled", False), bool):
                issues.append(f"Invalid enabled setting for {provider}")
            if not isinstance(settings.get("max_results", 10), int) or settings["max_results"] <= 0:
                issues.append(f"Invalid max_results for {provider}")

        return {
            "valid": len(issues) == 0,
            "issues": issues
        }

    def get_config_summary(self) -> Dict[str, Any]:
        """設定の要約を取得"""
        return {
            "enabled_providers": [
                provider for provider, config in self.config["providers"].items()
                if config.get("enabled", False)
            ],
            "cache_enabled": self.config["cache_settings"]["enabled"],
            "default_max_results": self.config["search_settings"]["default_max_results"],
            "total_api_keys": len([k for k in self.config["api_keys"].values() if k]),
            "validation": self.validate_config()
        }


# Global instance
_search_config_manager = None


def get_search_config_manager() -> SearchConfigManager:
    """グローバル検索設定マネージャーを取得"""
    global _search_config_manager
    if _search_config_manager is None:
        _search_config_manager = SearchConfigManager()
    return _search_config_manager


def setup_search_api_keys():
    """検索APIキーを設定（環境変数から）"""
    config_manager = get_search_config_manager()

    # 環境変数からAPIキーを取得
    api_keys = {
        "youtube_api_key": os.getenv("YOUTUBE_API_KEY"),
        "google_api_key": os.getenv("GOOGLE_API_KEY"),
        "google_search_engine_id": os.getenv("GOOGLE_SEARCH_ENGINE_ID"),
        "bing_api_key": os.getenv("BING_API_KEY"),
        "github_token": os.getenv("GITHUB_TOKEN"),
        "semantic_scholar_api_key": os.getenv("SEMANTIC_SCHOLAR_API_KEY")
    }

    for provider, api_key in api_keys.items():
        if api_key:
            config_manager.set_api_key(provider, api_key)

    # 設定を検証
    validation = config_manager.validate_config()
    if not validation["valid"]:
        logger.warning("Search configuration validation issues:")
        for issue in validation["issues"]:
            logger.warning(f"  - {issue}")


if __name__ == "__main__":
    # テスト実行
    config_manager = get_search_config_manager()
    setup_search_api_keys()

    summary = config_manager.get_config_summary()
    print("Search Configuration Summary:")
    print(f"Enabled providers: {summary['enabled_providers']}")
    print(f"Cache enabled: {summary['cache_enabled']}")
    print(f"Default max results: {summary['default_max_results']}")
    print(f"Total API keys: {summary['total_api_keys']}")
    print(f"Validation: {'Valid' if summary['validation']['valid'] else 'Invalid'}")

    if not summary['validation']['valid']:
        print("Issues:")
        for issue in summary['validation']['issues']:
            print(f"  - {issue}")
