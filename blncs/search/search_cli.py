"""
検索機能統合CLIコマンド for BLNCS
CLIから検索機能にアクセス
"""

import argparse
import shlex
import asyncio
from typing import List, Optional
from .advanced_search_engine import SearchManager, SearchProvider, Language, SearchType
from .search_config_manager import get_search_config_manager


class SearchCLI:
    """検索機能CLI"""

    def __init__(self, search_manager: SearchManager):
        """
        初期化
        Args:
            search_manager: 検索マネージャー
        """
        self.search_manager = search_manager
        self.config_manager = get_search_config_manager()

    def search(self, args) -> None:
        """検索コマンドを実行"""
        parser = argparse.ArgumentParser(
            description="Multi-source intelligent search",
            prog="blncs search"
        )

        parser.add_argument(
            "query",
            help="Search query (use quotes for multi-word queries)"
        )

        parser.add_argument(
            "--provider", "-p",
            choices=[p.value for p in SearchProvider] + ["all"],
            default="all",
            help="Search provider (default: all)"
        )

        parser.add_argument(
            "--language", "-l",
            choices=[lang.value for lang in Language],
            default="auto",
            help="Search language (default: auto-detect)"
        )

        parser.add_argument(
            "--limit", "-n",
            type=int,
            default=10,
            help="Maximum number of results (default: 10)"
        )

        parser.add_argument(
            "--type", "-t",
            choices=[st.value for st in SearchType],
            default="full_text",
            help="Search type (default: full_text)"
        )

        parser.add_argument(
            "--json", "-j",
            action="store_true",
            help="Output results in JSON format"
        )

        parser.add_argument(
            "--verbose", "-v",
            action="store_true",
            help="Show detailed information"
        )

        # プロバイダー固有のオプション
        parser.add_argument(
            "--safe-search",
            action="store_true",
            help="Enable safe search (for web searches)"
        )

        parsed_args = parser.parse_args(args)

        # 検索を実行
        try:
            self._execute_search(parsed_args)
        except KeyboardInterrupt:
            print("\nSearch cancelled by user.")
        except Exception as e:
            print(f"Search error: {e}")

    def _execute_search(self, args) -> None:
        """検索を実行"""
        query = args.query
        provider_name = args.provider
        language_name = args.language
        limit = args.limit
        search_type_name = args.type
        output_json = args.json
        verbose = args.verbose

        # プロバイダーを変換
        if provider_name == "all":
            provider = None  # すべてのプロバイダー
        else:
            try:
                provider = SearchProvider(provider_name)
            except ValueError:
                print(f"Invalid provider: {provider_name}")
                return

        # 言語を変換
        try:
            language = Language(language_name)
        except ValueError:
            print(f"Invalid language: {language_name}")
            return

        # 検索タイプを変換
        try:
            search_type = SearchType(search_type_name)
        except ValueError:
            print(f"Invalid search type: {search_type_name}")
            return

        print(f"Searching for: '{query}'")
        print(f"Provider: {provider_name}")
        print(f"Language: {language.value}")
        print(f"Limit: {limit}")
        print(f"Type: {search_type.value}")
        print("-" * 50)

        start_time = asyncio.get_event_loop().time()

        try:
            if provider:
                # 特定プロバイダーで検索
                results = self.search_manager.perform_external_search(
                    query_text=query,
                    provider=provider,
                    limit=limit,
                    language=language
                )

                if output_json:
                    self._output_json_results(results, asyncio.get_event_loop().time() - start_time)
                else:
                    self._output_text_results(results, verbose, asyncio.get_event_loop().time() - start_time)

            else:
                # 統一検索を実行
                all_results = self.search_manager.perform_unified_search(
                    query_text=query,
                    include_external=True,
                    limit=limit,
                    language=language
                )

                if output_json:
                    self._output_json_unified_results(all_results, asyncio.get_event_loop().time() - start_time)
                else:
                    self._output_text_unified_results(all_results, verbose, asyncio.get_event_loop().time() - start_time)

        except Exception as e:
            print(f"Search execution error: {e}")

    def _output_text_results(self, results: List, verbose: bool, execution_time: float) -> None:
        """テキスト形式で結果を出力"""
        if not results:
            print("No results found.")
            return

        for i, result in enumerate(results, 1):
            print(f"\n{i}. {result.title}")
            print(f"   Score: {result.score:.3f}")
".3f"
            if hasattr(result, 'url') and result.url:
                print(f"   URL: {result.url}")
            if hasattr(result, 'metadata') and result.metadata:
                metadata = result.metadata
                if 'provider' in metadata:
                    print(f"   Provider: {metadata['provider']}")
                if verbose:
                    for key, value in metadata.items():
                        if key != 'provider':
                            print(f"   {key}: {value}")
            print(f"   Description: {result.content_snippet[:200]}...")
            print()

        print(f"\nSearch completed in {execution_time:.3f} seconds")
        print(f"Found {len(results)} results")

    def _output_json_results(self, results: List, execution_time: float) -> None:
        """JSON形式で結果を出力"""
        import json

        output = {
            "query": self._get_last_query(),
            "execution_time": execution_time,
            "total_results": len(results),
            "results": []
        }

        for result in results:
            result_dict = {
                "title": result.title,
                "score": result.score,
                "description": result.content_snippet,
                "url": getattr(result, 'url', ''),
                "metadata": getattr(result, 'metadata', {})
            }
            output["results"].append(result_dict)

        print(json.dumps(output, indent=2, ensure_ascii=False))

    def _output_text_unified_results(self, all_results: dict, verbose: bool, execution_time: float) -> None:
        """統一検索結果をテキスト形式で出力"""
        total_results = 0

        for provider, results in all_results.items():
            if not results:
                continue

            print(f"\n{provider.upper()} ({len(results)} results):")
            print("-" * (len(provider) + 20))

            for i, result in enumerate(results, 1):
                print(f"\n{i}. {result.title}")
                print(f"   Score: {result.score:.3f}")
                if hasattr(result, 'url') and result.url:
                    print(f"   URL: {result.url}")
                if verbose and hasattr(result, 'metadata') and result.metadata:
                    for key, value in result.metadata.items():
                        print(f"   {key}: {value}")
                print(f"   Description: {result.content_snippet[:150]}...")
                print()

            total_results += len(results)

        print(f"\nSearch completed in {execution_time:.3f} seconds")
        print(f"Total results across all providers: {total_results}")

    def _output_json_unified_results(self, all_results: dict, execution_time: float) -> None:
        """統一検索結果をJSON形式で出力"""
        import json

        output = {
            "query": self._get_last_query(),
            "execution_time": execution_time,
            "providers": {},
            "total_results": 0
        }

        for provider, results in all_results.items():
            if results:
                output["providers"][provider] = []
                for result in results:
                    result_dict = {
                        "title": result.title,
                        "score": result.score,
                        "description": result.content_snippet,
                        "url": getattr(result, 'url', ''),
                        "metadata": getattr(result, 'metadata', {})
                    }
                    output["providers"][provider].append(result_dict)
                output["total_results"] += len(results)

        print(json.dumps(output, indent=2, ensure_ascii=False))

    def _get_last_query(self) -> str:
        """最後のクエリを取得（実装による）"""
        # 実際の実装では検索履歴から取得
        return "unknown"

    def suggestions(self, args) -> None:
        """検索提案コマンド"""
        parser = argparse.ArgumentParser(
            description="Get search suggestions",
            prog="blncs search suggestions"
        )

        parser.add_argument(
            "query",
            help="Partial search query"
        )

        parser.add_argument(
            "--limit", "-n",
            type=int,
            default=10,
            help="Maximum number of suggestions"
        )

        parsed_args = parser.parse_args(args)

        try:
            suggestions = self.search_manager.get_search_suggestions(
                parsed_args.query,
                parsed_args.limit
            )

            if suggestions:
                print(f"Suggestions for '{parsed_args.query}':")
                for i, suggestion in enumerate(suggestions, 1):
                    print(f"  {i}. {suggestion}")
            else:
                print(f"No suggestions found for '{parsed_args.query}'")

        except Exception as e:
            print(f"Error getting suggestions: {e}")

    def popular(self, args) -> None:
        """人気検索コマンド"""
        parser = argparse.ArgumentParser(
            description="Show popular searches",
            prog="blncs search popular"
        )

        parser.add_argument(
            "--days", "-d",
            type=int,
            default=7,
            help="Number of days to look back"
        )

        parser.add_argument(
            "--limit", "-n",
            type=int,
            default=20,
            help="Maximum number of popular searches"
        )

        parsed_args = parser.parse_args(args)

        try:
            popular_searches = self.search_manager.get_popular_searches(parsed_args.days)

            print(f"Popular searches (last {parsed_args.days} days):")
            print("-" * 40)

            for i, (query, count) in enumerate(popular_searches[:parsed_args.limit], 1):
                print(f"{i:2d}. {query} ({count} times)")

        except Exception as e:
            print(f"Error getting popular searches: {e}")

    def status(self, args) -> None:
        """検索ステータスコマンド"""
        parser = argparse.ArgumentParser(
            description="Show search system status",
            prog="blncs search status"
        )

        parsed_args = parser.parse_args(args)

        try:
            status = self.search_manager.get_search_status()

            print("BLNCS Search System Status:")
            print("=" * 30)
            print(f"Active: {status.get('is_active', False)}")
            print(f"Total documents: {status.get('total_documents', 0)}")
            print(f"Total terms: {status.get('total_terms', 0)}")

            # 設定情報も表示
            config_summary = self.config_manager.get_config_summary()
            print(f"\nEnabled providers: {', '.join(config_summary['enabled_providers'])}")
            print(f"Cache enabled: {config_summary['cache_enabled']}")
            print(f"Default max results: {config_summary['default_max_results']}")
            print(f"Total API keys configured: {config_summary['total_api_keys']}")

            validation = config_summary['validation']
            if validation['valid']:
                print("Configuration: Valid ✓")
            else:
                print("Configuration: Invalid ✗")
                for issue in validation['issues']:
                    print(f"  - {issue}")

        except Exception as e:
            print(f"Error getting search status: {e}")


def create_search_parser(subparsers) -> None:
    """検索コマンドのパーサーを追加"""
    search_parser = subparsers.add_parser(
        "search",
        help="Multi-source intelligent search",
        description="Search across YouTube, academic papers, web content, GitHub, and Stack Overflow"
    )

    search_parser.add_argument(
        "query",
        help="Search query (use quotes for multi-word queries)"
    )

    search_parser.add_argument(
        "--provider", "-p",
        choices=[p.value for p in SearchProvider] + ["all"],
        default="all",
        help="Search provider (default: all)"
    )

    search_parser.add_argument(
        "--language", "-l",
        choices=[lang.value for lang in Language],
        default="auto",
        help="Search language (default: auto-detect)"
    )

    search_parser.add_argument(
        "--limit", "-n",
        type=int,
        default=10,
        help="Maximum number of results"
    )

    search_parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output in JSON format"
    )

    # サブコマンド
    search_subparsers = search_parser.add_subparsers(dest="search_command")

    # suggestionsサブコマンド
    suggestions_parser = search_subparsers.add_parser(
        "suggestions",
        help="Get search suggestions"
    )
    suggestions_parser.add_argument("query", help="Partial search query")
    suggestions_parser.add_argument("--limit", "-n", type=int, default=10)

    # popularサブコマンド
    popular_parser = search_subparsers.add_parser(
        "popular",
        help="Show popular searches"
    )
    popular_parser.add_argument("--days", "-d", type=int, default=7)
    popular_parser.add_argument("--limit", "-n", type=int, default=20)

    # statusサブコマンド
    status_parser = search_subparsers.add_parser(
        "status",
        help="Show search system status"
    )
