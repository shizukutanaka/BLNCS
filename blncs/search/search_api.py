"""
検索統合APIシステム for BLNCS
REST API経由で検索機能を提供
"""

import asyncio
from typing import Dict, List, Optional, Any
from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from enum import Enum

from .advanced_search_engine import SearchManager, SearchType, SearchProvider, Language
from .search_config_manager import get_search_config_manager


class SearchRequest(BaseModel):
    """検索リクエストモデル"""
    query: str = Field(..., description="検索クエリ")
    provider: Optional[str] = Field(None, description="検索プロバイダー")
    search_type: str = Field("full_text", description="検索タイプ")
    language: str = Field("auto", description="検索言語")
    limit: int = Field(10, description="結果制限数", ge=1, le=100)
    include_external: bool = Field(True, description="外部検索を含む")


class SearchResponse(BaseModel):
    """検索レスポンスモデル"""
    query: str
    total_results: int
    results: List[Dict[str, Any]]
    providers: List[str]
    execution_time: float


class SearchAPI:
    """検索APIサーバー"""

    def __init__(self):
        """初期化"""
        self.search_manager = SearchManager()
        self.app = FastAPI(
            title="BLNCS Search API",
            description="Multi-source intelligent search API",
            version="1.0.0"
        )
        self._setup_routes()

    def _setup_routes(self):
        """APIルートを設定"""

        @self.app.get("/")
        async def root():
            """ルートエンドポイント"""
            return {"message": "BLNCS Search API", "version": "1.0.0"}

        @self.app.get("/search")
        async def search(
            query: str = Query(..., description="検索クエリ"),
            provider: Optional[str] = Query(None, description="検索プロバイダー"),
            search_type: str = Query("full_text", description="検索タイプ"),
            language: str = Query("auto", description="検索言語"),
            limit: int = Query(10, description="結果制限数", ge=1, le=100),
            include_external: bool = Query(True, description="外部検索を含む")
        ) -> SearchResponse:
            """
            検索を実行
            """
            start_time = asyncio.get_event_loop().time()

            try:
                # 検索プロバイダーを変換
                search_provider = None
                if provider and provider != "all":
                    try:
                        search_provider = SearchProvider(provider.lower())
                    except ValueError:
                        raise HTTPException(status_code=400, detail=f"Invalid provider: {provider}")

                # 検索タイプを変換
                try:
                    st = SearchType(search_type)
                except ValueError:
                    raise HTTPException(status_code=400, detail=f"Invalid search type: {search_type}")

                # 言語を変換
                try:
                    lang = Language(language)
                except ValueError:
                    raise HTTPException(status_code=400, detail=f"Invalid language: {language}")

                # 検索を実行
                if provider == "all" or not provider:
                    # すべてのプロバイダーで検索
                    results = self.search_manager.perform_unified_search(
                        query_text=query,
                        include_external=include_external,
                        limit=limit,
                        language=lang
                    )

                    # 結果を統合
                    all_results = []
                    providers_used = []

                    for provider_name, provider_results in results.items():
                        if provider_results:
                            providers_used.append(provider_name)
                            for result in provider_results:
                                all_results.append({
                                    "title": result.title,
                                    "description": result.content_snippet,
                                    "url": getattr(result, 'url', ''),
                                    "provider": provider_name,
                                    "score": result.score,
                                    "metadata": getattr(result, 'metadata', {})
                                })

                    # スコアでソート
                    all_results.sort(key=lambda x: x['score'], reverse=True)

                else:
                    # 特定プロバイダーで検索
                    results = self.search_manager.perform_external_search(
                        query_text=query,
                        provider=search_provider,
                        limit=limit,
                        language=lang
                    )

                    all_results = []
                    providers_used = [provider]

                    for result in results:
                        all_results.append({
                            "title": result.title,
                            "description": result.content_snippet,
                            "url": getattr(result, 'url', ''),
                            "provider": provider,
                            "score": result.score,
                            "metadata": getattr(result, 'metadata', {})
                        })

                execution_time = asyncio.get_event_loop().time() - start_time

                return SearchResponse(
                    query=query,
                    total_results=len(all_results),
                    results=all_results[:limit],  # 制限を適用
                    providers=providers_used,
                    execution_time=execution_time
                )

            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Search error: {str(e)}")

        @self.app.get("/search/suggestions")
        async def search_suggestions(
            query: str = Query(..., description="部分検索クエリ"),
            limit: int = Query(10, description="提案数", ge=1, le=20)
        ) -> Dict[str, List[str]]:
            """検索提案を取得"""
            try:
                suggestions = self.search_manager.get_search_suggestions(query, limit)
                return {"suggestions": suggestions}
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Suggestions error: {str(e)}")

        @self.app.get("/search/popular")
        async def popular_searches(
            days: int = Query(7, description="集計期間（日）", ge=1, le=30)
        ) -> Dict[str, List[Dict[str, Any]]]:
            """人気の検索を取得"""
            try:
                popular = self.search_manager.get_popular_searches(days)
                return {
                    "popular_searches": [
                        {"query": query, "count": count}
                        for query, count in popular
                    ]
                }
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Popular searches error: {str(e)}")

        @self.app.get("/search/status")
        async def search_status() -> Dict[str, Any]:
            """検索システムのステータスを取得"""
            try:
                status = self.search_manager.get_search_status()
                return status
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Status error: {str(e)}")

        @self.app.get("/search/providers")
        async def available_providers() -> Dict[str, List[str]]:
            """利用可能な検索プロバイダーを取得"""
            try:
                config_manager = get_search_config_manager()
                providers = []

                for provider in SearchProvider:
                    if config_manager.is_provider_enabled(provider.value):
                        providers.append({
                            "name": provider.value,
                            "enabled": True,
                            "description": self._get_provider_description(provider)
                        })
                    else:
                        providers.append({
                            "name": provider.value,
                            "enabled": False,
                            "description": self._get_provider_description(provider)
                        })

                return {"providers": providers}
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Providers error: {str(e)}")

    def _get_provider_description(self, provider: SearchProvider) -> str:
        """プロバイダーの説明を取得"""
        descriptions = {
            SearchProvider.YOUTUBE: "YouTube動画検索",
            SearchProvider.GOOGLE_SCHOLAR: "Google Scholar論文検索",
            SearchProvider.ARXIV: "arXiv学術論文検索",
            SearchProvider.SEMANTIC_SCHOLAR: "Semantic Scholar論文検索",
            SearchProvider.GOOGLE_WEB: "Googleウェブ検索",
            SearchProvider.BING_WEB: "Bingウェブ検索",
            SearchProvider.GITHUB: "GitHubリポジトリ検索",
            SearchProvider.STACK_OVERFLOW: "Stack Overflow質問検索"
        }
        return descriptions.get(provider, "不明なプロバイダー")

    def start_server(self, host: str = "127.0.0.1", port: int = 8001):
        """検索APIサーバーを開始"""
        import uvicorn

        print(f"Starting BLNCS Search API server on http://{host}:{port}")
        print("Available endpoints:")
        print(f"  GET /search - Execute search")
        print(f"  GET /search/suggestions - Get search suggestions")
        print(f"  GET /search/popular - Get popular searches")
        print(f"  GET /search/status - Get search system status")
        print(f"  GET /search/providers - Get available providers")

        uvicorn.run(self.app, host=host, port=port)

    def initialize_search_system(self):
        """検索システムを初期化"""
        print("Initializing BLNCS Search System...")
        self.search_manager.initialize_search_system()
        self.search_manager.start_search_system()
        print("Search system initialized successfully!")


# 使用例
if __name__ == "__main__":
    search_api = SearchAPI()
    search_api.initialize_search_system()
    search_api.start_server()
