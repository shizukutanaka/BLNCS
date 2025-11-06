"""
外部検索API統合システム for BLNCS
YouTube、論文、Web検索などの外部ソースを統合
"""

import asyncio
import aiohttp
import json
import time
import hashlib
import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlencode, quote_plus
from datetime import datetime, timedelta
import re

logger = logging.getLogger(__name__)


class SearchProvider(Enum):
    """検索プロバイダー"""
    YOUTUBE = "youtube"
    GOOGLE_SCHOLAR = "google_scholar"
    ARXIV = "arxiv"
    SEMANTIC_SCHOLAR = "semantic_scholar"
    GOOGLE_WEB = "google_web"
    BING_WEB = "bing_web"
    GITHUB = "github"
    STACK_OVERFLOW = "stack_overflow"


class Language(Enum):
    """対応言語"""
    AUTO = "auto"
    JA = "ja"
    EN = "en"
    ZH = "zh"
    KO = "ko"
    FR = "fr"
    DE = "de"
    ES = "es"
    PT = "pt"
    RU = "ru"
    AR = "ar"
    HI = "hi"


@dataclass
class SearchResult:
    """検索結果"""
    title: str
    description: str
    url: str
    provider: SearchProvider
    score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    thumbnail_url: Optional[str] = None
    published_date: Optional[datetime] = None
    language: Language = Language.EN
    tags: List[str] = field(default_factory=list)


@dataclass
class SearchQuery:
    """検索クエリ"""
    text: str
    provider: SearchProvider
    language: Language = Language.AUTO
    max_results: int = 10
    filters: Dict[str, Any] = field(default_factory=dict)
    sort_by: str = "relevance"
    safe_search: bool = True


class ExternalSearchManager:
    """外部検索統合マネージャー"""

    def __init__(self, config: Dict[str, Any]):
        """
        初期化
        Args:
            config: API設定（APIキー、レート制限など）
        """
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.cache_expiry: Dict[str, datetime] = {}
        self.rate_limits: Dict[SearchProvider, Dict[str, Any]] = {}
        self._init_rate_limits()

    def _init_rate_limits(self):
        """レート制限を初期化"""
        limits = {
            SearchProvider.YOUTUBE: {"requests_per_minute": 60, "requests_per_day": 10000},
            SearchProvider.GOOGLE_WEB: {"requests_per_minute": 60, "requests_per_day": 10000},
            SearchProvider.BING_WEB: {"requests_per_minute": 60, "requests_per_day": 10000},
            SearchProvider.GOOGLE_SCHOLAR: {"requests_per_minute": 30, "requests_per_day": 1000},
            SearchProvider.ARXIV: {"requests_per_minute": 100, "requests_per_day": 10000},
            SearchProvider.SEMANTIC_SCHOLAR: {"requests_per_minute": 100, "requests_per_day": 10000},
        }

        for provider, limit in limits.items():
            self.rate_limits[provider] = {
                "requests": [],
                "requests_per_minute": limit["requests_per_minute"],
                "requests_per_day": limit["requests_per_day"]
            }

    async def __aenter__(self):
        """非同期コンテキスト開始"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={
                "User-Agent": "BLNCS-External-Search/1.0",
                "Accept": "application/json",
                "Accept-Language": "ja,en-US;q=0.9,en;q=0.8"
            }
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """非同期コンテキスト終了"""
        if self.session:
            await self.session.close()

    def _check_rate_limit(self, provider: SearchProvider) -> bool:
        """レート制限チェック"""
        if provider not in self.rate_limits:
            return True

        limits = self.rate_limits[provider]
        now = datetime.now()

        # 1分以内のリクエストをフィルタ
        limits["requests"] = [
            req_time for req_time in limits["requests"]
            if (now - req_time).seconds < 60
        ]

        # 1日以内のリクエストをフィルタ
        limits["requests"] = [
            req_time for req_time in limits["requests"]
            if (now - req_time).days < 1
        ]

        # 制限チェック
        if len(limits["requests"]) >= limits["requests_per_minute"]:
            logger.warning(f"Rate limit exceeded for {provider.value}")
            return False

        limits["requests"].append(now)
        return True

    def _get_cache_key(self, query: SearchQuery) -> str:
        """キャッシュキーを生成"""
        key_data = {
            "text": query.text,
            "provider": query.provider.value,
            "language": query.language.value,
            "max_results": query.max_results,
            "filters": str(sorted(query.filters.items()))
        }
        key_string = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_string.encode()).hexdigest()

    def _get_cache(self, query: SearchQuery) -> Optional[List[SearchResult]]:
        """キャッシュから取得"""
        cache_key = self._get_cache_key(query)

        if cache_key in self.cache:
            expiry = self.cache_expiry.get(cache_key)
            if expiry and datetime.now() < expiry:
                return self.cache[cache_key]
            else:
                # キャッシュ期限切れ
                del self.cache[cache_key]
                if cache_key in self.cache_expiry:
                    del self.cache_expiry[cache_key]

        return None

    def _set_cache(self, query: SearchQuery, results: List[SearchResult], ttl_minutes: int = 60):
        """キャッシュに保存"""
        cache_key = self._get_cache_key(query)
        self.cache[cache_key] = results
        self.cache_expiry[cache_key] = datetime.now() + timedelta(minutes=ttl_minutes)

    async def search(self, query: SearchQuery) -> List[SearchResult]:
        """
        検索を実行
        Args:
            query: 検索クエリ
        Returns:
            検索結果リスト
        """
        # キャッシュチェック
        cached_results = self._get_cache(query)
        if cached_results:
            logger.info(f"Cache hit for query: {query.text}")
            return cached_results

        # レート制限チェック
        if not self._check_rate_limit(query.provider):
            logger.warning(f"Rate limit exceeded for {query.provider.value}")
            return []

        try:
            # プロバイダー別の検索実行
            if query.provider == SearchProvider.YOUTUBE:
                results = await self._search_youtube(query)
            elif query.provider == SearchProvider.GOOGLE_SCHOLAR:
                results = await self._search_google_scholar(query)
            elif query.provider == SearchProvider.ARXIV:
                results = await self._search_arxiv(query)
            elif query.provider == SearchProvider.SEMANTIC_SCHOLAR:
                results = await self._search_semantic_scholar(query)
            elif query.provider == SearchProvider.GOOGLE_WEB:
                results = await self._search_google_web(query)
            elif query.provider == SearchProvider.BING_WEB:
                results = await self._search_bing(query)
            elif query.provider == SearchProvider.GITHUB:
                results = await self._search_github(query)
            elif query.provider == SearchProvider.STACK_OVERFLOW:
                results = await self._search_stack_overflow(query)
            else:
                raise ValueError(f"Unsupported provider: {query.provider}")

            # キャッシュに保存
            self._set_cache(query, results)

            return results

        except Exception as e:
            logger.error(f"Search error for {query.provider.value}: {e}")
            return []

    async def _search_youtube(self, query: SearchQuery) -> List[SearchResult]:
        """YouTube検索"""
        api_key = self.config.get("youtube_api_key")
        if not api_key:
            logger.warning("YouTube API key not configured")
            return []

        # 言語検出と翻訳
        search_text = await self._translate_query(query.text, query.language)

        params = {
            "part": "snippet",
            "q": search_text,
            "type": "video",
            "maxResults": min(query.max_results, 50),
            "key": api_key,
            "safeSearch": "strict" if query.safe_search else "none"
        }

        if query.language != Language.AUTO:
            params["relevanceLanguage"] = query.language.value

        url = "https://www.googleapis.com/youtube/v3/search"

        try:
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()

                    results = []
                    for item in data.get("items", []):
                        snippet = item.get("snippet", {})

                        # 公開日時を解析
                        published_str = snippet.get("publishedAt", "")
                        published_date = None
                        if published_str:
                            try:
                                published_date = datetime.fromisoformat(published_str.replace('Z', '+00:00'))
                            except:
                                pass

                        result = SearchResult(
                            title=snippet.get("title", ""),
                            description=snippet.get("description", ""),
                            url=f"https://www.youtube.com/watch?v={item['id']['videoId']}",
                            provider=SearchProvider.YOUTUBE,
                            score=1.0,
                            metadata={
                                "channel_title": snippet.get("channelTitle", ""),
                                "video_id": item["id"]["videoId"],
                                "duration": "",  # 追加のAPIコールが必要
                                "view_count": 0
                            },
                            thumbnail_url=snippet.get("thumbnails", {}).get("default", {}).get("url"),
                            published_date=published_date,
                            language=self._detect_language(snippet.get("title", "")),
                            tags=snippet.get("tags", [])
                        )
                        results.append(result)

                    return results
                else:
                    logger.error(f"YouTube API error: {response.status}")
                    return []

        except Exception as e:
            logger.error(f"YouTube search error: {e}")
            return []

    async def _search_google_scholar(self, query: SearchQuery) -> List[SearchResult]:
        """Google Scholar検索（スクレイピング）"""
        search_text = await self._translate_query(query.text, query.language)

        # Google ScholarのURLを構築
        params = {
            "q": search_text,
            "hl": query.language.value if query.language != Language.AUTO else "en",
            "num": query.max_results
        }

        url = "https://scholar.google.com/scholar"

        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }

            async with self.session.get(url, params=params, headers=headers) as response:
                if response.status == 200:
                    html = await response.text()

                    # 簡易的なHTML解析（実際にはより高度なパーサーを使用）
                    results = []

                    # 論文タイトルの抽出（正規表現）
                    title_pattern = r'<h3[^>]*><a[^>]*>(.*?)</a></h3>'
                    titles = re.findall(title_pattern, html, re.DOTALL)

                    # 説明の抽出
                    desc_pattern = r'<div[^>]*class="gs_rs"[^>]*>(.*?)</div>'
                    descriptions = re.findall(desc_pattern, html, re.DOTALL)

                    for i, (title, desc) in enumerate(zip(titles[:query.max_results], descriptions[:query.max_results])):
                        # HTMLタグを除去
                        title = re.sub(r'<[^>]+>', '', title).strip()
                        desc = re.sub(r'<[^>]+>', '', desc).strip()

                        result = SearchResult(
                            title=title,
                            description=desc[:200] + "..." if len(desc) > 200 else desc,
                            url=f"https://scholar.google.com/scholar?q={quote_plus(search_text)}",
                            provider=SearchProvider.GOOGLE_SCHOLAR,
                            score=1.0 - (i * 0.1),  # 順位によるスコア
                            metadata={"rank": i + 1},
                            language=self._detect_language(title)
                        )
                        results.append(result)

                    return results
                else:
                    logger.error(f"Google Scholar error: {response.status}")
                    return []

        except Exception as e:
            logger.error(f"Google Scholar search error: {e}")
            return []

    async def _search_arxiv(self, query: SearchQuery) -> List[SearchResult]:
        """arXiv検索"""
        search_text = await self._translate_query(query.text, query.language)

        params = {
            "search_query": search_text,
            "start": 0,
            "max_results": query.max_results,
            "sortBy": "relevance" if query.sort_by == "relevance" else "submittedDate",
            "sortOrder": "descending"
        }

        url = "http://export.arxiv.org/api/query"

        try:
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    xml_data = await response.text()

                    # XMLを解析（簡易版）
                    results = []

                    # タイトル、要約、URLを抽出
                    title_pattern = r'<title>(.*?)</title>'
                    summary_pattern = r'<summary>(.*?)</summary>'
                    id_pattern = r'<id>(.*?)</id>'

                    titles = re.findall(title_pattern, xml_data)
                    summaries = re.findall(summary_pattern, xml_data)
                    ids = re.findall(id_pattern, xml_data)

                    for i, (title, summary, arxiv_id) in enumerate(zip(titles, summaries, ids)):
                        if i >= query.max_results:
                            break

                        # arXiv IDからURLを構築
                        match = re.search(r'arxiv.org/abs/([^/]+)', arxiv_id)
                        if match:
                            paper_id = match.group(1)
                            url = f"https://arxiv.org/abs/{paper_id}"

                            result = SearchResult(
                                title=title.strip(),
                                description=summary.strip()[:200] + "..." if len(summary.strip()) > 200 else summary.strip(),
                                url=url,
                                provider=SearchProvider.ARXIV,
                                score=1.0 - (i * 0.05),
                                metadata={
                                    "arxiv_id": paper_id,
                                    "categories": []
                                },
                                language=self._detect_language(title)
                            )
                            results.append(result)

                    return results
                else:
                    logger.error(f"arXiv API error: {response.status}")
                    return []

        except Exception as e:
            logger.error(f"arXiv search error: {e}")
            return []

    async def _search_semantic_scholar(self, query: SearchQuery) -> List[SearchResult]:
        """Semantic Scholar検索"""
        search_text = await self._translate_query(query.text, query.language)

        params = {
            "query": search_text,
            "limit": query.max_results,
            "fields": "title,abstract,url,year,authors,venue,citationCount"
        }

        url = "https://api.semanticscholar.org/graph/v1/paper/search"

        try:
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()

                    results = []
                    for i, paper in enumerate(data.get("data", [])):
                        result = SearchResult(
                            title=paper.get("title", ""),
                            description=paper.get("abstract", "")[:200] + "..." if len(paper.get("abstract", "")) > 200 else paper.get("abstract", ""),
                            url=paper.get("url", ""),
                            provider=SearchProvider.SEMANTIC_SCHOLAR,
                            score=1.0 - (i * 0.05),
                            metadata={
                                "year": paper.get("year"),
                                "authors": [author.get("name", "") for author in paper.get("authors", [])],
                                "venue": paper.get("venue", ""),
                                "citation_count": paper.get("citationCount", 0)
                            },
                            language=self._detect_language(paper.get("title", ""))
                        )
                        results.append(result)

                    return results
                else:
                    logger.error(f"Semantic Scholar API error: {response.status}")
                    return []

        except Exception as e:
            logger.error(f"Semantic Scholar search error: {e}")
            return []

    async def _search_google_web(self, query: SearchQuery) -> List[SearchResult]:
        """Google Web検索"""
        api_key = self.config.get("google_api_key")
        search_engine_id = self.config.get("google_search_engine_id")

        if not api_key or not search_engine_id:
            logger.warning("Google API key or Search Engine ID not configured")
            return []

        search_text = await self._translate_query(query.text, query.language)

        params = {
            "key": api_key,
            "cx": search_engine_id,
            "q": search_text,
            "num": query.max_results,
            "safe": "active" if query.safe_search else "off"
        }

        if query.language != Language.AUTO:
            params["lr"] = f"lang_{query.language.value}"

        url = "https://www.googleapis.com/customsearch/v1"

        try:
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()

                    results = []
                    for i, item in enumerate(data.get("items", [])):
                        result = SearchResult(
                            title=item.get("title", ""),
                            description=item.get("snippet", ""),
                            url=item.get("link", ""),
                            provider=SearchProvider.GOOGLE_WEB,
                            score=1.0 - (i * 0.1),
                            metadata={
                                "display_link": item.get("displayLink", ""),
                                "formatted_url": item.get("formattedUrl", "")
                            },
                            language=self._detect_language(item.get("title", ""))
                        )
                        results.append(result)

                    return results
                else:
                    logger.error(f"Google Custom Search API error: {response.status}")
                    return []

        except Exception as e:
            logger.error(f"Google Web search error: {e}")
            return []

    async def _search_bing(self, query: SearchQuery) -> List[SearchResult]:
        """Bing検索"""
        api_key = self.config.get("bing_api_key")
        if not api_key:
            logger.warning("Bing API key not configured")
            return []

        search_text = await self._translate_query(query.text, query.language)

        headers = {
            "Ocp-Apim-Subscription-Key": api_key,
            "User-Agent": "BLNCS-External-Search/1.0"
        }

        params = {
            "q": search_text,
            "count": query.max_results,
            "mkt": query.language.value if query.language != Language.AUTO else "en-US",
            "safeSearch": "Strict" if query.safe_search else "Off"
        }

        url = "https://api.bing.microsoft.com/v7.0/search"

        try:
            async with self.session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()

                    results = []
                    for i, item in enumerate(data.get("webPages", {}).get("value", [])):
                        result = SearchResult(
                            title=item.get("name", ""),
                            description=item.get("snippet", ""),
                            url=item.get("url", ""),
                            provider=SearchProvider.BING_WEB,
                            score=1.0 - (i * 0.1),
                            metadata={
                                "display_url": item.get("displayUrl", ""),
                                "last_crawled": item.get("dateLastCrawled", "")
                            },
                            language=self._detect_language(item.get("name", ""))
                        )
                        results.append(result)

                    return results
                else:
                    logger.error(f"Bing API error: {response.status}")
                    return []

        except Exception as e:
            logger.error(f"Bing search error: {e}")
            return []

    async def _search_github(self, query: SearchQuery) -> List[SearchResult]:
        """GitHub検索"""
        search_text = await self._translate_query(query.text, query.language)

        params = {
            "q": search_text,
            "sort": "best-match",
            "order": "desc",
            "per_page": query.max_results
        }

        url = "https://api.github.com/search/repositories"

        try:
            headers = {
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "BLNCS-External-Search/1.0"
            }

            # GitHub APIは認証不要だが、レート制限が厳しい
            token = self.config.get("github_token")
            if token:
                headers["Authorization"] = f"token {token}"

            async with self.session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()

                    results = []
                    for i, repo in enumerate(data.get("items", [])):
                        result = SearchResult(
                            title=repo.get("full_name", ""),
                            description=repo.get("description", ""),
                            url=repo.get("html_url", ""),
                            provider=SearchProvider.GITHUB,
                            score=1.0 - (i * 0.05),
                            metadata={
                                "stars": repo.get("stargazers_count", 0),
                                "forks": repo.get("forks_count", 0),
                                "language": repo.get("language", ""),
                                "updated_at": repo.get("updated_at", ""),
                                "owner": repo.get("owner", {}).get("login", "")
                            },
                            language=self._detect_language(repo.get("description", ""))
                        )
                        results.append(result)

                    return results
                else:
                    logger.error(f"GitHub API error: {response.status}")
                    return []

        except Exception as e:
            logger.error(f"GitHub search error: {e}")
            return []

    async def _search_stack_overflow(self, query: SearchQuery) -> List[SearchResult]:
        """Stack Overflow検索"""
        search_text = await self._translate_query(query.text, query.language)

        params = {
            "q": search_text,
            "site": "stackoverflow.com",
            "pagesize": query.max_results,
            "order": "desc",
            "sort": "relevance"
        }

        url = "https://api.stackexchange.com/2.3/search"

        try:
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()

                    results = []
                    for i, item in enumerate(data.get("items", [])):
                        result = SearchResult(
                            title=item.get("title", ""),
                            description=item.get("excerpt", "")[:200] + "..." if len(item.get("excerpt", "")) > 200 else item.get("excerpt", ""),
                            url=item.get("link", ""),
                            provider=SearchProvider.STACK_OVERFLOW,
                            score=1.0 - (i * 0.05),
                            metadata={
                                "score": item.get("score", 0),
                                "answer_count": item.get("answer_count", 0),
                                "view_count": item.get("view_count", 0),
                                "tags": item.get("tags", []),
                                "creation_date": datetime.fromtimestamp(item.get("creation_date", 0)) if item.get("creation_date") else None
                            },
                            language=self._detect_language(item.get("title", ""))
                        )
                        results.append(result)

                    return results
                else:
                    logger.error(f"Stack Overflow API error: {response.status}")
                    return []

        except Exception as e:
            logger.error(f"Stack Overflow search error: {e}")
            return []

    async def _translate_query(self, text: str, target_language: Language) -> str:
        """クエリを翻訳"""
        if target_language == Language.AUTO:
            return text

        # 簡易的な翻訳（実際にはGoogle Translate APIなどを使用）
        # ここでは英語がデフォルトなので、英語以外の言語の場合のみ翻訳を試行

        if target_language == Language.EN:
            return text

        # 実際の実装では翻訳APIを呼び出す
        # ここではプレースホルダー
        logger.info(f"Translation needed: {text} -> {target_language.value}")
        return text

    def _detect_language(self, text: str) -> Language:
        """言語を検出"""
        if not text:
            return Language.EN

        # 簡易的な言語検出（実際にはより高度なライブラリを使用）
        # 日本語文字を含む場合
        if re.search(r'[\u3040-\u309f\u30a0-\u30ff\u4e00-\u9faf]', text):
            return Language.JA

        # 中国語文字を含む場合
        if re.search(r'[\u4e00-\u9faf]', text):
            return Language.ZH

        # 韓国語文字を含む場合
        if re.search(r'[\uac00-\ud7af]', text):
            return Language.KO

        # その他の言語は英語として扱う
        return Language.EN

    async def get_search_stats(self) -> Dict[str, Any]:
        """検索統計を取得"""
        return {
            "cache_size": len(self.cache),
            "rate_limits": {
                provider.value: {
                    "requests_last_minute": len([r for r in limits["requests"]
                                               if (datetime.now() - r).seconds < 60]),
                    "limit_per_minute": limits["requests_per_minute"]
                }
                for provider, limits in self.rate_limits.items()
            },
            "total_searches": sum(len(limits["requests"]) for limits in self.rate_limits.values())
        }
