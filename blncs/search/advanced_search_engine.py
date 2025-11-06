"""
高度な検索機能システム for BLNCS
全文検索とインテリジェントインデックス機能を提供
"""

import asyncio
import json
import aiohttp
import threading
from typing import Any, Dict, List, Optional, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
import logging
import re
from urllib.parse import quote_plus

from .external_search_manager import ExternalSearchManager, SearchProvider, SearchQuery as ExternalSearchQuery, SearchResult as ExternalSearchResult, Language
from .multilingual_search import get_multilingual_search_engine, detect_text_language


class SearchType(Enum):
    """検索タイプ"""
    FULL_TEXT = "full_text"
    FUZZY = "fuzzy"
    PHRASE = "phrase"
    BOOLEAN = "boolean"
    WILDCARD = "wildcard"
    REGEX = "regex"


@dataclass
class SearchDocument:
    """検索ドキュメント情報"""
    doc_id: str
    title: str
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


@dataclass
class SearchResult:
    """検索結果情報"""
    doc_id: str
    title: str
    content_snippet: str
    score: float
    matched_fields: List[str] = field(default_factory=list)
    highlights: List[str] = field(default_factory=list)


@dataclass
class SearchQuery:
    """検索クエリ情報"""
    query_text: str
    search_type: SearchType = SearchType.FULL_TEXT
    filters: Dict[str, Any] = field(default_factory=dict)
    sort_by: str = "relevance"
    limit: int = 50
    provider: Optional[SearchProvider] = None
    language: Language = Language.AUTO
    include_external: bool = False


class InvertedIndex:
    """転置インデックスシステム"""

    def __init__(self):
        """初期化"""
        self.index: Dict[str, Dict[str, List[int]]] = defaultdict(lambda: defaultdict(list))  # term -> doc_id -> positions
        self.documents: Dict[str, SearchDocument] = {}
        self.document_terms: Dict[str, Set[str]] = defaultdict(set)
        self.total_documents = 0

    def add_document(self, document: SearchDocument):
        """
        ドキュメントをインデックスに追加
        Args:
            document: 検索ドキュメント
        """
        self.documents[document.doc_id] = document
        self.total_documents += 1

        # テキストをトークナイズ
        tokens = self._tokenize_text(f"{document.title} {document.content}")

        # 各トークンの位置を記録
        for position, token in enumerate(tokens):
            self.index[token][document.doc_id].append(position)
            self.document_terms[document.doc_id].add(token)

    def remove_document(self, doc_id: str):
        """
        ドキュメントをインデックスから削除
        Args:
            doc_id: ドキュメントID
        """
        if doc_id not in self.documents:
            return

        document = self.documents[doc_id]

        # テキストをトークナイズ
        tokens = self._tokenize_text(f"{document.title} {document.content}")

        # インデックスから削除
        for token in tokens:
            if doc_id in self.index[token]:
                del self.index[token][doc_id]

                # 空のエントリを削除
                if not self.index[token]:
                    del self.index[token]

        # ドキュメント情報を削除
        del self.documents[doc_id]
        del self.document_terms[doc_id]
        self.total_documents -= 1

    def search(self, query: SearchQuery) -> List[SearchResult]:
        """
        検索を実行
        Args:
            query: 検索クエリ
        Returns:
            検索結果リスト
        """
        if query.search_type == SearchType.FULL_TEXT:
            return self._full_text_search(query)
        elif query.search_type == SearchType.FUZZY:
            return self._fuzzy_search(query)
        elif query.search_type == SearchType.PHRASE:
            return self._phrase_search(query)
        elif query.search_type == SearchType.BOOLEAN:
            return self._boolean_search(query)
        else:
            return self._full_text_search(query)

    def _tokenize_text(self, text: str) -> List[str]:
        """テキストをトークナイズ"""
        # 簡易的なトークナイザー（実際の実装ではより高度なものを使用）
        text = text.lower()
        text = re.sub(r'[^\w\s]', ' ', text)  # 記号をスペースに変換
        tokens = text.split()
        return tokens

    def _full_text_search(self, query: SearchQuery) -> List[SearchResult]:
        """全文検索を実行"""
        query_tokens = self._tokenize_text(query.query_text)

        if not query_tokens:
            return []

        # 各ドキュメントのスコアを計算
        doc_scores = defaultdict(float)

        for token in query_tokens:
            if token in self.index:
                # TF-IDFスコアを計算
                idf = self._calculate_idf(token)
                for doc_id, positions in self.index[token].items():
                    tf = len(positions)
                    score = tf * idf
                    doc_scores[doc_id] += score

        # 結果をソートして制限
        results = []
        for doc_id, score in sorted(doc_scores.items(), key=lambda x: x[1], reverse=True):
            if len(results) >= query.limit:
                break

            document = self.documents[doc_id]
            snippet = self._generate_snippet(document.content, query_tokens)

            result = SearchResult(
                doc_id=doc_id,
                title=document.title,
                content_snippet=snippet,
                score=score,
                matched_fields=["title", "content"],
                highlights=self._generate_highlights(document.content, query_tokens)
            )
            results.append(result)

        return results[query.offset:query.offset + query.limit]

    def _fuzzy_search(self, query: SearchQuery) -> List[SearchResult]:
        """ファジー検索を実行"""
        query_tokens = self._tokenize_text(query.query_text)

        # 各トークンに対してファジーマッチングを実行
        all_matches = []

        for token in query_tokens:
            matches = []
            for index_token in self.index.keys():
                # レーベンシュタイン距離で類似度を計算
                distance = self._levenshtein_distance(token, index_token)
                max_len = max(len(token), len(index_token))

                if max_len > 0:
                    similarity = 1 - (distance / max_len)
                    if similarity > 0.8:  # 80%以上の類似度
                        matches.append((index_token, similarity))

            # 各マッチングトークンで検索を実行
            for matched_token, similarity in sorted(matches, key=lambda x: x[1], reverse=True)[:3]:
                temp_query = SearchQuery(
                    query_text=matched_token,
                    search_type=SearchType.FULL_TEXT,
                    limit=query.limit * 2
                )

                sub_results = self._full_text_search(temp_query)
                for result in sub_results:
                    result.score *= similarity  # 類似度でスコアを調整
                    all_matches.append(result)

        # 重複を除去してスコアでソート
        seen_docs = set()
        unique_results = []

        for result in sorted(all_matches, key=lambda x: x.score, reverse=True):
            if result.doc_id not in seen_docs:
                seen_docs.add(result.doc_id)
                unique_results.append(result)

        return unique_results[:query.limit]

    def _phrase_search(self, query: SearchQuery) -> List[SearchResult]:
        """フレーズ検索を実行"""
        # 完全なフレーズで検索
        results = []

        for doc_id, document in self.documents.items():
            content = f"{document.title} {document.content}".lower()

            if query.query_text.lower() in content:
                # フレーズが見つかった場合のスコア計算
                score = content.count(query.query_text.lower())
                snippet = self._generate_snippet(document.content, [query.query_text])

                result = SearchResult(
                    doc_id=doc_id,
                    title=document.title,
                    content_snippet=snippet,
                    score=score,
                    matched_fields=["content"],
                    highlights=[query.query_text]
                )
                results.append(result)

        return sorted(results, key=lambda x: x.score, reverse=True)[:query.limit]

    def _boolean_search(self, query: SearchQuery) -> List[SearchResult]:
        """ブール検索を実行"""
        # 簡易的なブール検索（実際の実装ではより高度なパーサーを使用）
        query_text = query.query_text

        # AND, OR, NOT演算子を処理
        if " AND " in query_text:
            terms = [term.strip() for term in query_text.split(" AND ")]
            return self._and_search(terms, query)
        elif " OR " in query_text:
            terms = [term.strip() for term in query_text.split(" OR ")]
            return self._or_search(terms, query)
        else:
            return self._full_text_search(query)

    def _and_search(self, terms: List[str], query: SearchQuery) -> List[SearchResult]:
        """AND検索を実行"""
        if not terms:
            return []

        # 最初の検索結果を取得
        first_results = self._full_text_search(SearchQuery(query_text=terms[0], limit=1000))
        matching_docs = {result.doc_id for result in first_results}

        # 他のすべての条件にマッチするドキュメントをフィルタリング
        for term in terms[1:]:
            term_results = self._full_text_search(SearchQuery(query_text=term, limit=1000))
            term_docs = {result.doc_id for result in term_results}
            matching_docs = matching_docs.intersection(term_docs)

        # マッチするドキュメントのみを返却
        return [result for result in first_results if result.doc_id in matching_docs]

    def _or_search(self, terms: List[str], query: SearchQuery) -> List[SearchResult]:
        """OR検索を実行"""
        all_results = []

        for term in terms:
            term_results = self._full_text_search(SearchQuery(query_text=term, limit=100))
            all_results.extend(term_results)

        # 重複を除去してスコアでソート
        seen_docs = set()
        unique_results = []

        for result in sorted(all_results, key=lambda x: x.score, reverse=True):
            if result.doc_id not in seen_docs:
                seen_docs.add(result.doc_id)
                unique_results.append(result)

        return unique_results[:query.limit]

    def _calculate_idf(self, term: str) -> float:
        """逆文書頻度を計算"""
        if term not in self.index:
            return 0.0

        doc_frequency = len(self.index[term])
        if self.total_documents == 0:
            return 0.0

        # IDF = log(N / df)
        import math
        return math.log(self.total_documents / doc_frequency)

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """レーベンシュタイン距離を計算"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = list(range(len(s2) + 1))

        for i, c1 in enumerate(s1):
            current_row = [i + 1]

            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)

                current_row.append(min(insertions, deletions, substitutions))

            previous_row = current_row

        return previous_row[-1]

    def _generate_snippet(self, content: str, query_tokens: List[str], max_length: int = 200) -> str:
        """スニペットを生成"""
        content_lower = content.lower()

        # クエリトークンが最初に現れる位置を検索
        first_match_pos = len(content)
        for token in query_tokens:
            pos = content_lower.find(token.lower())
            if pos != -1 and pos < first_match_pos:
                first_match_pos = pos

        # スニペットの開始位置を決定
        start_pos = max(0, first_match_pos - max_length // 2)
        end_pos = min(len(content), start_pos + max_length)

        snippet = content[start_pos:end_pos]

        # 前後に...を追加
        if start_pos > 0:
            snippet = "..." + snippet
        if end_pos < len(content):
            snippet = snippet + "..."

        return snippet

    def _generate_highlights(self, content: str, query_tokens: List[str]) -> List[str]:
        """ハイライトを生成"""
        highlights = []

        for token in query_tokens:
            # 大文字小文字を無視して検索
            pattern = re.compile(re.escape(token), re.IGNORECASE)
            matches = pattern.findall(content)
            highlights.extend(matches)

        return list(set(highlights))  # 重複を除去


class AdvancedSearchEngine:
    """高度な検索エンジン"""

    def __init__(self, db_path: str = "search_index.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self.index = InvertedIndex()
        self._init_db()
        self.search_callbacks: List[Callable] = []

        self.is_indexing_active = False
        self.indexing_thread: Optional[threading.Thread] = None

        self.multilingual_engine = get_multilingual_search_engine()
        self.config_manager = get_search_config_manager()
        asyncio.run(self._init_external_search())

    def _init_db(self):
        """データベースを初期化"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS search_documents (
                    doc_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    metadata TEXT,
                    tags TEXT,
                    created_at REAL,
                    updated_at REAL
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS search_log (
                    id INTEGER PRIMARY KEY,
                    query_text TEXT NOT NULL,
                    search_type TEXT,
                    result_count INTEGER,
                    timestamp REAL,
                    user_id TEXT
                )
            """)

            conn.commit()

    def index_document(self, document: SearchDocument):
        """
        ドキュメントをインデックスに登録
        Args:
            document: 検索ドキュメント
        """
        # インデックスに追加
        self.index.add_document(document)

        # データベースに保存
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO search_documents
                    (doc_id, title, content, metadata, tags, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    document.doc_id, document.title, document.content,
                    json.dumps(document.metadata), json.dumps(document.tags),
                    document.created_at, document.updated_at
                ))
                conn.commit()

        except Exception as e:
            logger.error(f"ドキュメントインデックスエラー: {e}")

    def remove_document(self, doc_id: str):
        """
        ドキュメントをインデックスから削除
        Args:
            doc_id: ドキュメントID
        """
        self.index.remove_document(doc_id)

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM search_documents WHERE doc_id = ?", (doc_id,))
                conn.commit()

        except Exception as e:
            logger.error(f"ドキュメント削除エラー: {e}")

    async def _init_external_search(self):
        """外部検索を初期化"""
        # 外部検索マネージャーを初期化
        self.external_search_manager = ExternalSearchManager()

    async def search_external(self, query: SearchQuery) -> List[SearchResult]:
        """外部検索を実行"""
        if not self.external_search_manager or not query.provider:
            return []

        detected_lang = detect_text_language(query.query_text)
        query.language = detected_lang

        external_query = ExternalSearchQuery(
            provider=query.provider,
            query_text=query.query_text,
            search_type=SearchType.FULL_TEXT,
            language=query.language
        )

        external_results = await self.external_search_manager.search(external_query, query.provider)

        # 外部検索結果を内部形式に変換
        internal_results = []
        for ext_result in external_results:
            internal_result = SearchResult(
                doc_id=f"ext_{query.provider.value}_{hash(ext_result.url) % 1000000}",
                title=ext_result.title,
                content_snippet=ext_result.description,
                score=ext_result.score,
                matched_fields=["external"],
                highlights=[query.query_text]
            )
            internal_results.append(internal_result)

        return internal_results

    def search(self, query: SearchQuery, user_id: Optional[str] = None) -> List[SearchResult]:
        """
        検索を実行
        Args:
            query: 検索クエリ
            user_id: ユーザーID（ログ記録用）
        Returns:
            検索結果リスト
        """
        start_time = time.time()

        # 検索を実行
        internal_results = self.index.search(query)

        # 外部検索を非同期で実行
        if query.include_external and query.provider:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            future = loop.run_in_executor(None, self.search_external, query)
            try:
                external_results = future.result()
            except Exception as e:
                logger.error(f"外部検索エラー: {e}")
                external_results = []
            finally:
                loop.close()
            internal_results.extend(external_results)

        # 検索ログを記録
        self._log_search(query, len(internal_results), user_id)

        # 検索コールバック実行
        for callback in self.search_callbacks:
            try:
                callback(query, internal_results)
            except Exception as e:
                logger.error(f"検索コールバックエラー: {e}")

        logger.info(f"検索実行: '{query.query_text}' - {len(internal_results)}件 ({time.time() - start_time:.3f}s)")

        return internal_results

    def suggest_search_terms(self, partial_query: str, limit: int = 10) -> List[str]:
        """
        検索語を提案
        Args:
            partial_query: 部分的なクエリ
            limit: 提案数制限
        Returns:
            提案リスト
        """
        suggestions = []

        partial_tokens = self.index._tokenize_text(partial_query)

        if partial_tokens:
            last_token = partial_tokens[-1]

            # インデックス内のトークンで前方一致検索
            for token in self.index.index.keys():
                if token.startswith(last_token) and len(token) > len(last_token):
                    suggestions.append(token)

        return suggestions[:limit]

    def get_popular_search_terms(self, days: int = 7, limit: int = 20) -> List[Tuple[str, int]]:
        """
        人気の検索語を取得
        Args:
            days: 集計期間（日）
            limit: 取得制限数
        Returns:
            (検索語, 検索回数)のリスト
        """
        try:
            cutoff_time = time.time() - (days * 24 * 3600)

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT query_text, COUNT(*) as count
                    FROM search_log
                    WHERE timestamp > ?
                    GROUP BY query_text
                    ORDER BY count DESC
                    LIMIT ?
                """, (cutoff_time, limit))

                return [(row[0], row[1]) for row in cursor.fetchall()]

        except Exception as e:
            logger.error(f"人気検索語取得エラー: {e}")
            return []

    def _log_search(self, query: SearchQuery, result_count: int, user_id: Optional[str]):
        """検索をログ記録"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO search_log
                    (query_text, search_type, result_count, timestamp, user_id)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    query.query_text, query.search_type.value, result_count,
                    time.time(), user_id
                ))
                conn.commit()

        except Exception as e:
            logger.error(f"検索ログ記録エラー: {e}")

    def add_search_callback(self, callback: Callable):
        """
        検索コールバックを追加
        Args:
            callback: コールバック関数
        """
        self.search_callbacks.append(callback)

    def start_indexing(self):
        """インデックス処理を開始"""
        if not self.is_indexing_active:
            self.is_indexing_active = True
            self.indexing_thread = threading.Thread(target=self._indexing_loop, daemon=True)
            self.indexing_thread.start()

    def stop_indexing(self):
        """インデックス処理を停止"""
        self.is_indexing_active = False
        if self.indexing_thread:
            self.indexing_thread.join()

    def _indexing_loop(self):
        """インデックスループ"""
        while self.is_indexing_active:
            try:
                # 定期的なインデックス最適化処理
                time.sleep(3600)  # 1時間間隔
            except Exception as e:
                logger.error(f"インデックスループエラー: {e}")


class SearchManager:
    """検索管理システム"""

    def __init__(self, db_path: str = "advanced_search.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self.search_engine = AdvancedSearchEngine(db_path)

        self.is_search_active = False

    def initialize_search_system(self):
        """検索システムを初期化"""
        # デフォルトのドキュメントをインデックス（サンプル）
        self._index_sample_documents()

    def _index_sample_documents(self):
        """サンプルドキュメントをインデックス"""
        sample_docs = [
            SearchDocument(
                doc_id="doc_1",
                title="Lightning Networkとは",
                content="Lightning NetworkはBitcoinのセカンドレイヤースケーリングソリューションです。マイクロペイメントを高速・低コストで実行できます。",
                tags=["blockchain", "bitcoin", "lightning"]
            ),
            SearchDocument(
                doc_id="doc_2",
                title="スマートコントラクトの基礎",
                content="スマートコントラクトはブロックチェーン上で自動実行されるプログラムです。契約条件が満たされた場合に自動的に実行されます。",
                tags=["blockchain", "smart_contract"]
            ),
            SearchDocument(
                doc_id="doc_3",
                title="暗号通貨のセキュリティ",
                content="暗号通貨のセキュリティは公開鍵暗号とデジタル署名に基づいています。秘密鍵の管理が非常に重要です。",
                tags=["cryptocurrency", "security"]
            )
        ]

        for doc in sample_docs:
            self.search_engine.index_document(doc)

    def start_search_system(self):
        """検索システムを開始"""
        if not self.is_search_active:
            self.is_search_active = True
            self.search_engine.start_indexing()

    def stop_search_system(self):
        """検索システムを停止"""
        self.is_search_active = False
        self.search_engine.stop_indexing()

    def perform_external_search(self, query_text: str, provider: SearchProvider,
                      limit: int = 10, language: Language = Language.AUTO,
                      user_id: Optional[str] = None) -> List[SearchResult]:
        """
        外部検索を実行
        Args:
            query_text: 検索クエリテキスト
            provider: 検索プロバイダー
            limit: 結果制限数
            language: 検索言語
            user_id: ユーザーID
        Returns:
            検索結果リスト
        """
        query = SearchQuery(
            query_text=query_text,
            provider=provider,
            limit=limit,
            language=language,
            include_external=True
        )

        return self.search_engine.search(query, user_id)

    def get_search_suggestions(self, partial_query: str, limit: int = 10) -> List[str]:
        """
        検索提案を取得
        Args:
            partial_query: 部分クエリ
            limit: 提案数制限
        Returns:
            提案リスト
        """
        return self.search_engine.suggest_search_terms(partial_query, limit)

    def get_popular_searches(self, days: int = 7) -> List[Tuple[str, int]]:
        """
        人気の検索を取得
        Args:
            days: 集計期間（日）
        Returns:
            人気検索リスト
        """
        return self.search_engine.get_popular_search_terms(days)

    def add_document(self, doc_id: str, title: str, content: str,
                    metadata: Dict[str, Any] = None, tags: List[str] = None):
        """
        ドキュメントを追加
        Args:
            doc_id: ドキュメントID
            title: タイトル
            content: コンテンツ
            metadata: メタデータ
            tags: タグリスト
        """
        document = SearchDocument(
            doc_id=doc_id,
            title=title,
            content=content,
            metadata=metadata or {},
            tags=tags or []
        )

        self.search_engine.index_document(document)

    def remove_document(self, doc_id: str):
        """
        ドキュメントを削除
        Args:
            doc_id: ドキュメントID
        """
        self.search_engine.remove_document(doc_id)

    def get_search_status(self) -> Dict[str, Any]:
        """検索ステータスを取得"""
        return {
            "is_active": self.is_search_active,
            "total_documents": self.search_engine.index.total_documents,
            "total_terms": len(self.search_engine.index.index)
        }


# 使用例
def example_usage():
    include_external: bool = False

    # システム初期化
    manager.initialize_search_system()

    # システム開始
    manager.start_search_system()

    # 検索テスト
    results = manager.perform_search("Lightning Network", SearchType.FULL_TEXT, limit=10)
    print(f"検索結果: {len(results)}件")

    for result in results[:3]:
        print(f"  - {result.title} (スコア: {result.score:.3f})")
        print(f"    {result.content_snippet}")

    # 検索提案テスト
    suggestions = manager.get_search_suggestions("light", limit=5)
    print(f"検索提案: {suggestions}")

    # 人気検索取得
    popular = manager.get_popular_searches(days=1)
    print(f"人気検索: {popular}")

    # ステータス表示
    status = manager.get_search_status()
    print(f"検索ステータス: {status}")

    manager.stop_search_system()


if __name__ == "__main__":
    example_usage()
