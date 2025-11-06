"""
分散トレーシングシステム for BLNCS
リクエスト追跡とパフォーマンス監視機能を提供
"""

import time
import json
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import logging
import asyncio
import uuid
import random
from collections import defaultdict

logger = logging.getLogger(__name__)


class TraceStatus(Enum):
    """トレースステータス"""
    STARTED = "started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class SpanKind(Enum):
    """スパン種別"""
    SERVER = "server"
    CLIENT = "client"
    INTERNAL = "internal"
    PRODUCER = "producer"
    CONSUMER = "consumer"


@dataclass
class TraceSpan:
    """トレーススパン情報"""
    span_id: str
    trace_id: str
    parent_span_id: Optional[str] = None
    operation_name: str = ""
    span_kind: SpanKind = SpanKind.INTERNAL
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    duration: Optional[float] = None
    status: TraceStatus = TraceStatus.STARTED
    tags: Dict[str, str] = field(default_factory=dict)
    logs: List[Dict[str, Any]] = field(default_factory=list)
    service_name: str = "unknown"
    resource_name: str = ""


@dataclass
class DistributedTrace:
    """分散トレース情報"""
    trace_id: str
    root_span_id: str
    service_name: str = ""
    operation_name: str = ""
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    duration: Optional[float] = None
    status: TraceStatus = TraceStatus.STARTED
    spans: List[TraceSpan] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)


class TraceContext:
    """トレースコンテキスト"""

    def __init__(self, trace_id: str, span_id: str, parent_span_id: Optional[str] = None):
        """
        初期化
        Args:
            trace_id: トレースID
            span_id: スパンID
            parent_span_id: 親スパンID
        """
        self.trace_id = trace_id
        self.span_id = span_id
        self.parent_span_id = parent_span_id

    def to_headers(self) -> Dict[str, str]:
        """HTTPヘッダー形式に変換"""
        return {
            "X-Trace-ID": self.trace_id,
            "X-Span-ID": self.span_id,
            "X-Parent-Span-ID": self.parent_span_id or ""
        }

    @classmethod
    def from_headers(cls, headers: Dict[str, str]) -> Optional['TraceContext']:
        """HTTPヘッダーから作成"""
        trace_id = headers.get("X-Trace-ID")
        span_id = headers.get("X-Span-ID")
        parent_span_id = headers.get("X-Parent-Span-ID")

        if trace_id and span_id:
            return cls(trace_id, span_id, parent_span_id if parent_span_id else None)
        return None


class TracingEngine:
    """トレーシングエンジン"""

    def __init__(self, service_name: str, db_path: str = "distributed_tracing.db"):
        """
        初期化
        Args:
            service_name: サービス名
            db_path: データベースパス
        """
        self.service_name = service_name
        self.db_path = db_path
        self._init_db()
        self.active_traces: Dict[str, DistributedTrace] = {}
        self.active_spans: Dict[str, TraceSpan] = {}
        self.trace_callbacks: List[Callable] = []

    def _init_db(self):
        """データベースを初期化"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS traces (
                    trace_id TEXT PRIMARY KEY,
                    root_span_id TEXT NOT NULL,
                    service_name TEXT,
                    operation_name TEXT,
                    start_time REAL,
                    end_time REAL,
                    duration REAL,
                    status TEXT,
                    tags TEXT
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS spans (
                    span_id TEXT PRIMARY KEY,
                    trace_id TEXT NOT NULL,
                    parent_span_id TEXT,
                    operation_name TEXT,
                    span_kind TEXT,
                    start_time REAL,
                    end_time REAL,
                    duration REAL,
                    status TEXT,
                    tags TEXT,
                    logs TEXT,
                    service_name TEXT,
                    resource_name TEXT,
                    FOREIGN KEY (trace_id) REFERENCES traces (trace_id)
                )
            """)

            conn.commit()

    def start_trace(self, operation_name: str, tags: Dict[str, str] = None) -> TraceContext:
        """
        トレースを開始
        Args:
            operation_name: 操作名
            tags: タグ情報
        Returns:
            トレースコンテキスト
        """
        trace_id = str(uuid.uuid4())
        span_id = str(uuid.uuid4())

        trace = DistributedTrace(
            trace_id=trace_id,
            root_span_id=span_id,
            service_name=self.service_name,
            operation_name=operation_name,
            tags=tags or {}
        )

        root_span = TraceSpan(
            span_id=span_id,
            trace_id=trace_id,
            operation_name=operation_name,
            span_kind=SpanKind.SERVER,
            service_name=self.service_name,
            tags=tags or {}
        )

        self.active_traces[trace_id] = trace
        self.active_spans[span_id] = root_span

        logger.info(f"トレース開始: {trace_id} - {operation_name}")

        return TraceContext(trace_id, span_id)

    def start_span(self, operation_name: str, parent_context: TraceContext,
                  span_kind: SpanKind = SpanKind.INTERNAL, tags: Dict[str, str] = None) -> TraceContext:
        """
        スパンを開始
        Args:
            operation_name: 操作名
            parent_context: 親コンテキスト
            span_kind: スパン種別
            tags: タグ情報
        Returns:
            トレースコンテキスト
        """
        span_id = str(uuid.uuid4())

        span = TraceSpan(
            span_id=span_id,
            trace_id=parent_context.trace_id,
            parent_span_id=parent_context.span_id,
            operation_name=operation_name,
            span_kind=span_kind,
            service_name=self.service_name,
            tags=tags or {}
        )

        self.active_spans[span_id] = span

        # 親トレースにスパンを追加
        if parent_context.trace_id in self.active_traces:
            self.active_traces[parent_context.trace_id].spans.append(span)

        logger.debug(f"スパン開始: {span_id} - {operation_name}")

        return TraceContext(parent_context.trace_id, span_id, parent_context.span_id)

    def end_span(self, context: TraceContext, status: TraceStatus = TraceStatus.COMPLETED,
                logs: List[Dict[str, Any]] = None):
        """
        スパンを終了
        Args:
            context: トレースコンテキスト
            status: ステータス
            logs: ログ情報
        """
        if context.span_id not in self.active_spans:
            return

        span = self.active_spans[context.span_id]
        span.end_time = time.time()
        span.duration = span.end_time - span.start_time
        span.status = status

        if logs:
            span.logs.extend(logs)

        # データベースに保存
        self._save_span_to_db(span)

        # アクティブスパンから削除
        del self.active_spans[context.span_id]

        logger.debug(f"スパン終了: {context.span_id} - {span.duration:.3f}s")

        # ルートスパンの場合はトレースも終了
        if context.span_id == self.active_traces.get(context.trace_id, DistributedTrace("", "")).root_span_id:
            self._end_trace(context.trace_id, status)

    def _end_trace(self, trace_id: str, status: TraceStatus):
        """トレースを終了"""
        if trace_id not in self.active_traces:
            return

        trace = self.active_traces[trace_id]
        trace.end_time = time.time()
        trace.duration = trace.end_time - trace.start_time
        trace.status = status

        # データベースに保存
        self._save_trace_to_db(trace)

        # アクティブトレースから削除
        del self.active_traces[trace_id]

        logger.info(f"トレース終了: {trace_id} - {trace.duration:.3f}s")

    def _save_span_to_db(self, span: TraceSpan):
        """スパンをデータベースに保存"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO spans
                    (span_id, trace_id, parent_span_id, operation_name, span_kind, start_time,
                     end_time, duration, status, tags, logs, service_name, resource_name)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    span.span_id, span.trace_id, span.parent_span_id, span.operation_name,
                    span.span_kind.value, span.start_time, span.end_time, span.duration,
                    span.status.value, json.dumps(span.tags), json.dumps(span.logs),
                    span.service_name, span.resource_name
                ))
                conn.commit()

        except Exception as e:
            logger.error(f"スパン保存エラー: {e}")

    def _save_trace_to_db(self, trace: DistributedTrace):
        """トレースをデータベースに保存"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO traces
                    (trace_id, root_span_id, service_name, operation_name, start_time,
                     end_time, duration, status, tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    trace.trace_id, trace.root_span_id, trace.service_name,
                    trace.operation_name, trace.start_time, trace.end_time,
                    trace.duration, trace.status.value, json.dumps(trace.tags)
                ))
                conn.commit()

        except Exception as e:
            logger.error(f"トレース保存エラー: {e}")

    def add_trace_callback(self, callback: Callable):
        """
        トレースコールバックを追加
        Args:
            callback: コールバック関数
        """
        self.trace_callbacks.append(callback)

    def get_trace_details(self, trace_id: str) -> Optional[Dict[str, Any]]:
        """
        トレース詳細を取得
        Args:
            trace_id: トレースID
        Returns:
            トレース情報（見つからない場合はNone）
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                # トレース情報を取得
                cursor = conn.execute("""
                    SELECT trace_id, root_span_id, service_name, operation_name, start_time,
                           end_time, duration, status, tags
                    FROM traces WHERE trace_id = ?
                """, (trace_id,))

                trace_row = cursor.fetchone()
                if not trace_row:
                    return None

                # スパン情報を取得
                spans_cursor = conn.execute("""
                    SELECT span_id, parent_span_id, operation_name, span_kind, start_time,
                           end_time, duration, status, tags, logs, service_name, resource_name
                    FROM spans WHERE trace_id = ?
                    ORDER BY start_time
                """, (trace_id,))

                spans = []
                for span_row in spans_cursor.fetchall():
                    spans.append({
                        "span_id": span_row[0],
                        "parent_span_id": span_row[1],
                        "operation_name": span_row[2],
                        "span_kind": span_row[3],
                        "start_time": span_row[4],
                        "end_time": span_row[5],
                        "duration": span_row[6],
                        "status": span_row[7],
                        "tags": json.loads(span_row[8]) if span_row[8] else {},
                        "logs": json.loads(span_row[9]) if span_row[9] else [],
                        "service_name": span_row[10],
                        "resource_name": span_row[11]
                    })

                return {
                    "trace_id": trace_row[0],
                    "root_span_id": trace_row[1],
                    "service_name": trace_row[2],
                    "operation_name": trace_row[3],
                    "start_time": trace_row[4],
                    "end_time": trace_row[5],
                    "duration": trace_row[6],
                    "status": trace_row[7],
                    "tags": json.loads(trace_row[8]) if trace_row[8] else {},
                    "spans": spans
                }

        except Exception as e:
            logger.error(f"トレース詳細取得エラー: {e}")
            return None


class TraceSampler:
    """トレースサンプラー"""

    def __init__(self, sample_rate: float = 0.1):
        """
        初期化
        Args:
            sample_rate: サンプリング率（0-1）
        """
        self.sample_rate = sample_rate

    def should_sample(self, operation_name: str, tags: Dict[str, str] = None) -> bool:
        """
        サンプリングすべきかを判定
        Args:
            operation_name: 操作名
            tags: タグ情報
        Returns:
            サンプリングフラグ
        """
        # エラーや高遅延操作は常にサンプリング
        if tags and (tags.get("error") == "true" or float(tags.get("duration", 0)) > 1000):
            return True

        # 確率ベースのサンプリング
        return random.random() < self.sample_rate


class DistributedTracingManager:
    """分散トレーシング管理システム"""

    def __init__(self, service_name: str, db_path: str = "distributed_tracing.db"):
        """
        初期化
        Args:
            service_name: サービス名
            db_path: データベースパス
        """
        self.service_name = service_name
        self.db_path = db_path
        self.tracing_engine = TracingEngine(service_name, db_path)
        self.trace_sampler = TraceSampler()
        self.current_context: Optional[TraceContext] = None

        self.is_tracing_active = False

    def initialize_tracing_system(self):
        """トレーシングシステムを初期化"""
        # デフォルトのトレースコールバックを登録
        self._register_default_trace_callbacks()

    def _register_default_trace_callbacks(self):
        """デフォルトのトレースコールバックを登録"""
        def log_trace_completion(trace_context: TraceContext):
            logger.info(f"トレース完了: {trace_context.trace_id}")

        self.tracing_engine.add_trace_callback(log_trace_completion)

    def start_tracing_system(self):
        """トレーシングシステムを開始"""
        if not self.is_tracing_active:
            self.is_tracing_active = True
            logger.info("分散トレーシングシステムを開始しました")

    def stop_tracing_system(self):
        """トレーシングシステムを停止"""
        self.is_tracing_active = False
        logger.info("分散トレーシングシステムを停止しました")

    def start_request_trace(self, operation_name: str, method: str = "", url: str = "",
                          user_agent: str = "", tags: Dict[str, str] = None) -> TraceContext:
        """
        リクエストトレースを開始
        Args:
            operation_name: 操作名
            method: HTTPメソッド
            url: URL
            user_agent: ユーザーエージェント
            tags: タグ情報
        Returns:
            トレースコンテキスト
        """
        # タグを準備
        request_tags = tags or {}
        request_tags.update({
            "http.method": method,
            "http.url": url,
            "user_agent": user_agent,
            "component": "http"
        })

        # サンプリングチェック
        if not self.trace_sampler.should_sample(operation_name, request_tags):
            # サンプリング対象外の場合はダミーコンテキストを返す
            return TraceContext("no_trace", "no_span")

        # トレースを開始
        context = self.tracing_engine.start_trace(operation_name, request_tags)
        self.current_context = context

        return context

    def start_child_span(self, operation_name: str, span_kind: SpanKind = SpanKind.INTERNAL,
                        tags: Dict[str, str] = None) -> TraceContext:
        """
        子スパンを開始
        Args:
            operation_name: 操作名
            span_kind: スパン種別
            tags: タグ情報
        Returns:
            トレースコンテキスト
        """
        if not self.current_context:
            # 現在のコンテキストがない場合は新しいトレースを開始
            return self.start_request_trace(operation_name, tags=tags)

        # 子スパンを開始
        child_tags = tags or {}
        child_tags.update({"component": "internal"})

        return self.tracing_engine.start_span(operation_name, self.current_context, span_kind, child_tags)

    def end_current_span(self, status: TraceStatus = TraceStatus.COMPLETED,
                        logs: List[Dict[str, Any]] = None):
        """
        現在のスパンを終了
        Args:
            status: ステータス
            logs: ログ情報
        """
        if self.current_context:
            self.tracing_engine.end_span(self.current_context, status, logs)

            # ルートスパンの場合はコンテキストをクリア
            trace_details = self.tracing_engine.get_trace_details(self.current_context.trace_id)
            if trace_details and self.current_context.span_id == trace_details["root_span_id"]:
                self.current_context = None

    def inject_trace_context(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        トレースコンテキストをHTTPヘッダーに注入
        Args:
            headers: 元のヘッダー
        Returns:
            トレースコンテキストを含むヘッダー
        """
        if self.current_context:
            trace_headers = self.current_context.to_headers()
            headers.update(trace_headers)

        return headers

    def extract_trace_context(self, headers: Dict[str, str]) -> Optional[TraceContext]:
        """
        HTTPヘッダーからトレースコンテキストを抽出
        Args:
            headers: HTTPヘッダー
        Returns:
            トレースコンテキスト（ない場合はNone）
        """
        return TraceContext.from_headers(headers)

    def set_current_context_from_headers(self, headers: Dict[str, str]):
        """
        HTTPヘッダーから現在のコンテキストを設定
        Args:
            headers: HTTPヘッダー
        """
        context = self.extract_trace_context(headers)
        if context:
            self.current_context = context

    def get_tracing_status(self) -> Dict[str, Any]:
        """トレーシングシステムステータスを取得"""
        return {
            "is_active": self.is_tracing_active,
            "service_name": self.service_name,
            "active_traces": len(self.tracing_engine.active_traces),
            "active_spans": len(self.tracing_engine.active_spans),
            "sample_rate": self.trace_sampler.sample_rate,
            "current_context": self.current_context.trace_id if self.current_context else None
        }

    def get_trace_analytics(self, hours: int = 24) -> Dict[str, Any]:
        """トレース分析情報を取得"""
        cutoff_time = time.time() - (hours * 3600)

        try:
            with sqlite3.connect(self.db_path) as conn:
                # トレース統計
                cursor = conn.execute("""
                    SELECT COUNT(*) as total_traces,
                           AVG(duration) as avg_duration,
                           COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_traces
                    FROM traces
                    WHERE start_time > ?
                """, (cutoff_time,))

                trace_stats = cursor.fetchone()

                # サービス別統計
                service_stats = conn.execute("""
                    SELECT service_name, COUNT(*) as traces, AVG(duration) as avg_duration
                    FROM traces
                    WHERE start_time > ?
                    GROUP BY service_name
                    ORDER BY traces DESC
                """, (cutoff_time,)).fetchall()

                return {
                    "total_traces": trace_stats[0],
                    "avg_duration": trace_stats[1],
                    "error_rate": (trace_stats[2] / trace_stats[0] * 100) if trace_stats[0] > 0 else 0,
                    "service_breakdown": [
                        {"service": stat[0], "traces": stat[1], "avg_duration": stat[2]}
                        for stat in service_stats[:10]
                    ],
                    "period_hours": hours
                }

        except Exception as e:
            logger.error(f"トレース分析取得エラー: {e}")
            return {}


# 使用例
def example_usage():
    manager = DistributedTracingManager("api_gateway")

    # システム初期化
    manager.initialize_tracing_system()

    # システム開始
    manager.start_tracing_system()

    # リクエストトレースを開始
    context = manager.start_request_trace(
        "process_user_request",
        method="POST",
        url="/api/users",
        tags={"user_id": "123", "endpoint": "/api/users"}
    )

    print(f"トレース開始: {context.trace_id}")

    # データベース操作のスパン
    db_context = manager.start_child_span(
        "database_query",
        SpanKind.CLIENT,
        {"db.operation": "SELECT", "db.table": "users"}
    )

    # データベース処理をシミュレーション
    time.sleep(0.1)

    manager.end_current_span(TraceStatus.COMPLETED, [
        {"timestamp": time.time(), "message": "クエリ実行完了"}
    ])

    # 外部API呼び出しのスパン
    api_context = manager.start_child_span(
        "external_api_call",
        SpanKind.CLIENT,
        {"api.endpoint": "https://external-api.com/users"}
    )

    # API呼び出しをシミュレーション
    time.sleep(0.2)

    manager.end_current_span(TraceStatus.COMPLETED)

    # リクエストトレースを終了
    manager.end_current_span(TraceStatus.COMPLETED)

    # トレース詳細を取得
    trace_details = manager.tracing_engine.get_trace_details(context.trace_id)
    if trace_details:
        print(f"トレース詳細: {len(trace_details['spans'])}スパン")

    # トレース分析を取得
    analytics = manager.get_trace_analytics(hours=1)
    print(f"トレース分析: {analytics['total_traces']}トレース")

    # システムステータス
    status = manager.get_tracing_status()
    print(f"トレーシングステータス: {status}")

    manager.stop_tracing_system()


if __name__ == "__main__":
    example_usage()
