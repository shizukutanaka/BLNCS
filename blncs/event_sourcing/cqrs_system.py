"""
イベントソーシングシステム for BLNCS
イベントストアとCQRSパターン機能を提供
"""

import time
import json
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Callable, Generator
from dataclasses import dataclass, field
from enum import Enum
import logging
import asyncio
import queue
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class EventType(Enum):
    """イベントタイプ"""
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    ORDER_PLACED = "order_placed"
    ORDER_CANCELLED = "order_cancelled"
    PAYMENT_PROCESSED = "payment_processed"
    INVENTORY_UPDATED = "inventory_updated"
    PRODUCT_CREATED = "product_created"
    SYSTEM_CONFIG_CHANGED = "system_config_changed"


class AggregateType(Enum):
    """集約タイプ"""
    USER = "user"
    ORDER = "order"
    PRODUCT = "product"
    INVENTORY = "inventory"
    PAYMENT = "payment"


@dataclass
class DomainEvent:
    """ドメインイベント情報"""
    event_id: str
    event_type: EventType
    aggregate_id: str
    aggregate_type: AggregateType
    event_data: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    version: int = 1
    metadata: Dict[str, Any] = field(default_factory=dict)
    correlation_id: Optional[str] = None
    causation_id: Optional[str] = None


@dataclass
class EventStream:
    """イベントストリーム情報"""
    stream_id: str
    aggregate_id: str
    aggregate_type: AggregateType
    events: List[DomainEvent] = field(default_factory=list)
    current_version: int = 0
    created_at: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)


@dataclass
class ReadModel:
    """読み取りモデル情報"""
    model_id: str
    model_type: str
    aggregate_id: str
    data: Dict[str, Any] = field(default_factory=dict)
    last_updated: float = field(default_factory=time.time)
    version: int = 0


class EventStore:
    """イベントストア"""

    def __init__(self, db_path: str = "event_store.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self._init_db()
        self.event_streams: Dict[str, EventStream] = {}
        self.event_handlers: Dict[EventType, List[Callable]] = defaultdict(list)

    def _init_db(self):
        """データベースを初期化"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    aggregate_id TEXT NOT NULL,
                    aggregate_type TEXT NOT NULL,
                    event_data TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    version INTEGER NOT NULL,
                    metadata TEXT,
                    correlation_id TEXT,
                    causation_id TEXT
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS event_streams (
                    stream_id TEXT PRIMARY KEY,
                    aggregate_id TEXT NOT NULL,
                    aggregate_type TEXT NOT NULL,
                    current_version INTEGER NOT NULL,
                    created_at REAL,
                    last_updated REAL
                )
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_aggregate
                ON events(aggregate_id, aggregate_type)
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_timestamp
                ON events(timestamp)
            """)

            conn.commit()

    def append_event(self, event: DomainEvent) -> bool:
        """
        イベントを追加
        Args:
            event: ドメインイベント
        Returns:
            追加成功フラグ
        """
        try:
            # イベントをデータベースに保存
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO events
                    (event_id, event_type, aggregate_id, aggregate_type, event_data, timestamp,
                     version, metadata, correlation_id, causation_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.event_id, event.event_type.value, event.aggregate_id,
                    event.aggregate_type.value, json.dumps(event.event_data), event.timestamp,
                    event.version, json.dumps(event.metadata), event.correlation_id, event.causation_id
                ))
                conn.commit()

            # イベントストリームを更新または作成
            stream_id = f"{event.aggregate_type.value}_{event.aggregate_id}"

            if stream_id not in self.event_streams:
                self.event_streams[stream_id] = EventStream(
                    stream_id=stream_id,
                    aggregate_id=event.aggregate_id,
                    aggregate_type=event.aggregate_type
                )

            stream = self.event_streams[stream_id]
            stream.events.append(event)
            stream.current_version = event.version
            stream.last_updated = event.timestamp

            # イベントストリーム情報を更新
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO event_streams
                    (stream_id, aggregate_id, aggregate_type, current_version, created_at, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    stream_id, event.aggregate_id, event.aggregate_type.value,
                    event.version, stream.created_at, stream.last_updated
                ))
                conn.commit()

            # イベントハンドラを実行
            for handler in self.event_handlers.get(event.event_type, []):
                try:
                    handler(event)
                except Exception as e:
                    logger.error(f"イベントハンドラエラー: {e}")

            logger.info(f"イベント追加: {event.event_type.value} - {event.aggregate_id}")
            return True

        except Exception as e:
            logger.error(f"イベント追加エラー: {e}")
            return False

    def get_events_for_aggregate(self, aggregate_id: str, aggregate_type: AggregateType,
                               from_version: int = 0) -> List[DomainEvent]:
        """
        集約のイベントを取得
        Args:
            aggregate_id: 集約ID
            aggregate_type: 集約タイプ
            from_version: 開始バージョン
        Returns:
            イベントリスト
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT event_id, event_type, aggregate_id, aggregate_type, event_data,
                           timestamp, version, metadata, correlation_id, causation_id
                    FROM events
                    WHERE aggregate_id = ? AND aggregate_type = ? AND version > ?
                    ORDER BY version ASC
                """, (aggregate_id, aggregate_type.value, from_version))

                events = []
                for row in cursor.fetchall():
                    event = DomainEvent(
                        event_id=row[0],
                        event_type=EventType(row[1]),
                        aggregate_id=row[2],
                        aggregate_type=AggregateType(row[3]),
                        event_data=json.loads(row[4]),
                        timestamp=row[5],
                        version=row[6],
                        metadata=json.loads(row[7]) if row[7] else {},
                        correlation_id=row[8],
                        causation_id=row[9]
                    )
                    events.append(event)

                return events

        except Exception as e:
            logger.error(f"イベント取得エラー: {e}")
            return []

    def get_event_stream(self, aggregate_id: str, aggregate_type: AggregateType) -> Optional[EventStream]:
        """
        イベントストリームを取得
        Args:
            aggregate_id: 集約ID
            aggregate_type: 集約タイプ
        Returns:
            イベントストリーム（見つからない場合はNone）
        """
        stream_id = f"{aggregate_type.value}_{aggregate_id}"

        if stream_id in self.event_streams:
            return self.event_streams[stream_id]

        # データベースから読み込み
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT stream_id, aggregate_id, aggregate_type, current_version, created_at, last_updated
                    FROM event_streams
                    WHERE aggregate_id = ? AND aggregate_type = ?
                """, (aggregate_id, aggregate_type.value))

                row = cursor.fetchone()
                if row:
                    stream = EventStream(
                        stream_id=row[0],
                        aggregate_id=row[1],
                        aggregate_type=AggregateType(row[2]),
                        current_version=row[3],
                        created_at=row[4],
                        last_updated=row[5]
                    )

                    # イベントを読み込み
                    stream.events = self.get_events_for_aggregate(aggregate_id, aggregate_type)

                    self.event_streams[stream_id] = stream
                    return stream

        except Exception as e:
            logger.error(f"イベントストリーム取得エラー: {e}")

        return None

    def register_event_handler(self, event_type: EventType, handler: Callable):
        """
        イベントハンドラを登録
        Args:
            event_type: イベントタイプ
            handler: ハンドラ関数
        """
        self.event_handlers[event_type].append(handler)

    def replay_events_for_aggregate(self, aggregate_id: str, aggregate_type: AggregateType,
                                  handler: Callable) -> int:
        """
        集約のイベントをリプレイ
        Args:
            aggregate_id: 集約ID
            aggregate_type: 集約タイプ
            handler: リプレイハンドラ関数
        Returns:
            リプレイしたイベント数
        """
        events = self.get_events_for_aggregate(aggregate_id, aggregate_type)

        for event in events:
            try:
                handler(event)
            except Exception as e:
                logger.error(f"イベントリプレイエラー: {e}")

        return len(events)


class CQRSManager:
    """CQRS管理システム"""

    def __init__(self, event_store: EventStore, db_path: str = "cqrs_read_models.db"):
        """
        初期化
        Args:
            event_store: イベントストア
            db_path: データベースパス
        """
        self.event_store = event_store
        self.db_path = db_path
        self._init_db()
        self.read_models: Dict[str, ReadModel] = {}
        self.projection_handlers: Dict[EventType, Callable] = {}

    def _init_db(self):
        """データベースを初期化"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS read_models (
                    model_id TEXT PRIMARY KEY,
                    model_type TEXT NOT NULL,
                    aggregate_id TEXT NOT NULL,
                    data TEXT,
                    last_updated REAL,
                    version INTEGER
                )
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_read_models_aggregate
                ON read_models(aggregate_id, model_type)
            """)

            conn.commit()

    def register_projection_handler(self, event_type: EventType, handler: Callable):
        """
        投影ハンドラを登録
        Args:
            event_type: イベントタイプ
            handler: ハンドラ関数
        """
        self.projection_handlers[event_type] = handler

    def create_read_model(self, model_type: str, aggregate_id: str, initial_data: Dict[str, Any] = None) -> str:
        """
        読み取りモデルを作成
        Args:
            model_type: モデルタイプ
            aggregate_id: 集約ID
            initial_data: 初期データ
        Returns:
            モデルID
        """
        model_id = f"{model_type}_{aggregate_id}_{int(time.time() * 1000000)}"

        read_model = ReadModel(
            model_id=model_id,
            model_type=model_type,
            aggregate_id=aggregate_id,
            data=initial_data or {}
        )

        self.read_models[model_id] = read_model

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO read_models
                    (model_id, model_type, aggregate_id, data, last_updated, version)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    model_id, model_type, aggregate_id, json.dumps(read_model.data),
                    read_model.last_updated, read_model.version
                ))
                conn.commit()

        except Exception as e:
            logger.error(f"読み取りモデル作成エラー: {e}")

        return model_id

    def update_read_model(self, model_id: str, new_data: Dict[str, Any]):
        """
        読み取りモデルを更新
        Args:
            model_id: モデルID
            new_data: 新しいデータ
        """
        if model_id not in self.read_models:
            return

        read_model = self.read_models[model_id]
        read_model.data.update(new_data)
        read_model.last_updated = time.time()
        read_model.version += 1

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    UPDATE read_models
                    SET data = ?, last_updated = ?, version = ?
                    WHERE model_id = ?
                """, (json.dumps(read_model.data), read_model.last_updated, read_model.version, model_id))
                conn.commit()

        except Exception as e:
            logger.error(f"読み取りモデル更新エラー: {e}")

    def get_read_model(self, model_type: str, aggregate_id: str) -> Optional[Dict[str, Any]]:
        """
        読み取りモデルを取得
        Args:
            model_type: モデルタイプ
            aggregate_id: 集約ID
        Returns:
            モデルデータ（見つからない場合はNone）
        """
        # メモリから検索
        for read_model in self.read_models.values():
            if read_model.model_type == model_type and read_model.aggregate_id == aggregate_id:
                return read_model.data

        # データベースから検索
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT data FROM read_models
                    WHERE model_type = ? AND aggregate_id = ?
                """, (model_type, aggregate_id))

                row = cursor.fetchone()
                if row:
                    return json.loads(row[0])

        except Exception as e:
            logger.error(f"読み取りモデル取得エラー: {e}")

        return None

    def project_events_to_read_model(self, aggregate_id: str, aggregate_type: AggregateType, model_type: str):
        """
        イベントを読み取りモデルに投影
        Args:
            aggregate_id: 集約ID
            aggregate_type: 集約タイプ
            model_type: モデルタイプ
        """
        # 既存のモデルを取得または作成
        model_id = f"{model_type}_{aggregate_id}"
        if model_id not in self.read_models:
            self.create_read_model(model_type, aggregate_id)

        # イベントをリプレイしてモデルを構築
        def replay_handler(event: DomainEvent):
            if event.aggregate_type == aggregate_type:
                handler = self.projection_handlers.get(event.event_type)
                if handler:
                    try:
                        handler(event, self.read_models[model_id])
                    except Exception as e:
                        logger.error(f"投影ハンドラエラー: {e}")

        self.event_store.replay_events_for_aggregate(aggregate_id, aggregate_type, replay_handler)


class EventSourcingManager:
    """イベントソーシング管理システム"""

    def __init__(self, db_path: str = "event_sourcing.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self.event_store = EventStore(db_path)
        self.cqrs_manager = CQRSManager(self.event_store, db_path)

        self.is_event_sourcing_active = False

    def initialize_event_sourcing_system(self):
        """イベントソーシングシステムを初期化"""
        # デフォルトの投影ハンドラを登録
        self._register_default_projection_handlers()

        # デフォルトの集約を作成
        self._create_default_aggregates()

    def _register_default_projection_handlers(self):
        """デフォルトの投影ハンドラを登録"""
        # ユーザー集約の投影ハンドラ
        def user_created_handler(event: DomainEvent, read_model: ReadModel):
            read_model.data.update({
                "user_id": event.aggregate_id,
                "created_at": event.timestamp,
                "status": "active"
            })
            read_model.data.update(event.event_data)

        def user_updated_handler(event: DomainEvent, read_model: ReadModel):
            read_model.data.update(event.event_data)

        def user_deleted_handler(event: DomainEvent, read_model: ReadModel):
            read_model.data["status"] = "deleted"
            read_model.data["deleted_at"] = event.timestamp

        # CQRSマネージャーにハンドラを登録
        self.cqrs_manager.register_projection_handler(EventType.USER_CREATED, user_created_handler)
        self.cqrs_manager.register_projection_handler(EventType.USER_UPDATED, user_updated_handler)
        self.cqrs_manager.register_projection_handler(EventType.USER_DELETED, user_deleted_handler)

        # イベントストアのイベントハンドラとして登録
        self.event_store.register_event_handler(EventType.USER_CREATED, lambda e: self._handle_event_for_cqrs(e))
        self.event_store.register_event_handler(EventType.USER_UPDATED, lambda e: self._handle_event_for_cqrs(e))
        self.event_store.register_event_handler(EventType.USER_DELETED, lambda e: self._handle_event_for_cqrs(e))

    def _handle_event_for_cqrs(self, event: DomainEvent):
        """CQRSのためのイベント処理"""
        # 対応する読み取りモデルを更新
        self.cqrs_manager.project_events_to_read_model(
            event.aggregate_id, event.aggregate_type, "user_summary"
        )

    def _create_default_aggregates(self):
        """デフォルトの集約を作成"""
        # サンプルユーザーのイベントシーケンスを作成
        user_events = [
            DomainEvent(
                event_id=f"event_{i}",
                event_type=EventType.USER_CREATED,
                aggregate_id="user_123",
                aggregate_type=AggregateType.USER,
                event_data={
                    "username": "testuser",
                    "email": "test@example.com",
                    "role": "user"
                },
                version=i+1
            )
            for i in range(3)  # 3つのイベントを作成
        ]

        for event in user_events:
            self.event_store.append_event(event)

    def start_event_sourcing_system(self):
        """イベントソーシングシステムを開始"""
        if not self.is_event_sourcing_active:
            self.is_event_sourcing_active = True
            logger.info("イベントソーシングシステムを開始しました")

    def stop_event_sourcing_system(self):
        """イベントソーシングシステムを停止"""
        self.is_event_sourcing_active = False
        logger.info("イベントソーシングシステムを停止しました")

    def emit_domain_event(self, event_type: EventType, aggregate_id: str,
                         aggregate_type: AggregateType, event_data: Dict[str, Any],
                         correlation_id: Optional[str] = None) -> str:
        """
        ドメインイベントを発行
        Args:
            event_type: イベントタイプ
            aggregate_id: 集約ID
            aggregate_type: 集約タイプ
            event_data: イベントデータ
            correlation_id: 相関ID
        Returns:
            イベントID
        """
        # 現在のバージョンを取得
        events = self.event_store.get_events_for_aggregate(aggregate_id, aggregate_type)
        current_version = len(events) + 1

        event = DomainEvent(
            event_id=f"event_{int(time.time() * 1000000)}",
            event_type=event_type,
            aggregate_id=aggregate_id,
            aggregate_type=aggregate_type,
            event_data=event_data,
            version=current_version,
            correlation_id=correlation_id
        )

        success = self.event_store.append_event(event)
        return event.event_id if success else None

    def get_aggregate_state(self, aggregate_id: str, aggregate_type: AggregateType) -> Dict[str, Any]:
        """
        集約の状態を取得
        Args:
            aggregate_id: 集約ID
            aggregate_type: 集約タイプ
        Returns:
            集約状態
        """
        # イベントをリプレイして状態を構築
        events = self.event_store.get_events_for_aggregate(aggregate_id, aggregate_type)

        state = {}
        for event in events:
            # イベントデータで状態を更新（簡易版）
            state.update(event.event_data)

        return state

    def get_read_model(self, model_type: str, aggregate_id: str) -> Optional[Dict[str, Any]]:
        """
        読み取りモデルを取得
        Args:
            model_type: モデルタイプ
            aggregate_id: 集約ID
        Returns:
            モデルデータ
        """
        return self.cqrs_manager.get_read_model(model_type, aggregate_id)

    def get_event_sourcing_status(self) -> Dict[str, Any]:
        """イベントソーシングシステムステータスを取得"""
        return {
            "is_active": self.is_event_sourcing_active,
            "total_events": len([e for stream in self.event_store.event_streams.values() for e in stream.events]),
            "total_streams": len(self.event_store.event_streams),
            "total_read_models": len(self.cqrs_manager.read_models),
            "event_handlers": len(self.event_store.event_handlers)
        }


# 使用例
def example_usage():
    manager = EventSourcingManager()

    # システム初期化
    manager.initialize_event_sourcing_system()

    # システム開始
    manager.start_event_sourcing_system()

    # ドメインイベントを発行
    event_id = manager.emit_domain_event(
        EventType.USER_CREATED,
        "user_456",
        AggregateType.USER,
        {
            "username": "newuser",
            "email": "newuser@example.com",
            "role": "premium"
        }
    )

    print(f"イベント発行: {event_id}")

    # 集約状態を取得
    user_state = manager.get_aggregate_state("user_456", AggregateType.USER)
    print(f"ユーザー状態: {user_state}")

    # 読み取りモデルを取得（自動的に構築される）
    read_model = manager.get_read_model("user_summary", "user_456")
    print(f"読み取りモデル: {read_model}")

    # イベントソーシングステータス
    status = manager.get_event_sourcing_status()
    print(f"イベントソーシングステータス: {status}")

    manager.stop_event_sourcing_system()


if __name__ == "__main__":
    example_usage()
