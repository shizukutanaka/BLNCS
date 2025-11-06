"""
オフライン同期システム for BLNCSモバイル
オフラインモードとデータシンクロナイザー機能を提供
"""

import asyncio
import json
import sqlite3
import time
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import logging
import threading

logger = logging.getLogger(__name__)


class SyncStatus(Enum):
    """同期ステータス"""
    PENDING = "pending"
    SYNCING = "syncing"
    COMPLETED = "completed"
    FAILED = "failed"
    CONFLICT = "conflict"


class NetworkStatus(Enum):
    """ネットワークステータス"""
    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


@dataclass
class OfflineData:
    """オフラインデータ情報"""
    data_id: str
    data_type: str
    data: Any
    operation: str  # 'create', 'update', 'delete'
    timestamp: float = field(default_factory=time.time)
    retry_count: int = 0
    max_retries: int = 3


@dataclass
class SyncResult:
    """同期結果情報"""
    data_id: str
    status: SyncStatus
    timestamp: float = field(default_factory=time.time)
    error_message: Optional[str] = None
    server_data: Optional[Any] = None


class OfflineStorage:
    """オフラインストレージマネージャー"""

    def __init__(self, db_path: str = "offline_data.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """データベースを初期化"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS offline_data (
                    data_id TEXT PRIMARY KEY,
                    data_type TEXT NOT NULL,
                    data TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    retry_count INTEGER DEFAULT 0,
                    max_retries INTEGER DEFAULT 3
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sync_results (
                    data_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    error_message TEXT,
                    server_data TEXT
                )
            """)
            conn.commit()

    def save_offline_data(self, data: OfflineData):
        """
        オフラインデータを保存
        Args:
            data: オフラインデータ
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO offline_data
                (data_id, data_type, data, operation, timestamp, retry_count, max_retries)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                data.data_id, data.data_type, json.dumps(data.data),
                data.operation, data.timestamp, data.retry_count, data.max_retries
            ))
            conn.commit()

    def get_pending_data(self) -> List[OfflineData]:
        """
        保留中のデータを取得
        Returns:
            オフラインデータリスト
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT data_id, data_type, data, operation, timestamp, retry_count, max_retries
                FROM offline_data
                ORDER BY timestamp ASC
            """)
            return [
                OfflineData(
                    data_id=row[0],
                    data_type=row[1],
                    data=json.loads(row[2]),
                    operation=row[3],
                    timestamp=row[4],
                    retry_count=row[5],
                    max_retries=row[6]
                )
                for row in cursor.fetchall()
            ]

    def remove_offline_data(self, data_id: str):
        """
        オフラインデータを削除
        Args:
            data_id: データID
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM offline_data WHERE data_id = ?", (data_id,))
            conn.commit()

    def update_retry_count(self, data_id: str, retry_count: int):
        """
        リトライ回数を更新
        Args:
            data_id: データID
            retry_count: リトライ回数
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE offline_data SET retry_count = ? WHERE data_id = ?
            """, (retry_count, data_id))
            conn.commit()

    def save_sync_result(self, result: SyncResult):
        """
        同期結果を保存
        Args:
            result: 同期結果
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO sync_results
                (data_id, status, timestamp, error_message, server_data)
                VALUES (?, ?, ?, ?, ?)
            """, (
                result.data_id, result.status.value, result.timestamp,
                result.error_message, json.dumps(result.server_data) if result.server_data else None
            ))
            conn.commit()

    def get_sync_history(self, data_id: str) -> List[SyncResult]:
        """
        同期履歴を取得
        Args:
            data_id: データID
        Returns:
            同期結果リスト
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT data_id, status, timestamp, error_message, server_data
                FROM sync_results WHERE data_id = ? ORDER BY timestamp DESC
            """, (data_id,))
            return [
                SyncResult(
                    data_id=row[0],
                    status=SyncStatus(row[1]),
                    timestamp=row[2],
                    error_message=row[3],
                    server_data=json.loads(row[4]) if row[4] else None
                )
                for row in cursor.fetchall()
            ]


class NetworkMonitor:
    """ネットワークモニター"""

    def __init__(self, check_interval: float = 5.0):
        """
        初期化
        Args:
            check_interval: チェック間隔（秒）
        """
        self.check_interval = check_interval
        self.current_status = NetworkStatus.UNKNOWN
        self.status_callbacks: List[Callable] = []
        self.is_monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None

    def start_monitoring(self):
        """ネットワーク監視を開始"""
        if not self.is_monitoring:
            self.is_monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()

    def stop_monitoring(self):
        """ネットワーク監視を停止"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()

    def add_status_callback(self, callback: Callable):
        """
        ステータス変更コールバックを追加
        Args:
            callback: コールバック関数
        """
        self.status_callbacks.append(callback)

    def _monitor_loop(self):
        """監視ループ"""
        while self.is_monitoring:
            try:
                new_status = self._check_network_status()
                if new_status != self.current_status:
                    self.current_status = new_status
                    for callback in self.status_callbacks:
                        try:
                            callback(new_status)
                        except Exception as e:
                            logger.error(f"ネットワークステータスコールバックエラー: {e}")
                time.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"ネットワーク監視エラー: {e}")

    def _check_network_status(self) -> NetworkStatus:
        """
        ネットワークステータスをチェック（簡易実装）
        Returns:
            ネットワークステータス
        """
        try:
            # 実際の実装では適切なネットワークチェックを行う
            import socket
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            return NetworkStatus.ONLINE
        except OSError:
            return NetworkStatus.OFFLINE


class DataSynchronizer:
    """データシンクロナイザー"""

    def __init__(self, storage: OfflineStorage, network_monitor: NetworkMonitor):
        """
        初期化
        Args:
            storage: オフラインストレージ
            network_monitor: ネットワークモニター
        """
        self.storage = storage
        self.network_monitor = network_monitor
        self.sync_callbacks: List[Callable] = []
        self.is_syncing = False
        self.sync_task: Optional[asyncio.Task] = None

    async def start_sync(self):
        """同期を開始"""
        if not self.is_syncing:
            self.is_syncing = True
            self.sync_task = asyncio.create_task(self._sync_loop())

    async def stop_sync(self):
        """同期を停止"""
        self.is_syncing = False
        if self.sync_task:
            self.sync_task.cancel()
            try:
                await self.sync_task
            except asyncio.CancelledError:
                pass

    def add_sync_callback(self, callback: Callable):
        """
        同期コールバックを追加
        Args:
            callback: コールバック関数
        """
        self.sync_callbacks.append(callback)

    async def _sync_loop(self):
        """同期ループ"""
        while self.is_syncing:
            if self.network_monitor.current_status == NetworkStatus.ONLINE:
                await self._perform_sync()
            await asyncio.sleep(10)  # 10秒ごとにチェック

    async def _perform_sync(self):
        """同期を実行"""
        pending_data = self.storage.get_pending_data()
        for offline_data in pending_data:
            try:
                result = await self._sync_single_item(offline_data)
                self.storage.save_sync_result(result)
                if result.status in [SyncStatus.COMPLETED, SyncStatus.FAILED]:
                    self.storage.remove_offline_data(offline_data.data_id)

                # コールバック通知
                for callback in self.sync_callbacks:
                    try:
                        await callback(result)
                    except Exception as e:
                        logger.error(f"同期コールバックエラー: {e}")

            except Exception as e:
                logger.error(f"同期エラー: {e}")
                offline_data.retry_count += 1
                if offline_data.retry_count >= offline_data.max_retries:
                    result = SyncResult(
                        data_id=offline_data.data_id,
                        status=SyncStatus.FAILED,
                        error_message=str(e)
                    )
                    self.storage.save_sync_result(result)
                    self.storage.remove_offline_data(offline_data.data_id)

    async def _sync_single_item(self, offline_data: OfflineData) -> SyncResult:
        """
        単一アイテムを同期（オーバーライド可能）
        Args:
            offline_data: オフラインデータ
        Returns:
            同期結果
        """
        # 実際の実装ではサーバーとの通信を行う
        await asyncio.sleep(0.5)  # シミュレーション

        return SyncResult(
            data_id=offline_data.data_id,
            status=SyncStatus.COMPLETED
        )


class OfflineModeManager:
    """オフラインモードマネージャー"""

    def __init__(self, db_path: str = "offline_data.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.storage = OfflineStorage(db_path)
        self.network_monitor = NetworkMonitor()
        self.synchronizer = DataSynchronizer(self.storage, self.network_monitor)
        self.is_initialized = False

    async def initialize(self):
        """マネージャーを初期化"""
        if not self.is_initialized:
            self.network_monitor.start_monitoring()
            await self.synchronizer.start_sync()
            self.is_initialized = True

    async def shutdown(self):
        """マネージャーをシャットダウン"""
        await self.synchronizer.stop_sync()
        self.network_monitor.stop_monitoring()

    def save_data_offline(self, data_type: str, data: Any, operation: str = "create"):
        """
        オフラインでデータを保存
        Args:
            data_type: データタイプ
            data: データ
            operation: 操作タイプ
        """
        data_id = f"{data_type}_{int(time.time() * 1000000)}"
        offline_data = OfflineData(
            data_id=data_id,
            data_type=data_type,
            data=data,
            operation=operation
        )
        self.storage.save_offline_data(offline_data)

    def get_network_status(self) -> NetworkStatus:
        """
        ネットワークステータスを取得
        Returns:
            ネットワークステータス
        """
        return self.network_monitor.current_status

    def add_network_callback(self, callback: Callable):
        """
        ネットワークステータスコールバックを追加
        Args:
            callback: コールバック関数
        """
        self.network_monitor.add_status_callback(callback)

    def add_sync_callback(self, callback: Callable):
        """
        同期コールバックを追加
        Args:
            callback: コールバック関数
        """
        self.synchronizer.add_sync_callback(callback)

    def get_pending_count(self) -> int:
        """
        保留中のデータ数を取得
        Returns:
            保留データ数
        """
        return len(self.storage.get_pending_data())

    def get_sync_history(self, data_id: str) -> List[SyncResult]:
        """
        同期履歴を取得
        Args:
            data_id: データID
        Returns:
            同期結果リスト
        """
        return self.storage.get_sync_history(data_id)


# 使用例
async def example_usage():
    manager = OfflineModeManager()

    # ネットワーク監視開始
    manager.network_monitor.start_monitoring()

    # オフラインデータ保存
    manager.save_data_offline("user", {"name": "テストユーザー"}, "create")

    print(f"ネットワークステータス: {manager.get_network_status()}")
    print(f"保留データ数: {manager.get_pending_count()}")

    await manager.shutdown()


if __name__ == "__main__":
    asyncio.run(example_usage())
