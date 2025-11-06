"""
バッチ処理とリアルタイムデータシンクAPI for BLNCS
複数の操作を効率的に処理し、リアルタイムでデータを同期
"""

import asyncio
import json
import time
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class SyncStatus(Enum):
    """同期ステータス"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class BatchJob:
    """バッチジョブ情報"""
    job_id: str
    operations: List[Dict[str, Any]]
    priority: int = 0
    created_at: float = field(default_factory=time.time)
    status: str = "pending"
    results: List[Any] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


@dataclass
class SyncTask:
    """同期タスク情報"""
    task_id: str
    data_type: str
    data: Any
    status: SyncStatus = SyncStatus.PENDING
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    error_message: Optional[str] = None


class BatchProcessor:
    """バッチ処理マネージャー"""

    def __init__(self, max_concurrent_jobs: int = 10):
        """
        初期化
        Args:
            max_concurrent_jobs: 最大同時ジョブ数
        """
        self.jobs: Dict[str, BatchJob] = {}
        self.job_queue: asyncio.Queue = asyncio.Queue()
        self.semaphore = asyncio.Semaphore(max_concurrent_jobs)
        self.is_running = False
        self.worker_task: Optional[asyncio.Task] = None

    async def start(self):
        """バッチプロセッサーを開始"""
        if not self.is_running:
            self.is_running = True
            self.worker_task = asyncio.create_task(self._worker_loop())

    async def stop(self):
        """バッチプロセッサーを停止"""
        self.is_running = False
        if self.worker_task:
            self.worker_task.cancel()
            try:
                await self.worker_task
            except asyncio.CancelledError:
                pass

    async def submit_batch_job(self, operations: List[Dict[str, Any]], priority: int = 0) -> str:
        """
        バッチジョブを送信
        Args:
            operations: 実行する操作のリスト
            priority: 優先度
        Returns:
            ジョブID
        """
        job_id = f"batch_{int(time.time() * 1000000)}"
        job = BatchJob(
            job_id=job_id,
            operations=operations,
            priority=priority
        )
        self.jobs[job_id] = job
        await self.job_queue.put(job)
        return job_id

    async def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """
        ジョブのステータスを取得
        Args:
            job_id: ジョブID
        Returns:
            ジョブ情報（存在しない場合はNone）
        """
        if job_id not in self.jobs:
            return None

        job = self.jobs[job_id]
        return {
            "job_id": job.job_id,
            "status": job.status,
            "created_at": job.created_at,
            "results_count": len(job.results),
            "errors_count": len(job.errors),
            "progress": len(job.results) / len(job.operations) if job.operations else 0
        }

    async def _worker_loop(self):
        """ワーカーループ"""
        while self.is_running:
            try:
                job = await self.job_queue.get()
                async with self.semaphore:
                    await self._execute_job(job)
                self.job_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"バッチジョブ実行エラー: {e}")

    async def _execute_job(self, job: BatchJob):
        """ジョブを実行"""
        job.status = "in_progress"
        logger.info(f"バッチジョブ開始: {job.job_id}")

        for operation in job.operations:
            try:
                # ここで実際の処理を実行（カスタム実装が必要）
                result = await self._process_operation(operation)
                job.results.append(result)
            except Exception as e:
                error_msg = f"操作失敗: {e}"
                job.errors.append(error_msg)
                logger.error(error_msg)

        job.status = "completed" if not job.errors else "failed"
        logger.info(f"バッチジョブ完了: {job.job_id}")

    async def _process_operation(self, operation: Dict[str, Any]) -> Any:
        """
        個別の操作を処理（オーバーライド可能）
        Args:
            operation: 操作データ
        Returns:
            処理結果
        """
        # デフォルト実装では単にデータを返却
        await asyncio.sleep(0.1)  # シミュレーション
        return {"operation": operation, "processed_at": time.time()}


class RealTimeDataSync:
    """リアルタイムデータ同期マネージャー"""

    def __init__(self, sync_interval: float = 1.0):
        """
        初期化
        Args:
            sync_interval: 同期間隔（秒）
        """
        self.sync_tasks: Dict[str, SyncTask] = {}
        self.subscribers: Dict[str, List[Callable]] = {}
        self.sync_interval = sync_interval
        self.is_running = False
        self.sync_task: Optional[asyncio.Task] = None

    async def start(self):
        """同期マネージャーを開始"""
        if not self.is_running:
            self.is_running = True
            self.sync_task = asyncio.create_task(self._sync_loop())

    async def stop(self):
        """同期マネージャーを停止"""
        self.is_running = False
        if self.sync_task:
            self.sync_task.cancel()
            try:
                await self.sync_task
            except asyncio.CancelledError:
                pass

    async def submit_sync_task(self, data_type: str, data: Any) -> str:
        """
        同期タスクを送信
        Args:
            data_type: データタイプ
            data: 同期するデータ
        Returns:
            タスクID
        """
        task_id = f"sync_{int(time.time() * 1000000)}"
        task = SyncTask(
            task_id=task_id,
            data_type=data_type,
            data=data
        )
        self.sync_tasks[task_id] = task
        return task_id

    def subscribe(self, data_type: str, callback: Callable):
        """
        データタイプの変更を購読
        Args:
            data_type: データタイプ
            callback: コールバック関数
        """
        if data_type not in self.subscribers:
            self.subscribers[data_type] = []
        self.subscribers[data_type].append(callback)

    def unsubscribe(self, data_type: str, callback: Callable):
        """
        購読を解除
        Args:
            data_type: データタイプ
            callback: コールバック関数
        """
        if data_type in self.subscribers:
            try:
                self.subscribers[data_type].remove(callback)
            except ValueError:
                pass

    async def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        タスクのステータスを取得
        Args:
            task_id: タスクID
        Returns:
            タスク情報（存在しない場合はNone）
        """
        if task_id not in self.sync_tasks:
            return None

        task = self.sync_tasks[task_id]
        return {
            "task_id": task.task_id,
            "data_type": task.data_type,
            "status": task.status.value,
            "created_at": task.created_at,
            "completed_at": task.completed_at,
            "error_message": task.error_message
        }

    async def _sync_loop(self):
        """同期ループ"""
        while self.is_running:
            try:
                await asyncio.sleep(self.sync_interval)
                await self._process_sync_tasks()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"同期ループエラー: {e}")

    async def _process_sync_tasks(self):
        """同期タスクを処理"""
        for task_id, task in list(self.sync_tasks.items()):
            if task.status == SyncStatus.PENDING:
                await self._execute_sync_task(task)

    async def _execute_sync_task(self, task: SyncTask):
        """同期タスクを実行"""
        task.status = SyncStatus.IN_PROGRESS
        try:
            # ここで実際の同期処理を実行
            await self._sync_data(task.data_type, task.data)
            task.status = SyncStatus.COMPLETED
            task.completed_at = time.time()

            # サブスクライバーに通知
            await self._notify_subscribers(task.data_type, task.data)

        except Exception as e:
            task.status = SyncStatus.FAILED
            task.error_message = str(e)
            logger.error(f"同期タスク失敗: {e}")

    async def _sync_data(self, data_type: str, data: Any):
        """
        データ同期処理（オーバーライド可能）
        Args:
            data_type: データタイプ
            data: 同期データ
        """
        # デフォルト実装ではログ出力のみ
        logger.info(f"データ同期: {data_type} - {data}")

    async def _notify_subscribers(self, data_type: str, data: Any):
        """サブスクライバーに通知"""
        if data_type in self.subscribers:
            for callback in self.subscribers[data_type]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(data_type, data)
                    else:
                        callback(data_type, data)
                except Exception as e:
                    logger.error(f"サブスクライバー通知エラー: {e}")


class BatchAPI:
    """バッチ処理API"""

    def __init__(self):
        self.batch_processor = BatchProcessor()
        self.data_sync = RealTimeDataSync()

    async def initialize(self):
        """APIを初期化"""
        await self.batch_processor.start()
        await self.data_sync.start()

    async def shutdown(self):
        """APIをシャットダウン"""
        await self.batch_processor.stop()
        await self.data_sync.stop()

    async def submit_batch_request(self, operations: List[Dict[str, Any]], priority: int = 0) -> Dict[str, Any]:
        """
        バッチリクエストを送信
        Args:
            operations: 操作リスト
            priority: 優先度
        Returns:
            レスポンスデータ
        """
        job_id = await self.batch_processor.submit_batch_job(operations, priority)
        return {
            "status": "submitted",
            "job_id": job_id,
            "message": "バッチジョブが送信されました"
        }

    async def get_batch_status(self, job_id: str) -> Dict[str, Any]:
        """
        バッチジョブのステータスを取得
        Args:
            job_id: ジョブID
        Returns:
            ステータスデータ
        """
        status = await self.batch_processor.get_job_status(job_id)
        if status:
            return status
        else:
            return {"error": "ジョブが見つかりません"}

    async def submit_sync_request(self, data_type: str, data: Any) -> Dict[str, Any]:
        """
        同期リクエストを送信
        Args:
            data_type: データタイプ
            data: 同期データ
        Returns:
            レスポンスデータ
        """
        task_id = await self.data_sync.submit_sync_task(data_type, data)
        return {
            "status": "submitted",
            "task_id": task_id,
            "message": "同期タスクが送信されました"
        }

    async def get_sync_status(self, task_id: str) -> Dict[str, Any]:
        """
        同期タスクのステータスを取得
        Args:
            task_id: タスクID
        Returns:
            ステータスデータ
        """
        status = await self.data_sync.get_task_status(task_id)
        if status:
            return status
        else:
            return {"error": "タスクが見つかりません"}


# 使用例
async def example_api_usage():
    api = BatchAPI()
    await api.initialize()

    # バッチリクエストの送信
    operations = [
        {"type": "process_data", "data": {"id": 1}},
        {"type": "process_data", "data": {"id": 2}}
    ]
    response = await api.submit_batch_request(operations, priority=1)
    print(f"バッチ送信: {response}")

    # 同期リクエストの送信
    sync_response = await api.submit_sync_request("user_data", {"name": "テストユーザー"})
    print(f"同期送信: {sync_response}")

    # ステータス確認
    status = await api.get_batch_status(response["job_id"])
    print(f"バッチステータス: {status}")

    await api.shutdown()


if __name__ == "__main__":
    asyncio.run(example_api_usage())
