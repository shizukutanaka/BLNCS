"""
ワークフロー自動化システム for BLNCS
ビジネスプロセス自動化とタスク管理機能を提供
"""

import time
import json
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import logging
import uuid
from collections import defaultdict, deque
import asyncio

logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    """タスクステータス"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


class TaskPriority(Enum):
    """タスク優先度"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class WorkflowStatus(Enum):
    """ワークフローステータス"""
    DRAFT = "draft"
    ACTIVE = "active"
    INACTIVE = "inactive"
    ARCHIVED = "archived"


@dataclass
class WorkflowTask:
    """ワークフロータスク情報"""
    task_id: str
    name: str
    description: str
    task_type: str  # 'manual', 'automated', 'approval'
    status: TaskStatus = TaskStatus.PENDING
    priority: TaskPriority = TaskPriority.NORMAL
    assignee: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)  # 依存タスクIDリスト
    estimated_duration: Optional[int] = None  # 推定実行時間（秒）
    actual_duration: Optional[float] = None
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowDefinition:
    """ワークフロー定義情報"""
    workflow_id: str
    name: str
    description: str
    tasks: List[WorkflowTask] = field(default_factory=list)
    triggers: List[Dict[str, Any]] = field(default_factory=list)  # トリガー条件
    status: WorkflowStatus = WorkflowStatus.DRAFT
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    version: int = 1


@dataclass
class WorkflowExecution:
    """ワークフロー実行情報"""
    execution_id: str
    workflow_id: str
    status: str = "running"
    current_task: Optional[str] = None
    started_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    results: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None


class TaskScheduler:
    """タスクスケジューラー"""

    def __init__(self, max_concurrent_tasks: int = 10):
        """
        初期化
        Args:
            max_concurrent_tasks: 最大同時実行タスク数
        """
        self.max_concurrent_tasks = max_concurrent_tasks
        self.running_tasks: Dict[str, WorkflowTask] = {}
        self.task_queue: deque = deque()
        self.completed_tasks: Dict[str, Dict[str, Any]] = {}
        self.scheduler_lock = threading.Lock()

    def schedule_task(self, task: WorkflowTask) -> bool:
        """
        タスクをスケジュール
        Args:
            task: スケジュールするタスク
        Returns:
            スケジュール成功フラグ
        """
        with self.scheduler_lock:
            if len(self.running_tasks) >= self.max_concurrent_tasks:
                self.task_queue.append(task)
                return False  # キューに追加

            # タスクを実行開始
            task.status = TaskStatus.RUNNING
            task.started_at = time.time()
            self.running_tasks[task.task_id] = task

            # 非同期でタスクを実行
            asyncio.create_task(self._execute_task(task))

            return True

    async def _execute_task(self, task: WorkflowTask):
        """タスクを実行"""
        try:
            logger.info(f"タスク実行開始: {task.name}")

            # タスクタイプに応じた実行処理
            if task.task_type == "automated":
                await self._execute_automated_task(task)
            elif task.task_type == "manual":
                await self._execute_manual_task(task)
            elif task.task_type == "approval":
                await self._execute_approval_task(task)

            # タスク完了処理
            task.status = TaskStatus.COMPLETED
            task.completed_at = time.time()
            task.actual_duration = task.completed_at - (task.started_at or task.created_at)

            logger.info(f"タスク実行完了: {task.name}")

        except Exception as e:
            logger.error(f"タスク実行エラー: {task.name} - {e}")
            task.status = TaskStatus.FAILED
            task.completed_at = time.time()
        finally:
            # 実行中のタスクから削除
            with self.scheduler_lock:
                if task.task_id in self.running_tasks:
                    del self.running_tasks[task.task_id]

                # 完了情報を記録
                self.completed_tasks[task.task_id] = {
                    "task": task,
                    "completed_at": task.completed_at
                }

                # キューから次のタスクを実行
                if self.task_queue:
                    next_task = self.task_queue.popleft()
                    asyncio.create_task(self._execute_task(next_task))

    async def _execute_automated_task(self, task: WorkflowTask):
        """自動タスクを実行"""
        # 実際の実装ではタスクの内容に応じた処理を実行
        await asyncio.sleep(2.0)  # 実行時間をシミュレーション

        # タスク結果をメタデータに記録
        task.metadata["result"] = "success"
        task.metadata["execution_time"] = 2.0

    async def _execute_manual_task(self, task: WorkflowTask):
        """手動タスクを実行（通知のみ）"""
        # 実際の実装では担当者に通知を送信
        logger.info(f"手動タスク通知: {task.name} -> {task.assignee}")

        # 担当者がタスクを完了するまで待機（簡易版）
        await asyncio.sleep(1.0)

    async def _execute_approval_task(self, task: WorkflowTask):
        """承認タスクを実行"""
        # 実際の実装では承認フローを実行
        logger.info(f"承認タスク開始: {task.name}")

        # 承認プロセスをシミュレーション
        await asyncio.sleep(3.0)

    def get_scheduler_status(self) -> Dict[str, Any]:
        """スケジューラーステータスを取得"""
        with self.scheduler_lock:
            return {
                "running_tasks": len(self.running_tasks),
                "queued_tasks": len(self.task_queue),
                "completed_tasks": len(self.completed_tasks),
                "max_concurrent": self.max_concurrent_tasks
            }


class WorkflowEngine:
    """ワークフローエンジン"""

    def __init__(self, db_path: str = "workflow.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self._init_db()
        self.workflows: Dict[str, WorkflowDefinition] = {}
        self.executions: Dict[str, WorkflowExecution] = {}
        self.scheduler = TaskScheduler()
        self.execution_callbacks: List[Callable] = []

        self.is_engine_active = False
        self.engine_thread: Optional[threading.Thread] = None

    def _init_db(self):
        """データベースを初期化"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS workflows (
                    workflow_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    tasks TEXT,
                    triggers TEXT,
                    status TEXT,
                    created_at REAL,
                    updated_at REAL,
                    version INTEGER
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS workflow_executions (
                    execution_id TEXT PRIMARY KEY,
                    workflow_id TEXT NOT NULL,
                    status TEXT,
                    current_task TEXT,
                    started_at REAL,
                    completed_at REAL,
                    results TEXT,
                    error_message TEXT,
                    FOREIGN KEY (workflow_id) REFERENCES workflows (workflow_id)
                )
            """)

            conn.commit()

    def create_workflow(self, workflow: WorkflowDefinition) -> str:
        """
        ワークフローを作成
        Args:
            workflow: ワークフロー定義
        Returns:
            ワークフローID
        """
        self.workflows[workflow.workflow_id] = workflow

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO workflows
                    (workflow_id, name, description, tasks, triggers, status, created_at, updated_at, version)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    workflow.workflow_id, workflow.name, workflow.description,
                    json.dumps([task.__dict__ for task in workflow.tasks]),
                    json.dumps(workflow.triggers), workflow.status.value,
                    workflow.created_at, workflow.updated_at, workflow.version
                ))
                conn.commit()

        except Exception as e:
            logger.error(f"ワークフロー作成エラー: {e}")

        return workflow.workflow_id

    def start_workflow_execution(self, workflow_id: str, trigger_data: Dict[str, Any] = None) -> str:
        """
        ワークフロー実行を開始
        Args:
            workflow_id: ワークフローID
            trigger_data: トリガーデータ
        Returns:
            実行ID
        """
        if workflow_id not in self.workflows:
            raise ValueError(f"ワークフローが見つかりません: {workflow_id}")

        execution_id = str(uuid.uuid4())
        execution = WorkflowExecution(
            execution_id=execution_id,
            workflow_id=workflow_id
        )

        self.executions[execution_id] = execution

        # データベースに記録
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO workflow_executions
                    (execution_id, workflow_id, status, started_at)
                    VALUES (?, ?, ?, ?)
                """, (execution_id, workflow_id, "running", time.time()))
                conn.commit()

        except Exception as e:
            logger.error(f"実行記録エラー: {e}")

        # 非同期でワークフローを実行
        asyncio.create_task(self._execute_workflow(execution, trigger_data))

        return execution_id

    async def _execute_workflow(self, execution: WorkflowExecution, trigger_data: Dict[str, Any] = None):
        """ワークフローを実行"""
        try:
            workflow = self.workflows[execution.workflow_id]

            logger.info(f"ワークフロー実行開始: {workflow.name}")

            # タスクを依存関係順に実行
            completed_tasks = set()
            remaining_tasks = workflow.tasks.copy()

            while remaining_tasks:
                # 実行可能なタスクを検索（依存関係が満たされているもの）
                executable_tasks = []

                for task in remaining_tasks:
                    if all(dep in completed_tasks for dep in task.dependencies):
                        executable_tasks.append(task)

                if not executable_tasks:
                    # デッドロック検知
                    logger.error(f"ワークフローデッドロック検知: {execution.workflow_id}")
                    execution.status = "failed"
                    execution.error_message = "タスクの依存関係でデッドロックが発生しました"
                    break

                # タスクを実行
                for task in executable_tasks:
                    remaining_tasks.remove(task)
                    execution.current_task = task.task_id

                    # スケジューラーにタスクを登録
                    success = self.scheduler.schedule_task(task)

                    if success:
                        completed_tasks.add(task.task_id)

                        # 実行結果を記録
                        execution.results[task.task_id] = {
                            "status": task.status.value,
                            "started_at": task.started_at,
                            "completed_at": task.completed_at,
                            "duration": task.actual_duration
                        }

                # 実行完了を待機（簡易版）
                await asyncio.sleep(0.1)

            # ワークフロー完了
            execution.status = "completed"
            execution.completed_at = time.time()

            logger.info(f"ワークフロー実行完了: {workflow.name}")

            # 実行コールバック実行
            for callback in self.execution_callbacks:
                try:
                    callback(execution)
                except Exception as e:
                    logger.error(f"実行コールバックエラー: {e}")

        except Exception as e:
            logger.error(f"ワークフロー実行エラー: {e}")
            execution.status = "failed"
            execution.error_message = str(e)

    def add_execution_callback(self, callback: Callable):
        """
        実行コールバックを追加
        Args:
            callback: コールバック関数
        """
        self.execution_callbacks.append(callback)

    def get_workflow_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """
        ワークフロー実行ステータスを取得
        Args:
            execution_id: 実行ID
        Returns:
            ステータス情報（見つからない場合はNone）
        """
        if execution_id not in self.executions:
            return None

        execution = self.executions[execution_id]

        return {
            "execution_id": execution.execution_id,
            "workflow_id": execution.workflow_id,
            "status": execution.status,
            "current_task": execution.current_task,
            "started_at": execution.started_at,
            "completed_at": execution.completed_at,
            "results": execution.results,
            "error_message": execution.error_message
        }

    def start_engine(self):
        """ワークフローエンジンを開始"""
        if not self.is_engine_active:
            self.is_engine_active = True
            self.engine_thread = threading.Thread(target=self._engine_loop, daemon=True)
            self.engine_thread.start()

    def stop_engine(self):
        """ワークフローエンジンを停止"""
        self.is_engine_active = False
        if self.engine_thread:
            self.engine_thread.join()

    def _engine_loop(self):
        """エンジンループ"""
        while self.is_engine_active:
            try:
                # 定期的なメンテナンス処理
                self._perform_maintenance()
                time.sleep(60.0)  # 1分間隔
            except Exception as e:
                logger.error(f"エンジンループエラー: {e}")

    def _perform_maintenance(self):
        """メンテナンス処理を実行"""
        # 実行中のワークフローをチェックしてタイムアウト処理など
        current_time = time.time()

        for execution_id, execution in list(self.executions.items()):
            if execution.status == "running":
                # 長時間実行中のワークフローをチェック
                if current_time - execution.started_at > 3600:  # 1時間制限
                    logger.warning(f"長時間実行中のワークフロー: {execution_id}")
                    execution.status = "failed"
                    execution.error_message = "実行タイムアウト"


class WorkflowAutomationManager:
    """ワークフロー自動化管理システム"""

    def __init__(self, db_path: str = "workflow_automation.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self.workflow_engine = WorkflowEngine(db_path)
        self.task_templates: Dict[str, Dict[str, Any]] = {}

        self.is_automation_active = False

    def initialize_automation_system(self):
        """自動化システムを初期化"""
        # デフォルトのタスクテンプレートを設定
        self._setup_default_task_templates()

        # デフォルトのワークフローを作成
        self._create_default_workflows()

    def _setup_default_task_templates(self):
        """デフォルトのタスクテンプレートを設定"""
        self.task_templates = {
            "data_backup": {
                "name": "データバックアップ",
                "task_type": "automated",
                "estimated_duration": 300,
                "metadata": {"backup_type": "full"}
            },
            "report_generation": {
                "name": "レポート生成",
                "task_type": "automated",
                "estimated_duration": 120,
                "metadata": {"report_type": "daily"}
            },
            "user_approval": {
                "name": "ユーザ承認",
                "task_type": "approval",
                "estimated_duration": 3600,
                "metadata": {"approval_type": "critical"}
            },
            "email_notification": {
                "name": "メール通知",
                "task_type": "automated",
                "estimated_duration": 30,
                "metadata": {"notification_type": "status_update"}
            }
        }

    def _create_default_workflows(self):
        """デフォルトのワークフローを作成"""
        # データバックアップワークフロー
        backup_workflow = WorkflowDefinition(
            workflow_id="daily_backup_workflow",
            name="日次バックアップワークフロー",
            description="システムの日次バックアップを実行",
            tasks=[
                WorkflowTask(
                    task_id="backup_task_1",
                    name="データベースバックアップ",
                    task_type="automated",
                    priority=TaskPriority.HIGH,
                    estimated_duration=300
                ),
                WorkflowTask(
                    task_id="backup_task_2",
                    name="バックアップ検証",
                    task_type="automated",
                    priority=TaskPriority.NORMAL,
                    estimated_duration=60,
                    dependencies=["backup_task_1"]
                ),
                WorkflowTask(
                    task_id="backup_task_3",
                    name="バックアップ通知",
                    task_type="automated",
                    priority=TaskPriority.LOW,
                    estimated_duration=30,
                    dependencies=["backup_task_2"]
                )
            ],
            triggers=[{
                "type": "schedule",
                "cron": "0 2 * * *",  # 毎日午前2時
                "enabled": True
            }],
            status=WorkflowStatus.ACTIVE
        )

        self.workflow_engine.create_workflow(backup_workflow)

    def start_automation_system(self):
        """自動化システムを開始"""
        if not self.is_automation_active:
            self.is_automation_active = True
            self.workflow_engine.start_engine()

    def stop_automation_system(self):
        """自動化システムを停止"""
        self.is_automation_active = False
        self.workflow_engine.stop_engine()

    def create_custom_workflow(self, name: str, description: str,
                             tasks: List[Dict[str, Any]], triggers: List[Dict[str, Any]] = None) -> str:
        """
        カスタムワークフローを作成
        Args:
            name: ワークフロー名
            description: 説明
            tasks: タスク定義リスト
            triggers: トリガー定義リスト
        Returns:
            ワークフローID
        """
        workflow_id = str(uuid.uuid4())

        # タスクオブジェクトを作成
        workflow_tasks = []
        for task_data in tasks:
            task = WorkflowTask(
                task_id=task_data.get("task_id", str(uuid.uuid4())),
                name=task_data["name"],
                description=task_data.get("description", ""),
                task_type=task_data["task_type"],
                priority=TaskPriority(task_data.get("priority", "normal")),
                assignee=task_data.get("assignee"),
                dependencies=task_data.get("dependencies", []),
                estimated_duration=task_data.get("estimated_duration")
            )
            workflow_tasks.append(task)

        workflow = WorkflowDefinition(
            workflow_id=workflow_id,
            name=name,
            description=description,
            tasks=workflow_tasks,
            triggers=triggers or []
        )

        return self.workflow_engine.create_workflow(workflow)

    def execute_workflow(self, workflow_id: str, trigger_data: Dict[str, Any] = None) -> str:
        """
        ワークフローを実行
        Args:
            workflow_id: ワークフローID
            trigger_data: トリガーデータ
        Returns:
            実行ID
        """
        return self.workflow_engine.start_workflow_execution(workflow_id, trigger_data)

    def get_workflow_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """
        ワークフロー実行ステータスを取得
        Args:
            execution_id: 実行ID
        Returns:
            ステータス情報
        """
        return self.workflow_engine.get_workflow_status(execution_id)

    def get_automation_status(self) -> Dict[str, Any]:
        """自動化ステータスを取得"""
        return {
            "is_active": self.is_automation_active,
            "total_workflows": len(self.workflow_engine.workflows),
            "active_executions": len([e for e in self.workflow_engine.executions.values() if e.status == "running"]),
            "scheduler_status": self.workflow_engine.scheduler.get_scheduler_status()
        }


# 使用例
def example_usage():
    manager = WorkflowAutomationManager()

    # システム初期化
    manager.initialize_automation_system()

    # システム開始
    manager.start_automation_system()

    # カスタムワークフロー作成
    workflow_id = manager.create_custom_workflow(
        name="カスタマーオンボーディング",
        description="新規顧客のオンボーディングプロセス",
        tasks=[
            {
                "name": "アカウント作成",
                "task_type": "automated",
                "priority": "high",
                "estimated_duration": 60
            },
            {
                "name": "初期設定",
                "task_type": "manual",
                "priority": "normal",
                "estimated_duration": 300,
                "assignee": "admin",
                "dependencies": ["アカウント作成"]
            },
            {
                "name": "ウェルカムメール送信",
                "task_type": "automated",
                "priority": "low",
                "estimated_duration": 30,
                "dependencies": ["初期設定"]
            }
        ]
    )

    print(f"ワークフロー作成: {workflow_id}")

    # ワークフロー実行
    execution_id = manager.execute_workflow(workflow_id, {"user_id": "new_customer_123"})
    print(f"ワークフロー実行開始: {execution_id}")

    # ステータス確認
    status = manager.get_workflow_status(execution_id)
    print(f"実行ステータス: {status}")

    # 全体ステータス
    overall_status = manager.get_automation_status()
    print(f"自動化ステータス: {overall_status}")

    manager.stop_automation_system()


if __name__ == "__main__":
    example_usage()
