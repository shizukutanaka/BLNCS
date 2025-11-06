"""
高可用性システム for BLNCS
自動フェイルオーバーとインテリジェントバックアップ機能を提供
"""

import asyncio
import json
import time
import shutil
import threading
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import logging
import sqlite3
import os
from pathlib import Path

logger = logging.getLogger(__name__)


class FailoverStatus(Enum):
    """フェイルオーバーステータス"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    RECOVERING = "recovering"


class BackupType(Enum):
    """バックアップタイプ"""
    FULL = "full"
    INCREMENTAL = "incremental"
    DIFFERENTIAL = "differential"


@dataclass
class SystemNode:
    """システムノード情報"""
    node_id: str
    node_type: str  # 'primary', 'secondary', 'backup'
    address: str
    port: int
    status: FailoverStatus = FailoverStatus.HEALTHY
    last_heartbeat: float = field(default_factory=time.time)
    priority: int = 0  # フェイルオーバー優先度（数値が大きいほど優先）
    max_connections: int = 1000
    current_load: float = 0.0


@dataclass
class BackupJob:
    """バックアップジョブ情報"""
    job_id: str
    backup_type: BackupType
    source_paths: List[str]
    destination_path: str
    schedule: str = "manual"  # cron形式またはmanual
    compression: bool = True
    encryption: bool = False
    retention_count: int = 7  # 保持するバックアップ数
    is_enabled: bool = True
    last_run: Optional[float] = None
    next_run: Optional[float] = None


@dataclass
class FailoverEvent:
    """フェイルオーバーイベント情報"""
    event_id: str
    timestamp: float
    failed_node: str
    failover_node: str
    reason: str
    duration: float = 0.0
    success: bool = False


class HealthMonitor:
    """ヘルスモニターシステム"""

    def __init__(self, check_interval: float = 10.0, timeout: float = 5.0):
        """
        初期化
        Args:
            check_interval: チェック間隔（秒）
            timeout: タイムアウト時間（秒）
        """
        self.check_interval = check_interval
        self.timeout = timeout
        self.nodes: Dict[str, SystemNode] = {}
        self.health_callbacks: List[Callable] = []
        self.is_monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None

    def register_node(self, node: SystemNode):
        """
        ノードを登録
        Args:
            node: システムノード情報
        """
        self.nodes[node.node_id] = node

    def unregister_node(self, node_id: str):
        """
        ノードを登録解除
        Args:
            node_id: ノードID
        """
        if node_id in self.nodes:
            del self.nodes[node_id]

    def check_node_health(self, node: SystemNode) -> FailoverStatus:
        """
        ノードのヘルスチェックを実行
        Args:
            node: チェック対象ノード
        Returns:
            ヘルスステータス
        """
        try:
            import socket
            import requests

            # ソケット接続チェック
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((node.address, node.port))
            sock.close()

            if result != 0:
                return FailoverStatus.FAILED

            # HTTPヘルスチェック（オプション）
            try:
                response = requests.get(f"http://{node.address}:{node.port}/health", timeout=self.timeout)
                if response.status_code != 200:
                    return FailoverStatus.DEGRADED
            except:
                # HTTPチェックが失敗してもソケット接続ができていればDEGRADED
                pass

            return FailoverStatus.HEALTHY

        except Exception as e:
            logger.error(f"ヘルスチェックエラー: {e}")
            return FailoverStatus.FAILED

    def start_monitoring(self):
        """ヘルス監視を開始"""
        if not self.is_monitoring:
            self.is_monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()

    def stop_monitoring(self):
        """ヘルス監視を停止"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()

    def add_health_callback(self, callback: Callable):
        """
        ヘルスチェックコールバックを追加
        Args:
            callback: コールバック関数（node_id, statusを受け取る）
        """
        self.health_callbacks.append(callback)

    def _monitor_loop(self):
        """監視ループ"""
        while self.is_monitoring:
            try:
                for node_id, node in list(self.nodes.items()):
                    new_status = self.check_node_health(node)

                    if new_status != node.status:
                        old_status = node.status
                        node.status = new_status
                        node.last_heartbeat = time.time()

                        logger.warning(f"ノードステータス変更: {node_id} {old_status.value} -> {new_status.value}")

                        # コールバック実行
                        for callback in self.health_callbacks:
                            try:
                                callback(node_id, new_status)
                            except Exception as e:
                                logger.error(f"ヘルスコールバックエラー: {e}")

                time.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"監視ループエラー: {e}")


class AutoFailoverManager:
    """自動フェイルオーバーマネージャー"""

    def __init__(self, health_monitor: HealthMonitor):
        """
        初期化
        Args:
            health_monitor: ヘルスモニターシステム
        """
        self.health_monitor = health_monitor
        self.failover_events: List[FailoverEvent] = []
        self.failover_callbacks: List[Callable] = []
        self.is_failover_active = False

    def start_failover_management(self):
        """フェイルオーバー管理を開始"""
        if not self.is_failover_active:
            self.is_failover_active = True

            # ヘルスモニターのコールバックを設定
            def on_health_change(node_id: str, status: FailoverStatus):
                if status == FailoverStatus.FAILED:
                    asyncio.create_task(self._trigger_failover(node_id))

            self.health_monitor.add_health_callback(on_health_change)

    def stop_failover_management(self):
        """フェイルオーバー管理を停止"""
        self.is_failover_active = False

    def select_failover_target(self, failed_node_id: str) -> Optional[str]:
        """
        フェイルオーバー対象を選択
        Args:
            failed_node_id: 失敗したノードID
        Returns:
            フェイルオーバー対象ノードID（見つからない場合はNone）
        """
        available_nodes = [
            node for node_id, node in self.health_monitor.nodes.items()
            if node_id != failed_node_id and node.status == FailoverStatus.HEALTHY
        ]

        if not available_nodes:
            return None

        # 優先度と負荷に基づいて選択
        return max(available_nodes, key=lambda x: (x.priority, -x.current_load)).node_id

    async def _trigger_failover(self, failed_node_id: str):
        """フェイルオーバーをトリガー"""
        start_time = time.time()

        try:
            target_node_id = self.select_failover_target(failed_node_id)

            if not target_node_id:
                logger.error(f"フェイルオーバー対象が見つかりません: {failed_node_id}")
                return

            # フェイルオーバー実行
            success = await self._execute_failover(failed_node_id, target_node_id)

            duration = time.time() - start_time

            # イベント記録
            event = FailoverEvent(
                event_id=f"failover_{int(time.time() * 1000000)}",
                timestamp=start_time,
                failed_node=failed_node_id,
                failover_node=target_node_id,
                reason="自動ヘルスチェックによる検知",
                duration=duration,
                success=success
            )

            self.failover_events.append(event)

            # コールバック実行
            for callback in self.failover_callbacks:
                try:
                    callback(event)
                except Exception as e:
                    logger.error(f"フェイルオーバーコールバックエラー: {e}")

            if success:
                logger.info(f"フェイルオーバー成功: {failed_node_id} -> {target_node_id}")
            else:
                logger.error(f"フェイルオーバー失敗: {failed_node_id}")

        except Exception as e:
            logger.error(f"フェイルオーバートリガーエラー: {e}")

    async def _execute_failover(self, failed_node_id: str, target_node_id: str) -> bool:
        """
        フェイルオーバーを実行（オーバーライド可能）
        Args:
            failed_node_id: 失敗したノードID
            target_node_id: フェイルオーバー対象ノードID
        Returns:
            実行成功フラグ
        """
        try:
            # 実際の実装では以下の処理を実行：
            # 1. トラフィックの転送
            # 2. セッション状態の同期
            # 3. データベース接続の切り替え
            # 4. キャッシュの同期

            await asyncio.sleep(1.0)  # フェイルオーバー時間をシミュレーション

            # ターゲットノードの負荷を更新
            if target_node_id in self.health_monitor.nodes:
                self.health_monitor.nodes[target_node_id].current_load += 0.3  # 負荷増加をシミュレーション

            return True

        except Exception as e:
            logger.error(f"フェイルオーバー実行エラー: {e}")
            return False

    def add_failover_callback(self, callback: Callable):
        """
        フェイルオーバーコールバックを追加
        Args:
            callback: コールバック関数
        """
        self.failover_callbacks.append(callback)

    def get_failover_history(self, limit: int = 100) -> List[FailoverEvent]:
        """フェイルオーバー履歴を取得"""
        return self.failover_events[-limit:]


class IntelligentBackupManager:
    """インテリジェントバックアップマネージャー"""

    def __init__(self, backup_root: str = "backups"):
        """
        初期化
        Args:
            backup_root: バックアップルートディレクトリ
        """
        self.backup_root = Path(backup_root)
        self.backup_root.mkdir(exist_ok=True)
        self.backup_jobs: Dict[str, BackupJob] = {}
        self.backup_history: List[Dict[str, Any]] = []
        self.scheduler_thread: Optional[threading.Thread] = None
        self.is_scheduling = False

    def create_backup_job(self, job: BackupJob):
        """
        バックアップジョブを作成
        Args:
            job: バックアップジョブ情報
        """
        self.backup_jobs[job.job_id] = job
        logger.info(f"バックアップジョブ作成: {job.job_id}")

    def execute_backup(self, job_id: str) -> bool:
        """
        バックアップを実行
        Args:
            job_id: ジョブID
        Returns:
            実行成功フラグ
        """
        if job_id not in self.backup_jobs:
            logger.error(f"バックアップジョブが見つかりません: {job_id}")
            return False

        job = self.backup_jobs[job_id]
        start_time = time.time()

        try:
            # バックアップ実行
            success = self._perform_backup(job)

            # 履歴記録
            self.backup_history.append({
                "job_id": job_id,
                "timestamp": start_time,
                "duration": time.time() - start_time,
                "success": success,
                "backup_type": job.backup_type.value,
                "size": self._get_backup_size(job)
            })

            job.last_run = start_time

            if success:
                logger.info(f"バックアップ成功: {job_id}")
                # 古いバックアップをクリーンアップ
                self._cleanup_old_backups(job)
            else:
                logger.error(f"バックアップ失敗: {job_id}")

            return success

        except Exception as e:
            logger.error(f"バックアップ実行エラー: {e}")
            return False

    def _perform_backup(self, job: BackupJob) -> bool:
        """バックアップを実行"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{job.backup_type.value}_{timestamp}"
            backup_path = self.backup_root / job_id / backup_name

            # ディレクトリ作成
            backup_path.mkdir(parents=True, exist_ok=True)

            # ファイルコピー
            for source_path in job.source_paths:
                source = Path(source_path)
                if source.exists():
                    if source.is_file():
                        shutil.copy2(source, backup_path / source.name)
                    elif source.is_dir():
                        shutil.copytree(source, backup_path / source.name)

            # メタデータ保存
            metadata = {
                "job_id": job.job_id,
                "backup_type": job.backup_type.value,
                "timestamp": time.time(),
                "source_paths": job.source_paths,
                "compression": job.compression,
                "encryption": job.encryption
            }

            with open(backup_path / "metadata.json", 'w') as f:
                json.dump(metadata, f, indent=2)

            return True

        except Exception as e:
            logger.error(f"バックアップ処理エラー: {e}")
            return False

    def _get_backup_size(self, job: BackupJob) -> int:
        """バックアップサイズを取得"""
        try:
            job_path = self.backup_root / job.job_id
            if not job_path.exists():
                return 0

            total_size = 0
            for backup_dir in job_path.iterdir():
                if backup_dir.is_dir():
                    total_size += sum(f.stat().st_size for f in backup_dir.rglob('*') if f.is_file())

            return total_size
        except Exception:
            return 0

    def _cleanup_old_backups(self, job: BackupJob):
        """古いバックアップをクリーンアップ"""
        try:
            job_path = self.backup_root / job.job_id
            if not job_path.exists():
                return

            backup_dirs = []
            for backup_dir in job_path.iterdir():
                if backup_dir.is_dir():
                    backup_dirs.append(backup_dir)

            # 作成時間でソート
            backup_dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)

            # 保持数を越えるバックアップを削除
            for old_backup in backup_dirs[job.retention_count:]:
                shutil.rmtree(old_backup)
                logger.info(f"古いバックアップを削除: {old_backup.name}")

        except Exception as e:
            logger.error(f"バックアップクリーンアップエラー: {e}")

    def start_scheduler(self):
        """スケジューラーを開始"""
        if not self.is_scheduling:
            self.is_scheduling = True
            self.scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
            self.scheduler_thread.start()

    def stop_scheduler(self):
        """スケジューラーを停止"""
        self.is_scheduling = False
        if self.scheduler_thread:
            self.scheduler_thread.join()

    def _scheduler_loop(self):
        """スケジューラーループ"""
        while self.is_scheduling:
            try:
                current_time = time.time()

                for job in self.backup_jobs.values():
                    if not job.is_enabled or job.schedule == "manual":
                        continue

                    # 次回実行時間をチェック（簡易実装）
                    if job.next_run and current_time >= job.next_run:
                        self.execute_backup(job.job_id)
                        # 次回実行時間を設定（24時間後）
                        job.next_run = current_time + 24 * 3600

                time.sleep(60)  # 1分間隔でチェック
            except Exception as e:
                logger.error(f"スケジューラーループエラー: {e}")


class HighAvailabilityManager:
    """高可用性管理システム"""

    def __init__(self, db_path: str = "ha_system.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self.health_monitor = HealthMonitor()
        self.failover_manager = AutoFailoverManager(self.health_monitor)
        self.backup_manager = IntelligentBackupManager()

        self.is_ha_active = False

    def initialize_ha_system(self, primary_node: SystemNode, secondary_nodes: List[SystemNode]):
        """
        高可用性システムを初期化
        Args:
            primary_node: プライマリノード
            secondary_nodes: セカンダリノードリスト
        """
        # ノードを登録
        self.health_monitor.register_node(primary_node)
        for node in secondary_nodes:
            self.health_monitor.register_node(node)

        # フェイルオーバー管理を開始
        self.failover_manager.start_failover_management()

        # バックアップスケジューラーを開始
        self.backup_manager.start_scheduler()

        # システムバックアップジョブを作成
        self._create_system_backup_job()

    def _create_system_backup_job(self):
        """システムバックアップジョブを作成"""
        backup_job = BackupJob(
            job_id="system_backup",
            backup_type=BackupType.FULL,
            source_paths=["blncs.db", "config/", "data/"],
            destination_path="backups/system",
            schedule="0 2 * * *",  # 毎日午前2時
            compression=True,
            encryption=False,
            retention_count=30  # 30日保持
        )

        self.backup_manager.create_backup_job(backup_job)

    def start_ha_system(self):
        """高可用性システムを開始"""
        if not self.is_ha_active:
            self.is_ha_active = True
            self.health_monitor.start_monitoring()

    def stop_ha_system(self):
        """高可用性システムを停止"""
        self.is_ha_active = False
        self.health_monitor.stop_monitoring()
        self.failover_manager.stop_failover_management()
        self.backup_manager.stop_scheduler()

    def execute_manual_backup(self, job_id: str = "system_backup") -> bool:
        """
        手動バックアップを実行
        Args:
            job_id: ジョブID
        Returns:
            実行成功フラグ
        """
        return self.backup_manager.execute_backup(job_id)

    def get_system_status(self) -> Dict[str, Any]:
        """システムステータスを取得"""
        healthy_nodes = len([node for node in self.health_monitor.nodes.values() if node.status == FailoverStatus.HEALTHY])
        total_nodes = len(self.health_monitor.nodes)

        return {
            "is_ha_active": self.is_ha_active,
            "total_nodes": total_nodes,
            "healthy_nodes": healthy_nodes,
            "failed_nodes": total_nodes - healthy_nodes,
            "recent_failovers": len(self.failover_manager.get_failover_history(10)),
            "backup_jobs": len(self.backup_manager.backup_jobs),
            "recent_backups": len(self.backup_manager.backup_history[-10:])
        }


# 使用例
def example_usage():
    ha_manager = HighAvailabilityManager()

    # ノード設定
    primary = SystemNode(
        node_id="primary_1",
        node_type="primary",
        address="127.0.0.1",
        port=8080,
        priority=100
    )

    secondary1 = SystemNode(
        node_id="secondary_1",
        node_type="secondary",
        address="127.0.0.1",
        port=8081,
        priority=50
    )

    secondary2 = SystemNode(
        node_id="secondary_2",
        node_type="secondary",
        address="127.0.0.1",
        port=8082,
        priority=30
    )

    # システム初期化
    ha_manager.initialize_ha_system(primary, [secondary1, secondary2])

    # システム開始
    ha_manager.start_ha_system()

    # 手動バックアップ実行
    success = ha_manager.execute_manual_backup()
    print(f"バックアップ実行: {'成功' if success else '失敗'}")

    # ステータス表示
    status = ha_manager.get_system_status()
    print(f"システムステータス: {status}")

    # フェイルオーバー履歴表示
    history = ha_manager.failover_manager.get_failover_history()
    print(f"フェイルオーバー履歴: {len(history)}件")

    ha_manager.stop_ha_system()


if __name__ == "__main__":
    example_usage()
