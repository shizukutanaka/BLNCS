"""
エンタープライズ統合プラットフォーム for BLNCS
異種システム統合とデータ同期機能を提供
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
import aiohttp
import uuid
from collections import defaultdict

logger = logging.getLogger(__name__)


class IntegrationPattern(Enum):
    """統合パターン"""
    POINT_TO_POINT = "point_to_point"
    HUB_AND_SPOKE = "hub_and_spoke"
    MESSAGE_BUS = "message_bus"
    API_GATEWAY = "api_gateway"
    ETL = "etl"
    ESB = "esb"  # Enterprise Service Bus


class SystemType(Enum):
    """システムタイプ"""
    ERP = "erp"  # Enterprise Resource Planning
    CRM = "crm"  # Customer Relationship Management
    HCM = "hcm"  # Human Capital Management
    SCM = "scm"  # Supply Chain Management
    ECOMMERCE = "ecommerce"
    DATABASE = "database"
    API = "api"
    IOT_PLATFORM = "iot_platform"
    BLOCKCHAIN = "blockchain"
    LEGACY_SYSTEM = "legacy_system"


class DataSyncStatus(Enum):
    """データ同期ステータス"""
    SYNCING = "syncing"
    COMPLETED = "completed"
    FAILED = "failed"
    CONFLICT = "conflict"
    PENDING = "pending"


@dataclass
class IntegratedSystem:
    """統合システム情報"""
    system_id: str
    name: str
    system_type: SystemType
    connection_config: Dict[str, Any]
    api_endpoints: List[Dict[str, str]] = field(default_factory=list)
    data_schemas: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    authentication: Dict[str, str] = field(default_factory=dict)
    status: str = "disconnected"
    last_sync: Optional[float] = None
    sync_frequency: int = 3600  # 同期間隔（秒）


@dataclass
class DataMapping:
    """データマッピング情報"""
    mapping_id: str
    source_system: str
    target_system: str
    source_schema: Dict[str, Any]
    target_schema: Dict[str, Any]
    transformation_rules: List[Dict[str, Any]] = field(default_factory=list)
    is_bidirectional: bool = False
    conflict_resolution: str = "source_priority"  # source_priority, target_priority, manual


@dataclass
class DataSyncJob:
    """データ同期ジョブ情報"""
    job_id: str
    mapping_id: str
    status: DataSyncStatus = DataSyncStatus.PENDING
    records_processed: int = 0
    records_synced: int = 0
    records_failed: int = 0
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    error_message: Optional[str] = None
    last_checkpoint: Dict[str, Any] = field(default_factory=dict)


class IntegrationBus:
    """統合バスシステム"""

    def __init__(self):
        """初期化"""
        self.integrated_systems: Dict[str, IntegratedSystem] = {}
        self.data_mappings: Dict[str, DataMapping] = {}
        self.message_queue: List[Dict[str, Any]] = []
        self.integration_callbacks: List[Callable] = []

    def register_system(self, system: IntegratedSystem) -> bool:
        """
        システムを登録
        Args:
            system: 統合システム情報
        Returns:
            登録成功フラグ
        """
        try:
            self.integrated_systems[system.system_id] = system
            logger.info(f"システム登録: {system.name} ({system.system_type.value})")
            return True
        except Exception as e:
            logger.error(f"システム登録エラー: {e}")
            return False

    def unregister_system(self, system_id: str) -> bool:
        """
        システムを登録解除
        Args:
            system_id: システムID
        Returns:
            登録解除成功フラグ
        """
        if system_id in self.integrated_systems:
            del self.integrated_systems[system_id]
            logger.info(f"システム登録解除: {system_id}")
            return True
        return False

    def define_data_mapping(self, mapping: DataMapping) -> str:
        """
        データマッピングを定義
        Args:
            mapping: データマッピング情報
        Returns:
            マッピングID
        """
        self.data_mappings[mapping.mapping_id] = mapping
        logger.info(f"データマッピング定義: {mapping.mapping_id}")
        return mapping.mapping_id

    async def send_message(self, source_system: str, target_system: str, message: Dict[str, Any]):
        """
        メッセージを送信
        Args:
            source_system: 送信元システム
            target_system: 宛先システム
            message: メッセージデータ
        """
        message_data = {
            "message_id": str(uuid.uuid4()),
            "source_system": source_system,
            "target_system": target_system,
            "message": message,
            "timestamp": time.time(),
            "status": "sent"
        }

        self.message_queue.append(message_data)

        # 非同期でメッセージ処理を実行
        asyncio.create_task(self._process_message(message_data))

    async def _process_message(self, message_data: Dict[str, Any]):
        """メッセージを処理"""
        try:
            source_system = message_data["source_system"]
            target_system = message_data["target_system"]
            message = message_data["message"]

            # 該当するデータマッピングを検索
            applicable_mappings = [
                mapping for mapping in self.data_mappings.values()
                if mapping.source_system == source_system and mapping.target_system == target_system
            ]

            if applicable_mappings:
                # マッピングを適用してデータを変換・同期
                for mapping in applicable_mappings:
                    await self._apply_data_mapping(message_data, mapping)

            # 統合コールバックを実行
            for callback in self.integration_callbacks:
                try:
                    callback(message_data)
                except Exception as e:
                    logger.error(f"統合コールバックエラー: {e}")

        except Exception as e:
            logger.error(f"メッセージ処理エラー: {e}")

    async def _apply_data_mapping(self, message_data: Dict[str, Any], mapping: DataMapping):
        """データマッピングを適用"""
        try:
            source_data = message_data["message"]

            # データ変換を実行（簡易版）
            transformed_data = self._transform_data(source_data, mapping.transformation_rules)

            # 宛先システムにデータを送信
            target_system_id = mapping.target_system

            if target_system_id in self.integrated_systems:
                target_system = self.integrated_systems[target_system_id]

                # 実際の実装では宛先システムのAPIを呼び出し
                logger.info(f"データ同期実行: {mapping.mapping_id} -> {target_system.name}")

        except Exception as e:
            logger.error(f"データマッピング適用エラー: {mapping.mapping_id} - {e}")

    def _transform_data(self, data: Any, transformation_rules: List[Dict[str, Any]]) -> Any:
        """データを変換"""
        # 簡易的なデータ変換（実際の実装ではより高度な変換ロジックを使用）
        if isinstance(data, dict):
            transformed = data.copy()

            for rule in transformation_rules:
                rule_type = rule.get("type")

                if rule_type == "field_mapping":
                    source_field = rule.get("source_field")
                    target_field = rule.get("target_field")

                    if source_field in data:
                        transformed[target_field] = data[source_field]
                        if "delete_source" in rule and rule["delete_source"]:
                            del transformed[source_field]

                elif rule_type == "value_transformation":
                    field = rule.get("field")
                    transformation = rule.get("transformation")

                    if field in transformed:
                        if transformation == "uppercase":
                            transformed[field] = str(transformed[field]).upper()
                        elif transformation == "lowercase":
                            transformed[field] = str(transformed[field]).lower()

            return transformed

        return data

    def add_integration_callback(self, callback: Callable):
        """
        統合コールバックを追加
        Args:
            callback: コールバック関数
        """
        self.integration_callbacks.append(callback)


class DataSynchronizer:
    """データ同期システム"""

    def __init__(self, integration_bus: IntegrationBus, db_path: str = "data_synchronization.db"):
        """
        初期化
        Args:
            integration_bus: 統合バス
            db_path: データベースパス
        """
        self.db_path = db_path
        self.integration_bus = integration_bus
        self._init_db()
        self.sync_jobs: Dict[str, DataSyncJob] = {}

    def _init_db(self):
        """データベースを初期化"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS data_sync_jobs (
                    job_id TEXT PRIMARY KEY,
                    mapping_id TEXT NOT NULL,
                    status TEXT,
                    records_processed INTEGER,
                    records_synced INTEGER,
                    records_failed INTEGER,
                    started_at REAL,
                    completed_at REAL,
                    error_message TEXT,
                    last_checkpoint TEXT
                )
            """)

            conn.commit()

    def start_data_synchronization(self, mapping_id: str) -> str:
        """
        データ同期を開始
        Args:
            mapping_id: マッピングID
        Returns:
            ジョブID
        """
        if mapping_id not in self.integration_bus.data_mappings:
            raise ValueError(f"マッピングが見つかりません: {mapping_id}")

        job_id = str(uuid.uuid4())

        job = DataSyncJob(
            job_id=job_id,
            mapping_id=mapping_id
        )

        self.sync_jobs[job_id] = job

        # 非同期で同期を実行
        asyncio.create_task(self._execute_data_sync(job))

        return job_id

    async def _execute_data_sync(self, job: DataSyncJob):
        """データ同期を実行"""
        job.status = DataSyncStatus.SYNCING
        job.started_at = time.time()

        try:
            mapping = self.integration_bus.data_mappings[job.mapping_id]

            # データ取得（ソースシステムから）
            source_data = await self._fetch_source_data(mapping)

            # データ変換
            transformed_data = self.integration_bus._transform_data(source_data, mapping.transformation_rules)

            # データ検証と同期
            await self._validate_and_sync_data(job, transformed_data, mapping)

            job.status = DataSyncStatus.COMPLETED
            job.completed_at = time.time()

            logger.info(f"データ同期完了: {job.job_id}")

        except Exception as e:
            job.status = DataSyncStatus.FAILED
            job.completed_at = time.time()
            job.error_message = str(e)

            logger.error(f"データ同期エラー: {job.job_id} - {e}")

    async def _fetch_source_data(self, mapping: DataMapping) -> List[Dict[str, Any]]:
        """ソースシステムからデータを取得"""
        # 実際の実装ではソースシステムのAPIを呼び出し
        await asyncio.sleep(0.5)  # データ取得時間をシミュレーション

        # サンプルデータを返却
        return [
            {"id": 1, "name": "Sample Data 1", "value": 100},
            {"id": 2, "name": "Sample Data 2", "value": 200}
        ]

    async def _validate_and_sync_data(self, job: DataSyncJob, data: Any, mapping: DataMapping):
        """データを検証・同期"""
        if isinstance(data, list):
            for item in data:
                job.records_processed += 1

                # データ検証（簡易版）
                is_valid = self._validate_data_item(item, mapping)

                if is_valid:
                    # 宛先システムにデータを送信
                    await self._send_to_target_system(item, mapping)
                    job.records_synced += 1
                else:
                    job.records_failed += 1

    def _validate_data_item(self, item: Dict[str, Any], mapping: DataMapping) -> bool:
        """データ項目を検証"""
        # 必須フィールドチェック（簡易版）
        required_fields = mapping.target_schema.get("required_fields", [])

        for field in required_fields:
            if field not in item:
                return False

        return True

    async def _send_to_target_system(self, data: Dict[str, Any], mapping: DataMapping):
        """データを宛先システムに送信"""
        # 実際の実装では宛先システムのAPIを呼び出し
        await asyncio.sleep(0.1)  # 送信時間をシミュレーション

    def get_sync_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """
        同期ジョブステータスを取得
        Args:
            job_id: ジョブID
        Returns:
            ジョブ情報（見つからない場合はNone）
        """
        if job_id not in self.sync_jobs:
            return None

        job = self.sync_jobs[job_id]

        return {
            "job_id": job.job_id,
            "mapping_id": job.mapping_id,
            "status": job.status.value,
            "records_processed": job.records_processed,
            "records_synced": job.records_synced,
            "records_failed": job.records_failed,
            "started_at": job.started_at,
            "completed_at": job.completed_at,
            "error_message": job.error_message
        }


class EnterpriseIntegrationPlatform:
    """エンタープライズ統合プラットフォーム"""

    def __init__(self, db_path: str = "enterprise_integration.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self.integration_bus = IntegrationBus()
        self.data_synchronizer = DataSynchronizer(self.integration_bus, db_path)

        self.is_integration_active = False

    def initialize_enterprise_integration_platform(self):
        """エンタープライズ統合プラットフォームを初期化"""
        # デフォルトのシステムを登録
        self._register_default_systems()

        # デフォルトのデータマッピングを作成
        self._create_default_data_mappings()

    def _register_default_systems(self):
        """デフォルトのシステムを登録"""
        systems = [
            IntegratedSystem(
                system_id="erp_system",
                name="ERPシステム",
                system_type=SystemType.ERP,
                connection_config={
                    "host": "erp.company.com",
                    "port": 443,
                    "protocol": "https"
                },
                api_endpoints=[
                    {"path": "/api/customers", "method": "GET"},
                    {"path": "/api/orders", "method": "POST"}
                ],
                data_schemas={
                    "customer": {
                        "fields": ["id", "name", "email", "phone"],
                        "required_fields": ["id", "name"]
                    }
                }
            ),
            IntegratedSystem(
                system_id="crm_system",
                name="CRMシステム",
                system_type=SystemType.CRM,
                connection_config={
                    "host": "crm.company.com",
                    "port": 443,
                    "protocol": "https"
                },
                api_endpoints=[
                    {"path": "/api/contacts", "method": "GET"},
                    {"path": "/api/leads", "method": "POST"}
                ],
                data_schemas={
                    "contact": {
                        "fields": ["id", "name", "email", "company"],
                        "required_fields": ["id", "name", "email"]
                    }
                }
            ),
            IntegratedSystem(
                system_id="ecommerce_platform",
                name="Eコマースプラットフォーム",
                system_type=SystemType.ECOMMERCE,
                connection_config={
                    "host": "shop.company.com",
                    "port": 443,
                    "protocol": "https"
                },
                api_endpoints=[
                    {"path": "/api/products", "method": "GET"},
                    {"path": "/api/orders", "method": "POST"}
                ],
                data_schemas={
                    "product": {
                        "fields": ["id", "name", "price", "category"],
                        "required_fields": ["id", "name", "price"]
                    }
                }
            )
        ]

        for system in systems:
            self.integration_bus.register_system(system)

    def _create_default_data_mappings(self):
        """デフォルトのデータマッピングを作成"""
        mappings = [
            DataMapping(
                mapping_id="customer_sync",
                source_system="erp_system",
                target_system="crm_system",
                source_schema={
                    "table": "customers",
                    "fields": ["customer_id", "first_name", "last_name", "email", "phone"]
                },
                target_schema={
                    "table": "contacts",
                    "fields": ["id", "first_name", "last_name", "email", "phone_number"]
                },
                transformation_rules=[
                    {
                        "type": "field_mapping",
                        "source_field": "customer_id",
                        "target_field": "id"
                    },
                    {
                        "type": "field_mapping",
                        "source_field": "first_name",
                        "target_field": "first_name"
                    },
                    {
                        "type": "field_mapping",
                        "source_field": "last_name",
                        "target_field": "last_name"
                    },
                    {
                        "type": "field_mapping",
                        "source_field": "email",
                        "target_field": "email"
                    },
                    {
                        "type": "field_mapping",
                        "source_field": "phone",
                        "target_field": "phone_number"
                    }
                ],
                is_bidirectional=True
            ),
            DataMapping(
                mapping_id="product_catalog_sync",
                source_system="erp_system",
                target_system="ecommerce_platform",
                source_schema={
                    "table": "products",
                    "fields": ["product_id", "name", "description", "price", "category"]
                },
                target_schema={
                    "table": "catalog",
                    "fields": ["id", "title", "description", "price", "category_name"]
                },
                transformation_rules=[
                    {
                        "type": "field_mapping",
                        "source_field": "product_id",
                        "target_field": "id"
                    },
                    {
                        "type": "field_mapping",
                        "source_field": "name",
                        "target_field": "title"
                    },
                    {
                        "type": "field_mapping",
                        "source_field": "description",
                        "target_field": "description"
                    },
                    {
                        "type": "field_mapping",
                        "source_field": "price",
                        "target_field": "price"
                    },
                    {
                        "type": "field_mapping",
                        "source_field": "category",
                        "target_field": "category_name"
                    }
                ]
            )
        ]

        for mapping in mappings:
            self.integration_bus.define_data_mapping(mapping)

    def start_enterprise_integration_platform(self):
        """エンタープライズ統合プラットフォームを開始"""
        if not self.is_integration_active:
            self.is_integration_active = True
            logger.info("エンタープライズ統合プラットフォームを開始しました")

    def stop_enterprise_integration_platform(self):
        """エンタープライズ統合プラットフォームを停止"""
        self.is_integration_active = False
        logger.info("エンタープライズ統合プラットフォームを停止しました")

    def integrate_system(self, system_name: str, system_type: SystemType,
                        connection_config: Dict[str, Any], data_schemas: Dict[str, Dict[str, Any]]) -> str:
        """
        システムを統合
        Args:
            system_name: システム名
            system_type: システムタイプ
            connection_config: 接続設定
            data_schemas: データスキーマ
        Returns:
            システムID
        """
        system_id = str(uuid.uuid4())

        system = IntegratedSystem(
            system_id=system_id,
            name=system_name,
            system_type=system_type,
            connection_config=connection_config,
            data_schemas=data_schemas
        )

        success = self.integration_bus.register_system(system)
        return system_id if success else None

    def create_data_mapping(self, source_system: str, target_system: str,
                          source_schema: Dict[str, Any], target_schema: Dict[str, Any],
                          transformation_rules: List[Dict[str, Any]] = None) -> str:
        """
        データマッピングを作成
        Args:
            source_system: ソースシステム
            target_system: ターゲットシステム
            source_schema: ソーススキーマ
            target_schema: ターゲットスキーマ
            transformation_rules: 変換ルール
        Returns:
            マッピングID
        """
        mapping_id = str(uuid.uuid4())

        mapping = DataMapping(
            mapping_id=mapping_id,
            source_system=source_system,
            target_system=target_system,
            source_schema=source_schema,
            target_schema=target_schema,
            transformation_rules=transformation_rules or []
        )

        return self.integration_bus.define_data_mapping(mapping)

    def start_data_synchronization(self, mapping_id: str) -> str:
        """
        データ同期を開始
        Args:
            mapping_id: マッピングID
        Returns:
            ジョブID
        """
        return self.data_synchronizer.start_data_synchronization(mapping_id)

    async def send_inter_system_message(self, source_system: str, target_system: str, message: Dict[str, Any]):
        """
        システム間メッセージを送信
        Args:
            source_system: 送信元システム
            target_system: 宛先システム
            message: メッセージデータ
        """
        await self.integration_bus.send_message(source_system, target_system, message)

    def get_enterprise_integration_status(self) -> Dict[str, Any]:
        """エンタープライズ統合プラットフォームステータスを取得"""
        return {
            "is_active": self.is_integration_active,
            "total_systems": len(self.integration_bus.integrated_systems),
            "total_mappings": len(self.integration_bus.data_mappings),
            "active_sync_jobs": len([j for j in self.data_synchronizer.sync_jobs.values() if j.status == DataSyncStatus.SYNCING]),
            "message_queue_size": len(self.integration_bus.message_queue)
        }


# 使用例
async def example_usage():
    platform = EnterpriseIntegrationPlatform()

    # プラットフォーム初期化
    platform.initialize_enterprise_integration_platform()

    # プラットフォーム開始
    platform.start_enterprise_integration_platform()

    # カスタムシステム統合
    system_id = platform.integrate_system(
        "Legacy HR System",
        SystemType.HCM,
        {
            "host": "hr.legacy.company.com",
            "port": 8080,
            "protocol": "http",
            "auth_type": "basic"
        },
        {
            "employee": {
                "fields": ["employee_id", "name", "department", "salary"],
                "required_fields": ["employee_id", "name"]
            }
        }
    )

    print(f"システム統合: {system_id}")

    # データマッピング作成
    mapping_id = platform.create_data_mapping(
        "erp_system",
        "crm_system",
        {
            "table": "employees",
            "fields": ["emp_id", "full_name", "dept", "salary"]
        },
        {
            "table": "staff",
            "fields": ["id", "name", "department", "compensation"]
        },
        [
            {"type": "field_mapping", "source_field": "emp_id", "target_field": "id"},
            {"type": "field_mapping", "source_field": "full_name", "target_field": "name"},
            {"type": "field_mapping", "source_field": "dept", "target_field": "department"},
            {"type": "field_mapping", "source_field": "salary", "target_field": "compensation"}
        ]
    )

    print(f"データマッピング作成: {mapping_id}")

    # データ同期開始
    job_id = platform.start_data_synchronization(mapping_id)
    print(f"データ同期開始: {job_id}")

    # システム間メッセージ送信
    await platform.send_inter_system_message(
        "erp_system",
        "crm_system",
        {
            "event_type": "employee_updated",
            "employee_id": "EMP001",
            "changes": {"department": "Sales"}
        }
    )

    # プラットフォームステータス
    status = platform.get_enterprise_integration_status()
    print(f"エンタープライズ統合ステータス: {status}")

    platform.stop_enterprise_integration_platform()


if __name__ == "__main__":
    asyncio.run(example_usage())
