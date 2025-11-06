"""
グローバルスケーリングシステム for BLNCS
マルチリージョン展開と自動スケーリング機能を提供
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


class ScalingStrategy(Enum):
    """スケーリング戦略"""
    HORIZONTAL = "horizontal"  # 水平スケーリング（インスタンス追加）
    VERTICAL = "vertical"      # 垂直スケーリング（リソース増強）
    AUTO = "auto"              # 自動スケーリング
    MANUAL = "manual"          # 手動スケーリング


class DeploymentRegion(Enum):
    """デプロイ地域"""
    NORTH_AMERICA = "north_america"
    EUROPE = "europe"
    ASIA_PACIFIC = "asia_pacific"
    SOUTH_AMERICA = "south_america"
    AFRICA = "africa"
    MIDDLE_EAST = "middle_east"


class ResourceType(Enum):
    """リソースタイプ"""
    CPU = "cpu"
    MEMORY = "memory"
    STORAGE = "storage"
    NETWORK = "network"
    GPU = "gpu"


@dataclass
class ScalingNode:
    """スケーリングノード情報"""
    node_id: str
    region: DeploymentRegion
    resource_type: ResourceType
    current_capacity: float
    max_capacity: float
    utilization_rate: float = 0.0
    status: str = "active"
    cost_per_hour: float = 0.0
    created_at: float = field(default_factory=time.time)
    last_scaled: Optional[float] = None


@dataclass
class ScalingPolicy:
    """スケーリングポリシー情報"""
    policy_id: str
    name: str
    target_metric: str  # 'cpu', 'memory', 'requests_per_second', etc.
    threshold_min: float
    threshold_max: float
    scale_out_increment: int = 1
    scale_in_increment: int = 1
    cooldown_period: int = 300  # クールダウン期間（秒）
    is_active: bool = True
    region: Optional[DeploymentRegion] = None


@dataclass
class ScalingEvent:
    """スケーリングイベント情報"""
    event_id: str
    timestamp: float
    scaling_type: str  # 'scale_out', 'scale_in'
    target_region: DeploymentRegion
    resource_change: Dict[str, int]
    trigger_reason: str
    cost_impact: float = 0.0
    success: bool = True


class LoadBalancerManager:
    """ロードバランサーマネージャー"""

    def __init__(self):
        """初期化"""
        self.regional_load_balancers: Dict[DeploymentRegion, Dict[str, Any]] = defaultdict(dict)
        self.global_routing_table: Dict[str, DeploymentRegion] = {}
        self.traffic_distribution: Dict[DeploymentRegion, float] = defaultdict(float)

    def register_regional_load_balancer(self, region: DeploymentRegion, lb_config: Dict[str, Any]):
        """
        地域別ロードバランサーを登録
        Args:
            region: 地域
            lb_config: ロードバランサー設定
        """
        self.regional_load_balancers[region] = lb_config

    def update_traffic_distribution(self, region: DeploymentRegion, traffic_percentage: float):
        """
        トラフィック分散を更新
        Args:
            region: 地域
            traffic_percentage: トラフィック割合（%）
        """
        self.traffic_distribution[region] = traffic_percentage

    def get_optimal_region(self, user_location: str, service_type: str = "default") -> DeploymentRegion:
        """
        最適な地域を取得
        Args:
            user_location: ユーザーの場所
            service_type: サービスタイプ
        Returns:
            最適な地域
        """
        # 簡易的な地域選択（実際の実装ではより高度なアルゴリズムを使用）
        location_mapping = {
            "north_america": ["US", "CA"],
            "europe": ["GB", "DE", "FR"],
            "asia_pacific": ["JP", "KR", "SG", "AU"]
        }

        for region, countries in location_mapping.items():
            if user_location in countries:
                return DeploymentRegion(region)

        # デフォルトは北米
        return DeploymentRegion.NORTH_AMERICA


class AutoScalingEngine:
    """自動スケーリングエンジン"""

    def __init__(self, load_balancer: LoadBalancerManager):
        """
        初期化
        Args:
            load_balancer: ロードバランサーマネージャー
        """
        self.load_balancer = load_balancer
        self.scaling_policies: Dict[str, ScalingPolicy] = {}
        self.scaling_nodes: Dict[str, ScalingNode] = {}
        self.scaling_history: List[ScalingEvent] = []
        self.metrics_cache: Dict[str, Dict[str, float]] = defaultdict(dict)

    def add_scaling_policy(self, policy: ScalingPolicy):
        """
        スケーリングポリシーを追加
        Args:
            policy: スケーリングポリシー
        """
        self.scaling_policies[policy.policy_id] = policy

    def register_scaling_node(self, node: ScalingNode):
        """
        スケーリングノードを登録
        Args:
            node: スケーリングノード
        """
        self.scaling_nodes[node.node_id] = node

    def collect_metrics(self, region: DeploymentRegion) -> Dict[str, float]:
        """
        メトリクスを収集
        Args:
            region: 地域
        Returns:
            メトリクス情報
        """
        # 実際の実装では監視システムからメトリクスを取得
        current_time = time.time()

        # 簡易的なメトリクス生成（実際の実装では実際の監視データを使用）
        metrics = {
            "cpu_utilization": 60.0 + 20.0 * (current_time % 100) / 100,  # 60-80%の範囲で変動
            "memory_utilization": 70.0 + 15.0 * (current_time % 80) / 80,  # 70-85%の範囲で変動
            "requests_per_second": 100 + 50 * (current_time % 60) / 60,  # 100-150の範囲で変動
            "response_time_ms": 200 + 100 * (current_time % 40) / 40,  # 200-300msの範囲で変動
            "error_rate": 0.02 + 0.01 * (current_time % 20) / 20  # 2-3%の範囲で変動
        }

        self.metrics_cache[region.value] = metrics
        return metrics

    def evaluate_scaling_policies(self, region: DeploymentRegion) -> List[ScalingEvent]:
        """
        スケーリングポリシーを評価
        Args:
            region: 地域
        Returns:
            スケーリングイベントリスト
        """
        events = []

        # 地域のメトリクスを取得
        metrics = self.collect_metrics(region)

        # アクティブなポリシーを評価
        for policy in self.scaling_policies.values():
            if not policy.is_active:
                continue

            if policy.region and policy.region != region:
                continue

            # ポリシーの評価
            scaling_event = self._evaluate_policy(policy, metrics, region)
            if scaling_event:
                events.append(scaling_event)

        return events

    def _evaluate_policy(self, policy: ScalingPolicy, metrics: Dict[str, float], region: DeploymentRegion) -> Optional[ScalingEvent]:
        """ポリシーを評価"""
        current_value = metrics.get(policy.target_metric, 0)

        # スケールアウト条件
        if current_value > policy.threshold_max:
            return ScalingEvent(
                event_id=f"scale_out_{int(time.time() * 1000000)}",
                timestamp=time.time(),
                scaling_type="scale_out",
                target_region=region,
                resource_change={"instances": policy.scale_out_increment},
                trigger_reason=f"{policy.target_metric}が上限閾値を超えました: {current_value:.2f} > {policy.threshold_max}"
            )

        # スケールイン条件
        elif current_value < policy.threshold_min:
            return ScalingEvent(
                event_id=f"scale_in_{int(time.time() * 1000000)}",
                timestamp=time.time(),
                scaling_type="scale_in",
                target_region=region,
                resource_change={"instances": -policy.scale_in_increment},
                trigger_reason=f"{policy.target_metric}が下限閾値未満です: {current_value:.2f} < {policy.threshold_min}"
            )

        return None

    def execute_scaling_event(self, event: ScalingEvent) -> bool:
        """
        スケーリングイベントを実行
        Args:
            event: スケーリングイベント
        Returns:
            実行成功フラグ
        """
        try:
            logger.info(f"スケーリング実行: {event.scaling_type} in {event.target_region.value}")

            # 実際の実装ではクラウドプロバイダーのAPIを呼び出し
            if event.scaling_type == "scale_out":
                # インスタンスを追加
                self._add_instances(event.target_region, event.resource_change.get("instances", 1))
            elif event.scaling_type == "scale_in":
                # インスタンスを削除
                self._remove_instances(event.target_region, abs(event.resource_change.get("instances", 1)))

            # イベントを履歴に記録
            self.scaling_history.append(event)

            return True

        except Exception as e:
            logger.error(f"スケーリング実行エラー: {e}")
            event.success = False
            return False

    def _add_instances(self, region: DeploymentRegion, count: int):
        """インスタンスを追加"""
        for i in range(count):
            node_id = f"node_{region.value}_{int(time.time() * 1000)}_{i}"

            node = ScalingNode(
                node_id=node_id,
                region=region,
                resource_type=ResourceType.CPU,
                current_capacity=100.0,
                max_capacity=100.0,
                cost_per_hour=0.10  # $0.10/時間
            )

            self.scaling_nodes[node_id] = node

    def _remove_instances(self, region: DeploymentRegion, count: int):
        """インスタンスを削除"""
        # その地域のノードを取得
        region_nodes = [node for node in self.scaling_nodes.values() if node.region == region]

        # 負荷の低いノードから削除
        nodes_to_remove = sorted(region_nodes, key=lambda n: n.utilization_rate)[:count]

        for node in nodes_to_remove:
            if node.node_id in self.scaling_nodes:
                del self.scaling_nodes[node.node_id]


class MultiRegionDeploymentManager:
    """マルチリージョンデプロイメントマネージャー"""

    def __init__(self, load_balancer: LoadBalancerManager, scaling_engine: AutoScalingEngine):
        """
        初期化
        Args:
            load_balancer: ロードバランサーマネージャー
            scaling_engine: 自動スケーリングエンジン
        """
        self.load_balancer = load_balancer
        self.scaling_engine = scaling_engine
        self.regional_deployments: Dict[DeploymentRegion, Dict[str, Any]] = defaultdict(dict)
        self.deployment_templates: Dict[str, Dict[str, Any]] = {}

    def register_deployment_template(self, template_id: str, template_config: Dict[str, Any]):
        """
        デプロイメントテンプレートを登録
        Args:
            template_id: テンプレートID
            template_config: テンプレート設定
        """
        self.deployment_templates[template_id] = template_config

    def deploy_to_region(self, region: DeploymentRegion, template_id: str, custom_config: Dict[str, Any] = None) -> str:
        """
        地域にデプロイ
        Args:
            region: 対象地域
            template_id: テンプレートID
            custom_config: カスタム設定
        Returns:
            デプロイメントID
        """
        deployment_id = f"deploy_{region.value}_{int(time.time() * 1000000)}"

        if template_id not in self.deployment_templates:
            raise ValueError(f"テンプレートが見つかりません: {template_id}")

        base_config = self.deployment_templates[template_id].copy()
        if custom_config:
            base_config.update(custom_config)

        deployment_info = {
            "deployment_id": deployment_id,
            "region": region,
            "template_id": template_id,
            "config": base_config,
            "status": "deploying",
            "created_at": time.time(),
            "nodes": []
        }

        self.regional_deployments[region][deployment_id] = deployment_info

        # 非同期でデプロイを実行
        asyncio.create_task(self._execute_regional_deployment(deployment_info))

        return deployment_id

    async def _execute_regional_deployment(self, deployment_info: Dict[str, Any]):
        """地域デプロイを実行"""
        try:
            region = deployment_info["region"]
            config = deployment_info["config"]

            # デプロイプロセスをシミュレーション
            await asyncio.sleep(5.0)  # デプロイ時間をシミュレーション

            # スケーリングノードを作成
            nodes_created = []
            for i in range(config.get("initial_nodes", 3)):
                node = ScalingNode(
                    node_id=f"node_{region.value}_{deployment_info['deployment_id']}_{i}",
                    region=region,
                    resource_type=ResourceType.CPU,
                    current_capacity=100.0,
                    max_capacity=100.0,
                    cost_per_hour=0.10
                )

                self.scaling_engine.register_scaling_node(node)
                nodes_created.append(node.node_id)

            deployment_info["status"] = "active"
            deployment_info["nodes"] = nodes_created

            logger.info(f"地域デプロイ完了: {region.value} - {len(nodes_created)}ノード")

        except Exception as e:
            deployment_info["status"] = "failed"
            logger.error(f"地域デプロイエラー: {e}")

    def update_regional_traffic(self, region: DeploymentRegion, traffic_percentage: float):
        """
        地域別トラフィックを更新
        Args:
            region: 地域
            traffic_percentage: トラフィック割合（%）
        """
        self.load_balancer.update_traffic_distribution(region, traffic_percentage)


class GlobalScalingManager:
    """グローバルスケーリング管理システム"""

    def __init__(self, db_path: str = "global_scaling.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self._init_db()
        self.load_balancer = LoadBalancerManager()
        self.scaling_engine = AutoScalingEngine(self.load_balancer)
        self.deployment_manager = MultiRegionDeploymentManager(self.load_balancer, self.scaling_engine)

        self.is_scaling_active = False
        self.scaling_thread: Optional[threading.Thread] = None

    def _init_db(self):
        """データベースを初期化"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scaling_nodes (
                    node_id TEXT PRIMARY KEY,
                    region TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    current_capacity REAL,
                    max_capacity REAL,
                    utilization_rate REAL,
                    status TEXT,
                    cost_per_hour REAL,
                    created_at REAL,
                    last_scaled REAL
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS scaling_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    scaling_type TEXT NOT NULL,
                    target_region TEXT NOT NULL,
                    resource_change TEXT,
                    trigger_reason TEXT,
                    cost_impact REAL,
                    success INTEGER
                )
            """)

            conn.commit()

    def initialize_global_scaling_system(self):
        """グローバルスケーリングシステムを初期化"""
        # デフォルトのスケーリングポリシーを設定
        self._setup_default_scaling_policies()

        # デフォルトのデプロイメントテンプレートを登録
        self._register_default_deployment_templates()

    def _setup_default_scaling_policies(self):
        """デフォルトのスケーリングポリシーを設定"""
        policies = [
            ScalingPolicy(
                policy_id="cpu_scaling_policy",
                name="CPU使用率ベーススケーリング",
                target_metric="cpu_utilization",
                threshold_min=30.0,
                threshold_max=80.0,
                scale_out_increment=2,
                scale_in_increment=1,
                cooldown_period=300
            ),
            ScalingPolicy(
                policy_id="memory_scaling_policy",
                name="メモリ使用率ベーススケーリング",
                target_metric="memory_utilization",
                threshold_min=40.0,
                threshold_max=85.0,
                scale_out_increment=1,
                scale_in_increment=1,
                cooldown_period=600
            )
        ]

        for policy in policies:
            self.scaling_engine.add_scaling_policy(policy)

    def _register_default_deployment_templates(self):
        """デフォルトのデプロイメントテンプレートを登録"""
        templates = {
            "web_service_template": {
                "service_type": "web",
                "initial_nodes": 3,
                "resource_requirements": {
                    "cpu": 2,
                    "memory": 4,
                    "storage": 50
                },
                "scaling_config": {
                    "min_nodes": 2,
                    "max_nodes": 20
                }
            },
            "api_service_template": {
                "service_type": "api",
                "initial_nodes": 2,
                "resource_requirements": {
                    "cpu": 1,
                    "memory": 2,
                    "storage": 20
                },
                "scaling_config": {
                    "min_nodes": 1,
                    "max_nodes": 10
                }
            }
        }

        for template_id, config in templates.items():
            self.deployment_manager.register_deployment_template(template_id, config)

    def start_global_scaling(self):
        """グローバルスケーリングを開始"""
        if not self.is_scaling_active:
            self.is_scaling_active = True
            self.scaling_thread = threading.Thread(target=self._scaling_loop, daemon=True)
            self.scaling_thread.start()

    def stop_global_scaling(self):
        """グローバルスケーリングを停止"""
        self.is_scaling_active = False
        if self.scaling_thread:
            self.scaling_thread.join()

    def deploy_service_globally(self, service_name: str, template_id: str) -> Dict[str, str]:
        """
        サービスをグローバルにデプロイ
        Args:
            service_name: サービス名
            template_id: テンプレートID
        Returns:
            地域別デプロイメントIDの辞書
        """
        deployment_ids = {}

        # 全地域にデプロイ
        for region in DeploymentRegion:
            try:
                deployment_id = self.deployment_manager.deploy_to_region(region, template_id, {
                    "service_name": service_name
                })
                deployment_ids[region.value] = deployment_id
            except Exception as e:
                logger.error(f"地域デプロイエラー: {region.value} - {e}")

        return deployment_ids

    def get_optimal_deployment_region(self, user_location: str, service_type: str = "default") -> DeploymentRegion:
        """
        最適なデプロイ地域を取得
        Args:
            user_location: ユーザーの場所
            service_type: サービスタイプ
        Returns:
            最適な地域
        """
        return self.load_balancer.get_optimal_region(user_location, service_type)

    def get_global_scaling_status(self) -> Dict[str, Any]:
        """グローバルスケーリングステータスを取得"""
        # 地域別ノード数
        region_node_counts = defaultdict(int)
        for node in self.scaling_engine.scaling_nodes.values():
            region_node_counts[node.region.value] += 1

        # 地域別メトリクス
        region_metrics = {}
        for region in DeploymentRegion:
            metrics = self.scaling_engine.collect_metrics(region)
            region_metrics[region.value] = metrics

        return {
            "is_active": self.is_scaling_active,
            "total_nodes": len(self.scaling_engine.scaling_nodes),
            "region_distribution": dict(region_node_counts),
            "scaling_policies": len(self.scaling_engine.scaling_policies),
            "recent_scaling_events": len(self.scaling_engine.scaling_history[-10:]),
            "regional_metrics": region_metrics,
            "traffic_distribution": dict(self.load_balancer.traffic_distribution)
        }

    def _scaling_loop(self):
        """スケーリングループ"""
        while self.is_scaling_active:
            try:
                # 全地域のスケーリングポリシーを評価
                for region in DeploymentRegion:
                    events = self.scaling_engine.evaluate_scaling_policies(region)

                    for event in events:
                        # スケーリングイベントを実行
                        success = self.scaling_engine.execute_scaling_event(event)
                        if success:
                            logger.info(f"スケーリング実行完了: {event.scaling_type} in {event.target_region.value}")

                time.sleep(60.0)  # 1分間隔でチェック

            except Exception as e:
                logger.error(f"スケーリングループエラー: {e}")


# 使用例
async def example_usage():
    manager = GlobalScalingManager()

    # システム初期化
    manager.initialize_global_scaling_system()

    # システム開始
    manager.start_global_scaling()

    # サービスをグローバルにデプロイ
    deployment_ids = manager.deploy_service_globally("web_service", "web_service_template")
    print(f"グローバルデプロイ開始: {len(deployment_ids)}地域")

    # トラフィック分散を更新
    manager.deployment_manager.update_regional_traffic(DeploymentRegion.NORTH_AMERICA, 40.0)
    manager.deployment_manager.update_regional_traffic(DeploymentRegion.ASIA_PACIFIC, 35.0)
    manager.deployment_manager.update_regional_traffic(DeploymentRegion.EUROPE, 25.0)

    # 最適な地域を取得
    optimal_region = manager.get_optimal_deployment_region("JP", "web")
    print(f"最適な地域: {optimal_region.value}")

    # スケーリングイベントを手動で実行（シミュレーション）
    scaling_event = ScalingEvent(
        event_id="manual_scale",
        timestamp=time.time(),
        scaling_type="scale_out",
        target_region=DeploymentRegion.ASIA_PACIFIC,
        resource_change={"instances": 2},
        trigger_reason="手動スケーリングテスト"
    )

    success = manager.scaling_engine.execute_scaling_event(scaling_event)
    print(f"手動スケーリング: {'成功' if success else '失敗'}")

    # グローバルステータス取得
    status = manager.get_global_scaling_status()
    print(f"グローバルスケーリングステータス: {status['total_nodes']}ノード")

    manager.stop_global_scaling()


if __name__ == "__main__":
    asyncio.run(example_usage())
