"""
リアルタイム監視拡張システム for BLNCS
高度な可視化ダッシュボードとアラート機能を提供
"""

import asyncio
import json
import time
import threading
from typing import Any, Dict, List, Optional, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
import uuid
from collections import defaultdict, deque
import statistics

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """アラート重要度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(Enum):
    """アラートステータス"""
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


@dataclass
class MetricDataPoint:
    """メトリクスデータポイント"""
    metric_name: str
    value: float
    timestamp: float
    tags: Dict[str, str] = field(default_factory=dict)
    unit: str = ""


@dataclass
class AlertRule:
    """アラートルール情報"""
    rule_id: str
    name: str
    metric_name: str
    condition: str  # 'gt', 'lt', 'eq', 'range'
    threshold: float
    duration: int = 0  # 条件継続時間（秒）
    severity: AlertSeverity = AlertSeverity.MEDIUM
    description: str = ""
    is_enabled: bool = True
    created_at: float = field(default_factory=time.time)


@dataclass
class Alert:
    """アラート情報"""
    alert_id: str
    rule_id: str
    severity: AlertSeverity
    status: AlertStatus
    message: str
    metric_name: str
    current_value: float
    threshold: float
    triggered_at: float
    acknowledged_at: Optional[float] = None
    resolved_at: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class MetricsCollector:
    """メトリクス収集システム"""

    def __init__(self, retention_period: int = 3600):  # 1時間保持
        """
        初期化
        Args:
            retention_period: データ保持期間（秒）
        """
        self.retention_period = retention_period
        self.metrics_buffer: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.collection_callbacks: List[Callable] = []
        self.is_collecting = False
        self.collector_thread: Optional[threading.Thread] = None

    def start_collection(self, interval: float = 1.0):
        """
        メトリクス収集を開始
        Args:
            interval: 収集間隔（秒）
        """
        if not self.is_collecting:
            self.is_collecting = True
            self.collector_thread = threading.Thread(
                target=self._collection_loop,
                args=(interval,),
                daemon=True
            )
            self.collector_thread.start()

    def stop_collection(self):
        """メトリクス収集を停止"""
        self.is_collecting = False
        if self.collector_thread:
            self.collector_thread.join()

    def collect_metric(self, metric_name: str, value: float, tags: Dict[str, str] = None, unit: str = ""):
        """
        メトリクスを収集
        Args:
            metric_name: メトリクス名
            value: 値
            tags: タグ情報
            unit: 単位
        """
        data_point = MetricDataPoint(
            metric_name=metric_name,
            value=value,
            timestamp=time.time(),
            tags=tags or {},
            unit=unit
        )

        self.metrics_buffer[metric_name].append(data_point)

        # 古いデータを削除
        cutoff_time = time.time() - self.retention_period
        self.metrics_buffer[metric_name] = deque(
            [dp for dp in self.metrics_buffer[metric_name] if dp.timestamp > cutoff_time]
        )

        # 収集コールバック実行
        for callback in self.collection_callbacks:
            try:
                callback(data_point)
            except Exception as e:
                logger.error(f"収集コールバックエラー: {e}")

    def get_metric_history(self, metric_name: str, limit: int = 100) -> List[MetricDataPoint]:
        """
        メトリクス履歴を取得
        Args:
            metric_name: メトリクス名
            limit: 取得数制限
        Returns:
            データポイントリスト
        """
        return list(self.metrics_buffer[metric_name])[-limit:]

    def get_metric_summary(self, metric_name: str) -> Dict[str, Any]:
        """
        メトリクス要約を取得
        Args:
            metric_name: メトリクス名
        Returns:
            要約統計情報
        """
        data_points = self.metrics_buffer[metric_name]

        if not data_points:
            return {}

        values = [dp.value for dp in data_points]

        return {
            "count": len(values),
            "min": min(values),
            "max": max(values),
            "avg": statistics.mean(values),
            "median": statistics.median(values),
            "latest": values[-1] if values else None,
            "time_range": {
                "start": data_points[0].timestamp if data_points else None,
                "end": data_points[-1].timestamp if data_points else None
            }
        }

    def add_collection_callback(self, callback: Callable):
        """
        収集コールバックを追加
        Args:
            callback: コールバック関数
        """
        self.collection_callbacks.append(callback)

    def _collection_loop(self):
        """収集ループ"""
        while self.is_collecting:
            try:
                # システムメトリクスを収集（簡易実装）
                self._collect_system_metrics()
                time.sleep(1.0)
            except Exception as e:
                logger.error(f"収集ループエラー: {e}")

    def _collect_system_metrics(self):
        """システムメトリクスを収集"""
        try:
            import psutil

            # CPU使用率
            cpu_percent = psutil.cpu_percent(interval=1)
            self.collect_metric("system.cpu.usage", cpu_percent, unit="%")

            # メモリ使用率
            memory = psutil.virtual_memory()
            self.collect_metric("system.memory.usage", memory.percent, unit="%")

            # ディスク使用率
            disk = psutil.disk_usage('/')
            self.collect_metric("system.disk.usage", disk.percent, unit="%")

            # ネットワークI/O
            net_io = psutil.net_io_counters()
            self.collect_metric("system.network.bytes_sent", net_io.bytes_sent, unit="bytes")
            self.collect_metric("system.network.bytes_recv", net_io.bytes_recv, unit="bytes")

        except ImportError:
            # psutilが利用できない場合はシミュレーションデータ
            self.collect_metric("system.cpu.usage", 50.0 + (time.time() % 20), unit="%")
            self.collect_metric("system.memory.usage", 60.0 + (time.time() % 10), unit="%")


class AlertEngine:
    """アラートエンジン"""

    def __init__(self, metrics_collector: MetricsCollector):
        """
        初期化
        Args:
            metrics_collector: メトリクス収集システム
        """
        self.metrics_collector = metrics_collector
        self.alert_rules: Dict[str, AlertRule] = {}
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history: List[Alert] = []
        self.evaluation_callbacks: List[Callable] = []
        self.is_evaluating = False
        self.evaluator_thread: Optional[threading.Thread] = None

    def start_evaluation(self, interval: float = 5.0):
        """
        アラート評価を開始
        Args:
            interval: 評価間隔（秒）
        """
        if not self.is_evaluating:
            self.is_evaluating = True
            self.evaluator_thread = threading.Thread(
                target=self._evaluation_loop,
                args=(interval,),
                daemon=True
            )
            self.evaluator_thread.start()

    def stop_evaluation(self):
        """アラート評価を停止"""
        self.is_evaluating = False
        if self.evaluator_thread:
            self.evaluator_thread.join()

    def add_alert_rule(self, rule: AlertRule):
        """
        アラートルールを追加
        Args:
            rule: アラートルール
        """
        self.alert_rules[rule.rule_id] = rule

    def remove_alert_rule(self, rule_id: str):
        """
        アラートルールを削除
        Args:
            rule_id: ルールID
        """
        if rule_id in self.alert_rules:
            del self.alert_rules[rule_id]

    def evaluate_alerts(self):
        """アラートを評価"""
        for rule in self.alert_rules.values():
            if not rule.is_enabled:
                continue

            try:
                self._evaluate_rule(rule)
            except Exception as e:
                logger.error(f"ルール評価エラー: {rule.rule_id} - {e}")

    def _evaluate_rule(self, rule: AlertRule):
        """ルールを評価"""
        # 最新のメトリクス値を取得
        history = self.metrics_collector.get_metric_history(rule.metric_name, limit=10)

        if not history:
            return

        latest_value = history[-1].value
        condition_met = self._check_condition(latest_value, rule.condition, rule.threshold)

        if condition_met:
            self._trigger_alert(rule, latest_value)
        else:
            self._resolve_alert(rule)

    def _check_condition(self, value: float, condition: str, threshold: float) -> bool:
        """条件をチェック"""
        if condition == "gt":
            return value > threshold
        elif condition == "lt":
            return value < threshold
        elif condition == "eq":
            return abs(value - threshold) < 0.01  # 許容誤差
        elif condition == "range":
            # 範囲チェック（簡易実装）
            return value > threshold
        else:
            return False

    def _trigger_alert(self, rule: AlertRule, current_value: float):
        """アラートを発行"""
        alert_id = f"alert_{int(time.time() * 1000000)}"

        alert = Alert(
            alert_id=alert_id,
            rule_id=rule.rule_id,
            severity=rule.severity,
            status=AlertStatus.ACTIVE,
            message=f"{rule.metric_name} が閾値を超えました: {current_value} > {rule.threshold}",
            metric_name=rule.metric_name,
            current_value=current_value,
            threshold=rule.threshold,
            triggered_at=time.time()
        )

        self.active_alerts[alert_id] = alert
        self.alert_history.append(alert)

        logger.warning(f"アラート発行: {alert.message}")

        # 評価コールバック実行
        for callback in self.evaluation_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"評価コールバックエラー: {e}")

    def _resolve_alert(self, rule: AlertRule):
        """アラートを解決"""
        # 対応するアクティブアラートを解決
        for alert in list(self.active_alerts.values()):
            if alert.rule_id == rule.rule_id and alert.status == AlertStatus.ACTIVE:
                alert.status = AlertStatus.RESOLVED
                alert.resolved_at = time.time()
                logger.info(f"アラート解決: {alert.alert_id}")

    def acknowledge_alert(self, alert_id: str):
        """
        アラートを確認済みに設定
        Args:
            alert_id: アラートID
        """
        if alert_id in self.active_alerts:
            self.active_alerts[alert_id].status = AlertStatus.ACKNOWLEDGED
            self.active_alerts[alert_id].acknowledged_at = time.time()

    def get_active_alerts(self) -> List[Alert]:
        """アクティブアラートを取得"""
        return [alert for alert in self.active_alerts.values() if alert.status == AlertStatus.ACTIVE]

    def get_alert_history(self, limit: int = 100) -> List[Alert]:
        """アラート履歴を取得"""
        return self.alert_history[-limit:]

    def add_evaluation_callback(self, callback: Callable):
        """
        評価コールバックを追加
        Args:
            callback: コールバック関数
        """
        self.evaluation_callbacks.append(callback)

    def _evaluation_loop(self):
        """評価ループ"""
        while self.is_evaluating:
            try:
                self.evaluate_alerts()
                time.sleep(5.0)  # 5秒間隔
            except Exception as e:
                logger.error(f"評価ループエラー: {e}")


class VisualizationManager:
    """可視化マネージャー"""

    def __init__(self, metrics_collector: MetricsCollector):
        """
        初期化
        Args:
            metrics_collector: メトリクス収集システム
        """
        self.metrics_collector = metrics_collector
        self.dashboards: Dict[str, Dict[str, Any]] = {}
        self.chart_configs: Dict[str, Dict[str, Any]] = {}

    def create_dashboard(self, dashboard_id: str, name: str, description: str = "") -> str:
        """
        ダッシュボードを作成
        Args:
            dashboard_id: ダッシュボードID
            name: ダッシュボード名
            description: 説明
        Returns:
            作成されたダッシュボードID
        """
        self.dashboards[dashboard_id] = {
            "id": dashboard_id,
            "name": name,
            "description": description,
            "charts": [],
            "created_at": time.time(),
            "updated_at": time.time()
        }

        return dashboard_id

    def add_chart_to_dashboard(self, dashboard_id: str, chart_config: Dict[str, Any]):
        """
        ダッシュボードにチャートを追加
        Args:
            dashboard_id: ダッシュボードID
            chart_config: チャート設定
        """
        if dashboard_id in self.dashboards:
            chart_id = f"chart_{len(self.dashboards[dashboard_id]['charts']) + 1}"
            chart_config["id"] = chart_id
            self.dashboards[dashboard_id]["charts"].append(chart_config)
            self.dashboards[dashboard_id]["updated_at"] = time.time()

    def get_dashboard_data(self, dashboard_id: str) -> Optional[Dict[str, Any]]:
        """
        ダッシュボードデータを取得
        Args:
            dashboard_id: ダッシュボードID
        Returns:
            ダッシュボードデータ（存在しない場合はNone）
        """
        if dashboard_id not in self.dashboards:
            return None

        dashboard = self.dashboards[dashboard_id].copy()

        # 各チャートのデータを取得
        for chart in dashboard["charts"]:
            metric_name = chart.get("metric_name")
            if metric_name:
                history = self.metrics_collector.get_metric_history(metric_name, limit=chart.get("data_points", 100))
                chart["data"] = [
                    {"timestamp": dp.timestamp, "value": dp.value}
                    for dp in history
                ]

        return dashboard

    def generate_realtime_data(self, dashboard_id: str) -> Dict[str, Any]:
        """
        リアルタイムデータを生成
        Args:
            dashboard_id: ダッシュボードID
        Returns:
            リアルタイムデータ
        """
        dashboard_data = self.get_dashboard_data(dashboard_id)

        if not dashboard_data:
            return {"error": "ダッシュボードが見つかりません"}

        realtime_data = {
            "dashboard_id": dashboard_id,
            "timestamp": time.time(),
            "charts": []
        }

        for chart in dashboard_data["charts"]:
            chart_info = {
                "chart_id": chart["id"],
                "metric_name": chart.get("metric_name"),
                "current_value": None,
                "data_points": chart.get("data", [])
            }

            # 最新値を取得
            if chart["data"]:
                chart_info["current_value"] = chart["data"][-1]["value"]

            realtime_data["charts"].append(chart_info)

        return realtime_data


class MonitoringDashboard:
    """監視ダッシュボード統合システム"""

    def __init__(self, db_path: str = "monitoring.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self.metrics_collector = MetricsCollector()
        self.alert_engine = AlertEngine(self.metrics_collector)
        self.visualization_manager = VisualizationManager(self.metrics_collector)

        self.is_monitoring = False
        self.monitoring_thread: Optional[threading.Thread] = None

    def start_monitoring(self):
        """監視システムを開始"""
        if not self.is_monitoring:
            self.is_monitoring = True
            self.metrics_collector.start_collection()
            self.alert_engine.start_evaluation()

            self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitoring_thread.start()

    def stop_monitoring(self):
        """監視システムを停止"""
        self.is_monitoring = False
        self.metrics_collector.stop_collection()
        self.alert_engine.stop_evaluation()

        if self.monitoring_thread:
            self.monitoring_thread.join()

    def add_alert_rule(self, metric_name: str, threshold: float, condition: str = "gt", severity: AlertSeverity = AlertSeverity.MEDIUM):
        """
        アラートルールを追加
        Args:
            metric_name: メトリクス名
            threshold: 閾値
            condition: 条件
            severity: 重要度
        """
        rule_id = f"rule_{int(time.time() * 1000000)}"
        rule = AlertRule(
            rule_id=rule_id,
            name=f"{metric_name}_{condition}_{threshold}",
            metric_name=metric_name,
            condition=condition,
            threshold=threshold,
            severity=severity,
            description=f"{metric_name}が{threshold}を{condition}した場合のアラート"
        )

        self.alert_engine.add_alert_rule(rule)

    def create_system_dashboard(self):
        """システム監視ダッシュボードを作成"""
        dashboard_id = "system_overview"

        self.visualization_manager.create_dashboard(
            dashboard_id,
            "システム概要",
            "システム全体のメトリクスとアラートを表示"
        )

        # CPU使用率チャート
        self.visualization_manager.add_chart_to_dashboard(dashboard_id, {
            "title": "CPU使用率",
            "type": "line",
            "metric_name": "system.cpu.usage",
            "color": "#ff6b6b",
            "data_points": 100
        })

        # メモリ使用率チャート
        self.visualization_manager.add_chart_to_dashboard(dashboard_id, {
            "title": "メモリ使用率",
            "type": "line",
            "metric_name": "system.memory.usage",
            "color": "#4ecdc4",
            "data_points": 100
        })

        # ディスク使用率チャート
        self.visualization_manager.add_chart_to_dashboard(dashboard_id, {
            "title": "ディスク使用率",
            "type": "line",
            "metric_name": "system.disk.usage",
            "color": "#45b7d1",
            "data_points": 100
        })

    def collect_custom_metric(self, name: str, value: float, tags: Dict[str, str] = None):
        """
        カスタムメトリクスを収集
        Args:
            name: メトリクス名
            value: 値
            tags: タグ情報
        """
        self.metrics_collector.collect_metric(name, value, tags)

    def get_system_status(self) -> Dict[str, Any]:
        """システムステータスを取得"""
        return {
            "is_monitoring": self.is_monitoring,
            "active_alerts": len(self.alert_engine.get_active_alerts()),
            "total_metrics": len(self.metrics_collector.metrics_buffer),
            "uptime": time.time() - (self.metrics_collector._start_time if hasattr(self.metrics_collector, '_start_time') else time.time())
        }

    def _monitoring_loop(self):
        """監視ループ"""
        while self.is_monitoring:
            try:
                # 追加の監視処理をここに実装
                time.sleep(10.0)
            except Exception as e:
                logger.error(f"監視ループエラー: {e}")


# 使用例
def example_usage():
    dashboard = MonitoringDashboard()

    # システム開始
    dashboard.start_monitoring()

    # システムダッシュボード作成
    dashboard.create_system_dashboard()

    # アラートルール追加
    dashboard.add_alert_rule("system.cpu.usage", 80.0, "gt", AlertSeverity.HIGH)
    dashboard.add_alert_rule("system.memory.usage", 90.0, "gt", AlertSeverity.CRITICAL)

    # カスタムメトリクス収集
    for i in range(50):
        dashboard.collect_custom_metric("custom.transactions", 100 + i * 2)
        time.sleep(0.5)

    # システムステータス表示
    status = dashboard.get_system_status()
    print(f"システムステータス: {status}")

    # アクティブアラート表示
    alerts = dashboard.alert_engine.get_active_alerts()
    print(f"アクティブアラート: {len(alerts)}件")

    dashboard.stop_monitoring()


if __name__ == "__main__":
    example_usage()
