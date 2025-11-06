"""
高度な分析機能システム for BLNCS
ビジネスインテリジェンスと予測分析ダッシュボード機能を提供
"""

import time
import json
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict, deque
import statistics

logger = logging.getLogger(__name__)


class AnalysisType(Enum):
    """分析タイプ"""
    DESCRIPTIVE = "descriptive"      # 記述統計
    DIAGNOSTIC = "diagnostic"        # 診断分析
    PREDICTIVE = "predictive"        # 予測分析
    PRESCRIPTIVE = "prescriptive"    # 処方的分析


class MetricCategory(Enum):
    """メトリクスカテゴリ"""
    PERFORMANCE = "performance"
    BUSINESS = "business"
    SECURITY = "security"
    USER_EXPERIENCE = "user_experience"
    FINANCIAL = "financial"
    OPERATIONAL = "operational"


@dataclass
class AnalysisMetric:
    """分析メトリクス情報"""
    metric_id: str
    name: str
    category: MetricCategory
    data_type: str  # 'numeric', 'categorical', 'boolean', 'timestamp'
    unit: str = ""
    description: str = ""
    is_real_time: bool = False
    retention_days: int = 90


@dataclass
class AnalysisResult:
    """分析結果情報"""
    analysis_id: str
    analysis_type: AnalysisType
    metric_id: str
    period_start: float
    period_end: float
    results: Dict[str, Any]
    insights: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    generated_at: float = field(default_factory=time.time)


class DataWarehouse:
    """データウェアハウスシステム"""

    def __init__(self, db_path: str = "analytics.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self._init_db()
        self.metrics: Dict[str, AnalysisMetric] = {}

    def _init_db(self):
        """データベースを初期化"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS metric_definitions (
                    metric_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    data_type TEXT NOT NULL,
                    unit TEXT,
                    description TEXT,
                    is_real_time INTEGER DEFAULT 0,
                    retention_days INTEGER DEFAULT 90
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS metric_data (
                    id INTEGER PRIMARY KEY,
                    metric_id TEXT NOT NULL,
                    value REAL,
                    timestamp REAL NOT NULL,
                    tags TEXT,
                    created_at REAL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (metric_id) REFERENCES metric_definitions (metric_id)
                )
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_metric_data_timestamp
                ON metric_data(timestamp)
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_metric_data_metric
                ON metric_data(metric_id)
            """)

            conn.commit()

    def register_metric(self, metric: AnalysisMetric):
        """
        メトリクスを登録
        Args:
            metric: 分析メトリクス情報
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO metric_definitions
                    (metric_id, name, category, data_type, unit, description, is_real_time, retention_days)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    metric.metric_id, metric.name, metric.category.value,
                    metric.data_type, metric.unit, metric.description,
                    1 if metric.is_real_time else 0, metric.retention_days
                ))
                conn.commit()

            self.metrics[metric.metric_id] = metric

        except Exception as e:
            logger.error(f"メトリクス登録エラー: {e}")

    def store_metric_data(self, metric_id: str, value: float, timestamp: Optional[float] = None, tags: Dict[str, str] = None):
        """
        メトリクスデータを保存
        Args:
            metric_id: メトリクスID
            value: 値
            timestamp: タイムスタンプ
            tags: タグ情報
        """
        if metric_id not in self.metrics:
            logger.error(f"未登録のメトリクス: {metric_id}")
            return

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO metric_data (metric_id, value, timestamp, tags)
                    VALUES (?, ?, ?, ?)
                """, (
                    metric_id, value, timestamp or time.time(),
                    json.dumps(tags) if tags else None
                ))
                conn.commit()

        except Exception as e:
            logger.error(f"メトリクスデータ保存エラー: {e}")

    def get_metric_history(self, metric_id: str, start_time: Optional[float] = None,
                          end_time: Optional[float] = None, limit: int = 10000) -> List[Dict[str, Any]]:
        """
        メトリクス履歴を取得
        Args:
            metric_id: メトリクスID
            start_time: 開始時間
            end_time: 終了時間
            limit: 取得制限数
        Returns:
            データポイントリスト
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                query = "SELECT value, timestamp, tags FROM metric_data WHERE metric_id = ?"
                params = [metric_id]

                if start_time:
                    query += " AND timestamp >= ?"
                    params.append(start_time)

                if end_time:
                    query += " AND timestamp <= ?"
                    params.append(end_time)

                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)

                cursor = conn.execute(query, params)

                data_points = []
                for row in cursor.fetchall():
                    data_point = {
                        "value": row[0],
                        "timestamp": row[1],
                        "tags": json.loads(row[2]) if row[2] else {}
                    }
                    data_points.append(data_point)

                return data_points

        except Exception as e:
            logger.error(f"メトリクス履歴取得エラー: {e}")
            return []

    def cleanup_old_data(self):
        """古いデータをクリーンアップ"""
        cutoff_time = time.time() - (24 * 3600)  # デフォルトで全メトリクスをチェック

        try:
            with sqlite3.connect(self.db_path) as conn:
                # 各メトリクスの保持期間を確認して削除
                cursor = conn.execute("SELECT metric_id, retention_days FROM metric_definitions")
                for row in cursor.fetchall():
                    metric_id, retention_days = row
                    cutoff = time.time() - (retention_days * 24 * 3600)

                    conn.execute(
                        "DELETE FROM metric_data WHERE metric_id = ? AND timestamp < ?",
                        (metric_id, cutoff)
                    )

                conn.commit()

        except Exception as e:
            logger.error(f"データクリーンアップエラー: {e}")


class BusinessIntelligenceAnalyzer:
    """ビジネスインテリジェンスアナライザー"""

    def __init__(self, data_warehouse: DataWarehouse):
        """
        初期化
        Args:
            data_warehouse: データウェアハウスシステム
        """
        self.data_warehouse = data_warehouse
        self.analysis_cache: Dict[str, AnalysisResult] = {}

    def perform_descriptive_analysis(self, metric_id: str, days: int = 30) -> AnalysisResult:
        """
        記述統計分析を実行
        Args:
            metric_id: メトリクスID
            days: 分析期間（日）
        Returns:
            分析結果
        """
        cache_key = f"descriptive_{metric_id}_{days}"

        if cache_key in self.analysis_cache:
            return self.analysis_cache[cache_key]

        end_time = time.time()
        start_time = end_time - (days * 24 * 3600)

        data_points = self.data_warehouse.get_metric_history(metric_id, start_time, end_time)

        if not data_points:
            return AnalysisResult(
                analysis_id=f"analysis_{int(time.time() * 1000000)}",
                analysis_type=AnalysisType.DESCRIPTIVE,
                metric_id=metric_id,
                period_start=start_time,
                period_end=end_time,
                results={},
                insights=["データ不足のため分析できません"]
            )

        values = [dp["value"] for dp in data_points]

        results = {
            "count": len(values),
            "mean": statistics.mean(values),
            "median": statistics.median(values),
            "mode": statistics.mode(values) if len(set(values)) < len(values) * 0.1 else None,
            "std_dev": statistics.stdev(values) if len(values) > 1 else 0,
            "min": min(values),
            "max": max(values),
            "range": max(values) - min(values),
            "quartiles": {
                "q1": np.percentile(values, 25),
                "q3": np.percentile(values, 75)
            },
            "outliers": self._detect_outliers(values)
        }

        insights = self._generate_descriptive_insights(results, metric_id)

        analysis_result = AnalysisResult(
            analysis_id=f"analysis_{int(time.time() * 1000000)}",
            analysis_type=AnalysisType.DESCRIPTIVE,
            metric_id=metric_id,
            period_start=start_time,
            period_end=end_time,
            results=results,
            insights=insights,
            confidence_score=0.95
        )

        self.analysis_cache[cache_key] = analysis_result
        return analysis_result

    def _detect_outliers(self, values: List[float]) -> List[float]:
        """外れ値を検出"""
        if len(values) < 10:
            return []

        q1 = np.percentile(values, 25)
        q3 = np.percentile(values, 75)
        iqr = q3 - q1

        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr

        outliers = [v for v in values if v < lower_bound or v > upper_bound]
        return outliers

    def _generate_descriptive_insights(self, results: Dict[str, Any], metric_id: str) -> List[str]:
        """記述的洞察を生成"""
        insights = []

        if results["std_dev"] > results["mean"] * 0.3:
            insights.append(f"{metric_id}の変動が大きいです（標準偏差: {results['std_dev']:.2f}）")

        outlier_count = len(results["outliers"])
        if outlier_count > 0:
            insights.append(f"{outlier_count}個の外れ値が検出されました")

        if results["mean"] > results["median"]:
            insights.append(f"{metric_id}は正の歪度を示しています（平均 > 中央値）")

        return insights


class PredictiveAnalyzer:
    """予測アナライザー"""

    def __init__(self, data_warehouse: DataWarehouse):
        """
        初期化
        Args:
            data_warehouse: データウェアハウスシステム
        """
        self.data_warehouse = data_warehouse
        self.prediction_models: Dict[str, Dict[str, Any]] = {}

    def train_prediction_model(self, metric_id: str, days: int = 30) -> Dict[str, Any]:
        """
        予測モデルを学習
        Args:
            metric_id: メトリクスID
            days: 学習期間（日）
        Returns:
            モデル情報
        """
        end_time = time.time()
        start_time = end_time - (days * 24 * 3600)

        data_points = self.data_warehouse.get_metric_history(metric_id, start_time, end_time)

        if len(data_points) < 10:
            return {"error": "データ不足のためモデルを学習できません"}

        # 時系列データを準備
        timestamps = [dp["timestamp"] for dp in data_points]
        values = [dp["value"] for dp in data_points]

        # 線形回帰モデルを学習（簡易実装）
        x = np.array(timestamps)
        y = np.array(values)

        # トレンド計算
        slope, intercept = np.polyfit(x, y, 1)

        # 季節性分析（簡易版）
        if len(values) >= 24:  # 最低24データポイント必要
            seasonal_pattern = self._analyze_seasonality(values)
        else:
            seasonal_pattern = None

        model_info = {
            "metric_id": metric_id,
            "training_period": {"start": start_time, "end": end_time},
            "data_points": len(values),
            "trend_slope": slope,
            "trend_intercept": intercept,
            "seasonal_pattern": seasonal_pattern,
            "last_value": values[-1],
            "mean_error": self._calculate_prediction_error(x, y, slope, intercept)
        }

        self.prediction_models[metric_id] = model_info
        return model_info

    def predict_future_values(self, metric_id: str, future_hours: int = 24) -> Dict[str, Any]:
        """
        未来値を予測
        Args:
            metric_id: メトリクスID
            future_hours: 予測時間（時間）
        Returns:
            予測結果
        """
        if metric_id not in self.prediction_models:
            return {"error": "予測モデルが学習されていません"}

        model = self.prediction_models[metric_id]
        current_time = time.time()

        predictions = []
        for hour in range(1, future_hours + 1):
            future_timestamp = current_time + (hour * 3600)

            # トレンドベース予測
            trend_prediction = model["trend_slope"] * future_timestamp + model["trend_intercept"]

            # 季節性調整（簡易版）
            if model["seasonal_pattern"]:
                seasonal_adjustment = model["seasonal_pattern"].get(hour % 24, 0)
                trend_prediction += seasonal_adjustment

            predictions.append({
                "timestamp": future_timestamp,
                "predicted_value": trend_prediction,
                "confidence": self._calculate_prediction_confidence(hour, model)
            })

        return {
            "metric_id": metric_id,
            "predictions": predictions,
            "model_info": model,
            "prediction_horizon": future_hours
        }

    def _analyze_seasonality(self, values: List[float]) -> Dict[int, float]:
        """季節性を分析"""
        if len(values) < 48:  # 最低48データポイント必要
            return {}

        # 24時間周期で季節性を分析（簡易版）
        hourly_patterns = defaultdict(list)

        # タイムスタンプから時間を抽出してグループ化（簡易版）
        for i, value in enumerate(values):
            hour = (i * 24) % 24  # 簡易的な時間割り当て
            hourly_patterns[hour].append(value)

        # 各時間の平均値を計算
        seasonal_pattern = {}
        for hour, hour_values in hourly_patterns.items():
            if len(hour_values) >= 3:  # 最低3データポイント
                seasonal_pattern[hour] = statistics.mean(hour_values)

        return seasonal_pattern

    def _calculate_prediction_error(self, x: np.ndarray, y: np.ndarray, slope: float, intercept: float) -> float:
        """予測誤差を計算"""
        predictions = slope * x + intercept
        errors = np.abs(y - predictions)
        return np.mean(errors)

    def _calculate_prediction_confidence(self, hour: int, model: Dict[str, Any]) -> float:
        """予測信頼度を計算"""
        # 時間経過とともに信頼度が低下
        base_confidence = 0.9
        decay_factor = 0.05 * hour  # 1時間ごとに5%低下

        confidence = max(0.1, base_confidence - decay_factor)

        # 学習データの質による調整
        if model["data_points"] < 50:
            confidence *= 0.7  # データ不足ペナルティ

        return confidence


class AnalyticsDashboard:
    """分析ダッシュボードシステム"""

    def __init__(self, data_warehouse: DataWarehouse):
        """
        初期化
        Args:
            data_warehouse: データウェアハウスシステム
        """
        self.data_warehouse = data_warehouse
        self.bi_analyzer = BusinessIntelligenceAnalyzer(data_warehouse)
        self.predictive_analyzer = PredictiveAnalyzer(data_warehouse)
        self.dashboard_configs: Dict[str, Dict[str, Any]] = {}

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
        self.dashboard_configs[dashboard_id] = {
            "id": dashboard_id,
            "name": name,
            "description": description,
            "widgets": [],
            "created_at": time.time(),
            "updated_at": time.time()
        }

        return dashboard_id

    def add_widget_to_dashboard(self, dashboard_id: str, widget_config: Dict[str, Any]):
        """
        ダッシュボードにウィジェットを追加
        Args:
            dashboard_id: ダッシュボードID
            widget_config: ウィジェット設定
        """
        if dashboard_id in self.dashboard_configs:
            widget_id = f"widget_{len(self.dashboard_configs[dashboard_id]['widgets']) + 1}"
            widget_config["id"] = widget_id
            self.dashboard_configs[dashboard_id]["widgets"].append(widget_config)
            self.dashboard_configs[dashboard_id]["updated_at"] = time.time()

    def generate_dashboard_data(self, dashboard_id: str) -> Dict[str, Any]:
        """
        ダッシュボードデータを生成
        Args:
            dashboard_id: ダッシュボードID
        Returns:
            ダッシュボードデータ
        """
        if dashboard_id not in self.dashboard_configs:
            return {"error": "ダッシュボードが見つかりません"}

        dashboard = self.dashboard_configs[dashboard_id].copy()
        dashboard["data"] = {}

        for widget in dashboard["widgets"]:
            widget_type = widget.get("type")
            metric_id = widget.get("metric_id")

            if widget_type == "descriptive_chart" and metric_id:
                analysis_result = self.bi_analyzer.perform_descriptive_analysis(metric_id)
                widget["data"] = analysis_result.results
                widget["insights"] = analysis_result.insights

            elif widget_type == "predictive_chart" and metric_id:
                # 予測モデルを学習（初回のみ）
                if metric_id not in self.predictive_analyzer.prediction_models:
                    self.predictive_analyzer.train_prediction_model(metric_id)

                prediction_result = self.predictive_analyzer.predict_future_values(metric_id, 24)
                widget["data"] = prediction_result

        return dashboard

    def get_kpi_summary(self, metric_ids: List[str], days: int = 7) -> Dict[str, Any]:
        """
        KPIサマリーを取得
        Args:
            metric_ids: メトリクスIDリスト
            days: 集計期間（日）
        Returns:
            KPIサマリー情報
        """
        summary = {}

        for metric_id in metric_ids:
            if metric_id in self.data_warehouse.metrics:
                metric = self.data_warehouse.metrics[metric_id]

                # 記述分析を実行
                analysis = self.bi_analyzer.perform_descriptive_analysis(metric_id, days)

                summary[metric_id] = {
                    "name": metric.name,
                    "category": metric.category.value,
                    "current_value": analysis.results.get("mean", 0),
                    "trend": "up" if analysis.results.get("trend_slope", 0) > 0 else "down",
                    "change_percentage": 0,  # 実装は後で追加
                    "status": "normal"  # 実装は後で追加
                }

        return summary


class AdvancedAnalyticsManager:
    """高度な分析管理システム"""

    def __init__(self, db_path: str = "advanced_analytics.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self.data_warehouse = DataWarehouse(db_path)
        self.analytics_dashboard = AnalyticsDashboard(self.data_warehouse)

        self.is_analytics_active = False
        self.analytics_thread: Optional[threading.Thread] = None

    def initialize_analytics_system(self):
        """分析システムを初期化"""
        # デフォルトメトリクスを登録
        self._register_default_metrics()

        # デフォルトダッシュボードを作成
        self._create_default_dashboards()

    def _register_default_metrics(self):
        """デフォルトメトリクスを登録"""
        default_metrics = [
            AnalysisMetric(
                metric_id="system_cpu_usage",
                name="CPU使用率",
                category=MetricCategory.PERFORMANCE,
                data_type="numeric",
                unit="%",
                description="システム全体のCPU使用率",
                is_real_time=True
            ),
            AnalysisMetric(
                metric_id="system_memory_usage",
                name="メモリ使用率",
                category=MetricCategory.PERFORMANCE,
                data_type="numeric",
                unit="%",
                description="システム全体のメモリ使用率",
                is_real_time=True
            ),
            AnalysisMetric(
                metric_id="api_response_time",
                name="APIレスポンスタイム",
                category=MetricCategory.PERFORMANCE,
                data_type="numeric",
                unit="ms",
                description="APIエンドポイントの平均レスポンスタイム",
                is_real_time=True
            ),
            AnalysisMetric(
                metric_id="user_active_sessions",
                name="アクティブセッション数",
                category=MetricCategory.BUSINESS,
                data_type="numeric",
                description="現在のアクティブユーザーセッション数"
            ),
            AnalysisMetric(
                metric_id="transaction_volume",
                name="トランザクション量",
                category=MetricCategory.BUSINESS,
                data_type="numeric",
                unit="件",
                description="1日あたりのトランザクション処理件数"
            )
        ]

        for metric in default_metrics:
            self.data_warehouse.register_metric(metric)

    def _create_default_dashboards(self):
        """デフォルトダッシュボードを作成"""
        # パフォーマンスダッシュボード
        performance_dashboard = self.analytics_dashboard.create_dashboard(
            "performance_overview",
            "パフォーマンス概要",
            "システム全体のパフォーマンスメトリクスを表示"
        )

        self.analytics_dashboard.add_widget_to_dashboard(performance_dashboard, {
            "type": "descriptive_chart",
            "title": "CPU使用率トレンド",
            "metric_id": "system_cpu_usage",
            "chart_type": "line"
        })

        self.analytics_dashboard.add_widget_to_dashboard(performance_dashboard, {
            "type": "descriptive_chart",
            "title": "メモリ使用率トレンド",
            "metric_id": "system_memory_usage",
            "chart_type": "line"
        })

        # ビジネスダッシュボード
        business_dashboard = self.analytics_dashboard.create_dashboard(
            "business_insights",
            "ビジネス洞察",
            "ビジネスメトリクスと予測分析を表示"
        )

        self.analytics_dashboard.add_widget_to_dashboard(business_dashboard, {
            "type": "predictive_chart",
            "title": "トランザクション量予測",
            "metric_id": "transaction_volume",
            "chart_type": "line"
        })

    def start_analytics_system(self):
        """分析システムを開始"""
        if not self.is_analytics_active:
            self.is_analytics_active = True
            self.analytics_thread = threading.Thread(target=self._analytics_loop, daemon=True)
            self.analytics_thread.start()

    def stop_analytics_system(self):
        """分析システムを停止"""
        self.is_analytics_active = False
        if self.analytics_thread:
            self.analytics_thread.join()

    def record_metric(self, metric_id: str, value: float, tags: Dict[str, str] = None):
        """
        メトリクスを記録
        Args:
            metric_id: メトリクスID
            value: 値
            tags: タグ情報
        """
        self.data_warehouse.store_metric_data(metric_id, value, tags=tags)

    def get_performance_dashboard(self) -> Dict[str, Any]:
        """パフォーマンスダッシュボードを取得"""
        return self.analytics_dashboard.generate_dashboard_data("performance_overview")

    def get_business_insights(self) -> Dict[str, Any]:
        """ビジネス洞察を取得"""
        return self.analytics_dashboard.generate_dashboard_data("business_insights")

    def get_kpi_summary(self) -> Dict[str, Any]:
        """KPIサマリーを取得"""
        return self.analytics_dashboard.get_kpi_summary([
            "system_cpu_usage", "system_memory_usage", "api_response_time",
            "user_active_sessions", "transaction_volume"
        ])

    def _analytics_loop(self):
        """分析ループ"""
        while self.is_analytics_active:
            try:
                # 定期的なデータクリーンアップ
                if int(time.time()) % (24 * 3600) == 0:  # 毎日実行
                    self.data_warehouse.cleanup_old_data()

                time.sleep(3600)  # 1時間間隔
            except Exception as e:
                logger.error(f"分析ループエラー: {e}")


# 使用例
def example_usage():
    manager = AdvancedAnalyticsManager()

    # システム初期化
    manager.initialize_analytics_system()

    # システム開始
    manager.start_analytics_system()

    # メトリクス記録のシミュレーション
    for i in range(100):
        # CPU使用率
        cpu_usage = 50.0 + 10.0 * np.sin(i * 0.1) + np.random.normal(0, 2)
        manager.record_metric("system_cpu_usage", max(0, min(100, cpu_usage)))

        # メモリ使用率
        memory_usage = 60.0 + 5.0 * np.cos(i * 0.15) + np.random.normal(0, 1)
        manager.record_metric("system_memory_usage", max(0, min(100, memory_usage)))

        # トランザクション量（徐々に増加傾向）
        base_volume = 1000 + i * 5
        transaction_volume = base_volume + np.random.normal(0, 50)
        manager.record_metric("transaction_volume", transaction_volume)

        time.sleep(0.1)

    # パフォーマンスダッシュボード取得
    performance_data = manager.get_performance_dashboard()
    print(f"パフォーマンスデータ: {len(performance_data.get('widgets', []))}個のウィジェット")

    # KPIサマリー取得
    kpi_summary = manager.get_kpi_summary()
    print(f"KPIサマリー: {len(kpi_summary)}個のメトリクス")

    # 予測モデル学習と予測実行
    model_info = manager.analytics_dashboard.predictive_analyzer.train_prediction_model("transaction_volume")
    print(f"予測モデル学習完了: {model_info.get('data_points', 0)}データポイント")

    prediction = manager.analytics_dashboard.predictive_analyzer.predict_future_values("transaction_volume", 24)
    print(f"24時間予測完了: {len(prediction.get('predictions', []))}個の予測値")

    manager.stop_analytics_system()


if __name__ == "__main__":
    example_usage()
