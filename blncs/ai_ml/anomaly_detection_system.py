"""
機械学習ベースの異常検知システム for BLNCS
リアルタイム異常検知と予測機能を提供
"""

import time
import json
import threading
from typing import Any, Dict, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from collections import defaultdict, deque
import logging
import numpy as np
from datetime import datetime, timedelta
import pickle
import os

logger = logging.getLogger(__name__)


@dataclass
class MetricData:
    """メトリクスデータ情報"""
    timestamp: float
    value: float
    metric_type: str
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class AnomalyResult:
    """異常検知結果情報"""
    metric_type: str
    timestamp: float
    value: float
    anomaly_score: float
    is_anomaly: bool
    confidence: float
    description: str = ""


class SimpleAnomalyDetector:
    """簡易異常検知アルゴリズム"""

    def __init__(self, sensitivity: float = 2.0, window_size: int = 100):
        """
        初期化
        Args:
            sensitivity: 異常検知の感度（標準偏差の倍率）
            window_size: 分析ウィンドウサイズ
        """
        self.sensitivity = sensitivity
        self.window_size = window_size
        self.baselines: Dict[str, Dict[str, float]] = defaultdict(dict)

    def fit(self, data: List[MetricData]) -> Dict[str, Any]:
        """
        学習データからベースラインを構築
        Args:
            data: 学習データ
        Returns:
            学習結果統計
        """
        stats = {}

        for metric_type in set(d.metric_type for d in data):
            metric_data = [d.value for d in data if d.metric_type == metric_type]

            if len(metric_data) >= 10:  # 最低データ数
                mean_val = np.mean(metric_data)
                std_val = np.std(metric_data)

                self.baselines[metric_type] = {
                    'mean': mean_val,
                    'std': std_val,
                    'min': np.min(metric_data),
                    'max': np.max(metric_data)
                }

                stats[metric_type] = {
                    'count': len(metric_data),
                    'mean': mean_val,
                    'std': std_val
                }

        return stats

    def detect(self, data: MetricData) -> AnomalyResult:
        """
        異常検知を実行
        Args:
            data: 検知対象データ
        Returns:
            異常検知結果
        """
        metric_type = data.metric_type

        if metric_type not in self.baselines:
            return AnomalyResult(
                metric_type=metric_type,
                timestamp=data.timestamp,
                value=data.value,
                anomaly_score=0.0,
                is_anomaly=False,
                confidence=0.0,
                description="ベースラインが存在しません"
            )

        baseline = self.baselines[metric_type]
        mean_val = baseline['mean']
        std_val = baseline['std']

        # Zスコア計算
        if std_val > 0:
            z_score = abs(data.value - mean_val) / std_val
            anomaly_score = min(z_score / self.sensitivity, 1.0)
        else:
            anomaly_score = 0.0

        is_anomaly = anomaly_score > 0.7  # 閾値
        confidence = min(anomaly_score, 1.0)

        description = ""
        if is_anomaly:
            if data.value > baseline['max']:
                description = "通常範囲を超える高い値"
            elif data.value < baseline['min']:
                description = "通常範囲を下回る低い値"
            else:
                description = "異常な変動パターン"

        return AnomalyResult(
            metric_type=metric_type,
            timestamp=data.timestamp,
            value=data.value,
            anomaly_score=anomaly_score,
            is_anomaly=is_anomaly,
            confidence=confidence,
            description=description
        )


class TimeSeriesAnomalyDetector:
    """時系列異常検知アルゴリズム"""

    def __init__(self, seasonal_period: int = 24, trend_sensitivity: float = 1.5):
        """
        初期化
        Args:
            seasonal_period: 季節性周期（時間単位）
            trend_sensitivity: トレンド検知感度
        """
        self.seasonal_period = seasonal_period
        self.trend_sensitivity = trend_sensitivity
        self.historical_data: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.trend_models: Dict[str, Dict[str, float]] = defaultdict(dict)

    def update_model(self, data: MetricData):
        """
        モデルを更新
        Args:
            data: 新しいデータ
        """
        metric_type = data.metric_type
        self.historical_data[metric_type].append(data)

        # 簡易トレンド分析
        if len(self.historical_data[metric_type]) >= 10:
            values = [d.value for d in self.historical_data[metric_type]]
            self.trend_models[metric_type] = {
                'slope': self._calculate_slope(values),
                'seasonal_avg': np.mean(values[-self.seasonal_period:]) if len(values) >= self.seasonal_period else np.mean(values)
            }

    def detect_anomaly(self, data: MetricData) -> AnomalyResult:
        """
        時系列異常検知を実行
        Args:
            data: 検知対象データ
        Returns:
            異常検知結果
        """
        metric_type = data.metric_type

        if metric_type not in self.trend_models:
            return AnomalyResult(
                metric_type=metric_type,
                timestamp=data.timestamp,
                value=data.value,
                anomaly_score=0.0,
                is_anomaly=False,
                confidence=0.0,
                description="学習データ不足"
            )

        model = self.trend_models[metric_type]
        expected_value = model['seasonal_avg'] + model['slope'] * (len(self.historical_data[metric_type]) % self.seasonal_period)

        # 異常スコア計算
        deviation = abs(data.value - expected_value)
        baseline_std = np.std([d.value for d in self.historical_data[metric_type][-50:]]) if len(self.historical_data[metric_type]) >= 50 else 1.0

        if baseline_std > 0:
            anomaly_score = min(deviation / (baseline_std * self.trend_sensitivity), 1.0)
        else:
            anomaly_score = 0.0

        is_anomaly = anomaly_score > 0.6
        confidence = min(anomaly_score, 1.0)

        description = ""
        if is_anomaly:
            if data.value > expected_value:
                description = "予想値を超える上昇傾向"
            else:
                description = "予想値未満の下降傾向"

        return AnomalyResult(
            metric_type=metric_type,
            timestamp=data.timestamp,
            value=data.value,
            anomaly_score=anomaly_score,
            is_anomaly=is_anomaly,
            confidence=confidence,
            description=description
        )

    def _calculate_slope(self, values: List[float]) -> float:
        """単純な線形トレンドの傾きを計算"""
        if len(values) < 2:
            return 0.0

        x = np.arange(len(values))
        y = np.array(values)

        # 最小二乗法で傾きを計算
        slope = np.polyfit(x, y, 1)[0]
        return slope


class AnomalyDetectionEngine:
    """異常検知エンジン"""

    def __init__(self, detectors: Optional[List[Any]] = None):
        """
        初期化
        Args:
            detectors: 使用する検知アルゴリズムリスト
        """
        self.detectors = detectors or [SimpleAnomalyDetector(), TimeSeriesAnomalyDetector()]
        self.metric_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self.anomaly_callbacks: List[Callable] = []
        self.is_running = False
        self.engine_thread: Optional[threading.Thread] = None

    def start_detection(self, interval: float = 1.0):
        """
        異常検知を開始
        Args:
            interval: 検知間隔（秒）
        """
        if not self.is_running:
            self.is_running = True
            self.engine_thread = threading.Thread(
                target=self._detection_loop,
                args=(interval,),
                daemon=True
            )
            self.engine_thread.start()

    def stop_detection(self):
        """異常検知を停止"""
        self.is_running = False
        if self.engine_thread:
            self.engine_thread.join()

    def add_metric(self, metric_data: MetricData):
        """
        メトリクスデータを追加
        Args:
            metric_data: メトリクスデータ
        """
        self.metric_history[metric_data.metric_type].append(metric_data)

        # 検知器のモデルを更新
        for detector in self.detectors:
            if hasattr(detector, 'update_model'):
                detector.update_model(metric_data)

    def detect_anomaly(self, metric_data: MetricData) -> List[AnomalyResult]:
        """
        異常検知を実行
        Args:
            metric_data: 検知対象データ
        Returns:
            異常検知結果リスト
        """
        results = []

        for detector in self.detectors:
            try:
                if hasattr(detector, 'detect'):
                    result = detector.detect(metric_data)
                elif hasattr(detector, 'detect_anomaly'):
                    result = detector.detect_anomaly(metric_data)
                else:
                    continue

                results.append(result)

                # 異常検知時のコールバック実行
                if result.is_anomaly:
                    for callback in self.anomaly_callbacks:
                        try:
                            callback(result)
                        except Exception as e:
                            logger.error(f"異常検知コールバックエラー: {e}")

            except Exception as e:
                logger.error(f"異常検知エラー: {e}")

        return results

    def add_anomaly_callback(self, callback: Callable):
        """
        異常検知コールバックを追加
        Args:
            callback: コールバック関数
        """
        self.anomaly_callbacks.append(callback)

    def get_recent_anomalies(self, limit: int = 100) -> List[AnomalyResult]:
        """
        最近の異常を取得
        Args:
            limit: 取得数制限
        Returns:
            異常結果リスト
        """
        # 簡易実装：実際には異常結果を保存する仕組みが必要
        return []

    def _detection_loop(self, interval: float):
        """検知ループ"""
        while self.is_running:
            try:
                # 各メトリクスタイプの最新データをチェック
                current_time = time.time()
                for metric_type, history in self.metric_history.items():
                    if history:
                        latest_data = history[-1]

                        # 最後の検知から十分時間が経過している場合のみ検知
                        if current_time - latest_data.timestamp > interval:
                            self.detect_anomaly(latest_data)

                time.sleep(interval)
            except Exception as e:
                logger.error(f"検知ループエラー: {e}")


class PredictiveAnomalySystem:
    """予測的異常検知システム"""

    def __init__(self, prediction_window: int = 10):
        """
        初期化
        Args:
            prediction_window: 予測ウィンドウサイズ
        """
        self.prediction_window = prediction_window
        self.prediction_models: Dict[str, Dict[str, Any]] = defaultdict(dict)
        self.anomaly_predictions: Dict[str, List[Tuple[float, float]]] = defaultdict(list)

    def train_prediction_model(self, metric_type: str, data: List[MetricData]):
        """
        予測モデルを学習
        Args:
            metric_type: メトリクスタイプ
            data: 学習データ
        """
        if len(data) < self.prediction_window * 2:
            return

        values = [d.value for d in data]

        # 簡易な移動平均予測モデル
        self.prediction_models[metric_type] = {
            'window_size': self.prediction_window,
            'recent_values': values[-self.prediction_window:],
            'mean': np.mean(values),
            'trend': self._calculate_trend(values)
        }

    def predict_anomaly(self, metric_type: str, current_value: float) -> float:
        """
        異常予測を実行
        Args:
            metric_type: メトリクスタイプ
            current_value: 現在の値
        Returns:
            異常予測スコア（0-1）
        """
        if metric_type not in self.prediction_models:
            return 0.0

        model = self.prediction_models[metric_type]
        expected_value = model['mean'] + model['trend']

        # 予測偏差を計算
        deviation = abs(current_value - expected_value)
        max_deviation = model['mean'] * 0.5  # 最大偏差の50%

        if max_deviation > 0:
            prediction_score = min(deviation / max_deviation, 1.0)
        else:
            prediction_score = 0.0

        # 予測履歴に追加
        self.anomaly_predictions[metric_type].append((time.time(), prediction_score))

        # 古い予測を削除
        cutoff_time = time.time() - 300  # 5分前
        self.anomaly_predictions[metric_type] = [
            (t, s) for t, s in self.anomaly_predictions[metric_type] if t > cutoff_time
        ]

        return prediction_score

    def _calculate_trend(self, values: List[float]) -> float:
        """トレンドを計算"""
        if len(values) < 5:
            return 0.0

        # 単純な線形回帰でトレンドを計算
        x = np.arange(len(values))
        y = np.array(values)

        try:
            slope = np.polyfit(x, y, 1)[0]
            return slope
        except:
            return 0.0


class AnomalyDetectionManager:
    """異常検知管理システム"""

    def __init__(self, db_path: str = "anomaly_detection.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self.detectors = [
            SimpleAnomalyDetector(sensitivity=2.0),
            TimeSeriesAnomalyDetector(seasonal_period=24)
        ]
        self.engine = AnomalyDetectionEngine(self.detectors)
        self.predictive_system = PredictiveAnomalySystem()
        self._init_db()

    def _init_db(self):
        """データベースを初期化"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS anomaly_results (
                        id INTEGER PRIMARY KEY,
                        metric_type TEXT NOT NULL,
                        timestamp REAL NOT NULL,
                        value REAL NOT NULL,
                        anomaly_score REAL NOT NULL,
                        is_anomaly INTEGER NOT NULL,
                        confidence REAL NOT NULL,
                        description TEXT,
                        created_at REAL DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.commit()
        except Exception as e:
            logger.error(f"異常検知DB初期化エラー: {e}")

    def start_system(self, detection_interval: float = 1.0):
        """
        システムを開始
        Args:
            detection_interval: 検知間隔（秒）
        """
        self.engine.start_detection(detection_interval)

        # 異常検知コールバックを設定
        def on_anomaly_detected(result: AnomalyResult):
            self._save_anomaly_result(result)

        self.engine.add_anomaly_callback(on_anomaly_detected)

    def stop_system(self):
        """システムを停止"""
        self.engine.stop_detection()

    def process_metric(self, metric_type: str, value: float, tags: Dict[str, str] = None):
        """
        メトリクスを処理
        Args:
            metric_type: メトリクスタイプ
            value: 値
            tags: タグ情報
        """
        metric_data = MetricData(
            timestamp=time.time(),
            value=value,
            metric_type=metric_type,
            tags=tags or {}
        )

        # 検知エンジンに追加
        self.engine.add_metric(metric_data)

        # 異常検知を実行
        results = self.engine.detect_anomaly(metric_data)

        # 予測システムで異常予測
        prediction_score = self.predictive_system.predict_anomaly(metric_type, value)

        # 結果をログ出力
        for result in results:
            if result.is_anomaly:
                logger.warning(f"異常検知: {result.metric_type} = {result.value} (スコア: {result.anomaly_score:.3f})")

    def train_models(self, training_data: Dict[str, List[MetricData]]):
        """
        モデルを学習
        Args:
            training_data: 学習データ（メトリクスタイプ別）
        """
        for metric_type, data in training_data.items():
            # 検知器の学習
            for detector in self.detectors:
                if hasattr(detector, 'fit'):
                    detector.fit(data)

            # 予測システムの学習
            self.predictive_system.train_prediction_model(metric_type, data)

    def get_anomaly_stats(self) -> Dict[str, Any]:
        """異常検知統計を取得"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT metric_type, COUNT(*) as count, AVG(anomaly_score) as avg_score
                    FROM anomaly_results
                    WHERE is_anomaly = 1 AND timestamp > ?
                    GROUP BY metric_type
                """, (time.time() - 3600,))  # 過去1時間

                stats = {}
                for row in cursor.fetchall():
                    stats[row[0]] = {
                        'count': row[1],
                        'avg_score': row[2]
                    }

                return stats
        except Exception as e:
            logger.error(f"統計取得エラー: {e}")
            return {}

    def _save_anomaly_result(self, result: AnomalyResult):
        """異常結果を保存"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO anomaly_results
                    (metric_type, timestamp, value, anomaly_score, is_anomaly, confidence, description)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    result.metric_type, result.timestamp, result.value,
                    result.anomaly_score, 1 if result.is_anomaly else 0,
                    result.confidence, result.description
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"異常結果保存エラー: {e}")


# 使用例
def example_usage():
    manager = AnomalyDetectionManager()

    # システム開始
    manager.start_system()

    # いくつかのメトリクスを処理
    for i in range(100):
        # 通常値
        manager.process_metric("cpu_usage", 50.0 + np.random.normal(0, 5))

        # 時々異常値
        if i % 20 == 0:
            manager.process_metric("cpu_usage", 95.0)  # 異常値

        time.sleep(0.1)

    # 統計表示
    stats = manager.get_anomaly_stats()
    print(f"異常検知統計: {stats}")

    manager.stop_system()


if __name__ == "__main__":
    example_usage()
