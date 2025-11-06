"""
ユーザー体験最適化システム for BLNCS
パーソナライズ機能とA/Bテストフレームワーク機能を提供
"""

import time
import json
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
import hashlib
import random
import uuid
from collections import defaultdict

logger = logging.getLogger(__name__)


class UserSegment(Enum):
    """ユーザーセグメント"""
    NEW_USER = "new_user"
    RETURNING_USER = "returning_user"
    POWER_USER = "power_user"
    ENTERPRISE_USER = "enterprise_user"
    DEVELOPER = "developer"
    BUSINESS_USER = "business_user"


class ExperimentStatus(Enum):
    """実験ステータス"""
    DRAFT = "draft"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class PersonalizationType(Enum):
    """パーソナライズタイプ"""
    CONTENT = "content"
    UI_LAYOUT = "ui_layout"
    FEATURE_AVAILABILITY = "feature_availability"
    NOTIFICATION_FREQUENCY = "notification_frequency"
    DASHBOARD_WIDGETS = "dashboard_widgets"


@dataclass
class UserProfile:
    """ユーザープロファイル情報"""
    user_id: str
    segment: UserSegment
    preferences: Dict[str, Any] = field(default_factory=dict)
    behavior_patterns: Dict[str, Any] = field(default_factory=dict)
    feature_usage: Dict[str, int] = field(default_factory=dict)
    last_active: float = field(default_factory=time.time)
    created_at: float = field(default_factory=time.time)
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class ABTestExperiment:
    """A/Bテスト実験情報"""
    experiment_id: str
    name: str
    description: str
    hypothesis: str
    variants: List[Dict[str, Any]]
    target_audience: Dict[str, Any]  # ターゲットユーザー条件
    primary_metric: str  # 主要評価指標
    secondary_metrics: List[str] = field(default_factory=list)
    status: ExperimentStatus = ExperimentStatus.DRAFT
    start_date: Optional[float] = None
    end_date: Optional[float] = None
    sample_size: int = 1000
    confidence_level: float = 0.95
    min_detectable_effect: float = 0.05
    results: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExperimentResult:
    """実験結果情報"""
    experiment_id: str
    variant_id: str
    user_id: str
    metrics: Dict[str, float]
    conversion_events: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


class UserSegmentationEngine:
    """ユーザーセグメンテーションエンジン"""

    def __init__(self, db_path: str = "user_profiles.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self._init_db()
        self.user_profiles: Dict[str, UserProfile] = {}
        self.segmentation_rules: Dict[UserSegment, Dict[str, Any]] = {}

    def _init_db(self):
        """データベースを初期化"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS user_profiles (
                    user_id TEXT PRIMARY KEY,
                    segment TEXT NOT NULL,
                    preferences TEXT,
                    behavior_patterns TEXT,
                    feature_usage TEXT,
                    last_active REAL,
                    created_at REAL,
                    tags TEXT
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS user_interactions (
                    id INTEGER PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    interaction_type TEXT NOT NULL,
                    feature_name TEXT,
                    value REAL,
                    timestamp REAL NOT NULL,
                    metadata TEXT,
                    FOREIGN KEY (user_id) REFERENCES user_profiles (user_id)
                )
            """)

            conn.commit()

    def create_user_profile(self, user_id: str, initial_segment: UserSegment = UserSegment.NEW_USER) -> UserProfile:
        """
        ユーザープロファイルを作成
        Args:
            user_id: ユーザーID
            initial_segment: 初期セグメント
        Returns:
            作成されたプロファイル
        """
        profile = UserProfile(
            user_id=user_id,
            segment=initial_segment
        )

        self.user_profiles[user_id] = profile
        self._save_user_profile(profile)

        return profile

    def update_user_segment(self, user_id: str, new_segment: UserSegment, reason: str = ""):
        """
        ユーザーセグメントを更新
        Args:
            user_id: ユーザーID
            new_segment: 新しいセグメント
            reason: 更新理由
        """
        if user_id in self.user_profiles:
            old_segment = self.user_profiles[user_id].segment
            self.user_profiles[user_id].segment = new_segment
            self.user_profiles[user_id].last_active = time.time()

            self._save_user_profile(self.user_profiles[user_id])

            logger.info(f"ユーザーセグメント更新: {user_id} {old_segment.value} -> {new_segment.value} ({reason})")

    def record_user_interaction(self, user_id: str, interaction_type: str,
                               feature_name: Optional[str] = None, value: float = 1.0,
                               metadata: Dict[str, Any] = None):
        """
        ユーザーインタラクションを記録
        Args:
            user_id: ユーザーID
            interaction_type: インタラクションタイプ
            feature_name: 機能名
            value: 値
            metadata: メタデータ
        """
        if user_id not in self.user_profiles:
            self.create_user_profile(user_id)

        profile = self.user_profiles[user_id]

        # インタラクションを記録
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO user_interactions
                    (user_id, interaction_type, feature_name, value, timestamp, metadata)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    user_id, interaction_type, feature_name, value,
                    time.time(), json.dumps(metadata) if metadata else None
                ))
                conn.commit()

        except Exception as e:
            logger.error(f"インタラクション記録エラー: {e}")

        # プロファイルを更新
        profile.last_active = time.time()

        if feature_name:
            profile.feature_usage[feature_name] = profile.feature_usage.get(feature_name, 0) + int(value)

        # セグメントを自動更新
        self._update_segment_based_on_behavior(profile)

    def _update_segment_based_on_behavior(self, profile: UserProfile):
        """行動に基づいてセグメントを更新"""
        # 簡易的なセグメンテーションルール
        total_interactions = sum(profile.feature_usage.values())
        days_active = (time.time() - profile.created_at) / (24 * 3600)

        if total_interactions > 100 and days_active > 30:
            if profile.segment == UserSegment.NEW_USER:
                self.update_user_segment(profile.user_id, UserSegment.POWER_USER, "高頻度利用")
        elif total_interactions > 50 and days_active > 7:
            if profile.segment == UserSegment.NEW_USER:
                self.update_user_segment(profile.user_id, UserSegment.RETURNING_USER, "定期利用")

    def _save_user_profile(self, profile: UserProfile):
        """ユーザープロファイルを保存"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO user_profiles
                    (user_id, segment, preferences, behavior_patterns, feature_usage,
                     last_active, created_at, tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    profile.user_id, profile.segment.value,
                    json.dumps(profile.preferences),
                    json.dumps(profile.behavior_patterns),
                    json.dumps(profile.feature_usage),
                    profile.last_active, profile.created_at,
                    json.dumps(profile.tags)
                ))
                conn.commit()

        except Exception as e:
            logger.error(f"プロファイル保存エラー: {e}")

    def get_user_segment(self, user_id: str) -> Optional[UserSegment]:
        """
        ユーザーセグメントを取得
        Args:
            user_id: ユーザーID
        Returns:
            ユーザーセグメント（見つからない場合はNone）
        """
        if user_id in self.user_profiles:
            return self.user_profiles[user_id].segment

        # データベースから読み込み
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT segment FROM user_profiles WHERE user_id = ?",
                    (user_id,)
                )
                row = cursor.fetchone()
                if row:
                    return UserSegment(row[0])

        except Exception as e:
            logger.error(f"セグメント取得エラー: {e}")

        return None


class PersonalizationEngine:
    """パーソナライズエンジン"""

    def __init__(self, segmentation_engine: UserSegmentationEngine):
        """
        初期化
        Args:
            segmentation_engine: ユーザーセグメンテーションエンジン
        """
        self.segmentation_engine = segmentation_engine
        self.personalization_rules: Dict[str, Dict[str, Any]] = {}
        self.personalization_cache: Dict[str, Dict[str, Any]] = {}

    def set_personalization_rule(self, rule_id: str, rule_config: Dict[str, Any]):
        """
        パーソナライズルールを設定
        Args:
            rule_id: ルールID
            rule_config: ルール設定
        """
        self.personalization_rules[rule_id] = rule_config

    def get_personalized_content(self, user_id: str, content_type: PersonalizationType) -> Dict[str, Any]:
        """
        パーソナライズされたコンテンツを取得
        Args:
            user_id: ユーザーID
            content_type: コンテンツタイプ
        Returns:
            パーソナライズ設定
        """
        cache_key = f"{user_id}_{content_type.value}"

        if cache_key in self.personalization_cache:
            return self.personalization_cache[cache_key]

        user_segment = self.segmentation_engine.get_user_segment(user_id)

        if not user_segment:
            # デフォルト設定を返却
            default_config = self._get_default_personalization(content_type)
            self.personalization_cache[cache_key] = default_config
            return default_config

        # セグメントに基づいてパーソナライズ
        personalized_config = self._apply_personalization_rules(user_segment, content_type)

        self.personalization_cache[cache_key] = personalized_config
        return personalized_config

    def _get_default_personalization(self, content_type: PersonalizationType) -> Dict[str, Any]:
        """デフォルトのパーソナライズ設定を取得"""
        defaults = {
            PersonalizationType.CONTENT: {
                "theme": "light",
                "language": "ja",
                "notifications": True
            },
            PersonalizationType.UI_LAYOUT: {
                "sidebar_collapsed": False,
                "dashboard_layout": "grid",
                "widget_order": []
            },
            PersonalizationType.FEATURE_AVAILABILITY: {
                "advanced_features": False,
                "beta_features": False
            },
            PersonalizationType.NOTIFICATION_FREQUENCY: {
                "email_frequency": "daily",
                "push_frequency": "immediate"
            },
            PersonalizationType.DASHBOARD_WIDGETS: {
                "visible_widgets": ["performance", "alerts"],
                "widget_positions": {}
            }
        }

        return defaults.get(content_type, {})

    def _apply_personalization_rules(self, user_segment: UserSegment, content_type: PersonalizationType) -> Dict[str, Any]:
        """パーソナライズルールを適用"""
        base_config = self._get_default_personalization(content_type)

        # セグメント別の調整
        if user_segment == UserSegment.POWER_USER:
            if content_type == PersonalizationType.FEATURE_AVAILABILITY:
                base_config["advanced_features"] = True
            elif content_type == PersonalizationType.DASHBOARD_WIDGETS:
                base_config["visible_widgets"].extend(["analytics", "reports"])

        elif user_segment == UserSegment.ENTERPRISE_USER:
            if content_type == PersonalizationType.FEATURE_AVAILABILITY:
                base_config["advanced_features"] = True
                base_config["beta_features"] = True
            elif content_type == PersonalizationType.NOTIFICATION_FREQUENCY:
                base_config["email_frequency"] = "immediate"

        return base_config

    def update_user_preferences(self, user_id: str, preferences: Dict[str, Any]):
        """
        ユーザーの設定を更新
        Args:
            user_id: ユーザーID
            preferences: 設定情報
        """
        if user_id in self.segmentation_engine.user_profiles:
            self.segmentation_engine.user_profiles[user_id].preferences.update(preferences)
            self.segmentation_engine._save_user_profile(self.segmentation_engine.user_profiles[user_id])

            # キャッシュをクリア
            cache_keys_to_remove = [k for k in self.personalization_cache.keys() if k.startswith(user_id)]
            for key in cache_keys_to_remove:
                del self.personalization_cache[key]


class ABTestFramework:
    """A/Bテストフレームワーク"""

    def __init__(self, db_path: str = "ab_tests.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self._init_db()
        self.experiments: Dict[str, ABTestExperiment] = {}
        self.experiment_assignments: Dict[str, str] = {}  # user_id -> variant_id
        self.results: Dict[str, List[ExperimentResult]] = defaultdict(list)

    def _init_db(self):
        """データベースを初期化"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS experiments (
                    experiment_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    hypothesis TEXT,
                    variants TEXT,
                    target_audience TEXT,
                    primary_metric TEXT,
                    secondary_metrics TEXT,
                    status TEXT,
                    start_date REAL,
                    end_date REAL,
                    sample_size INTEGER,
                    confidence_level REAL,
                    min_detectable_effect REAL,
                    results TEXT
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS experiment_assignments (
                    user_id TEXT,
                    experiment_id TEXT,
                    variant_id TEXT,
                    assigned_at REAL,
                    PRIMARY KEY (user_id, experiment_id)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS experiment_results (
                    id INTEGER PRIMARY KEY,
                    experiment_id TEXT NOT NULL,
                    variant_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    metrics TEXT,
                    conversion_events TEXT,
                    timestamp REAL
                )
            """)

            conn.commit()

    def create_experiment(self, experiment: ABTestExperiment) -> str:
        """
        実験を作成
        Args:
            experiment: 実験情報
        Returns:
            実験ID
        """
        self.experiments[experiment.experiment_id] = experiment

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO experiments
                    (experiment_id, name, description, hypothesis, variants, target_audience,
                     primary_metric, secondary_metrics, status, start_date, end_date,
                     sample_size, confidence_level, min_detectable_effect, results)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    experiment.experiment_id, experiment.name, experiment.description,
                    experiment.hypothesis, json.dumps(experiment.variants),
                    json.dumps(experiment.target_audience), experiment.primary_metric,
                    json.dumps(experiment.secondary_metrics), experiment.status.value,
                    experiment.start_date, experiment.end_date, experiment.sample_size,
                    experiment.confidence_level, experiment.min_detectable_effect,
                    json.dumps(experiment.results)
                ))
                conn.commit()

        except Exception as e:
            logger.error(f"実験作成エラー: {e}")

        return experiment.experiment_id

    def start_experiment(self, experiment_id: str):
        """
        実験を開始
        Args:
            experiment_id: 実験ID
        """
        if experiment_id in self.experiments:
            self.experiments[experiment_id].status = ExperimentStatus.RUNNING
            self.experiments[experiment_id].start_date = time.time()

            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute(
                        "UPDATE experiments SET status = ?, start_date = ? WHERE experiment_id = ?",
                        (ExperimentStatus.RUNNING.value, time.time(), experiment_id)
                    )
                    conn.commit()

            except Exception as e:
                logger.error(f"実験開始エラー: {e}")

    def assign_user_to_experiment(self, user_id: str, experiment_id: str) -> Optional[str]:
        """
        ユーザーを実験に割り当て
        Args:
            user_id: ユーザーID
            experiment_id: 実験ID
        Returns:
            割り当てられたバリアントID（割り当てられない場合はNone）
        """
        if experiment_id not in self.experiments:
            return None

        experiment = self.experiments[experiment_id]

        if experiment.status != ExperimentStatus.RUNNING:
            return None

        # 既に割り当て済みの場合は既存のバリアントを返却
        if user_id in self.experiment_assignments:
            current_assignment = self.experiment_assignments[user_id]
            if current_assignment == experiment_id:
                return current_assignment

        # ターゲットオーディエンスチェック（簡易版）
        if not self._check_target_audience(user_id, experiment.target_audience):
            return None

        # バリアントを選択（簡易的なランダム割り当て）
        selected_variant = random.choice(experiment.variants)

        # 割り当てを記録
        self.experiment_assignments[user_id] = selected_variant["id"]

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO experiment_assignments
                    (user_id, experiment_id, variant_id, assigned_at)
                    VALUES (?, ?, ?, ?)
                """, (user_id, experiment_id, selected_variant["id"], time.time()))
                conn.commit()

        except Exception as e:
            logger.error(f"割り当て記録エラー: {e}")

        return selected_variant["id"]

    def record_experiment_result(self, experiment_id: str, user_id: str,
                               metrics: Dict[str, float], conversion_events: List[str] = None):
        """
        実験結果を記録
        Args:
            experiment_id: 実験ID
            user_id: ユーザーID
            metrics: 測定指標
            conversion_events: コンバージョンイベント
        """
        if experiment_id not in self.experiments:
            return

        # ユーザーのバリアントを取得
        variant_id = self.experiment_assignments.get(user_id)
        if not variant_id:
            return

        result = ExperimentResult(
            experiment_id=experiment_id,
            variant_id=variant_id,
            user_id=user_id,
            metrics=metrics,
            conversion_events=conversion_events or []
        )

        self.results[experiment_id].append(result)

        # データベースに保存
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO experiment_results
                    (experiment_id, variant_id, user_id, metrics, conversion_events, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    experiment_id, variant_id, user_id,
                    json.dumps(metrics),
                    json.dumps(conversion_events or []),
                    time.time()
                ))
                conn.commit()

        except Exception as e:
            logger.error(f"結果記録エラー: {e}")

    def analyze_experiment_results(self, experiment_id: str) -> Dict[str, Any]:
        """
        実験結果を分析
        Args:
            experiment_id: 実験ID
        Returns:
            分析結果
        """
        if experiment_id not in self.experiments:
            return {"error": "実験が見つかりません"}

        experiment = self.experiments[experiment_id]
        results = self.results[experiment_id]

        if not results:
            return {"error": "結果データがありません"}

        # バリアント別の結果を集計
        variant_results = defaultdict(list)

        for result in results:
            variant_results[result.variant_id].append(result)

        analysis = {
            "experiment_id": experiment_id,
            "total_participants": len(results),
            "variant_analysis": {}
        }

        for variant_id, variant_data in variant_results.items():
            variant_metrics = defaultdict(list)

            for result in variant_data:
                for metric_name, metric_value in result.metrics.items():
                    variant_metrics[metric_name].append(metric_value)

            # 統計計算
            variant_analysis = {}
            for metric_name, values in variant_metrics.items():
                if values:
                    variant_analysis[metric_name] = {
                        "mean": sum(values) / len(values),
                        "std": (sum((x - sum(values)/len(values))**2 for x in values) / len(values))**0.5,
                        "count": len(values)
                    }

            analysis["variant_analysis"][variant_id] = variant_analysis

        return analysis

    def _check_target_audience(self, user_id: str, target_audience: Dict[str, Any]) -> bool:
        """ターゲットオーディエンスをチェック"""
        # 簡易実装：セグメントチェックのみ
        required_segment = target_audience.get("segment")

        if required_segment:
            user_segment = self.segmentation_engine.get_user_segment(user_id)
            if user_segment and user_segment.value != required_segment:
                return False

        return True


class UXOptimizationManager:
    """ユーザー体験最適化管理システム"""

    def __init__(self, db_path: str = "ux_optimization.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self.segmentation_engine = UserSegmentationEngine(db_path)
        self.personalization_engine = PersonalizationEngine(self.segmentation_engine)
        self.ab_test_framework = ABTestFramework(db_path)

        self.is_optimization_active = False
        self.optimization_thread: Optional[threading.Thread] = None

    def initialize_ux_system(self):
        """UX最適化システムを初期化"""
        # デフォルトのパーソナライズルールを設定
        self._setup_default_personalization_rules()

        # デフォルトの実験を作成
        self._create_default_experiments()

    def _setup_default_personalization_rules(self):
        """デフォルトのパーソナライズルールを設定"""
        # 新規ユーザーのシンプルなUI
        self.personalization_engine.set_personalization_rule("new_user_ui", {
            "segment": UserSegment.NEW_USER.value,
            "ui_layout": {
                "sidebar_collapsed": True,
                "show_tooltips": True,
                "dashboard_layout": "simple"
            }
        })

        # パワーユーザーの詳細な機能
        self.personalization_engine.set_personalization_rule("power_user_features", {
            "segment": UserSegment.POWER_USER.value,
            "feature_availability": {
                "advanced_features": True,
                "custom_dashboards": True,
                "api_access": True
            }
        })

    def _create_default_experiments(self):
        """デフォルトの実験を作成"""
        # ダッシュボードレイアウト実験
        dashboard_experiment = ABTestExperiment(
            experiment_id="dashboard_layout_test",
            name="ダッシュボードレイアウト最適化",
            description="異なるダッシュボードレイアウトの効果を比較",
            hypothesis="グリッドレイアウトの方がリストレイアウトよりユーザーエンゲージメントが高い",
            variants=[
                {"id": "grid_layout", "name": "グリッドレイアウト", "config": {"layout": "grid"}},
                {"id": "list_layout", "name": "リストレイアウト", "config": {"layout": "list"}}
            ],
            target_audience={"segment": UserSegment.NEW_USER.value},
            primary_metric="session_duration",
            secondary_metrics=["page_views", "feature_usage"],
            sample_size=500
        )

        self.ab_test_framework.create_experiment(dashboard_experiment)

    def start_optimization_system(self):
        """最適化システムを開始"""
        if not self.is_optimization_active:
            self.is_optimization_active = True
            self.optimization_thread = threading.Thread(target=self._optimization_loop, daemon=True)
            self.optimization_thread.start()

    def stop_optimization_system(self):
        """最適化システムを停止"""
        self.is_optimization_active = False
        if self.optimization_thread:
            self.optimization_thread.join()

    def get_personalized_experience(self, user_id: str, experience_type: PersonalizationType) -> Dict[str, Any]:
        """
        パーソナライズされた体験を取得
        Args:
            user_id: ユーザーID
            experience_type: 体験タイプ
        Returns:
            パーソナライズ設定
        """
        return self.personalization_engine.get_personalized_content(user_id, experience_type)

    def record_user_behavior(self, user_id: str, action: str, feature: Optional[str] = None,
                           value: float = 1.0, metadata: Dict[str, Any] = None):
        """
        ユーザー行動を記録
        Args:
            user_id: ユーザーID
            action: 行動
            feature: 機能名
            value: 値
            metadata: メタデータ
        """
        self.segmentation_engine.record_user_interaction(user_id, action, feature, value, metadata)

    def assign_user_to_experiment(self, user_id: str, experiment_id: str) -> Optional[str]:
        """
        ユーザーを実験に割り当て
        Args:
            user_id: ユーザーID
            experiment_id: 実験ID
        Returns:
            割り当てられたバリアントID
        """
        return self.ab_test_framework.assign_user_to_experiment(user_id, experiment_id)

    def record_experiment_metrics(self, experiment_id: str, user_id: str,
                                metrics: Dict[str, float], events: List[str] = None):
        """
        実験メトリクスを記録
        Args:
            experiment_id: 実験ID
            user_id: ユーザーID
            metrics: 測定指標
            events: イベントリスト
        """
        self.ab_test_framework.record_experiment_result(experiment_id, user_id, metrics, events)

    def get_optimization_insights(self) -> Dict[str, Any]:
        """最適化洞察を取得"""
        return {
            "total_users": len(self.segmentation_engine.user_profiles),
            "segment_distribution": self._get_segment_distribution(),
            "active_experiments": len([exp for exp in self.ab_test_framework.experiments.values()
                                     if exp.status == ExperimentStatus.RUNNING]),
            "personalization_coverage": self._calculate_personalization_coverage()
        }

    def _get_segment_distribution(self) -> Dict[str, int]:
        """セグメント分布を取得"""
        distribution = defaultdict(int)

        for profile in self.segmentation_engine.user_profiles.values():
            distribution[profile.segment.value] += 1

        return dict(distribution)

    def _calculate_personalization_coverage(self) -> float:
        """パーソナライズ適用率を計算"""
        if not self.segmentation_engine.user_profiles:
            return 0.0

        personalized_users = 0

        for user_id in self.segmentation_engine.user_profiles.keys():
            try:
                self.personalization_engine.get_personalized_content(user_id, PersonalizationType.CONTENT)
                personalized_users += 1
            except:
                pass

        return personalized_users / len(self.segmentation_engine.user_profiles)

    def _optimization_loop(self):
        """最適化ループ"""
        while self.is_optimization_active:
            try:
                # 定期的な最適化処理
                time.sleep(300)  # 5分間隔
            except Exception as e:
                logger.error(f"最適化ループエラー: {e}")


# 使用例
def example_usage():
    manager = UXOptimizationManager()

    # システム初期化
    manager.initialize_ux_system()

    # システム開始
    manager.start_optimization_system()

    # ユーザー行動のシミュレーション
    for user_id in [f"user_{i}" for i in range(10)]:
        # ユーザー作成
        manager.segmentation_engine.create_user_profile(user_id)

        # 行動記録
        for action in ["login", "dashboard_view", "feature_use", "logout"]:
            manager.record_user_behavior(user_id, action, "dashboard" if "dashboard" in action else None)

    # パーソナライズ設定取得
    personalization = manager.get_personalized_experience("user_1", PersonalizationType.UI_LAYOUT)
    print(f"パーソナライズ設定: {personalization}")

    # 実験割り当て
    variant = manager.assign_user_to_experiment("user_1", "dashboard_layout_test")
    print(f"実験割り当て: {variant}")

    # 実験結果記録
    manager.record_experiment_metrics(
        "dashboard_layout_test",
        "user_1",
        {"session_duration": 300.0, "page_views": 15}
    )

    # 洞察取得
    insights = manager.get_optimization_insights()
    print(f"最適化洞察: {insights}")

    manager.stop_optimization_system()


if __name__ == "__main__":
    example_usage()
