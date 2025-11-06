"""
高度なセキュリティ脅威検知 for BLNCS
AIベースの脅威検知と自動対応システムを提供
"""

import time
import json
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
import asyncio
import numpy as np
import hashlib
import ipaddress
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """脅威レベル"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(Enum):
    """脅威タイプ"""
    DDoS_ATTACK = "ddos_attack"
    SQL_INJECTION = "sql_injection"
    XSS_ATTACK = "xss_attack"
    BRUTE_FORCE = "brute_force"
    MALWARE = "malware"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_EXFILTRATION = "data_exfiltration"
    INSIDER_THREAT = "insider_threat"
    ZERO_DAY_EXPLOIT = "zero_day_exploit"


class DetectionMethod(Enum):
    """検知手法"""
    RULE_BASED = "rule_based"
    MACHINE_LEARNING = "machine_learning"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    SIGNATURE_BASED = "signature_based"
    ANOMALY_DETECTION = "anomaly_detection"


@dataclass
class SecurityEvent:
    """セキュリティイベント情報"""
    event_id: str
    timestamp: float
    event_type: str
    source_ip: str
    destination_ip: str
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    threat_level: ThreatLevel = ThreatLevel.LOW
    threat_type: Optional[ThreatType] = None
    detection_method: DetectionMethod = DetectionMethod.RULE_BASED
    description: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    false_positive_likelihood: float = 0.0


@dataclass
class ThreatIntelligence:
    """脅威インテリジェンス情報"""
    threat_id: str
    threat_type: ThreatType
    indicators: List[str]  # 攻撃指標（IP、ドメイン、ファイルハッシュなど）
    severity: str
    description: str
    mitre_technique: Optional[str] = None
    confidence: float = 0.0
    last_updated: float = field(default_factory=time.time)


@dataclass
class AutomatedResponse:
    """自動対応情報"""
    response_id: str
    threat_id: str
    response_type: str  # 'block_ip', 'isolate_user', 'alert_admin', 'shutdown_service'
    parameters: Dict[str, Any] = field(default_factory=dict)
    executed_at: Optional[float] = None
    success: bool = False
    error_message: Optional[str] = None


class AIBasedThreatDetector:
    """AIベースの脅威検知システム"""

    def __init__(self):
        """初期化"""
        self.threat_models: Dict[str, Any] = {}
        self.behavioral_baselines: Dict[str, Dict[str, float]] = defaultdict(dict)
        self.anomaly_detectors: Dict[str, Any] = {}

    def train_threat_model(self, training_data: List[Dict[str, Any]], threat_type: ThreatType):
        """
        脅威検知モデルを学習
        Args:
            training_data: 学習データ
            threat_type: 脅威タイプ
        """
        # 特徴量を抽出
        features = []
        labels = []

        for data in training_data:
            feature_vector = self._extract_features(data)
            features.append(feature_vector)
            labels.append(1 if data.get("is_threat", False) else 0)

        # 簡易的な機械学習モデル（実際の実装ではより高度なモデルを使用）
        X = np.array(features)
        y = np.array(labels)

        # モデルを学習（簡易版）
        self.threat_models[threat_type.value] = {
            "model_type": "logistic_regression",
            "weights": np.random.randn(len(features[0])),
            "bias": 0.0,
            "training_samples": len(training_data),
            "accuracy": 0.85  # 仮の精度
        }

    def _extract_features(self, data: Dict[str, Any]) -> List[float]:
        """特徴量を抽出"""
        features = []

        # リクエスト頻度特徴
        features.append(data.get("request_count", 0))
        features.append(data.get("unique_ips", 0))
        features.append(data.get("error_rate", 0.0))

        # 時間特徴
        features.append(data.get("avg_response_time", 0.0))
        features.append(data.get("requests_per_minute", 0.0))

        # パターン特徴
        features.append(data.get("repeated_patterns", 0))
        features.append(data.get("unusual_user_agents", 0))

        return features

    def detect_threat(self, event_data: Dict[str, Any], threat_type: ThreatType) -> Tuple[bool, float]:
        """
        脅威を検知
        Args:
            event_data: イベントデータ
            threat_type: 脅威タイプ
        Returns:
            (検知フラグ, 信頼度)のタプル
        """
        if threat_type.value not in self.threat_models:
            return False, 0.0

        model = self.threat_models[threat_type.value]

        # 特徴量を抽出して予測
        features = self._extract_features(event_data)

        # 簡易的な予測（実際の実装では学習済みモデルを使用）
        prediction_score = np.random.random()  # 仮の予測スコア

        confidence = prediction_score if prediction_score > 0.5 else 1 - prediction_score

        return prediction_score > 0.7, confidence

    def analyze_behavioral_anomaly(self, user_id: str, behavior_data: Dict[str, Any]) -> Tuple[bool, float]:
        """
        行動異常を分析
        Args:
            user_id: ユーザーID
            behavior_data: 行動データ
        Returns:
            (異常検知フラグ, 異常スコア)のタプル
        """
        if user_id not in self.behavioral_baselines:
            # ベースラインがない場合は異常なし
            return False, 0.0

        baseline = self.behavioral_baselines[user_id]

        # 行動パターンを比較（簡易版）
        anomaly_score = 0.0

        # ログイン時間異常チェック
        login_hour = behavior_data.get("login_hour", 12)
        baseline_hour = baseline.get("avg_login_hour", 12)

        if abs(login_hour - baseline_hour) > 4:  # 4時間以上の差
            anomaly_score += 0.3

        # リクエスト頻度異常チェック
        request_rate = behavior_data.get("requests_per_hour", 10)
        baseline_rate = baseline.get("avg_requests_per_hour", 10)

        if request_rate > baseline_rate * 3:  # 3倍以上の頻度
            anomaly_score += 0.4

        # アクセス場所異常チェック
        location = behavior_data.get("location", "unknown")
        baseline_location = baseline.get("usual_location", "unknown")

        if location != baseline_location and baseline_location != "unknown":
            anomaly_score += 0.2

        return anomaly_score > 0.6, anomaly_score


class ThreatIntelligenceManager:
    """脅威インテリジェンス管理システム"""

    def __init__(self, db_path: str = "threat_intelligence.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self._init_db()
        self.threat_intel: Dict[str, ThreatIntelligence] = {}
        self.blacklisted_ips: Set[str] = set()
        self.blacklisted_domains: Set[str] = set()

    def _init_db(self):
        """データベースを初期化"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_intelligence (
                    threat_id TEXT PRIMARY KEY,
                    threat_type TEXT NOT NULL,
                    indicators TEXT,
                    severity TEXT,
                    description TEXT,
                    mitre_technique TEXT,
                    confidence REAL,
                    last_updated REAL
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS blacklists (
                    id INTEGER PRIMARY KEY,
                    indicator_type TEXT NOT NULL,  # 'ip', 'domain', 'hash'
                    indicator_value TEXT NOT NULL,
                    threat_type TEXT,
                    added_at REAL,
                    source TEXT
                )
            """)

            conn.commit()

    def add_threat_intelligence(self, intel: ThreatIntelligence):
        """
        脅威インテリジェンスを追加
        Args:
            intel: 脅威インテリジェンス情報
        """
        self.threat_intel[intel.threat_id] = intel

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO threat_intelligence
                    (threat_id, threat_type, indicators, severity, description, mitre_technique, confidence, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    intel.threat_id, intel.threat_type.value, json.dumps(intel.indicators),
                    intel.severity, intel.description, intel.mitre_technique,
                    intel.confidence, intel.last_updated
                ))
                conn.commit()

        except Exception as e:
            logger.error(f"脅威インテリジェンス追加エラー: {e}")

    def add_to_blacklist(self, indicator_type: str, indicator_value: str, threat_type: str = None, source: str = "automated"):
        """
        ブラックリストに追加
        Args:
            indicator_type: インジケータタイプ（ip, domain, hash）
            indicator_value: インジケータ値
            threat_type: 脅威タイプ
            source: 追加ソース
        """
        if indicator_type == "ip":
            self.blacklisted_ips.add(indicator_value)
        elif indicator_type == "domain":
            self.blacklisted_domains.add(indicator_value)

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO blacklists
                    (indicator_type, indicator_value, threat_type, added_at, source)
                    VALUES (?, ?, ?, ?, ?)
                """, (indicator_type, indicator_value, threat_type, time.time(), source))
                conn.commit()

        except Exception as e:
            logger.error(f"ブラックリスト追加エラー: {e}")

    def is_blacklisted(self, indicator_type: str, indicator_value: str) -> bool:
        """
        ブラックリストチェック
        Args:
            indicator_type: インジケータタイプ
            indicator_value: インジケータ値
        Returns:
            ブラックリスト登録フラグ
        """
        if indicator_type == "ip":
            return indicator_value in self.blacklisted_ips
        elif indicator_type == "domain":
            return indicator_value in self.blacklisted_domains
        return False

    def get_threat_intel_by_type(self, threat_type: ThreatType) -> List[ThreatIntelligence]:
        """脅威タイプ別のインテリジェンスを取得"""
        return [intel for intel in self.threat_intel.values() if intel.threat_type == threat_type]


class AutomatedResponseEngine:
    """自動対応エンジン"""

    def __init__(self, threat_detector: AIBasedThreatDetector, threat_intel: ThreatIntelligenceManager):
        """
        初期化
        Args:
            threat_detector: AIベース脅威検知システム
            threat_intel: 脅威インテリジェンス管理システム
        """
        self.threat_detector = threat_detector
        self.threat_intel = threat_intel
        self.response_rules: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.response_history: List[AutomatedResponse] = []

    def add_response_rule(self, threat_type: ThreatType, response_config: Dict[str, Any]):
        """
        対応ルールを追加
        Args:
            threat_type: 脅威タイプ
            response_config: 対応設定
        """
        self.response_rules[threat_type.value].append(response_config)

    def execute_automated_response(self, threat_event: SecurityEvent) -> List[AutomatedResponse]:
        """
        自動対応を実行
        Args:
            threat_event: 脅威イベント
        Returns:
            実行された対応リスト
        """
        responses = []

        # 脅威タイプに応じた対応ルールを取得
        rules = self.response_rules.get(threat_event.threat_type.value, [])

        for rule in rules:
            response_type = rule.get("response_type")
            parameters = rule.get("parameters", {})

            # 対応を実行
            response = self._execute_response(threat_event, response_type, parameters)
            responses.append(response)

            # 対応履歴を記録
            self.response_history.append(response)

        return responses

    def _execute_response(self, threat_event: SecurityEvent, response_type: str, parameters: Dict[str, Any]) -> AutomatedResponse:
        """対応を実行"""
        response_id = f"response_{int(time.time() * 1000000)}"

        response = AutomatedResponse(
            response_id=response_id,
            threat_id=threat_event.event_id,
            response_type=response_type,
            parameters=parameters
        )

        try:
            # 対応タイプに応じた処理
            if response_type == "block_ip":
                ip_to_block = parameters.get("ip_address", threat_event.source_ip)
                # IPブロック処理を実行（実際の実装ではファイアウォール設定など）
                logger.warning(f"IPブロック実行: {ip_to_block}")
                response.success = True

            elif response_type == "isolate_user":
                user_id = threat_event.user_id or parameters.get("user_id")
                # ユーザー隔離処理を実行
                logger.warning(f"ユーザー隔離実行: {user_id}")
                response.success = True

            elif response_type == "alert_admin":
                # 管理者アラートを送信
                logger.warning(f"管理者アラート送信: {threat_event.description}")
                response.success = True

            elif response_type == "shutdown_service":
                service_name = parameters.get("service_name", "unknown")
                # サービスシャットダウンを実行
                logger.warning(f"サービスシャットダウン実行: {service_name}")
                response.success = True

            response.executed_at = time.time()

        except Exception as e:
            response.success = False
            response.error_message = str(e)
            logger.error(f"対応実行エラー: {response_type} - {e}")

        return response

    def get_response_history(self, limit: int = 100) -> List[AutomatedResponse]:
        """対応履歴を取得"""
        return self.response_history[-limit:]


class AdvancedThreatDetectionManager:
    """高度な脅威検知管理システム"""

    def __init__(self, db_path: str = "advanced_threat_detection.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self._init_db()
        self.threat_detector = AIBasedThreatDetector()
        self.threat_intel = ThreatIntelligenceManager(db_path)
        self.response_engine = AutomatedResponseEngine(self.threat_detector, self.threat_intel)

        self.detected_threats: List[SecurityEvent] = []
        self.is_detection_active = False
        self.detection_thread: Optional[threading.Thread] = None

    def _init_db(self):
        """データベースを初期化"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    event_type TEXT NOT NULL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    user_id TEXT,
                    session_id TEXT,
                    threat_level TEXT,
                    threat_type TEXT,
                    detection_method TEXT,
                    description TEXT,
                    raw_data TEXT,
                    confidence REAL,
                    false_positive_likelihood REAL
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS automated_responses (
                    response_id TEXT PRIMARY KEY,
                    threat_id TEXT NOT NULL,
                    response_type TEXT NOT NULL,
                    parameters TEXT,
                    executed_at REAL,
                    success INTEGER,
                    error_message TEXT,
                    FOREIGN KEY (threat_id) REFERENCES security_events (event_id)
                )
            """)

            conn.commit()

    def initialize_threat_detection_system(self):
        """脅威検知システムを初期化"""
        # デフォルトの脅威インテリジェンスを追加
        self._load_default_threat_intel()

        # デフォルトの対応ルールを設定
        self._setup_default_response_rules()

    def _load_default_threat_intel(self):
        """デフォルトの脅威インテリジェンスを読み込み"""
        default_intel = [
            ThreatIntelligence(
                threat_id="ddos_patterns",
                threat_type=ThreatType.DDoS_ATTACK,
                indicators=["high_request_rate", "multiple_source_ips", "unusual_traffic_pattern"],
                severity="high",
                description="DDoS攻撃パターン",
                mitre_technique="T1498",
                confidence=0.8
            ),
            ThreatIntelligence(
                threat_id="sql_injection_patterns",
                threat_type=ThreatType.SQL_INJECTION,
                indicators=["single_quote_usage", "union_select_pattern", "comment_syntax"],
                severity="critical",
                description="SQLインジェクション攻撃パターン",
                mitre_technique="T1190",
                confidence=0.9
            )
        ]

        for intel in default_intel:
            self.threat_intel.add_threat_intelligence(intel)

    def _setup_default_response_rules(self):
        """デフォルトの対応ルールを設定"""
        # DDoS攻撃対応ルール
        self.response_engine.add_response_rule(ThreatType.DDoS_ATTACK, {
            "response_type": "block_ip",
            "parameters": {"ip_address": "source_ip", "duration": 3600}
        })

        # SQLインジェクション対応ルール
        self.response_engine.add_response_rule(ThreatType.SQL_INJECTION, {
            "response_type": "alert_admin",
            "parameters": {"priority": "high", "message": "SQLインジェクション検知"}
        })

    def start_threat_detection(self):
        """脅威検知を開始"""
        if not self.is_detection_active:
            self.is_detection_active = True
            self.detection_thread = threading.Thread(target=self._detection_loop, daemon=True)
            self.detection_thread.start()

    def stop_threat_detection(self):
        """脅威検知を停止"""
        self.is_detection_active = False
        if self.detection_thread:
            self.detection_thread.join()

    def analyze_security_event(self, event_data: Dict[str, Any]) -> Optional[SecurityEvent]:
        """
        セキュリティイベントを分析
        Args:
            event_data: イベントデータ
        Returns:
            セキュリティイベント（脅威でない場合はNone）
        """
        try:
            # ブラックリストチェック
            source_ip = event_data.get("source_ip", "")
            if self.threat_intel.is_blacklisted("ip", source_ip):
                threat_event = SecurityEvent(
                    event_id=f"threat_{int(time.time() * 1000000)}",
                    timestamp=time.time(),
                    event_type="blacklisted_access",
                    source_ip=source_ip,
                    destination_ip=event_data.get("destination_ip", ""),
                    threat_level=ThreatLevel.HIGH,
                    threat_type=ThreatType.UNAUTHORIZED_ACCESS,
                    detection_method=DetectionMethod.RULE_BASED,
                    description="ブラックリストIPからのアクセス",
                    confidence=0.9
                )

                self.detected_threats.append(threat_event)
                self._save_security_event(threat_event)

                return threat_event

            # AIベースの脅威検知を実行
            for threat_type in ThreatType:
                is_threat, confidence = self.threat_detector.detect_threat(event_data, threat_type)

                if is_threat:
                    threat_event = SecurityEvent(
                        event_id=f"threat_{int(time.time() * 1000000)}",
                        timestamp=time.time(),
                        event_type=f"{threat_type.value}_detected",
                        source_ip=source_ip,
                        destination_ip=event_data.get("destination_ip", ""),
                        threat_level=ThreatLevel.HIGH,
                        threat_type=threat_type,
                        detection_method=DetectionMethod.MACHINE_LEARNING,
                        description=f"AI検知: {threat_type.value}",
                        confidence=confidence
                    )

                    self.detected_threats.append(threat_event)
                    self._save_security_event(threat_event)

                    # 自動対応を実行
                    responses = self.response_engine.execute_automated_response(threat_event)
                    for response in responses:
                        self._save_automated_response(response)

                    return threat_event

            # 行動異常チェック
            if "user_id" in event_data:
                user_id = event_data["user_id"]
                is_anomaly, anomaly_score = self.threat_detector.analyze_behavioral_anomaly(user_id, event_data)

                if is_anomaly:
                    threat_event = SecurityEvent(
                        event_id=f"threat_{int(time.time() * 1000000)}",
                        timestamp=time.time(),
                        event_type="behavioral_anomaly",
                        source_ip=source_ip,
                        destination_ip=event_data.get("destination_ip", ""),
                        user_id=user_id,
                        threat_level=ThreatLevel.MEDIUM,
                        threat_type=ThreatType.INSIDER_THREAT,
                        detection_method=DetectionMethod.BEHAVIORAL_ANALYSIS,
                        description="行動異常検知",
                        confidence=anomaly_score
                    )

                    self.detected_threats.append(threat_event)
                    self._save_security_event(threat_event)

                    return threat_event

        except Exception as e:
            logger.error(f"セキュリティイベント分析エラー: {e}")

        return None

    def _save_security_event(self, event: SecurityEvent):
        """セキュリティイベントを保存"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO security_events
                    (event_id, timestamp, event_type, source_ip, destination_ip, user_id, session_id,
                     threat_level, threat_type, detection_method, description, raw_data, confidence, false_positive_likelihood)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.event_id, event.timestamp, event.event_type, event.source_ip,
                    event.destination_ip, event.user_id, event.session_id, event.threat_level.value,
                    event.threat_type.value if event.threat_type else None, event.detection_method.value,
                    event.description, json.dumps(event.raw_data), event.confidence, event.false_positive_likelihood
                ))
                conn.commit()

        except Exception as e:
            logger.error(f"セキュリティイベント保存エラー: {e}")

    def _save_automated_response(self, response: AutomatedResponse):
        """自動対応を保存"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO automated_responses
                    (response_id, threat_id, response_type, parameters, executed_at, success, error_message)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    response.response_id, response.threat_id, response.response_type,
                    json.dumps(response.parameters), response.executed_at,
                    1 if response.success else 0, response.error_message
                ))
                conn.commit()

        except Exception as e:
            logger.error(f"自動対応保存エラー: {e}")

    def get_threat_summary(self, hours: int = 24) -> Dict[str, Any]:
        """
        脅威サマリーを取得
        Args:
            hours: 集計時間（時）
        Returns:
            サマリー情報
        """
        cutoff_time = time.time() - (hours * 3600)

        relevant_threats = [threat for threat in self.detected_threats if threat.timestamp > cutoff_time]

        # 脅威レベル別集計
        threat_levels = defaultdict(int)
        for threat in relevant_threats:
            threat_levels[threat.threat_level.value] += 1

        # 脅威タイプ別集計
        threat_types = defaultdict(int)
        for threat in relevant_threats:
            if threat.threat_type:
                threat_types[threat.threat_type.value] += 1

        return {
            "total_threats": len(relevant_threats),
            "threat_level_breakdown": dict(threat_levels),
            "threat_type_breakdown": dict(threat_types),
            "automated_responses": len(self.response_engine.response_history),
            "blacklisted_ips": len(self.threat_intel.blacklisted_ips),
            "period_hours": hours
        }

    def _detection_loop(self):
        """検知ループ"""
        while self.is_detection_active:
            try:
                # 定期的な脅威インテリジェンス更新
                self._update_threat_intelligence()

                time.sleep(300)  # 5分間隔
            except Exception as e:
                logger.error(f"検知ループエラー: {e}")

    def _update_threat_intelligence(self):
        """脅威インテリジェンスを更新"""
        # 実際の実装では外部の脅威インテリジェンスフィードから更新
        pass


# 使用例
def example_usage():
    manager = AdvancedThreatDetectionManager()

    # システム初期化
    manager.initialize_threat_detection_system()

    # システム開始
    manager.start_threat_detection()

    # 行動ベースラインを設定
    manager.threat_detector.behavioral_baselines["user_123"] = {
        "avg_login_hour": 9,
        "avg_requests_per_hour": 10,
        "usual_location": "JP"
    }

    # セキュリティイベント分析のシミュレーション
    for i in range(20):
        # 通常のアクセスイベント
        normal_event = {
            "source_ip": f"192.168.1.{i % 10 + 10}",
            "destination_ip": "10.0.0.1",
            "user_id": "user_123",
            "request_count": 10,
            "error_rate": 0.05,
            "login_hour": 9,
            "requests_per_hour": 10,
            "location": "JP"
        }

        threat_detected = manager.analyze_security_event(normal_event)

        # 時々脅威イベントを挿入
        if i % 5 == 0:
            threat_event = {
                "source_ip": "203.0.113.1",  # 脅威IP
                "destination_ip": "10.0.0.1",
                "request_count": 1000,  # 高負荷
                "error_rate": 0.8,
                "repeated_patterns": 50
            }

            threat_detected = manager.analyze_security_event(threat_event)
            if threat_detected:
                print(f"脅威検知: {threat_detected.threat_type.value} (レベル: {threat_detected.threat_level.value})")

    # 脅威サマリー取得
    summary = manager.get_threat_summary(hours=1)
    print(f"脅威サマリー: {summary['total_threats']}件の脅威検知")

    # 対応履歴取得
    responses = manager.response_engine.get_response_history()
    print(f"自動対応実行: {len(responses)}件")

    manager.stop_threat_detection()


if __name__ == "__main__":
    example_usage()
