"""
エンタープライズ監査ログとコンプライアンスシステム for BLNCS
包括的な監査ログ記録とコンプライアンスレポート機能を提供
"""

import json
import time
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import logging
import hashlib
import uuid
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)


class AuditEventType(Enum):
    """監査イベントタイプ"""
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    ADMIN_ACTION = "admin_action"
    SECURITY_EVENT = "security_event"
    SYSTEM_EVENT = "system_event"
    API_CALL = "api_call"
    CONFIG_CHANGE = "config_change"
    TRANSACTION = "transaction"


class ComplianceStandard(Enum):
    """コンプライアンス基準"""
    GDPR = "GDPR"
    HIPAA = "HIPAA"
    SOX = "SOX"
    PCI_DSS = "PCI_DSS"
    ISO_27001 = "ISO_27001"
    NIST = "NIST"
    CCPA = "CCPA"


@dataclass
class AuditEvent:
    """監査イベント情報"""
    event_id: str
    timestamp: float
    event_type: AuditEventType
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    resource: str = ""  # アクセス対象リソース
    action: str = ""     # 実行アクション
    details: Dict[str, Any] = field(default_factory=dict)
    ip_address: str = ""
    user_agent: str = ""
    compliance_standards: List[ComplianceStandard] = field(default_factory=list)
    risk_level: str = "low"  # low, medium, high, critical
    location: str = ""   # 地理的位置情報


@dataclass
class ComplianceReport:
    """コンプライアンスレポート情報"""
    report_id: str
    standard: ComplianceStandard
    period_start: float
    period_end: float
    total_events: int = 0
    compliance_score: float = 0.0
    violations: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    generated_at: float = field(default_factory=time.time)


class AuditLogger:
    """監査ログ記録システム"""

    def __init__(self, db_path: str = "audit.db", retention_days: int = 365):
        """
        初期化
        Args:
            db_path: データベースパス
            retention_days: ログ保持期間（日）
        """
        self.db_path = db_path
        self.retention_days = retention_days
        self._init_db()
        self.audit_callbacks: List[Callable] = []

    def _init_db(self):
        """データベースを初期化"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    event_type TEXT NOT NULL,
                    user_id TEXT,
                    session_id TEXT,
                    resource TEXT,
                    action TEXT,
                    details TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    compliance_standards TEXT,
                    risk_level TEXT,
                    location TEXT,
                    created_at REAL DEFAULT CURRENT_TIMESTAMP
                )
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp
                ON audit_events(timestamp)
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_user
                ON audit_events(user_id)
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_event_type
                ON audit_events(event_type)
            """)

            conn.commit()

    def log_event(self, event: AuditEvent):
        """
        監査イベントを記録
        Args:
            event: 監査イベント
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                compliance_standards_str = json.dumps([s.value for s in event.compliance_standards])

                conn.execute("""
                    INSERT INTO audit_events
                    (event_id, timestamp, event_type, user_id, session_id, resource,
                     action, details, ip_address, user_agent, compliance_standards,
                     risk_level, location)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.event_id, event.timestamp, event.event_type.value,
                    event.user_id, event.session_id, event.resource, event.action,
                    json.dumps(event.details), event.ip_address, event.user_agent,
                    compliance_standards_str, event.risk_level, event.location
                ))
                conn.commit()

            # 監査コールバック実行
            for callback in self.audit_callbacks:
                try:
                    callback(event)
                except Exception as e:
                    logger.error(f"監査コールバックエラー: {e}")

        except Exception as e:
            logger.error(f"監査ログ記録エラー: {e}")

    def query_events(self, start_time: Optional[float] = None,
                    end_time: Optional[float] = None,
                    event_type: Optional[AuditEventType] = None,
                    user_id: Optional[str] = None,
                    limit: int = 1000) -> List[AuditEvent]:
        """
        監査イベントをクエリ
        Args:
            start_time: 開始時間
            end_time: 終了時間
            event_type: イベントタイプ
            user_id: ユーザID
            limit: 取得制限数
        Returns:
            監査イベントリスト
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                query = "SELECT * FROM audit_events WHERE 1=1"
                params = []

                if start_time:
                    query += " AND timestamp >= ?"
                    params.append(start_time)

                if end_time:
                    query += " AND timestamp <= ?"
                    params.append(end_time)

                if event_type:
                    query += " AND event_type = ?"
                    params.append(event_type.value)

                if user_id:
                    query += " AND user_id = ?"
                    params.append(user_id)

                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)

                cursor = conn.execute(query, params)

                events = []
                for row in cursor.fetchall():
                    compliance_standards = [
                        ComplianceStandard(s) for s in json.loads(row[10])
                    ] if row[10] else []

                    event = AuditEvent(
                        event_id=row[0],
                        timestamp=row[1],
                        event_type=AuditEventType(row[2]),
                        user_id=row[3],
                        session_id=row[4],
                        resource=row[5],
                        action=row[6],
                        details=json.loads(row[7]) if row[7] else {},
                        ip_address=row[8],
                        user_agent=row[9],
                        compliance_standards=compliance_standards,
                        risk_level=row[11],
                        location=row[12]
                    )
                    events.append(event)

                return events

        except Exception as e:
            logger.error(f"監査クエリエラー: {e}")
            return []

    def cleanup_old_logs(self):
        """古いログをクリーンアップ"""
        cutoff_time = time.time() - (self.retention_days * 24 * 3600)

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "DELETE FROM audit_events WHERE timestamp < ?",
                    (cutoff_time,)
                )
                deleted_count = cursor.rowcount
                conn.commit()

                if deleted_count > 0:
                    logger.info(f"古い監査ログを削除: {deleted_count}件")

        except Exception as e:
            logger.error(f"ログクリーンアップエラー: {e}")

    def add_audit_callback(self, callback: Callable):
        """
        監査コールバックを追加
        Args:
            callback: コールバック関数
        """
        self.audit_callbacks.append(callback)


class ComplianceReporter:
    """コンプライアンスレポートシステム"""

    def __init__(self, audit_logger: AuditLogger):
        """
        初期化
        Args:
            audit_logger: 監査ログ記録システム
        """
        self.audit_logger = audit_logger
        self.report_callbacks: List[Callable] = []

    def generate_compliance_report(self, standard: ComplianceStandard,
                                 start_date: datetime, end_date: datetime) -> ComplianceReport:
        """
        コンプライアンスレポートを生成
        Args:
            standard: コンプライアンス基準
            start_date: レポート開始日
            end_date: レポート終了日
        Returns:
            コンプライアンスレポート
        """
        start_timestamp = start_date.timestamp()
        end_timestamp = end_date.timestamp()

        # 関連イベントを取得
        all_events = self.audit_logger.query_events(
            start_time=start_timestamp,
            end_time=end_timestamp,
            limit=10000
        )

        # 基準に関連するイベントをフィルタリング
        relevant_events = self._filter_events_by_standard(all_events, standard)

        # 違反を検出
        violations = self._detect_violations(relevant_events, standard)

        # コンプライアンススコアを計算
        compliance_score = self._calculate_compliance_score(relevant_events, violations, standard)

        # 推奨事項を生成
        recommendations = self._generate_recommendations(violations, standard)

        report = ComplianceReport(
            report_id=f"report_{int(time.time() * 1000000)}",
            standard=standard,
            period_start=start_timestamp,
            period_end=end_timestamp,
            total_events=len(relevant_events),
            compliance_score=compliance_score,
            violations=violations,
            recommendations=recommendations
        )

        # レポートコールバック実行
        for callback in self.report_callbacks:
            try:
                callback(report)
            except Exception as e:
                logger.error(f"レポートコールバックエラー: {e}")

        return report

    def _filter_events_by_standard(self, events: List[AuditEvent], standard: ComplianceStandard) -> List[AuditEvent]:
        """基準に関連するイベントをフィルタリング"""
        # 実際の実装では各基準の要件に基づいてフィルタリング
        if standard == ComplianceStandard.GDPR:
            return [e for e in events if e.compliance_standards and standard in e.compliance_standards]
        elif standard == ComplianceStandard.HIPAA:
            return [e for e in events if e.event_type in [AuditEventType.DATA_ACCESS, AuditEventType.DATA_MODIFICATION]]
        else:
            return events  # デフォルトはすべてのイベント

    def _detect_violations(self, events: List[AuditEvent], standard: ComplianceStandard) -> List[Dict[str, Any]]:
        """違反を検出"""
        violations = []

        for event in events:
            # リスクレベルに基づいて違反を判定
            if event.risk_level in ["high", "critical"]:
                violations.append({
                    "event_id": event.event_id,
                    "timestamp": event.timestamp,
                    "violation_type": event.risk_level,
                    "description": f"高リスクイベント検知: {event.action}",
                    "severity": event.risk_level
                })

        return violations

    def _calculate_compliance_score(self, events: List[AuditEvent],
                                  violations: List[Dict[str, Any]],
                                  standard: ComplianceStandard) -> float:
        """コンプライアンススコアを計算"""
        if not events:
            return 100.0

        total_events = len(events)
        violation_count = len(violations)

        # 基本スコア（違反率に基づく）
        base_score = max(0, 100 - (violation_count / total_events * 100))

        # 基準固有の調整
        if standard == ComplianceStandard.GDPR:
            # GDPRの場合、データアクセスログの完全性を重視
            data_access_events = len([e for e in events if e.event_type == AuditEventType.DATA_ACCESS])
            if data_access_events > 0:
                base_score *= 0.9  # データアクセスログの割引

        return min(100.0, max(0.0, base_score))

    def _generate_recommendations(self, violations: List[Dict[str, Any]],
                                standard: ComplianceStandard) -> List[str]:
        """推奨事項を生成"""
        recommendations = []

        if violations:
            recommendations.append("リスクの高い操作に対する追加の承認プロセスを実装してください")

        if standard == ComplianceStandard.GDPR:
            recommendations.append("データ処理活動の記録を強化してください")
            recommendations.append("データ主体の権利行使プロセスを文書化してください")

        elif standard == ComplianceStandard.HIPAA:
            recommendations.append("医療データのアクセス制御を強化してください")
            recommendations.append("データ暗号化の実施状況を確認してください")

        if len(recommendations) == 0:
            recommendations.append("現在のコンプライアンス状況は良好です")

        return recommendations

    def add_report_callback(self, callback: Callable):
        """
        レポートコールバックを追加
        Args:
            callback: コールバック関数
        """
        self.report_callbacks.append(callback)


class EnterpriseAuditManager:
    """エンタープライズ監査管理システム"""

    def __init__(self, db_path: str = "enterprise_audit.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self.audit_logger = AuditLogger(db_path)
        self.compliance_reporter = ComplianceReporter(self.audit_logger)

        self.is_active = False
        self.audit_thread: Optional[threading.Thread] = None

    def start_audit_system(self):
        """監査システムを開始"""
        if not self.is_active:
            self.is_active = True
            self.audit_thread = threading.Thread(target=self._audit_loop, daemon=True)
            self.audit_thread.start()

    def stop_audit_system(self):
        """監査システムを停止"""
        self.is_active = False
        if self.audit_thread:
            self.audit_thread.join()

    def record_audit_event(self, event_type: AuditEventType, user_id: Optional[str] = None,
                          resource: str = "", action: str = "",
                          details: Dict[str, Any] = None,
                          compliance_standards: List[ComplianceStandard] = None,
                          risk_level: str = "low"):
        """
        監査イベントを記録
        Args:
            event_type: イベントタイプ
            user_id: ユーザID
            resource: リソース
            action: アクション
            details: 詳細情報
            compliance_standards: 適用コンプライアンス基準
            risk_level: リスクレベル
        """
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            timestamp=time.time(),
            event_type=event_type,
            user_id=user_id,
            resource=resource,
            action=action,
            details=details or {},
            compliance_standards=compliance_standards or [],
            risk_level=risk_level
        )

        self.audit_logger.log_event(event)

    def generate_monthly_report(self, standard: ComplianceStandard) -> ComplianceReport:
        """
        月次レポートを生成
        Args:
            standard: コンプライアンス基準
        Returns:
            コンプライアンスレポート
        """
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)

        return self.compliance_reporter.generate_compliance_report(standard, start_date, end_date)

    def get_audit_summary(self, days: int = 30) -> Dict[str, Any]:
        """
        監査サマリーを取得
        Args:
            days: 集計期間（日）
        Returns:
            サマリー情報
        """
        end_time = time.time()
        start_time = end_time - (days * 24 * 3600)

        all_events = self.audit_logger.query_events(
            start_time=start_time,
            end_time=end_time,
            limit=10000
        )

        # イベントタイプ別集計
        event_counts = {}
        for event in all_events:
            event_type = event.event_type.value
            event_counts[event_type] = event_counts.get(event_type, 0) + 1

        # リスクレベル別集計
        risk_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for event in all_events:
            risk_counts[event.risk_level] = risk_counts.get(event.risk_level, 0) + 1

        return {
            "period_days": days,
            "total_events": len(all_events),
            "event_type_breakdown": event_counts,
            "risk_level_breakdown": risk_counts,
            "unique_users": len(set(e.user_id for e in all_events if e.user_id)),
            "generated_at": time.time()
        }

    def _audit_loop(self):
        """監査ループ"""
        while self.is_active:
            try:
                # 定期的なログクリーンアップ
                if int(time.time()) % (24 * 3600) == 0:  # 毎日実行
                    self.audit_logger.cleanup_old_logs()

                time.sleep(3600)  # 1時間間隔
            except Exception as e:
                logger.error(f"監査ループエラー: {e}")


# 使用例
def example_usage():
    manager = EnterpriseAuditManager()

    # システム開始
    manager.start_audit_system()

    # いくつかの監査イベントを記録
    manager.record_audit_event(
        AuditEventType.USER_LOGIN,
        user_id="user_123",
        action="login",
        details={"method": "password"},
        compliance_standards=[ComplianceStandard.GDPR],
        risk_level="low"
    )

    manager.record_audit_event(
        AuditEventType.DATA_ACCESS,
        user_id="user_123",
        resource="user_data",
        action="read",
        details={"record_count": 10},
        compliance_standards=[ComplianceStandard.HIPAA],
        risk_level="medium"
    )

    manager.record_audit_event(
        AuditEventType.ADMIN_ACTION,
        user_id="admin_456",
        resource="system_config",
        action="modify",
        details={"config_section": "security"},
        compliance_standards=[ComplianceStandard.SOX, ComplianceStandard.ISO_27001],
        risk_level="high"
    )

    # サマリー取得
    summary = manager.get_audit_summary(days=1)
    print(f"監査サマリー: {summary}")

    # コンプライアンスレポート生成
    report = manager.generate_monthly_report(ComplianceStandard.GDPR)
    print(f"GDPRレポート: スコア={report.compliance_score:.2f}, 違反={len(report.violations)}件")

    manager.stop_audit_system()


if __name__ == "__main__":
    example_usage()
