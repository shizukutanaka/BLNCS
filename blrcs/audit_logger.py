import time
import json
import hashlib
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from enum import Enum
import logging
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)

class AuditEventType(Enum):
    """監査イベントタイプ"""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    CONFIGURATION_CHANGE = "configuration_change"
    SECURITY_VIOLATION = "security_violation"
    SYSTEM_ACCESS = "system_access"
    ERROR = "error"
    PERFORMANCE = "performance"

@dataclass
class AuditEvent:
    """監査イベント"""
    timestamp: float
    event_type: AuditEventType
    user_id: Optional[str]
    ip_address: str
    action: str
    resource: Optional[str]
    result: str
    details: Dict[str, Any]
    risk_score: int = 0
    session_id: Optional[str] = None
    correlation_id: Optional[str] = None

class AuditLogger:
    """包括的監査ログシステム"""
    
    def __init__(self, db_path: str = "audit.db", encryption_key: Optional[str] = None):
        self.db_path = Path(db_path)
        self.encryption_key = encryption_key
        self.buffer: List[AuditEvent] = []
        self.buffer_size = 100
        self.flush_interval = 10  # 秒
        self._init_database()
        self._start_flush_task()
        
    def _init_database(self):
        """データベース初期化"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    event_type TEXT NOT NULL,
                    user_id TEXT,
                    ip_address TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource TEXT,
                    result TEXT NOT NULL,
                    details TEXT NOT NULL,
                    risk_score INTEGER DEFAULT 0,
                    session_id TEXT,
                    correlation_id TEXT,
                    hash TEXT NOT NULL,
                    INDEX idx_timestamp (timestamp),
                    INDEX idx_user_id (user_id),
                    INDEX idx_event_type (event_type),
                    INDEX idx_risk_score (risk_score)
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    details TEXT NOT NULL,
                    resolved BOOLEAN DEFAULT FALSE,
                    resolved_at REAL,
                    resolved_by TEXT
                )
            """)
            
    def _start_flush_task(self):
        """定期フラッシュタスク開始"""
        asyncio.create_task(self._flush_loop())
        
    async def _flush_loop(self):
        """定期的にバッファをフラッシュ"""
        while True:
            await asyncio.sleep(self.flush_interval)
            await self.flush()
            
    async def log_event(self, event: AuditEvent):
        """監査イベントログ"""
        # リスクスコア計算
        event.risk_score = self._calculate_risk_score(event)
        
        # バッファに追加
        self.buffer.append(event)
        
        # 高リスクイベントは即座にフラッシュ
        if event.risk_score >= 80:
            await self.flush()
            await self._create_alert(event)
        elif len(self.buffer) >= self.buffer_size:
            await self.flush()
            
    async def flush(self):
        """バッファをデータベースにフラッシュ"""
        if not self.buffer:
            return
            
        events_to_write = self.buffer.copy()
        self.buffer.clear()
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                for event in events_to_write:
                    # イベントハッシュ生成（改ざん検出用）
                    event_hash = self._generate_event_hash(event)
                    
                    # 詳細を暗号化（オプション）
                    details_json = json.dumps(event.details)
                    if self.encryption_key:
                        details_json = self._encrypt(details_json)
                        
                    conn.execute("""
                        INSERT INTO audit_logs 
                        (timestamp, event_type, user_id, ip_address, action, 
                         resource, result, details, risk_score, session_id, 
                         correlation_id, hash)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        event.timestamp,
                        event.event_type.value,
                        event.user_id,
                        event.ip_address,
                        event.action,
                        event.resource,
                        event.result,
                        details_json,
                        event.risk_score,
                        event.session_id,
                        event.correlation_id,
                        event_hash
                    ))
                    
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to flush audit logs: {e}")
            # バッファに戻す
            self.buffer = events_to_write + self.buffer
            
    def _calculate_risk_score(self, event: AuditEvent) -> int:
        """リスクスコア計算"""
        score = 0
        
        # イベントタイプによる基本スコア
        risk_scores = {
            AuditEventType.SECURITY_VIOLATION: 80,
            AuditEventType.AUTHORIZATION: 40,
            AuditEventType.AUTHENTICATION: 30,
            AuditEventType.CONFIGURATION_CHANGE: 50,
            AuditEventType.DATA_MODIFICATION: 30,
            AuditEventType.DATA_ACCESS: 20,
            AuditEventType.ERROR: 60,
            AuditEventType.SYSTEM_ACCESS: 40,
            AuditEventType.PERFORMANCE: 10
        }
        
        score = risk_scores.get(event.event_type, 0)
        
        # 失敗結果の場合はスコア増加
        if event.result.lower() in ["failed", "denied", "error"]:
            score += 20
            
        # 異常なIPアドレス
        if self._is_suspicious_ip(event.ip_address):
            score += 30
            
        # 異常な時間帯
        if self._is_suspicious_time(event.timestamp):
            score += 10
            
        # 特定のアクション
        suspicious_actions = ["delete", "drop", "truncate", "alter", "grant", "revoke"]
        if any(action in event.action.lower() for action in suspicious_actions):
            score += 20
            
        return min(100, score)
        
    def _is_suspicious_ip(self, ip_address: str) -> bool:
        """疑わしいIPアドレスチェック"""
        # 既知の悪意のあるIP範囲チェック
        suspicious_ranges = [
            "10.0.0.0/8",  # プライベートIP（内部からの異常アクセス）
            "192.168.0.0/16",
            "172.16.0.0/12"
        ]
        
        # Tor出口ノードチェック
        # Tor出口ノード検証 - 将来実装予定
        if self._is_tor_exit_node(ip_addr):
            anomalies.append("tor_exit_node_detected")
        
        return False
        
    def _is_suspicious_time(self, timestamp: float) -> bool:
        """疑わしい時間帯チェック"""
        dt = datetime.fromtimestamp(timestamp)
        hour = dt.hour
        
        # 深夜から早朝（1:00 - 5:00）
        if 1 <= hour <= 5:
            return True
            
        # 週末
        if dt.weekday() >= 5:
            return True
            
        return False
        
    def _generate_event_hash(self, event: AuditEvent) -> str:
        """イベントハッシュ生成"""
        event_str = f"{event.timestamp}{event.event_type.value}{event.user_id}"
        event_str += f"{event.ip_address}{event.action}{event.resource}{event.result}"
        return hashlib.sha256(event_str.encode()).hexdigest()
        
    def _encrypt(self, data: str) -> str:
        """データ暗号化"""
        if not self.encryption_key:
            return data
            
        # 簡易暗号化（本番環境では適切な暗号化ライブラリを使用）
        from cryptography.fernet import Fernet
        f = Fernet(self.encryption_key.encode()[:32].ljust(32, b'0'))
        return f.encrypt(data.encode()).decode()
        
    def _decrypt(self, data: str) -> str:
        """データ復号化"""
        if not self.encryption_key:
            return data
            
        from cryptography.fernet import Fernet
        f = Fernet(self.encryption_key.encode()[:32].ljust(32, b'0'))
        return f.decrypt(data.encode()).decode()
        
    async def _create_alert(self, event: AuditEvent):
        """アラート作成"""
        severity = "HIGH" if event.risk_score >= 80 else "MEDIUM"
        
        alert_description = f"High risk event detected: {event.event_type.value}"
        alert_details = {
            "event_id": event.correlation_id,
            "user_id": event.user_id,
            "ip_address": event.ip_address,
            "action": event.action,
            "risk_score": event.risk_score
        }
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO audit_alerts 
                (timestamp, alert_type, severity, description, details)
                VALUES (?, ?, ?, ?, ?)
            """, (
                time.time(),
                event.event_type.value,
                severity,
                alert_description,
                json.dumps(alert_details)
            ))
            
        logger.warning(f"Security alert created: {alert_description}")
        
    async def log_authentication(self, user_id: str, ip_address: str, 
                                success: bool, method: str = "password"):
        """認証イベントログ"""
        await self.log_event(AuditEvent(
            timestamp=time.time(),
            event_type=AuditEventType.AUTHENTICATION,
            user_id=user_id,
            ip_address=ip_address,
            action=f"login_{method}",
            resource="auth_system",
            result="success" if success else "failed",
            details={"method": method}
        ))
        
    async def log_authorization(self, user_id: str, ip_address: str,
                               resource: str, action: str, allowed: bool):
        """認可イベントログ"""
        await self.log_event(AuditEvent(
            timestamp=time.time(),
            event_type=AuditEventType.AUTHORIZATION,
            user_id=user_id,
            ip_address=ip_address,
            action=action,
            resource=resource,
            result="allowed" if allowed else "denied",
            details={"resource": resource, "action": action}
        ))
        
    async def log_data_access(self, user_id: str, ip_address: str,
                             resource: str, operation: str):
        """データアクセスログ"""
        await self.log_event(AuditEvent(
            timestamp=time.time(),
            event_type=AuditEventType.DATA_ACCESS,
            user_id=user_id,
            ip_address=ip_address,
            action=operation,
            resource=resource,
            result="success",
            details={"operation": operation}
        ))
        
    async def log_rate_limit_violation(self, ip_address: str, user_id: Optional[str]):
        """レート制限違反ログ"""
        await self.log_event(AuditEvent(
            timestamp=time.time(),
            event_type=AuditEventType.SECURITY_VIOLATION,
            user_id=user_id,
            ip_address=ip_address,
            action="rate_limit_exceeded",
            resource="api",
            result="blocked",
            details={"violation_type": "rate_limit"}
        ))
        
    async def log_csrf_violation(self, ip_address: str, session_id: str):
        """CSRF違反ログ"""
        await self.log_event(AuditEvent(
            timestamp=time.time(),
            event_type=AuditEventType.SECURITY_VIOLATION,
            user_id=None,
            ip_address=ip_address,
            action="csrf_token_invalid",
            resource="api",
            result="blocked",
            details={"violation_type": "csrf"},
            session_id=session_id
        ))
        
    async def log_validation_failure(self, ip_address: str, errors: List[str]):
        """検証失敗ログ"""
        await self.log_event(AuditEvent(
            timestamp=time.time(),
            event_type=AuditEventType.SECURITY_VIOLATION,
            user_id=None,
            ip_address=ip_address,
            action="input_validation_failed",
            resource="api",
            result="blocked",
            details={"errors": errors}
        ))
        
    async def log_request(self, ip_address: str, user_id: Optional[str],
                         method: str, path: str, status_code: int,
                         response_time: float):
        """HTTPリクエストログ"""
        await self.log_event(AuditEvent(
            timestamp=time.time(),
            event_type=AuditEventType.SYSTEM_ACCESS,
            user_id=user_id,
            ip_address=ip_address,
            action=f"{method}_{path}",
            resource=path,
            result=str(status_code),
            details={
                "method": method,
                "path": path,
                "status_code": status_code,
                "response_time": response_time
            }
        ))
        
    async def log_error(self, ip_address: str, error: str, stack_trace: str):
        """エラーログ"""
        await self.log_event(AuditEvent(
            timestamp=time.time(),
            event_type=AuditEventType.ERROR,
            user_id=None,
            ip_address=ip_address,
            action="system_error",
            resource="system",
            result="error",
            details={
                "error": error,
                "stack_trace": stack_trace[:1000]  # 制限
            }
        ))
        
    def query_logs(self, start_time: float = None, end_time: float = None,
                  event_type: AuditEventType = None, user_id: str = None,
                  min_risk_score: int = None) -> List[Dict]:
        """監査ログクエリ"""
        query = "SELECT * FROM audit_logs WHERE 1=1"
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
            
        if min_risk_score:
            query += " AND risk_score >= ?"
            params.append(min_risk_score)
            
        query += " ORDER BY timestamp DESC LIMIT 1000"
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
            
    def verify_integrity(self) -> bool:
        """ログ整合性検証"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT timestamp, event_type, user_id, ip_address, 
                       action, resource, result, hash
                FROM audit_logs
                ORDER BY timestamp
            """)
            
            for row in cursor:
                # ハッシュ再計算
                event_str = f"{row[0]}{row[1]}{row[2]}{row[3]}{row[4]}{row[5]}{row[6]}"
                expected_hash = hashlib.sha256(event_str.encode()).hexdigest()
                
                if expected_hash != row[7]:
                    logger.error(f"Integrity check failed for audit log at {row[0]}")
                    return False
                    
        return True