"""セッションセキュリティ管理システム"""

import time
import secrets
import hashlib
import hmac
import json
import logging
from typing import Dict, Optional, Any, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import asyncio
from enum import Enum

logger = logging.getLogger(__name__)

class SessionStatus(Enum):
    """セッションステータス"""
    ACTIVE = "active"
    EXPIRED = "expired"
    INVALIDATED = "invalidated"
    LOCKED = "locked"

@dataclass
class SessionData:
    """セッションデータ"""
    session_id: str
    user_id: str
    created_at: float
    last_activity: float
    ip_address: str
    user_agent: str
    fingerprint: str
    status: SessionStatus = SessionStatus.ACTIVE
    data: Dict[str, Any] = field(default_factory=dict)
    failed_attempts: int = 0
    refresh_token: Optional[str] = None
    expires_at: Optional[float] = None

class SessionSecurityManager:
    """セッションセキュリティマネージャー"""
    
    def __init__(self):
        self.sessions: Dict[str, SessionData] = {}
        self.session_timeout = 3600  # 1時間
        self.absolute_timeout = 86400  # 24時間
        self.max_failed_attempts = 5
        self.fingerprint_salt = secrets.token_hex(32)
        self.session_secret = secrets.token_bytes(32)
        self.cleanup_interval = 300  # 5分ごとにクリーンアップ
        self._start_cleanup_task()
        
    def _start_cleanup_task(self):
        """クリーンアップタスク開始"""
        asyncio.create_task(self._cleanup_expired_sessions())
        
    async def _cleanup_expired_sessions(self):
        """期限切れセッションのクリーンアップ"""
        while True:
            try:
                await asyncio.sleep(self.cleanup_interval)
                current_time = time.time()
                expired_sessions = []
                
                for session_id, session in self.sessions.items():
                    if self._is_session_expired(session, current_time):
                        expired_sessions.append(session_id)
                        
                for session_id in expired_sessions:
                    await self.invalidate_session(session_id)
                    
                if expired_sessions:
                    logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
                    
            except Exception as e:
                logger.error(f"Session cleanup error: {e}")
                
    def create_session(self, user_id: str, ip_address: str, user_agent: str) -> Tuple[str, str]:
        """セッション作成"""
        session_id = self._generate_session_id()
        fingerprint = self._generate_fingerprint(ip_address, user_agent)
        refresh_token = secrets.token_urlsafe(32)
        
        session = SessionData(
            session_id=session_id,
            user_id=user_id,
            created_at=time.time(),
            last_activity=time.time(),
            ip_address=ip_address,
            user_agent=user_agent,
            fingerprint=fingerprint,
            refresh_token=refresh_token,
            expires_at=time.time() + self.absolute_timeout
        )
        
        self.sessions[session_id] = session
        logger.info(f"Session created for user {user_id} from {ip_address}")
        
        return session_id, refresh_token
        
    def validate_session(self, session_id: str, ip_address: str, user_agent: str) -> Tuple[bool, Optional[str]]:
        """セッション検証"""
        if session_id not in self.sessions:
            return False, "Session not found"
            
        session = self.sessions[session_id]
        current_time = time.time()
        
        # ステータスチェック
        if session.status != SessionStatus.ACTIVE:
            return False, f"Session {session.status.value}"
            
        # 絶対タイムアウトチェック
        if session.expires_at and current_time > session.expires_at:
            session.status = SessionStatus.EXPIRED
            return False, "Session expired (absolute timeout)"
            
        # アイドルタイムアウトチェック
        if current_time - session.last_activity > self.session_timeout:
            session.status = SessionStatus.EXPIRED
            return False, "Session expired (idle timeout)"
            
        # フィンガープリント検証
        expected_fingerprint = self._generate_fingerprint(ip_address, user_agent)
        if not self._verify_fingerprint(session.fingerprint, expected_fingerprint):
            session.failed_attempts += 1
            if session.failed_attempts >= self.max_failed_attempts:
                session.status = SessionStatus.LOCKED
                return False, "Session locked due to suspicious activity"
            return False, "Session fingerprint mismatch"
            
        # セッション更新
        session.last_activity = current_time
        session.failed_attempts = 0
        
        return True, None
        
    def refresh_session(self, session_id: str, refresh_token: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """セッションリフレッシュ"""
        if session_id not in self.sessions:
            return False, None, "Session not found"
            
        session = self.sessions[session_id]
        
        # リフレッシュトークン検証
        if not session.refresh_token or not secrets.compare_digest(session.refresh_token, refresh_token):
            session.failed_attempts += 1
            if session.failed_attempts >= self.max_failed_attempts:
                session.status = SessionStatus.LOCKED
            return False, None, "Invalid refresh token"
            
        # 新しいリフレッシュトークン生成
        new_refresh_token = secrets.token_urlsafe(32)
        session.refresh_token = new_refresh_token
        session.last_activity = time.time()
        session.expires_at = time.time() + self.absolute_timeout
        session.failed_attempts = 0
        
        logger.info(f"Session refreshed for user {session.user_id}")
        
        return True, new_refresh_token, None
        
    async def invalidate_session(self, session_id: str):
        """セッション無効化"""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            session.status = SessionStatus.INVALIDATED
            
            # セッションデータをクリア
            session.data.clear()
            session.refresh_token = None
            
            # 一定時間後に完全削除
            await asyncio.sleep(60)  # 1分後
            if session_id in self.sessions:
                del self.sessions[session_id]
                
            logger.info(f"Session invalidated for user {session.user_id}")
            
    def get_session_data(self, session_id: str) -> Optional[Dict[str, Any]]:
        """セッションデータ取得"""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            if session.status == SessionStatus.ACTIVE:
                return session.data
        return None
        
    def set_session_data(self, session_id: str, key: str, value: Any) -> bool:
        """セッションデータ設定"""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            if session.status == SessionStatus.ACTIVE:
                session.data[key] = value
                return True
        return False
        
    def _generate_session_id(self) -> str:
        """セッションID生成"""
        random_bytes = secrets.token_bytes(32)
        timestamp = str(time.time()).encode()
        
        h = hashlib.sha256()
        h.update(random_bytes)
        h.update(timestamp)
        h.update(self.session_secret)
        
        return h.hexdigest()
        
    def _generate_fingerprint(self, ip_address: str, user_agent: str) -> str:
        """フィンガープリント生成"""
        data = f"{ip_address}:{user_agent}:{self.fingerprint_salt}"
        return hashlib.sha256(data.encode()).hexdigest()
        
    def _verify_fingerprint(self, stored: str, provided: str) -> bool:
        """フィンガープリント検証"""
        return secrets.compare_digest(stored, provided)
        
    def _is_session_expired(self, session: SessionData, current_time: float) -> bool:
        """セッション期限切れチェック"""
        if session.status != SessionStatus.ACTIVE:
            return True
            
        if session.expires_at and current_time > session.expires_at:
            return True
            
        if current_time - session.last_activity > self.session_timeout:
            return True
            
        return False
        
    def get_active_sessions(self, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """アクティブセッション取得"""
        active_sessions = []
        current_time = time.time()
        
        for session in self.sessions.values():
            if session.status == SessionStatus.ACTIVE and not self._is_session_expired(session, current_time):
                if user_id is None or session.user_id == user_id:
                    active_sessions.append({
                        "session_id": session.session_id,
                        "user_id": session.user_id,
                        "created_at": session.created_at,
                        "last_activity": session.last_activity,
                        "ip_address": session.ip_address,
                        "remaining_time": self.session_timeout - (current_time - session.last_activity)
                    })
                    
        return active_sessions
        
    def terminate_user_sessions(self, user_id: str, except_session: Optional[str] = None):
        """ユーザーの全セッション終了"""
        terminated = 0
        
        for session_id, session in list(self.sessions.items()):
            if session.user_id == user_id and session_id != except_session:
                session.status = SessionStatus.INVALIDATED
                terminated += 1
                
        logger.info(f"Terminated {terminated} sessions for user {user_id}")
        return terminated

class SessionHijackingProtection:
    """セッションハイジャック保護"""
    
    def __init__(self):
        self.ip_change_threshold = 3  # IPアドレス変更の閾値
        self.suspicious_patterns = []
        self.blocked_ips = set()
        
    def detect_hijacking(self, session: SessionData, new_ip: str, new_agent: str) -> Tuple[bool, str]:
        """ハイジャック検出"""
        risk_score = 0
        reasons = []
        
        # IPアドレス変更チェック
        if session.ip_address != new_ip:
            risk_score += 30
            reasons.append("IP address changed")
            
            # 地理的距離チェック（簡略版）
            if self._is_suspicious_ip_change(session.ip_address, new_ip):
                risk_score += 40
                reasons.append("Suspicious IP location change")
                
        # User-Agent変更チェック
        if session.user_agent != new_agent:
            risk_score += 20
            reasons.append("User-Agent changed")
            
            # ブラウザ/OS変更チェック
            if self._is_major_agent_change(session.user_agent, new_agent):
                risk_score += 30
                reasons.append("Major browser/OS change")
                
        # 時間ベースの異常検出
        if self._is_suspicious_timing(session):
            risk_score += 20
            reasons.append("Suspicious access timing")
            
        # ブロックされたIPチェック
        if new_ip in self.blocked_ips:
            risk_score += 50
            reasons.append("IP is blocked")
            
        is_hijacked = risk_score >= 70
        reason = "; ".join(reasons) if reasons else "No issues detected"
        
        if is_hijacked:
            logger.warning(f"Possible session hijacking detected: {reason} (score: {risk_score})")
            
        return is_hijacked, reason
        
    def _is_suspicious_ip_change(self, old_ip: str, new_ip: str) -> bool:
        """疑わしいIP変更チェック"""
        # 簡略版: 最初の2オクテットが異なる場合を疑わしいとする
        old_parts = old_ip.split('.')[:2]
        new_parts = new_ip.split('.')[:2]
        return old_parts != new_parts
        
    def _is_major_agent_change(self, old_agent: str, new_agent: str) -> bool:
        """主要なUser-Agent変更チェック"""
        # ブラウザとOSの主要部分を比較
        old_browser = self._extract_browser(old_agent)
        new_browser = self._extract_browser(new_agent)
        
        old_os = self._extract_os(old_agent)
        new_os = self._extract_os(new_agent)
        
        return old_browser != new_browser or old_os != new_os
        
    def _extract_browser(self, user_agent: str) -> str:
        """ブラウザ情報抽出"""
        browsers = ["Chrome", "Firefox", "Safari", "Edge", "Opera"]
        for browser in browsers:
            if browser in user_agent:
                return browser
        return "Unknown"
        
    def _extract_os(self, user_agent: str) -> str:
        """OS情報抽出"""
        os_list = ["Windows", "Mac", "Linux", "Android", "iOS"]
        for os in os_list:
            if os in user_agent:
                return os
        return "Unknown"
        
    def _is_suspicious_timing(self, session: SessionData) -> bool:
        """疑わしいタイミングチェック"""
        current_time = time.time()
        time_since_creation = current_time - session.created_at
        
        # セッション作成直後の急激な活動
        if time_since_creation < 5 and session.failed_attempts > 2:
            return True
            
        # 深夜の異常なアクセスパターン
        current_hour = datetime.fromtimestamp(current_time).hour
        if 2 <= current_hour <= 5:  # 深夜2時から5時
            return session.failed_attempts > 1
            
        return False
        
    def block_ip(self, ip_address: str, duration: int = 3600):
        """IP一時ブロック"""
        self.blocked_ips.add(ip_address)
        
        async def unblock():
            await asyncio.sleep(duration)
            self.blocked_ips.discard(ip_address)
            logger.info(f"IP {ip_address} unblocked")
            
        asyncio.create_task(unblock())
        logger.warning(f"IP {ip_address} blocked for {duration} seconds")

# グローバルインスタンス
session_manager = SessionSecurityManager()
hijack_protection = SessionHijackingProtection()