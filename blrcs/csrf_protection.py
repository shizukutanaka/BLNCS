import secrets
import hashlib
import time
from typing import Optional, Dict, Tuple
import hmac
import logging

logger = logging.getLogger(__name__)

class CSRFProtection:
    """CSRF攻撃防御実装"""
    
    def __init__(self, secret_key: str = None):
        self.secret_key = secret_key or secrets.token_hex(32)
        self.tokens: Dict[str, float] = {}
        self.token_ttl = 3600  # 1時間
        self.max_tokens_per_session = 10
        
    def generate_token(self, session_id: str) -> str:
        """CSRFトークン生成"""
        if not session_id:
            raise ValueError("Session ID is required")
            
        # セッションごとのトークン数制限
        self._cleanup_session_tokens(session_id)
        
        # 新しいトークン生成
        token = secrets.token_urlsafe(32)
        timestamp = str(int(time.time()))
        
        # HMAC署名付きトークン
        signature = self._create_signature(session_id, token, timestamp)
        signed_token = f"{token}.{timestamp}.{signature}"
        
        # トークン保存
        token_key = f"{session_id}:{token}"
        self.tokens[token_key] = time.time()
        
        logger.debug(f"Generated CSRF token for session {session_id}")
        return signed_token
        
    def validate_token(self, session_id: str, token: str) -> Tuple[bool, str]:
        """トークン検証"""
        if not session_id or not token:
            return False, "Missing session or token"
            
        try:
            # トークン分解
            parts = token.split('.')
            if len(parts) != 3:
                return False, "Invalid token format"
                
            token_value, timestamp, signature = parts
            
            # 署名検証
            expected_signature = self._create_signature(session_id, token_value, timestamp)
            if not hmac.compare_digest(signature, expected_signature):
                return False, "Invalid token signature"
                
            # タイムスタンプ検証
            token_time = int(timestamp)
            if time.time() - token_time > self.token_ttl:
                return False, "Token expired"
                
            # トークン存在確認
            token_key = f"{session_id}:{token_value}"
            if token_key not in self.tokens:
                return False, "Token not found or already used"
                
            # 使用済みトークンを削除（ワンタイム使用）
            del self.tokens[token_key]
            
            logger.debug(f"CSRF token validated for session {session_id}")
            return True, "Token valid"
            
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return False, "Token validation failed"
            
    def _create_signature(self, session_id: str, token: str, timestamp: str) -> str:
        """HMAC署名生成"""
        message = f"{session_id}:{token}:{timestamp}"
        signature = hmac.new(
            self.secret_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        return signature
        
    def _cleanup_session_tokens(self, session_id: str):
        """セッションの古いトークンをクリーンアップ"""
        current_time = time.time()
        session_prefix = f"{session_id}:"
        
        # 期限切れトークン削除
        expired_tokens = []
        session_tokens = []
        
        for token_key, created_time in self.tokens.items():
            if token_key.startswith(session_prefix):
                if current_time - created_time > self.token_ttl:
                    expired_tokens.append(token_key)
                else:
                    session_tokens.append((token_key, created_time))
                    
        # 期限切れ削除
        for token_key in expired_tokens:
            del self.tokens[token_key]
            
        # トークン数制限
        if len(session_tokens) >= self.max_tokens_per_session:
            # 最も古いトークンを削除
            session_tokens.sort(key=lambda x: x[1])
            for i in range(len(session_tokens) - self.max_tokens_per_session + 1):
                del self.tokens[session_tokens[i][0]]
                
    def cleanup_expired_tokens(self):
        """全体の期限切れトークンクリーンアップ"""
        current_time = time.time()
        expired = []
        
        for token_key, created_time in self.tokens.items():
            if current_time - created_time > self.token_ttl:
                expired.append(token_key)
                
        for token_key in expired:
            del self.tokens[token_key]
            
        if expired:
            logger.info(f"Cleaned up {len(expired)} expired CSRF tokens")
            
    def get_token_header_name(self) -> str:
        """CSRFトークンヘッダー名"""
        return "X-CSRF-Token"
        
    def get_token_field_name(self) -> str:
        """CSRFトークンフィールド名"""
        return "csrf_token"