"""JWT認証システム（リフレッシュトークン対応）"""

import jwt
import time
import secrets
import hashlib
import logging
from typing import Dict, Optional, Any, List, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import asyncio

logger = logging.getLogger(__name__)

class TokenType(Enum):
    """トークンタイプ"""
    ACCESS = "access"
    REFRESH = "refresh"
    API = "api"

@dataclass
class TokenPayload:
    """トークンペイロード"""
    user_id: str
    session_id: str
    token_type: TokenType
    issued_at: float
    expires_at: float
    permissions: List[str]
    jti: str  # JWT ID
    
class JWTAuthenticator:
    """JWT認証システム"""
    
    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = secret_key or secrets.token_hex(32)
        self.algorithm = "HS256"
        self.access_token_lifetime = 900  # 15分
        self.refresh_token_lifetime = 604800  # 7日
        self.api_token_lifetime = 2592000  # 30日
        
        # トークンブラックリスト
        self.blacklisted_tokens = set()
        self.refresh_tokens = {}  # refresh_token_id -> token_info
        
        # 統計情報
        self.issued_tokens = 0
        self.verified_tokens = 0
        self.failed_verifications = 0
        
        # クリーンアップタスク開始
        asyncio.create_task(self._cleanup_expired_tokens())
        
    async def _cleanup_expired_tokens(self):
        """期限切れトークンのクリーンアップ"""
        while True:
            try:
                await asyncio.sleep(300)  # 5分ごと
                current_time = time.time()
                
                # ブラックリスト内の期限切れトークンを削除
                expired_tokens = []
                for token_id in self.blacklisted_tokens:
                    try:
                        # トークンをデコードして期限をチェック
                        payload = jwt.decode(token_id, self.secret_key, algorithms=[self.algorithm])
                        if payload.get("exp", 0) < current_time:
                            expired_tokens.append(token_id)
                    except:
                        # デコードに失敗したトークンも削除
                        expired_tokens.append(token_id)
                        
                for token_id in expired_tokens:
                    self.blacklisted_tokens.discard(token_id)
                    
                # 期限切れリフレッシュトークンを削除
                expired_refresh_tokens = []
                for token_id, token_info in self.refresh_tokens.items():
                    if token_info.get("expires_at", 0) < current_time:
                        expired_refresh_tokens.append(token_id)
                        
                for token_id in expired_refresh_tokens:
                    del self.refresh_tokens[token_id]
                    
                if expired_tokens or expired_refresh_tokens:
                    logger.debug(f"Cleaned up {len(expired_tokens)} expired blacklisted tokens and {len(expired_refresh_tokens)} refresh tokens")
                    
            except Exception as e:
                logger.error(f"Token cleanup error: {e}")
                
    def create_access_token(self, user_id: str, session_id: str, permissions: List[str] = None) -> str:
        """アクセストークン作成"""
        current_time = time.time()
        expires_at = current_time + self.access_token_lifetime
        jti = secrets.token_hex(16)
        
        payload = {
            "sub": user_id,
            "sid": session_id,
            "type": TokenType.ACCESS.value,
            "iat": current_time,
            "exp": expires_at,
            "permissions": permissions or [],
            "jti": jti
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        self.issued_tokens += 1
        
        logger.debug(f"Access token created for user {user_id}")
        return token
        
    def create_refresh_token(self, user_id: str, session_id: str) -> str:
        """リフレッシュトークン作成"""
        current_time = time.time()
        expires_at = current_time + self.refresh_token_lifetime
        jti = secrets.token_hex(16)
        
        payload = {
            "sub": user_id,
            "sid": session_id,
            "type": TokenType.REFRESH.value,
            "iat": current_time,
            "exp": expires_at,
            "jti": jti
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        
        # リフレッシュトークン情報を保存
        self.refresh_tokens[jti] = {
            "user_id": user_id,
            "session_id": session_id,
            "created_at": current_time,
            "expires_at": expires_at,
            "used": False
        }
        
        self.issued_tokens += 1
        logger.debug(f"Refresh token created for user {user_id}")
        return token
        
    def create_api_token(self, user_id: str, permissions: List[str], description: str = "") -> str:
        """APIトークン作成"""
        current_time = time.time()
        expires_at = current_time + self.api_token_lifetime
        jti = secrets.token_hex(16)
        
        payload = {
            "sub": user_id,
            "type": TokenType.API.value,
            "iat": current_time,
            "exp": expires_at,
            "permissions": permissions,
            "jti": jti,
            "description": description
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        self.issued_tokens += 1
        
        logger.info(f"API token created for user {user_id}: {description}")
        return token
        
    def verify_token(self, token: str, required_permissions: List[str] = None) -> Tuple[bool, Optional[TokenPayload], Optional[str]]:
        """トークン検証"""
        try:
            # ブラックリストチェック
            if token in self.blacklisted_tokens:
                self.failed_verifications += 1
                return False, None, "Token is blacklisted"
                
            # トークンデコード
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # 必須フィールドチェック
            required_fields = ["sub", "type", "iat", "exp", "jti"]
            for field in required_fields:
                if field not in payload:
                    self.failed_verifications += 1
                    return False, None, f"Missing required field: {field}"
                    
            # 期限チェック
            if payload["exp"] < time.time():
                self.failed_verifications += 1
                return False, None, "Token expired"
                
            # トークンタイプ検証
            token_type = TokenType(payload["type"])
            
            # リフレッシュトークンの特別な検証
            if token_type == TokenType.REFRESH:
                jti = payload["jti"]
                if jti not in self.refresh_tokens:
                    self.failed_verifications += 1
                    return False, None, "Refresh token not found"
                    
                if self.refresh_tokens[jti]["used"]:
                    self.failed_verifications += 1
                    return False, None, "Refresh token already used"
                    
            # 権限チェック
            user_permissions = payload.get("permissions", [])
            if required_permissions:
                missing_permissions = set(required_permissions) - set(user_permissions)
                if missing_permissions:
                    self.failed_verifications += 1
                    return False, None, f"Missing permissions: {list(missing_permissions)}"
                    
            # TokenPayload作成
            token_payload = TokenPayload(
                user_id=payload["sub"],
                session_id=payload.get("sid", ""),
                token_type=token_type,
                issued_at=payload["iat"],
                expires_at=payload["exp"],
                permissions=user_permissions,
                jti=payload["jti"]
            )
            
            self.verified_tokens += 1
            return True, token_payload, None
            
        except jwt.ExpiredSignatureError:
            self.failed_verifications += 1
            return False, None, "Token expired"
        except jwt.InvalidTokenError as e:
            self.failed_verifications += 1
            return False, None, f"Invalid token: {e}"
        except Exception as e:
            self.failed_verifications += 1
            logger.error(f"Token verification error: {e}")
            return False, None, "Token verification failed"
            
    def refresh_access_token(self, refresh_token: str) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
        """アクセストークンリフレッシュ"""
        # リフレッシュトークン検証
        valid, payload, error = self.verify_token(refresh_token)
        if not valid or not payload:
            return False, None, None, error
            
        if payload.token_type != TokenType.REFRESH:
            return False, None, None, "Not a refresh token"
            
        # リフレッシュトークンを使用済みにマーク
        jti = payload.jti
        if jti in self.refresh_tokens:
            self.refresh_tokens[jti]["used"] = True
            
        # 新しいトークンペア作成
        new_access_token = self.create_access_token(
            payload.user_id,
            payload.session_id,
            payload.permissions
        )
        new_refresh_token = self.create_refresh_token(
            payload.user_id,
            payload.session_id
        )
        
        logger.debug(f"Tokens refreshed for user {payload.user_id}")
        return True, new_access_token, new_refresh_token, None
        
    def revoke_token(self, token: str) -> bool:
        """トークン無効化"""
        try:
            # トークンをブラックリストに追加
            self.blacklisted_tokens.add(token)
            
            # リフレッシュトークンの場合は使用済みにマーク
            try:
                payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
                if payload.get("type") == TokenType.REFRESH.value:
                    jti = payload.get("jti")
                    if jti in self.refresh_tokens:
                        self.refresh_tokens[jti]["used"] = True
            except:
                pass  # デコードエラーは無視
                
            logger.info("Token revoked successfully")
            return True
            
        except Exception as e:
            logger.error(f"Token revocation error: {e}")
            return False
            
    def revoke_user_tokens(self, user_id: str) -> int:
        """ユーザーの全トークン無効化"""
        revoked_count = 0
        
        # リフレッシュトークンを無効化
        for jti, token_info in self.refresh_tokens.items():
            if token_info["user_id"] == user_id and not token_info["used"]:
                token_info["used"] = True
                revoked_count += 1
                
        logger.info(f"Revoked {revoked_count} tokens for user {user_id}")
        return revoked_count
        
    def get_token_info(self, token: str) -> Optional[Dict[str, Any]]:
        """トークン情報取得"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            return {
                "user_id": payload.get("sub"),
                "session_id": payload.get("sid"),
                "token_type": payload.get("type"),
                "issued_at": payload.get("iat"),
                "expires_at": payload.get("exp"),
                "permissions": payload.get("permissions", []),
                "jti": payload.get("jti"),
                "description": payload.get("description", ""),
                "is_expired": payload.get("exp", 0) < time.time(),
                "is_blacklisted": token in self.blacklisted_tokens
            }
            
        except Exception as e:
            logger.error(f"Failed to get token info: {e}")
            return None
            
    def get_user_active_tokens(self, user_id: str) -> List[Dict[str, Any]]:
        """ユーザーのアクティブトークン取得"""
        active_tokens = []
        current_time = time.time()
        
        for jti, token_info in self.refresh_tokens.items():
            if (token_info["user_id"] == user_id and 
                not token_info["used"] and 
                token_info["expires_at"] > current_time):
                
                active_tokens.append({
                    "jti": jti,
                    "type": "refresh",
                    "created_at": token_info["created_at"],
                    "expires_at": token_info["expires_at"],
                    "session_id": token_info["session_id"]
                })
                
        return active_tokens
        
    def get_stats(self) -> Dict[str, Any]:
        """統計情報取得"""
        current_time = time.time()
        
        # アクティブなリフレッシュトークン数
        active_refresh_tokens = sum(
            1 for token_info in self.refresh_tokens.values()
            if not token_info["used"] and token_info["expires_at"] > current_time
        )
        
        return {
            "issued_tokens": self.issued_tokens,
            "verified_tokens": self.verified_tokens,
            "failed_verifications": self.failed_verifications,
            "blacklisted_tokens": len(self.blacklisted_tokens),
            "active_refresh_tokens": active_refresh_tokens,
            "total_refresh_tokens": len(self.refresh_tokens),
            "success_rate": (
                self.verified_tokens / (self.verified_tokens + self.failed_verifications)
                if (self.verified_tokens + self.failed_verifications) > 0 else 0
            )
        }

class TokenMiddleware:
    """JWTトークンミドルウェア"""
    
    def __init__(self, authenticator: JWTAuthenticator):
        self.authenticator = authenticator
        
    async def authenticate_request(self, headers: Dict[str, str], required_permissions: List[str] = None) -> Tuple[bool, Optional[TokenPayload], Optional[str]]:
        """リクエスト認証"""
        # Authorizationヘッダーから取得
        auth_header = headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return False, None, "Missing or invalid Authorization header"
            
        token = auth_header[7:]  # "Bearer " を除去
        
        # トークン検証
        valid, payload, error = self.authenticator.verify_token(token, required_permissions)
        
        if not valid:
            logger.warning(f"Authentication failed: {error}")
            
        return valid, payload, error
        
    def require_permissions(self, required_permissions: List[str]):
        """権限要求デコレータ"""
        def decorator(func):
            async def wrapper(*args, **kwargs):
                # リクエストオブジェクトから認証情報を取得
                # 実装は使用するWebフレームワークに依存
                pass
            return wrapper
        return decorator

# グローバルインスタンス
jwt_authenticator = JWTAuthenticator()
token_middleware = TokenMiddleware(jwt_authenticator)