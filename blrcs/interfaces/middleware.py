import time
import asyncio
import logging
from typing import Optional, Dict, Any, Callable
from functools import wraps
import json
import traceback

from .rate_limiter import RateLimiter, RateLimitConfig
from .csrf_protection import CSRFProtection
from .input_validator import InputValidator, ValidationRule
from .security_headers import SecurityHeaders, SecurityHeaderConfig
from .audit_logger import AuditLogger

logger = logging.getLogger(__name__)

class SecurityMiddleware:
    """統合セキュリティミドルウェア"""
    
    def __init__(self):
        self.rate_limiter = RateLimiter(RateLimitConfig())
        self.csrf_protection = CSRFProtection()
        self.input_validator = InputValidator()
        self.security_headers = SecurityHeaders(SecurityHeaderConfig())
        self.audit_logger = AuditLogger()
        
    async def __call__(self, request, call_next):
        """ミドルウェア処理"""
        start_time = time.time()
        request_id = self._generate_request_id()
        
        # リクエストコンテキスト設定
        request.state.request_id = request_id
        request.state.start_time = start_time
        
        try:
            # 1. レート制限チェック
            ip_address = self._get_client_ip(request)
            user_id = self._get_user_id(request)
            
            allowed, error_msg = await self.rate_limiter.check_rate_limit(ip_address, user_id)
            if not allowed:
                await self.audit_logger.log_rate_limit_violation(ip_address, user_id)
                return self._rate_limit_response(error_msg)
                
            # 2. CSRF保護（POST/PUT/DELETE）
            if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
                session_id = self._get_session_id(request)
                csrf_token = self._get_csrf_token(request)
                
                valid, error_msg = self.csrf_protection.validate_token(session_id, csrf_token)
                if not valid:
                    await self.audit_logger.log_csrf_violation(ip_address, session_id)
                    return self._csrf_error_response(error_msg)
                    
            # 3. 入力検証
            if request.method in ["POST", "PUT", "PATCH"]:
                validation_errors = await self._validate_request_body(request)
                if validation_errors:
                    await self.audit_logger.log_validation_failure(ip_address, validation_errors)
                    return self._validation_error_response(validation_errors)
                    
            # 4. リクエスト処理
            response = await call_next(request)
            
            # 5. セキュリティヘッダー追加
            request_context = {
                "origin": request.headers.get("Origin"),
                "method": request.method,
                "sensitive_data": self._contains_sensitive_data(response)
            }
            
            security_headers_dict = self.security_headers.get_headers(request_context)
            for header_name, header_value in security_headers_dict.items():
                response.headers[header_name] = header_value
                
            # 6. レスポンス時間記録
            response_time = time.time() - start_time
            response.headers["X-Response-Time"] = f"{response_time:.3f}s"
            response.headers["X-Request-ID"] = request_id
            
            # 7. 監査ログ
            await self.audit_logger.log_request(
                ip_address, user_id, request.method, 
                request.url.path, response.status_code, response_time
            )
            
            return response
            
        except Exception as e:
            # エラーログ
            logger.error(f"Middleware error: {e}", exc_info=True)
            await self.audit_logger.log_error(ip_address, str(e), traceback.format_exc())
            
            return self._internal_error_response()
            
    def _generate_request_id(self) -> str:
        """リクエストID生成"""
        import uuid
        return str(uuid.uuid4())
        
    def _get_client_ip(self, request) -> str:
        """クライアントIP取得"""
        # X-Forwarded-For ヘッダーチェック
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
            
        # X-Real-IP ヘッダーチェック
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
            
        # デフォルト
        return request.client.host if request.client else "unknown"
        
    def _get_user_id(self, request) -> Optional[str]:
        """ユーザーID取得"""
        # JWTトークンから取得
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]
            # JWT デコード - セキュリティライブラリ使用推奨
            return None
            
        # セッションから取得
        if hasattr(request.state, "user_id"):
            return request.state.user_id
            
        return None
        
    def _get_session_id(self, request) -> Optional[str]:
        """セッションID取得"""
        # クッキーから取得
        session_cookie = request.cookies.get("session_id")
        if session_cookie:
            return session_cookie
            
        # ヘッダーから取得
        return request.headers.get("X-Session-ID")
        
    def _get_csrf_token(self, request) -> Optional[str]:
        """CSRFトークン取得"""
        # ヘッダーから取得
        csrf_header = request.headers.get("X-CSRF-Token")
        if csrf_header:
            return csrf_header
            
        # フォームデータから取得
        if hasattr(request, "form"):
            return request.form.get("csrf_token")
            
        # JSONボディから取得
        if hasattr(request, "json"):
            try:
                body = request.json()
                return body.get("csrf_token")
            except:
                pass
                
        return None
        
    async def _validate_request_body(self, request) -> List[str]:
        """リクエストボディ検証"""
        errors = []
        
        try:
            # Content-Type チェック
            content_type = request.headers.get("Content-Type", "")
            
            if "application/json" in content_type:
                body = await request.body()
                data = json.loads(body)
                
                # 各フィールドの検証
                for field_name, field_value in data.items():
                    if isinstance(field_value, str):
                        # 文字列フィールドの検証
                        rule = ValidationRule(
                            field_name=field_name,
                            data_type=str,
                            max_length=10000
                        )
                        valid, field_errors = self.input_validator.validate_input(
                            field_value, rule
                        )
                        errors.extend(field_errors)
                        
        except Exception as e:
            errors.append(f"Request body validation error: {str(e)}")
            
        return errors
        
    def _contains_sensitive_data(self, response) -> bool:
        """レスポンスに機密データが含まれるかチェック"""
        # パスベースのチェック
        sensitive_paths = ["/api/auth", "/api/user", "/api/payment", "/api/wallet"]
        
        if hasattr(response, "url"):
            for path in sensitive_paths:
                if path in str(response.url):
                    return True
                    
        return False
        
    def _rate_limit_response(self, message: str):
        """レート制限エラーレスポンス"""
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=429,
            content={"error": "Too Many Requests", "message": message},
            headers={"Retry-After": "60"}
        )
        
    def _csrf_error_response(self, message: str):
        """CSRFエラーレスポンス"""
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=403,
            content={"error": "CSRF Protection", "message": message}
        )
        
    def _validation_error_response(self, errors: List[str]):
        """検証エラーレスポンス"""
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=400,
            content={"error": "Validation Failed", "errors": errors}
        )
        
    def _internal_error_response(self):
        """内部エラーレスポンス"""
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=500,
            content={"error": "Internal Server Error", "message": "An unexpected error occurred"}
        )

class PerformanceMiddleware:
    """パフォーマンス最適化ミドルウェア"""
    
    def __init__(self):
        self.cache = {}
        self.metrics = {}
        
    async def __call__(self, request, call_next):
        """ミドルウェア処理"""
        # キャッシュ可能なGETリクエスト
        if request.method == "GET":
            cache_key = self._get_cache_key(request)
            
            # キャッシュヒット
            if cache_key in self.cache:
                cached_response, cached_time = self.cache[cache_key]
                if time.time() - cached_time < 300:  # 5分間キャッシュ
                    cached_response.headers["X-Cache"] = "HIT"
                    return cached_response
                    
        # 圧縮設定
        accept_encoding = request.headers.get("Accept-Encoding", "")
        
        # レスポンス処理
        response = await call_next(request)
        
        # キャッシュ保存
        if request.method == "GET" and response.status_code == 200:
            cache_key = self._get_cache_key(request)
            self.cache[cache_key] = (response, time.time())
            response.headers["X-Cache"] = "MISS"
            
        # 圧縮
        if "gzip" in accept_encoding:
            response.headers["Content-Encoding"] = "gzip"
            
        return response
        
    def _get_cache_key(self, request) -> str:
        """キャッシュキー生成"""
        import hashlib
        key_parts = [
            request.method,
            str(request.url),
            request.headers.get("Accept", ""),
            request.headers.get("Accept-Language", "")
        ]
        key_string = ":".join(key_parts)
        return hashlib.sha256(key_string.encode()).hexdigest()

class ErrorHandlingMiddleware:
    """エラーハンドリングミドルウェア"""
    
    def __init__(self):
        self.error_handlers = {}
        
    async def __call__(self, request, call_next):
        """ミドルウェア処理"""
        try:
            response = await call_next(request)
            return response
            
        except ValueError as e:
            return self._handle_value_error(e)
            
        except KeyError as e:
            return self._handle_key_error(e)
            
        except PermissionError as e:
            return self._handle_permission_error(e)
            
        except TimeoutError as e:
            return self._handle_timeout_error(e)
            
        except Exception as e:
            return self._handle_generic_error(e)
            
    def _handle_value_error(self, error):
        """値エラーハンドリング"""
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=400,
            content={
                "error": "Invalid Value",
                "message": str(error),
                "type": "ValueError"
            }
        )
        
    def _handle_key_error(self, error):
        """キーエラーハンドリング"""
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=400,
            content={
                "error": "Missing Required Field",
                "message": f"Required field not found: {str(error)}",
                "type": "KeyError"
            }
        )
        
    def _handle_permission_error(self, error):
        """権限エラーハンドリング"""
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=403,
            content={
                "error": "Permission Denied",
                "message": str(error),
                "type": "PermissionError"
            }
        )
        
    def _handle_timeout_error(self, error):
        """タイムアウトエラーハンドリング"""
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=504,
            content={
                "error": "Request Timeout",
                "message": "The request took too long to process",
                "type": "TimeoutError"
            }
        )
        
    def _handle_generic_error(self, error):
        """一般エラーハンドリング"""
        from fastapi.responses import JSONResponse
        logger.error(f"Unhandled error: {error}", exc_info=True)
        
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal Server Error",
                "message": "An unexpected error occurred",
                "type": type(error).__name__
            }
        )