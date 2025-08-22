"""包括的エラーハンドリングシステム"""

import logging
import traceback
import time
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass
from enum import Enum
from functools import wraps
import asyncio

logger = logging.getLogger(__name__)

class ErrorSeverity(Enum):
    """エラー深刻度"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ErrorCategory(Enum):
    """エラーカテゴリー"""
    VALIDATION = "validation"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATABASE = "database"
    NETWORK = "network"
    BUSINESS_LOGIC = "business_logic"
    SYSTEM = "system"
    EXTERNAL_SERVICE = "external_service"
    RATE_LIMIT = "rate_limit"
    UNKNOWN = "unknown"

@dataclass
class ErrorContext:
    """エラーコンテキスト"""
    error_id: str
    timestamp: float
    severity: ErrorSeverity
    category: ErrorCategory
    message: str
    details: Dict[str, Any]
    stack_trace: Optional[str] = None
    user_id: Optional[str] = None
    request_id: Optional[str] = None
    
class ApplicationError(Exception):
    """アプリケーション基底エラー"""
    
    def __init__(self, 
                 message: str,
                 code: str = "APP_ERROR",
                 severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                 category: ErrorCategory = ErrorCategory.UNKNOWN,
                 details: Dict[str, Any] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.severity = severity
        self.category = category
        self.details = details or {}
        self.timestamp = time.time()
        
class ValidationError(ApplicationError):
    """検証エラー"""
    def __init__(self, message: str, field: str = None, **kwargs):
        super().__init__(
            message,
            code="VALIDATION_ERROR",
            severity=ErrorSeverity.LOW,
            category=ErrorCategory.VALIDATION,
            **kwargs
        )
        if field:
            self.details["field"] = field
            
class AuthenticationError(ApplicationError):
    """認証エラー"""
    def __init__(self, message: str = "Authentication failed", **kwargs):
        super().__init__(
            message,
            code="AUTH_ERROR",
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.AUTHENTICATION,
            **kwargs
        )
        
class AuthorizationError(ApplicationError):
    """認可エラー"""
    def __init__(self, message: str = "Access denied", **kwargs):
        super().__init__(
            message,
            code="AUTHZ_ERROR",
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.AUTHORIZATION,
            **kwargs
        )
        
class DatabaseError(ApplicationError):
    """データベースエラー"""
    def __init__(self, message: str, operation: str = None, **kwargs):
        super().__init__(
            message,
            code="DB_ERROR",
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.DATABASE,
            **kwargs
        )
        if operation:
            self.details["operation"] = operation
            
class NetworkError(ApplicationError):
    """ネットワークエラー"""
    def __init__(self, message: str, endpoint: str = None, **kwargs):
        super().__init__(
            message,
            code="NETWORK_ERROR",
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.NETWORK,
            **kwargs
        )
        if endpoint:
            self.details["endpoint"] = endpoint
            
class RateLimitError(ApplicationError):
    """レート制限エラー"""
    def __init__(self, message: str = "Rate limit exceeded", retry_after: int = None, **kwargs):
        super().__init__(
            message,
            code="RATE_LIMIT",
            severity=ErrorSeverity.LOW,
            category=ErrorCategory.RATE_LIMIT,
            **kwargs
        )
        if retry_after:
            self.details["retry_after"] = retry_after

class ErrorHandler:
    """統合エラーハンドラー"""
    
    def __init__(self):
        self.error_handlers: Dict[type, Callable] = {}
        self.error_history: List[ErrorContext] = []
        self.max_history = 1000
        self.recovery_strategies: Dict[ErrorCategory, Callable] = {}
        
    def register_handler(self, error_type: type, handler: Callable):
        """エラーハンドラー登録"""
        self.error_handlers[error_type] = handler
        
    def register_recovery_strategy(self, category: ErrorCategory, strategy: Callable):
        """リカバリー戦略登録"""
        self.recovery_strategies[category] = strategy
        
    async def handle_error(self, error: Exception, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """エラー処理"""
        import uuid
        
        # エラーコンテキスト作成
        error_context = ErrorContext(
            error_id=str(uuid.uuid4()),
            timestamp=time.time(),
            severity=self._get_severity(error),
            category=self._get_category(error),
            message=str(error),
            details=context or {},
            stack_trace=traceback.format_exc(),
            user_id=context.get("user_id") if context else None,
            request_id=context.get("request_id") if context else None
        )
        
        # 履歴に追加
        self.error_history.append(error_context)
        if len(self.error_history) > self.max_history:
            self.error_history.pop(0)
            
        # ログ記録
        self._log_error(error_context)
        
        # カスタムハンドラー実行
        if type(error) in self.error_handlers:
            try:
                handler = self.error_handlers[type(error)]
                await handler(error, error_context)
            except Exception as e:
                logger.error(f"Error handler failed: {e}")
                
        # リカバリー戦略実行
        if error_context.category in self.recovery_strategies:
            try:
                strategy = self.recovery_strategies[error_context.category]
                await strategy(error_context)
            except Exception as e:
                logger.error(f"Recovery strategy failed: {e}")
                
        # レスポンス生成
        return self._create_error_response(error_context)
        
    def _get_severity(self, error: Exception) -> ErrorSeverity:
        """エラー深刻度取得"""
        if isinstance(error, ApplicationError):
            return error.severity
        elif isinstance(error, (ValueError, KeyError, TypeError)):
            return ErrorSeverity.LOW
        elif isinstance(error, (IOError, ConnectionError)):
            return ErrorSeverity.MEDIUM
        else:
            return ErrorSeverity.HIGH
            
    def _get_category(self, error: Exception) -> ErrorCategory:
        """エラーカテゴリー取得"""
        if isinstance(error, ApplicationError):
            return error.category
        elif isinstance(error, ValueError):
            return ErrorCategory.VALIDATION
        elif isinstance(error, (IOError, ConnectionError)):
            return ErrorCategory.NETWORK
        else:
            return ErrorCategory.UNKNOWN
            
    def _log_error(self, context: ErrorContext):
        """エラーログ記録"""
        log_level = {
            ErrorSeverity.LOW: logging.INFO,
            ErrorSeverity.MEDIUM: logging.WARNING,
            ErrorSeverity.HIGH: logging.ERROR,
            ErrorSeverity.CRITICAL: logging.CRITICAL
        }.get(context.severity, logging.ERROR)
        
        logger.log(
            log_level,
            f"[{context.error_id}] {context.category.value}: {context.message}",
            extra={
                "error_id": context.error_id,
                "severity": context.severity.value,
                "category": context.category.value,
                "user_id": context.user_id,
                "request_id": context.request_id,
                "details": context.details
            }
        )
        
    def _create_error_response(self, context: ErrorContext) -> Dict[str, Any]:
        """エラーレスポンス生成"""
        # ユーザー向けメッセージ
        user_message = self._get_user_friendly_message(context)
        
        response = {
            "error": True,
            "error_id": context.error_id,
            "message": user_message,
            "timestamp": context.timestamp
        }
        
        # 開発環境では詳細情報を含める
        import os
        if os.getenv("BLRCS_ENV") == "development":
            response["details"] = context.details
            response["category"] = context.category.value
            response["severity"] = context.severity.value
            
        return response
        
    def _get_user_friendly_message(self, context: ErrorContext) -> str:
        """ユーザーフレンドリーメッセージ生成"""
        messages = {
            ErrorCategory.VALIDATION: "入力内容に誤りがあります。ご確認ください。",
            ErrorCategory.AUTHENTICATION: "認証に失敗しました。ログイン情報をご確認ください。",
            ErrorCategory.AUTHORIZATION: "このリソースへのアクセス権限がありません。",
            ErrorCategory.DATABASE: "データ処理中にエラーが発生しました。しばらくしてから再度お試しください。",
            ErrorCategory.NETWORK: "ネットワーク接続に問題が発生しました。接続を確認してください。",
            ErrorCategory.RATE_LIMIT: "リクエストが多すぎます。しばらくしてから再度お試しください。",
            ErrorCategory.SYSTEM: "システムエラーが発生しました。管理者に連絡してください。",
            ErrorCategory.EXTERNAL_SERVICE: "外部サービスとの通信に失敗しました。",
            ErrorCategory.BUSINESS_LOGIC: "処理中にエラーが発生しました。",
            ErrorCategory.UNKNOWN: "予期しないエラーが発生しました。"
        }
        
        return messages.get(context.category, messages[ErrorCategory.UNKNOWN])
        
    def get_error_stats(self) -> Dict[str, Any]:
        """エラー統計取得"""
        if not self.error_history:
            return {"total": 0}
            
        stats = {
            "total": len(self.error_history),
            "by_severity": {},
            "by_category": {},
            "recent_errors": []
        }
        
        for error in self.error_history:
            # 深刻度別
            severity = error.severity.value
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
            
            # カテゴリー別
            category = error.category.value
            stats["by_category"][category] = stats["by_category"].get(category, 0) + 1
            
        # 最近のエラー
        stats["recent_errors"] = [
            {
                "error_id": e.error_id,
                "timestamp": e.timestamp,
                "message": e.message,
                "severity": e.severity.value,
                "category": e.category.value
            }
            for e in self.error_history[-10:]
        ]
        
        return stats

def error_handler(severity: ErrorSeverity = ErrorSeverity.MEDIUM):
    """エラーハンドリングデコレータ"""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                handler = ErrorHandler()
                context = {
                    "function": func.__name__,
                    "args": str(args)[:100],
                    "kwargs": str(kwargs)[:100]
                }
                return await handler.handle_error(e, context)
                
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                handler = ErrorHandler()
                context = {
                    "function": func.__name__,
                    "args": str(args)[:100],
                    "kwargs": str(kwargs)[:100]
                }
                return asyncio.run(handler.handle_error(e, context))
                
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
            
    return decorator

# グローバルエラーハンドラー
global_error_handler = ErrorHandler()