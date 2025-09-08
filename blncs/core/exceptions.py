"""
BLNCS core exception classes.
Simple, clear error handling without unnecessary complexity.
"""

import traceback
import logging
import sys
import time
from datetime import datetime
from typing import Dict, Any, Optional, Callable, List
from functools import wraps


class BLNCSError(Exception):
    """Base exception for BLNCS"""
    def __init__(self, message: str, recoverable: bool = True, error_code: Optional[str] = None, **details: Any) -> None:
        self.message = message
        self.recoverable = recoverable
        self.error_code = error_code or self.__class__.__name__.upper()
        self.details = details
        self.timestamp = datetime.now()
        super().__init__(message)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "error": self.__class__.__name__,
            "error_code": self.error_code,
            "message": self.message,
            "severity": "warning" if self.recoverable else "error",
            "recoverable": self.recoverable,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details
        }
    
    def get_user_message(self) -> str:
        """Get user-friendly error message"""
        return self.message
    
    def get_recovery_suggestions(self) -> list[str]:
        """Get suggested recovery actions"""
        if not self.recoverable:
            return []
        
        base_suggestions = ["問題が続く場合は再試行してください"]
        
        if hasattr(self, '_recovery_suggestions'):
            return self._recovery_suggestions + base_suggestions
        return base_suggestions


class ConfigError(BLNCSError):
    """Configuration error"""
    def __init__(self, message: str, config_key: Optional[str] = None, **details: Any) -> None:
        super().__init__(message, recoverable=True, **details)
        self.config_key = config_key
        self._recovery_suggestions = [
            "設定ファイルを確認してください",
            "'blncs_cli.py config --repair' で自動修復を試してください"
        ]


class ValidationError(BLNCSError):
    """Data validation error"""
    def __init__(self, message: str, field: Optional[str] = None, value: Any = None, **details: Any) -> None:
        super().__init__(message, recoverable=True, **details)
        self.field = field
        self.value = value
        self._recovery_suggestions = [
            "入力値を確認してください",
            "設定ファイルの形式を確認してください"
        ]


class LightningError(BLNCSError):
    """Lightning Network operation error"""
    def __init__(self, message, operation=None, **details):
        super().__init__(message, recoverable=True, **details)
        self.operation = operation
        self._recovery_suggestions = [
            "Lightning ノードの接続を確認してください",
            "'blncs_cli.py connection --status' で接続状態を確認してください"
        ]


class ConnectionError(LightningError):
    """Connection error to Lightning node"""
    def __init__(self, message, host=None, port=None, **details):
        super().__init__(message, operation="connect", **details)
        self.host = host
        self.port = port
        self._recovery_suggestions = [
            f"Lightning ノード ({host}:{port}) が起動していることを確認してください",
            "ネットワーク接続を確認してください",
            "'blncs_cli.py connection --reconnect' で再接続を試してください"
        ]


class TimeoutError(LightningError):
    """Operation timeout error"""
    def __init__(self, message, timeout_seconds=None, operation=None, **details):
        super().__init__(message, operation=operation, **details)
        self.timeout_seconds = timeout_seconds
        self._recovery_suggestions = [
            "ネットワーク接続を確認してください",
            "Lightning ノードの応答性を確認してください",
            f"タイムアウト値 ({timeout_seconds}秒) を増加することを検討してください"
        ]


class SecurityError(BLNCSError):
    """Security-related error"""
    def __init__(self, message, auth_failure=False, **details):
        # Security errors are typically non-recoverable
        super().__init__(message, recoverable=auth_failure, **details)
        self.auth_failure = auth_failure
        if auth_failure:
            self._recovery_suggestions = [
                "認証情報を確認してください",
                "パスワードが正しいことを確認してください"
            ]


class ChannelError(LightningError):
    """Channel management error"""
    def __init__(self, message, channel_id=None, **details):
        super().__init__(message, operation="channel_management", **details)
        self.channel_id = channel_id
        self._recovery_suggestions = [
            "チャネルの状態を確認してください",
            "'blncs_cli.py channels' でチャネル一覧を確認してください"
        ]


class PaymentError(LightningError):
    """Payment operation error"""
    def __init__(self, message, amount=None, invoice=None, **details):
        super().__init__(message, operation="payment", **details)
        self.amount = amount
        self.invoice = invoice
        self._recovery_suggestions = [
            "残高が十分であることを確認してください",
            "インボイスが有効であることを確認してください",
            "手数料設定を確認してください"
        ]


class MonitoringError(BLNCSError):
    """Monitoring system error"""
    def __init__(self, message, monitor_type=None, **details):
        super().__init__(message, recoverable=True, **details)
        self.monitor_type = monitor_type
        self._recovery_suggestions = [
            "監視システムの設定を確認してください",
            "'blncs_cli.py monitor --status' で監視状態を確認してください"
        ]


class PerformanceError(BLNCSError):
    """Performance-related error"""
    def __init__(self, message, metric=None, threshold=None, **details):
        super().__init__(message, recoverable=True, **details)
        self.metric = metric
        self.threshold = threshold
        self._recovery_suggestions = [
            "システムリソースを確認してください",
            "パフォーマンス設定を調整してください"
        ]


# Error handler utility functions
def handle_error(error: Exception, logger=None, context: str = None) -> Dict[str, Any]:
    """Standardized error handling"""
    error_info = {
        'timestamp': datetime.now().isoformat(),
        'context': context or 'unknown',
        'traceback': traceback.format_exc()
    }
    
    if isinstance(error, BLNCSError):
        error_info.update(error.to_dict())
        error_info['recovery_suggestions'] = error.get_recovery_suggestions()
    else:
        # Handle standard Python exceptions
        error_info.update({
            'error': error.__class__.__name__,
            'error_code': error.__class__.__name__.upper(),
            'message': str(error),
            'severity': 'error',
            'recoverable': False
        })
    
    if logger:
        logger.error(f"Error in {context}: {error_info['message']}")
    
    return error_info


def format_error_for_cli(error: Exception, show_details: bool = False) -> str:
    """Format error for CLI display"""
    if isinstance(error, BLNCSError):
        message = f"❌ {error.get_user_message()}"
        
        if show_details and error.details:
            message += f"\n詳細: {error.details}"
        
        suggestions = error.get_recovery_suggestions()
        if suggestions:
            message += f"\n\n💡 解決方法:"
            for i, suggestion in enumerate(suggestions, 1):
                message += f"\n  {i}. {suggestion}"
        
        return message
    else:
        return f"❌ エラー: {str(error)}"


class CircuitBreakerError(BLNCSError):
    """Circuit breaker has opened due to repeated failures"""
    def __init__(self, message: str, failure_count: int = 0, **details):
        super().__init__(message, recoverable=False, **details)
        self.failure_count = failure_count
        self._recovery_suggestions = [
            "システムが安定するまで待機してください",
            "根本的な問題を解決してからリセットしてください"
        ]


class RateLimitError(BLNCSError):
    """Rate limit exceeded error"""
    def __init__(self, message: str, retry_after: Optional[int] = None, **details):
        super().__init__(message, recoverable=True, **details)
        self.retry_after = retry_after
        self._recovery_suggestions = [
            f"リクエスト頻度を下げてください",
            f"{retry_after}秒後に再試行してください" if retry_after else "しばらく待ってから再試行してください"
        ]


# Enhanced error handling decorators and utilities
def handle_exceptions(logger: Optional[logging.Logger] = None,
                     default_return: Any = None,
                     reraise: bool = True,
                     log_level: int = logging.ERROR):
    """Decorator for standardized exception handling"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except BLNCSError:
                # Re-raise BLNCS errors without modification
                raise
            except Exception as e:
                if logger:
                    logger.log(log_level, f"Error in {func.__name__}: {str(e)}")
                
                if reraise:
                    # Wrap in BLNCS error for consistency
                    raise BLNCSError(
                        f"Unexpected error in {func.__name__}: {str(e)}",
                        recoverable=True,
                        original_error=str(e),
                        function=func.__name__
                    ) from e
                
                return default_return
        return wrapper
    return decorator


def retry_on_exception(max_attempts: int = 3,
                      delay: float = 1.0,
                      backoff: float = 2.0,
                      exceptions: tuple = (Exception,),
                      logger: Optional[logging.Logger] = None):
    """Decorator for automatic retry on specified exceptions"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            current_delay = delay
            
            for attempt in range(max_attempts):
                try:
                    result = func(*args, **kwargs)
                    if attempt > 0 and logger:
                        logger.info(f"{func.__name__} succeeded after {attempt + 1} attempts")
                    return result
                except exceptions as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        if logger:
                            logger.warning(f"{func.__name__} failed (attempt {attempt + 1}/{max_attempts}): {str(e)}")
                        time.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        # Convert to BLNCS error on final failure
                        raise BLNCSError(
                            f"Failed after {max_attempts} attempts: {str(e)}",
                            recoverable=True,
                            attempts=max_attempts,
                            last_error=str(e)
                        ) from e
            
            raise last_exception
        return wrapper
    return decorator


class ErrorAggregator:
    """Collects and aggregates errors for batch reporting"""
    
    def __init__(self):
        self.errors: List[Dict[str, Any]] = []
        self.error_counts: Dict[str, int] = {}
    
    def add_error(self, error: Exception, context: str = ""):
        """Add an error to the aggregator"""
        error_info = handle_error(error, context=context)
        self.errors.append(error_info)
        
        # Count error types
        error_type = error_info.get('error', 'Unknown')
        self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1
    
    def has_errors(self) -> bool:
        """Check if any errors have been collected"""
        return len(self.errors) > 0
    
    def get_summary(self) -> Dict[str, Any]:
        """Get error summary"""
        if not self.errors:
            return {"total_errors": 0}
        
        return {
            "total_errors": len(self.errors),
            "error_counts": self.error_counts,
            "first_error": self.errors[0],
            "last_error": self.errors[-1],
            "unique_error_types": len(self.error_counts)
        }
    
    def clear(self):
        """Clear all collected errors"""
        self.errors.clear()
        self.error_counts.clear()


# Circuit Breaker implementation
class CircuitBreaker:
    """Circuit breaker pattern for handling cascading failures"""
    
    def __init__(self, failure_threshold: int = 5, timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'CLOSED'  # CLOSED, OPEN, HALF_OPEN
    
    def call(self, func: Callable, *args, **kwargs):
        """Execute function through circuit breaker"""
        if self.state == 'OPEN':
            if self._should_attempt_reset():
                self.state = 'HALF_OPEN'
            else:
                raise CircuitBreakerError(
                    "Circuit breaker is OPEN - too many recent failures",
                    failure_count=self.failure_count
                )
        
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset"""
        if self.last_failure_time is None:
            return True
        return (datetime.now() - self.last_failure_time).total_seconds() > self.timeout
    
    def _on_success(self):
        """Handle successful call"""
        self.failure_count = 0
        self.state = 'CLOSED'
    
    def _on_failure(self):
        """Handle failed call"""
        self.failure_count += 1
        self.last_failure_time = datetime.now()
        
        if self.failure_count >= self.failure_threshold:
            self.state = 'OPEN'
    
    def reset(self):
        """Manually reset the circuit breaker"""
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'CLOSED'


def create_error_context(operation: str, **context_data) -> Dict[str, Any]:
    """Create standardized error context"""
    return {
        'operation': operation,
        'timestamp': datetime.now().isoformat(),
        'context_data': context_data
    }