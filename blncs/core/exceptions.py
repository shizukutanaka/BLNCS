"""
BLNCS core exception classes.
Simple, clear error handling without unnecessary complexity.
"""

import traceback
from datetime import datetime
from typing import Dict, Any, Optional


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