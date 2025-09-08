"""
BLNCS Error Recovery System
Automated error recovery and self-healing functionality.
"""

import time
import logging
from typing import Dict, Any, Optional, Callable
from threading import Lock, Thread
from datetime import datetime, timedelta

from .exceptions import BLNCSError, ConnectionError, TimeoutError, LightningError
from .config import get_config
from .logger import get_logger
from .cache import get_cache


class ErrorRecovery:
    """Error recovery system"""
    
    def __init__(self) -> None:
        self.config = get_config()
        self.logger = get_logger(__name__)
        self.cache = get_cache()
        self.recovery_attempts = {}  # Retry attempts by error type
        self.recovery_lock = Lock()
        
        # Recovery settings
        self.max_retries = self.config.get('recovery.max_retries', 3)
        self.retry_delay = self.config.get('recovery.retry_delay', 2.0)
        self.exponential_backoff = self.config.get('recovery.exponential_backoff', True)
        self.recovery_timeout = self.config.get('recovery.timeout', 300)  # 5 minutes
        
        # Recovery strategies
        self.recovery_strategies = {
            ConnectionError: self._recover_connection,
            TimeoutError: self._recover_timeout,
            LightningError: self._recover_lightning,
            BLNCSError: self._recover_general
        }
        
    def attempt_recovery(self, error: Exception, operation: str, 
                        retry_func: Callable, *args, **kwargs) -> Any:
        """Attempt error recovery"""
        error_key = f"{operation}:{error.__class__.__name__}"
        
        with self.recovery_lock:
            attempts = self.recovery_attempts.get(error_key, 0)
            
            if attempts >= self.max_retries:
                self.logger.error(f"Max retry attempts reached: {error_key}")
                raise error
            
            # Increment attempt count
            self.recovery_attempts[error_key] = attempts + 1
            
        self.logger.info(f"Attempting recovery ({attempts + 1}/{self.max_retries}): {error_key}")
        
        try:
            # 回復アクションを実行
            recovery_result = self._execute_recovery_action(error, operation)
            
            if recovery_result:
                # 遅延後に再試行
                delay = self._calculate_retry_delay(attempts)
                time.sleep(delay)
                
                # 元の操作を再実行
                result = retry_func(*args, **kwargs)
                
                # 成功した場合、試行回数をリセット
                with self.recovery_lock:
                    self.recovery_attempts.pop(error_key, None)
                    
                self.logger.info(f"エラー回復に成功しました: {error_key}")
                return result
            else:
                raise error
                
        except Exception as retry_error:
            self.logger.warning(f"エラー回復に失敗: {retry_error}")
            raise error
    
    def _execute_recovery_action(self, error: Exception, operation: str) -> bool:
        """エラータイプに応じた回復アクションを実行"""
        
        if isinstance(error, ConnectionError):
            return self._recover_connection_error(error)
        elif isinstance(error, TimeoutError):
            return self._recover_timeout_error(error)
        elif isinstance(error, LightningError):
            return self._recover_lightning_error(error)
        else:
            return self._recover_generic_error(error)
    
    def _recover_connection_error(self, error: ConnectionError) -> bool:
        """接続エラーの回復"""
        self.logger.info("接続エラーの回復を試行中...")
        
        try:
            # キャッシュクリア
            self.cache.clear()
            
            # 接続設定をリロード
            config = get_config()
            config.data = config._load_config()
            
            # ネットワーク接続テスト
            import socket
            host = error.host or self.config.get('lightning.host', 'localhost')
            port = error.port or self.config.get('lightning.port', 8080)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                self.logger.info(f"ネットワーク接続が回復: {host}:{port}")
                return True
            else:
                self.logger.warning(f"ネットワーク接続に失敗: {host}:{port}")
                return False
                
        except Exception as e:
            self.logger.error(f"接続回復エラー: {e}")
            return False
    
    def _recover_timeout_error(self, error: TimeoutError) -> bool:
        """タイムアウトエラーの回復"""
        self.logger.info("タイムアウトエラーの回復を試行中...")
        
        try:
            # タイムアウト設定を動的に調整
            current_timeout = self.config.get('lightning.timeout', 15)
            new_timeout = min(current_timeout * 1.5, 60)  # 最大60秒
            
            self.config.set('lightning.timeout', new_timeout)
            self.logger.info(f"タイムアウト値を調整: {current_timeout}s → {new_timeout}s")
            
            # 接続タイムアウトも調整
            current_connect = self.config.get('lightning.connect_timeout', 5)
            new_connect = min(current_connect * 1.2, 15)  # 最大15秒
            
            self.config.set('lightning.connect_timeout', new_connect)
            self.logger.info(f"接続タイムアウト値を調整: {current_connect}s → {new_connect}s")
            
            return True
            
        except Exception as e:
            self.logger.error(f"タイムアウト回復エラー: {e}")
            return False
    
    def _recover_lightning_error(self, error: LightningError) -> bool:
        """Lightning Network エラーの回復"""
        self.logger.info("Lightning エラーの回復を試行中...")
        
        try:
            # Lightning関連のキャッシュをクリア
            cache_keys_to_clear = []
            
            # node_info キャッシュをクリア
            host = self.config.get('lightning.host', 'localhost')
            port = self.config.get('lightning.port', 8080)
            cache_keys_to_clear.append(f"node_info:{host}:{port}")
            
            for key in cache_keys_to_clear:
                self.cache.delete(key)
            
            self.logger.info("Lightning 関連キャッシュをクリアしました")
            
            # 接続パラメーターをリセット
            self.config.merge_env_vars()  # 環境変数を再読み込み
            
            return True
            
        except Exception as e:
            self.logger.error(f"Lightning 回復エラー: {e}")
            return False
    
    def _recover_generic_error(self, error: Exception) -> bool:
        """一般的なエラーの回復"""
        self.logger.info("一般エラーの回復を試行中...")
        
        try:
            # 基本的な回復アクション
            # 1. キャッシュの部分クリア
            self.cache.cleanup_expired()
            
            # 2. 設定の再読み込み
            config = get_config()
            config.data = config._load_config()
            
            # 3. 短い待機時間
            time.sleep(1)
            
            return True
            
        except Exception as e:
            self.logger.error(f"一般回復エラー: {e}")
            return False
    
    def _calculate_retry_delay(self, attempt: int) -> float:
        """再試行遅延時間を計算"""
        if self.exponential_backoff:
            return self.retry_delay * (2 ** attempt)
        else:
            return self.retry_delay
    
    def reset_recovery_state(self, operation: Optional[str] = None) -> None:
        """回復状態をリセット"""
        with self.recovery_lock:
            if operation:
                # 特定の操作のリセット
                keys_to_remove = [k for k in self.recovery_attempts.keys() 
                                if k.startswith(operation + ":")]
                for key in keys_to_remove:
                    del self.recovery_attempts[key]
                self.logger.info(f"回復状態をリセット: {operation}")
            else:
                # 全体のリセット
                self.recovery_attempts.clear()
                self.logger.info("全ての回復状態をリセット")
    
    def get_recovery_status(self) -> Dict[str, Any]:
        """回復状態を取得"""
        with self.recovery_lock:
            return {
                'active_recoveries': dict(self.recovery_attempts),
                'max_retries': self.max_retries,
                'retry_delay': self.retry_delay,
                'exponential_backoff': self.exponential_backoff,
                'recovery_timeout': self.recovery_timeout
            }


class AutoRecoveryDecorator:
    """自動回復デコレーター"""
    
    def __init__(self, operation_name: str, max_retries: int = 3, 
                 recoverable_errors: tuple = None):
        self.operation_name = operation_name
        self.max_retries = max_retries
        self.recoverable_errors = recoverable_errors or (
            BLNCSError, ConnectionError, TimeoutError, LightningError
        )
        self.recovery_system = None
    
    def __call__(self, func: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if self.recovery_system is None:
                self.recovery_system = get_error_recovery()
            
            last_error = None
            
            for attempt in range(self.max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except self.recoverable_errors as e:
                    last_error = e
                    if attempt < self.max_retries:
                        try:
                            return self.recovery_system.attempt_recovery(
                                e, self.operation_name, func, *args, **kwargs
                            )
                        except Exception:
                            # 回復に失敗した場合は次の試行へ
                            continue
                    else:
                        # 最大試行回数に達した
                        break
                except Exception as e:
                    # 回復不可能なエラー
                    raise e
            
            # すべての試行が失敗した場合
            if last_error:
                raise last_error
            
        return wrapper


# Global instance
_recovery_system = None
_recovery_lock = Lock()

def get_error_recovery() -> ErrorRecovery:
    """エラー回復システムの取得（シングルトン）"""
    global _recovery_system
    
    if _recovery_system is None:
        with _recovery_lock:
            if _recovery_system is None:
                _recovery_system = ErrorRecovery()
    
    return _recovery_system


# Convenience decorator
def auto_recover(operation_name: str, max_retries: int = 3, 
                recoverable_errors: tuple = None):
    """自動回復デコレーターのファクトリ関数"""
    return AutoRecoveryDecorator(operation_name, max_retries, recoverable_errors)