"""
BLNCS シャットダウン処理モジュール
システムの適切な終了処理とクリーンアップ。
"""

import signal
import sys
import threading
import time
from typing import Callable, List, Any
from pathlib import Path

from .logger import get_logger
from .cache import get_cache
from .history import get_history


class ShutdownHandler:
    """システムのシャットダウン処理管理"""
    
    def __init__(self) -> None:
        self.logger = get_logger(__name__)
        self.shutdown_hooks: List[Callable] = []
        self.shutdown_in_progress = False
        self.shutdown_lock = threading.Lock()
        
        # シグナルハンドラーを登録
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # デフォルトのクリーンアップフックを登録
        self.register_cleanup_hook(self._cleanup_cache)
        self.register_cleanup_hook(self._cleanup_history)
        self.register_cleanup_hook(self._cleanup_temp_files)
    
    def _signal_handler(self, signum: int, frame: Any) -> None:
        """シグナル受信時の処理"""
        signal_name = signal.Signals(signum).name
        self.logger.info(f"終了シグナルを受信: {signal_name}")
        self.shutdown()
    
    def register_cleanup_hook(self, hook: Callable[[], None]) -> None:
        """クリーンアップフックを登録"""
        with self.shutdown_lock:
            self.shutdown_hooks.append(hook)
            self.logger.debug(f"クリーンアップフックを登録: {hook.__name__}")
    
    def shutdown(self, exit_code: int = 0) -> None:
        """システムのシャットダウン処理"""
        with self.shutdown_lock:
            if self.shutdown_in_progress:
                self.logger.warning("シャットダウン処理は既に進行中です")
                return
            
            self.shutdown_in_progress = True
        
        self.logger.info("システムのシャットダウンを開始...")
        
        # クリーンアップフックを実行
        for hook in self.shutdown_hooks:
            try:
                self.logger.debug(f"クリーンアップ実行: {hook.__name__}")
                hook()
            except Exception as e:
                self.logger.error(f"クリーンアップエラー ({hook.__name__}): {e}")
        
        self.logger.info("シャットダウン処理完了")
        
        # プログラムを終了
        sys.exit(exit_code)
    
    def _cleanup_cache(self):
        """キャッシュのクリーンアップ"""
        try:
            cache = get_cache()
            cache.optimize_memory()
            self.logger.debug("キャッシュをクリーンアップしました")
        except Exception as e:
            self.logger.error(f"キャッシュクリーンアップエラー: {e}")
    
    def _cleanup_history(self):
        """履歴のクリーンアップ"""
        try:
            history = get_history()
            history.optimize_storage()
            self.logger.debug("履歴をクリーンアップしました")
        except Exception as e:
            self.logger.error(f"履歴クリーンアップエラー: {e}")
    
    def _cleanup_temp_files(self):
        """一時ファイルのクリーンアップ"""
        try:
            temp_patterns = [
                "*.tmp",
                "*.temp",
                "*.log.backup",
                ".blncs_temp_*"
            ]
            
            cleanup_dirs = [Path("."), Path("./data"), Path("./logs")]
            
            for directory in cleanup_dirs:
                if not directory.exists():
                    continue
                
                for pattern in temp_patterns:
                    for temp_file in directory.glob(pattern):
                        try:
                            temp_file.unlink()
                            self.logger.debug(f"一時ファイルを削除: {temp_file}")
                        except Exception as e:
                            self.logger.warning(f"一時ファイル削除失敗: {temp_file} - {e}")
        
        except Exception as e:
            self.logger.error(f"一時ファイルクリーンアップエラー: {e}")
    
    def emergency_shutdown(self):
        """緊急シャットダウン（最小限のクリーンアップのみ）"""
        self.logger.critical("緊急シャットダウンを実行")
        
        try:
            # 最重要なクリーンアップのみ実行
            self._cleanup_cache()
            self._cleanup_history()
        except Exception as e:
            self.logger.error(f"緊急シャットダウン中のエラー: {e}")
        
        sys.exit(1)


# グローバルシャットダウンハンドラー
_global_shutdown_handler = None

def get_shutdown_handler() -> ShutdownHandler:
    """グローバルシャットダウンハンドラーを取得"""
    global _global_shutdown_handler
    if _global_shutdown_handler is None:
        _global_shutdown_handler = ShutdownHandler()
    return _global_shutdown_handler

def register_cleanup(hook: Callable):
    """クリーンアップフックを登録（簡易インターフェース）"""
    handler = get_shutdown_handler()
    handler.register_cleanup_hook(hook)

def shutdown_gracefully(exit_code: int = 0):
    """適切なシャットダウンを実行"""
    handler = get_shutdown_handler()
    handler.shutdown(exit_code)

def emergency_exit():
    """緊急シャットダウンを実行"""
    handler = get_shutdown_handler()
    handler.emergency_shutdown()