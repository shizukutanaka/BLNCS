"""
BLNCS Logging Module
Memory-efficient logging with rotation and compression.
"""

import logging
import logging.handlers
import sys
import os
from pathlib import Path
from typing import Optional


def setup_logger(name: str = "blncs", level: str = "INFO", enable_file_logging: bool = True) -> logging.Logger:
    """Setup and configure logger with rotation and optimization"""
    logger = logging.getLogger(name)
    
    # Convert string level to logging constant
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)
    
    # Remove existing handlers to avoid duplicates
    logger.handlers = []
    
    # Optimized formatter (compact format)
    formatter = logging.Formatter(
        '%(asctime)s|%(levelname)s|%(name)s|%(message)s',
        datefmt='%H:%M:%S'
    )
    
    # Console handler (更に軽量化: ERRORレベル以上のみ表示)
    console_handler = logging.StreamHandler(sys.stdout)
    
    # より軽量な設定: 本番環境ではERROR以上、開発環境ではWARNING以上
    env = os.getenv('BLNCS_ENV', 'development')
    if env == 'production':
        console_level = logging.ERROR
    else:
        console_level = logging.WARNING
    
    console_handler.setLevel(console_level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File logging with rotation (if enabled)
    if enable_file_logging:
        logs_dir = Path("logs")
        logs_dir.mkdir(exist_ok=True)
        
        log_file = logs_dir / f"{name}.log"
        
        # 軽量化: より小さなファイルサイズと少ないバックアップ
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=5*1024*1024,  # 5MB (10MBから削減)
            backupCount=3,  # 3ファイル (5ファイルから削減)
            encoding='utf-8'
        )
        
        # ファイルはINFO以上のみ記録（DEBUG除外で軽量化）
        file_level = max(logging.INFO, numeric_level)
        file_handler.setLevel(file_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        # Memory handler: 容量削減とERRORレベルでフラッシュ
        memory_handler = logging.handlers.MemoryHandler(
            capacity=50,  # 50メッセージ (100から削減)
            flushLevel=logging.ERROR,  # ERRORレベルでフラッシュ (WARNINGから変更)
            target=file_handler
        )
        memory_handler.setLevel(logging.INFO)  # INFOレベル以上のみ
        memory_handler.setFormatter(formatter)
    
    # Prevent propagation to root logger
    logger.propagate = False
    
    return logger


def get_logger(name: Optional[str] = None, setup_if_needed: bool = True) -> logging.Logger:
    """Get logger instance with automatic setup"""
    logger_name = name or "blncs"
    logger = logging.getLogger(logger_name)
    
    # Auto-setup if no handlers exist
    if setup_if_needed and not logger.handlers:
        # Use environment variables to avoid circular imports
        log_level = os.getenv('BLNCS_LOG_LEVEL', 'INFO')
        enable_file_logging = os.getenv('BLNCS_FILE_LOGGING', 'true').lower() == 'true'
        
        logger = setup_logger(logger_name, log_level, enable_file_logging)
    
    return logger


def cleanup_old_logs(days: int = 7) -> int:
    """古いログファイルをクリーンアップ"""
    import time
    from datetime import datetime, timedelta
    
    logs_dir = Path("logs")
    if not logs_dir.exists():
        return
    
    cutoff_time = time.time() - (days * 24 * 3600)
    
    cleaned_count = 0
    for log_file in logs_dir.glob("*.log*"):
        try:
            if log_file.stat().st_mtime < cutoff_time:
                log_file.unlink()
                cleaned_count += 1
        except Exception:
            pass  # ファイル削除に失敗しても継続
    
    if cleaned_count > 0:
        logger = get_logger()
        logger.info(f"古いログファイルを{cleaned_count}個削除しました")


def optimize_logging_memory() -> None:
    """ログシステムのメモリ使用量を最適化"""
    # すべてのロガーのメモリハンドラをフラッシュ
    for name in logging.Logger.manager.loggerDict:
        logger = logging.getLogger(name)
        for handler in logger.handlers:
            if isinstance(handler, logging.handlers.MemoryHandler):
                handler.flush()
    
    # 古いログファイルをクリーンアップ
    cleanup_old_logs()


# 自動初期化
if not logging.getLogger("blncs").handlers:
    setup_logger()