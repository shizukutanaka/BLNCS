"""
BLNCS Core Module - Simple Interface
Following Pike: do one thing well - provide core system access.
"""

from typing import Optional

# Global instances cache for performance
_instances = {}

def _get_or_create(key: str, factory_func):
    """Get cached instance or create new one"""
    if key not in _instances:
        _instances[key] = factory_func()
    return _instances[key]

# Essential core systems only
def get_config():
    """Get configuration management system"""
    def _factory():
        from .config import get_config
        return get_config()
    return _get_or_create('config', _factory)

def get_logger(name: Optional[str] = None):
    """Get logging system"""
    try:
        from .unified_logging import get_logger as _get_logger
        return _get_logger(name)
    except ImportError:
        import logging
        return logging.getLogger(name or __name__)

def get_database():
    """Get unified database system"""
    def _factory():
        from .unified_database import get_database
        return get_database()
    return _get_or_create('database', _factory)

def get_cache():
    """Get unified cache system"""
    def _factory():
        from .simple_cache import get_simple_cache
        return get_simple_cache()
    return _get_or_create('cache', _factory)

def get_validator():
    """Get config validator system"""
    def _factory():
        from .config import ConfigManager
        return ConfigManager()
    return _get_or_create('validator', _factory)

def get_backup_manager():
    """Get backup manager"""
    def _factory():
        from ..utils.lightweight_backup import get_lightweight_backup_manager
        return get_lightweight_backup_manager()
    return _get_or_create('backup_manager', _factory)

def get_backup_helper():
    """Shorthand for lightweight auto backup helper."""
    from ..utils.lightweight_backup import auto_backup
    return auto_backup

def get_monitor():
    """Get unified monitoring system"""
    def _factory():
        from ..monitoring.lightweight_monitor import get_lightweight_monitor
        return get_lightweight_monitor()
    return _get_or_create('monitor', _factory)

__all__ = [
    'get_config',
    'get_logger',
    'get_database',
    'get_cache',
    'get_validator',
    'get_backup_manager',
    'get_backup_helper',
    'get_monitor'
]