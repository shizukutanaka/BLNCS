"""
BLNCS Core Module
Lightweight Bitcoin Lightning Network Control System
"""

from typing import Optional

# Core components with lazy loading
def get_config():
    """Get configuration management system"""
    from .config import get_config as _get_config
    return _get_config()

def get_logger(name: Optional[str] = None):
    """Get logging system"""  
    from .logger import get_logger as _get_logger
    return _get_logger(name)

def get_cache():
    """Get cache system"""
    from .cache import get_cache as _get_cache
    return _get_cache()

def get_health_checker():
    """Get health checker"""
    from .health import get_health_checker as _get_health_checker
    return _get_health_checker()

def get_validator():
    """Get validator"""
    from .validation import get_validator as _get_validator
    return _get_validator()

def get_security_manager():
    """Get security manager"""
    from .security import get_security_manager
    return get_security_manager()

def get_monitor():
    """Get system monitor"""
    from .performance import get_unified_monitor
    return get_unified_monitor()

def get_fee_optimizer():
    """Get fee optimizer"""
    from .fee_optimizer import get_fee_optimizer
    return get_fee_optimizer()

def get_channel_manager():
    """Get channel manager"""
    from .channel_manager import get_channel_manager
    return get_channel_manager()

def get_connection_pool():
    """Get connection pool"""
    from .connection_pool import ConnectionPool
    return ConnectionPool()

def get_unified_monitor():
    """Get unified monitor"""
    from .performance import get_unified_monitor
    return get_unified_monitor()

def get_backup_manager():
    """Get backup manager"""
    from .simple_backup import SimpleBackup
    return SimpleBackup()

__all__ = [
    'get_config',
    'get_logger', 
    'get_cache',
    'get_health_checker',
    'get_validator',
    'get_security_manager',
    'get_monitor',
    'get_fee_optimizer',
    'get_channel_manager',
    'get_connection_pool',
    'get_unified_monitor',
    'get_backup_manager'
]