"""
BLNCS Core Module
Lightweight Bitcoin Lightning Network Control System
"""

from typing import Optional

# Core components with lazy loading
def get_config():
    """Get configuration management system"""
    from .config_manager import get_config_manager
    return get_config_manager()

def get_logger(name: Optional[str] = None):
    """Get logging system"""  
    from .logger import get_logger as _get_logger
    return _get_logger(name)

def get_cache():
    """Get unified cache system"""
    from .unified_cache import get_cache_manager
    return get_cache_manager()

def get_health_checker():
    """Get health checker"""
    from .health import get_health_checker as _get_health_checker
    return _get_health_checker()

def get_validator():
    """Get enhanced validator system"""
    from .enhanced_validator import get_enhanced_validator
    return get_enhanced_validator()

def get_security_manager():
    """Get security manager"""
    from ..security import get_security_manager
    return get_security_manager()

def get_monitor():
    """Get unified system monitor"""
    from .monitor import get_monitor as _get_monitor
    return _get_monitor()


def get_fee_optimizer():
    """Get fee optimizer"""
    from .fee_optimizer import get_fee_optimizer
    return get_fee_optimizer()

def get_channel_manager():
    """Get channel manager"""
    from ..lightning.channel_manager import get_channel_manager
    return get_channel_manager()

def get_connection_pool():
    """Get connection pool"""
    from .connection_pool import ConnectionPool
    return ConnectionPool()

def get_backup_manager():
    """Get backup manager"""
    from .backup_enhanced import SimpleBackup
    return SimpleBackup()

def get_recovery_system():
    """Get error recovery system"""
    from .advanced_error_recovery import get_error_recovery
    return get_error_recovery()

def get_unified_monitoring():
    """Get unified monitoring system"""
    from .monitoring_unified import get_unified_monitoring
    return get_unified_monitoring()

def get_service_container():
    """Get service container for dependency injection"""
    from .service_container import get_container
    return get_container()

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
    'get_backup_manager',
    'get_recovery_system',
    'get_unified_monitoring',
    'get_service_container'
]