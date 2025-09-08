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

def get_config_manager():
    """Get enhanced configuration manager"""
    from .config_manager import get_config_manager as _get_config_manager
    return _get_config_manager()

def get_logger(name: Optional[str] = None):
    """Get logging system"""  
    from .logger import get_logger as _get_logger
    return _get_logger(name)

def get_cache():
    """Get cache system"""
    from .fast_cache import get_cache as _get_cache
    return _get_cache()

def get_health_checker():
    """Get health checker"""
    from .health import get_health_checker as _get_health_checker
    return _get_health_checker()

def get_validator():
    """Get enhanced validator"""
    from .enhanced_validator import get_enhanced_validator
    return get_enhanced_validator()

def get_enhanced_validator():
    """Get enhanced validator system"""
    from .enhanced_validator import get_enhanced_validator as _get_enhanced_validator
    return _get_enhanced_validator()

def get_security_manager():
    """Get security manager"""
    from .security import get_security_manager
    return get_security_manager()

def get_monitor():
    """Get unified system monitor"""
    from .monitor import get_monitor as _get_monitor
    return _get_monitor()

def get_unified_monitor():
    """Get unified monitor (alias for get_monitor)"""
    return get_monitor()

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

def get_backup_manager():
    """Get backup manager"""
    from .backup_enhanced import SimpleBackup
    return SimpleBackup()

def get_recovery_system():
    """Get error recovery system"""
    from .recovery import get_error_recovery
    return get_error_recovery()

def get_enhanced_recovery_system():
    """Get enhanced error recovery system"""
    from .recovery_enhanced import get_enhanced_error_recovery
    return get_enhanced_error_recovery()

def get_unified_monitoring():
    """Get unified monitoring system"""
    from .monitoring_unified import get_unified_monitoring
    return get_unified_monitoring()

def get_enhanced_monitoring():
    """Get enhanced unified monitoring system"""
    from .monitoring_unified import get_unified_monitoring
    return get_unified_monitoring()

__all__ = [
    'get_config',
    'get_config_manager',
    'get_logger', 
    'get_cache',
    'get_health_checker',
    'get_validator',
    'get_enhanced_validator',
    'get_security_manager',
    'get_monitor',
    'get_fee_optimizer',
    'get_channel_manager',
    'get_connection_pool',
    'get_unified_monitor',
    'get_backup_manager',
    'get_recovery_system',
    'get_enhanced_recovery_system',
    'get_unified_monitoring',
    'get_enhanced_monitoring'
]