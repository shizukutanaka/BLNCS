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
        from .config_manager import get_config_manager
        return get_config_manager()
    return _get_or_create('config', _factory)

def get_logger(name: Optional[str] = None):
    """Get logging system"""  
    from .logger import get_logger as _get_logger
    return _get_logger(name)

def get_database():
    """Get unified database system"""
    def _factory():
        from .database import get_database
        return get_database()
    return _get_or_create('database', _factory)

def get_cache():
    """Get unified cache system"""
    def _factory():
        from .cache_unified import get_cache
        return get_cache()
    return _get_or_create('cache', _factory)

def get_validator():
    """Get enhanced validator system"""
    def _factory():
        from .enhanced_validator import get_enhanced_validator
        return get_enhanced_validator()
    return _get_or_create('validator', _factory)

__all__ = [
    'get_config',
    'get_logger', 
    'get_database',
    'get_cache',
    'get_validator'
]