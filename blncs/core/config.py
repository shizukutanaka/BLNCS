"""
Configuration compatibility wrapper
Provides backward compatibility for modules using old config module.
"""

from .config_manager import get_config_manager

def get_config():
    """Get configuration instance for backward compatibility"""
    return get_config_manager()