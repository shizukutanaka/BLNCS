"""
Configuration Manager for BLNCS - Wrapper for lightweight implementation
Maintains compatibility while using optimized lightweight config system.
"""

from .config_lightweight import (
    LightweightConfigManager, 
    get_config_manager as get_lightweight_config_manager,
    ConfigValue
)

# Re-export for compatibility
ConfigManager = LightweightConfigManager

def get_config_manager(config_path=None):
    """Get configuration manager instance (compatibility wrapper)"""
    return get_lightweight_config_manager(config_path)

__all__ = ['ConfigManager', 'LightweightConfigManager', 'get_config_manager', 'ConfigValue']