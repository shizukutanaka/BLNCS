"""
BLNCS - Bitcoin Lightning Network Control System

Enterprise-grade Lightning Network management with proper dependency injection.
"""

__version__ = "1.0.0"
__author__ = "BLNCS Team"
__description__ = "Bitcoin Lightning Network Control System"

# Use service container instead of lazy loading to avoid circular dependency issues
def get_config():
    """Get configuration manager via service container"""
    from .core import get_service_container
    container = get_service_container()
    return container.get('config')

def get_logger():
    """Get logger via service container"""
    from .core import get_service_container
    container = get_service_container()
    return container.get_singleton('logger')

def get_cache_manager():
    """Get cache manager via service container"""
    from .core import get_service_container
    container = get_service_container()
    return container.get_singleton('cache')

def get_lightning_client():
    """Get Lightning client via service container"""
    from .core import get_service_container
    container = get_service_container()
    return container.get('lightning_client')

def get_api_server(config=None):
    """Get API server via service container"""
    from .core import get_service_container
    container = get_service_container()
    try:
        return container.get('api_server')
    except KeyError:
        raise ImportError("API server not configured. Check installation.")

__all__ = [
    'get_config',
    'get_logger', 
    'get_cache_manager',
    'get_lightning_client',
    'get_api_server'
]