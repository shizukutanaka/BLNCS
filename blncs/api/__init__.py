"""
BLNCS API Module
軽量Lightning Network API
"""

try:
    from .unified_rest_api import UnifiedAPIServer, create_app
    API_AVAILABLE = True
except ImportError:
    API_AVAILABLE = False

    class UnifiedAPIServer:
        def __init__(self, *args, **kwargs): pass
        def start(self): pass
        def stop(self): pass

    def create_app(*args, **kwargs):
        return UnifiedAPIServer()

def get_api_server(*args, **kwargs):
    return create_app(*args, **kwargs)

__all__ = ['UnifiedAPIServer', 'create_app', 'get_api_server', 'API_AVAILABLE']