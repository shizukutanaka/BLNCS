"""
Simple Lightning Network Client - Alias for main client
This module provides backward compatibility for imports.
"""

from .client import SimpleClient, LightningError

# Create singleton instance
_client_instance = None

def get_lightning_client(host='localhost', port=8080, cert_path=None, macaroon_path=None):
    """Get or create Lightning client instance"""
    global _client_instance
    if _client_instance is None:
        _client_instance = SimpleClient(host, port, cert_path, macaroon_path)
    return _client_instance

# Export main class for direct imports
__all__ = ['SimpleClient', 'LightningError', 'get_lightning_client']