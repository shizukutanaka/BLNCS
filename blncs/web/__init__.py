"""
BLNCS Web Dashboard
Modern web interface for BLNCS management and monitoring.
"""

from .app import create_web_app, WebDashboardServer
from .api_client import BLNCSAPIClient
from .dashboard_routes import dashboard_routes
from .static_routes import static_routes
from .websocket_handler import WebSocketHandler

__all__ = [
    'create_web_app',
    'WebDashboardServer',
    'BLNCSAPIClient',
    'dashboard_routes',
    'static_routes',
    'WebSocketHandler'
]

__version__ = '1.0.0'