"""
BLNCS GUI Package - Modern dashboard interface.

This package provides a professional, Atlassian-inspired desktop GUI
for monitoring Bitcoin Lightning Network infrastructure.
"""

from .dashboard_gui import create_dashboard_gui, DashboardGUI, AtlassianTheme
from .net_utils import network_utils, NetworkUtils

__version__ = "2.0.0"
__all__ = [
    'create_dashboard_gui',
    'DashboardGUI',
    'AtlassianTheme',
    'network_utils',
    'NetworkUtils'
]
