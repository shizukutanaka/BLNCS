"""
BLNCS GUI Package - Modern dashboard interface.

This package provides a professional, Atlassian-inspired desktop GUI
for monitoring Bitcoin Lightning Network infrastructure.
"""

from .dashboard_gui import AtlassianTheme, DashboardGUI, create_dashboard_gui
from .net_utils import NetworkUtils, network_utils

__version__ = "2.0.0"
__all__ = [
    "create_dashboard_gui",
    "DashboardGUI",
    "AtlassianTheme",
    "network_utils",
    "NetworkUtils",
]
