"""
BLNCS Mobile-First Responsive Web Interface
Modern, accessible web interface supporting all devices and user types.
"""

from .web_interface import (
    WebInterfaceManager,
    UIComponentLibrary,
    ResponsiveLayoutEngine,
    ThemeManager,
    AccessibilityManager,
    MobileOptimizations,
    ComponentRenderer,
    get_web_interface_manager,
    initialize_web_interface
)

__all__ = [
    "WebInterfaceManager",
    "UIComponentLibrary",
    "ResponsiveLayoutEngine",
    "ThemeManager",
    "AccessibilityManager",
    "MobileOptimizations",
    "ComponentRenderer",
    "get_web_interface_manager",
    "initialize_web_interface"
]