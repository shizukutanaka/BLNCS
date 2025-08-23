"""
BLRCS Interfaces Module

This module contains all user interfaces and external API systems:
- REST API system
- Web application interface  
- Command line interface
- Desktop GUI application
- Internationalization support
"""

from .api_system import *
from .app import *
from .cli import *
from .desktop import *
from .i18n_system import *

__all__ = [
    'ApiSystem',
    'WebApp',
    'CLI',
    'DesktopApp', 
    'I18nSystem'
]