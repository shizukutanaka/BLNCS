"""
BLNCS Documentation and Help System
Comprehensive documentation management and interactive help system.
"""

from .documentation_manager import DocumentationManager, get_documentation_manager
from .help_system import HelpSystem, get_help_system
from .content_generator import ContentGenerator, generate_documentation
from .interactive_help import InteractiveHelp, show_help

__all__ = [
    'DocumentationManager',
    'get_documentation_manager',
    'HelpSystem', 
    'get_help_system',
    'ContentGenerator',
    'generate_documentation',
    'InteractiveHelp',
    'show_help'
]

__version__ = '1.0.0'