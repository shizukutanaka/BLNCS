"""
BLNCS Internationalization (i18n) Module
Multi-language support system for global accessibility.
"""

from .translator import Translator, get_translator, set_language, get_current_language
from .language_manager import LanguageManager, get_language_manager
from .locale_utils import get_system_locale, format_currency, format_datetime, format_number

__all__ = [
    'Translator',
    'get_translator', 
    'set_language',
    'get_current_language',
    'LanguageManager',
    'get_language_manager',
    'get_system_locale',
    'format_currency',
    'format_datetime', 
    'format_number'
]

__version__ = '1.0.0'