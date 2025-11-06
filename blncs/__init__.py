#!/usr/bin/env python3
"""
BLNCS - Bitcoin Lightning Network Control System

Enterprise-grade Lightning Network management with proper dependency injection.
"""

import os
import gettext
from pathlib import Path

__author__ = "BLNCS Team"
__description__ = "Bitcoin Lightning Network Control System"

# Initialize internationalization system
_i18n_manager = None

class I18NManager:
    """Simplified i18n manager for basic functionality"""

    def __init__(self, domain: str = "blncs", localedir: str = None):
        self.domain = domain
        if localedir is None:
            project_root = Path(__file__).parent.parent.parent
            self.localedir = str(project_root / "locale")
        else:
            self.localedir = localedir

        self._translation = None
        self._current_locale = 'en'

        # Try to setup translations
        self._setup_translations()

    def _setup_translations(self):
        """Setup gettext translations"""
        try:
            # Try to load specific translation if available
            try:
                self._translation = gettext.translation(
                    self.domain,
                    self.localedir,
                    languages=['en', 'ja'],
                    fallback=True
                )
            except Exception:
                # Use null translation as fallback
                self._translation = gettext.NullTranslations()
        except Exception:
            # Final fallback to null translation
            self._translation = gettext.NullTranslations()

    def get_text(self, message: str, *args) -> str:
        """Get translated text"""
        try:
            if self._translation:
                translated = self._translation.gettext(message)
            else:
                translated = message
            if args:
                translated = translated % args
            return translated
        except Exception:
            return message % args if args else message

# Initialize i18n manager
_i18n_manager = I18NManager()

# Global translation function
def _(message: str, *args) -> str:
    """Global translation function"""
    return _i18n_manager.get_text(message, *args)

# Simplified direct imports for memory efficiency
def get_config():
    """Get configuration manager"""
    from .core import get_config
    return get_config()


def get_logger():
    """Get logger"""
    from .core import get_logger
    return get_logger()


def get_cache_manager():
    """Get cache manager"""
    from .core import get_cache
    return get_cache()


def get_lightning_client():
    """Get Lightning client"""
    try:
        from .lightning import get_lightning_client
        return get_lightning_client()
    except ImportError:
        raise ImportError("Lightning client not available. Check installation.")


def get_api_server(config=None):
    """Get API server"""
    try:
        from .api import get_api_server
        return get_api_server()
    except ImportError:
        raise ImportError("API server not configured. Check installation.")


def get_i18n_manager():
    """Get internationalization manager"""
    return _i18n_manager


__all__ = [
    'get_config',
    'get_logger',
    'get_cache_manager',
    'get_lightning_client',
    'get_api_server',
    'get_i18n_manager',
    '_',
    '__version__'
]