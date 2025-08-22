# BLRCS i18n Module
# Simple internationalization support
import json
from pathlib import Path
from typing import Dict, Optional
from blrcs.logger import get_logger

class Translator:
    """Simple internationalization support."""
    
    def __init__(self, default_lang: str = "en", supported_langs: list = None):
        self.default_lang = default_lang
        self.supported_langs = supported_langs or ["en", "ja"]
        self.translations: Dict[str, Dict[str, str]] = {}
        self.current_lang = default_lang
        self.logger = get_logger(__name__)
        self._load_translations()
    
    def _load_translations(self):
        """Load translation files"""
        translations_dir = Path(__file__).parent / "translations"
        
        for lang in self.supported_langs:
            lang_file = translations_dir / f"{lang}.json"
            if lang_file.exists():
                with open(lang_file, 'r', encoding='utf-8') as f:
                    self.translations[lang] = json.load(f)
            else:
                self.translations[lang] = {}
    
    def set_language(self, lang: str):
        """Set current language"""
        if lang in self.supported_langs:
            self.current_lang = lang
        else:
            self.current_lang = self.default_lang
    
    def get(self, key: str, lang: Optional[str] = None, **kwargs) -> str:
        """Get translated string."""
        lang = lang or self.current_lang
        
        # Try to get translation
        if lang in self.translations and key in self.translations[lang]:
            text = self.translations[lang][key]
        elif self.default_lang in self.translations and key in self.translations[self.default_lang]:
            # Fallback to default language and log warning
            text = self.translations[self.default_lang][key]
            try:
                self.logger.warning(
                    "Missing translation key; fell back to default language",
                    extra={
                        'extra': {
                            'key': key,
                            'requested_lang': lang,
                            'fallback_lang': self.default_lang,
                            'event': 'i18n_fallback_default'
                        }
                    }
                )
            except Exception:
                pass
        else:
            # No translation anywhere: return key and log error
            text = key
            try:
                self.logger.error(
                    "Missing translation key in all languages",
                    extra={
                        'extra': {
                            'key': key,
                            'requested_lang': lang,
                            'available_langs': list(self.translations.keys()),
                            'event': 'i18n_missing_key'
                        }
                    }
                )
            except Exception:
                pass
        
        # Format if parameters provided
        if kwargs:
            try:
                text = text.format(**kwargs)
            except Exception as e:
                # Log formatting failure but return unformatted text
                try:
                    self.logger.exception(
                        "Translation formatting failed",
                        extra={
                            'extra': {
                                'key': key,
                                'requested_lang': lang,
                                'params': {k: type(v).__name__ for k, v in kwargs.items()},
                                'event': 'i18n_format_error'
                            }
                        }
                    )
                except Exception:
                    pass
        
        return text
    
    def get_all(self, lang: Optional[str] = None) -> Dict[str, str]:
        """Get all translations for a language"""
        lang = lang or self.current_lang
        return self.translations.get(lang, {})
