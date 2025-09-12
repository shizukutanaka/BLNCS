#!/usr/bin/env python3
"""
BLNCS Language Management System
Advanced language detection, preferences, and UI integration.
"""

import os
import json
import locale
import logging
from pathlib import Path
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from threading import Lock

try:
    from .translator import Translator, get_translator
    from .locale_utils import get_system_locale
except ImportError:
    # For standalone testing
    import sys
    sys.path.append(str(Path(__file__).parent))
    from translator import Translator, get_translator
    from locale_utils import get_system_locale

logger = logging.getLogger(__name__)


@dataclass
class LanguagePreferences:
    """User language preferences with fallbacks"""
    primary_language: str = 'en'
    fallback_languages: List[str] = field(default_factory=lambda: ['en'])
    auto_detect: bool = True
    save_preference: bool = True
    ui_language: str = 'en'
    date_format: str = 'auto'
    number_format: str = 'auto'
    currency_format: str = 'auto'


class LanguageManager:
    """Advanced language management with preferences and UI integration"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = Path(config_path or self._get_default_config_path())
        self.translator = get_translator()
        self.preferences = LanguagePreferences()
        self.language_change_callbacks: List[Callable[[str, str], None]] = []
        self.lock = Lock()
        
        # Load preferences
        self.load_preferences()
        
        # Apply initial language
        self.apply_preferred_language()
    
    def _get_default_config_path(self) -> str:
        """Get default configuration path"""
        config_dir = Path.home() / '.blncs'
        config_dir.mkdir(exist_ok=True)
        return str(config_dir / 'language_preferences.json')
    
    def load_preferences(self):
        """Load language preferences from config file"""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Update preferences with loaded data
                for key, value in data.items():
                    if hasattr(self.preferences, key):
                        setattr(self.preferences, key, value)
                
                logger.info(f"Loaded language preferences: {self.preferences.primary_language}")
            else:
                logger.info("No language preferences found, using defaults")
                
        except Exception as e:
            logger.error(f"Failed to load language preferences: {e}")
    
    def save_preferences(self):
        """Save current preferences to config file"""
        if not self.preferences.save_preference:
            return
        
        try:
            # Create config directory if needed
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Convert preferences to dict
            preferences_dict = {
                'primary_language': self.preferences.primary_language,
                'fallback_languages': self.preferences.fallback_languages,
                'auto_detect': self.preferences.auto_detect,
                'save_preference': self.preferences.save_preference,
                'ui_language': self.preferences.ui_language,
                'date_format': self.preferences.date_format,
                'number_format': self.preferences.number_format,
                'currency_format': self.preferences.currency_format
            }
            
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(preferences_dict, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Saved language preferences to {self.config_path}")
            
        except Exception as e:
            logger.error(f"Failed to save language preferences: {e}")
    
    def detect_system_language(self) -> str:
        """Detect system language"""
        try:
            # Get system locale
            system_locale = get_system_locale()
            
            # Extract language code
            if system_locale:
                language_code = system_locale.split('_')[0].lower()
                
                # Check if language is available
                available_languages = self.translator.get_available_languages()
                if language_code in available_languages:
                    logger.info(f"Detected system language: {language_code}")
                    return language_code
                else:
                    logger.info(f"System language {language_code} not available, using fallback")
            
        except Exception as e:
            logger.warning(f"Failed to detect system language: {e}")
        
        return 'en'  # Fallback to English
    
    def apply_preferred_language(self):
        """Apply preferred language with auto-detection and fallbacks"""
        target_language = self.preferences.primary_language
        
        # Auto-detect system language if enabled
        if self.preferences.auto_detect and target_language == 'en':
            detected_language = self.detect_system_language()
            if detected_language != 'en':
                target_language = detected_language
                self.preferences.primary_language = detected_language
                self.save_preferences()
        
        # Set language with fallback handling
        if not self.set_language(target_language):
            logger.warning(f"Failed to set language {target_language}, trying fallbacks")
            
            # Try fallback languages
            for fallback_lang in self.preferences.fallback_languages:
                if self.set_language(fallback_lang):
                    self.preferences.primary_language = fallback_lang
                    break
            else:
                # Ultimate fallback to English
                self.set_language('en')
                self.preferences.primary_language = 'en'
    
    def set_language(self, language_code: str, save_preference: bool = True) -> bool:
        """Set current language with preference saving"""
        # Check if language is available
        available_languages = self.translator.get_available_languages()
        if language_code not in available_languages:
            logger.warning(f"Language {language_code} not available")
            return False
        
        # Get old language for callbacks
        old_language = self.translator.get_current_language()
        
        # Set language in translator
        if not self.translator.set_language(language_code):
            return False
        
        # Update preferences
        with self.lock:
            self.preferences.primary_language = language_code
            self.preferences.ui_language = language_code
        
        # Save preferences if requested
        if save_preference:
            self.save_preferences()
        
        # Notify callbacks
        self._notify_language_change(old_language, language_code)
        
        logger.info(f"Language set to {language_code}")
        return True
    
    def get_current_language(self) -> str:
        """Get current language"""
        return self.translator.get_current_language()
    
    def get_available_languages(self) -> Dict[str, str]:
        """Get available languages with metadata"""
        return self.translator.get_available_languages()
    
    def get_language_info(self, language_code: str) -> Optional[Dict[str, Any]]:
        """Get detailed language information"""
        if language_code not in self.translator.translations:
            return None
        
        translation_data = self.translator.translations[language_code]
        return {
            'code': language_code,
            'name': translation_data.language_name,
            'metadata': translation_data.metadata,
            'translation_count': len(translation_data.translations)
        }
    
    def add_language_change_callback(self, callback: Callable[[str, str], None]):
        """Add callback for language change events"""
        with self.lock:
            self.language_change_callbacks.append(callback)
    
    def remove_language_change_callback(self, callback: Callable[[str, str], None]):
        """Remove language change callback"""
        with self.lock:
            if callback in self.language_change_callbacks:
                self.language_change_callbacks.remove(callback)
    
    def _notify_language_change(self, old_language: str, new_language: str):
        """Notify all callbacks of language change"""
        with self.lock:
            callbacks = self.language_change_callbacks.copy()
        
        for callback in callbacks:
            try:
                callback(old_language, new_language)
            except Exception as e:
                logger.error(f"Language change callback failed: {e}")
    
    def get_language_completion_percentage(self, language_code: str) -> float:
        """Get translation completion percentage compared to English"""
        if language_code not in self.translator.translations:
            return 0.0
        
        if language_code == 'en':
            return 100.0
        
        english_count = len(self.translator.translations['en'].translations)
        language_count = len(self.translator.translations[language_code].translations)
        
        if english_count == 0:
            return 100.0
        
        return (language_count / english_count) * 100.0
    
    def get_missing_translations(self, language_code: str) -> List[str]:
        """Get list of missing translation keys for a language"""
        if language_code not in self.translator.translations or 'en' not in self.translator.translations:
            return []
        
        english_keys = set(self.translator.translations['en'].translations.keys())
        language_keys = set(self.translator.translations[language_code].translations.keys())
        
        return list(english_keys - language_keys)
    
    def create_language_selector_data(self) -> List[Dict[str, Any]]:
        """Create data structure for language selector UI"""
        languages = []
        current_language = self.get_current_language()
        
        for code, name in self.get_available_languages().items():
            completion = self.get_language_completion_percentage(code)
            
            languages.append({
                'code': code,
                'name': name,
                'completion': completion,
                'is_current': code == current_language,
                'is_complete': completion >= 95.0
            })
        
        # Sort by completion percentage (descending) and then by name
        languages.sort(key=lambda x: (-x['completion'], x['name']))
        
        return languages
    
    def export_translation_template(self, language_code: str, output_path: str):
        """Export translation template for translators"""
        if 'en' not in self.translator.translations:
            logger.error("English translations not available for template export")
            return
        
        english_translations = self.translator.translations['en']
        
        # Create template structure
        template = {
            '_metadata': {
                'language_name': 'Language Name',
                'language_code': language_code,
                'version': '1.0.0',
                'contributors': ['Your Name'],
                'completion_status': 'in_progress',
                'notes': 'Translation template generated automatically'
            }
        }
        
        # Add all English keys with empty values for translation
        for key, english_value in english_translations.translations.items():
            template[key] = f"TODO: Translate '{english_value}'"
        
        # Save template
        template_path = Path(output_path)
        template_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(template_path, 'w', encoding='utf-8') as f:
            json.dump(template, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Translation template exported to {template_path}")
    
    def validate_translations(self, language_code: str) -> Dict[str, List[str]]:
        """Validate translations for common issues"""
        if language_code not in self.translator.translations:
            return {'errors': [f'Language {language_code} not found']}
        
        translation_data = self.translator.translations[language_code]
        issues = {
            'errors': [],
            'warnings': [],
            'missing': [],
            'formatting_issues': []
        }
        
        # Check for missing translations
        if 'en' in self.translator.translations:
            missing = self.get_missing_translations(language_code)
            issues['missing'] = missing
        
        # Check for formatting issues
        for key, value in translation_data.translations.items():
            if not value or value.strip() == '':
                issues['errors'].append(f'Empty translation for key: {key}')
            
            # Check for untranslated placeholders
            if 'TODO:' in value:
                issues['warnings'].append(f'Untranslated placeholder in key: {key}')
            
            # Check for formatting consistency
            if '{' in value and '}' in value:
                # This is a formatted string, could add more validation
                pass
        
        return issues


# Global language manager instance
_language_manager = None
_language_manager_lock = Lock()


def get_language_manager() -> LanguageManager:
    """Get global language manager instance"""
    global _language_manager
    
    if _language_manager is None:
        with _language_manager_lock:
            if _language_manager is None:
                _language_manager = LanguageManager()
    
    return _language_manager


if __name__ == "__main__":
    # Test language manager
    import tempfile
    
    with tempfile.TemporaryDirectory() as temp_dir:
        config_path = Path(temp_dir) / "test_config.json"
        manager = LanguageManager(str(config_path))
        
        print("Language Manager Test")
        print("=" * 30)
        
        # Test language detection
        detected = manager.detect_system_language()
        print(f"Detected system language: {detected}")
        
        # Test available languages
        languages = manager.get_available_languages()
        print(f"\nAvailable languages: {list(languages.keys())}")
        
        # Test language selector data
        selector_data = manager.create_language_selector_data()
        print(f"\nLanguage selector data:")
        for lang_data in selector_data:
            current_marker = " (current)" if lang_data['is_current'] else ""
            print(f"  {lang_data['code']}: {lang_data['name']} - {lang_data['completion']:.1f}%{current_marker}")
        
        # Test language switching
        print(f"\nTesting language switching:")
        for lang_code in ['ja', 'es', 'en']:
            success = manager.set_language(lang_code)
            current = manager.get_current_language()
            print(f"  Set to {lang_code}: {'✅' if success else '❌'} (current: {current})")
        
        # Test validation
        validation = manager.validate_translations('en')
        print(f"\nValidation results for English: {len(validation.get('errors', []))} errors")
        
        print("\nLanguage manager test completed")