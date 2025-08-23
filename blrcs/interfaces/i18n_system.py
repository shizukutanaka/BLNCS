"""
Internationalization (i18n) System
Multi-language support for global deployment
"""

import json
import os
import re
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import threading


class Language(Enum):
    """Supported languages"""
    EN = "en"  # English
    JA = "ja"  # Japanese
    ZH = "zh"  # Chinese
    KO = "ko"  # Korean
    ES = "es"  # Spanish
    FR = "fr"  # French
    DE = "de"  # German
    RU = "ru"  # Russian
    AR = "ar"  # Arabic
    HI = "hi"  # Hindi
    PT = "pt"  # Portuguese
    IT = "it"  # Italian


@dataclass
class Translation:
    """Translation entry"""
    key: str
    language: Language
    value: str
    context: str = ""
    plural_forms: Dict[str, str] = field(default_factory=dict)
    variables: List[str] = field(default_factory=list)


@dataclass
class Locale:
    """Locale configuration"""
    language: Language
    country: str = ""
    variant: str = ""
    date_format: str = "%Y-%m-%d"
    time_format: str = "%H:%M:%S"
    number_format: str = "."
    currency: str = "USD"
    direction: str = "ltr"  # left-to-right or rtl


class TranslationLoader:
    """Loads translations from various sources"""
    
    def __init__(self, base_path: str = "translations"):
        self.base_path = Path(base_path)
        self.translations = {}
        
    def load_json(self, language: Language) -> Dict[str, str]:
        """Load translations from JSON file"""
        file_path = self.base_path / f"{language.value}.json"
        
        if file_path.exists():
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}
        
    def load_all(self) -> Dict[Language, Dict[str, str]]:
        """Load all available translations"""
        translations = {}
        
        for language in Language:
            trans = self.load_json(language)
            if trans:
                translations[language] = trans
                
        return translations
        
    def save_json(self, language: Language, translations: Dict[str, str]):
        """Save translations to JSON file"""
        file_path = self.base_path / f"{language.value}.json"
        
        # Create directory if not exists
        self.base_path.mkdir(parents=True, exist_ok=True)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(translations, f, ensure_ascii=False, indent=2)


class Translator:
    """Main translation engine"""
    
    def __init__(self):
        self.loader = TranslationLoader()
        self.translations = {}
        self.current_language = Language.EN
        self.fallback_language = Language.EN
        self.cache = {}
        self.lock = threading.Lock()
        
        # Load initial translations
        self._load_translations()
        
    def _load_translations(self):
        """Load all translations"""
        self.translations = self.loader.load_all()
        
        # Add default English translations if not present
        if Language.EN not in self.translations:
            self.translations[Language.EN] = self._get_default_translations()
            
    def _get_default_translations(self) -> Dict[str, str]:
        """Get default English translations"""
        return {
            # System messages
            "system.welcome": "Welcome to BLRCS",
            "system.loading": "Loading...",
            "system.ready": "System ready",
            "system.error": "An error occurred",
            "system.success": "Operation successful",
            "system.warning": "Warning",
            "system.info": "Information",
            
            # Authentication
            "auth.login": "Login",
            "auth.logout": "Logout",
            "auth.username": "Username",
            "auth.password": "Password",
            "auth.email": "Email",
            "auth.register": "Register",
            "auth.forgot_password": "Forgot password?",
            "auth.reset_password": "Reset password",
            "auth.invalid_credentials": "Invalid credentials",
            "auth.session_expired": "Session expired",
            "auth.access_denied": "Access denied",
            
            # Security
            "security.alert": "Security Alert",
            "security.threat_detected": "Threat detected",
            "security.scanning": "Scanning for threats",
            "security.secure": "System secure",
            "security.vulnerability": "Vulnerability found",
            "security.update_required": "Security update required",
            
            # Operations
            "ops.start": "Start",
            "ops.stop": "Stop",
            "ops.restart": "Restart",
            "ops.status": "Status",
            "ops.running": "Running",
            "ops.stopped": "Stopped",
            "ops.pending": "Pending",
            "ops.failed": "Failed",
            
            # Data
            "data.save": "Save",
            "data.load": "Load",
            "data.delete": "Delete",
            "data.export": "Export",
            "data.import": "Import",
            "data.backup": "Backup",
            "data.restore": "Restore",
            
            # UI
            "ui.ok": "OK",
            "ui.cancel": "Cancel",
            "ui.yes": "Yes",
            "ui.no": "No",
            "ui.confirm": "Confirm",
            "ui.close": "Close",
            "ui.help": "Help",
            "ui.settings": "Settings",
            "ui.dashboard": "Dashboard",
            "ui.profile": "Profile",
            
            # Errors
            "error.not_found": "Not found",
            "error.internal": "Internal error",
            "error.timeout": "Request timeout",
            "error.network": "Network error",
            "error.permission": "Permission denied",
            "error.invalid_input": "Invalid input",
            "error.rate_limit": "Rate limit exceeded",
            
            # Validation
            "validation.required": "This field is required",
            "validation.email": "Invalid email address",
            "validation.min_length": "Minimum length is {min}",
            "validation.max_length": "Maximum length is {max}",
            "validation.pattern": "Invalid format",
            "validation.number": "Must be a number",
            
            # Time
            "time.seconds": "{count} second(s)",
            "time.minutes": "{count} minute(s)",
            "time.hours": "{count} hour(s)",
            "time.days": "{count} day(s)",
            "time.ago": "{time} ago",
            "time.remaining": "{time} remaining"
        }
        
    def set_language(self, language: Language):
        """Set current language"""
        self.current_language = language
        
        # Clear cache when language changes
        with self.lock:
            self.cache.clear()
            
    def get(self, key: str, language: Optional[Language] = None, 
           **variables) -> str:
        """Get translated string"""
        lang = language or self.current_language
        
        # Check cache
        cache_key = f"{lang.value}:{key}"
        if cache_key in self.cache and not variables:
            return self.cache[cache_key]
            
        # Get translation
        if lang in self.translations and key in self.translations[lang]:
            translation = self.translations[lang][key]
        elif self.fallback_language in self.translations and \
             key in self.translations[self.fallback_language]:
            translation = self.translations[self.fallback_language][key]
        else:
            translation = key  # Return key if no translation found
            
        # Replace variables
        if variables:
            for var_name, var_value in variables.items():
                translation = translation.replace(f"{{{var_name}}}", str(var_value))
                
        # Cache result if no variables
        if not variables:
            with self.lock:
                self.cache[cache_key] = translation
                
        return translation
        
    def t(self, key: str, **variables) -> str:
        """Shorthand for get()"""
        return self.get(key, **variables)
        
    def add_translation(self, key: str, language: Language, value: str):
        """Add or update a translation"""
        if language not in self.translations:
            self.translations[language] = {}
            
        self.translations[language][key] = value
        
        # Clear cache
        with self.lock:
            cache_key = f"{language.value}:{key}"
            if cache_key in self.cache:
                del self.cache[cache_key]
                
    def has_translation(self, key: str, language: Optional[Language] = None) -> bool:
        """Check if translation exists"""
        lang = language or self.current_language
        return lang in self.translations and key in self.translations[lang]
        
    def get_available_languages(self) -> List[Language]:
        """Get list of languages with translations"""
        return list(self.translations.keys())
        
    def export_translations(self, language: Language, file_path: str):
        """Export translations to file"""
        if language in self.translations:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(self.translations[language], f, 
                         ensure_ascii=False, indent=2)
                         
    def import_translations(self, language: Language, file_path: str):
        """Import translations from file"""
        with open(file_path, 'r', encoding='utf-8') as f:
            translations = json.load(f)
            
        self.translations[language] = translations
        
        # Clear cache for this language
        with self.lock:
            keys_to_remove = [k for k in self.cache if k.startswith(f"{language.value}:")]
            for key in keys_to_remove:
                del self.cache[key]


class Pluralizer:
    """Handles plural forms for different languages"""
    
    def __init__(self):
        self.rules = {
            Language.EN: self._plural_en,
            Language.JA: self._plural_ja,
            Language.ZH: self._plural_zh,
            Language.FR: self._plural_fr,
            Language.RU: self._plural_ru,
            Language.AR: self._plural_ar
        }
        
    def get_plural_form(self, count: int, language: Language) -> str:
        """Get plural form key for count"""
        if language in self.rules:
            return self.rules[language](count)
        return "other"
        
    def _plural_en(self, count: int) -> str:
        """English plural rules"""
        if count == 1:
            return "one"
        return "other"
        
    def _plural_ja(self, count: int) -> str:
        """Japanese plural rules (no plurals)"""
        return "other"
        
    def _plural_zh(self, count: int) -> str:
        """Chinese plural rules (no plurals)"""
        return "other"
        
    def _plural_fr(self, count: int) -> str:
        """French plural rules"""
        if count == 0 or count == 1:
            return "one"
        return "other"
        
    def _plural_ru(self, count: int) -> str:
        """Russian plural rules"""
        if count % 10 == 1 and count % 100 != 11:
            return "one"
        elif count % 10 in [2, 3, 4] and count % 100 not in [12, 13, 14]:
            return "few"
        return "many"
        
    def _plural_ar(self, count: int) -> str:
        """Arabic plural rules"""
        if count == 0:
            return "zero"
        elif count == 1:
            return "one"
        elif count == 2:
            return "two"
        elif count % 100 in range(3, 11):
            return "few"
        elif count % 100 in range(11, 100):
            return "many"
        return "other"


class DateTimeFormatter:
    """Formats dates and times for different locales"""
    
    def __init__(self):
        self.formats = {
            Language.EN: {
                "date": "%m/%d/%Y",
                "time": "%I:%M %p",
                "datetime": "%m/%d/%Y %I:%M %p"
            },
            Language.JA: {
                "date": "%Y年%m月%d日",
                "time": "%H時%M分",
                "datetime": "%Y年%m月%d日 %H時%M分"
            },
            Language.ZH: {
                "date": "%Y年%m月%d日",
                "time": "%H:%M",
                "datetime": "%Y年%m月%d日 %H:%M"
            },
            Language.FR: {
                "date": "%d/%m/%Y",
                "time": "%H:%M",
                "datetime": "%d/%m/%Y %H:%M"
            },
            Language.DE: {
                "date": "%d.%m.%Y",
                "time": "%H:%M",
                "datetime": "%d.%m.%Y %H:%M"
            }
        }
        
    def format_date(self, date, language: Language) -> str:
        """Format date for locale"""
        if language in self.formats:
            return date.strftime(self.formats[language]["date"])
        return date.strftime("%Y-%m-%d")
        
    def format_time(self, time, language: Language) -> str:
        """Format time for locale"""
        if language in self.formats:
            return time.strftime(self.formats[language]["time"])
        return time.strftime("%H:%M:%S")
        
    def format_datetime(self, datetime, language: Language) -> str:
        """Format datetime for locale"""
        if language in self.formats:
            return datetime.strftime(self.formats[language]["datetime"])
        return datetime.strftime("%Y-%m-%d %H:%M:%S")


class NumberFormatter:
    """Formats numbers for different locales"""
    
    def __init__(self):
        self.formats = {
            Language.EN: {"decimal": ".", "thousands": ","},
            Language.FR: {"decimal": ",", "thousands": " "},
            Language.DE: {"decimal": ",", "thousands": "."},
            Language.JA: {"decimal": ".", "thousands": ","},
            Language.AR: {"decimal": "٫", "thousands": "٬"}
        }
        
    def format_number(self, number: Union[int, float], 
                     language: Language, decimals: int = 2) -> str:
        """Format number for locale"""
        if language in self.formats:
            fmt = self.formats[language]
        else:
            fmt = self.formats[Language.EN]
            
        # Format with decimals
        if isinstance(number, float):
            formatted = f"{number:,.{decimals}f}"
        else:
            formatted = f"{number:,}"
            
        # Replace separators
        formatted = formatted.replace(",", "TEMP")
        formatted = formatted.replace(".", fmt["decimal"])
        formatted = formatted.replace("TEMP", fmt["thousands"])
        
        return formatted
        
    def format_currency(self, amount: float, currency: str, 
                       language: Language) -> str:
        """Format currency for locale"""
        formatted_number = self.format_number(amount, language, 2)
        
        # Currency position varies by locale
        if language in [Language.EN, Language.JA, Language.ZH]:
            return f"{currency}{formatted_number}"
        else:
            return f"{formatted_number} {currency}"
            
    def format_percentage(self, value: float, language: Language) -> str:
        """Format percentage for locale"""
        formatted_number = self.format_number(value, language, 2)
        
        # Arabic uses different percent sign
        if language == Language.AR:
            return f"{formatted_number}٪"
        return f"{formatted_number}%"


class I18nSystem:
    """Complete internationalization system"""
    
    def __init__(self):
        self.translator = Translator()
        self.pluralizer = Pluralizer()
        self.date_formatter = DateTimeFormatter()
        self.number_formatter = NumberFormatter()
        self.current_locale = Locale(Language.EN)
        
    def set_locale(self, locale: Locale):
        """Set current locale"""
        self.current_locale = locale
        self.translator.set_language(locale.language)
        
    def t(self, key: str, **variables) -> str:
        """Translate string"""
        return self.translator.t(key, **variables)
        
    def n(self, key: str, count: int, **variables) -> str:
        """Translate with plural form"""
        plural_form = self.pluralizer.get_plural_form(
            count, self.current_locale.language
        )
        
        # Try plural key first, then fallback to base key
        plural_key = f"{key}.{plural_form}"
        if self.translator.has_translation(plural_key):
            return self.translator.t(plural_key, count=count, **variables)
        return self.translator.t(key, count=count, **variables)
        
    def d(self, date) -> str:
        """Format date"""
        return self.date_formatter.format_date(date, self.current_locale.language)
        
    def dt(self, datetime) -> str:
        """Format datetime"""
        return self.date_formatter.format_datetime(datetime, self.current_locale.language)
        
    def num(self, number: Union[int, float], decimals: int = 2) -> str:
        """Format number"""
        return self.number_formatter.format_number(
            number, self.current_locale.language, decimals
        )
        
    def curr(self, amount: float, currency: Optional[str] = None) -> str:
        """Format currency"""
        currency = currency or self.current_locale.currency
        return self.number_formatter.format_currency(
            amount, currency, self.current_locale.language
        )
        
    def pct(self, value: float) -> str:
        """Format percentage"""
        return self.number_formatter.format_percentage(
            value, self.current_locale.language
        )
        
    def get_direction(self) -> str:
        """Get text direction for current locale"""
        if self.current_locale.language in [Language.AR]:
            return "rtl"
        return "ltr"


# Global i18n instance
i18n = I18nSystem()


def get_i18n() -> I18nSystem:
    """Get the global i18n system instance"""
    return i18n