#!/usr/bin/env python3
"""
BLNCS Locale Utilities
Locale-aware formatting for numbers, dates, and currencies.
"""

import os
import locale
import logging
from datetime import datetime, date
from typing import Optional, Union, Dict, Any
from decimal import Decimal

logger = logging.getLogger(__name__)


def get_system_locale() -> Optional[str]:
    """Get system locale with fallback handling"""
    try:
        # Try different methods to get system locale
        
        # Method 1: locale.getdefaultlocale()
        try:
            system_locale, encoding = locale.getdefaultlocale()
            if system_locale:
                logger.debug(f"System locale from getdefaultlocale(): {system_locale}")
                return system_locale
        except Exception as e:
            logger.debug(f"getdefaultlocale() failed: {e}")
        
        # Method 2: locale.getlocale()
        try:
            system_locale, encoding = locale.getlocale()
            if system_locale:
                logger.debug(f"System locale from getlocale(): {system_locale}")
                return system_locale
        except Exception as e:
            logger.debug(f"getlocale() failed: {e}")
        
        # Method 3: Environment variables
        for env_var in ['LC_ALL', 'LC_CTYPE', 'LANG']:
            env_locale = os.environ.get(env_var)
            if env_locale and env_locale != 'C':
                logger.debug(f"System locale from {env_var}: {env_locale}")
                return env_locale
        
        # Method 4: Windows-specific
        if os.name == 'nt':
            try:
                import ctypes
                windll = ctypes.windll.kernel32
                locale_id = windll.GetUserDefaultUILanguage()
                # Convert Windows LCID to locale string
                locale_map = {
                    1033: 'en_US',  # English (US)
                    1041: 'ja_JP',  # Japanese
                    1031: 'de_DE',  # German
                    1036: 'fr_FR',  # French
                    1034: 'es_ES',  # Spanish
                    1040: 'it_IT',  # Italian
                    2052: 'zh_CN',  # Chinese (Simplified)
                    1028: 'zh_TW',  # Chinese (Traditional)
                    1042: 'ko_KR',  # Korean
                    1046: 'pt_BR',  # Portuguese (Brazil)
                    1049: 'ru_RU',  # Russian
                }
                if locale_id in locale_map:
                    windows_locale = locale_map[locale_id]
                    logger.debug(f"System locale from Windows LCID {locale_id}: {windows_locale}")
                    return windows_locale
            except Exception as e:
                logger.debug(f"Windows locale detection failed: {e}")
        
        logger.warning("Could not detect system locale, using default")
        return None
        
    except Exception as e:
        logger.error(f"Failed to get system locale: {e}")
        return None


class LocaleFormatter:
    """Locale-aware formatting utilities"""
    
    def __init__(self, language_code: str = 'en', auto_detect: bool = True):
        self.language_code = language_code
        self.locale_code = None
        
        if auto_detect:
            self.detect_and_set_locale()
        else:
            self.set_locale_for_language(language_code)
    
    def detect_and_set_locale(self):
        """Detect and set appropriate locale"""
        try:
            system_locale = get_system_locale()
            if system_locale:
                self.locale_code = system_locale
                self.set_system_locale(system_locale)
            else:
                self.set_locale_for_language(self.language_code)
        except Exception as e:
            logger.warning(f"Failed to detect locale: {e}")
            self.set_locale_for_language(self.language_code)
    
    def set_locale_for_language(self, language_code: str):
        """Set locale based on language code"""
        # Map language codes to common locales
        language_locale_map = {
            'en': ['en_US.UTF-8', 'en_US', 'English_United States.1252', 'C'],
            'ja': ['ja_JP.UTF-8', 'ja_JP', 'Japanese_Japan.932'],
            'es': ['es_ES.UTF-8', 'es_ES', 'Spanish_Spain.1252'],
            'de': ['de_DE.UTF-8', 'de_DE', 'German_Germany.1252'],
            'fr': ['fr_FR.UTF-8', 'fr_FR', 'French_France.1252'],
            'it': ['it_IT.UTF-8', 'it_IT', 'Italian_Italy.1252'],
            'pt': ['pt_PT.UTF-8', 'pt_PT', 'Portuguese_Portugal.1252'],
            'ru': ['ru_RU.UTF-8', 'ru_RU', 'Russian_Russia.1251'],
            'zh': ['zh_CN.UTF-8', 'zh_CN', 'Chinese_China.936'],
            'ko': ['ko_KR.UTF-8', 'ko_KR', 'Korean_Korea.949']
        }
        
        possible_locales = language_locale_map.get(language_code, ['C'])
        
        for locale_name in possible_locales:
            try:
                self.set_system_locale(locale_name)
                self.locale_code = locale_name
                logger.debug(f"Set locale to {locale_name} for language {language_code}")
                return
            except Exception as e:
                logger.debug(f"Failed to set locale {locale_name}: {e}")
        
        logger.warning(f"Could not set locale for language {language_code}")
        self.locale_code = 'C'
    
    def set_system_locale(self, locale_name: str):
        """Set system locale"""
        try:
            locale.setlocale(locale.LC_ALL, locale_name)
        except locale.Error:
            # Try different variations
            variations = [
                locale_name,
                locale_name.split('.')[0],  # Remove encoding
                locale_name.split('_')[0],  # Just language
                'C'  # Ultimate fallback
            ]
            
            for variation in variations:
                try:
                    locale.setlocale(locale.LC_ALL, variation)
                    break
                except locale.Error:
                    continue
            else:
                raise locale.Error(f"Could not set any locale variation for {locale_name}")
    
    def format_currency(self, amount: Union[int, float, Decimal], 
                       currency_code: str = 'BTC') -> str:
        """Format currency amount with locale-aware formatting"""
        try:
            # Handle special Bitcoin formatting
            if currency_code.upper() in ['BTC', 'SAT', 'SATS']:
                return self._format_bitcoin_amount(amount, currency_code)
            
            # Use locale-aware currency formatting for fiat
            if hasattr(locale, 'currency'):
                try:
                    return locale.currency(float(amount), symbol=True, grouping=True)
                except Exception:
                    pass
            
            # Fallback formatting
            return self._format_number_with_symbol(amount, currency_code)
            
        except Exception as e:
            logger.warning(f"Currency formatting failed: {e}")
            return f"{amount} {currency_code}"
    
    def _format_bitcoin_amount(self, amount: Union[int, float, Decimal], 
                              unit: str) -> str:
        """Format Bitcoin amounts with proper precision"""
        try:
            amount = float(amount)
            
            if unit.upper() in ['SAT', 'SATS']:
                # Format satoshis (no decimal places)
                formatted = self.format_number(int(amount), decimals=0)
                return f"{formatted} sats"
            
            elif unit.upper() == 'BTC':
                # Format Bitcoin (8 decimal places)
                formatted = self.format_number(amount, decimals=8)
                return f"{formatted} BTC"
            
            else:
                return f"{amount} {unit}"
                
        except Exception as e:
            logger.warning(f"Bitcoin amount formatting failed: {e}")
            return f"{amount} {unit}"
    
    def _format_number_with_symbol(self, amount: Union[int, float, Decimal], 
                                  symbol: str) -> str:
        """Format number with currency symbol"""
        try:
            formatted_number = self.format_number(float(amount), decimals=2)
            return f"{formatted_number} {symbol}"
        except Exception:
            return f"{amount} {symbol}"
    
    def format_number(self, number: Union[int, float, Decimal], 
                     decimals: Optional[int] = None) -> str:
        """Format number with locale-aware thousands separators"""
        try:
            if decimals is not None:
                # Format with specific decimal places
                format_str = f"{{:,.{decimals}f}}"
                return format_str.format(float(number))
            else:
                # Auto-detect appropriate format
                if isinstance(number, int) or float(number).is_integer():
                    return "{:,}".format(int(number))
                else:
                    return "{:,.2f}".format(float(number))
                    
        except Exception as e:
            logger.warning(f"Number formatting failed: {e}")
            return str(number)
    
    def format_datetime(self, dt: Union[datetime, date], 
                       format_type: str = 'medium') -> str:
        """Format datetime with locale-aware formatting"""
        try:
            if isinstance(dt, date) and not isinstance(dt, datetime):
                dt = datetime.combine(dt, datetime.min.time())
            
            # Define format types based on language
            formats = self._get_datetime_formats()
            
            if format_type in formats:
                return dt.strftime(formats[format_type])
            else:
                return dt.strftime(formats['medium'])
                
        except Exception as e:
            logger.warning(f"Datetime formatting failed: {e}")
            return str(dt)
    
    def _get_datetime_formats(self) -> Dict[str, str]:
        """Get datetime formats for current language"""
        # Language-specific datetime formats
        formats_by_language = {
            'en': {
                'short': '%m/%d/%y %H:%M',
                'medium': '%b %d, %Y %H:%M:%S',
                'long': '%B %d, %Y %I:%M:%S %p',
                'date_only': '%B %d, %Y',
                'time_only': '%I:%M:%S %p'
            },
            'ja': {
                'short': '%y/%m/%d %H:%M',
                'medium': '%Y年%m月%d日 %H:%M:%S',
                'long': '%Y年%m月%d日 %H時%M分%S秒',
                'date_only': '%Y年%m月%d日',
                'time_only': '%H:%M:%S'
            },
            'es': {
                'short': '%d/%m/%y %H:%M',
                'medium': '%d de %b de %Y %H:%M:%S',
                'long': '%d de %B de %Y %H:%M:%S',
                'date_only': '%d de %B de %Y',
                'time_only': '%H:%M:%S'
            },
            'de': {
                'short': '%d.%m.%y %H:%M',
                'medium': '%d. %b %Y %H:%M:%S',
                'long': '%d. %B %Y %H:%M:%S',
                'date_only': '%d. %B %Y',
                'time_only': '%H:%M:%S'
            }
        }
        
        return formats_by_language.get(self.language_code, formats_by_language['en'])
    
    def format_relative_time(self, dt: datetime) -> str:
        """Format relative time (e.g., '2 hours ago')"""
        try:
            now = datetime.now()
            diff = now - dt
            
            # Get relative time strings for current language
            relative_strings = self._get_relative_time_strings()
            
            if diff.days > 0:
                return relative_strings['days_ago'].format(days=diff.days)
            elif diff.seconds >= 3600:
                hours = diff.seconds // 3600
                return relative_strings['hours_ago'].format(hours=hours)
            elif diff.seconds >= 60:
                minutes = diff.seconds // 60
                return relative_strings['minutes_ago'].format(minutes=minutes)
            else:
                return relative_strings['seconds_ago'].format(seconds=diff.seconds)
                
        except Exception as e:
            logger.warning(f"Relative time formatting failed: {e}")
            return str(dt)
    
    def _get_relative_time_strings(self) -> Dict[str, str]:
        """Get relative time strings for current language"""
        strings_by_language = {
            'en': {
                'seconds_ago': '{seconds} seconds ago',
                'minutes_ago': '{minutes} minutes ago',
                'hours_ago': '{hours} hours ago',
                'days_ago': '{days} days ago'
            },
            'ja': {
                'seconds_ago': '{seconds}秒前',
                'minutes_ago': '{minutes}分前',
                'hours_ago': '{hours}時間前',
                'days_ago': '{days}日前'
            },
            'es': {
                'seconds_ago': 'hace {seconds} segundos',
                'minutes_ago': 'hace {minutes} minutos',
                'hours_ago': 'hace {hours} horas',
                'days_ago': 'hace {days} días'
            }
        }
        
        return strings_by_language.get(self.language_code, strings_by_language['en'])


# Global formatter instance
_formatter = None
_formatter_lock = None

def get_formatter(language_code: str = 'en') -> LocaleFormatter:
    """Get locale formatter for language"""
    global _formatter, _formatter_lock
    
    if _formatter_lock is None:
        import threading
        _formatter_lock = threading.Lock()
    
    with _formatter_lock:
        if _formatter is None or _formatter.language_code != language_code:
            _formatter = LocaleFormatter(language_code)
    
    return _formatter


# Convenience functions
def format_currency(amount: Union[int, float, Decimal], 
                   currency_code: str = 'BTC',
                   language_code: str = 'en') -> str:
    """Format currency with locale awareness"""
    return get_formatter(language_code).format_currency(amount, currency_code)


def format_number(number: Union[int, float, Decimal], 
                 decimals: Optional[int] = None,
                 language_code: str = 'en') -> str:
    """Format number with locale awareness"""
    return get_formatter(language_code).format_number(number, decimals)


def format_datetime(dt: Union[datetime, date], 
                   format_type: str = 'medium',
                   language_code: str = 'en') -> str:
    """Format datetime with locale awareness"""
    return get_formatter(language_code).format_datetime(dt, format_type)


if __name__ == "__main__":
    # Test locale utilities
    import time
    from decimal import Decimal
    
    print("Locale Utilities Test")
    print("=" * 30)
    
    # Test system locale detection
    system_locale = get_system_locale()
    print(f"Detected system locale: {system_locale}")
    
    # Test formatters for different languages
    test_languages = ['en', 'ja', 'es']
    test_amount = Decimal('0.12345678')
    test_number = 1234567.89
    test_datetime = datetime.now()
    
    for lang in test_languages:
        print(f"\n{lang.upper()} Formatting:")
        formatter = LocaleFormatter(lang)
        
        print(f"  BTC: {formatter.format_currency(test_amount, 'BTC')}")
        print(f"  Sats: {formatter.format_currency(test_amount * 100000000, 'sats')}")
        print(f"  Number: {formatter.format_number(test_number)}")
        print(f"  DateTime: {formatter.format_datetime(test_datetime)}")
        print(f"  Relative: {formatter.format_relative_time(test_datetime - timedelta(hours=2))}")
    
    print("\nLocale utilities test completed")