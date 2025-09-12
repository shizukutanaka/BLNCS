#!/usr/bin/env python3
"""
BLNCS Translation System
Core translation functionality with dynamic language switching.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Union
from threading import Lock
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class TranslationData:
    """Container for translation data with metadata"""
    language_code: str
    language_name: str
    translations: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get(self, key: str, default: str = None) -> str:
        """Get translation with fallback"""
        return self.translations.get(key, default or key)


class Translator:
    """Multi-language translation system with fallback support"""
    
    def __init__(self, translations_dir: Optional[str] = None):
        self.translations_dir = Path(translations_dir or self._get_default_translations_dir())
        self.current_language = 'en'  # Default to English
        self.fallback_language = 'en'
        self.translations: Dict[str, TranslationData] = {}
        self.lock = Lock()
        
        # Load available translations
        self.load_all_translations()
    
    def _get_default_translations_dir(self) -> str:
        """Get default translations directory"""
        return str(Path(__file__).parent / 'translations')
    
    def load_all_translations(self):
        """Load all available translation files"""
        logger.info(f"Loading translations from {self.translations_dir}")
        
        if not self.translations_dir.exists():
            logger.warning(f"Translations directory not found: {self.translations_dir}")
            self._create_default_translations()
            return
        
        # Load translation files
        for translation_file in self.translations_dir.glob("*.json"):
            language_code = translation_file.stem
            try:
                self.load_translation(language_code)
            except Exception as e:
                logger.error(f"Failed to load translation {language_code}: {e}")
        
        # Ensure English is available as fallback
        if 'en' not in self.translations:
            self._create_english_fallback()
        
        logger.info(f"Loaded translations for languages: {list(self.translations.keys())}")
    
    def load_translation(self, language_code: str):
        """Load translation file for specific language"""
        translation_file = self.translations_dir / f"{language_code}.json"
        
        if not translation_file.exists():
            logger.warning(f"Translation file not found: {translation_file}")
            return
        
        try:
            with open(translation_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Extract metadata and translations
            metadata = data.get('_metadata', {})
            translations = {k: v for k, v in data.items() if not k.startswith('_')}
            
            # Create translation data
            language_name = metadata.get('language_name', language_code)
            translation_data = TranslationData(
                language_code=language_code,
                language_name=language_name,
                translations=translations,
                metadata=metadata
            )
            
            with self.lock:
                self.translations[language_code] = translation_data
            
            logger.info(f"Loaded {len(translations)} translations for {language_name}")
            
        except Exception as e:
            logger.error(f"Failed to load translation file {translation_file}: {e}")
    
    def _create_default_translations(self):
        """Create default translation files"""
        logger.info("Creating default translation files")
        
        # Create translations directory
        self.translations_dir.mkdir(parents=True, exist_ok=True)
        
        # Create English (default)
        self._create_english_fallback()
        
        # Create Japanese
        self._create_japanese_translation()
        
        # Create Spanish
        self._create_spanish_translation()
    
    def _create_english_fallback(self):
        """Create English fallback translation"""
        english_translations = {
            "_metadata": {
                "language_name": "English",
                "language_code": "en",
                "version": "1.0.0",
                "contributors": ["BLNCS Team"]
            },
            
            # Application
            "app.title": "Bitcoin Lightning Network Control System",
            "app.version": "Version {version}",
            "app.loading": "Loading...",
            "app.error": "Error",
            "app.success": "Success",
            "app.warning": "Warning",
            "app.info": "Information",
            
            # Common actions
            "action.start": "Start",
            "action.stop": "Stop",
            "action.connect": "Connect",
            "action.disconnect": "Disconnect",
            "action.save": "Save",
            "action.cancel": "Cancel",
            "action.close": "Close",
            "action.refresh": "Refresh",
            "action.export": "Export",
            "action.import": "Import",
            "action.delete": "Delete",
            "action.edit": "Edit",
            "action.view": "View",
            "action.copy": "Copy",
            "action.paste": "Paste",
            
            # Lightning Network
            "lightning.node_id": "Node ID",
            "lightning.channels": "Channels",
            "lightning.balance": "Balance",
            "lightning.capacity": "Capacity",
            "lightning.status": "Status",
            "lightning.online": "Online",
            "lightning.offline": "Offline",
            "lightning.connecting": "Connecting",
            "lightning.active": "Active",
            "lightning.inactive": "Inactive",
            "lightning.pending": "Pending",
            
            # Wallet
            "wallet.balance": "Balance",
            "wallet.address": "Address",
            "wallet.transaction": "Transaction",
            "wallet.send": "Send",
            "wallet.receive": "Receive",
            "wallet.history": "History",
            "wallet.amount": "Amount",
            "wallet.fee": "Fee",
            "wallet.confirm": "Confirm",
            
            # Settings
            "settings.title": "Settings",
            "settings.language": "Language",
            "settings.theme": "Theme",
            "settings.node": "Node Settings",
            "settings.network": "Network",
            "settings.advanced": "Advanced",
            "settings.backup": "Backup",
            "settings.security": "Security",
            
            # Monitoring
            "monitoring.title": "Monitoring",
            "monitoring.metrics": "Metrics",
            "monitoring.alerts": "Alerts",
            "monitoring.health": "Health",
            "monitoring.performance": "Performance",
            "monitoring.cpu": "CPU Usage",
            "monitoring.memory": "Memory Usage",
            "monitoring.disk": "Disk Usage",
            "monitoring.network": "Network",
            
            # Errors
            "error.connection_failed": "Connection failed",
            "error.invalid_input": "Invalid input",
            "error.file_not_found": "File not found",
            "error.permission_denied": "Permission denied",
            "error.network_error": "Network error",
            "error.timeout": "Connection timeout",
            "error.unknown": "Unknown error",
            
            # Success messages
            "success.connected": "Successfully connected",
            "success.saved": "Successfully saved",
            "success.updated": "Successfully updated",
            "success.deleted": "Successfully deleted",
            "success.backup_created": "Backup created successfully",
            
            # Time and dates
            "time.now": "Now",
            "time.today": "Today",
            "time.yesterday": "Yesterday",
            "time.seconds_ago": "{seconds} seconds ago",
            "time.minutes_ago": "{minutes} minutes ago",
            "time.hours_ago": "{hours} hours ago",
            "time.days_ago": "{days} days ago",
            
            # Units
            "unit.sats": "sats",
            "unit.btc": "BTC",
            "unit.bytes": "bytes",
            "unit.kb": "KB",
            "unit.mb": "MB",
            "unit.gb": "GB",
            "unit.percent": "%",
            
            # Navigation
            "nav.dashboard": "Dashboard",
            "nav.wallet": "Wallet",
            "nav.channels": "Channels",
            "nav.transactions": "Transactions",
            "nav.monitoring": "Monitoring",
            "nav.settings": "Settings",
            "nav.help": "Help"
        }
        
        # Save English translation
        english_file = self.translations_dir / "en.json"
        with open(english_file, 'w', encoding='utf-8') as f:
            json.dump(english_translations, f, indent=2, ensure_ascii=False)
        
        # Load into memory
        self.translations['en'] = TranslationData(
            language_code='en',
            language_name='English',
            translations={k: v for k, v in english_translations.items() if not k.startswith('_')},
            metadata=english_translations['_metadata']
        )
        
        logger.info("Created English translation with {} entries".format(
            len(english_translations) - 1))  # -1 for metadata
    
    def _create_japanese_translation(self):
        """Create Japanese translation"""
        japanese_translations = {
            "_metadata": {
                "language_name": "日本語",
                "language_code": "ja", 
                "version": "1.0.0",
                "contributors": ["BLNCS Team"]
            },
            
            # Application
            "app.title": "ビットコインライトニングネットワーク制御システム",
            "app.version": "バージョン {version}",
            "app.loading": "読み込み中...",
            "app.error": "エラー",
            "app.success": "成功",
            "app.warning": "警告",
            "app.info": "情報",
            
            # Common actions
            "action.start": "開始",
            "action.stop": "停止",
            "action.connect": "接続",
            "action.disconnect": "切断",
            "action.save": "保存",
            "action.cancel": "キャンセル",
            "action.close": "閉じる",
            "action.refresh": "更新",
            "action.export": "エクスポート",
            "action.import": "インポート",
            "action.delete": "削除",
            "action.edit": "編集",
            "action.view": "表示",
            "action.copy": "コピー",
            "action.paste": "貼り付け",
            
            # Lightning Network
            "lightning.node_id": "ノードID",
            "lightning.channels": "チャンネル",
            "lightning.balance": "残高",
            "lightning.capacity": "容量",
            "lightning.status": "ステータス",
            "lightning.online": "オンライン",
            "lightning.offline": "オフライン",
            "lightning.connecting": "接続中",
            "lightning.active": "アクティブ",
            "lightning.inactive": "非アクティブ",
            "lightning.pending": "保留中",
            
            # Wallet
            "wallet.balance": "残高",
            "wallet.address": "アドレス",
            "wallet.transaction": "取引",
            "wallet.send": "送金",
            "wallet.receive": "受金",
            "wallet.history": "履歴",
            "wallet.amount": "金額",
            "wallet.fee": "手数料",
            "wallet.confirm": "確認",
            
            # Settings
            "settings.title": "設定",
            "settings.language": "言語",
            "settings.theme": "テーマ",
            "settings.node": "ノード設定",
            "settings.network": "ネットワーク",
            "settings.advanced": "詳細設定",
            "settings.backup": "バックアップ",
            "settings.security": "セキュリティ",
            
            # Monitoring
            "monitoring.title": "監視",
            "monitoring.metrics": "メトリクス",
            "monitoring.alerts": "アラート",
            "monitoring.health": "ヘルス",
            "monitoring.performance": "パフォーマンス",
            "monitoring.cpu": "CPU使用率",
            "monitoring.memory": "メモリ使用率",
            "monitoring.disk": "ディスク使用率",
            "monitoring.network": "ネットワーク",
            
            # Errors
            "error.connection_failed": "接続に失敗しました",
            "error.invalid_input": "無効な入力です",
            "error.file_not_found": "ファイルが見つかりません",
            "error.permission_denied": "アクセスが拒否されました",
            "error.network_error": "ネットワークエラー",
            "error.timeout": "接続タイムアウト",
            "error.unknown": "不明なエラー",
            
            # Success messages
            "success.connected": "正常に接続しました",
            "success.saved": "正常に保存しました",
            "success.updated": "正常に更新しました",
            "success.deleted": "正常に削除しました",
            "success.backup_created": "バックアップが正常に作成されました",
            
            # Time and dates
            "time.now": "今",
            "time.today": "今日",
            "time.yesterday": "昨日",
            "time.seconds_ago": "{seconds}秒前",
            "time.minutes_ago": "{minutes}分前",
            "time.hours_ago": "{hours}時間前",
            "time.days_ago": "{days}日前",
            
            # Units
            "unit.sats": "sats",
            "unit.btc": "BTC",
            "unit.bytes": "バイト",
            "unit.kb": "KB",
            "unit.mb": "MB",
            "unit.gb": "GB",
            "unit.percent": "%",
            
            # Navigation
            "nav.dashboard": "ダッシュボード",
            "nav.wallet": "ウォレット", 
            "nav.channels": "チャンネル",
            "nav.transactions": "取引",
            "nav.monitoring": "監視",
            "nav.settings": "設定",
            "nav.help": "ヘルプ"
        }
        
        # Save Japanese translation
        japanese_file = self.translations_dir / "ja.json"
        with open(japanese_file, 'w', encoding='utf-8') as f:
            json.dump(japanese_translations, f, indent=2, ensure_ascii=False)
        
        # Load into memory
        self.translations['ja'] = TranslationData(
            language_code='ja',
            language_name='日本語',
            translations={k: v for k, v in japanese_translations.items() if not k.startswith('_')},
            metadata=japanese_translations['_metadata']
        )
        
        logger.info("Created Japanese translation with {} entries".format(
            len(japanese_translations) - 1))
    
    def _create_spanish_translation(self):
        """Create Spanish translation"""
        spanish_translations = {
            "_metadata": {
                "language_name": "Español",
                "language_code": "es",
                "version": "1.0.0", 
                "contributors": ["BLNCS Team"]
            },
            
            # Application
            "app.title": "Sistema de Control de Red Lightning de Bitcoin",
            "app.version": "Versión {version}",
            "app.loading": "Cargando...",
            "app.error": "Error",
            "app.success": "Éxito",
            "app.warning": "Advertencia",
            "app.info": "Información",
            
            # Common actions
            "action.start": "Iniciar",
            "action.stop": "Detener",
            "action.connect": "Conectar",
            "action.disconnect": "Desconectar",
            "action.save": "Guardar",
            "action.cancel": "Cancelar",
            "action.close": "Cerrar",
            "action.refresh": "Actualizar",
            "action.export": "Exportar",
            "action.import": "Importar",
            "action.delete": "Eliminar",
            "action.edit": "Editar",
            "action.view": "Ver",
            "action.copy": "Copiar",
            "action.paste": "Pegar",
            
            # Lightning Network
            "lightning.node_id": "ID del Nodo",
            "lightning.channels": "Canales",
            "lightning.balance": "Balance",
            "lightning.capacity": "Capacidad",
            "lightning.status": "Estado",
            "lightning.online": "En línea",
            "lightning.offline": "Fuera de línea",
            "lightning.connecting": "Conectando",
            "lightning.active": "Activo",
            "lightning.inactive": "Inactivo",
            "lightning.pending": "Pendiente",
            
            # Wallet
            "wallet.balance": "Balance",
            "wallet.address": "Dirección",
            "wallet.transaction": "Transacción",
            "wallet.send": "Enviar",
            "wallet.receive": "Recibir",
            "wallet.history": "Historial",
            "wallet.amount": "Cantidad",
            "wallet.fee": "Comisión",
            "wallet.confirm": "Confirmar",
            
            # Settings
            "settings.title": "Configuración",
            "settings.language": "Idioma",
            "settings.theme": "Tema",
            "settings.node": "Configuración del Nodo",
            "settings.network": "Red",
            "settings.advanced": "Avanzado",
            "settings.backup": "Respaldo",
            "settings.security": "Seguridad",
            
            # Monitoring
            "monitoring.title": "Monitoreo",
            "monitoring.metrics": "Métricas",
            "monitoring.alerts": "Alertas",
            "monitoring.health": "Salud",
            "monitoring.performance": "Rendimiento",
            "monitoring.cpu": "Uso de CPU",
            "monitoring.memory": "Uso de Memoria",
            "monitoring.disk": "Uso de Disco",
            "monitoring.network": "Red",
            
            # Errors
            "error.connection_failed": "Fallo en la conexión",
            "error.invalid_input": "Entrada inválida",
            "error.file_not_found": "Archivo no encontrado",
            "error.permission_denied": "Permiso denegado",
            "error.network_error": "Error de red",
            "error.timeout": "Tiempo de espera agotado",
            "error.unknown": "Error desconocido",
            
            # Success messages
            "success.connected": "Conectado exitosamente",
            "success.saved": "Guardado exitosamente",
            "success.updated": "Actualizado exitosamente",
            "success.deleted": "Eliminado exitosamente",
            "success.backup_created": "Respaldo creado exitosamente",
            
            # Time and dates
            "time.now": "Ahora",
            "time.today": "Hoy",
            "time.yesterday": "Ayer",
            "time.seconds_ago": "hace {seconds} segundos",
            "time.minutes_ago": "hace {minutes} minutos",
            "time.hours_ago": "hace {hours} horas",
            "time.days_ago": "hace {days} días",
            
            # Units
            "unit.sats": "sats",
            "unit.btc": "BTC",
            "unit.bytes": "bytes",
            "unit.kb": "KB",
            "unit.mb": "MB", 
            "unit.gb": "GB",
            "unit.percent": "%",
            
            # Navigation
            "nav.dashboard": "Panel de Control",
            "nav.wallet": "Billetera",
            "nav.channels": "Canales",
            "nav.transactions": "Transacciones",
            "nav.monitoring": "Monitoreo",
            "nav.settings": "Configuración",
            "nav.help": "Ayuda"
        }
        
        # Save Spanish translation
        spanish_file = self.translations_dir / "es.json"
        with open(spanish_file, 'w', encoding='utf-8') as f:
            json.dump(spanish_translations, f, indent=2, ensure_ascii=False)
        
        # Load into memory
        self.translations['es'] = TranslationData(
            language_code='es',
            language_name='Español', 
            translations={k: v for k, v in spanish_translations.items() if not k.startswith('_')},
            metadata=spanish_translations['_metadata']
        )
        
        logger.info("Created Spanish translation with {} entries".format(
            len(spanish_translations) - 1))
    
    def set_language(self, language_code: str) -> bool:
        """Set current language"""
        if language_code not in self.translations:
            logger.warning(f"Language {language_code} not available")
            return False
        
        with self.lock:
            old_language = self.current_language
            self.current_language = language_code
        
        logger.info(f"Language changed from {old_language} to {language_code}")
        return True
    
    def get_current_language(self) -> str:
        """Get current language code"""
        return self.current_language
    
    def get_available_languages(self) -> Dict[str, str]:
        """Get available languages as code -> name mapping"""
        return {
            code: data.language_name 
            for code, data in self.translations.items()
        }
    
    def translate(self, key: str, **kwargs) -> str:
        """Translate a key with optional formatting parameters"""
        # Get translation from current language
        translation = self._get_translation(key, self.current_language)
        
        # Fallback to English if not found
        if translation == key and self.current_language != self.fallback_language:
            translation = self._get_translation(key, self.fallback_language)
        
        # Format with parameters if provided
        if kwargs:
            try:
                translation = translation.format(**kwargs)
            except (KeyError, ValueError) as e:
                logger.warning(f"Failed to format translation '{key}': {e}")
        
        return translation
    
    def _get_translation(self, key: str, language_code: str) -> str:
        """Get translation for specific language"""
        translation_data = self.translations.get(language_code)
        if not translation_data:
            return key
        
        return translation_data.get(key, key)
    
    def bulk_translate(self, keys: list, **kwargs) -> Dict[str, str]:
        """Translate multiple keys at once"""
        return {key: self.translate(key, **kwargs) for key in keys}
    
    def add_translation(self, language_code: str, key: str, value: str):
        """Add or update a translation dynamically"""
        if language_code not in self.translations:
            logger.warning(f"Language {language_code} not loaded")
            return
        
        with self.lock:
            self.translations[language_code].translations[key] = value
        
        logger.debug(f"Added translation {language_code}:{key} = {value}")
    
    def save_translations(self, language_code: str):
        """Save translations to file"""
        if language_code not in self.translations:
            logger.error(f"Language {language_code} not loaded")
            return
        
        translation_data = self.translations[language_code]
        
        # Prepare data for saving
        save_data = {
            '_metadata': translation_data.metadata,
            **translation_data.translations
        }
        
        # Save to file
        translation_file = self.translations_dir / f"{language_code}.json"
        try:
            with open(translation_file, 'w', encoding='utf-8') as f:
                json.dump(save_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Saved {language_code} translations to {translation_file}")
            
        except Exception as e:
            logger.error(f"Failed to save translations for {language_code}: {e}")


# Global translator instance
_translator = None
_translator_lock = Lock()


def get_translator() -> Translator:
    """Get global translator instance"""
    global _translator
    
    if _translator is None:
        with _translator_lock:
            if _translator is None:
                _translator = Translator()
    
    return _translator


def set_language(language_code: str) -> bool:
    """Set global language"""
    return get_translator().set_language(language_code)


def get_current_language() -> str:
    """Get current global language"""
    return get_translator().get_current_language()


# Convenience functions
def _(key: str, **kwargs) -> str:
    """Shorthand translation function"""
    return get_translator().translate(key, **kwargs)


def tr(key: str, **kwargs) -> str:
    """Alternative translation function"""
    return get_translator().translate(key, **kwargs)


if __name__ == "__main__":
    # Test translator
    import tempfile
    
    with tempfile.TemporaryDirectory() as temp_dir:
        translator = Translator(temp_dir)
        
        print("Available languages:")
        for code, name in translator.get_available_languages().items():
            print(f"  {code}: {name}")
        
        # Test translations
        test_keys = ["app.title", "action.start", "lightning.balance"]
        
        for lang in ['en', 'ja', 'es']:
            translator.set_language(lang)
            print(f"\n{translator.translations[lang].language_name}:")
            for key in test_keys:
                print(f"  {key}: {translator.translate(key)}")
        
        # Test formatting
        translator.set_language('en')
        formatted = translator.translate('time.minutes_ago', minutes=5)
        print(f"\nFormatted: {formatted}")
        
        print("\nTranslation system test completed")