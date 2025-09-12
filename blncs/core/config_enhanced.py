"""
Enhanced Configuration Management System for BLNCS
Provides secure, validated, and hierarchical configuration management.
"""

import os
import json
import yaml
import toml
import logging
from typing import Dict, Any, Optional, Union, List, Callable
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    import pydantic
    from pydantic import BaseModel, validator, Field
    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False
    BaseModel = object


@dataclass 
class ConfigSource:
    """Configuration source metadata"""
    path: str
    format: str  # json, yaml, toml, env
    priority: int = 0
    encrypted: bool = False
    last_modified: Optional[datetime] = None
    checksum: Optional[str] = None


class ConfigValidator:
    """Configuration validation using schema"""
    
    def __init__(self):
        self.schemas: Dict[str, Any] = {}
        self.validators: Dict[str, Callable] = {}
    
    def register_schema(self, key: str, schema: Dict[str, Any]):
        """Register validation schema for config key"""
        self.schemas[key] = schema
    
    def register_validator(self, key: str, validator_func: Callable):
        """Register custom validator function"""
        self.validators[key] = validator_func
    
    def validate(self, key: str, value: Any) -> bool:
        """Validate configuration value"""
        # Custom validator first
        if key in self.validators:
            try:
                return self.validators[key](value)
            except Exception:
                return False
        
        # Schema validation
        if key in self.schemas:
            return self._validate_schema(value, self.schemas[key])
        
        return True  # No validation rules = valid
    
    def _validate_schema(self, value: Any, schema: Dict[str, Any]) -> bool:
        """Basic schema validation"""
        if 'type' in schema:
            expected_type = schema['type']
            if expected_type == 'string' and not isinstance(value, str):
                return False
            elif expected_type == 'integer' and not isinstance(value, int):
                return False
            elif expected_type == 'boolean' and not isinstance(value, bool):
                return False
            elif expected_type == 'array' and not isinstance(value, list):
                return False
            elif expected_type == 'object' and not isinstance(value, dict):
                return False
        
        if 'min_length' in schema and isinstance(value, str):
            if len(value) < schema['min_length']:
                return False
        
        if 'max_length' in schema and isinstance(value, str):
            if len(value) > schema['max_length']:
                return False
        
        if 'enum' in schema:
            if value not in schema['enum']:
                return False
        
        return True


class ConfigEncryption:
    """Configuration encryption/decryption"""
    
    def __init__(self, password: str):
        self.password = password.encode()
        self._key = None
    
    def _get_key(self) -> bytes:
        """Derive encryption key from password"""
        if self._key is None:
            salt = b'blncs_config_salt_2024'  # Use consistent salt
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            self._key = base64.urlsafe_b64encode(kdf.derive(self.password))
        return self._key
    
    def encrypt(self, data: str) -> str:
        """Encrypt configuration data"""
        try:
            f = Fernet(self._get_key())
            encrypted_data = f.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted_data).decode()
        except Exception as e:
            raise ValueError(f"Encryption failed: {e}")
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt configuration data"""
        try:
            f = Fernet(self._get_key())
            decoded_data = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted_data = f.decrypt(decoded_data)
            return decrypted_data.decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")


class EnhancedConfigManager:
    """Enhanced configuration manager with multiple sources and validation"""
    
    def __init__(self, app_name: str = "BLNCS"):
        self.app_name = app_name
        self.config_data: Dict[str, Any] = {}
        self.sources: List[ConfigSource] = []
        self.validator = ConfigValidator()
        self.encryptor: Optional[ConfigEncryption] = None
        self.watchers: Dict[str, List[Callable]] = {}
        self.logger = logging.getLogger(__name__)
        
        # Setup default paths
        self.user_config_dir = Path.home() / f".{app_name.lower()}"
        self.system_config_dir = Path(f"/etc/{app_name.lower()}")
        
        # Ensure user config directory exists
        self.user_config_dir.mkdir(exist_ok=True)
        
        # Load default configuration
        self._load_defaults()
    
    def _load_defaults(self):
        """Load default configuration"""
        defaults = {
            'app': {
                'name': self.app_name,
                'version': '1.0.0',
                'debug': False,
                'log_level': 'INFO'
            },
            'lightning': {
                'host': 'localhost',
                'port': 8080,
                'network': 'mainnet',  # mainnet, testnet, regtest
                'auto_connect': True,
                'connection_timeout': 30,
                'max_retries': 3
            },
            'database': {
                'path': 'blncs.db',
                'pool_size': 10,
                'cache_size': 20000,
                'backup_enabled': True,
                'backup_interval': 3600  # 1 hour
            },
            'security': {
                'encrypt_config': False,
                'encrypt_database': True,
                'session_timeout': 1800,  # 30 minutes
                'max_login_attempts': 3
            },
            'ui': {
                'theme': 'light',
                'language': 'en',
                'auto_refresh': 5,  # seconds
                'show_notifications': True,
                'minimize_to_tray': True
            }
        }
        
        self.config_data = defaults
        
        # Register validation schemas
        self._register_validation_schemas()
    
    def _register_validation_schemas(self):
        """Register validation schemas for configuration"""
        schemas = {
            'lightning.network': {
                'type': 'string',
                'enum': ['mainnet', 'testnet', 'regtest']
            },
            'lightning.port': {
                'type': 'integer',
                'minimum': 1,
                'maximum': 65535
            },
            'database.pool_size': {
                'type': 'integer',
                'minimum': 1,
                'maximum': 100
            },
            'ui.theme': {
                'type': 'string',
                'enum': ['light', 'dark', 'auto']
            },
            'ui.language': {
                'type': 'string',
                'enum': ['en', 'ja', 'es', 'fr', 'de']
            },
            'app.log_level': {
                'type': 'string',
                'enum': ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
            }
        }
        
        for key, schema in schemas.items():
            self.validator.register_schema(key, schema)
    
    def enable_encryption(self, password: str):
        """Enable configuration encryption"""
        self.encryptor = ConfigEncryption(password)
    
    def add_config_source(self, path: str, priority: int = 0, encrypted: bool = False):
        """Add configuration source"""
        path_obj = Path(path)
        if not path_obj.exists():
            return False
        
        # Determine format from extension
        suffix = path_obj.suffix.lower()
        format_map = {
            '.json': 'json',
            '.yaml': 'yaml',
            '.yml': 'yaml', 
            '.toml': 'toml'
        }
        
        file_format = format_map.get(suffix, 'json')
        
        source = ConfigSource(
            path=str(path_obj),
            format=file_format,
            priority=priority,
            encrypted=encrypted,
            last_modified=datetime.fromtimestamp(path_obj.stat().st_mtime),
            checksum=self._calculate_file_checksum(str(path_obj))
        )
        
        self.sources.append(source)
        self.sources.sort(key=lambda x: x.priority, reverse=True)
        
        return True
    
    def _calculate_file_checksum(self, file_path: str) -> str:
        """Calculate file checksum"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                return hashlib.sha256(content).hexdigest()
        except Exception:
            return ""
    
    def load_config(self):
        """Load configuration from all sources"""
        # Start with defaults
        config = self.config_data.copy()
        
        # Load from sources in priority order
        for source in self.sources:
            try:
                source_config = self._load_source(source)
                config = self._merge_config(config, source_config)
            except Exception as e:
                self.logger.error(f"Failed to load config from {source.path}: {e}")
        
        # Validate loaded configuration
        validated_config = {}
        for key, value in self._flatten_config(config).items():
            if self.validator.validate(key, value):
                validated_config[key] = value
            else:
                self.logger.warning(f"Invalid configuration value for {key}: {value}")
        
        # Restore nested structure
        self.config_data = self._unflatten_config(validated_config) if validated_config else config
    
    def _load_source(self, source: ConfigSource) -> Dict[str, Any]:
        """Load configuration from a single source"""
        with open(source.path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Decrypt if necessary
        if source.encrypted and self.encryptor:
            content = self.encryptor.decrypt(content)
        
        # Parse based on format
        if source.format == 'json':
            return json.loads(content)
        elif source.format == 'yaml':
            return yaml.safe_load(content)
        elif source.format == 'toml':
            return toml.loads(content)
        else:
            raise ValueError(f"Unsupported format: {source.format}")
    
    def _merge_config(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Merge configuration dictionaries"""
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_config(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _flatten_config(self, config: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
        """Flatten nested configuration for validation"""
        result = {}
        
        for key, value in config.items():
            new_key = f"{prefix}.{key}" if prefix else key
            
            if isinstance(value, dict):
                result.update(self._flatten_config(value, new_key))
            else:
                result[new_key] = value
        
        return result
    
    def _unflatten_config(self, flat_config: Dict[str, Any]) -> Dict[str, Any]:
        """Restore nested configuration structure"""
        result = {}
        
        for key, value in flat_config.items():
            parts = key.split('.')
            current = result
            
            for part in parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]
            
            current[parts[-1]] = value
        
        return result
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        keys = key.split('.')
        current = self.config_data
        
        try:
            for k in keys:
                current = current[k]
            return current
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any, persist: bool = False) -> bool:
        """Set configuration value"""
        # Validate value
        if not self.validator.validate(key, value):
            self.logger.error(f"Invalid value for {key}: {value}")
            return False
        
        # Set value
        keys = key.split('.')
        current = self.config_data
        
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        
        old_value = current.get(keys[-1])
        current[keys[-1]] = value
        
        # Notify watchers
        self._notify_watchers(key, old_value, value)
        
        # Persist if requested
        if persist:
            self.save_config()
        
        return True
    
    def watch(self, key: str, callback: Callable[[str, Any, Any], None]):
        """Watch for configuration changes"""
        if key not in self.watchers:
            self.watchers[key] = []
        self.watchers[key].append(callback)
    
    def _notify_watchers(self, key: str, old_value: Any, new_value: Any):
        """Notify configuration watchers"""
        if key in self.watchers:
            for callback in self.watchers[key]:
                try:
                    callback(key, old_value, new_value)
                except Exception as e:
                    self.logger.error(f"Watcher callback failed for {key}: {e}")
    
    def save_config(self, path: Optional[str] = None):
        """Save configuration to file"""
        if path is None:
            path = self.user_config_dir / "config.json"
        else:
            path = Path(path)
        
        # Prepare content
        content = json.dumps(self.config_data, indent=2, ensure_ascii=False)
        
        # Encrypt if necessary
        if self.encryptor and path.name.endswith('.enc'):
            content = self.encryptor.encrypt(content)
        
        # Write to file
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        self.logger.info(f"Configuration saved to {path}")
    
    def reload(self):
        """Reload configuration from sources"""
        self.load_config()
        self.logger.info("Configuration reloaded")
    
    def get_config_info(self) -> Dict[str, Any]:
        """Get configuration metadata"""
        return {
            'sources': [
                {
                    'path': s.path,
                    'format': s.format,
                    'priority': s.priority,
                    'encrypted': s.encrypted,
                    'last_modified': s.last_modified.isoformat() if s.last_modified else None
                }
                for s in self.sources
            ],
            'total_keys': len(self._flatten_config(self.config_data)),
            'validation_rules': len(self.validator.schemas),
            'watchers': {k: len(v) for k, v in self.watchers.items()}
        }


# Global instance
_config_manager: Optional[EnhancedConfigManager] = None


def get_config_manager() -> EnhancedConfigManager:
    """Get or create global configuration manager"""
    global _config_manager
    if _config_manager is None:
        _config_manager = EnhancedConfigManager()
    return _config_manager


def init_config(app_name: str = "BLNCS", config_files: Optional[List[str]] = None):
    """Initialize configuration system"""
    global _config_manager
    _config_manager = EnhancedConfigManager(app_name)
    
    # Add default config sources
    default_sources = [
        (_config_manager.system_config_dir / "config.json", 100),  # System config (highest priority)
        (_config_manager.user_config_dir / "config.json", 50),     # User config
        (_config_manager.user_config_dir / "config.local.json", 25)  # Local overrides
    ]
    
    for config_path, priority in default_sources:
        if config_path.exists():
            _config_manager.add_config_source(str(config_path), priority)
    
    # Add custom config files
    if config_files:
        for config_file in config_files:
            _config_manager.add_config_source(config_file)
    
    # Load configuration
    _config_manager.load_config()
    
    return _config_manager


# Convenience functions
def get(key: str, default: Any = None) -> Any:
    """Get configuration value"""
    return get_config_manager().get(key, default)


def set(key: str, value: Any, persist: bool = False) -> bool:
    """Set configuration value"""
    return get_config_manager().set(key, value, persist)


def watch(key: str, callback: Callable[[str, Any, Any], None]):
    """Watch for configuration changes"""
    get_config_manager().watch(key, callback)