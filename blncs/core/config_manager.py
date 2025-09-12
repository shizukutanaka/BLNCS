"""
Unified configuration management system for BLNCS
Practical configuration system with validation, environment overrides, and optional hot-reload.
Consolidated from multiple config management approaches.
"""

import os
import yaml
import json
import time
import threading
import shutil
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, Callable
from dataclasses import dataclass
from functools import lru_cache
from enum import Enum

# Optional dependencies for advanced features
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

try:
    import tomli
    import tomli_w
    TOML_AVAILABLE = True
except ImportError:
    TOML_AVAILABLE = False

from .logger import get_logger
from .exceptions import ConfigError, ValidationError


class ConfigFormat(Enum):
    """Supported configuration formats"""
    JSON = "json"
    YAML = "yaml"
    TOML = "toml"


@dataclass
class ConfigSchema:
    """Configuration schema definition"""
    name: str
    type: type
    required: bool = False
    default: Any = None
    min_value: Optional[Union[int, float]] = None
    max_value: Optional[Union[int, float]] = None
    allowed_values: Optional[List[Any]] = None
    env_var: Optional[str] = None
    description: str = ""
    validator: Optional[Callable] = None


if WATCHDOG_AVAILABLE:
    class ConfigChangeHandler(FileSystemEventHandler):
        """File system event handler for configuration hot-reload"""
        
        def __init__(self, config_manager):
            self.config_manager = config_manager
            
        def on_modified(self, event):
            if not event.is_directory and event.src_path == str(self.config_manager.config_path):
                self.config_manager.logger.info(f"Configuration file changed: {event.src_path}")
                self.config_manager._reload_from_file()
else:
    class ConfigChangeHandler:
        """Dummy handler when watchdog is not available"""
        def __init__(self, config_manager):
            pass


class ConfigManager:
    """Unified configuration management with validation, environment support, and optional hot-reload"""
    
    # Configuration schema definitions
    SCHEMA = {
        'system.environment': ConfigSchema(
            name='environment', 
            type=str, 
            required=True,
            allowed_values=['development', 'production', 'testing'],
            env_var='BLNCS_ENV',
            description='Application environment'
        ),
        'system.data_dir': ConfigSchema(
            name='data_dir', 
            type=str, 
            required=True,
            default='./data',
            env_var='BLNCS_DATA_DIR',
            description='Data directory path'
        ),
        'lightning.host': ConfigSchema(
            name='host', 
            type=str, 
            required=True,
            default='localhost',
            env_var='BLNCS_LN_HOST',
            description='Lightning node host'
        ),
        'lightning.port': ConfigSchema(
            name='port', 
            type=int, 
            required=True,
            min_value=1,
            max_value=65535,
            default=10009,
            env_var='BLNCS_LN_PORT',
            description='Lightning node port'
        ),
        'lightning.network': ConfigSchema(
            name='network', 
            type=str, 
            required=True,
            allowed_values=['mainnet', 'testnet', 'regtest'],
            env_var='BLNCS_LN_NETWORK',
            description='Lightning network type'
        ),
        'performance.max_connections': ConfigSchema(
            name='max_connections', 
            type=int,
            min_value=1,
            max_value=100,
            default=10,
            env_var='BLNCS_MAX_CONNECTIONS',
            description='Maximum concurrent connections'
        ),
        'performance.cache_ttl': ConfigSchema(
            name='cache_ttl', 
            type=int,
            min_value=0,
            max_value=3600,
            default=300,
            env_var='BLNCS_CACHE_TTL',
            description='Cache time-to-live in seconds'
        ),
        'security.rate_limit': ConfigSchema(
            name='rate_limit', 
            type=int,
            min_value=1,
            max_value=10000,
            default=100,
            env_var='BLNCS_RATE_LIMIT',
            description='Rate limit per minute'
        ),
        'logging.level': ConfigSchema(
            name='level', 
            type=str,
            allowed_values=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
            default='INFO',
            env_var='BLNCS_LOG_LEVEL',
            description='Logging level'
        ),
    }
    
    def __init__(self, 
                 config_path: Optional[str] = None,
                 auto_reload: bool = False,
                 backup_count: int = 5,
                 enable_cache: bool = True):
        self.logger = get_logger(__name__)
        self._lock = threading.RLock()
        self.auto_reload = auto_reload and WATCHDOG_AVAILABLE
        self.backup_count = backup_count
        self.enable_cache = enable_cache
        
        # Configuration state
        self.config_path = Path(config_path or self._find_config_file())
        self.format = self._detect_format()
        self._config: Dict[str, Any] = {}
        self._env_overrides: Dict[str, Any] = {}
        self._runtime_overrides: Dict[str, Any] = {}
        self._observers: List[Callable] = []
        self._cache = {} if enable_cache else None
        
        # File watcher for hot-reload
        self._file_observer = None
        self._change_handler = None
        
        # Initialize
        self._create_default_config()
        self.reload()
        
        if self.auto_reload:
            self._setup_file_watcher()
    
    def _find_config_file(self) -> str:
        """Find configuration file in standard locations"""
        locations = [
            Path("config/config.yaml"),
            Path("config.yaml"),
            Path("config.json"),
            Path.home() / ".blncs" / "config.yaml",
            Path.home() / ".blncs" / "config.json",
            Path("/etc/blncs/config.yaml"),
        ]
        
        for location in locations:
            if location.exists():
                return str(location)
        
        return "config/config.yaml"
    
    def _detect_format(self) -> ConfigFormat:
        """Detect configuration format from file extension"""
        ext = self.config_path.suffix.lower()
        if ext in ['.yaml', '.yml']:
            return ConfigFormat.YAML
        elif ext == '.toml' and TOML_AVAILABLE:
            return ConfigFormat.TOML
        else:
            return ConfigFormat.JSON
    
    def _create_default_config(self):
        """Create default configuration file if it doesn't exist"""
        if not self.config_path.exists():
            self.logger.info(f"Creating default configuration: {self.config_path}")
            
            default_config = {
                "app": {
                    "name": "BLNCS",
                    "debug": False,
                    "log_level": "INFO",
                    "language": "en"
                },
                "lightning": {
                    "host": "localhost",
                    "port": 10009,
                    "tls_cert_path": "~/.lnd/tls.cert",
                    "macaroon_path": "~/.lnd/data/chain/bitcoin/mainnet/admin.macaroon",
                    "network": "mainnet"
                },
                "database": {
                    "url": "sqlite:///blncs.db",
                    "pool_size": 10
                },
                "gui": {
                    "theme": "default",
                    "window_size": "1200x800",
                    "auto_refresh": True,
                    "refresh_interval": 5000
                },
                "security": {
                    "encrypt_data": True,
                    "session_timeout": 3600,
                    "max_login_attempts": 3
                },
                "monitoring": {
                    "enable_metrics": True,
                    "metrics_port": 9090,
                    "alert_thresholds": {
                        "channel_balance": 0.1,
                        "fee_rate": 1000
                    }
                },
                "performance": {
                    "max_connections": 10,
                    "cache_ttl": 300
                }
            }
            
            self._save_to_file(default_config)
    
    def _setup_file_watcher(self):
        """Setup file system watcher for hot-reload"""
        if not WATCHDOG_AVAILABLE or self._file_observer:
            return
        
        try:
            self._change_handler = ConfigChangeHandler(self)
            self._file_observer = Observer()
            self._file_observer.schedule(
                self._change_handler, 
                str(self.config_path.parent), 
                recursive=False
            )
            self._file_observer.start()
            self.logger.info("Configuration hot-reload enabled")
        except Exception as e:
            self.logger.warning(f"Failed to setup file watcher: {e}")
    
    def _create_backup(self):
        """Create configuration backup"""
        if self.config_path.exists() and self.backup_count > 0:
            timestamp = int(time.time())
            backup_name = f"{self.config_path.stem}.{timestamp}{self.config_path.suffix}"
            backup_dir = self.config_path.parent / "backups"
            backup_path = backup_dir / backup_name
            
            # Create backups directory
            backup_dir.mkdir(exist_ok=True)
            
            # Copy current config to backup
            shutil.copy2(self.config_path, backup_path)
            
            # Clean old backups
            backups = sorted(backup_dir.glob(f"{self.config_path.stem}.*{self.config_path.suffix}"))
            if len(backups) > self.backup_count:
                for backup in backups[:-self.backup_count]:
                    backup.unlink()
                    self.logger.debug(f"Removed old backup: {backup}")
            
            self.logger.debug(f"Configuration backup created: {backup_path}")
    
    def reload(self) -> None:
        """Reload configuration from file and environment"""
        with self._lock:
            old_config = self._config.copy() if self._config else {}
            
            # Load base configuration
            self._config = self._load_file()
            
            # Apply environment variable overrides
            self._env_overrides = self._load_env_overrides()
            
            # Merge configurations
            self._apply_overrides()
            
            # Validate configuration
            self._validate_config()
            
            # Clear cache
            if self._cache:
                self._cache.clear()
            
            # Notify observers
            for observer in self._observers:
                try:
                    observer(old_config, self._config)
                except Exception as e:
                    self.logger.error(f"Configuration observer error: {e}")
            
            self.logger.info("Configuration reloaded successfully")
    
    def _reload_from_file(self):
        """Internal method for file watcher reload"""
        try:
            self.reload()
        except Exception as e:
            self.logger.error(f"Failed to reload configuration: {e}")
    
    def _load_file(self) -> Dict[str, Any]:
        """Load configuration from file (supports JSON, YAML, TOML)"""
        if not self.config_path.exists():
            self.logger.warning(f"Config file not found: {self.config_path}, using defaults")
            return self._get_defaults()
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                if self.format == ConfigFormat.YAML:
                    config = yaml.safe_load(f) or {}
                elif self.format == ConfigFormat.TOML and TOML_AVAILABLE:
                    config = tomli.load(f.buffer)
                else:
                    config = json.load(f)
            
            return config
        except Exception as e:
            raise ConfigError(f"Failed to load config file: {e}")
    
    def _load_env_overrides(self) -> Dict[str, Any]:
        """Load configuration overrides from environment variables"""
        overrides = {}
        
        for key_path, schema in self.SCHEMA.items():
            if schema.env_var:
                env_value = os.environ.get(schema.env_var)
                if env_value is not None:
                    # Convert to appropriate type
                    try:
                        if schema.type == int:
                            value = int(env_value)
                        elif schema.type == float:
                            value = float(env_value)
                        elif schema.type == bool:
                            value = env_value.lower() in ('true', '1', 'yes', 'on')
                        else:
                            value = env_value
                        
                        # Set nested dictionary value
                        self._set_nested_value(overrides, key_path, value)
                        
                    except ValueError as e:
                        self.logger.warning(f"Invalid env value for {schema.env_var}: {e}")
        
        return overrides
    
    def _apply_overrides(self) -> None:
        """Apply environment and runtime overrides to configuration"""
        # Apply environment overrides
        self._merge_dicts(self._config, self._env_overrides)
        
        # Apply runtime overrides
        self._merge_dicts(self._config, self._runtime_overrides)
    
    def _merge_dicts(self, base: Dict, override: Dict) -> None:
        """Recursively merge override dictionary into base"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_dicts(base[key], value)
            else:
                base[key] = value
    
    def _validate_config(self) -> None:
        """Validate configuration against schema"""
        errors = []
        
        for key_path, schema in self.SCHEMA.items():
            value = self.get(key_path)
            
            # Check required fields
            if schema.required and value is None:
                errors.append(f"Required field missing: {key_path}")
                continue
            
            if value is None:
                continue
            
            # Type validation
            if not isinstance(value, schema.type):
                errors.append(f"Invalid type for {key_path}: expected {schema.type.__name__}, got {type(value).__name__}")
            
            # Range validation
            if schema.min_value is not None and value < schema.min_value:
                errors.append(f"Value too small for {key_path}: {value} < {schema.min_value}")
            
            if schema.max_value is not None and value > schema.max_value:
                errors.append(f"Value too large for {key_path}: {value} > {schema.max_value}")
            
            # Allowed values validation
            if schema.allowed_values and value not in schema.allowed_values:
                errors.append(f"Invalid value for {key_path}: {value} not in {schema.allowed_values}")
            
            # Custom validator
            if schema.validator and not schema.validator(value):
                errors.append(f"Custom validation failed for {key_path}")
        
        if errors:
            raise ValidationError(f"Configuration validation failed: {'; '.join(errors)}")
    
    def _get_defaults(self) -> Dict[str, Any]:
        """Get default configuration"""
        defaults = {}
        
        for key_path, schema in self.SCHEMA.items():
            if schema.default is not None:
                self._set_nested_value(defaults, key_path, schema.default)
        
        return defaults
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot-notation key"""
        # Check cache first
        if self._cache:
            cache_key = f"config:{key}"
            if cache_key in self._cache:
                return self._cache[cache_key]
        
        # Navigate nested dictionary
        value = self._get_nested_value(self._config, key)
        
        # Use default if not found
        if value is None:
            # Check schema default
            if key in self.SCHEMA and self.SCHEMA[key].default is not None:
                value = self.SCHEMA[key].default
            else:
                value = default
        
        # Cache the result
        if value is not None and self._cache:
            self._cache[cache_key] = value
        
        return value
    
    def _get_nested_value(self, config: Dict, key_path: str, default: Any = None) -> Any:
        """Get nested configuration value using dot notation"""
        keys = key_path.split('.')
        current = config
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        
        return current
    
    def _set_nested_value(self, config: Dict, key_path: str, value: Any):
        """Set nested configuration value using dot notation"""
        keys = key_path.split('.')
        current = config
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value
    
    def set(self, key: str, value: Any, persist: bool = False) -> None:
        """Set configuration value"""
        with self._lock:
            # Validate against schema if exists
            if key in self.SCHEMA:
                self._validate_value(key, value)
            
            # Set value in runtime overrides
            self._set_nested_value(self._runtime_overrides, key, value)
            
            # Apply overrides
            self._apply_overrides()
            
            # Clear cache for this key
            if self._cache:
                cache_key = f"config:{key}"
                self._cache.pop(cache_key, None)
            
            # Persist to file if requested
            if persist:
                self._save_config()
    
    def _validate_value(self, key: str, value: Any):
        """Validate a single value against schema"""
        if key not in self.SCHEMA:
            return
        
        schema = self.SCHEMA[key]
        
        # Type check
        if not isinstance(value, schema.type):
            raise ValidationError(f"Invalid type for {key}: expected {schema.type.__name__}")
        
        # Range check
        if schema.min_value is not None and value < schema.min_value:
            raise ValidationError(f"Value too small for {key}: {value} < {schema.min_value}")
        
        if schema.max_value is not None and value > schema.max_value:
            raise ValidationError(f"Value too large for {key}: {value} > {schema.max_value}")
        
        # Allowed values check
        if schema.allowed_values and value not in schema.allowed_values:
            raise ValidationError(f"Invalid value for {key}: {value} not in {schema.allowed_values}")
        
        # Custom validator
        if schema.validator and not schema.validator(value):
            raise ValidationError(f"Custom validation failed for {key}")
    
    def _save_config(self) -> None:
        """Save configuration to file"""
        self._save_to_file(self._config)
    
    def _save_to_file(self, config: Dict[str, Any]):
        """Save configuration to file with backup"""
        try:
            # Create backup before saving
            if self.backup_count > 0:
                self._create_backup()
            
            # Ensure directory exists
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Save configuration
            with open(self.config_path, 'w', encoding='utf-8') as f:
                if self.format == ConfigFormat.YAML:
                    yaml.dump(config, f, default_flow_style=False, indent=2, sort_keys=True)
                elif self.format == ConfigFormat.TOML and TOML_AVAILABLE:
                    tomli_w.dump(config, f)
                else:
                    json.dump(config, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Configuration saved to {self.config_path}")
            
        except Exception as e:
            raise ConfigError(f"Failed to save config: {e}")
    
    def get_all(self) -> Dict[str, Any]:
        """Get entire configuration"""
        return self._config.copy()
    
    def validate(self) -> bool:
        """Validate current configuration"""
        try:
            self._validate_config()
            return True
        except ValidationError:
            return False
    
    def export_env_template(self) -> str:
        """Export environment variable template"""
        lines = ["# BLNCS Environment Variables Template", ""]
        
        for key_path, schema in self.SCHEMA.items():
            if schema.env_var:
                value = self.get(key_path) or schema.default or ""
                comment = f"# {key_path}"
                if schema.description:
                    comment += f" - {schema.description}"
                if schema.allowed_values:
                    comment += f" (options: {', '.join(map(str, schema.allowed_values))})"
                elif schema.min_value or schema.max_value:
                    if schema.min_value and schema.max_value:
                        comment += f" (range: {schema.min_value}-{schema.max_value})"
                    elif schema.min_value:
                        comment += f" (min: {schema.min_value})"
                    elif schema.max_value:
                        comment += f" (max: {schema.max_value})"
                
                lines.append(comment)
                lines.append(f"{schema.env_var}={value}")
                lines.append("")
        
        return "\n".join(lines)
    
    def add_observer(self, callback: Callable[[Dict, Dict], None]):
        """Add configuration change observer"""
        self._observers.append(callback)
    
    def remove_observer(self, callback: Callable):
        """Remove configuration change observer"""
        if callback in self._observers:
            self._observers.remove(callback)
    
    def update(self, config: Dict[str, Any], persist: bool = False):
        """Update multiple configuration values"""
        with self._lock:
            self._deep_merge(self._runtime_overrides, config)
            self._apply_overrides()
            
            if self._cache:
                self._cache.clear()
            
            if persist:
                self._save_config()
    
    def _deep_merge(self, base: Dict, update: Dict):
        """Deep merge update dictionary into base"""
        for key, value in update.items():
            if isinstance(value, dict) and key in base and isinstance(base[key], dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def export_config(self, file_path: Union[str, Path], format: Optional[ConfigFormat] = None):
        """Export configuration to file"""
        file_path = Path(file_path)
        
        if format is None:
            ext = file_path.suffix.lower()
            if ext in ['.yaml', '.yml']:
                format = ConfigFormat.YAML
            elif ext == '.toml' and TOML_AVAILABLE:
                format = ConfigFormat.TOML
            else:
                format = ConfigFormat.JSON
        
        with open(file_path, 'w', encoding='utf-8') as f:
            if format == ConfigFormat.YAML:
                yaml.dump(self._config, f, default_flow_style=False, indent=2)
            elif format == ConfigFormat.TOML and TOML_AVAILABLE:
                tomli_w.dump(self._config, f)
            else:
                json.dump(self._config, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"Configuration exported to {file_path}")
    
    def list_backups(self) -> List[str]:
        """List available configuration backups"""
        backup_dir = self.config_path.parent / "backups"
        
        if not backup_dir.exists():
            return []
        
        backups = sorted(backup_dir.glob(f"{self.config_path.stem}.*{self.config_path.suffix}"))
        return [backup.name for backup in backups]
    
    def restore_backup(self, backup_file: Optional[str] = None):
        """Restore configuration from backup"""
        backup_dir = self.config_path.parent / "backups"
        
        if backup_file:
            backup_path = backup_dir / backup_file
        else:
            # Find latest backup
            backups = sorted(backup_dir.glob(f"{self.config_path.stem}.*{self.config_path.suffix}"))
            if not backups:
                raise FileNotFoundError("No backup files found")
            backup_path = backups[-1]
        
        if not backup_path.exists():
            raise FileNotFoundError(f"Backup file not found: {backup_path}")
        
        # Copy backup to main config
        shutil.copy2(backup_path, self.config_path)
        
        # Reload configuration
        self.reload()
        
        self.logger.info(f"Configuration restored from backup: {backup_path}")
    
    def __del__(self):
        """Cleanup on destruction"""
        if self._file_observer:
            try:
                self._file_observer.stop()
                self._file_observer.join()
            except:
                pass


# Global configuration manager
_config_manager: Optional[ConfigManager] = None


def get_config_manager(config_path: Optional[str] = None, **kwargs) -> ConfigManager:
    """Get global configuration manager"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager(config_path, **kwargs)
    return _config_manager


def reload_config():
    """Reload configuration"""
    manager = get_config_manager()
    manager.reload()


def get_config_value(key: str, default: Any = None) -> Any:
    """Get configuration value"""
    manager = get_config_manager()
    return manager.get(key, default)


def set_config_value(key: str, value: Any, persist: bool = False):
    """Set configuration value"""
    manager = get_config_manager()
    manager.set(key, value, persist)


def update_config(config: Dict[str, Any], persist: bool = False):
    """Update multiple configuration values"""
    manager = get_config_manager()
    manager.update(config, persist)