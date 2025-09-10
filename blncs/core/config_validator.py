"""
Configuration Validation and Hot-Reloading System for BLNCS
Ensures configuration integrity and supports runtime updates.
"""

import os
import time
import threading
import json
import yaml
from typing import Dict, Any, Optional, List, Callable, Union, Set
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum
import hashlib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from .logger import get_logger
from .exceptions import ConfigError, ValidationError


class ConfigFormat(Enum):
    """Supported configuration formats"""
    JSON = "json"
    YAML = "yaml"
    ENV = "env"


@dataclass
class ValidationRule:
    """Configuration validation rule"""
    key: str
    required: bool = False
    data_type: type = str
    allowed_values: Optional[List[Any]] = None
    min_value: Optional[Union[int, float]] = None
    max_value: Optional[Union[int, float]] = None
    regex_pattern: Optional[str] = None
    validator: Optional[Callable[[Any], bool]] = None
    description: str = ""


@dataclass
class ConfigChange:
    """Represents a configuration change"""
    key: str
    old_value: Any
    new_value: Any
    timestamp: float = field(default_factory=time.time)


class ConfigFileWatcher(FileSystemEventHandler):
    """File system event handler for configuration changes"""
    
    def __init__(self, config_validator, file_paths: List[str]):
        self.config_validator = config_validator
        self.file_paths = set(os.path.abspath(path) for path in file_paths)
        self.logger = get_logger(__name__)
    
    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory:
            file_path = os.path.abspath(event.src_path)
            if file_path in self.file_paths:
                self.logger.info(f"Configuration file modified: {file_path}")
                self.config_validator._handle_file_change(file_path)


class ConfigValidator:
    """Configuration validation and hot-reloading system"""
    
    def __init__(self, config_paths: List[str] = None, enable_hot_reload: bool = True):
        self.logger = get_logger(__name__)
        self.config_paths = config_paths or []
        self.enable_hot_reload = enable_hot_reload
        
        # Validation rules
        self._validation_rules: Dict[str, ValidationRule] = {}
        self._rules_lock = threading.RLock()
        
        # Configuration state
        self._current_config: Dict[str, Any] = {}
        self._config_hashes: Dict[str, str] = {}
        self._config_lock = threading.RLock()
        
        # Change tracking
        self._change_handlers: List[Callable[[List[ConfigChange]], None]] = []
        self._change_history: List[ConfigChange] = []
        self._handlers_lock = threading.RLock()
        
        # File watching
        self._observer: Optional[Observer] = None
        self._file_watcher: Optional[ConfigFileWatcher] = None
        
        # Default validation rules
        self._register_default_rules()
        
        # Start file watching if enabled
        if self.enable_hot_reload and self.config_paths:
            self._start_file_watching()
    
    def _register_default_rules(self):
        """Register default validation rules for common config keys"""
        default_rules = [
            # Lightning node configuration
            ValidationRule(
                key="lightning.host",
                required=True,
                data_type=str,
                description="Lightning node host address"
            ),
            ValidationRule(
                key="lightning.port",
                required=True,
                data_type=int,
                min_value=1,
                max_value=65535,
                description="Lightning node port"
            ),
            ValidationRule(
                key="lightning.network",
                required=True,
                data_type=str,
                allowed_values=["mainnet", "testnet", "regtest"],
                description="Bitcoin network"
            ),
            ValidationRule(
                key="lightning.verify_ssl",
                required=False,
                data_type=bool,
                description="Enable SSL verification"
            ),
            
            # Database configuration
            ValidationRule(
                key="database.path",
                required=True,
                data_type=str,
                description="Database file path"
            ),
            ValidationRule(
                key="database.max_connections",
                required=False,
                data_type=int,
                min_value=1,
                max_value=100,
                description="Maximum database connections"
            ),
            
            # Caching configuration
            ValidationRule(
                key="cache.max_size",
                required=False,
                data_type=int,
                min_value=1,
                description="Maximum cache size"
            ),
            ValidationRule(
                key="cache.default_ttl",
                required=False,
                data_type=int,
                min_value=1,
                description="Default cache TTL in seconds"
            ),
            
            # Logging configuration
            ValidationRule(
                key="logging.level",
                required=False,
                data_type=str,
                allowed_values=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                description="Logging level"
            ),
            
            # Security configuration
            ValidationRule(
                key="security.max_retry_attempts",
                required=False,
                data_type=int,
                min_value=1,
                max_value=10,
                description="Maximum retry attempts"
            )
        ]
        
        for rule in default_rules:
            self.add_validation_rule(rule)
    
    def add_validation_rule(self, rule: ValidationRule) -> None:
        """Add a validation rule"""
        with self._rules_lock:
            self._validation_rules[rule.key] = rule
        
        self.logger.debug(f"Added validation rule: {rule.key}")
    
    def remove_validation_rule(self, key: str) -> bool:
        """Remove a validation rule"""
        with self._rules_lock:
            if key in self._validation_rules:
                del self._validation_rules[key]
                self.logger.debug(f"Removed validation rule: {key}")
                return True
        return False
    
    def _get_nested_value(self, config: Dict[str, Any], key: str) -> Any:
        """Get nested configuration value using dot notation"""
        keys = key.split('.')
        value = config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return None
        
        return value
    
    def _set_nested_value(self, config: Dict[str, Any], key: str, value: Any) -> None:
        """Set nested configuration value using dot notation"""
        keys = key.split('.')
        current = config
        
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        
        current[keys[-1]] = value
    
    def _validate_value(self, rule: ValidationRule, value: Any) -> bool:
        """Validate a single value against a rule"""
        # Type validation
        if not isinstance(value, rule.data_type):
            try:
                # Try to convert
                if rule.data_type == int:
                    value = int(value)
                elif rule.data_type == float:
                    value = float(value)
                elif rule.data_type == bool:
                    if isinstance(value, str):
                        value = value.lower() in ('true', '1', 'yes', 'on')
                    else:
                        value = bool(value)
                elif rule.data_type == str:
                    value = str(value)
            except (ValueError, TypeError):
                return False
        
        # Allowed values validation
        if rule.allowed_values is not None and value not in rule.allowed_values:
            return False
        
        # Numeric range validation
        if rule.min_value is not None and value < rule.min_value:
            return False
        
        if rule.max_value is not None and value > rule.max_value:
            return False
        
        # Regex validation
        if rule.regex_pattern is not None:
            import re
            if not re.match(rule.regex_pattern, str(value)):
                return False
        
        # Custom validator
        if rule.validator is not None:
            try:
                return rule.validator(value)
            except Exception:
                return False
        
        return True
    
    def validate_config(self, config: Dict[str, Any]) -> List[str]:
        """Validate configuration against all rules"""
        errors = []
        
        with self._rules_lock:
            for key, rule in self._validation_rules.items():
                value = self._get_nested_value(config, key)
                
                # Check required fields
                if rule.required and value is None:
                    errors.append(f"Required configuration key missing: {key}")
                    continue
                
                # Skip validation if value is None and not required
                if value is None:
                    continue
                
                # Validate the value
                if not self._validate_value(rule, value):
                    error_msg = f"Invalid value for {key}: {value}"
                    
                    # Add more specific error details
                    if rule.allowed_values:
                        error_msg += f" (allowed: {rule.allowed_values})"
                    elif rule.min_value is not None or rule.max_value is not None:
                        error_msg += f" (range: {rule.min_value}-{rule.max_value})"
                    
                    errors.append(error_msg)
        
        return errors
    
    def _load_config_file(self, file_path: str) -> Dict[str, Any]:
        """Load configuration from a file"""
        if not os.path.exists(file_path):
            raise ConfigError(f"Configuration file not found: {file_path}")
        
        path_obj = Path(file_path)
        suffix = path_obj.suffix.lower()
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                if suffix == '.json':
                    return json.load(f)
                elif suffix in ['.yml', '.yaml']:
                    return yaml.safe_load(f) or {}
                elif suffix == '.env':
                    # Simple .env file parser
                    config = {}
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if '=' in line:
                                key, value = line.split('=', 1)
                                config[key.strip()] = value.strip()
                    return config
                else:
                    raise ConfigError(f"Unsupported configuration file format: {suffix}")
        
        except (json.JSONDecodeError, yaml.YAMLError) as e:
            raise ConfigError(f"Error parsing configuration file {file_path}: {e}")
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate hash of configuration file"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except OSError:
            return ""
    
    def load_config(self, validate: bool = True) -> Dict[str, Any]:
        """Load and validate configuration from all sources"""
        config = {}
        
        # Load from files
        for file_path in self.config_paths:
            if os.path.exists(file_path):
                file_config = self._load_config_file(file_path)
                config.update(file_config)
                
                # Update file hash
                self._config_hashes[file_path] = self._calculate_file_hash(file_path)
                self.logger.debug(f"Loaded configuration from: {file_path}")
        
        # Load from environment variables
        env_config = {}
        for key in os.environ:
            if key.startswith('BLNCS_'):
                config_key = key[6:].lower().replace('_', '.')
                env_config[config_key] = os.environ[key]
        
        if env_config:
            # Merge environment variables into config
            for key, value in env_config.items():
                self._set_nested_value(config, key, value)
            
            self.logger.debug(f"Loaded {len(env_config)} environment variables")
        
        # Validate configuration
        if validate:
            errors = self.validate_config(config)
            if errors:
                raise ConfigError(f"Configuration validation failed: {'; '.join(errors)}")
        
        with self._config_lock:
            self._current_config = config
        
        self.logger.info("Configuration loaded and validated successfully")
        return config.copy()
    
    def _handle_file_change(self, file_path: str) -> None:
        """Handle configuration file change"""
        try:
            # Check if file hash actually changed
            new_hash = self._calculate_file_hash(file_path)
            old_hash = self._config_hashes.get(file_path)
            
            if new_hash == old_hash:
                return  # No actual change
            
            self.logger.info(f"Detected configuration change in: {file_path}")
            
            # Load new configuration
            old_config = self._current_config.copy()
            new_config = self.load_config()
            
            # Find changes
            changes = self._find_config_changes(old_config, new_config)
            
            if changes:
                # Notify change handlers
                self._notify_change_handlers(changes)
                
                # Add to history
                self._change_history.extend(changes)
                
                # Limit history size
                if len(self._change_history) > 1000:
                    self._change_history = self._change_history[-500:]
        
        except Exception as e:
            self.logger.error(f"Error handling configuration file change: {e}")
    
    def _find_config_changes(self, old_config: Dict[str, Any], new_config: Dict[str, Any]) -> List[ConfigChange]:
        """Find differences between old and new configuration"""
        changes = []
        
        def compare_dicts(old_dict, new_dict, prefix=""):
            # Check for modified and new keys
            for key, new_value in new_dict.items():
                full_key = f"{prefix}.{key}" if prefix else key
                
                if key not in old_dict:
                    changes.append(ConfigChange(full_key, None, new_value))
                elif old_dict[key] != new_value:
                    if isinstance(old_dict[key], dict) and isinstance(new_value, dict):
                        compare_dicts(old_dict[key], new_value, full_key)
                    else:
                        changes.append(ConfigChange(full_key, old_dict[key], new_value))
            
            # Check for removed keys
            for key, old_value in old_dict.items():
                if key not in new_dict:
                    full_key = f"{prefix}.{key}" if prefix else key
                    changes.append(ConfigChange(full_key, old_value, None))
        
        compare_dicts(old_config, new_config)
        return changes
    
    def add_change_handler(self, handler: Callable[[List[ConfigChange]], None]) -> None:
        """Add configuration change handler"""
        with self._handlers_lock:
            self._change_handlers.append(handler)
        
        self.logger.debug("Added configuration change handler")
    
    def remove_change_handler(self, handler: Callable[[List[ConfigChange]], None]) -> bool:
        """Remove configuration change handler"""
        with self._handlers_lock:
            if handler in self._change_handlers:
                self._change_handlers.remove(handler)
                self.logger.debug("Removed configuration change handler")
                return True
        return False
    
    def _notify_change_handlers(self, changes: List[ConfigChange]) -> None:
        """Notify all change handlers"""
        with self._handlers_lock:
            handlers = self._change_handlers.copy()
        
        for handler in handlers:
            try:
                handler(changes)
            except Exception as e:
                self.logger.error(f"Error in configuration change handler: {e}")
    
    def _start_file_watching(self) -> None:
        """Start file system watching for configuration changes"""
        if self._observer is not None:
            return
        
        try:
            self._observer = Observer()
            self._file_watcher = ConfigFileWatcher(self, self.config_paths)
            
            # Watch directories containing config files
            watched_dirs = set()
            for file_path in self.config_paths:
                directory = os.path.dirname(os.path.abspath(file_path))
                if directory not in watched_dirs:
                    self._observer.schedule(self._file_watcher, directory, recursive=False)
                    watched_dirs.add(directory)
            
            self._observer.start()
            self.logger.info(f"Started file watching for {len(watched_dirs)} directories")
        
        except Exception as e:
            self.logger.error(f"Failed to start file watching: {e}")
    
    def _stop_file_watching(self) -> None:
        """Stop file system watching"""
        if self._observer is not None:
            self._observer.stop()
            self._observer.join()
            self._observer = None
            self._file_watcher = None
            self.logger.info("Stopped file watching")
    
    def get_config_value(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        with self._config_lock:
            return self._get_nested_value(self._current_config, key) or default
    
    def get_change_history(self, limit: int = 100) -> List[ConfigChange]:
        """Get recent configuration changes"""
        return self._change_history[-limit:]
    
    def get_validation_summary(self) -> Dict[str, Any]:
        """Get validation rules summary"""
        with self._rules_lock:
            return {
                'total_rules': len(self._validation_rules),
                'required_keys': [
                    key for key, rule in self._validation_rules.items() 
                    if rule.required
                ],
                'optional_keys': [
                    key for key, rule in self._validation_rules.items() 
                    if not rule.required
                ]
            }
    
    def shutdown(self) -> None:
        """Shutdown the configuration validator"""
        self._stop_file_watching()
        self.logger.info("Configuration validator shutdown")


# Global config validator instance
_config_validator: Optional[ConfigValidator] = None
_validator_lock = threading.Lock()


def get_config_validator(config_paths: List[str] = None, 
                        enable_hot_reload: bool = True) -> ConfigValidator:
    """Get global config validator instance"""
    global _config_validator
    if _config_validator is None:
        with _validator_lock:
            if _config_validator is None:
                _config_validator = ConfigValidator(config_paths, enable_hot_reload)
    return _config_validator


# Convenience functions
def validate_config_file(file_path: str) -> List[str]:
    """Validate a configuration file"""
    validator = get_config_validator([file_path])
    config = validator.load_config(validate=False)
    return validator.validate_config(config)


def add_config_validation_rule(rule: ValidationRule) -> None:
    """Add a configuration validation rule"""
    validator = get_config_validator()
    validator.add_validation_rule(rule)