"""
Enhanced configuration management system for BLNCS
Supports environment variables, validation, and dynamic reloading.
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass
from functools import lru_cache
import threading

from .logger import get_logger
from .exceptions import ConfigError, ValidationError
from .fast_cache import get_fast_cache


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


class ConfigManager:
    """Advanced configuration management with validation and environment support"""
    
    # Configuration schema definitions
    SCHEMA = {
        'system.environment': ConfigSchema(
            name='environment', 
            type=str, 
            required=True,
            allowed_values=['development', 'production', 'testing'],
            env_var='BLNCS_ENV'
        ),
        'system.data_dir': ConfigSchema(
            name='data_dir', 
            type=str, 
            required=True,
            default='./data',
            env_var='BLNCS_DATA_DIR'
        ),
        'lightning.host': ConfigSchema(
            name='host', 
            type=str, 
            required=True,
            default='localhost',
            env_var='BLNCS_LN_HOST'
        ),
        'lightning.port': ConfigSchema(
            name='port', 
            type=int, 
            required=True,
            min_value=1,
            max_value=65535,
            default=8080,
            env_var='BLNCS_LN_PORT'
        ),
        'lightning.network': ConfigSchema(
            name='network', 
            type=str, 
            required=True,
            allowed_values=['mainnet', 'testnet', 'regtest'],
            env_var='BLNCS_LN_NETWORK'
        ),
        'performance.max_connections': ConfigSchema(
            name='max_connections', 
            type=int,
            min_value=1,
            max_value=100,
            default=10,
            env_var='BLNCS_MAX_CONNECTIONS'
        ),
        'performance.cache_ttl': ConfigSchema(
            name='cache_ttl', 
            type=int,
            min_value=0,
            max_value=3600,
            default=300,
            env_var='BLNCS_CACHE_TTL'
        ),
        'security.rate_limit': ConfigSchema(
            name='rate_limit', 
            type=int,
            min_value=1,
            max_value=10000,
            default=100,
            env_var='BLNCS_RATE_LIMIT'
        ),
        'logging.level': ConfigSchema(
            name='level', 
            type=str,
            allowed_values=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
            default='INFO',
            env_var='BLNCS_LOG_LEVEL'
        ),
    }
    
    def __init__(self, config_path: Optional[str] = None):
        self.logger = get_logger(__name__)
        self.cache = get_fast_cache()
        self._lock = threading.RLock()
        
        # Configuration state
        self.config_path = config_path or self._find_config_file()
        self._config: Dict[str, Any] = {}
        self._env_overrides: Dict[str, Any] = {}
        self._runtime_overrides: Dict[str, Any] = {}
        
        # Load configuration
        self.reload()
    
    def _find_config_file(self) -> str:
        """Find configuration file in standard locations"""
        locations = [
            Path("config/config.yaml"),
            Path("config.yaml"),
            Path.home() / ".blncs" / "config.yaml",
            Path("/etc/blncs/config.yaml"),
        ]
        
        for location in locations:
            if location.exists():
                return str(location)
        
        return "config/config.yaml"
    
    def reload(self) -> None:
        """Reload configuration from file and environment"""
        with self._lock:
            # Load base configuration
            self._config = self._load_file()
            
            # Apply environment variable overrides
            self._env_overrides = self._load_env_overrides()
            
            # Merge configurations
            self._apply_overrides()
            
            # Validate configuration
            self._validate_config()
            
            # Clear cache
            self.cache.clear()
            
            self.logger.info("Configuration reloaded successfully")
    
    def _load_file(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        config_file = Path(self.config_path)
        
        if not config_file.exists():
            self.logger.warning(f"Config file not found: {self.config_path}, using defaults")
            return self._get_defaults()
        
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f) or {}
            
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
                        keys = key_path.split('.')
                        current = overrides
                        for key in keys[:-1]:
                            if key not in current:
                                current[key] = {}
                            current = current[key]
                        current[keys[-1]] = value
                        
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
        
        if errors:
            raise ValidationError(f"Configuration validation failed: {'; '.join(errors)}")
    
    def _get_defaults(self) -> Dict[str, Any]:
        """Get default configuration"""
        defaults = {}
        
        for key_path, schema in self.SCHEMA.items():
            if schema.default is not None:
                keys = key_path.split('.')
                current = defaults
                for key in keys[:-1]:
                    if key not in current:
                        current[key] = {}
                    current = current[key]
                current[keys[-1]] = schema.default
        
        return defaults
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot-notation key"""
        # Check cache first
        cache_key = f"config:{key}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached
        
        # Navigate nested dictionary
        keys = key.split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    break
            else:
                value = None
                break
        
        # Use default if not found
        if value is None:
            # Check schema default
            if key in self.SCHEMA and self.SCHEMA[key].default is not None:
                value = self.SCHEMA[key].default
            else:
                value = default
        
        # Cache the result
        if value is not None:
            self.cache.set(cache_key, value, ttl=60)
        
        return value
    
    def set(self, key: str, value: Any, persist: bool = False) -> None:
        """Set configuration value"""
        with self._lock:
            # Validate against schema if exists
            if key in self.SCHEMA:
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
            
            # Set value in runtime overrides
            keys = key.split('.')
            current = self._runtime_overrides
            for k in keys[:-1]:
                if k not in current:
                    current[k] = {}
                current = current[k]
            current[keys[-1]] = value
            
            # Apply overrides
            self._apply_overrides()
            
            # Clear cache for this key
            cache_key = f"config:{key}"
            self.cache.delete(cache_key)
            
            # Persist to file if requested
            if persist:
                self._save_config()
    
    def _save_config(self) -> None:
        """Save configuration to file"""
        config_file = Path(self.config_path)
        
        try:
            # Ensure directory exists
            config_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Save configuration
            with open(config_file, 'w') as f:
                yaml.dump(self._config, f, default_flow_style=False, sort_keys=True)
            
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


# Global configuration manager
_config_manager = None


def get_config_manager() -> ConfigManager:
    """Get global configuration manager"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
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