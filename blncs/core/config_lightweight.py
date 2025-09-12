"""
Lightweight Configuration Manager for BLNCS
Simple configuration system using only standard library.
"""

import os
import json
import threading
from pathlib import Path
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass

@dataclass
class ConfigValue:
    """Simple configuration value with type checking"""
    name: str
    default: Any
    value_type: type = str
    required: bool = False
    env_var: Optional[str] = None

class LightweightConfigManager:
    """Lightweight configuration manager using only standard library"""
    
    def __init__(self, config_path: Union[str, Path] = "config.json"):
        self.config_path = Path(config_path)
        self.config_data = {}
        self._cache = {}
        self._lock = threading.Lock()
        self._schema = {}
        
        # Default configuration schema
        self._setup_default_schema()
        self._load_config()
    
    def _setup_default_schema(self):
        """Setup default configuration schema"""
        self._schema = {
            'lightning': ConfigValue(
                'lightning', 
                {'host': 'localhost', 'port': 8080}, 
                dict,
                env_var='BLNCS_LIGHTNING_CONFIG'
            ),
            'database': ConfigValue(
                'database',
                {'path': 'blncs.db'},
                dict,
                env_var='BLNCS_DATABASE_CONFIG'
            ),
            'logging': ConfigValue(
                'logging',
                {'level': 'INFO', 'file': None},
                dict,
                env_var='BLNCS_LOGGING_CONFIG'
            ),
            'backup': ConfigValue(
                'backup',
                {'enabled': True, 'interval_hours': 24},
                dict,
                env_var='BLNCS_BACKUP_CONFIG'
            )
        }
    
    def _load_config(self):
        """Load configuration from file and environment"""
        with self._lock:
            # Load from file if exists
            if self.config_path.exists():
                try:
                    with open(self.config_path, 'r', encoding='utf-8') as f:
                        file_config = json.load(f)
                    self.config_data.update(file_config)
                except (json.JSONDecodeError, IOError) as e:
                    print(f"Warning: Could not load config file {self.config_path}: {e}")
            
            # Apply environment overrides
            for key, config_value in self._schema.items():
                if config_value.env_var and os.getenv(config_value.env_var):
                    try:
                        env_val = os.getenv(config_value.env_var)
                        if config_value.value_type == dict:
                            env_val = json.loads(env_val)
                        elif config_value.value_type == bool:
                            env_val = env_val.lower() in ('true', '1', 'yes', 'on')
                        elif config_value.value_type == int:
                            env_val = int(env_val)
                        elif config_value.value_type == float:
                            env_val = float(env_val)
                        
                        self.config_data[key] = env_val
                    except (ValueError, json.JSONDecodeError) as e:
                        print(f"Warning: Invalid environment value for {config_value.env_var}: {e}")
            
            # Apply defaults for missing values
            for key, config_value in self._schema.items():
                if key not in self.config_data:
                    self.config_data[key] = config_value.default
            
            # Clear cache after reload
            self._cache.clear()
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value with caching"""
        cache_key = f"get_{key}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        with self._lock:
            # Navigate nested keys
            value = self.config_data
            for part in key.split('.'):
                if isinstance(value, dict) and part in value:
                    value = value[part]
                else:
                    value = default
                    break
            
            self._cache[cache_key] = value
            return value
    
    def set(self, key: str, value: Any):
        """Set configuration value"""
        with self._lock:
            # Navigate to parent and set value
            config = self.config_data
            parts = key.split('.')
            
            for part in parts[:-1]:
                if part not in config:
                    config[part] = {}
                config = config[part]
            
            config[parts[-1]] = value
            
            # Clear related cache entries
            self._cache = {k: v for k, v in self._cache.items() if not k.startswith(f"get_{key.split('.')[0]}")}
    
    def get_all(self) -> Dict[str, Any]:
        """Get all configuration data"""
        with self._lock:
            return self.config_data.copy()
    
    def save_config(self):
        """Save current configuration to file"""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        with self._lock:
            try:
                with open(self.config_path, 'w', encoding='utf-8') as f:
                    json.dump(self.config_data, f, indent=2, ensure_ascii=False)
            except IOError as e:
                print(f"Warning: Could not save config file {self.config_path}: {e}")
    
    def reload(self):
        """Reload configuration from file and environment"""
        self._load_config()
    
    def get_data_dir(self) -> Path:
        """Get data directory path"""
        data_dir = self.get('data_dir', Path.home() / '.blncs')
        return Path(data_dir)
    
    def get_log_level(self) -> str:
        """Get logging level"""
        return self.get('logging.level', 'INFO')
    
    def get_db_path(self) -> str:
        """Get database path"""
        return str(self.get_data_dir() / self.get('database.path', 'blncs.db'))

# Create singleton instance
_config_instance = None
_config_lock = threading.Lock()

def get_config_manager(config_path: Union[str, Path] = None) -> LightweightConfigManager:
    """Get or create configuration manager instance"""
    global _config_instance
    if _config_instance is None:
        with _config_lock:
            if _config_instance is None:
                path = config_path or os.getenv('BLNCS_CONFIG_PATH', 'config.json')
                _config_instance = LightweightConfigManager(path)
    return _config_instance

# For backward compatibility
ConfigManager = LightweightConfigManager

__all__ = ['LightweightConfigManager', 'ConfigManager', 'get_config_manager', 'ConfigValue']