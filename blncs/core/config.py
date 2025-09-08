"""
BLNCS Configuration Management
Simple configuration loading and management with caching.
"""

import yaml
import os
import time
from pathlib import Path
from typing import Dict, Any, Optional

from .cache import get_cache


class Config:
    """Configuration manager for BLNCS with caching"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._find_config_file()
        self.cache = get_cache()
        self._last_modified = None
        self.data = self._load_config()
    
    def _find_config_file(self) -> str:
        """Find configuration file in standard locations"""
        locations = [
            Path("config/config.yaml"),
            Path.home() / ".blncs" / "config.yaml",
            Path("/etc/blncs/config.yaml"),
        ]
        
        for location in locations:
            if location.exists():
                return str(location)
        
        # Return default path if no config found
        return "config/config.yaml"
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file with caching"""
        config_file = Path(self.config_path)
        
        if not config_file.exists():
            return self._default_config()
        
        # Check if file has been modified
        try:
            current_mtime = config_file.stat().st_mtime
            cache_key = f"config:{self.config_path}:{current_mtime}"
            
            # Try to get from cache first
            cached_config = self.cache.get(cache_key)
            if cached_config and self._last_modified == current_mtime:
                return cached_config
            
            # Load from file
            with open(self.config_path, 'r') as f:
                config_data = yaml.safe_load(f) or {}
            
            # Cache the config
            self.cache.set(cache_key, config_data, 300)  # Cache for 5 minutes
            self._last_modified = current_mtime
            
            return config_data
            
        except Exception:
            return self._default_config()
    
    def _default_config(self) -> Dict[str, Any]:
        """Return default configuration with environment variable support"""
        return {
            'lightning': {
                'host': os.getenv('LN_HOST', 'localhost'),
                'port': int(os.getenv('LN_PORT', '8080')),
                'network': os.getenv('LN_NETWORK', 'testnet'),
                'timeout': int(os.getenv('LN_TIMEOUT', '15')),  # より短いタイムアウト
                'connect_timeout': int(os.getenv('LN_CONNECT_TIMEOUT', '5')),  # 接続タイムアウト追加
                'max_retries': int(os.getenv('LN_MAX_RETRIES', '5')),  # 増加
                'retry_delay': int(os.getenv('LN_RETRY_DELAY', '2')),  # より短い遅延
                'macaroon_path': os.getenv('LN_MACAROON_PATH', '~/.lnd/data/chain/bitcoin/testnet/readonly.macaroon')
            },
            'system': {
                'name': 'BLNCS',
                'environment': os.getenv('BLNCS_ENV', 'production'),
                'log_level': os.getenv('LOG_LEVEL', 'WARNING'),  # より軽量なデフォルトレベル
                'debug': os.getenv('DEBUG', 'false').lower() == 'true',
                'enable_file_logging': os.getenv('ENABLE_FILE_LOGGING', 'true').lower() == 'true'
            },
            'performance': {
                'monitoring_enabled': os.getenv('PERF_MONITORING', 'true').lower() == 'true',
                'collection_interval': int(os.getenv('PERF_INTERVAL', '60')),  # 軽量化のため間隔延長
                'max_history': int(os.getenv('PERF_MAX_HISTORY', '500')),  # メモリ使用量削減
                'auto_tune': os.getenv('PERF_AUTO_TUNE', 'false').lower() == 'true'  # デフォルト無効
            },
            'monitor': {
                'enabled': os.getenv('MONITOR_ENABLED', 'true').lower() == 'true',
                'interval': int(os.getenv('MONITOR_INTERVAL', '120')),  # 軽量化のため間隔延長
                'alert_threshold': int(os.getenv('MONITOR_ALERT_THRESHOLD', '50000'))  # より実用的な閾値
            },
            'security': {
                'enable_auth': os.getenv('SECURITY_AUTH', 'false').lower() == 'true',
                'session_timeout': int(os.getenv('SECURITY_SESSION_TIMEOUT', '1800')),  # 30分に短縮
                'max_failed_attempts': int(os.getenv('SECURITY_MAX_FAILED', '3'))  # より厳格に
            },
            'fees': {
                'target_confirmation': int(os.getenv('FEES_TARGET_CONF', '3')),  # より高速な確認目標
                'max_fee_rate': int(os.getenv('FEES_MAX_RATE', '50')),  # より控えめな上限
                'min_fee_rate': int(os.getenv('FEES_MIN_RATE', '2')),  # より現実的な最低料金
                'lightning_fee_ppm': int(os.getenv('FEES_LN_PPM', '500')),  # より競争力のある手数料
                'max_lightning_fee_ppm': int(os.getenv('FEES_MAX_LN_PPM', '2000'))  # より低い上限
            },
            'channel': {
                'min_size': int(os.getenv('CHANNEL_MIN_SIZE', '20000')),  # より小さな最小サイズ
                'max_size': int(os.getenv('CHANNEL_MAX_SIZE', '5000000')),  # より実用的な上限
                'target_count': int(os.getenv('CHANNEL_TARGET_COUNT', '3')),  # より管理しやすい数
                'min_balance_ratio': float(os.getenv('CHANNEL_MIN_BALANCE_RATIO', '0.2')),  # より安全な下限
                'max_balance_ratio': float(os.getenv('CHANNEL_MAX_BALANCE_RATIO', '0.8')),  # より安全な上限
                'auto_rebalance': os.getenv('CHANNEL_AUTO_REBALANCE', 'false').lower() == 'true',
                'auto_close_inactive': os.getenv('CHANNEL_AUTO_CLOSE', 'false').lower() == 'true'
            }
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key"""
        keys = key.split('.')
        value = self.data
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value"""
        keys = key.split('.')
        data = self.data
        
        for k in keys[:-1]:
            if k not in data:
                data[k] = {}
            data = data[k]
        
        data[keys[-1]] = value
    
    def save(self) -> None:
        """Save configuration to file and invalidate cache"""
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w') as f:
            yaml.dump(self.data, f, default_flow_style=False)
        
        # Invalidate cache entries for this config file
        config_file = Path(self.config_path)
        if config_file.exists():
            new_mtime = config_file.stat().st_mtime
            cache_key = f"config:{self.config_path}:{new_mtime}"
            self.cache.set(cache_key, self.data, 300)
            self._last_modified = new_mtime
    
    def merge_env_vars(self) -> None:
        """Merge current environment variables into configuration"""
        env_config = self._default_config()
        self._merge_dict(self.data, env_config)
    
    def _merge_dict(self, target: Dict[str, Any], source: Dict[str, Any]) -> None:
        """Deep merge source dict into target dict"""
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._merge_dict(target[key], value)
            else:
                # Only update if environment variable has a meaningful value
                if not (key in target):
                    target[key] = value
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get entire configuration section"""
        return self.data.get(section, {})
    
    def has_key(self, key: str) -> bool:
        """Check if configuration key exists"""
        keys = key.split('.')
        value = self.data
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return False
        return True
    
    def get_env_template(self) -> str:
        """Generate environment variable template"""
        template_lines = [
            "# BLNCS Environment Variables Template",
            "# Copy this to .env and modify values as needed\n"
        ]
        
        env_mappings = {
            'lightning.host': 'LN_HOST',
            'lightning.port': 'LN_PORT', 
            'lightning.network': 'LN_NETWORK',
            'lightning.timeout': 'LN_TIMEOUT',
            'system.environment': 'BLNCS_ENV',
            'system.log_level': 'LOG_LEVEL',
            'system.debug': 'DEBUG',
            'performance.monitoring_enabled': 'PERF_MONITORING',
            'performance.collection_interval': 'PERF_INTERVAL',
            'monitor.enabled': 'MONITOR_ENABLED',
            'monitor.interval': 'MONITOR_INTERVAL',
            'security.enable_auth': 'SECURITY_AUTH',
            'fees.target_confirmation': 'FEES_TARGET_CONF',
            'channel.target_count': 'CHANNEL_TARGET_COUNT'
        }
        
        for config_key, env_var in env_mappings.items():
            current_value = self.get(config_key)
            if isinstance(current_value, bool):
                current_value = 'true' if current_value else 'false'
            template_lines.append(f"#{env_var}={current_value}")
        
        return '\n'.join(template_lines)


# Global config instance cache
_global_configs = {}

def get_config(config_path: Optional[str] = None) -> Config:
    """Get configuration instance with caching"""
    cache_key = config_path or "default"
    
    if cache_key not in _global_configs:
        _global_configs[cache_key] = Config(config_path)
    
    config = _global_configs[cache_key]
    
    # Check if we need to reload due to file changes
    config_file = Path(config.config_path)
    if config_file.exists():
        current_mtime = config_file.stat().st_mtime
        if config._last_modified != current_mtime:
            config.data = config._load_config()
    
    return config