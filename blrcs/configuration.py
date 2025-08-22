"""
Configuration Management System
Centralized configuration for national-level deployment
"""

import os
import json
import yaml
import configparser
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, field, asdict
from pathlib import Path
import hashlib
from enum import Enum


class Environment(Enum):
    """Deployment environments"""
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"
    GOVERNMENT = "government"


class SecurityLevel(Enum):
    """Security configuration levels"""
    BASIC = "basic"
    STANDARD = "standard"
    ENHANCED = "enhanced"
    MAXIMUM = "maximum"
    PARANOID = "paranoid"


@dataclass
class DatabaseConfig:
    """Database configuration"""
    engine: str = "sqlite"
    host: str = "localhost"
    port: int = 5432
    database: str = "blrcs"
    username: str = "blrcs_user"
    password: str = ""
    pool_size: int = 20
    max_overflow: int = 10
    pool_timeout: int = 30
    pool_recycle: int = 3600
    echo: bool = False
    
    @property
    def connection_string(self) -> str:
        """Generate database connection string"""
        if self.engine == "sqlite":
            return f"sqlite:///{self.database}.db"
        elif self.engine == "postgresql":
            return f"postgresql://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"
        elif self.engine == "mysql":
            return f"mysql://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"
        else:
            raise ValueError(f"Unsupported database engine: {self.engine}")


@dataclass
class CacheConfig:
    """Cache configuration"""
    backend: str = "memory"
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: str = ""
    memcached_hosts: List[str] = field(default_factory=lambda: ["localhost:11211"])
    ttl: int = 300
    max_size: int = 10000
    eviction_policy: str = "lru"


@dataclass
class SecurityConfig:
    """Security configuration"""
    level: SecurityLevel = SecurityLevel.ENHANCED
    encryption_key: str = ""
    jwt_secret: str = ""
    session_timeout: int = 3600
    max_login_attempts: int = 5
    lockout_duration: int = 900
    password_min_length: int = 12
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_numbers: bool = True
    password_require_special: bool = True
    mfa_enabled: bool = True
    mfa_methods: List[str] = field(default_factory=lambda: ["totp", "sms", "email"])
    tls_version: str = "1.3"
    cipher_suites: List[str] = field(default_factory=list)
    allowed_origins: List[str] = field(default_factory=lambda: ["http://localhost:8000"])
    csrf_enabled: bool = True
    rate_limit_enabled: bool = True
    rate_limit_requests: int = 100
    rate_limit_window: int = 60


@dataclass
class MonitoringConfig:
    """Monitoring configuration"""
    enabled: bool = True
    metrics_enabled: bool = True
    metrics_port: int = 9090
    logging_level: str = "INFO"
    log_format: str = "json"
    log_file: str = "/var/log/blrcs/app.log"
    audit_enabled: bool = True
    audit_file: str = "/var/log/blrcs/audit.log"
    tracing_enabled: bool = False
    tracing_endpoint: str = ""
    health_check_interval: int = 30
    alert_email: str = ""
    alert_webhook: str = ""


@dataclass
class APIConfig:
    """API configuration"""
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4
    timeout: int = 30
    max_request_size: int = 10485760  # 10MB
    cors_enabled: bool = True
    cors_origins: List[str] = field(default_factory=lambda: ["*"])
    api_key_header: str = "X-API-Key"
    rate_limit_strategy: str = "sliding_window"
    documentation_enabled: bool = True
    documentation_path: str = "/docs"


@dataclass
class PerformanceConfig:
    """Performance configuration"""
    connection_pool_size: int = 100
    thread_pool_size: int = 50
    async_enabled: bool = True
    compression_enabled: bool = True
    compression_level: int = 6
    lazy_loading: bool = True
    query_cache_enabled: bool = True
    query_cache_size: int = 1000
    response_cache_enabled: bool = True
    response_cache_ttl: int = 60


@dataclass
class BLRCSConfig:
    """Main BLRCS configuration"""
    environment: Environment = Environment.PRODUCTION
    debug: bool = False
    testing: bool = False
    
    # Sub-configurations
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    api: APIConfig = field(default_factory=APIConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    
    # Paths
    base_dir: str = "/opt/blrcs"
    data_dir: str = "/var/lib/blrcs"
    log_dir: str = "/var/log/blrcs"
    config_dir: str = "/etc/blrcs"
    backup_dir: str = "/var/backups/blrcs"
    temp_dir: str = "/tmp/blrcs"
    
    # Feature flags
    features: Dict[str, bool] = field(default_factory=lambda: {
        "quantum_encryption": False,
        "ai_threat_detection": True,
        "blockchain_audit": False,
        "ml_anomaly_detection": True,
        "auto_scaling": True,
        "disaster_recovery": True
    })
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert configuration to JSON"""
        return json.dumps(self.to_dict(), indent=2, default=str)
    
    def to_yaml(self) -> str:
        """Convert configuration to YAML"""
        return yaml.dump(self.to_dict(), default_flow_style=False)
    
    def validate(self) -> List[str]:
        """Validate configuration"""
        errors = []
        
        # Validate database
        if not self.database.host:
            errors.append("Database host is required")
        if self.database.pool_size < 1:
            errors.append("Database pool size must be at least 1")
            
        # Validate security
        if self.security.level == SecurityLevel.PARANOID:
            if not self.security.encryption_key:
                errors.append("Encryption key required for PARANOID security level")
            if not self.security.mfa_enabled:
                errors.append("MFA must be enabled for PARANOID security level")
                
        # Validate API
        if self.api.port < 1 or self.api.port > 65535:
            errors.append("API port must be between 1 and 65535")
            
        # Validate paths
        for path_name in ["base_dir", "data_dir", "log_dir", "config_dir"]:
            path_value = getattr(self, path_name)
            if not path_value:
                errors.append(f"{path_name} is required")
                
        return errors


class ConfigLoader:
    """Configuration loader from various sources"""
    
    def __init__(self):
        self.config = BLRCSConfig()
        self.config_sources = []
        
    def load_from_env(self) -> "ConfigLoader":
        """Load configuration from environment variables"""
        env_prefix = "BLRCS_"
        
        for key, value in os.environ.items():
            if key.startswith(env_prefix):
                config_key = key[len(env_prefix):].lower()
                self._set_nested_value(config_key, value)
                
        self.config_sources.append("environment")
        return self
        
    def load_from_file(self, file_path: str) -> "ConfigLoader":
        """Load configuration from file"""
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {file_path}")
            
        if path.suffix == ".json":
            with open(path, 'r') as f:
                data = json.load(f)
        elif path.suffix in [".yaml", ".yml"]:
            with open(path, 'r') as f:
                data = yaml.safe_load(f)
        elif path.suffix in [".ini", ".cfg"]:
            parser = configparser.ConfigParser()
            parser.read(path)
            data = {section: dict(parser.items(section)) 
                   for section in parser.sections()}
        else:
            raise ValueError(f"Unsupported configuration file format: {path.suffix}")
            
        self._update_config(data)
        self.config_sources.append(f"file:{file_path}")
        return self
        
    def load_from_dict(self, data: Dict[str, Any]) -> "ConfigLoader":
        """Load configuration from dictionary"""
        self._update_config(data)
        self.config_sources.append("dictionary")
        return self
        
    def _set_nested_value(self, key: str, value: Any):
        """Set nested configuration value"""
        parts = key.split("_")
        obj = self.config
        
        for part in parts[:-1]:
            if hasattr(obj, part):
                obj = getattr(obj, part)
            else:
                return
                
        if hasattr(obj, parts[-1]):
            attr_type = type(getattr(obj, parts[-1]))
            if attr_type == bool:
                value = value.lower() in ["true", "1", "yes", "on"]
            elif attr_type == int:
                value = int(value)
            elif attr_type == float:
                value = float(value)
                
            setattr(obj, parts[-1], value)
            
    def _update_config(self, data: Dict[str, Any]):
        """Update configuration from dictionary"""
        for key, value in data.items():
            if hasattr(self.config, key):
                if isinstance(value, dict):
                    # Update nested configuration
                    nested_obj = getattr(self.config, key)
                    for nested_key, nested_value in value.items():
                        if hasattr(nested_obj, nested_key):
                            setattr(nested_obj, nested_key, nested_value)
                else:
                    setattr(self.config, key, value)
                    
    def get_config(self) -> BLRCSConfig:
        """Get loaded configuration"""
        return self.config
        
    def validate(self) -> List[str]:
        """Validate loaded configuration"""
        return self.config.validate()


class ConfigManager:
    """Configuration manager with hot-reload support"""
    
    def __init__(self):
        self._config = None
        self._config_hash = None
        self._config_file = None
        self._callbacks = []
        
    def load(self, config_file: Optional[str] = None) -> BLRCSConfig:
        """Load configuration"""
        loader = ConfigLoader()
        
        # Load from environment first
        loader.load_from_env()
        
        # Load from file if provided
        if config_file and Path(config_file).exists():
            loader.load_from_file(config_file)
            self._config_file = config_file
            
        # Load from default locations
        default_locations = [
            "/etc/blrcs/config.yaml",
            "/etc/blrcs/config.json",
            "./config.yaml",
            "./config.json"
        ]
        
        if not config_file:
            for location in default_locations:
                if Path(location).exists():
                    loader.load_from_file(location)
                    self._config_file = location
                    break
                    
        self._config = loader.get_config()
        self._config_hash = self._calculate_hash()
        
        # Validate configuration
        errors = self._config.validate()
        if errors:
            raise ValueError(f"Configuration validation failed: {', '.join(errors)}")
            
        return self._config
        
    def reload(self) -> bool:
        """Reload configuration if changed"""
        if not self._config_file:
            return False
            
        new_hash = self._calculate_file_hash(self._config_file)
        
        if new_hash != self._config_hash:
            old_config = self._config
            try:
                self.load(self._config_file)
                self._notify_callbacks(old_config, self._config)
                return True
            except Exception:
                self._config = old_config
                raise
                
        return False
        
    def register_callback(self, callback):
        """Register configuration change callback"""
        self._callbacks.append(callback)
        
    def _calculate_hash(self) -> str:
        """Calculate configuration hash"""
        config_str = json.dumps(self._config.to_dict(), sort_keys=True, default=str)
        return hashlib.sha256(config_str.encode()).hexdigest()
        
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate file hash"""
        with open(file_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
            
    def _notify_callbacks(self, old_config: BLRCSConfig, new_config: BLRCSConfig):
        """Notify callbacks of configuration change"""
        for callback in self._callbacks:
            try:
                callback(old_config, new_config)
            except Exception:
                pass  # Log but don't fail
                
    def get(self) -> BLRCSConfig:
        """Get current configuration"""
        if not self._config:
            self.load()
        return self._config


# Global configuration instance
_config_manager = ConfigManager()


def get_config() -> BLRCSConfig:
    """Get global configuration"""
    return _config_manager.get()


def reload_config() -> bool:
    """Reload configuration"""
    return _config_manager.reload()


def register_config_callback(callback):
    """Register configuration change callback"""
    _config_manager.register_callback(callback)