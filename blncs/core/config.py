#!/usr/bin/env python3
"""
BLNCS Configuration Management System
Unified, secure, and optimized configuration management
"""

import os
import json
import yaml
import logging
import re
import copy
import secrets
from pathlib import Path
from typing import Dict, Any, Optional, Union, Callable, List
from dataclasses import dataclass, asdict, field
from datetime import datetime
import threading
from enum import Enum
import hashlib
import time

try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    Fernet = None

logger = logging.getLogger(__name__)


class ConfigFormat(Enum):
    JSON = "json"
    YAML = "yaml"
    ENV = "env"


@dataclass
class LightningConfig:
    """Lightning Network configuration"""
    network: str = "testnet"
    host: str = "localhost"
    port: int = 10009
    macaroon_path: Optional[str] = None
    tls_cert_path: Optional[str] = None
    connection_timeout: int = 30
    max_channels: int = 25
    min_channel_size: int = 100000
    max_channel_size: int = 16777215
    fee_rate_ppm: int = 1000


@dataclass
class DatabaseConfig:
    """Database configuration"""
    url: str = "sqlite:///./blncs.db"
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30
    echo: bool = False


@dataclass
class CacheConfig:
    """Cache configuration"""
    enabled: bool = True
    ttl: int = 3600
    max_size: int = 1000
    backend: str = "memory"
    redis_url: Optional[str] = "redis://localhost:6379"


@dataclass
class SecurityConfig:
    """Security configuration"""
    jwt_secret: Optional[str] = None
    jwt_algorithm: str = "HS256"
    jwt_expiration: int = 3600
    api_key: Optional[str] = None
    enable_tls: bool = True
    enforce_https: bool = False
    rate_limit: int = 100
    encryption_key: Optional[str] = None
    trusted_hosts: List[str] = field(default_factory=list)


@dataclass
class APIConfig:
    """API configuration"""
    enabled: bool = True
    host: str = "localhost"
    port: int = 3000
    cors_enabled: bool = True
    cors_allowed_origins: List[str] = field(default_factory=lambda: ["http://localhost:3000"])
    authentication_enabled: bool = False
    rate_limiting_enabled: bool = True


@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str = "INFO"
    output: str = "console"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_path: Optional[str] = None


@dataclass
class PerformanceConfig:
    """Performance configuration"""
    enable_optimization: bool = True
    async_operations: bool = True
    connection_pool_size: int = 20
    worker_threads: int = 4
    request_timeout: int = 30


@dataclass
class ValidationRule:
    """Configuration validation rule"""
    path: str
    required: bool = False
    type_check: Optional[type] = None
    validator: Optional[Callable] = None
    default: Any = None


class ConfigurationError(Exception):
    """Configuration-related errors"""
    pass


class ConfigManager:
    """
    Unified configuration manager with:
    - Multiple formats (JSON, YAML, ENV)
    - Environment-specific configs
    - Hot-reloading (optional)
    - Validation
    - Encryption for sensitive values (optional)
    """

    def __init__(
        self,
        config_path: Optional[str] = None,
        environment: Optional[str] = None,
        *,
        enable_file_watching: bool = False,
        enable_encryption: bool = False,
        auto_generate_secrets: bool = True
    ):
        self.environment = environment or os.getenv('BLNCS_ENV', 'development')
        self._config_path = self._detect_config_path(config_path)
        self.config_path = str(self._config_path)

        # Configuration sections
        self.lightning = LightningConfig()
        self.database = DatabaseConfig()
        self.cache = CacheConfig()
        self.security = SecurityConfig()
        self.api = APIConfig()
        self.logging = LoggingConfig()
        self.performance = PerformanceConfig()

        # Internal state
        self._raw_config: Dict[str, Any] = {}
        self._validation_rules: List[ValidationRule] = []
        self._watchers: List[Callable] = []
        self._file_watchers: Dict[str, threading.Thread] = {}
        self._file_watch_stop_events: Dict[str, threading.Event] = {}
        self._enable_file_watching = enable_file_watching
        self._enable_encryption = enable_encryption and CRYPTO_AVAILABLE
        self._auto_generate_secrets = auto_generate_secrets
        self._fernet: Optional[Fernet] = None
        self._lock = threading.RLock()

        # Fast access cache
        self._config_cache: Optional[Dict[str, Any]] = None
        self._cache_hash: Optional[str] = None
        self._cache_timestamp: float = 0.0

        # Initialize
        self._init_encryption()
        self._load_config()
        self._setup_default_validation()

        if enable_file_watching:
            self._start_file_watching()

    def _detect_config_path(self, config_path: Optional[str] = None) -> Path:
        """Auto-detect configuration file path"""
        if config_path:
            path = Path(config_path)
            if path.exists():
                return path.resolve()

        env = self.environment
        candidates = [
            f"config/{env}.json",
            f"config/{env}.yaml",
            f"config/blncs_{env}.json",
            "config/blncs.json",
            "config/config.json",
            "blncs.json",
            "config.json"
        ]

        for candidate in candidates:
            path = Path(candidate)
            if path.exists():
                logger.info(f"Found config file: {path}")
                return path.resolve()

        # Create default config
        default_path = Path(f"config/{env}.json")
        self._create_default_config(default_path)
        return default_path.resolve()

    def _create_default_config(self, path: Path):
        """Create a default configuration file"""
        default_config = {
            "version": "2.0.0",
            "environment": self.environment,
            "lightning": asdict(self.lightning),
            "database": asdict(self.database),
            "cache": asdict(self.cache),
            "security": asdict(self.security),
            "api": asdict(self.api),
            "logging": asdict(self.logging),
            "performance": asdict(self.performance)
        }

        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(default_config, f, indent=2)

        logger.info(f"Created default config: {path}")

    def _init_encryption(self):
        """Initialize encryption if enabled"""
        if not self._enable_encryption:
            return

        encryption_key = os.getenv('BLNCS_ENCRYPTION_KEY')

        if not encryption_key and self._auto_generate_secrets:
            encryption_key = Fernet.generate_key().decode()
            os.environ['BLNCS_ENCRYPTION_KEY'] = encryption_key
            logger.warning("Auto-generated encryption key for development. Set BLNCS_ENCRYPTION_KEY in production!")

        if encryption_key:
            try:
                self._fernet = Fernet(encryption_key.encode())
            except Exception as e:
                logger.error(f"Failed to initialize encryption: {e}")

    def _load_config(self):
        """Load configuration from file and environment"""
        with self._lock:
            # Load base configuration
            self._raw_config = self._load_file_config()

            # Substitute environment placeholders
            self._raw_config = self._substitute_env_placeholders(self._raw_config)

            # Update dataclass configs
            self._update_from_dict(self._raw_config)

            # Override with environment variables
            self._load_env_overrides()

            # Auto-generate secrets if needed
            if self._auto_generate_secrets and self.environment == 'development':
                self._auto_generate_missing_secrets()

            # Validate
            self._validate_config()

    def _load_file_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        if not self._config_path.exists():
            return {}

        try:
            with open(self._config_path, 'r', encoding='utf-8') as f:
                if self._config_path.suffix in {'.yaml', '.yml'}:
                    return yaml.safe_load(f) or {}
                else:
                    return json.load(f)
        except Exception as e:
            raise ConfigurationError(f"Failed to load config: {e}")

    _ENV_PLACEHOLDER_PATTERN = re.compile(r"\$\{([^}]+)\}")

    def _substitute_env_placeholders(self, value: Any) -> Any:
        """Recursively substitute ${ENV_VAR} or ${ENV_VAR:default} placeholders"""
        if isinstance(value, dict):
            return {k: self._substitute_env_placeholders(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._substitute_env_placeholders(item) for item in value]
        if isinstance(value, str):
            def replace(match):
                placeholder = match.group(1)
                if ':' in placeholder:
                    env_name, default = placeholder.split(':', 1)
                else:
                    env_name, default = placeholder, None

                env_value = os.getenv(env_name.strip())
                if env_value is None:
                    return default if default else match.group(0)
                return env_value

            return self._ENV_PLACEHOLDER_PATTERN.sub(replace, value)
        return value

    def _update_from_dict(self, config_data: Dict[str, Any]):
        """Update configuration dataclasses from dictionary"""
        if 'lightning' in config_data:
            self._update_dataclass(self.lightning, config_data['lightning'])
        if 'database' in config_data:
            self._update_dataclass(self.database, config_data['database'])
        if 'cache' in config_data:
            self._update_dataclass(self.cache, config_data['cache'])
        if 'security' in config_data:
            self._update_dataclass(self.security, config_data['security'])
        if 'api' in config_data:
            self._update_dataclass(self.api, config_data['api'])
        if 'logging' in config_data:
            self._update_dataclass(self.logging, config_data['logging'])
        if 'performance' in config_data:
            self._update_dataclass(self.performance, config_data['performance'])

    def _update_dataclass(self, obj: Any, data: Dict[str, Any]):
        """Update dataclass fields from dictionary"""
        for key, value in data.items():
            if hasattr(obj, key):
                setattr(obj, key, value)

    def _load_env_overrides(self):
        """Load environment variable overrides"""
        env_prefix = "BLNCS_"

        for key, value in os.environ.items():
            if key.startswith(env_prefix):
                config_key = key[len(env_prefix):].lower()
                config_path = config_key.replace('_', '.')

                # Convert value
                converted_value = self._convert_env_value(value)
                self._set_nested_value(config_path, converted_value)

    def _convert_env_value(self, value: str) -> Any:
        """Convert environment variable string to appropriate type"""
        if value.lower() in ('true', 'false'):
            return value.lower() == 'true'

        try:
            return int(value)
        except ValueError:
            pass

        try:
            return float(value)
        except ValueError:
            pass

        if value.startswith('{') or value.startswith('['):
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                pass

        return value

    def _set_nested_value(self, path: str, value: Any):
        """Set nested value in dataclasses using dot notation"""
        keys = path.split('.')
        if len(keys) < 2:
            return

        section = keys[0]
        field_path = keys[1:]

        if hasattr(self, section):
            obj = getattr(self, section)
            current = obj

            for key in field_path[:-1]:
                if hasattr(current, key):
                    current = getattr(current, key)
                else:
                    return

            final_key = field_path[-1]
            if hasattr(current, final_key):
                setattr(current, final_key, value)

    def _auto_generate_missing_secrets(self):
        """Auto-generate missing secrets in development"""
        if not self.security.jwt_secret:
            self.security.jwt_secret = secrets.token_urlsafe(32)
            logger.warning("Auto-generated JWT secret for development")

        if not self.security.api_key:
            self.security.api_key = secrets.token_urlsafe(32)
            logger.warning("Auto-generated API key for development")

    def auto_detect_configuration(self) -> Dict[str, Any]:
        """Automatically detect and suggest optimal configuration"""
        suggestions = {
            'detected_hardware': self._detect_hardware(),
            'network_connectivity': self._detect_network(),
            'available_services': self._detect_services(),
            'recommended_settings': {},
            'warnings': [],
            'optimizations': []
        }

        # Generate recommendations based on detection
        suggestions['recommended_settings'] = self._generate_recommendations(suggestions)

        return suggestions

    def _detect_hardware(self) -> Dict[str, Any]:
        """Detect hardware capabilities"""
        try:
            import psutil
            cpu_count = psutil.cpu_count()
            memory_gb = psutil.virtual_memory().total / (1024**3)
            disk_gb = psutil.disk_usage('/').total / (1024**3)

            # GPU detection
            gpu_info = {'available': False, 'count': 0}
            try:
                import GPUtil
                gpus = GPUtil.getGPUs()
                gpu_info = {
                    'available': len(gpus) > 0,
                    'count': len(gpus),
                    'names': [gpu.name for gpu in gpus]
                }
            except ImportError:
                gpu_info['warning'] = "GPUtil not installed - GPU detection disabled"

            return {
                'cpu_cores': cpu_count,
                'memory_gb': round(memory_gb, 2),
                'disk_gb': round(disk_gb, 2),
                'gpu': gpu_info
            }
        except Exception as e:
            return {'error': f"Hardware detection failed: {e}"}

    def _detect_network(self) -> Dict[str, Any]:
        """Detect network connectivity and capabilities"""
        try:
            import socket
            import urllib.request

            # Check internet connectivity
            connectivity = {'internet': False, 'ipv6': False}
            try:
                urllib.request.urlopen('https://www.google.com', timeout=5)
                connectivity['internet'] = True
            except:
                connectivity['internet'] = False

            # Check IPv6 support
            try:
                socket.socket(socket.AF_INET6, socket.SOCK_STREAM).close()
                connectivity['ipv6'] = True
            except:
                connectivity['ipv6'] = False

            # Get local IP addresses
            ips = []
            try:
                hostname = socket.gethostname()
                ips = socket.gethostbyname_ex(hostname)[2]
            except:
                pass

            return {
                'connectivity': connectivity,
                'local_ips': ips,
                'hostname': socket.gethostname()
            }
        except Exception as e:
            return {'error': f"Network detection failed: {e}"}

    def _detect_services(self) -> Dict[str, Any]:
        """Detect available services and dependencies"""
        services = {}

        # Check Lightning Network
        services['lightning'] = self._check_lightning_service()

        # Check database connectivity
        services['database'] = self._check_database_service()

        # Check Redis
        services['redis'] = self._check_redis_service()

        # Check Python dependencies
        services['dependencies'] = self._check_dependencies()

        return services

    def _check_lightning_service(self) -> Dict[str, Any]:
        """Check Lightning Network service availability"""
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.lightning.host, self.lightning.port))
            sock.close()

            return {
                'available': result == 0,
                'host': self.lightning.host,
                'port': self.lightning.port,
                'macaroon_exists': bool(self.lightning.macaroon_path and Path(self.lightning.macaroon_path).exists()),
                'tls_cert_exists': bool(self.lightning.tls_cert_path and Path(self.lightning.tls_cert_path).exists())
            }
        except Exception as e:
            return {'available': False, 'error': str(e)}

    def _check_database_service(self) -> Dict[str, Any]:
        """Check database connectivity"""
        try:
            if 'sqlite' in self.database.url:
                # SQLite - check if file exists or can be created
                db_path = self.database.url.replace('sqlite:///', '')
                db_exists = Path(db_path).exists()
                return {
                    'type': 'sqlite',
                    'available': True,
                    'path': db_path,
                    'exists': db_exists
                }
            else:
                # Other databases - try to connect
                return {
                    'type': 'external',
                    'url': self.database.url,
                    'available': False,  # Would need actual connection test
                    'note': 'External database connectivity check not implemented'
                }
        except Exception as e:
            return {'available': False, 'error': str(e)}

    def _check_redis_service(self) -> Dict[str, Any]:
        """Check Redis service availability"""
        if not self.cache.redis_url:
            return {'available': False, 'reason': 'No Redis URL configured'}

        try:
            import redis
            # Parse Redis URL
            if self.cache.redis_url.startswith('redis://'):
                url_parts = self.cache.redis_url.replace('redis://', '').split(':')
                if len(url_parts) >= 2:
                    host = url_parts[0]
                    port = int(url_parts[1].split('/')[0])

                    r = redis.Redis(host=host, port=port, socket_timeout=5)
                    r.ping()
                    return {
                        'available': True,
                        'host': host,
                        'port': port
                    }
        except ImportError:
            return {'available': False, 'reason': 'redis-py not installed'}
        except Exception as e:
            return {'available': False, 'error': str(e)}

        return {'available': False, 'reason': 'Invalid Redis URL'}

    def _check_dependencies(self) -> Dict[str, Any]:
        """Check Python dependencies"""
        dependencies = {
            'cryptography': False,
            'psutil': False,
            'pyotp': False,
            'redis': False,
            'sqlalchemy': False,
            'fastapi': False,
            'uvicorn': False,
            'gputil': False
        }

        for dep in dependencies.keys():
            try:
                __import__(dep.replace('-', '_'))
                dependencies[dep] = True
            except ImportError:
                pass

        return dependencies

    def _generate_recommendations(self, detection_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate configuration recommendations based on detection"""
        recommendations = {}

        hardware = detection_results.get('detected_hardware', {})
        services = detection_results.get('available_services', {})

        # Performance recommendations
        if hardware.get('cpu_cores', 0) >= 8:
            recommendations['performance.thread_pool_workers'] = hardware['cpu_cores'] * 2
        else:
            recommendations['performance.thread_pool_workers'] = max(4, hardware.get('cpu_cores', 1))

        if hardware.get('memory_gb', 0) >= 16:
            recommendations['database.pool_size'] = 20
            recommendations['cache.max_size'] = 2000
        else:
            recommendations['database.pool_size'] = 5
            recommendations['cache.max_size'] = 500

        # GPU recommendations
        gpu = hardware.get('gpu', {})
        if gpu.get('available'):
            recommendations['performance.enable_gpu_monitoring'] = True
            recommendations['performance.gpu_optimization'] = True

        # Service recommendations
        lightning = services.get('lightning', {})
        if lightning.get('available'):
            recommendations['lightning.auto_connect'] = True
        else:
            recommendations['lightning.connection_retry_interval'] = 30

        database = services.get('database', {})
        if database.get('available') and database.get('type') == 'sqlite':
            recommendations['database.enable_wal_mode'] = True

        redis = services.get('redis', {})
        if redis.get('available'):
            recommendations['cache.backend'] = 'redis'
        else:
            recommendations['cache.backend'] = 'memory'

        # Security recommendations
        deps = services.get('dependencies', {})
        if deps.get('cryptography'):
            recommendations['security.enable_encryption'] = True
        if deps.get('pyotp'):
            recommendations['security.enable_mfa'] = True

        return recommendations

    def _setup_default_validation(self):
        """Setup default validation rules"""
        self._validation_rules = [
            ValidationRule("lightning.network", required=True, type_check=str),
            ValidationRule("lightning.host", required=True, type_check=str),
            ValidationRule("lightning.port", required=True, type_check=int),
            ValidationRule("api.enabled", required=True, type_check=bool),
            ValidationRule("api.port", required=True, type_check=int),
            ValidationRule("logging.level", required=True, type_check=str),
        ]

    def _validate_config(self):
        """Validate configuration"""
        # Validate Lightning network
        if self.lightning.network not in ['mainnet', 'testnet', 'simnet', 'regtest']:
            raise ConfigurationError(f"Invalid lightning network: {self.lightning.network}")

        # Validate port ranges
        if not (1 <= self.lightning.port <= 65535):
            raise ConfigurationError(f"Invalid lightning port: {self.lightning.port}")

        if not (1 <= self.api.port <= 65535):
            raise ConfigurationError(f"Invalid API port: {self.api.port}")

        # Validate log level
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if self.logging.level.upper() not in valid_levels:
            raise ConfigurationError(f"Invalid log level: {self.logging.level}")

        # Production environment validation
        if self.environment == 'production':
            if not self.security.jwt_secret:
                raise ConfigurationError("JWT secret required in production")

            if not self.security.trusted_hosts:
                raise ConfigurationError("Trusted hosts required in production")

            if not self.security.enforce_https:
                logger.warning("HTTPS not enforced in production - this is a security risk!")

    def _start_file_watching(self):
        """Start watching configuration files for changes"""
        path_key = self.config_path
        if path_key in self._file_watchers:
            return

        stop_event = threading.Event()

        def watch_file():
            last_modified = 0.0
            config_path = Path(path_key)

            if config_path.exists():
                try:
                    last_modified = config_path.stat().st_mtime
                except OSError:
                    pass

            while not stop_event.wait(1.0):
                try:
                    if not config_path.exists():
                        continue

                    current_modified = config_path.stat().st_mtime
                    if last_modified and current_modified > last_modified:
                        logger.info(f"Config file changed, reloading: {path_key}")
                        self.reload()
                        self._notify_watchers()
                    last_modified = current_modified
                except Exception as e:
                    logger.exception(f"File watching error: {e}")

        watcher = threading.Thread(target=watch_file, daemon=True)
        watcher.start()
        self._file_watchers[path_key] = watcher
        self._file_watch_stop_events[path_key] = stop_event

    def get(self, path: str, default: Any = None) -> Any:
        """Get configuration value using dot notation with caching"""
        # Check cache validity first
        if not self._is_cache_valid():
            self._update_cache()

        # Use cached data for fast access
        if self._config_cache is not None:
            keys = path.split('.')
            current = self._config_cache

            for key in keys:
                if isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    return default
            return current

        # Fallback to non-cached method
        keys = path.split('.')
        config_dict = self.to_dict()

        current = config_dict
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        return current

    def _is_cache_valid(self) -> bool:
        """Check if configuration cache is still valid"""
        if self._config_cache is None:
            return False

        # Check if raw config has changed
        current_hash = self._calculate_config_hash()
        if current_hash != self._cache_hash:
            return False

        # Check if cache is too old (5 minutes)
        if time.time() - self._cache_timestamp > 300:
            return False

        return True

    def _update_cache(self):
        """Update the configuration cache"""
        self._config_cache = self.to_dict()
        self._cache_hash = self._calculate_config_hash()
        self._cache_timestamp = time.time()

    def _calculate_config_hash(self) -> str:
        """Calculate hash of current configuration for cache validation"""
        try:
            config_str = json.dumps(self._raw_config, sort_keys=True, default=str)
            return hashlib.md5(config_str.encode()).hexdigest()
        except Exception:
            # Fallback hash if serialization fails
            return str(hash(str(self._raw_config)))

    def invalidate_cache(self):
        """Invalidate the configuration cache"""
        self._config_cache = None
        self._cache_hash = None
        self._cache_timestamp = 0.0

    def set(self, path: str, value: Any):
        """Set configuration value using dot notation"""
        with self._lock:
            self._set_nested_value(path, value)
            # Invalidate cache when configuration changes
            self.invalidate_cache()

    def reload(self):
        """Reload configuration from file"""
        try:
            self._load_config()
            # Invalidate cache on reload
            self.invalidate_cache()
            logger.info(f"Configuration reloaded: {self.config_path}")
        except Exception as e:
            logger.error(f"Failed to reload config: {e}")
            raise

    def add_watcher(self, callback: Callable):
        """Add a configuration change watcher"""
        self._watchers.append(callback)

    def _notify_watchers(self):
        """Notify all watchers of configuration changes"""
        config_dict = self.to_dict()
        for watcher in list(self._watchers):
            try:
                watcher(config_dict)
            except Exception as e:
                logger.exception(f"Watcher error: {e}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            'version': self._raw_config.get('version', '2.0.0'),
            'environment': self.environment,
            'lightning': asdict(self.lightning),
            'database': asdict(self.database),
            'cache': asdict(self.cache),
            'security': asdict(self.security),
            'api': asdict(self.api),
            'logging': asdict(self.logging),
            'performance': asdict(self.performance),
        }

    def save(self, path: Optional[str] = None):
        """Save current configuration to file"""
        save_path = Path(path) if path else self._config_path
        config_dict = self.to_dict()

        try:
            with open(save_path, 'w', encoding='utf-8') as f:
                if save_path.suffix in {'.yaml', '.yml'}:
                    yaml.dump(config_dict, f, default_flow_style=False, indent=2)
                else:
                    json.dump(config_dict, f, indent=2)
            logger.info(f"Configuration saved: {save_path}")
        except Exception as e:
            raise ConfigurationError(f"Failed to save config: {e}")

    def encrypt(self, data: str) -> str:
        """Encrypt sensitive data"""
        if not self._fernet:
            raise ConfigurationError("Encryption not enabled")

        encrypted = self._fernet.encrypt(data.encode())
        return encrypted.hex()

    def decrypt(self, encrypted_hex: str) -> str:
        """Decrypt sensitive data"""
        if not self._fernet:
            raise ConfigurationError("Encryption not enabled")

        encrypted = bytes.fromhex(encrypted_hex)
        decrypted = self._fernet.decrypt(encrypted)
        return decrypted.decode()

    def enable_dynamic_reloading(self, check_interval: int = 30):
        """Enable dynamic configuration reloading"""
        if hasattr(self, '_reload_thread') and self._reload_thread and self._reload_thread.is_alive():
            logger.warning("Dynamic reloading is already enabled")
            return

        self._reload_check_interval = check_interval
        self._reload_thread = threading.Thread(target=self._dynamic_reload_loop, daemon=True)
        self._reload_thread.start()
        logger.info(f"Dynamic configuration reloading enabled (check every {check_interval}s)")

    def disable_dynamic_reloading(self):
        """Disable dynamic configuration reloading"""
        if hasattr(self, '_reload_thread') and self._reload_thread:
            self._reload_thread = None  # Thread will exit on next iteration
            logger.info("Dynamic configuration reloading disabled")

    def _dynamic_reload_loop(self):
        """Dynamic reload monitoring loop"""
        last_check = time.time()

        while getattr(self, '_reload_thread', None) is not None:
            try:
                current_time = time.time()
                if current_time - last_check >= self._reload_check_interval:
                    if self._check_for_config_changes():
                        logger.info("Configuration changes detected, reloading...")
                        self.reload()
                        # Notify watchers
                        self._notify_config_change()
                    last_check = current_time

                time.sleep(5)  # Check every 5 seconds for thread responsiveness

            except Exception as e:
                logger.error(f"Error in dynamic reload loop: {e}")
                time.sleep(10)  # Wait longer on error

    def _check_for_config_changes(self) -> bool:
        """Check if configuration file has changed"""
        try:
            config_path = Path(self.config_path)
            if not config_path.exists():
                return False

            current_mtime = config_path.stat().st_mtime
            last_mtime = getattr(self, '_last_config_mtime', 0)

            if current_mtime > last_mtime:
                self._last_config_mtime = current_mtime
                return True

            return False

        except Exception as e:
            logger.error(f"Error checking for config changes: {e}")
            return False

    def _notify_config_change(self):
        """Notify about configuration changes"""
        try:
            config_dict = self.to_dict()
            for watcher in list(self._watchers):
                try:
                    watcher(config_dict)
                except Exception as e:
                    logger.exception(f"Config change watcher error: {e}")
        except Exception as e:
            logger.error(f"Error notifying config changes: {e}")

    def create_backup(self, backup_path: Optional[str] = None) -> str:
        """Create a backup of current configuration"""
        if backup_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"{self.config_path}.backup_{timestamp}"

        try:
            import shutil
            shutil.copy2(self.config_path, backup_path)
            logger.info(f"Configuration backup created: {backup_path}")
            return backup_path
        except Exception as e:
            logger.error(f"Failed to create config backup: {e}")
            raise ConfigurationError(f"Backup creation failed: {e}")

    def restore_from_backup(self, backup_path: str):
        """Restore configuration from backup"""
        try:
            import shutil
            if not Path(backup_path).exists():
                raise ConfigurationError(f"Backup file does not exist: {backup_path}")

            # Create backup of current config before restore
            current_backup = self.create_backup()

            # Restore from backup
            shutil.copy2(backup_path, self.config_path)
            self.reload()

            logger.info(f"Configuration restored from backup: {backup_path}")
            logger.info(f"Previous config backed up to: {current_backup}")

        except Exception as e:
            logger.error(f"Failed to restore from backup: {e}")
            raise ConfigurationError(f"Restore failed: {e}")

    def validate_configuration_integrity(self) -> Dict[str, Any]:
        """Validate configuration file integrity"""
        results = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'checks': {}
        }

        try:
            # Check file existence
            config_path = Path(self.config_path)
            results['checks']['file_exists'] = config_path.exists()

            if not results['checks']['file_exists']:
                results['valid'] = False
                results['errors'].append("Configuration file does not exist")
                return results

            # Check file permissions
            import stat
            file_stat = config_path.stat()
            mode = stat.filemode(file_stat.st_mode)
            results['checks']['file_permissions'] = mode

            # Check if file is readable/writable by owner only (security)
            if file_stat.st_mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH):
                results['warnings'].append("Configuration file is readable/writable by group or others")

            # Check file size (not too large)
            size_mb = file_stat.st_size / (1024 * 1024)
            results['checks']['file_size_mb'] = round(size_mb, 2)
            if size_mb > 10:  # 10MB limit
                results['warnings'].append(f"Configuration file is very large: {size_mb:.2f}MB")

            # Try to parse configuration
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    if config_path.suffix in ['.yaml', '.yml']:
                        import yaml
                        data = yaml.safe_load(f)
                    else:
                        data = json.load(f)

                results['checks']['parseable'] = True
                results['checks']['has_version'] = 'version' in data
                results['checks']['has_environment'] = 'environment' in data

            except Exception as e:
                results['valid'] = False
                results['errors'].append(f"Configuration file parsing failed: {e}")
                results['checks']['parseable'] = False

        except Exception as e:
            results['valid'] = False
            results['errors'].append(f"Integrity check failed: {e}")

        return results

    def export_configuration(self, format_type: str = 'json', include_sensitive: bool = False) -> str:
        """Export configuration in specified format"""
        config_dict = self.to_dict()

        if not include_sensitive:
            # Remove sensitive information
            sensitive_fields = ['jwt_secret', 'api_key', 'encryption_key']
            for section_name, section in config_dict.items():
                if isinstance(section, dict):
                    for field in sensitive_fields:
                        if field in section:
                            section[field] = "***REDACTED***"

        try:
            if format_type.lower() == 'json':
                return json.dumps(config_dict, indent=2, ensure_ascii=False)
            elif format_type.lower() == 'yaml':
                import yaml
                return yaml.dump(config_dict, default_flow_style=False, indent=2, allow_unicode=True)
            else:
                raise ConfigurationError(f"Unsupported export format: {format_type}")
        except Exception as e:
            raise ConfigurationError(f"Export failed: {e}")

    def import_configuration(self, config_data: Union[str, Dict], format_type: str = 'auto'):
        """Import configuration from string or dict"""
        try:
            if isinstance(config_data, dict):
                parsed_data = config_data
            elif isinstance(config_data, str):
                if format_type == 'auto':
                    # Auto-detect format
                    if config_data.strip().startswith('{'):
                        parsed_data = json.loads(config_data)
                        format_type = 'json'
                    else:
                        import yaml
                        parsed_data = yaml.safe_load(config_data)
                        format_type = 'yaml'
                elif format_type == 'json':
                    parsed_data = json.loads(config_data)
                elif format_type == 'yaml':
                    import yaml
                    parsed_data = yaml.safe_load(config_data)
                else:
                    raise ConfigurationError(f"Unsupported import format: {format_type}")
            else:
                raise ConfigurationError("Invalid config data type")

            # Validate imported data
            if not isinstance(parsed_data, dict):
                raise ConfigurationError("Imported configuration must be a dictionary")

            # Update configuration
            self._raw_config = parsed_data
            self._update_from_dict(parsed_data)
            self._validate_config()

            # Save to file
            self.save()

            logger.info(f"Configuration imported successfully from {format_type} format")

        except Exception as e:
            raise ConfigurationError(f"Import failed: {e}")

    def get_configuration_diff(self, other_config: Union['ConfigManager', Dict]) -> Dict[str, Any]:
        """Get differences between current config and another config"""
        try:
            current = self.to_dict()

            if isinstance(other_config, ConfigManager):
                other = other_config.to_dict()
            elif isinstance(other_config, dict):
                other = other_config
            else:
                raise ConfigurationError("Invalid config type for comparison")

            diff = {
                'added': {},
                'removed': {},
                'modified': {}
            }

            # Find differences
            all_keys = set(current.keys()) | set(other.keys())

            for key in all_keys:
                current_value = current.get(key)
                other_value = other.get(key)

                if key not in current:
                    diff['added'][key] = other_value
                elif key not in other:
                    diff['removed'][key] = current_value
                elif current_value != other_value:
                    diff['modified'][key] = {
                        'from': current_value,
                        'to': other_value
                    }

            return diff

        except Exception as e:
            logger.error(f"Failed to compute config diff: {e}")
            return {'error': str(e)}

    def shutdown(self):
        """Shutdown and cleanup resources"""
        for stop_event in self._file_watch_stop_events.values():
            stop_event.set()

        for watcher in self._file_watchers.values():
            if watcher.is_alive():
                watcher.join(timeout=1)

        self._file_watchers.clear()
        self._file_watch_stop_events.clear()
        self._watchers.clear()

    def __repr__(self) -> str:
        return f"ConfigManager(path={self.config_path}, env={self.environment})"


# Singleton instance
_global_config: Optional[ConfigManager] = None


def get_config(config_path: Optional[str] = None, **kwargs) -> ConfigManager:
    """Get or create global configuration instance"""
    global _global_config
    if _global_config is None:
        _global_config = ConfigManager(config_path, **kwargs)
    return _global_config


def set_config(config: ConfigManager):
    """Set global configuration instance"""
    global _global_config
    _global_config = config


def reset_config():
    """Reset global configuration instance"""
    global _global_config
    if _global_config:
        _global_config.shutdown()
    _global_config = None


__all__ = [
    'ConfigManager', 'get_config', 'set_config', 'reset_config',
    'LightningConfig', 'DatabaseConfig', 'CacheConfig',
    'SecurityConfig', 'APIConfig', 'LoggingConfig', 'PerformanceConfig',
    'ConfigurationError', 'ValidationRule'
]
