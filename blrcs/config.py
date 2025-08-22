# BLRCS Configuration System
# Enhanced unified configuration with validation and optimization
import os
import json
import threading
import hashlib
import time
from pathlib import Path
from typing import Optional, Dict, Any, List, Callable, Union
from dataclasses import dataclass, field, asdict
from functools import lru_cache
from contextlib import contextmanager
from collections import defaultdict
from enum import Enum

class ConfigEnvironment(Enum):
    """Configuration environments"""
    DEVELOPMENT = "dev"
    TESTING = "test"
    STAGING = "staging"
    PRODUCTION = "prod"

class ConfigValidator:
    """Configuration validation with custom rules"""
    
    def __init__(self):
        self.rules: List[Callable] = []
        self.warnings: List[str] = []
        self.errors: List[str] = []
    
    def add_rule(self, rule: Callable[[Any], bool], message: str, level: str = "error"):
        """Add validation rule"""
        self.rules.append((rule, message, level))
    
    def validate(self, config: 'BLRCSConfig') -> tuple[bool, List[str], List[str]]:
        """Validate configuration"""
        self.warnings.clear()
        self.errors.clear()
        
        for rule, message, level in self.rules:
            try:
                if not rule(config):
                    if level == "warning":
                        self.warnings.append(message)
                    else:
                        self.errors.append(message)
            except Exception as e:
                self.errors.append(f"Validation rule failed: {str(e)}")
        
        return len(self.errors) == 0, self.warnings, self.errors

class ConfigWatcher:
    """Configuration file watcher for hot reloading"""
    
    def __init__(self, config_path: Path, callback: Callable):
        self.config_path = config_path
        self.callback = callback
        self.last_modified = 0
        self.watching = False
        self.thread: Optional[threading.Thread] = None
    
    def start(self):
        """Start watching configuration file"""
        if self.watching:
            return
        
        self.watching = True
        self.thread = threading.Thread(target=self._watch_loop, daemon=True)
        self.thread.start()
    
    def stop(self):
        """Stop watching"""
        self.watching = False
        if self.thread:
            self.thread.join(timeout=1)
    
    def _watch_loop(self):
        """Watch loop"""
        while self.watching:
            try:
                if self.config_path.exists():
                    current_modified = self.config_path.stat().st_mtime
                    if current_modified > self.last_modified:
                        self.last_modified = current_modified
                        self.callback()
                time.sleep(0.5)  # 最適化: 1s -> 0.5s
            except Exception:
                time.sleep(2)  # 最適化: 5s -> 2s

class ConfigHistory:
    """Configuration change history"""
    
    def __init__(self, max_entries: int = 50):
        self.max_entries = max_entries
        self.history: List[Dict[str, Any]] = []
        self.lock = threading.Lock()
    
    def add_change(self, key: str, old_value: Any, new_value: Any, timestamp: float = None):
        """Add configuration change to history"""
        with self.lock:
            change = {
                'timestamp': timestamp or time.time(),
                'key': key,
                'old_value': old_value,
                'new_value': new_value,
                'checksum': self._calculate_checksum(new_value)
            }
            
            self.history.append(change)
            if len(self.history) > self.max_entries:
                self.history.pop(0)
    
    def get_history(self, key: str = None) -> List[Dict[str, Any]]:
        """Get configuration history"""
        with self.lock:
            if key:
                return [h for h in self.history if h['key'] == key]
            return list(self.history)
    
    def _calculate_checksum(self, value: Any) -> str:
        """Calculate checksum for value"""
        return hashlib.sha256(str(value).encode()).hexdigest()[:8]

@dataclass
class BLRCSConfig:
    """Main configuration class following Clean Code principles."""
    # Core Settings
    app_name: str = "BLRCS"
    mode: str = field(default_factory=lambda: os.getenv("BLRCS_MODE", "prod"))
    debug: bool = field(default_factory=lambda: os.getenv("BLRCS_DEBUG", "").lower() == "true")
    
    # Server Settings
    host: str = field(default_factory=lambda: os.getenv("BLRCS_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.getenv("BLRCS_PORT", "8080")))
    
    # Database
    db_path: Path = field(default_factory=lambda: Path(os.getenv("BLRCS_DB", "data/blrcs.db")))
    db_pool_size: int = field(default_factory=lambda: int(os.getenv("BLRCS_DB_POOL_SIZE", "5")))
    
    # Logging
    log_level: str = field(default_factory=lambda: os.getenv("BLRCS_LOG_LEVEL", "INFO"))
    log_file: Optional[Path] = field(default_factory=lambda: Path(os.getenv("BLRCS_LOG_FILE")) if os.getenv("BLRCS_LOG_FILE") else None)
    log_max_bytes: int = field(default_factory=lambda: int(os.getenv("BLRCS_LOG_MAX_BYTES", "1000000")))
    log_backups: int = field(default_factory=lambda: int(os.getenv("BLRCS_LOG_BACKUPS", "3")))
    
    # Security
    api_key: Optional[str] = field(default_factory=lambda: os.getenv("BLRCS_API_KEY"))
    secret_key: str = field(default_factory=lambda: os.getenv("BLRCS_SECRET_KEY", ""))
    session_timeout: int = field(default_factory=lambda: int(os.getenv("BLRCS_SESSION_TIMEOUT", "1800")))
    rate_limit: str = field(default_factory=lambda: os.getenv("BLRCS_RATE_LIMIT", "100/minute"))
    max_body_size: int = field(default_factory=lambda: int(os.getenv("BLRCS_MAX_BODY", "1048576")))
    
    # Cache Settings  
    cache_enabled: bool = field(default_factory=lambda: os.getenv("BLRCS_CACHE_ENABLED", "true").lower() == "true")
    cache_ttl: int = field(default_factory=lambda: int(os.getenv("BLRCS_CACHE_TTL", "300")))
    cache_size: int = field(default_factory=lambda: int(os.getenv("BLRCS_CACHE_SIZE", "1000")))
    
    # Performance
    worker_threads: int = field(default_factory=lambda: int(os.getenv("BLRCS_WORKER_THREADS", "4")))
    enable_compression: bool = field(default_factory=lambda: os.getenv("BLRCS_ENABLE_COMPRESSION", "true").lower() == "true")
    
    # Localization
    default_lang: str = field(default_factory=lambda: os.getenv("BLRCS_LANG", "en"))
    supported_langs: list = field(default_factory=lambda: ["en", "ja"])

    # Lightning (LND REST)
    lnd_rest_host: str = field(default_factory=lambda: os.getenv("BLRCS_LND_REST_HOST", "127.0.0.1"))
    lnd_rest_port: int = field(default_factory=lambda: int(os.getenv("BLRCS_LND_REST_PORT", "8080")))
    lnd_tls_cert: Optional[Path] = field(default_factory=lambda: Path(os.getenv("BLRCS_LND_TLS_CERT")).expanduser() if os.getenv("BLRCS_LND_TLS_CERT") else None)
    lnd_admin_macaroon: Optional[Path] = field(default_factory=lambda: Path(os.getenv("BLRCS_LND_ADMIN_MACAROON")).expanduser() if os.getenv("BLRCS_LND_ADMIN_MACAROON") else None)

    # LND process/runtime
    lnd_exe: Optional[Path] = field(default_factory=lambda: Path(os.getenv("BLRCS_LND_EXE")).expanduser() if os.getenv("BLRCS_LND_EXE") else None)
    lnd_dir: Optional[Path] = field(default_factory=lambda: Path(os.getenv("BLRCS_LND_DIR")).expanduser() if os.getenv("BLRCS_LND_DIR") else None)
    lnd_network: str = field(default_factory=lambda: os.getenv("BLRCS_LND_NETWORK", "mainnet"))
    lnd_backend: str = field(default_factory=lambda: os.getenv("BLRCS_LND_BACKEND", "neutrino"))
    lnd_extra_args: Optional[str] = field(default_factory=lambda: os.getenv("BLRCS_LND_EXTRA_ARGS"))

    # LND poller (Lightning tab)
    lnd_poll_base_ms: int = field(default_factory=lambda: int(os.getenv("BLRCS_LND_POLL_BASE_MS", "5000")))
    lnd_poll_max_ms: int = field(default_factory=lambda: int(os.getenv("BLRCS_LND_POLL_MAX_MS", "60000")))
    lnd_poll_backoff_factor: float = field(default_factory=lambda: float(os.getenv("BLRCS_LND_POLL_BACKOFF_FACTOR", "2.0")))
    lnd_poll_watchdog_margin_ms: int = field(default_factory=lambda: int(os.getenv("BLRCS_LND_POLL_WATCHDOG_MARGIN_MS", "500")))
    
    def __post_init__(self):
        """Enhanced validation and initialization"""
        # Initialize enhanced features
        self._validator = ConfigValidator()
        self._history = ConfigHistory()
        self._watchers: List[ConfigWatcher] = []
        self._change_callbacks: List[Callable] = []
        self._lock = threading.RLock()
        self._checksum = ""
        
        # Setup validation rules
        self._setup_validation_rules()
        
        # Ensure directories exist
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if self.log_file:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Generate secret key if not provided
        if not self.secret_key:
            import secrets
            self.secret_key = secrets.token_urlsafe(32)
        
        # Coerce string paths to Path when loaded from JSON
        def _to_path(v):
            if isinstance(v, str) and v:
                return Path(v).expanduser()
            return v
        self.db_path = _to_path(self.db_path) or self.db_path
        self.log_file = _to_path(self.log_file) if self.log_file else self.log_file
        self.lnd_tls_cert = _to_path(self.lnd_tls_cert)
        self.lnd_admin_macaroon = _to_path(self.lnd_admin_macaroon)
        self.lnd_exe = _to_path(self.lnd_exe)
        self.lnd_dir = _to_path(self.lnd_dir)
        
        # Validate and calculate initial checksum
        self._validate()
        self._checksum = self._calculate_checksum()
    
    def _setup_validation_rules(self):
        """Setup validation rules"""
        # Port validation
        self._validator.add_rule(
            lambda c: 1 <= c.port <= 65535,
            f"Port must be between 1-65535, got {self.port}"
        )
        
        # LND REST port validation
        self._validator.add_rule(
            lambda c: 1 <= c.lnd_rest_port <= 65535,
            f"LND REST port must be between 1-65535, got {self.lnd_rest_port}"
        )
        
        # Log level validation
        self._validator.add_rule(
            lambda c: c.log_level in ["TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL", "SECURITY", "AUDIT"],
            f"Invalid log level: {self.log_level}"
        )
        
        # Mode validation
        self._validator.add_rule(
            lambda c: c.mode in ["dev", "test", "staging", "prod"],
            f"Invalid mode: {self.mode}"
        )
        
        # Network validation
        self._validator.add_rule(
            lambda c: c.lnd_network.lower() in ["mainnet", "testnet", "signet", "regtest"],
            f"Invalid LND network: {self.lnd_network}"
        )
        
        # Backend validation
        self._validator.add_rule(
            lambda c: c.lnd_backend.lower() in ["neutrino", "bitcoind", "neutrino+bitcoind"],
            f"Invalid LND backend: {self.lnd_backend}"
        )
        
        # Performance warnings
        self._validator.add_rule(
            lambda c: c.worker_threads <= 32,
            f"High worker thread count ({self.worker_threads}) may impact performance",
            "warning"
        )
        
        self._validator.add_rule(
            lambda c: c.cache_size <= 10000,
            f"Large cache size ({self.cache_size}) may use excessive memory",
            "warning"
        )
    
    def _calculate_checksum(self) -> str:
        """Calculate configuration checksum"""
        config_str = json.dumps(self.to_dict(), sort_keys=True, default=str)
        return hashlib.sha256(config_str.encode()).hexdigest()[:16]
        
    def _validate(self):
        """Validate configuration values"""
        if self.port < 1 or self.port > 65535:
            raise ValueError(f"Invalid port: {self.port}")
        
        if self.log_level not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            raise ValueError(f"Invalid log level: {self.log_level}")
            
        if self.mode not in ["dev", "test", "prod"]:
            raise ValueError(f"Invalid mode: {self.mode}")
        
        if self.lnd_rest_port < 1 or self.lnd_rest_port > 65535:
            raise ValueError(f"Invalid LND REST port: {self.lnd_rest_port}")
        
        if self.lnd_network.lower() not in ["mainnet", "testnet", "signet", "regtest"]:
            raise ValueError(f"Invalid LND network: {self.lnd_network}")
        
        if self.lnd_backend.lower() not in ["neutrino", "bitcoind", "neutrino+bitcoind"]:
            raise ValueError(f"Invalid LND backend: {self.lnd_backend}")

        # LND poller validation
        if self.lnd_poll_base_ms <= 0:
            raise ValueError(f"Invalid LND poll base interval: {self.lnd_poll_base_ms}")
        if self.lnd_poll_max_ms < self.lnd_poll_base_ms:
            raise ValueError(
                f"Invalid LND poll max interval: {self.lnd_poll_max_ms} (must be >= base {self.lnd_poll_base_ms})"
            )
        if self.lnd_poll_backoff_factor < 1.0:
            raise ValueError(f"Invalid LND poll backoff factor: {self.lnd_poll_backoff_factor}")
        if self.lnd_poll_watchdog_margin_ms < 0:
            raise ValueError(f"Invalid LND poll watchdog margin: {self.lnd_poll_watchdog_margin_ms}")
        if self.lnd_poll_watchdog_margin_ms >= self.lnd_poll_base_ms:
            raise ValueError(
                f"Watchdog margin {self.lnd_poll_watchdog_margin_ms} must be < base interval {self.lnd_poll_base_ms}"
            )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary"""
        return asdict(self)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value with default"""
        return getattr(self, key, default)
    
    def set(self, key: str, value: Any, validate: bool = True):
        """Enhanced set configuration value with validation and history"""
        if not hasattr(self, key):
            raise ValueError(f"Unknown configuration key: {key}")
        
        with self._lock:
            old_value = getattr(self, key)
            
            # Skip if value unchanged
            if old_value == value:
                return
            
            # Validate if requested
            if validate:
                # Temporarily set value for validation
                setattr(self, key, value)
                is_valid, warnings, errors = self._validator.validate(self)
                
                if not is_valid:
                    # Restore old value and raise error
                    setattr(self, key, old_value)
                    raise ValueError(f"Invalid value for {key}: {'; '.join(errors)}")
                
                # Log warnings
                if warnings:
                    import logging
                    logger = logging.getLogger(__name__)
                    for warning in warnings:
                        logger.warning(f"Configuration warning: {warning}")
            
            # Set the value
            setattr(self, key, value)
            
            # Update checksum
            old_checksum = self._checksum
            self._checksum = self._calculate_checksum()
            
            # Record change in history
            self._history.add_change(key, old_value, value)
            
            # Notify change callbacks
            for callback in self._change_callbacks:
                try:
                    callback(key, old_value, value)
                except Exception:
                    pass  # Don't let callback errors break config updates
    
    def bulk_update(self, updates: Dict[str, Any], validate: bool = True):
        """Update multiple configuration values atomically"""
        with self._lock:
            # Store original values for rollback
            original_values = {key: getattr(self, key) for key in updates.keys() if hasattr(self, key)}
            
            try:
                # Apply all updates
                for key, value in updates.items():
                    if hasattr(self, key):
                        setattr(self, key, value)
                
                # Validate all changes
                if validate:
                    is_valid, warnings, errors = self._validator.validate(self)
                    if not is_valid:
                        raise ValueError(f"Bulk update validation failed: {'; '.join(errors)}")
                
                # Record changes and update checksum
                for key, value in updates.items():
                    if key in original_values:
                        self._history.add_change(key, original_values[key], value)
                
                self._checksum = self._calculate_checksum()
                
                # Notify callbacks
                for callback in self._change_callbacks:
                    try:
                        callback("bulk_update", original_values, updates)
                    except Exception:
                        pass
            
            except Exception as e:
                # Rollback all changes
                for key, value in original_values.items():
                    setattr(self, key, value)
                raise e
    
    def add_change_callback(self, callback: Callable):
        """Add configuration change callback"""
        self._change_callbacks.append(callback)
    
    def remove_change_callback(self, callback: Callable):
        """Remove configuration change callback"""
        if callback in self._change_callbacks:
            self._change_callbacks.remove(callback)
    
    def get_change_history(self, key: str = None) -> List[Dict[str, Any]]:
        """Get configuration change history"""
        return self._history.get_history(key)
    
    def validate_config(self) -> tuple[bool, List[str], List[str]]:
        """Validate current configuration"""
        return self._validator.validate(self)
    
    def get_checksum(self) -> str:
        """Get current configuration checksum"""
        return self._checksum
    
    @contextmanager
    def transaction(self):
        """Configuration transaction context manager"""
        with self._lock:
            original_state = self.to_dict()
            try:
                yield self
            except Exception:
                # Rollback on error
                for key, value in original_state.items():
                    if hasattr(self, key):
                        setattr(self, key, value)
                self._checksum = self._calculate_checksum()
                raise
    
    def create_profile(self, name: str) -> Dict[str, Any]:
        """Create configuration profile"""
        return {
            'name': name,
            'timestamp': time.time(),
            'config': self.to_dict(),
            'checksum': self._checksum
        }
    
    def load_profile(self, profile: Dict[str, Any], validate: bool = True):
        """Load configuration profile"""
        if 'config' in profile:
            self.bulk_update(profile['config'], validate)
    
    def start_watching(self, config_path: Path = None):
        """Start watching configuration file for changes"""
        if not config_path:
            config_path = Path("config.json")
        
        def reload_callback():
            try:
                new_config = BLRCSConfig.load(config_path)
                # Update current config with new values
                updates = {}
                for key, value in new_config.to_dict().items():
                    if hasattr(self, key) and getattr(self, key) != value:
                        updates[key] = value
                
                if updates:
                    self.bulk_update(updates)
            except Exception:
                pass  # Silently ignore reload errors
        
        watcher = ConfigWatcher(config_path, reload_callback)
        watcher.start()
        self._watchers.append(watcher)
    
    def stop_watching(self):
        """Stop all configuration watchers"""
        for watcher in self._watchers:
            watcher.stop()
        self._watchers.clear()
    
    def update_from_env(self):
        """Re-read configuration from environment"""
        self.__init__()
    
    def save(self, path: Optional[Path] = None, encrypt: bool = True, backup: bool = True):
        """Enhanced save configuration with backup and validation"""
        path = path or Path("config.json")
        
        # Create backup if requested and file exists
        if backup and path.exists():
            backup_path = path.with_suffix(f".{int(time.time())}.bak")
            import shutil
            shutil.copy2(path, backup_path)
            
            # Keep only last 5 backups
            backup_files = sorted(path.parent.glob(f"{path.stem}.*.bak"), 
                                key=lambda p: p.stat().st_mtime, reverse=True)
            for old_backup in backup_files[5:]:
                old_backup.unlink()
        
        data = self.to_dict()
        
        # Add metadata
        metadata = {
            '_metadata': {
                'version': '2.0',
                'timestamp': time.time(),
                'checksum': self._checksum,
                'environment': self.mode,
                'encrypted': encrypt
            }
        }
        data.update(metadata)
        
        if encrypt:
            try:
                from .encryption import get_secure_storage
                secure_storage = get_secure_storage()
                # Save sensitive config encrypted
                encrypted_data = data.copy()
                sensitive_keys = ['api_key', 'secret_key', 'lnd_admin_macaroon', 'lnd_tls_cert']
                
                for key, value in data.items():
                    if key in sensitive_keys and value:
                        secure_storage.store(f"config_{key}", str(value))
                        encrypted_data[key] = f"ENCRYPTED:{key}"
                
                data = encrypted_data
            except ImportError:
                # Fallback to unencrypted if encryption not available
                data['_metadata']['encrypted'] = False
        
        # Atomic write
        temp_path = path.with_suffix('.tmp')
        try:
            with open(temp_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str, sort_keys=True)
            
            # Atomic move
            temp_path.replace(path)
        except Exception:
            if temp_path.exists():
                temp_path.unlink()
            raise
    
    @classmethod
    def load(cls, path: Optional[Path] = None, validate: bool = True) -> 'BLRCSConfig':
        """Enhanced load configuration with validation and recovery"""
        path = path or Path("config.json")
        
        if not path.exists():
            return cls()
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Extract metadata if present
            metadata = data.pop('_metadata', {})
            
            # Verify checksum if available
            if 'checksum' in metadata:
                temp_config = cls(**{k: v for k, v in data.items() if not k.startswith('_')})
                calculated_checksum = temp_config._calculate_checksum()
                if calculated_checksum != metadata['checksum']:
                    import logging
                    logger = logging.getLogger(__name__)
                    logger.warning(f"Configuration checksum mismatch: expected {metadata['checksum']}, got {calculated_checksum}")
            
            # Decrypt sensitive values if encrypted
            if metadata.get('encrypted', False):
                try:
                    from .encryption import get_secure_storage
                    secure_storage = get_secure_storage()
                    
                    for key, value in data.items():
                        if isinstance(value, str) and value.startswith("ENCRYPTED:"):
                            config_key = value.replace("ENCRYPTED:", "")
                            decrypted_value = secure_storage.retrieve(f"config_{config_key}")
                            if decrypted_value:
                                data[key] = decrypted_value
                            else:
                                # Remove encrypted keys that can't be decrypted
                                data[key] = None
                except ImportError:
                    import logging
                    logger = logging.getLogger(__name__)
                    logger.warning("Encryption module not available, skipping decryption")
            
            # Filter out metadata and None values
            config_data = {k: v for k, v in data.items() 
                         if not k.startswith('_') and v is not None}
            
            # Create config instance
            config = cls(**config_data)
            
            # Validate if requested
            if validate:
                is_valid, warnings, errors = config.validate_config()
                if not is_valid:
                    import logging
                    logger = logging.getLogger(__name__)
                    logger.error(f"Configuration validation failed: {'; '.join(errors)}")
                    # Try to recover from backup
                    backup_config = cls._load_from_backup(path)
                    if backup_config:
                        logger.info("Recovered configuration from backup")
                        return backup_config
                    else:
                        logger.warning("Using default configuration due to validation failure")
                        return cls()
                
                if warnings:
                    import logging
                    logger = logging.getLogger(__name__)
                    for warning in warnings:
                        logger.warning(f"Configuration warning: {warning}")
            
            return config
            
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to load configuration from {path}: {str(e)}")
            
            # Try to recover from backup
            backup_config = cls._load_from_backup(path)
            if backup_config:
                logger.info("Recovered configuration from backup")
                return backup_config
            
            logger.warning("Using default configuration")
            return cls()
    
    @classmethod
    def _load_from_backup(cls, original_path: Path) -> Optional['BLRCSConfig']:
        """Try to load from backup files"""
        backup_files = sorted(original_path.parent.glob(f"{original_path.stem}.*.bak"), 
                            key=lambda p: p.stat().st_mtime, reverse=True)
        
        for backup_file in backup_files:
            try:
                return cls.load(backup_file, validate=False)
            except Exception:
                continue
        
        return None

# Global configuration instance
_config: Optional[BLRCSConfig] = None

# Enhanced global configuration management
class ConfigManager:
    """Enhanced configuration manager with caching and validation"""
    
    def __init__(self):
        self._config: Optional[BLRCSConfig] = None
        self._config_cache: Dict[str, BLRCSConfig] = {}
        self._lock = threading.RLock()
        self._default_path = Path("config.json")
    
    def get_config(self, environment: str = None, force_reload: bool = False) -> BLRCSConfig:
        """Get configuration for environment"""
        with self._lock:
            cache_key = environment or "default"
            
            if force_reload or cache_key not in self._config_cache:
                try:
                    if environment:
                        config_path = Path(f"config.{environment}.json")
                    else:
                        config_path = self._default_path
                    
                    if config_path.exists():
                        config = BLRCSConfig.load(config_path)
                    else:
                        config = BLRCSConfig()
                    
                    self._config_cache[cache_key] = config
                    
                    # Set as default if no environment specified
                    if not environment:
                        self._config = config
                        
                except Exception:
                    # Fallback to environment-based defaults if loading fails
                    config = BLRCSConfig()
                    self._config_cache[cache_key] = config
                    if not environment:
                        self._config = config
            
            return self._config_cache[cache_key]
    
    def save_config(self, config: BLRCSConfig, environment: str = None):
        """Save configuration for environment"""
        with self._lock:
            if environment:
                config_path = Path(f"config.{environment}.json")
            else:
                config_path = self._default_path
            
            config.save(config_path)
            
            # Update cache
            cache_key = environment or "default"
            self._config_cache[cache_key] = config
            
            if not environment:
                self._config = config
    
    def clear_cache(self):
        """Clear configuration cache"""
        with self._lock:
            self._config_cache.clear()
            self._config = None
    
    def list_environments(self) -> List[str]:
        """List available configuration environments"""
        config_files = Path('.').glob('config.*.json')
        environments = []
        for config_file in config_files:
            parts = config_file.stem.split('.')
            if len(parts) == 2 and parts[0] == 'config':
                environments.append(parts[1])
        return sorted(environments)

# Global configuration manager
_config_manager = ConfigManager()

@lru_cache(maxsize=1)
def get_config(environment: str = None, force_reload: bool = False) -> BLRCSConfig:
    """Get configuration instance with enhanced features"""
    if force_reload:
        get_config.cache_clear()
    return _config_manager.get_config(environment, force_reload)

def save_config(config: BLRCSConfig, environment: str = None):
    """Save configuration"""
    _config_manager.save_config(config, environment)

def get_config_manager() -> ConfigManager:
    """Get configuration manager instance"""
    return _config_manager

def reset_config():
    """Reset configuration (mainly for testing)"""
    _config_manager.clear_cache()
    get_config.cache_clear()

def switch_environment(environment: str) -> BLRCSConfig:
    """Switch to different configuration environment"""
    return get_config(environment, force_reload=True)

def merge_configs(*configs: BLRCSConfig) -> BLRCSConfig:
    """Merge multiple configurations (later configs override earlier ones)"""
    if not configs:
        return BLRCSConfig()
    
    # Start with first config
    merged_data = configs[0].to_dict()
    
    # Merge subsequent configs
    for config in configs[1:]:
        config_data = config.to_dict()
        for key, value in config_data.items():
            if value is not None:  # Only override with non-None values
                merged_data[key] = value
    
    return BLRCSConfig(**{k: v for k, v in merged_data.items() if not k.startswith('_')})

def create_environment_config(base_environment: str, target_environment: str, 
                            overrides: Dict[str, Any] = None) -> BLRCSConfig:
    """Create new environment configuration based on existing one"""
    base_config = get_config(base_environment)
    config_data = base_config.to_dict()
    
    if overrides:
        config_data.update(overrides)
    
    new_config = BLRCSConfig(**{k: v for k, v in config_data.items() if not k.startswith('_')})
    save_config(new_config, target_environment)
    
    return new_config

def parse_rate_limit(rate_limit_str: str) -> tuple:
    """Parse rate limit string like '100/minute' to (count, seconds)"""
    parts = rate_limit_str.split('/')
    if len(parts) != 2:
        raise ValueError(f"Invalid rate limit format: {rate_limit_str}")
    
    count = int(parts[0])
    period = parts[1].lower()
    
    periods = {
        'second': 1,
        'minute': 60, 
        'hour': 3600,
        'day': 86400
    }
    
    if period not in periods:
        raise ValueError(f"Invalid rate limit period: {period}")
    
    return count, periods[period]
