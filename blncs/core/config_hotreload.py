#!/usr/bin/env python3
"""
Configuration Hot-Reload System for BLNCS
Implements runtime configuration updates with file watching and validation
"""

import asyncio
import hashlib
import json
import os
import time
import yaml
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Callable, Union
import logging
import threading
import weakref
from contextlib import asynccontextmanager
import copy

from blncs.core.async_memory_manager import track_async_task, lightning_operation_context
from blncs.core.exceptions import BLNCSError
from blncs.core.config_manager import get_config_manager

logger = logging.getLogger(__name__)

class ConfigChangeType(Enum):
    """Configuration change types"""
    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"
    MOVED = "moved"

class ReloadStrategy(Enum):
    """Configuration reload strategies"""
    IMMEDIATE = "immediate"        # Apply changes immediately
    BATCHED = "batched"           # Batch changes over time window
    MANUAL = "manual"             # Require manual trigger
    GRACEFUL = "graceful"         # Wait for safe points to reload

@dataclass
class ConfigChange:
    """Configuration change event"""
    file_path: Path
    change_type: ConfigChangeType
    timestamp: float
    old_content: Optional[str] = None
    new_content: Optional[str] = None
    old_hash: Optional[str] = None
    new_hash: Optional[str] = None
    
@dataclass
class ValidationResult:
    """Configuration validation result"""
    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    changes: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ReloadResult:
    """Configuration reload result"""
    success: bool
    applied_changes: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    reload_time: float = 0.0
    components_reloaded: List[str] = field(default_factory=list)

class ConfigValidator:
    """Configuration validation engine"""
    
    def __init__(self):
        self.validation_rules: Dict[str, List[Callable]] = {}
        self.required_fields: Dict[str, Set[str]] = {}
        self.field_types: Dict[str, Dict[str, type]] = {}
        self.range_constraints: Dict[str, Dict[str, tuple]] = {}
        
        # Setup default validation rules
        self._setup_default_rules()
    
    def _setup_default_rules(self):
        """Setup default validation rules for BLNCS configuration"""
        # Lightning configuration rules
        self.required_fields['lightning'] = {
            'host', 'port', 'network'
        }
        
        self.field_types['lightning'] = {
            'host': str,
            'port': int,
            'network': str,
            'timeout': (int, float),
            'max_channels': int,
            'max_htlc_msat': int
        }
        
        self.range_constraints['lightning'] = {
            'port': (1, 65535),
            'timeout': (1, 300),
            'max_channels': (1, 10000),
            'max_htlc_msat': (1000, 1000000000000)  # 1k to 1M sats in msat
        }
        
        # Database configuration rules
        self.required_fields['database'] = {
            'path'
        }
        
        self.field_types['database'] = {
            'path': str,
            'pool_size': int,
            'timeout': (int, float),
            'wal_mode': bool
        }
        
        self.range_constraints['database'] = {
            'pool_size': (1, 100),
            'timeout': (1, 3600)
        }
        
        # Security configuration rules
        self.field_types['security'] = {
            'jwt_secret': str,
            'rate_limit_requests': int,
            'rate_limit_window': int,
            'max_connections': int
        }
        
        self.range_constraints['security'] = {
            'rate_limit_requests': (1, 100000),
            'rate_limit_window': (1, 3600),
            'max_connections': (1, 10000)
        }
    
    def add_validation_rule(self, section: str, rule: Callable[[Dict[str, Any]], List[str]]):
        """Add custom validation rule"""
        if section not in self.validation_rules:
            self.validation_rules[section] = []
        self.validation_rules[section].append(rule)
    
    def validate_config(self, config: Dict[str, Any], previous_config: Optional[Dict[str, Any]] = None) -> ValidationResult:
        """Validate configuration"""
        errors = []
        warnings = []
        changes = {}
        
        try:
            # Validate structure and required fields
            for section, required in self.required_fields.items():
                if section not in config:
                    errors.append(f"Missing required section: {section}")
                    continue
                
                section_config = config[section]
                for field in required:
                    if field not in section_config:
                        errors.append(f"Missing required field: {section}.{field}")
            
            # Validate field types
            for section, types in self.field_types.items():
                if section not in config:
                    continue
                
                section_config = config[section]
                for field, expected_type in types.items():
                    if field not in section_config:
                        continue
                    
                    value = section_config[field]
                    if isinstance(expected_type, tuple):
                        # Multiple allowed types
                        if not any(isinstance(value, t) for t in expected_type):
                            errors.append(f"Invalid type for {section}.{field}: expected {expected_type}, got {type(value)}")
                    else:
                        # Single expected type
                        if not isinstance(value, expected_type):
                            errors.append(f"Invalid type for {section}.{field}: expected {expected_type.__name__}, got {type(value).__name__}")
            
            # Validate range constraints
            for section, constraints in self.range_constraints.items():
                if section not in config:
                    continue
                
                section_config = config[section]
                for field, (min_val, max_val) in constraints.items():
                    if field not in section_config:
                        continue
                    
                    value = section_config[field]
                    if isinstance(value, (int, float)):
                        if value < min_val or value > max_val:
                            errors.append(f"Value out of range for {section}.{field}: {value} not in [{min_val}, {max_val}]")
            
            # Run custom validation rules
            for section, rules in self.validation_rules.items():
                if section not in config:
                    continue
                
                for rule in rules:
                    try:
                        rule_errors = rule(config[section])
                        errors.extend(rule_errors)
                    except Exception as e:
                        errors.append(f"Validation rule error for {section}: {e}")
            
            # Detect changes from previous configuration
            if previous_config:
                changes = self._detect_changes(previous_config, config)
                
                # Add warnings for potentially dangerous changes
                dangerous_changes = ['lightning.network', 'database.path', 'security.jwt_secret']
                for change_key in changes.keys():
                    if change_key in dangerous_changes:
                        warnings.append(f"Potentially dangerous change detected: {change_key}")
            
            return ValidationResult(
                valid=len(errors) == 0,
                errors=errors,
                warnings=warnings,
                changes=changes
            )
            
        except Exception as e:
            return ValidationResult(
                valid=False,
                errors=[f"Validation error: {e}"],
                warnings=warnings,
                changes=changes
            )
    
    def _detect_changes(self, old_config: Dict[str, Any], new_config: Dict[str, Any]) -> Dict[str, Any]:
        """Detect changes between configurations"""
        changes = {}
        
        def _compare_dicts(old_dict: Dict[str, Any], new_dict: Dict[str, Any], prefix: str = ""):
            for key, new_value in new_dict.items():
                full_key = f"{prefix}.{key}" if prefix else key
                
                if key not in old_dict:
                    changes[full_key] = {'type': 'added', 'new_value': new_value}
                elif old_dict[key] != new_value:
                    if isinstance(new_value, dict) and isinstance(old_dict[key], dict):
                        _compare_dicts(old_dict[key], new_value, full_key)
                    else:
                        changes[full_key] = {
                            'type': 'modified',
                            'old_value': old_dict[key],
                            'new_value': new_value
                        }
            
            # Check for deleted keys
            for key in old_dict.keys():
                if key not in new_dict:
                    full_key = f"{prefix}.{key}" if prefix else key
                    changes[full_key] = {'type': 'deleted', 'old_value': old_dict[key]}
        
        _compare_dicts(old_config, new_config)
        return changes

class FileWatcher:
    """File system watcher for configuration files"""
    
    def __init__(self):
        self.watched_files: Dict[Path, Dict[str, Any]] = {}
        self.change_callbacks: List[Callable[[ConfigChange], None]] = []
        self.polling_interval = 1.0  # seconds
        self.watch_task: Optional[asyncio.Task] = None
        self._stop_watching = False
        
    def add_file(self, file_path: Path, callback: Optional[Callable] = None):
        """Add file to watch list"""
        file_path = Path(file_path).resolve()
        
        # Get initial file state
        initial_state = self._get_file_state(file_path)
        self.watched_files[file_path] = initial_state
        
        if callback:
            self.change_callbacks.append(callback)
        
        logger.info(f"Added file to watch list: {file_path}")
    
    def _get_file_state(self, file_path: Path) -> Dict[str, Any]:
        """Get current file state"""
        try:
            if not file_path.exists():
                return {
                    'exists': False,
                    'mtime': 0,
                    'size': 0,
                    'hash': None,
                    'content': None
                }
            
            stat = file_path.stat()
            
            # Read and hash content
            content = file_path.read_text(encoding='utf-8')
            content_hash = hashlib.sha256(content.encode()).hexdigest()
            
            return {
                'exists': True,
                'mtime': stat.st_mtime,
                'size': stat.st_size,
                'hash': content_hash,
                'content': content
            }
            
        except Exception as e:
            logger.error(f"Error getting file state for {file_path}: {e}")
            return {
                'exists': False,
                'mtime': 0,
                'size': 0,
                'hash': None,
                'content': None,
                'error': str(e)
            }
    
    async def start_watching(self):
        """Start file watching"""
        if self.watch_task:
            return
        
        self._stop_watching = False
        self.watch_task = asyncio.create_task(self._watch_loop())
        logger.info("Started file watching")
    
    async def stop_watching(self):
        """Stop file watching"""
        self._stop_watching = True
        
        if self.watch_task:
            self.watch_task.cancel()
            try:
                await self.watch_task
            except asyncio.CancelledError:
                pass
            self.watch_task = None
        
        logger.info("Stopped file watching")
    
    async def _watch_loop(self):
        """Main file watching loop"""
        while not self._stop_watching:
            try:
                changes = []
                
                # Check all watched files
                for file_path, old_state in list(self.watched_files.items()):
                    new_state = self._get_file_state(file_path)
                    
                    # Detect changes
                    if old_state['hash'] != new_state['hash']:
                        change_type = self._determine_change_type(old_state, new_state)
                        
                        change = ConfigChange(
                            file_path=file_path,
                            change_type=change_type,
                            timestamp=time.time(),
                            old_content=old_state.get('content'),
                            new_content=new_state.get('content'),
                            old_hash=old_state.get('hash'),
                            new_hash=new_state.get('hash')
                        )
                        
                        changes.append(change)
                        
                        # Update stored state
                        self.watched_files[file_path] = new_state
                
                # Notify callbacks of changes
                for change in changes:
                    for callback in self.change_callbacks:
                        try:
                            if asyncio.iscoroutinefunction(callback):
                                await callback(change)
                            else:
                                callback(change)
                        except Exception as e:
                            logger.error(f"Error in change callback: {e}")
                
                # Wait before next check
                await asyncio.sleep(self.polling_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in file watch loop: {e}")
                await asyncio.sleep(5.0)
    
    def _determine_change_type(self, old_state: Dict[str, Any], new_state: Dict[str, Any]) -> ConfigChangeType:
        """Determine type of file change"""
        if not old_state['exists'] and new_state['exists']:
            return ConfigChangeType.CREATED
        elif old_state['exists'] and not new_state['exists']:
            return ConfigChangeType.DELETED
        elif old_state['exists'] and new_state['exists']:
            return ConfigChangeType.MODIFIED
        else:
            return ConfigChangeType.MODIFIED  # Fallback

class ConfigHotReloader:
    """Main configuration hot-reload manager"""
    
    def __init__(self, config_manager=None, reload_strategy: ReloadStrategy = ReloadStrategy.GRACEFUL):
        self.config_manager = config_manager or get_config_manager()
        self.reload_strategy = reload_strategy
        self.validator = ConfigValidator()
        self.file_watcher = FileWatcher()
        
        # Reload management
        self.pending_changes: List[ConfigChange] = []
        self.reload_callbacks: Dict[str, List[Callable]] = {}
        self.batch_window = 5.0  # seconds
        self.batch_task: Optional[asyncio.Task] = None
        self.reload_lock = asyncio.Lock()
        
        # Statistics
        self.stats = {
            'reload_count': 0,
            'successful_reloads': 0,
            'failed_reloads': 0,
            'validation_errors': 0,
            'last_reload': None
        }
        
        # Setup file watching
        self.file_watcher.change_callbacks.append(self._on_file_change)
    
    def add_config_file(self, file_path: Union[str, Path]):
        """Add configuration file to watch"""
        file_path = Path(file_path)
        self.file_watcher.add_file(file_path)
    
    def add_reload_callback(self, component: str, callback: Callable[[Dict[str, Any]], None]):
        """Add callback for configuration reloads"""
        if component not in self.reload_callbacks:
            self.reload_callbacks[component] = []
        self.reload_callbacks[component].append(callback)
        logger.info(f"Added reload callback for component: {component}")
    
    async def start(self):
        """Start hot-reload system"""
        # Add current config files to watcher
        config_files = self.config_manager.get_config_files()
        for config_file in config_files:
            self.add_config_file(config_file)
        
        # Start file watching
        await self.file_watcher.start_watching()
        
        logger.info("Configuration hot-reload system started")
    
    async def stop(self):
        """Stop hot-reload system"""
        await self.file_watcher.stop_watching()
        
        if self.batch_task:
            self.batch_task.cancel()
            try:
                await self.batch_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Configuration hot-reload system stopped")
    
    async def _on_file_change(self, change: ConfigChange):
        """Handle file change event"""
        logger.info(f"Configuration file changed: {change.file_path} ({change.change_type.value})")
        
        if self.reload_strategy == ReloadStrategy.IMMEDIATE:
            await self._process_change_immediate(change)
        elif self.reload_strategy == ReloadStrategy.BATCHED:
            await self._process_change_batched(change)
        elif self.reload_strategy == ReloadStrategy.MANUAL:
            self.pending_changes.append(change)
            logger.info("Change queued for manual reload")
        elif self.reload_strategy == ReloadStrategy.GRACEFUL:
            await self._process_change_graceful(change)
    
    async def _process_change_immediate(self, change: ConfigChange):
        """Process change immediately"""
        try:
            reload_result = await self._reload_configuration(change)
            if reload_result.success:
                logger.info(f"Configuration reloaded successfully: {change.file_path}")
            else:
                logger.error(f"Configuration reload failed: {reload_result.errors}")
        except Exception as e:
            logger.error(f"Error processing immediate change: {e}")
    
    async def _process_change_batched(self, change: ConfigChange):
        """Process change with batching"""
        self.pending_changes.append(change)
        
        # Start batch timer if not already running
        if not self.batch_task:
            self.batch_task = asyncio.create_task(self._batch_reload_timer())
    
    async def _process_change_graceful(self, change: ConfigChange):
        """Process change gracefully (wait for safe point)"""
        # For now, treat same as immediate but could add logic to wait for safe points
        await self._process_change_immediate(change)
    
    async def _batch_reload_timer(self):
        """Timer for batched configuration reloads"""
        try:
            await asyncio.sleep(self.batch_window)
            
            if self.pending_changes:
                # Process all pending changes
                changes = list(self.pending_changes)
                self.pending_changes.clear()
                
                logger.info(f"Processing {len(changes)} batched configuration changes")
                
                # Use the most recent change for reload
                latest_change = max(changes, key=lambda c: c.timestamp)
                reload_result = await self._reload_configuration(latest_change)
                
                if reload_result.success:
                    logger.info("Batched configuration reload successful")
                else:
                    logger.error(f"Batched configuration reload failed: {reload_result.errors}")
        
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Error in batch reload timer: {e}")
        finally:
            self.batch_task = None
    
    @track_async_task("reload_configuration")
    async def _reload_configuration(self, change: ConfigChange) -> ReloadResult:
        """Reload configuration with validation and callback execution"""
        async with lightning_operation_context("config_reload"):
            async with self.reload_lock:
                start_time = time.time()
                self.stats['reload_count'] += 1
                
                try:
                    # Load new configuration
                    new_config = await self._load_config_from_file(change.file_path)
                    if not new_config:
                        return ReloadResult(
                            success=False,
                            errors=["Failed to load configuration file"],
                            reload_time=time.time() - start_time
                        )
                    
                    # Get current configuration for comparison
                    old_config = self.config_manager.get_all()
                    
                    # Validate new configuration
                    validation = self.validator.validate_config(new_config, old_config)
                    
                    if not validation.valid:
                        self.stats['validation_errors'] += 1
                        return ReloadResult(
                            success=False,
                            errors=validation.errors,
                            warnings=validation.warnings,
                            reload_time=time.time() - start_time
                        )
                    
                    # Create backup of current config
                    config_backup = copy.deepcopy(old_config)
                    
                    # Apply new configuration
                    self.config_manager.update_config(new_config)
                    
                    # Notify components of changes
                    components_reloaded = []
                    callback_errors = []
                    
                    for component, callbacks in self.reload_callbacks.items():
                        try:
                            # Check if this component's config changed
                            if component in validation.changes or self._component_affected(component, validation.changes):
                                for callback in callbacks:
                                    if asyncio.iscoroutinefunction(callback):
                                        await callback(new_config.get(component, {}))
                                    else:
                                        callback(new_config.get(component, {}))
                                
                                components_reloaded.append(component)
                        
                        except Exception as e:
                            callback_errors.append(f"Error reloading component {component}: {e}")
                            logger.error(f"Error reloading component {component}: {e}")
                            
                            # Rollback on critical errors
                            try:
                                self.config_manager.update_config(config_backup)
                                logger.warning("Configuration rolled back due to callback error")
                            except Exception as rollback_error:
                                logger.error(f"Failed to rollback configuration: {rollback_error}")
                    
                    # Update statistics
                    if callback_errors:
                        self.stats['failed_reloads'] += 1
                    else:
                        self.stats['successful_reloads'] += 1
                    
                    self.stats['last_reload'] = time.time()
                    
                    return ReloadResult(
                        success=len(callback_errors) == 0,
                        applied_changes=validation.changes,
                        errors=callback_errors,
                        warnings=validation.warnings,
                        reload_time=time.time() - start_time,
                        components_reloaded=components_reloaded
                    )
                
                except Exception as e:
                    self.stats['failed_reloads'] += 1
                    logger.error(f"Configuration reload error: {e}")
                    
                    return ReloadResult(
                        success=False,
                        errors=[f"Reload error: {e}"],
                        reload_time=time.time() - start_time
                    )
    
    async def _load_config_from_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Load configuration from file"""
        try:
            if not file_path.exists():
                logger.error(f"Configuration file does not exist: {file_path}")
                return None
            
            content = file_path.read_text(encoding='utf-8')
            
            # Determine file format and parse
            if file_path.suffix.lower() in ['.yml', '.yaml']:
                return yaml.safe_load(content)
            elif file_path.suffix.lower() == '.json':
                return json.loads(content)
            else:
                # Try to parse as YAML first, then JSON
                try:
                    return yaml.safe_load(content)
                except yaml.YAMLError:
                    return json.loads(content)
        
        except Exception as e:
            logger.error(f"Error loading configuration from {file_path}: {e}")
            return None
    
    def _component_affected(self, component: str, changes: Dict[str, Any]) -> bool:
        """Check if component is affected by configuration changes"""
        for change_key in changes.keys():
            if change_key.startswith(f"{component}.") or change_key == component:
                return True
        return False
    
    async def manual_reload(self) -> ReloadResult:
        """Manually trigger configuration reload"""
        if not self.pending_changes:
            return ReloadResult(
                success=True,
                errors=["No pending changes to reload"]
            )
        
        # Process the most recent pending change
        latest_change = max(self.pending_changes, key=lambda c: c.timestamp)
        self.pending_changes.clear()
        
        return await self._reload_configuration(latest_change)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get hot-reload statistics"""
        return {
            **self.stats,
            'watched_files': len(self.file_watcher.watched_files),
            'pending_changes': len(self.pending_changes),
            'registered_callbacks': {
                component: len(callbacks) 
                for component, callbacks in self.reload_callbacks.items()
            },
            'reload_strategy': self.reload_strategy.value
        }

# Factory function
async def create_hotreload_manager(config_manager=None, 
                                 reload_strategy: ReloadStrategy = ReloadStrategy.GRACEFUL) -> ConfigHotReloader:
    """Create configuration hot-reload manager"""
    manager = ConfigHotReloader(config_manager, reload_strategy)
    
    # Add validation rules for common components
    manager.validator.add_validation_rule('lightning', _validate_lightning_config)
    manager.validator.add_validation_rule('security', _validate_security_config)
    
    logger.info(f"Created configuration hot-reload manager with {reload_strategy.value} strategy")
    return manager

# Context manager for hot-reload system
@asynccontextmanager
async def hotreload_system(config_files: List[Union[str, Path]], 
                          config_manager=None,
                          reload_strategy: ReloadStrategy = ReloadStrategy.GRACEFUL):
    """Context manager for configuration hot-reload system"""
    manager = await create_hotreload_manager(config_manager, reload_strategy)
    
    # Add config files
    for config_file in config_files:
        manager.add_config_file(config_file)
    
    try:
        await manager.start()
        yield manager
    finally:
        await manager.stop()

# Validation functions
def _validate_lightning_config(config: Dict[str, Any]) -> List[str]:
    """Validate Lightning Network configuration"""
    errors = []
    
    # Check network values
    valid_networks = ['mainnet', 'testnet', 'regtest', 'signet']
    if 'network' in config and config['network'] not in valid_networks:
        errors.append(f"Invalid network: {config['network']}. Must be one of {valid_networks}")
    
    # Check host format (basic validation)
    if 'host' in config:
        host = config['host']
        if not isinstance(host, str) or len(host) == 0:
            errors.append("Lightning host must be a non-empty string")
    
    return errors

def _validate_security_config(config: Dict[str, Any]) -> List[str]:
    """Validate security configuration"""
    errors = []
    
    # Check JWT secret strength
    if 'jwt_secret' in config:
        secret = config['jwt_secret']
        if len(secret) < 32:
            errors.append("JWT secret must be at least 32 characters long")
    
    return errors

# Export main classes and functions
__all__ = [
    'ConfigChangeType',
    'ReloadStrategy',
    'ConfigChange',
    'ValidationResult',
    'ReloadResult',
    'ConfigValidator',
    'FileWatcher',
    'ConfigHotReloader',
    'create_hotreload_manager',
    'hotreload_system'
]