#!/usr/bin/env python3
"""
Comprehensive plugin architecture with hot-swapping for BLNCS
Enables dynamic loading, unloading, and reloading of plugins without system restart
"""

import asyncio
import importlib
import importlib.util
import inspect
import os
import sys
import threading
import weakref
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Type, Callable, Union
import logging
import time
import hashlib
import json
import concurrent.futures

from blncs.core.dependency_injection import Container, DependencyScope
from blncs.core.async_memory_manager import get_async_resource_tracker, track_async_task
from blncs.core.exceptions import BLNCSError

logger = logging.getLogger(__name__)

class PluginState(Enum):
    """Plugin lifecycle states"""
    UNLOADED = "unloaded"
    LOADING = "loading"
    LOADED = "loaded"
    INITIALIZING = "initializing" 
    ACTIVE = "active"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"
    HOTSWAPPING = "hotswapping"

class PluginType(Enum):
    """Plugin types and categories"""
    CORE = "core"
    EXTENSION = "extension"
    MIDDLEWARE = "middleware"
    HANDLER = "handler"
    PROCESSOR = "processor"
    MONITOR = "monitor"
    CONNECTOR = "connector"

@dataclass
class PluginMetadata:
    """Plugin metadata and configuration"""
    name: str
    version: str
    description: str
    author: str
    plugin_type: PluginType
    dependencies: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    api_version: str = "1.0"
    min_blncs_version: str = "1.0.0"
    permissions: List[str] = field(default_factory=list)
    config_schema: Dict[str, Any] = field(default_factory=dict)
    hot_reloadable: bool = True
    auto_start: bool = True

@dataclass
class PluginInfo:
    """Runtime plugin information"""
    metadata: PluginMetadata
    state: PluginState
    module_path: Path
    class_name: str
    instance: Optional['BasePlugin'] = None
    load_time: float = 0
    last_reload: float = 0
    error_count: int = 0
    last_error: Optional[str] = None
    file_hash: Optional[str] = None
    dependencies_resolved: bool = False

class PluginHook:
    """Plugin hook system for event handling"""
    
    def __init__(self, name: str):
        self.name = name
        self.handlers: List[Callable] = []
        self.filters: List[Callable] = []
        self._lock = threading.RLock()
    
    def add_handler(self, handler: Callable, priority: int = 50):
        """Add event handler with priority"""
        with self._lock:
            self.handlers.append((priority, handler))
            self.handlers.sort(key=lambda x: x[0])
    
    def remove_handler(self, handler: Callable):
        """Remove event handler"""
        with self._lock:
            self.handlers = [(p, h) for p, h in self.handlers if h != handler]
    
    def add_filter(self, filter_func: Callable, priority: int = 50):
        """Add filter function"""
        with self._lock:
            self.filters.append((priority, filter_func))
            self.filters.sort(key=lambda x: x[0])
    
    async def emit(self, *args, **kwargs):
        """Emit event to all handlers"""
        results = []
        with self._lock:
            handlers = [(p, h) for p, h in self.handlers]
        
        for priority, handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    result = await handler(*args, **kwargs)
                else:
                    result = handler(*args, **kwargs)
                results.append(result)
            except Exception as e:
                logger.error(f"Error in hook handler {handler}: {e}")
        
        return results
    
    async def filter(self, value: Any, *args, **kwargs) -> Any:
        """Apply filters to value"""
        with self._lock:
            filters = [(p, f) for p, f in self.filters]
        
        current_value = value
        for priority, filter_func in filters:
            try:
                if asyncio.iscoroutinefunction(filter_func):
                    current_value = await filter_func(current_value, *args, **kwargs)
                else:
                    current_value = filter_func(current_value, *args, **kwargs)
            except Exception as e:
                logger.error(f"Error in filter {filter_func}: {e}")
        
        return current_value

class BasePlugin(ABC):
    """Base class for all BLNCS plugins"""
    
    def __init__(self, container: Optional[Container] = None):
        self.container = container or Container()
        self.config: Dict[str, Any] = {}
        self.hooks: Dict[str, PluginHook] = {}
        self.logger = logging.getLogger(f"plugin.{self.__class__.__name__}")
        self._state = PluginState.UNLOADED
        self._tasks: Set[asyncio.Task] = set()
        self._resources: List[Any] = []
        
    @property
    def state(self) -> PluginState:
        return self._state
    
    @abstractmethod
    async def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize plugin with configuration"""
        pass
    
    @abstractmethod
    async def start(self) -> bool:
        """Start plugin operations"""
        pass
    
    @abstractmethod
    async def stop(self) -> bool:
        """Stop plugin operations"""
        pass
    
    async def cleanup(self) -> bool:
        """Cleanup plugin resources"""
        # Cancel all tasks
        for task in list(self._tasks):
            if not task.done():
                task.cancel()
        
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
            self._tasks.clear()
        
        # Cleanup resources
        for resource in self._resources:
            try:
                if hasattr(resource, 'close'):
                    if asyncio.iscoroutinefunction(resource.close):
                        await resource.close()
                    else:
                        resource.close()
                elif hasattr(resource, 'cleanup'):
                    if asyncio.iscoroutinefunction(resource.cleanup):
                        await resource.cleanup()
                    else:
                        resource.cleanup()
            except Exception as e:
                self.logger.warning(f"Error cleaning up resource {resource}: {e}")
        
        self._resources.clear()
        return True
    
    def add_hook(self, name: str) -> PluginHook:
        """Add plugin hook"""
        if name not in self.hooks:
            self.hooks[name] = PluginHook(name)
        return self.hooks[name]
    
    def add_task(self, coro):
        """Add async task to plugin"""
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task
    
    def add_resource(self, resource: Any):
        """Add resource for cleanup tracking"""
        self._resources.append(resource)
        return resource
    
    @classmethod
    @abstractmethod
    def get_metadata(cls) -> PluginMetadata:
        """Get plugin metadata"""
        pass

class PluginManager:
    """Main plugin manager with hot-swapping support"""
    
    def __init__(self, plugin_dirs: List[Path], container: Optional[Container] = None):
        self.plugin_dirs = [Path(d) for d in plugin_dirs]
        self.container = container or Container()
        self.plugins: Dict[str, PluginInfo] = {}
        self.hooks: Dict[str, PluginHook] = {}
        self._lock = asyncio.Lock()
        self._file_watcher_task: Optional[asyncio.Task] = None
        self._resource_tracker = get_async_resource_tracker()
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)
        
        # Built-in hooks
        self._register_builtin_hooks()
    
    def _register_builtin_hooks(self):
        """Register built-in system hooks"""
        builtin_hooks = [
            'plugin.before_load',
            'plugin.after_load', 
            'plugin.before_unload',
            'plugin.after_unload',
            'plugin.error',
            'system.startup',
            'system.shutdown',
            'lightning.payment_received',
            'lightning.payment_sent',
            'lightning.channel_opened',
            'lightning.channel_closed'
        ]
        
        for hook_name in builtin_hooks:
            self.hooks[hook_name] = PluginHook(hook_name)
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.start_file_watcher()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.shutdown()
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate hash of plugin file for change detection"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return ""
    
    async def _discover_plugins(self) -> List[Path]:
        """Discover plugin files in plugin directories"""
        plugin_files = []
        
        for plugin_dir in self.plugin_dirs:
            if not plugin_dir.exists():
                continue
            
            for file_path in plugin_dir.rglob("*.py"):
                if file_path.name.startswith("__"):
                    continue
                
                # Quick check if file contains plugin class
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        if 'BasePlugin' in content and 'get_metadata' in content:
                            plugin_files.append(file_path)
                except Exception:
                    continue
        
        return plugin_files
    
    async def _load_plugin_module(self, file_path: Path) -> Optional[type]:
        """Load plugin module and find plugin class"""
        try:
            # Generate module name
            module_name = f"blncs_plugin_{file_path.stem}_{int(time.time())}"
            
            # Load module
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            if not spec or not spec.loader:
                logger.error(f"Cannot load plugin spec from {file_path}")
                return None
            
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            
            # Find plugin class
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (issubclass(obj, BasePlugin) and 
                    obj != BasePlugin and 
                    hasattr(obj, 'get_metadata')):
                    return obj
            
            logger.warning(f"No plugin class found in {file_path}")
            return None
            
        except Exception as e:
            logger.error(f"Error loading plugin module {file_path}: {e}")
            return None
    
    @track_async_task("load_plugin")
    async def load_plugin(self, file_path: Path, force_reload: bool = False) -> bool:
        """Load or reload a plugin"""
        async with self._lock:
            plugin_name = file_path.stem
            
            # Check if already loaded
            if plugin_name in self.plugins and not force_reload:
                logger.debug(f"Plugin {plugin_name} already loaded")
                return True
            
            # Unload existing plugin if reloading
            if plugin_name in self.plugins and force_reload:
                await self.unload_plugin(plugin_name)
            
            logger.info(f"Loading plugin: {plugin_name}")
            
            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)
            
            # Load plugin module
            plugin_class = await self._load_plugin_module(file_path)
            if not plugin_class:
                return False
            
            try:
                # Get metadata
                metadata = plugin_class.get_metadata()
                
                # Create plugin info
                plugin_info = PluginInfo(
                    metadata=metadata,
                    state=PluginState.LOADING,
                    module_path=file_path,
                    class_name=plugin_class.__name__,
                    file_hash=file_hash,
                    load_time=time.time()
                )
                
                # Check dependencies
                if not await self._check_dependencies(plugin_info):
                    logger.error(f"Dependencies not met for plugin {plugin_name}")
                    return False
                
                # Check conflicts
                if not await self._check_conflicts(plugin_info):
                    logger.error(f"Conflicts detected for plugin {plugin_name}")
                    return False
                
                # Emit before_load hook
                await self.hooks['plugin.before_load'].emit(plugin_info)
                
                # Create plugin instance
                plugin_instance = plugin_class(self.container)
                plugin_info.instance = plugin_instance
                plugin_info.state = PluginState.LOADED
                
                # Register plugin
                self.plugins[plugin_name] = plugin_info
                
                # Initialize if auto_start
                if metadata.auto_start:
                    await self.initialize_plugin(plugin_name)
                    await self.start_plugin(plugin_name)
                
                # Emit after_load hook
                await self.hooks['plugin.after_load'].emit(plugin_info)
                
                logger.info(f"Successfully loaded plugin: {plugin_name} v{metadata.version}")
                return True
                
            except Exception as e:
                logger.error(f"Error loading plugin {plugin_name}: {e}")
                if plugin_name in self.plugins:
                    self.plugins[plugin_name].state = PluginState.ERROR
                    self.plugins[plugin_name].last_error = str(e)
                await self.hooks['plugin.error'].emit(plugin_name, e)
                return False
    
    @track_async_task("unload_plugin")
    async def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a plugin"""
        async with self._lock:
            if plugin_name not in self.plugins:
                logger.warning(f"Plugin {plugin_name} not found")
                return False
            
            plugin_info = self.plugins[plugin_name]
            logger.info(f"Unloading plugin: {plugin_name}")
            
            try:
                # Emit before_unload hook
                await self.hooks['plugin.before_unload'].emit(plugin_info)
                
                # Stop plugin if running
                if plugin_info.state == PluginState.ACTIVE:
                    await self.stop_plugin(plugin_name)
                
                # Cleanup plugin
                if plugin_info.instance:
                    await plugin_info.instance.cleanup()
                
                # Remove from container
                # TODO: Implement container cleanup for plugin services
                
                # Remove plugin
                del self.plugins[plugin_name]
                
                # Emit after_unload hook
                await self.hooks['plugin.after_unload'].emit(plugin_name)
                
                logger.info(f"Successfully unloaded plugin: {plugin_name}")
                return True
                
            except Exception as e:
                logger.error(f"Error unloading plugin {plugin_name}: {e}")
                plugin_info.state = PluginState.ERROR
                plugin_info.last_error = str(e)
                await self.hooks['plugin.error'].emit(plugin_name, e)
                return False
    
    async def initialize_plugin(self, plugin_name: str, config: Optional[Dict[str, Any]] = None) -> bool:
        """Initialize a loaded plugin"""
        if plugin_name not in self.plugins:
            return False
        
        plugin_info = self.plugins[plugin_name]
        if not plugin_info.instance:
            return False
        
        try:
            plugin_info.state = PluginState.INITIALIZING
            
            # Use provided config or default
            plugin_config = config or {}
            
            result = await plugin_info.instance.initialize(plugin_config)
            
            if result:
                plugin_info.instance.config = plugin_config
                logger.info(f"Plugin {plugin_name} initialized successfully")
            else:
                plugin_info.state = PluginState.ERROR
                plugin_info.last_error = "Initialization failed"
            
            return result
            
        except Exception as e:
            logger.error(f"Error initializing plugin {plugin_name}: {e}")
            plugin_info.state = PluginState.ERROR
            plugin_info.last_error = str(e)
            return False
    
    async def start_plugin(self, plugin_name: str) -> bool:
        """Start an initialized plugin"""
        if plugin_name not in self.plugins:
            return False
        
        plugin_info = self.plugins[plugin_name]
        if not plugin_info.instance:
            return False
        
        try:
            result = await plugin_info.instance.start()
            
            if result:
                plugin_info.state = PluginState.ACTIVE
                logger.info(f"Plugin {plugin_name} started successfully")
            else:
                plugin_info.state = PluginState.ERROR
                plugin_info.last_error = "Start failed"
            
            return result
            
        except Exception as e:
            logger.error(f"Error starting plugin {plugin_name}: {e}")
            plugin_info.state = PluginState.ERROR
            plugin_info.last_error = str(e)
            return False
    
    async def stop_plugin(self, plugin_name: str) -> bool:
        """Stop an active plugin"""
        if plugin_name not in self.plugins:
            return False
        
        plugin_info = self.plugins[plugin_name]
        if not plugin_info.instance:
            return False
        
        try:
            plugin_info.state = PluginState.STOPPING
            
            result = await plugin_info.instance.stop()
            
            if result:
                plugin_info.state = PluginState.STOPPED
                logger.info(f"Plugin {plugin_name} stopped successfully")
            else:
                plugin_info.state = PluginState.ERROR
                plugin_info.last_error = "Stop failed"
            
            return result
            
        except Exception as e:
            logger.error(f"Error stopping plugin {plugin_name}: {e}")
            plugin_info.state = PluginState.ERROR
            plugin_info.last_error = str(e)
            return False
    
    async def reload_plugin(self, plugin_name: str) -> bool:
        """Hot-reload a plugin"""
        if plugin_name not in self.plugins:
            logger.warning(f"Cannot reload unknown plugin: {plugin_name}")
            return False
        
        plugin_info = self.plugins[plugin_name]
        
        if not plugin_info.metadata.hot_reloadable:
            logger.warning(f"Plugin {plugin_name} is not hot-reloadable")
            return False
        
        logger.info(f"Hot-reloading plugin: {plugin_name}")
        
        try:
            plugin_info.state = PluginState.HOTSWAPPING
            
            # Save current config
            current_config = plugin_info.instance.config if plugin_info.instance else {}
            
            # Reload the plugin
            success = await self.load_plugin(plugin_info.module_path, force_reload=True)
            
            if success and plugin_name in self.plugins:
                # Restore config and start if it was running
                await self.initialize_plugin(plugin_name, current_config)
                await self.start_plugin(plugin_name)
                
                self.plugins[plugin_name].last_reload = time.time()
                logger.info(f"Successfully hot-reloaded plugin: {plugin_name}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error hot-reloading plugin {plugin_name}: {e}")
            if plugin_name in self.plugins:
                self.plugins[plugin_name].state = PluginState.ERROR
                self.plugins[plugin_name].last_error = str(e)
            return False
    
    async def _check_dependencies(self, plugin_info: PluginInfo) -> bool:
        """Check if plugin dependencies are satisfied"""
        for dep in plugin_info.metadata.dependencies:
            if dep not in self.plugins:
                logger.error(f"Missing dependency {dep} for plugin {plugin_info.metadata.name}")
                return False
            
            dep_plugin = self.plugins[dep]
            if dep_plugin.state not in [PluginState.LOADED, PluginState.ACTIVE]:
                logger.error(f"Dependency {dep} not loaded for plugin {plugin_info.metadata.name}")
                return False
        
        plugin_info.dependencies_resolved = True
        return True
    
    async def _check_conflicts(self, plugin_info: PluginInfo) -> bool:
        """Check for plugin conflicts"""
        for conflict in plugin_info.metadata.conflicts:
            if conflict in self.plugins:
                conflicting_plugin = self.plugins[conflict]
                if conflicting_plugin.state in [PluginState.LOADED, PluginState.ACTIVE]:
                    logger.error(f"Conflict with plugin {conflict} for plugin {plugin_info.metadata.name}")
                    return False
        
        return True
    
    async def start_file_watcher(self):
        """Start watching plugin files for changes"""
        if self._file_watcher_task:
            return
        
        self._file_watcher_task = asyncio.create_task(self._file_watcher_loop())
        task_id = self._resource_tracker.register_task(self._file_watcher_task, "plugin_file_watcher")
        self._file_watcher_task._blncs_task_id = task_id
    
    async def _file_watcher_loop(self):
        """File watcher loop for hot-reloading"""
        file_hashes = {}
        
        while True:
            try:
                await asyncio.sleep(2.0)  # Check every 2 seconds
                
                # Check for changes in loaded plugins
                for plugin_name, plugin_info in list(self.plugins.items()):
                    if not plugin_info.metadata.hot_reloadable:
                        continue
                    
                    current_hash = self._calculate_file_hash(plugin_info.module_path)
                    
                    if plugin_info.file_hash != current_hash:
                        logger.info(f"Detected changes in plugin {plugin_name}, reloading...")
                        await self.reload_plugin(plugin_name)
                
                # Discover new plugins
                plugin_files = await self._discover_plugins()
                for file_path in plugin_files:
                    plugin_name = file_path.stem
                    if plugin_name not in self.plugins:
                        logger.info(f"Discovered new plugin: {plugin_name}")
                        await self.load_plugin(file_path)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in file watcher: {e}")
                await asyncio.sleep(5.0)
    
    async def load_all_plugins(self) -> Dict[str, bool]:
        """Load all discovered plugins"""
        plugin_files = await self._discover_plugins()
        results = {}
        
        for file_path in plugin_files:
            plugin_name = file_path.stem
            success = await self.load_plugin(file_path)
            results[plugin_name] = success
        
        return results
    
    def get_plugin_info(self, plugin_name: str) -> Optional[PluginInfo]:
        """Get plugin information"""
        return self.plugins.get(plugin_name)
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """List all plugins with their status"""
        return [
            {
                'name': info.metadata.name,
                'version': info.metadata.version,
                'state': info.state.value,
                'type': info.metadata.plugin_type.value,
                'auto_start': info.metadata.auto_start,
                'hot_reloadable': info.metadata.hot_reloadable,
                'dependencies': info.metadata.dependencies,
                'load_time': info.load_time,
                'last_reload': info.last_reload,
                'error_count': info.error_count,
                'last_error': info.last_error
            }
            for info in self.plugins.values()
        ]
    
    def get_hook(self, name: str) -> PluginHook:
        """Get or create a hook"""
        if name not in self.hooks:
            self.hooks[name] = PluginHook(name)
        return self.hooks[name]
    
    async def emit_hook(self, name: str, *args, **kwargs):
        """Emit hook to all registered handlers"""
        if name in self.hooks:
            return await self.hooks[name].emit(*args, **kwargs)
        return []
    
    async def shutdown(self):
        """Shutdown plugin manager"""
        logger.info("Shutting down plugin manager")
        
        # Stop file watcher
        if self._file_watcher_task:
            self._file_watcher_task.cancel()
            try:
                await self._file_watcher_task
            except asyncio.CancelledError:
                pass
        
        # Stop all plugins
        for plugin_name in list(self.plugins.keys()):
            await self.stop_plugin(plugin_name)
            await self.unload_plugin(plugin_name)
        
        # Shutdown executor
        self._executor.shutdown(wait=True)
        
        logger.info("Plugin manager shutdown completed")

# Plugin registry for easy plugin development
class PluginRegistry:
    """Registry for plugin registration and discovery"""
    
    _plugins: Dict[str, Type[BasePlugin]] = {}
    
    @classmethod
    def register(cls, plugin_class: Type[BasePlugin]):
        """Register a plugin class"""
        metadata = plugin_class.get_metadata()
        cls._plugins[metadata.name] = plugin_class
        return plugin_class
    
    @classmethod
    def get_plugin(cls, name: str) -> Optional[Type[BasePlugin]]:
        """Get registered plugin by name"""
        return cls._plugins.get(name)
    
    @classmethod
    def list_registered(cls) -> List[str]:
        """List all registered plugin names"""
        return list(cls._plugins.keys())

# Decorator for plugin registration
def register_plugin(plugin_class: Type[BasePlugin]):
    """Decorator to register a plugin"""
    return PluginRegistry.register(plugin_class)

# Factory function
async def create_plugin_manager(plugin_dirs: List[str], container: Optional[Container] = None) -> PluginManager:
    """Create and initialize plugin manager"""
    plugin_paths = [Path(d) for d in plugin_dirs]
    manager = PluginManager(plugin_paths, container)
    
    # Ensure plugin directories exist
    for plugin_dir in plugin_paths:
        plugin_dir.mkdir(parents=True, exist_ok=True)
    
    return manager

# Export main classes and functions
__all__ = [
    'BasePlugin',
    'PluginManager',
    'PluginMetadata',
    'PluginInfo', 
    'PluginState',
    'PluginType',
    'PluginHook',
    'PluginRegistry',
    'register_plugin',
    'create_plugin_manager'
]