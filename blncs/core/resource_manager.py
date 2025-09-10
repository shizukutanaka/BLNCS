"""
Resource Management System for BLNCS
Handles proper cleanup of threads, connections, and other resources.
"""

import threading
import weakref
import atexit
import signal
import time
from typing import Dict, Set, Optional, Callable, Any, Protocol
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass
from enum import Enum

from .logger import get_logger


class ResourceType(Enum):
    """Types of resources that need management"""
    THREAD = "thread"
    CONNECTION = "connection"
    FILE_HANDLE = "file_handle"
    PROCESS = "process"
    CACHE = "cache"
    SUBSCRIPTION = "subscription"


@dataclass
class ResourceInfo:
    """Information about a managed resource"""
    resource_id: str
    resource_type: ResourceType
    resource: Any
    cleanup_func: Optional[Callable] = None
    created_at: float = 0
    description: str = ""


class ManagedResource(Protocol):
    """Protocol for resources that can be managed"""
    def cleanup(self) -> None:
        """Cleanup the resource"""
        ...


class ResourceManager:
    """Centralized resource management with proper cleanup"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self._resources: Dict[str, ResourceInfo] = {}
        self._lock = threading.RLock()
        self._shutdown_requested = threading.Event()
        self._cleanup_handlers: Set[Callable] = set()
        
        # Register cleanup on exit
        atexit.register(self.shutdown_all)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, initiating shutdown")
        self.shutdown_all()
    
    def register_resource(self, resource_id: str, resource: Any, 
                         resource_type: ResourceType, cleanup_func: Optional[Callable] = None,
                         description: str = "") -> None:
        """Register a resource for management"""
        with self._lock:
            if resource_id in self._resources:
                self.logger.warning(f"Resource {resource_id} already registered, replacing")
            
            self._resources[resource_id] = ResourceInfo(
                resource_id=resource_id,
                resource_type=resource_type,
                resource=resource,
                cleanup_func=cleanup_func,
                created_at=time.time(),
                description=description
            )
        
        self.logger.debug(f"Registered resource: {resource_id} ({resource_type.value})")
    
    def unregister_resource(self, resource_id: str, cleanup: bool = True) -> bool:
        """Unregister and optionally cleanup a resource"""
        with self._lock:
            resource_info = self._resources.get(resource_id)
            if not resource_info:
                return False
            
            if cleanup:
                self._cleanup_resource(resource_info)
            
            del self._resources[resource_id]
        
        self.logger.debug(f"Unregistered resource: {resource_id}")
        return True
    
    def _cleanup_resource(self, resource_info: ResourceInfo) -> None:
        """Cleanup a single resource"""
        try:
            if resource_info.cleanup_func:
                resource_info.cleanup_func()
            elif hasattr(resource_info.resource, 'cleanup'):
                resource_info.resource.cleanup()
            elif hasattr(resource_info.resource, 'close'):
                resource_info.resource.close()
            elif resource_info.resource_type == ResourceType.THREAD:
                # Handle thread cleanup
                thread = resource_info.resource
                if isinstance(thread, threading.Thread) and thread.is_alive():
                    thread.join(timeout=2.0)
                    if thread.is_alive():
                        self.logger.warning(f"Thread {resource_info.resource_id} did not shutdown gracefully")
            
            self.logger.debug(f"Cleaned up resource: {resource_info.resource_id}")
        
        except Exception as e:
            self.logger.error(f"Error cleaning up resource {resource_info.resource_id}: {e}")
    
    def get_resource_stats(self) -> Dict[str, Any]:
        """Get statistics about managed resources"""
        with self._lock:
            stats = {
                'total_resources': len(self._resources),
                'by_type': {},
                'oldest_resource_age': 0
            }
            
            current_time = time.time()
            oldest_age = 0
            
            for resource_info in self._resources.values():
                resource_type = resource_info.resource_type.value
                stats['by_type'][resource_type] = stats['by_type'].get(resource_type, 0) + 1
                
                age = current_time - resource_info.created_at
                if age > oldest_age:
                    oldest_age = age
            
            stats['oldest_resource_age'] = oldest_age
            return stats
    
    def add_cleanup_handler(self, handler: Callable) -> None:
        """Add a cleanup handler to be called during shutdown"""
        with self._lock:
            self._cleanup_handlers.add(handler)
    
    def remove_cleanup_handler(self, handler: Callable) -> None:
        """Remove a cleanup handler"""
        with self._lock:
            self._cleanup_handlers.discard(handler)
    
    def shutdown_all(self) -> None:
        """Shutdown all managed resources"""
        if self._shutdown_requested.is_set():
            return
        
        self._shutdown_requested.set()
        self.logger.info("Starting resource manager shutdown")
        
        # Call custom cleanup handlers first
        with self._lock:
            for handler in self._cleanup_handlers.copy():
                try:
                    handler()
                except Exception as e:
                    self.logger.error(f"Error in cleanup handler: {e}")
        
        # Cleanup all registered resources
        with self._lock:
            resources_to_cleanup = list(self._resources.values())
        
        for resource_info in resources_to_cleanup:
            self._cleanup_resource(resource_info)
        
        with self._lock:
            self._resources.clear()
        
        self.logger.info("Resource manager shutdown complete")
    
    def is_shutdown(self) -> bool:
        """Check if shutdown has been requested"""
        return self._shutdown_requested.is_set()
    
    @contextmanager
    def managed_thread(self, thread_name: str, target: Callable, 
                      args: tuple = (), kwargs: dict = None, daemon: bool = False):
        """Context manager for managed threads"""
        if kwargs is None:
            kwargs = {}
        
        stop_event = threading.Event()
        thread = threading.Thread(
            target=target,
            args=args + (stop_event,),
            kwargs=kwargs,
            name=thread_name,
            daemon=daemon
        )
        
        resource_id = f"thread_{thread_name}_{id(thread)}"
        
        # Register cleanup function
        def cleanup_thread():
            stop_event.set()
            if thread.is_alive():
                thread.join(timeout=3.0)
                if thread.is_alive():
                    self.logger.warning(f"Thread {thread_name} did not stop gracefully")
        
        self.register_resource(
            resource_id=resource_id,
            resource=thread,
            resource_type=ResourceType.THREAD,
            cleanup_func=cleanup_thread,
            description=f"Managed thread: {thread_name}"
        )
        
        try:
            thread.start()
            yield thread
        finally:
            self.unregister_resource(resource_id, cleanup=True)
    
    @contextmanager
    def managed_connection(self, connection_id: str, connection: Any):
        """Context manager for managed connections"""
        self.register_resource(
            resource_id=connection_id,
            resource=connection,
            resource_type=ResourceType.CONNECTION,
            description=f"Managed connection: {connection_id}"
        )
        
        try:
            yield connection
        finally:
            self.unregister_resource(connection_id, cleanup=True)


# Global resource manager instance
_resource_manager: Optional[ResourceManager] = None
_manager_lock = threading.Lock()


def get_resource_manager() -> ResourceManager:
    """Get global resource manager instance"""
    global _resource_manager
    if _resource_manager is None:
        with _manager_lock:
            if _resource_manager is None:
                _resource_manager = ResourceManager()
    return _resource_manager


# Convenience functions
def register_resource(resource_id: str, resource: Any, resource_type: ResourceType, 
                     cleanup_func: Optional[Callable] = None, description: str = "") -> None:
    """Register a resource with the global manager"""
    manager = get_resource_manager()
    manager.register_resource(resource_id, resource, resource_type, cleanup_func, description)


def unregister_resource(resource_id: str, cleanup: bool = True) -> bool:
    """Unregister a resource from the global manager"""
    manager = get_resource_manager()
    return manager.unregister_resource(resource_id, cleanup)


def managed_thread(thread_name: str, target: Callable, args: tuple = (), 
                  kwargs: dict = None, daemon: bool = False):
    """Context manager for managed threads"""
    manager = get_resource_manager()
    return manager.managed_thread(thread_name, target, args, kwargs, daemon)


def managed_connection(connection_id: str, connection: Any):
    """Context manager for managed connections"""
    manager = get_resource_manager()
    return manager.managed_connection(connection_id, connection)


def shutdown_all_resources():
    """Shutdown all managed resources"""
    manager = get_resource_manager()
    manager.shutdown_all()