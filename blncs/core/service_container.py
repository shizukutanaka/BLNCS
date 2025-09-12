"""
Lightweight Service Container for BLNCS
Simple dependency injection without complexity overhead.
"""

from typing import Dict, Any, Optional, Callable, TypeVar, Type
import threading
import weakref
from functools import wraps

from .logger import get_logger

T = TypeVar('T')


class ServiceContainer:
    """Lightweight service container for dependency management"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self._services: Dict[str, Any] = {}
        self._factories: Dict[str, Callable] = {}
        self._singletons: Dict[str, Any] = {}
        self._lock = threading.RLock()
    
    def register_singleton(self, name: str, factory: Callable[[], T]) -> None:
        """Register a singleton service"""
        with self._lock:
            self._factories[name] = factory
            if name in self._singletons:
                del self._singletons[name]  # Force re-creation
        
        self.logger.debug(f"Registered singleton service: {name}")
    
    def register_factory(self, name: str, factory: Callable[[], T]) -> None:
        """Register a factory service (new instance each time)"""
        with self._lock:
            self._factories[name] = factory
        
        self.logger.debug(f"Registered factory service: {name}")
    
    def register_instance(self, name: str, instance: Any) -> None:
        """Register an existing instance"""
        with self._lock:
            self._services[name] = instance
        
        self.logger.debug(f"Registered instance: {name}")
    
    def get(self, name: str) -> Any:
        """Get service by name"""
        with self._lock:
            # Check for direct instance first
            if name in self._services:
                return self._services[name]
            
            # Check for singleton
            if name in self._singletons:
                return self._singletons[name]
            
            # Check for factory
            if name in self._factories:
                instance = self._factories[name]()
                
                # Cache as singleton if it was registered as one
                # (we can distinguish by checking if get_singleton was called)
                if hasattr(self, '_singleton_names') and name in self._singleton_names:
                    self._singletons[name] = instance
                
                return instance
            
            raise KeyError(f"Service '{name}' not found")
    
    def get_singleton(self, name: str) -> Any:
        """Get singleton service (cached instance)"""
        if not hasattr(self, '_singleton_names'):
            self._singleton_names = set()
        self._singleton_names.add(name)
        
        with self._lock:
            if name in self._singletons:
                return self._singletons[name]
            
            if name in self._factories:
                instance = self._factories[name]()
                self._singletons[name] = instance
                return instance
            
            raise KeyError(f"Singleton service '{name}' not found")
    
    def clear(self) -> None:
        """Clear all services"""
        with self._lock:
            self._services.clear()
            self._factories.clear()
            self._singletons.clear()
        
        self.logger.info("Cleared all services")
    
    def list_services(self) -> Dict[str, str]:
        """List all registered services"""
        with self._lock:
            services = {}
            
            for name in self._services:
                services[name] = "instance"
            
            for name in self._factories:
                if name in self._singletons:
                    services[name] = "singleton"
                else:
                    services[name] = "factory"
            
            return services


# Global service container
_container: Optional[ServiceContainer] = None
_container_lock = threading.Lock()


def get_container() -> ServiceContainer:
    """Get global service container"""
    global _container
    if _container is None:
        with _container_lock:
            if _container is None:
                _container = ServiceContainer()
    return _container


def inject(service_name: str):
    """Decorator to inject service as function parameter"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            container = get_container()
            service = container.get(service_name)
            return func(service, *args, **kwargs)
        return wrapper
    return decorator


# Initialize core services
def initialize_core_services():
    """Initialize core BLNCS services in the container"""
    container = get_container()
    
    # Configuration
    container.register_singleton('config', lambda: get_config_manager())
    
    # Logging
    container.register_factory('logger', lambda: get_logger())
    
    # Cache
    container.register_singleton('cache', lambda: get_cache_manager())
    
    # Database
    container.register_singleton('database', lambda: get_database_manager())
    
    # Health checker
    container.register_singleton('health', lambda: get_health_checker())
    
    # Validator
    container.register_singleton('validator', lambda: get_validator())
    
    # Security manager
    container.register_singleton('security', lambda: get_security_manager())
    
    # Monitor
    container.register_singleton('monitor', lambda: get_monitor())
    
    # Fee optimizer
    container.register_singleton('fee_optimizer', lambda: get_fee_optimizer())
    
    # Channel manager
    container.register_singleton('channel_manager', lambda: get_channel_manager())
    
    # Connection pool
    container.register_singleton('connection_pool', lambda: get_connection_pool())
    
    # Backup manager
    container.register_singleton('backup_manager', lambda: get_backup_manager())
    
    # Recovery system
    container.register_singleton('recovery', lambda: get_recovery_system())
    
    # Unified monitoring
    container.register_singleton('monitoring', lambda: get_unified_monitoring())


# Lazy imports for core services
def get_config_manager():
    from .config_manager import get_config_manager as _get
    return _get()

def get_cache_manager():
    from .cache_unified import get_cache_manager as _get
    return _get()

def get_database_manager():
    from .database import get_database_manager as _get
    return _get()

def get_health_checker():
    from .health import get_health_checker as _get
    return _get()

def get_validator():
    from .input_validator import get_enhanced_validator as _get
    return _get()

def get_security_manager():
    from ..security import get_security_manager as _get
    return _get()

def get_monitor():
    from .monitoring_unified import get_monitor as _get
    return _get()

def get_fee_optimizer():
    from .fee_optimizer import get_fee_optimizer as _get
    return _get()

def get_channel_manager():
    from ..lightning.channel_manager import get_channel_manager as _get
    return _get()

def get_connection_pool():
    from .connection_pool_unified import get_connection_pool as _get_pool
    return _get_pool()

def get_backup_manager():
    from .backup_enhanced import SimpleBackup
    return SimpleBackup()

def get_recovery_system():
    from .advanced_error_recovery import get_error_recovery as _get
    return _get()

def get_unified_monitoring():
    from .monitoring_unified import get_unified_monitoring as _get
    return _get()


# Auto-initialize when module is imported
initialize_core_services()