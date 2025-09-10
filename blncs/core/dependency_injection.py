"""
Comprehensive Dependency Injection System
Enterprise-grade IoC container with lifecycle management and configuration support.
"""

import asyncio
import inspect
import threading
from typing import (
    Dict, List, Set, Optional, Any, Callable, TypeVar, Generic, Type,
    get_type_hints, get_origin, get_args, Union, Protocol, runtime_checkable
)
from typing_extensions import get_origin, get_args, ParamSpec
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from abc import ABC, abstractmethod
import functools
import weakref
from contextlib import asynccontextmanager, contextmanager

from ..core.structured_logging import StructuredLogger
from ..core.type_system import typed, TypeSafetyLevel
from ..core.resource_management import ManagedResource, ResourceType, get_resource_tracker

T = TypeVar('T')
P = ParamSpec('P')


class DependencyScope(Enum):
    """Dependency injection scopes."""
    SINGLETON = "singleton"      # One instance for the entire application
    TRANSIENT = "transient"      # New instance every time
    SCOPED = "scoped"           # One instance per scope (e.g., per request)
    THREAD_LOCAL = "thread_local"  # One instance per thread


class InjectionError(Exception):
    """Dependency injection related errors."""
    pass


class CircularDependencyError(InjectionError):
    """Circular dependency detected."""
    pass


@runtime_checkable
class Injectable(Protocol):
    """Protocol for injectable dependencies."""
    
    def __init__(self, *args, **kwargs):
        """Initialize the injectable."""
        ...


@runtime_checkable
class Configurable(Protocol):
    """Protocol for configurable dependencies."""
    
    def configure(self, config: Dict[str, Any]) -> None:
        """Configure the dependency."""
        ...


@runtime_checkable
class AsyncInitializable(Protocol):
    """Protocol for async initializable dependencies."""
    
    async def initialize(self) -> None:
        """Async initialization."""
        ...
    
    async def cleanup(self) -> None:
        """Async cleanup."""
        ...


@dataclass
class DependencyRegistration:
    """Dependency registration information."""
    interface: Type[T]
    implementation: Type[T]
    scope: DependencyScope
    factory: Optional[Callable[..., T]] = None
    singleton_instance: Optional[T] = None
    configuration: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[Type] = field(default_factory=list)
    registered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    initialization_order: int = 0
    tags: Set[str] = field(default_factory=set)


@dataclass
class InjectionContext:
    """Context for dependency injection resolution."""
    resolution_stack: List[Type] = field(default_factory=list)
    scope_instances: Dict[str, Dict[Type, Any]] = field(default_factory=dict)
    thread_local_instances: Dict[int, Dict[Type, Any]] = field(default_factory=dict)
    request_id: Optional[str] = None
    

class DependencyGraph:
    """Dependency graph for circular dependency detection."""
    
    def __init__(self):
        self.edges: Dict[Type, Set[Type]] = {}
        self.nodes: Set[Type] = set()
        
    def add_dependency(self, dependent: Type, dependency: Type) -> None:
        """Add a dependency relationship."""
        self.nodes.add(dependent)
        self.nodes.add(dependency)
        
        if dependent not in self.edges:
            self.edges[dependent] = set()
        self.edges[dependent].add(dependency)
    
    def has_circular_dependency(self) -> Optional[List[Type]]:
        """Check for circular dependencies using DFS."""
        visited = set()
        rec_stack = set()
        
        def dfs(node: Type, path: List[Type]) -> Optional[List[Type]]:
            visited.add(node)
            rec_stack.add(node)
            path.append(node)
            
            for neighbor in self.edges.get(node, []):
                if neighbor not in visited:
                    result = dfs(neighbor, path.copy())
                    if result:
                        return result
                elif neighbor in rec_stack:
                    # Found circular dependency
                    cycle_start = path.index(neighbor)
                    return path[cycle_start:] + [neighbor]
            
            rec_stack.remove(node)
            return None
        
        for node in self.nodes:
            if node not in visited:
                result = dfs(node, [])
                if result:
                    return result
        
        return None
    
    def get_initialization_order(self) -> List[Type]:
        """Get topological ordering for initialization."""
        in_degree = {node: 0 for node in self.nodes}
        
        # Calculate in-degrees
        for node in self.edges:
            for neighbor in self.edges[node]:
                in_degree[neighbor] += 1
        
        # Kahn's algorithm for topological sorting
        queue = [node for node in self.nodes if in_degree[node] == 0]
        result = []
        
        while queue:
            node = queue.pop(0)
            result.append(node)
            
            for neighbor in self.edges.get(node, []):
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)
        
        if len(result) != len(self.nodes):
            raise CircularDependencyError("Circular dependency detected in initialization order")
        
        return result


class DIContainer:
    """Dependency Injection Container."""
    
    def __init__(self, name: str = "default"):
        self.name = name
        self.registrations: Dict[Type, DependencyRegistration] = {}
        self.singletons: Dict[Type, Any] = {}
        self.lock = threading.RLock()
        self.logger = StructuredLogger(f"di_container.{name}")
        self.dependency_graph = DependencyGraph()
        self.resource_tracker = get_resource_tracker()
        
        # Thread-local storage for scoped instances
        self.thread_local = threading.local()
        
    def register(self, interface: Type[T], implementation: Type[T] = None,
                scope: DependencyScope = DependencyScope.TRANSIENT,
                factory: Callable[..., T] = None,
                configuration: Dict[str, Any] = None,
                tags: Set[str] = None) -> 'DIContainer':
        """Register a dependency."""
        if implementation is None:
            implementation = interface
        
        with self.lock:
            registration = DependencyRegistration(
                interface=interface,
                implementation=implementation,
                scope=scope,
                factory=factory,
                configuration=configuration or {},
                tags=tags or set()
            )
            
            # Analyze dependencies
            self._analyze_dependencies(registration)
            
            self.registrations[interface] = registration
            
            self.logger.debug("Registered dependency", extra={
                'interface': interface.__name__,
                'implementation': implementation.__name__,
                'scope': scope.value
            })
            
        return self
    
    def register_singleton(self, interface: Type[T], instance: T) -> 'DIContainer':
        """Register a singleton instance."""
        with self.lock:
            registration = DependencyRegistration(
                interface=interface,
                implementation=type(instance),
                scope=DependencyScope.SINGLETON,
                singleton_instance=instance
            )
            
            self.registrations[interface] = registration
            self.singletons[interface] = instance
            
            # Register with resource tracker if it's a managed resource
            if isinstance(instance, ManagedResource):
                self.resource_tracker.register_resource(instance)
            
            self.logger.debug("Registered singleton", extra={
                'interface': interface.__name__,
                'instance_type': type(instance).__name__
            })
            
        return self
    
    def register_factory(self, interface: Type[T], factory: Callable[..., T],
                        scope: DependencyScope = DependencyScope.TRANSIENT) -> 'DIContainer':
        """Register a factory function."""
        return self.register(interface, factory=factory, scope=scope)
    
    def _analyze_dependencies(self, registration: DependencyRegistration) -> None:
        """Analyze dependencies of a registration."""
        implementation = registration.implementation
        
        if implementation is None:
            return
        
        # Get constructor signature
        try:
            signature = inspect.signature(implementation.__init__)
            type_hints = get_type_hints(implementation.__init__)
            
            for param_name, param in signature.parameters.items():
                if param_name == 'self':
                    continue
                
                # Get parameter type
                if param_name in type_hints:
                    param_type = type_hints[param_name]
                    
                    # Handle Optional types
                    origin = get_origin(param_type)
                    if origin is Union:
                        args = get_args(param_type)
                        if len(args) == 2 and type(None) in args:
                            # This is Optional[T]
                            param_type = next(arg for arg in args if arg is not type(None))
                    
                    registration.dependencies.append(param_type)
                    self.dependency_graph.add_dependency(registration.interface, param_type)
                    
        except Exception as e:
            self.logger.warning("Failed to analyze dependencies", extra={
                'implementation': implementation.__name__,
                'error': str(e)
            })
    
    @typed(TypeSafetyLevel.STRICT)
    def resolve(self, interface: Type[T], context: Optional[InjectionContext] = None) -> T:
        """Resolve a dependency."""
        if context is None:
            context = InjectionContext()
        
        # Check for circular dependencies
        if interface in context.resolution_stack:
            cycle = context.resolution_stack + [interface]
            raise CircularDependencyError(f"Circular dependency detected: {' -> '.join(cls.__name__ for cls in cycle)}")
        
        with self.lock:
            if interface not in self.registrations:
                # Try to create automatic registration for concrete types
                if inspect.isclass(interface) and not inspect.isabstract(interface):
                    self.register(interface, interface)
                else:
                    raise InjectionError(f"No registration found for {interface.__name__}")
            
            registration = self.registrations[interface]
            
            # Handle different scopes
            if registration.scope == DependencyScope.SINGLETON:
                return self._resolve_singleton(registration, context)
            elif registration.scope == DependencyScope.TRANSIENT:
                return self._resolve_transient(registration, context)
            elif registration.scope == DependencyScope.SCOPED:
                return self._resolve_scoped(registration, context)
            elif registration.scope == DependencyScope.THREAD_LOCAL:
                return self._resolve_thread_local(registration, context)
            else:
                raise InjectionError(f"Unsupported scope: {registration.scope}")
    
    def _resolve_singleton(self, registration: DependencyRegistration, context: InjectionContext) -> T:
        """Resolve singleton dependency."""
        if registration.singleton_instance is not None:
            return registration.singleton_instance
        
        if registration.interface in self.singletons:
            return self.singletons[registration.interface]
        
        # Create singleton instance
        instance = self._create_instance(registration, context)
        self.singletons[registration.interface] = instance
        registration.singleton_instance = instance
        
        return instance
    
    def _resolve_transient(self, registration: DependencyRegistration, context: InjectionContext) -> T:
        """Resolve transient dependency."""
        return self._create_instance(registration, context)
    
    def _resolve_scoped(self, registration: DependencyRegistration, context: InjectionContext) -> T:
        """Resolve scoped dependency."""
        scope_key = context.request_id or "default_scope"
        
        if scope_key not in context.scope_instances:
            context.scope_instances[scope_key] = {}
        
        scope_instances = context.scope_instances[scope_key]
        
        if registration.interface in scope_instances:
            return scope_instances[registration.interface]
        
        instance = self._create_instance(registration, context)
        scope_instances[registration.interface] = instance
        
        return instance
    
    def _resolve_thread_local(self, registration: DependencyRegistration, context: InjectionContext) -> T:
        """Resolve thread-local dependency."""
        thread_id = threading.get_ident()
        
        if thread_id not in context.thread_local_instances:
            context.thread_local_instances[thread_id] = {}
        
        thread_instances = context.thread_local_instances[thread_id]
        
        if registration.interface in thread_instances:
            return thread_instances[registration.interface]
        
        instance = self._create_instance(registration, context)
        thread_instances[registration.interface] = instance
        
        return instance
    
    def _create_instance(self, registration: DependencyRegistration, context: InjectionContext) -> T:
        """Create an instance of the registered type."""
        context.resolution_stack.append(registration.interface)
        
        try:
            # Use factory if available
            if registration.factory:
                instance = self._create_with_factory(registration, context)
            else:
                instance = self._create_with_constructor(registration, context)
            
            # Configure if configurable
            if isinstance(instance, Configurable) and registration.configuration:
                instance.configure(registration.configuration)
            
            # Register with resource tracker if it's a managed resource
            if isinstance(instance, ManagedResource):
                self.resource_tracker.register_resource(instance)
            
            return instance
            
        finally:
            context.resolution_stack.pop()
    
    def _create_with_factory(self, registration: DependencyRegistration, context: InjectionContext) -> T:
        """Create instance using factory function."""
        factory = registration.factory
        signature = inspect.signature(factory)
        kwargs = {}
        
        for param_name, param in signature.parameters.items():
            if param.annotation != inspect.Parameter.empty:
                dependency = self.resolve(param.annotation, context)
                kwargs[param_name] = dependency
        
        return factory(**kwargs)
    
    def _create_with_constructor(self, registration: DependencyRegistration, context: InjectionContext) -> T:
        """Create instance using constructor injection."""
        implementation = registration.implementation
        signature = inspect.signature(implementation.__init__)
        type_hints = get_type_hints(implementation.__init__)
        kwargs = {}
        
        for param_name, param in signature.parameters.items():
            if param_name == 'self':
                continue
                
            if param_name in type_hints:
                param_type = type_hints[param_name]
                
                # Handle Optional parameters
                origin = get_origin(param_type)
                if origin is Union:
                    args = get_args(param_type)
                    if len(args) == 2 and type(None) in args:
                        # This is Optional[T]
                        param_type = next(arg for arg in args if arg is not type(None))
                        
                        # Try to resolve, but don't fail if not available
                        try:
                            dependency = self.resolve(param_type, context)
                            kwargs[param_name] = dependency
                        except InjectionError:
                            # Optional dependency not available, use None
                            kwargs[param_name] = None
                        continue
                
                # Required dependency
                dependency = self.resolve(param_type, context)
                kwargs[param_name] = dependency
        
        return implementation(**kwargs)
    
    def validate_registrations(self) -> List[str]:
        """Validate all registrations for circular dependencies."""
        errors = []
        
        try:
            # Check for circular dependencies
            circular = self.dependency_graph.has_circular_dependency()
            if circular:
                cycle_str = " -> ".join(cls.__name__ for cls in circular)
                errors.append(f"Circular dependency detected: {cycle_str}")
            
            # Validate each registration
            for interface, registration in self.registrations.items():
                try:
                    # Try to analyze dependencies
                    self._analyze_dependencies(registration)
                except Exception as e:
                    errors.append(f"Invalid registration for {interface.__name__}: {str(e)}")
                    
        except Exception as e:
            errors.append(f"Validation error: {str(e)}")
        
        return errors
    
    async def initialize_async_dependencies(self) -> None:
        """Initialize all async dependencies in proper order."""
        initialization_order = self.dependency_graph.get_initialization_order()
        
        for interface in initialization_order:
            if interface in self.registrations:
                registration = self.registrations[interface]
                
                if registration.scope == DependencyScope.SINGLETON:
                    instance = self._resolve_singleton(registration, InjectionContext())
                    
                    if isinstance(instance, AsyncInitializable):
                        try:
                            await instance.initialize()
                            self.logger.debug("Initialized async dependency", extra={
                                'interface': interface.__name__
                            })
                        except Exception as e:
                            self.logger.error("Failed to initialize async dependency", extra={
                                'interface': interface.__name__,
                                'error': str(e)
                            })
    
    async def cleanup_async_dependencies(self) -> None:
        """Cleanup all async dependencies."""
        for interface, instance in self.singletons.items():
            if isinstance(instance, AsyncInitializable):
                try:
                    await instance.cleanup()
                    self.logger.debug("Cleaned up async dependency", extra={
                        'interface': interface.__name__
                    })
                except Exception as e:
                    self.logger.error("Failed to cleanup async dependency", extra={
                        'interface': interface.__name__,
                        'error': str(e)
                    })
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get container statistics."""
        with self.lock:
            return {
                'name': self.name,
                'total_registrations': len(self.registrations),
                'singleton_instances': len(self.singletons),
                'registrations_by_scope': {
                    scope.value: sum(1 for reg in self.registrations.values() if reg.scope == scope)
                    for scope in DependencyScope
                },
                'dependency_count': len(self.dependency_graph.nodes),
                'has_circular_dependencies': self.dependency_graph.has_circular_dependency() is not None
            }


def injectable(scope: DependencyScope = DependencyScope.TRANSIENT, 
              configuration: Dict[str, Any] = None,
              tags: Set[str] = None):
    """Decorator to mark a class as injectable."""
    
    def decorator(cls: Type[T]) -> Type[T]:
        # Store injection metadata
        cls._injection_scope = scope
        cls._injection_configuration = configuration or {}
        cls._injection_tags = tags or set()
        
        return cls
    
    return decorator


def inject(container_name: str = "default"):
    """Decorator for method injection."""
    
    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        signature = inspect.signature(func)
        type_hints = get_type_hints(func)
        
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            container = get_container(container_name)
            
            # Resolve missing dependencies
            bound_args = signature.bind_partial(*args, **kwargs)
            
            for param_name, param in signature.parameters.items():
                if param_name not in bound_args.arguments and param_name in type_hints:
                    param_type = type_hints[param_name]
                    dependency = container.resolve(param_type)
                    bound_args.arguments[param_name] = dependency
            
            return func(**bound_args.arguments)
        
        @functools.wraps(func)
        async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            container = get_container(container_name)
            
            # Resolve missing dependencies
            bound_args = signature.bind_partial(*args, **kwargs)
            
            for param_name, param in signature.parameters.items():
                if param_name not in bound_args.arguments and param_name in type_hints:
                    param_type = type_hints[param_name]
                    dependency = container.resolve(param_type)
                    bound_args.arguments[param_name] = dependency
            
            return await func(**bound_args.arguments)
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else wrapper
    
    return decorator


# Global container registry
_containers: Dict[str, DIContainer] = {}
_default_container: Optional[DIContainer] = None


def create_container(name: str = "default") -> DIContainer:
    """Create a new DI container."""
    global _containers, _default_container
    
    container = DIContainer(name)
    _containers[name] = container
    
    if name == "default":
        _default_container = container
    
    return container


def get_container(name: str = "default") -> DIContainer:
    """Get a DI container by name."""
    global _containers, _default_container
    
    if name == "default" and _default_container is not None:
        return _default_container
    
    if name not in _containers:
        return create_container(name)
    
    return _containers[name]


def auto_register_module(module, container: DIContainer = None) -> None:
    """Auto-register all injectable classes from a module."""
    if container is None:
        container = get_container()
    
    for name in dir(module):
        obj = getattr(module, name)
        
        if (inspect.isclass(obj) and 
            hasattr(obj, '_injection_scope') and 
            obj.__module__ == module.__name__):
            
            container.register(
                interface=obj,
                implementation=obj,
                scope=obj._injection_scope,
                configuration=obj._injection_configuration,
                tags=obj._injection_tags
            )


# Context manager for scoped resolution
@asynccontextmanager
async def injection_scope(container: DIContainer = None, request_id: str = None):
    """Create an injection scope for scoped dependencies."""
    if container is None:
        container = get_container()
    
    context = InjectionContext(request_id=request_id or str(threading.get_ident()))
    
    try:
        yield context
    finally:
        # Cleanup scoped instances
        scope_key = context.request_id or "default_scope"
        if scope_key in context.scope_instances:
            for instance in context.scope_instances[scope_key].values():
                if isinstance(instance, AsyncInitializable):
                    try:
                        await instance.cleanup()
                    except Exception as e:
                        logger = StructuredLogger("injection_scope")
                        logger.error("Error cleaning up scoped instance", extra={'error': str(e)})
            
            del context.scope_instances[scope_key]