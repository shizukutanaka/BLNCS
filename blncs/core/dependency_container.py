#!/usr/bin/env python3
"""
Dependency Injection Container
Implements IoC (Inversion of Control) patterns for clean architecture
Based on 2025 Python best practices for dependency management
"""

import logging
from typing import Dict, Any, Type, TypeVar, Optional, Callable, Set
from dataclasses import dataclass
from enum import Enum
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

T = TypeVar('T')


class LifecycleScope(Enum):
    """Dependency lifecycle scope"""
    SINGLETON = "singleton"        # Single instance for application lifetime
    TRANSIENT = "transient"        # New instance every time
    SCOPED = "scoped"             # Single instance per scope/request
    LAZY = "lazy"                 # Instance created on first access


@dataclass
class ServiceDescriptor:
    """Describes a registered service"""
    interface: Type
    implementation: Optional[Type] = None
    factory: Optional[Callable] = None
    instance: Optional[Any] = None
    scope: LifecycleScope = LifecycleScope.TRANSIENT
    dependencies: Set[str] = None  # Type names this service depends on

    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = set()


class ServiceContainer:
    """
    Dependency Injection Container
    Manages service registration, resolution, and lifecycle
    """

    def __init__(self):
        self.services: Dict[str, ServiceDescriptor] = {}
        self.singletons: Dict[str, Any] = {}
        self.scoped_instances: Dict[str, Dict[str, Any]] = {}
        self.current_scope: Optional[str] = None
        self.scope_stack: list = []

    def register_singleton(
        self,
        interface: Type[T],
        implementation: Optional[Type[T]] = None,
        instance: Optional[T] = None,
        factory: Optional[Callable[[], T]] = None
    ) -> None:
        """
        Register a singleton service (single instance for lifetime)

        Args:
            interface: Service interface/type
            implementation: Concrete implementation class
            instance: Optional pre-created instance
            factory: Optional factory function
        """
        self._register(
            interface,
            implementation=implementation,
            instance=instance,
            factory=factory,
            scope=LifecycleScope.SINGLETON
        )
        logger.debug(f"Registered singleton: {interface.__name__}")

    def register_transient(
        self,
        interface: Type[T],
        implementation: Optional[Type[T]] = None,
        factory: Optional[Callable[[], T]] = None
    ) -> None:
        """
        Register a transient service (new instance every time)

        Args:
            interface: Service interface/type
            implementation: Concrete implementation class
            factory: Optional factory function
        """
        self._register(
            interface,
            implementation=implementation,
            factory=factory,
            scope=LifecycleScope.TRANSIENT
        )
        logger.debug(f"Registered transient: {interface.__name__}")

    def register_scoped(
        self,
        interface: Type[T],
        implementation: Optional[Type[T]] = None,
        factory: Optional[Callable[[], T]] = None
    ) -> None:
        """
        Register a scoped service (single instance per scope/request)

        Args:
            interface: Service interface/type
            implementation: Concrete implementation class
            factory: Optional factory function
        """
        self._register(
            interface,
            implementation=implementation,
            factory=factory,
            scope=LifecycleScope.SCOPED
        )
        logger.debug(f"Registered scoped: {interface.__name__}")

    def _register(
        self,
        interface: Type,
        implementation: Optional[Type] = None,
        instance: Optional[Any] = None,
        factory: Optional[Callable] = None,
        scope: LifecycleScope = LifecycleScope.TRANSIENT
    ) -> None:
        """Internal registration method"""
        service_name = interface.__name__

        descriptor = ServiceDescriptor(
            interface=interface,
            implementation=implementation or interface,
            instance=instance,
            factory=factory,
            scope=scope
        )

        self.services[service_name] = descriptor

        # If instance provided for singleton, store it immediately
        if scope == LifecycleScope.SINGLETON and instance is not None:
            self.singletons[service_name] = instance

    def resolve(self, service_type: Type[T]) -> T:
        """
        Resolve a service instance

        Args:
            service_type: Type to resolve

        Returns:
            Instance of the service

        Raises:
            ValueError: If service not registered
        """
        service_name = service_type.__name__

        if service_name not in self.services:
            raise ValueError(f"Service not registered: {service_name}")

        descriptor = self.services[service_name]

        # Handle singletons
        if descriptor.scope == LifecycleScope.SINGLETON:
            if service_name not in self.singletons:
                instance = self._create_instance(descriptor)
                self.singletons[service_name] = instance
            return self.singletons[service_name]

        # Handle scoped
        elif descriptor.scope == LifecycleScope.SCOPED:
            if self.current_scope is None:
                raise RuntimeError("No scope context - use create_scope()")

            if self.current_scope not in self.scoped_instances:
                self.scoped_instances[self.current_scope] = {}

            scope_dict = self.scoped_instances[self.current_scope]

            if service_name not in scope_dict:
                instance = self._create_instance(descriptor)
                scope_dict[service_name] = instance

            return scope_dict[service_name]

        # Handle transient
        else:  # TRANSIENT
            return self._create_instance(descriptor)

    def _create_instance(self, descriptor: ServiceDescriptor) -> Any:
        """Create an instance of a service"""
        # Use factory if provided
        if descriptor.factory is not None:
            return descriptor.factory()

        # Use pre-created instance
        if descriptor.instance is not None:
            return descriptor.instance

        # Create instance from implementation class
        try:
            return descriptor.implementation()
        except TypeError as e:
            logger.error(
                f"Failed to instantiate {descriptor.implementation.__name__}: {e}"
            )
            raise

    def create_scope(self) -> str:
        """
        Create a new scope for scoped services

        Returns:
            Scope ID
        """
        scope_id = f"scope_{len(self.scope_stack)}"
        self.scope_stack.append(scope_id)
        self.current_scope = scope_id
        logger.debug(f"Created scope: {scope_id}")
        return scope_id

    def end_scope(self) -> None:
        """End the current scope and clean up scoped instances"""
        if self.current_scope is None:
            return

        if self.current_scope in self.scoped_instances:
            del self.scoped_instances[self.current_scope]

        if self.scope_stack and self.scope_stack[-1] == self.current_scope:
            self.scope_stack.pop()

        self.current_scope = self.scope_stack[-1] if self.scope_stack else None
        logger.debug(f"Ended scope: {self.current_scope}")

    def get_service_info(self, service_type: Type) -> Optional[ServiceDescriptor]:
        """Get information about a registered service"""
        service_name = service_type.__name__
        return self.services.get(service_name)

    def clear(self) -> None:
        """Clear all registrations"""
        self.services.clear()
        self.singletons.clear()
        self.scoped_instances.clear()
        self.scope_stack.clear()
        self.current_scope = None
        logger.info("Cleared all service registrations")

    def get_all_services(self) -> Dict[str, ServiceDescriptor]:
        """Get all registered services"""
        return self.services.copy()


class ServiceCollection:
    """
    Fluent builder for service registration
    Allows chaining of registration calls
    """

    def __init__(self):
        self.container = ServiceContainer()

    def add_singleton(
        self,
        interface: Type[T],
        implementation: Optional[Type[T]] = None,
        instance: Optional[T] = None,
        factory: Optional[Callable[[], T]] = None
    ) -> 'ServiceCollection':
        """Add singleton and return self for chaining"""
        self.container.register_singleton(interface, implementation, instance, factory)
        return self

    def add_transient(
        self,
        interface: Type[T],
        implementation: Optional[Type[T]] = None,
        factory: Optional[Callable[[], T]] = None
    ) -> 'ServiceCollection':
        """Add transient and return self for chaining"""
        self.container.register_transient(interface, implementation, factory)
        return self

    def add_scoped(
        self,
        interface: Type[T],
        implementation: Optional[Type[T]] = None,
        factory: Optional[Callable[[], T]] = None
    ) -> 'ServiceCollection':
        """Add scoped and return self for chaining"""
        self.container.register_scoped(interface, implementation, factory)
        return self

    def build(self) -> ServiceContainer:
        """Build and return the container"""
        logger.info(f"Built container with {len(self.container.services)} services")
        return self.container


# Global container instance
_global_container: Optional[ServiceContainer] = None


def get_container() -> ServiceContainer:
    """Get global service container"""
    global _global_container
    if _global_container is None:
        _global_container = ServiceContainer()
    return _global_container


def set_container(container: ServiceContainer) -> None:
    """Set global service container"""
    global _global_container
    _global_container = container
    logger.info("Set global service container")


__all__ = [
    'LifecycleScope',
    'ServiceDescriptor',
    'ServiceContainer',
    'ServiceCollection',
    'get_container',
    'set_container',
]
