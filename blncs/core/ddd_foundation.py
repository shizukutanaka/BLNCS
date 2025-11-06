#!/usr/bin/env python3
"""
Domain-Driven Design (DDD) Foundation
Implements tactical DDD patterns: Entities, Value Objects, Aggregates
Based on 2025 enterprise architecture best practices
"""

import logging
from typing import Any, List, Dict, Optional, TypeVar, Generic
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from datetime import datetime

logger = logging.getLogger(__name__)

T = TypeVar('T')
ID = TypeVar('ID')


@dataclass
class ValueObject:
    """
    Value Object - has no identity, immutable, defined by attributes
    Core DDD pattern for modeling concepts without identity
    """

    def __eq__(self, other: Any) -> bool:
        """Value objects are equal if all attributes are equal"""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __hash__(self) -> int:
        """Value objects are hashable"""
        return hash(tuple(sorted(self.__dict__.items())))

    def __repr__(self) -> str:
        attrs = ", ".join(f"{k}={v}" for k, v in self.__dict__.items())
        return f"{self.__class__.__name__}({attrs})"


@dataclass
class Money(ValueObject):
    """Example Value Object - monetary amount"""
    amount: float
    currency: str = "BTC"

    def add(self, other: 'Money') -> 'Money':
        """Add two monetary amounts"""
        if self.currency != other.currency:
            raise ValueError(f"Cannot add {self.currency} and {other.currency}")
        return Money(self.amount + other.amount, self.currency)

    def multiply(self, factor: float) -> 'Money':
        """Multiply monetary amount"""
        return Money(self.amount * factor, self.currency)


@dataclass
class Address(ValueObject):
    """Example Value Object - address"""
    street: str
    city: str
    country: str
    postal_code: str


@dataclass
class Entity(ABC, Generic[ID]):
    """
    Entity - has identity, mutable, tracked by ID
    Core DDD pattern for modeling domain objects with identity
    """

    id: ID
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    version: int = field(default=1)  # For optimistic locking

    def __eq__(self, other: Any) -> bool:
        """Entities are equal if they have same ID"""
        if not isinstance(other, self.__class__):
            return False
        return self.id == other.id

    def __hash__(self) -> int:
        """Entities are hashable by ID"""
        return hash(self.id)

    def mark_as_modified(self) -> None:
        """Mark entity as modified"""
        self.updated_at = datetime.utcnow()
        self.version += 1
        logger.debug(f"Marked entity {self.id} as modified (v{self.version})")

    @abstractmethod
    def validate(self) -> None:
        """Validate entity invariants"""
        pass


@dataclass
class Aggregate(Entity[ID]):
    """
    Aggregate Root - boundary for consistency of related entities
    In DDD, aggregates are the primary consistency boundary
    Only aggregate roots should be referenced from outside the aggregate
    """

    domain_events: List[Any] = field(default_factory=list, init=False)

    def add_domain_event(self, event: Any) -> None:
        """
        Add domain event for external notification
        Events are collected and dispatched after transaction commits
        """
        self.domain_events.append(event)
        logger.debug(f"Added event to aggregate {self.id}: {event}")

    def get_domain_events(self) -> List[Any]:
        """Get all domain events"""
        return self.domain_events.copy()

    def clear_domain_events(self) -> None:
        """Clear domain events (after publishing)"""
        self.domain_events.clear()

    def has_events(self) -> bool:
        """Check if aggregate has uncommitted events"""
        return len(self.domain_events) > 0


class Repository(ABC, Generic[ID, T]):
    """
    Repository - abstraction over persistence
    Mediates between domain and data mapping layers
    Provides collection-like interface for aggregates
    """

    @abstractmethod
    async def add(self, aggregate: T) -> None:
        """Add an aggregate to repository"""
        pass

    @abstractmethod
    async def remove(self, aggregate_id: ID) -> None:
        """Remove an aggregate from repository"""
        pass

    @abstractmethod
    async def find_by_id(self, aggregate_id: ID) -> Optional[T]:
        """Find aggregate by ID"""
        pass

    @abstractmethod
    async def get_by_id(self, aggregate_id: ID) -> T:
        """Get aggregate by ID, raise if not found"""
        pass

    @abstractmethod
    async def get_all(self) -> List[T]:
        """Get all aggregates"""
        pass

    @abstractmethod
    async def save(self, aggregate: T) -> None:
        """Save (update) an aggregate"""
        pass


@dataclass
class DomainEvent:
    """
    Base class for domain events
    Events represent something that happened in the domain
    """

    aggregate_id: Any
    occurred_at: datetime = field(default_factory=datetime.utcnow)
    version: int = 1  # Event schema version


class Specification(ABC, Generic[T]):
    """
    Specification pattern - encapsulate query logic
    Used for complex filtering and business rules
    """

    @abstractmethod
    def is_satisfied_by(self, candidate: T) -> bool:
        """Check if candidate satisfies specification"""
        pass

    def and_spec(self, other: 'Specification[T]') -> 'AndSpecification[T]':
        """Combine with AND"""
        return AndSpecification(self, other)

    def or_spec(self, other: 'Specification[T]') -> 'OrSpecification[T]':
        """Combine with OR"""
        return OrSpecification(self, other)

    def not_spec(self) -> 'NotSpecification[T]':
        """Negate specification"""
        return NotSpecification(self)


class AndSpecification(Specification[T]):
    """Composite specification - AND"""

    def __init__(self, left: Specification[T], right: Specification[T]):
        self.left = left
        self.right = right

    def is_satisfied_by(self, candidate: T) -> bool:
        return self.left.is_satisfied_by(candidate) and self.right.is_satisfied_by(candidate)


class OrSpecification(Specification[T]):
    """Composite specification - OR"""

    def __init__(self, left: Specification[T], right: Specification[T]):
        self.left = left
        self.right = right

    def is_satisfied_by(self, candidate: T) -> bool:
        return self.left.is_satisfied_by(candidate) or self.right.is_satisfied_by(candidate)


class NotSpecification(Specification[T]):
    """Composite specification - NOT"""

    def __init__(self, spec: Specification[T]):
        self.spec = spec

    def is_satisfied_by(self, candidate: T) -> bool:
        return not self.spec.is_satisfied_by(candidate)


class DomainService(ABC):
    """
    Domain Service - business logic that doesn't belong to entities
    Used for operations that span multiple aggregates
    """

    @abstractmethod
    async def execute(self, *args: Any, **kwargs: Any) -> Any:
        """Execute domain service"""
        pass


class UnitOfWork(ABC):
    """
    Unit of Work pattern - manages transactions and repository coordin</br>ation
    Ensures consistency across multiple aggregates
    """

    @abstractmethod
    async def begin(self) -> None:
        """Begin transaction"""
        pass

    @abstractmethod
    async def commit(self) -> None:
        """Commit transaction and dispatch domain events"""
        pass

    @abstractmethod
    async def rollback(self) -> None:
        """Rollback transaction"""
        pass

    @abstractmethod
    async def register_new(self, aggregate: Aggregate) -> None:
        """Register new aggregate for persistence"""
        pass

    @abstractmethod
    async def register_dirty(self, aggregate: Aggregate) -> None:
        """Register modified aggregate for update"""
        pass

    @abstractmethod
    async def register_clean(self, aggregate: Aggregate) -> None:
        """Register unmodified aggregate"""
        pass


class BoundedContext:
    """
    Bounded Context - isolation boundary for domains
    Encapsulates domain logic and provides ubiquitous language
    """

    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self.aggregates: Dict[str, Any] = {}
        self.repositories: Dict[str, Repository] = {}
        self.services: Dict[str, DomainService] = {}

        logger.info(f"Created bounded context: {name}")

    def register_aggregate(self, aggregate_type: type) -> None:
        """Register aggregate root type"""
        self.aggregates[aggregate_type.__name__] = aggregate_type
        logger.debug(f"Registered aggregate: {aggregate_type.__name__}")

    def register_repository(self, name: str, repository: Repository) -> None:
        """Register repository"""
        self.repositories[name] = repository
        logger.debug(f"Registered repository: {name}")

    def register_service(self, name: str, service: DomainService) -> None:
        """Register domain service"""
        self.services[name] = service
        logger.debug(f"Registered service: {name}")

    def get_repository(self, name: str) -> Optional[Repository]:
        """Get repository by name"""
        return self.repositories.get(name)

    def get_service(self, name: str) -> Optional[DomainService]:
        """Get service by name"""
        return self.services.get(name)

    def __repr__(self) -> str:
        return (
            f"BoundedContext(name={self.name}, "
            f"aggregates={len(self.aggregates)}, "
            f"repositories={len(self.repositories)}, "
            f"services={len(self.services)})"
        )


__all__ = [
    'ValueObject',
    'Money',
    'Address',
    'Entity',
    'Aggregate',
    'Repository',
    'DomainEvent',
    'Specification',
    'AndSpecification',
    'OrSpecification',
    'NotSpecification',
    'DomainService',
    'UnitOfWork',
    'BoundedContext',
]
