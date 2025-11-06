#!/usr/bin/env python3
"""
Event Sourcing and Event-Driven Architecture
Implements patterns for building event-driven systems
Stores state changes as immutable event sequences
"""

import logging
import json
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


@dataclass
class Event:
    """
    Base domain event
    Represents something that happened in the domain
    """

    event_id: str
    aggregate_id: str
    aggregate_type: str
    event_type: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    version: int = 1
    data: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary"""
        return {
            **asdict(self),
            'timestamp': self.timestamp.isoformat()
        }

    def to_json(self) -> str:
        """Convert event to JSON"""
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Event':
        """Create event from dictionary"""
        if isinstance(data.get('timestamp'), str):
            data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        return cls(**data)


class EventStore(ABC):
    """
    Event Store - persists events as immutable log
    Single source of truth for application state
    """

    @abstractmethod
    async def append_event(self, event: Event) -> None:
        """Append event to store"""
        pass

    @abstractmethod
    async def append_events(self, events: List[Event]) -> None:
        """Append multiple events atomically"""
        pass

    @abstractmethod
    async def get_events(self, aggregate_id: str) -> List[Event]:
        """Get all events for an aggregate"""
        pass

    @abstractmethod
    async def get_events_from_version(
        self,
        aggregate_id: str,
        from_version: int
    ) -> List[Event]:
        """Get events from specific version onwards"""
        pass

    @abstractmethod
    async def get_all_events(self) -> List[Event]:
        """Get all events in order"""
        pass

    @abstractmethod
    async def get_events_of_type(self, event_type: str) -> List[Event]:
        """Get events of specific type"""
        pass


class InMemoryEventStore(EventStore):
    """Simple in-memory implementation of event store"""

    def __init__(self):
        self.events: List[Event] = []
        self.aggregate_events: Dict[str, List[Event]] = {}

    async def append_event(self, event: Event) -> None:
        """Append single event"""
        self.events.append(event)

        if event.aggregate_id not in self.aggregate_events:
            self.aggregate_events[event.aggregate_id] = []

        self.aggregate_events[event.aggregate_id].append(event)
        logger.debug(f"Appended event: {event.event_type} for {event.aggregate_id}")

    async def append_events(self, events: List[Event]) -> None:
        """Append multiple events"""
        for event in events:
            await self.append_event(event)

    async def get_events(self, aggregate_id: str) -> List[Event]:
        """Get all events for aggregate"""
        return self.aggregate_events.get(aggregate_id, []).copy()

    async def get_events_from_version(
        self,
        aggregate_id: str,
        from_version: int
    ) -> List[Event]:
        """Get events from version"""
        events = self.aggregate_events.get(aggregate_id, [])
        return [e for e in events if e.version >= from_version]

    async def get_all_events(self) -> List[Event]:
        """Get all events"""
        return self.events.copy()

    async def get_events_of_type(self, event_type: str) -> List[Event]:
        """Get events of type"""
        return [e for e in self.events if e.event_type == event_type]


class EventProjection(ABC):
    """
    Projection - read model built from events
    Optimizes queries by denormalizing event data
    """

    @abstractmethod
    async def handle_event(self, event: Event) -> None:
        """Handle event and update projection"""
        pass

    @abstractmethod
    async def get_state(self) -> Dict[str, Any]:
        """Get current projection state"""
        pass

    @abstractmethod
    async def rebuild_from_events(self, events: List[Event]) -> None:
        """Rebuild projection from event history"""
        pass


class InMemoryProjection(EventProjection):
    """Simple in-memory projection"""

    def __init__(self, name: str):
        self.name = name
        self.state: Dict[str, Any] = {}
        self.event_handlers: Dict[str, Callable] = {}

    def register_handler(self, event_type: str, handler: Callable) -> None:
        """Register event handler"""
        self.event_handlers[event_type] = handler
        logger.debug(f"Registered handler for {event_type} in {self.name}")

    async def handle_event(self, event: Event) -> None:
        """Handle event"""
        if event.event_type in self.event_handlers:
            handler = self.event_handlers[event.event_type]
            await handler(event, self.state)
            logger.debug(f"Handled {event.event_type} in projection {self.name}")

    async def get_state(self) -> Dict[str, Any]:
        """Get state"""
        return self.state.copy()

    async def rebuild_from_events(self, events: List[Event]) -> None:
        """Rebuild from events"""
        self.state.clear()
        for event in events:
            await self.handle_event(event)


class EventHandler(ABC):
    """Handler for domain events"""

    @abstractmethod
    async def handle(self, event: Event) -> None:
        """Handle event"""
        pass


class EventPublisher(ABC):
    """Publishes events to subscribers"""

    @abstractmethod
    async def publish(self, event: Event) -> None:
        """Publish single event"""
        pass

    @abstractmethod
    async def publish_multiple(self, events: List[Event]) -> None:
        """Publish multiple events"""
        pass


class InMemoryEventPublisher(EventPublisher):
    """Simple in-memory event publisher"""

    def __init__(self):
        self.subscribers: Dict[str, List[EventHandler]] = {}

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        """Subscribe to event type"""
        if event_type not in self.subscribers:
            self.subscribers[event_type] = []

        self.subscribers[event_type].append(handler)
        logger.debug(f"Subscribed handler to {event_type}")

    async def publish(self, event: Event) -> None:
        """Publish event to all subscribers"""
        if event.event_type in self.subscribers:
            handlers = self.subscribers[event.event_type]
            for handler in handlers:
                try:
                    await handler.handle(event)
                except Exception as e:
                    logger.error(f"Error in event handler: {e}")

    async def publish_multiple(self, events: List[Event]) -> None:
        """Publish multiple events"""
        for event in events:
            await self.publish(event)


class EventSourcing:
    """
    Event Sourcing aggregator
    Combines event store, projections, and publishers
    """

    def __init__(
        self,
        event_store: EventStore,
        publisher: EventPublisher
    ):
        self.event_store = event_store
        self.publisher = publisher
        self.projections: Dict[str, EventProjection] = {}

    def register_projection(self, name: str, projection: EventProjection) -> None:
        """Register a projection"""
        self.projections[name] = projection
        logger.info(f"Registered projection: {name}")

    async def append_and_publish(self, events: List[Event]) -> None:
        """
        Append events to store and publish
        Ensures consistency between store and subscribers
        """
        # Store events
        await self.event_store.append_events(events)

        # Update all projections
        for projection in self.projections.values():
            for event in events:
                await projection.handle_event(event)

        # Publish events
        await self.publisher.publish_multiple(events)

        logger.info(f"Appended and published {len(events)} events")

    async def get_aggregate_history(self, aggregate_id: str) -> List[Event]:
        """Get complete history of aggregate"""
        return await self.event_store.get_events(aggregate_id)

    async def rebuild_projection(self, projection_name: str) -> None:
        """Rebuild projection from all events"""
        if projection_name not in self.projections:
            raise ValueError(f"Unknown projection: {projection_name}")

        projection = self.projections[projection_name]
        all_events = await self.event_store.get_all_events()
        await projection.rebuild_from_events(all_events)

        logger.info(f"Rebuilt projection: {projection_name}")


class EventBus:
    """
    Event Bus - coordinates event publication and handling
    Decouples event producers from consumers
    """

    def __init__(self):
        self.handlers: Dict[str, List[Callable]] = {}
        self.middleware: List[Callable] = []

    def subscribe(self, event_type: str, handler: Callable) -> None:
        """Subscribe to event type"""
        if event_type not in self.handlers:
            self.handlers[event_type] = []

        self.handlers[event_type].append(handler)
        logger.debug(f"Subscribed to {event_type}")

    def unsubscribe(self, event_type: str, handler: Callable) -> None:
        """Unsubscribe from event type"""
        if event_type in self.handlers:
            self.handlers[event_type].remove(handler)

    def add_middleware(self, middleware: Callable) -> None:
        """Add event middleware"""
        self.middleware.append(middleware)

    async def publish(self, event: Event) -> None:
        """Publish event"""
        # Apply middleware
        for mw in self.middleware:
            event = await mw(event) if hasattr(mw, '__await__') else mw(event)

        # Handle event
        if event.event_type in self.handlers:
            for handler in self.handlers[event.event_type]:
                try:
                    if hasattr(handler, '__await__'):
                        await handler(event)
                    else:
                        handler(event)
                except Exception as e:
                    logger.error(f"Error in event handler: {e}")


__all__ = [
    'Event',
    'EventStore',
    'InMemoryEventStore',
    'EventProjection',
    'InMemoryProjection',
    'EventHandler',
    'EventPublisher',
    'InMemoryEventPublisher',
    'EventSourcing',
    'EventBus',
]
