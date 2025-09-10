"""
BLNCS Real-time Event Streaming and Message Queues
Apache Kafka, Redis Streams, WebSocket, and event-driven architecture.
"""

from .event_streaming import (
    EventStreamManager,
    EventProducer,
    EventConsumer,
    MessageQueue,
    EventRouter,
    StreamProcessor,
    EventStore,
    WebSocketManager,
    EventBus,
    StreamingConfig,
    EventType,
    get_event_stream_manager,
    initialize_streaming
)

__all__ = [
    "EventStreamManager",
    "EventProducer",
    "EventConsumer",
    "MessageQueue",
    "EventRouter",
    "StreamProcessor",
    "EventStore",
    "WebSocketManager",
    "EventBus",
    "StreamingConfig",
    "EventType",
    "get_event_stream_manager",
    "initialize_streaming"
]