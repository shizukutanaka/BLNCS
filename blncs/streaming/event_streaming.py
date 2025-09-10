"""
Real-time Event Streaming and Message Queue System
High-performance event processing with Kafka, Redis Streams, and WebSocket integration.
"""

import asyncio
import json
import logging
import time
import uuid
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Callable, AsyncGenerator
from enum import Enum
from dataclasses import dataclass, field, asdict
from collections import defaultdict, deque
import aioredis
import websockets
from kafka import KafkaProducer, KafkaConsumer
from kafka.errors import KafkaError
import structlog

logger = structlog.get_logger(__name__)

class EventType(Enum):
    PAYMENT_CREATED = "payment.created"
    PAYMENT_COMPLETED = "payment.completed"
    PAYMENT_FAILED = "payment.failed"
    CHANNEL_OPENED = "channel.opened"
    CHANNEL_CLOSED = "channel.closed"
    CHANNEL_UPDATED = "channel.updated"
    NODE_CONNECTED = "node.connected"
    NODE_DISCONNECTED = "node.disconnected"
    INVOICE_CREATED = "invoice.created"
    INVOICE_PAID = "invoice.paid"
    LIQUIDITY_WARNING = "liquidity.warning"
    SECURITY_ALERT = "security.alert"
    SYSTEM_ERROR = "system.error"
    USER_ACTION = "user.action"
    COMPLIANCE_EVENT = "compliance.event"
    PERFORMANCE_ALERT = "performance.alert"

class StreamingBackend(Enum):
    KAFKA = "kafka"
    REDIS_STREAMS = "redis_streams"
    IN_MEMORY = "in_memory"

class DeliveryGuarantee(Enum):
    AT_MOST_ONCE = "at_most_once"
    AT_LEAST_ONCE = "at_least_once"
    EXACTLY_ONCE = "exactly_once"

@dataclass
class StreamingConfig:
    backend: StreamingBackend = StreamingBackend.KAFKA
    kafka_bootstrap_servers: str = "localhost:9092"
    redis_url: str = "redis://localhost:6379"
    max_message_size: int = 1048576  # 1MB
    batch_size: int = 100
    batch_timeout_ms: int = 1000
    retention_hours: int = 168  # 7 days
    partitions: int = 3
    replication_factor: int = 1
    delivery_guarantee: DeliveryGuarantee = DeliveryGuarantee.AT_LEAST_ONCE
    enable_compression: bool = True
    enable_websockets: bool = True
    websocket_port: int = 8765
    consumer_group_prefix: str = "blncs"

@dataclass
class Event:
    id: str
    type: EventType
    data: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.utcnow)
    source: str = "blncs"
    correlation_id: Optional[str] = None
    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "correlation_id": self.correlation_id,
            "tenant_id": self.tenant_id,
            "user_id": self.user_id,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Event':
        return cls(
            id=data["id"],
            type=EventType(data["type"]),
            data=data["data"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            source=data.get("source", "blncs"),
            correlation_id=data.get("correlation_id"),
            tenant_id=data.get("tenant_id"),
            user_id=data.get("user_id"),
            metadata=data.get("metadata", {})
        )

class EventProducer:
    def __init__(self, config: StreamingConfig):
        self.config = config
        self.kafka_producer = None
        self.redis_client = None
        self.message_buffer = deque()
        self.buffer_lock = threading.Lock()
        self.batch_task = None
    
    async def initialize(self):
        """Initialize event producer"""
        try:
            if self.config.backend == StreamingBackend.KAFKA:
                await self._initialize_kafka_producer()
            elif self.config.backend == StreamingBackend.REDIS_STREAMS:
                await self._initialize_redis_client()
            
            # Start batch processing
            self.batch_task = asyncio.create_task(self._batch_processor())
            
            logger.info(f"Event producer initialized with backend: {self.config.backend.value}")
            
        except Exception as e:
            logger.error(f"Failed to initialize event producer: {e}")
            raise
    
    async def _initialize_kafka_producer(self):
        """Initialize Kafka producer"""
        self.kafka_producer = KafkaProducer(
            bootstrap_servers=self.config.kafka_bootstrap_servers.split(','),
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            key_serializer=lambda v: v.encode('utf-8') if v else None,
            batch_size=self.config.batch_size * 1024,  # Convert to bytes
            linger_ms=self.config.batch_timeout_ms,
            compression_type='gzip' if self.config.enable_compression else None,
            acks='all' if self.config.delivery_guarantee == DeliveryGuarantee.EXACTLY_ONCE else 1
        )
    
    async def _initialize_redis_client(self):
        """Initialize Redis client"""
        self.redis_client = aioredis.from_url(self.config.redis_url)
    
    async def publish_event(self, event: Event, topic: str = None) -> bool:
        """Publish event to stream"""
        try:
            if not topic:
                topic = f"blncs.{event.type.value.replace('.', '_')}"
            
            if self.config.backend == StreamingBackend.KAFKA:
                return await self._publish_to_kafka(event, topic)
            elif self.config.backend == StreamingBackend.REDIS_STREAMS:
                return await self._publish_to_redis_stream(event, topic)
            else:
                # In-memory fallback
                return await self._publish_to_memory(event, topic)
                
        except Exception as e:
            logger.error(f"Failed to publish event {event.id}: {e}")
            return False
    
    async def _publish_to_kafka(self, event: Event, topic: str) -> bool:
        """Publish event to Kafka"""
        try:
            # Use tenant_id as partition key for tenant isolation
            partition_key = event.tenant_id or event.user_id or event.id
            
            future = self.kafka_producer.send(
                topic=topic,
                value=event.to_dict(),
                key=partition_key
            )
            
            # For exactly-once semantics, wait for acknowledgment
            if self.config.delivery_guarantee == DeliveryGuarantee.EXACTLY_ONCE:
                record_metadata = future.get(timeout=10)
                logger.debug(f"Event {event.id} published to {record_metadata.topic}:{record_metadata.partition}")
            
            return True
            
        except KafkaError as e:
            logger.error(f"Kafka publish error for event {event.id}: {e}")
            return False
    
    async def _publish_to_redis_stream(self, event: Event, stream: str) -> bool:
        """Publish event to Redis Stream"""
        try:
            await self.redis_client.xadd(stream, event.to_dict())
            
            # Set retention policy
            await self.redis_client.xtrim(
                stream, 
                maxlen=10000,  # Keep last 10k messages
                approximate=True
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Redis stream publish error for event {event.id}: {e}")
            return False
    
    async def _publish_to_memory(self, event: Event, topic: str) -> bool:
        """Publish event to in-memory buffer"""
        with self.buffer_lock:
            self.message_buffer.append((topic, event))
            
            # Limit buffer size
            while len(self.message_buffer) > 10000:
                self.message_buffer.popleft()
        
        return True
    
    async def _batch_processor(self):
        """Process events in batches"""
        batch = []
        last_flush = time.time()
        
        while True:
            try:
                current_time = time.time()
                
                # Collect events for batch
                with self.buffer_lock:
                    while len(self.message_buffer) > 0 and len(batch) < self.config.batch_size:
                        batch.append(self.message_buffer.popleft())
                
                # Flush batch if size reached or timeout elapsed
                if len(batch) >= self.config.batch_size or \
                   (len(batch) > 0 and (current_time - last_flush) * 1000 >= self.config.batch_timeout_ms):
                    
                    await self._flush_batch(batch)
                    batch.clear()
                    last_flush = current_time
                
                await asyncio.sleep(0.01)  # Small delay to prevent busy loop
                
            except Exception as e:
                logger.error(f"Batch processor error: {e}")
                await asyncio.sleep(1)
    
    async def _flush_batch(self, batch: List[tuple]):
        """Flush batch of events"""
        if not batch:
            return
        
        try:
            if self.config.backend == StreamingBackend.KAFKA:
                for topic, event in batch:
                    await self._publish_to_kafka(event, topic)
                self.kafka_producer.flush()
            
        except Exception as e:
            logger.error(f"Batch flush error: {e}")
    
    async def close(self):
        """Close event producer"""
        if self.batch_task:
            self.batch_task.cancel()
        
        if self.kafka_producer:
            self.kafka_producer.close()
        
        if self.redis_client:
            await self.redis_client.close()

class EventConsumer:
    def __init__(self, config: StreamingConfig, consumer_group: str):
        self.config = config
        self.consumer_group = consumer_group
        self.kafka_consumer = None
        self.redis_client = None
        self.event_handlers = defaultdict(list)
        self.running = False
        self.consumer_task = None
    
    async def initialize(self):
        """Initialize event consumer"""
        try:
            if self.config.backend == StreamingBackend.KAFKA:
                await self._initialize_kafka_consumer()
            elif self.config.backend == StreamingBackend.REDIS_STREAMS:
                await self._initialize_redis_client()
            
            logger.info(f"Event consumer initialized for group: {self.consumer_group}")
            
        except Exception as e:
            logger.error(f"Failed to initialize event consumer: {e}")
            raise
    
    async def _initialize_kafka_consumer(self):
        """Initialize Kafka consumer"""
        self.kafka_consumer = KafkaConsumer(
            bootstrap_servers=self.config.kafka_bootstrap_servers.split(','),
            group_id=f"{self.config.consumer_group_prefix}_{self.consumer_group}",
            value_deserializer=lambda m: json.loads(m.decode('utf-8')),
            key_deserializer=lambda m: m.decode('utf-8') if m else None,
            auto_offset_reset='earliest',
            enable_auto_commit=self.config.delivery_guarantee != DeliveryGuarantee.EXACTLY_ONCE
        )
    
    async def _initialize_redis_client(self):
        """Initialize Redis client"""
        self.redis_client = aioredis.from_url(self.config.redis_url)
    
    def subscribe(self, event_type: EventType, handler: Callable[[Event], None]):
        """Subscribe to event type"""
        self.event_handlers[event_type].append(handler)
        logger.info(f"Subscribed to {event_type.value} in group {self.consumer_group}")
    
    def subscribe_topic(self, topic: str, handler: Callable[[Event], None]):
        """Subscribe to topic"""
        if self.config.backend == StreamingBackend.KAFKA and self.kafka_consumer:
            self.kafka_consumer.subscribe([topic])
        
        # Store handler for processing
        self.event_handlers[topic].append(handler)
    
    async def start_consuming(self):
        """Start consuming events"""
        if self.running:
            return
        
        self.running = True
        
        if self.config.backend == StreamingBackend.KAFKA:
            self.consumer_task = asyncio.create_task(self._consume_kafka_messages())
        elif self.config.backend == StreamingBackend.REDIS_STREAMS:
            self.consumer_task = asyncio.create_task(self._consume_redis_streams())
        
        logger.info(f"Started consuming events for group: {self.consumer_group}")
    
    async def _consume_kafka_messages(self):
        """Consume messages from Kafka"""
        while self.running:
            try:
                message_pack = self.kafka_consumer.poll(timeout_ms=1000)
                
                for topic_partition, messages in message_pack.items():
                    for message in messages:
                        await self._process_message(message.value, message.topic)
                
                # Commit offsets for exactly-once processing
                if self.config.delivery_guarantee == DeliveryGuarantee.EXACTLY_ONCE:
                    self.kafka_consumer.commit()
                
            except Exception as e:
                logger.error(f"Kafka consumer error: {e}")
                await asyncio.sleep(1)
    
    async def _consume_redis_streams(self):
        """Consume messages from Redis Streams"""
        streams = {}
        for event_type in self.event_handlers.keys():
            if isinstance(event_type, EventType):
                stream_name = f"blncs.{event_type.value.replace('.', '_')}"
                streams[stream_name] = '0'  # Start from beginning
        
        while self.running:
            try:
                messages = await self.redis_client.xread(streams, block=1000)
                
                for stream_name, stream_messages in messages:
                    for message_id, fields in stream_messages:
                        # Convert Redis fields to event dict
                        event_data = {k.decode(): v.decode() for k, v in fields.items()}
                        await self._process_message(event_data, stream_name.decode())
                        
                        # Update stream position
                        streams[stream_name.decode()] = message_id.decode()
                
            except Exception as e:
                logger.error(f"Redis streams consumer error: {e}")
                await asyncio.sleep(1)
    
    async def _process_message(self, message_data: Dict[str, Any], topic: str):
        """Process incoming message"""
        try:
            # Parse event
            if isinstance(message_data, dict) and 'type' in message_data:
                event = Event.from_dict(message_data)
            else:
                # Handle raw message data
                event = Event(
                    id=str(uuid.uuid4()),
                    type=EventType.SYSTEM_ERROR,
                    data=message_data if isinstance(message_data, dict) else {"raw": str(message_data)}
                )
            
            # Route to handlers
            handlers = self.event_handlers.get(event.type, [])
            handlers.extend(self.event_handlers.get(topic, []))
            
            # Execute handlers
            for handler in handlers:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(event)
                    else:
                        handler(event)
                except Exception as e:
                    logger.error(f"Handler error for event {event.id}: {e}")
                    
        except Exception as e:
            logger.error(f"Message processing error: {e}")
    
    async def stop_consuming(self):
        """Stop consuming events"""
        self.running = False
        
        if self.consumer_task:
            self.consumer_task.cancel()
            try:
                await self.consumer_task
            except asyncio.CancelledError:
                pass
        
        if self.kafka_consumer:
            self.kafka_consumer.close()
        
        if self.redis_client:
            await self.redis_client.close()

class MessageQueue:
    def __init__(self, name: str, config: StreamingConfig):
        self.name = name
        self.config = config
        self.redis_client = None
        self.queue_key = f"queue:{name}"
        self.processing_key = f"processing:{name}"
        self.dead_letter_key = f"dead_letter:{name}"
    
    async def initialize(self):
        """Initialize message queue"""
        self.redis_client = aioredis.from_url(self.config.redis_url)
    
    async def enqueue(self, message: Dict[str, Any], priority: int = 0) -> str:
        """Add message to queue"""
        message_id = str(uuid.uuid4())
        queue_item = {
            "id": message_id,
            "data": json.dumps(message),
            "priority": priority,
            "timestamp": datetime.utcnow().isoformat(),
            "attempts": 0
        }
        
        # Add to priority queue (higher score = higher priority)
        await self.redis_client.zadd(self.queue_key, {json.dumps(queue_item): priority})
        
        return message_id
    
    async def dequeue(self, timeout: int = 10) -> Optional[Dict[str, Any]]:
        """Get message from queue"""
        # Use BZPOPMAX for blocking pop with priority
        result = await self.redis_client.bzpopmax(self.queue_key, timeout=timeout)
        
        if result:
            _, message_data, _ = result
            message = json.loads(message_data)
            
            # Move to processing queue
            await self.redis_client.hset(
                self.processing_key,
                message["id"],
                message_data
            )
            
            return message
        
        return None
    
    async def ack_message(self, message_id: str):
        """Acknowledge message processing"""
        await self.redis_client.hdel(self.processing_key, message_id)
    
    async def nack_message(self, message_id: str, requeue: bool = True):
        """Negative acknowledgment - requeue or dead letter"""
        message_data = await self.redis_client.hget(self.processing_key, message_id)
        
        if message_data:
            message = json.loads(message_data)
            message["attempts"] += 1
            
            if requeue and message["attempts"] < 3:
                # Requeue with lower priority
                await self.redis_client.zadd(
                    self.queue_key, 
                    {json.dumps(message): message["priority"] - message["attempts"]}
                )
            else:
                # Move to dead letter queue
                await self.redis_client.lpush(self.dead_letter_key, message_data)
            
            await self.redis_client.hdel(self.processing_key, message_id)
    
    async def get_stats(self) -> Dict[str, int]:
        """Get queue statistics"""
        return {
            "queued": await self.redis_client.zcard(self.queue_key),
            "processing": await self.redis_client.hlen(self.processing_key),
            "dead_letter": await self.redis_client.llen(self.dead_letter_key)
        }

class WebSocketManager:
    def __init__(self, config: StreamingConfig):
        self.config = config
        self.clients = {}
        self.topic_subscriptions = defaultdict(set)
        self.server = None
    
    async def start_server(self):
        """Start WebSocket server"""
        if not self.config.enable_websockets:
            return
        
        self.server = await websockets.serve(
            self.handle_client,
            "localhost",
            self.config.websocket_port
        )
        
        logger.info(f"WebSocket server started on port {self.config.websocket_port}")
    
    async def handle_client(self, websocket, path):
        """Handle WebSocket client connection"""
        client_id = str(uuid.uuid4())
        self.clients[client_id] = websocket
        
        logger.info(f"WebSocket client connected: {client_id}")
        
        try:
            async for message in websocket:
                await self.handle_message(client_id, message)
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            await self.disconnect_client(client_id)
    
    async def handle_message(self, client_id: str, message: str):
        """Handle client message"""
        try:
            data = json.loads(message)
            action = data.get("action")
            
            if action == "subscribe":
                topic = data.get("topic")
                if topic:
                    self.topic_subscriptions[topic].add(client_id)
                    await self.send_to_client(client_id, {
                        "type": "subscription_confirmed",
                        "topic": topic
                    })
            
            elif action == "unsubscribe":
                topic = data.get("topic")
                if topic:
                    self.topic_subscriptions[topic].discard(client_id)
                    await self.send_to_client(client_id, {
                        "type": "unsubscription_confirmed",
                        "topic": topic
                    })
            
        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON from client {client_id}: {message}")
    
    async def disconnect_client(self, client_id: str):
        """Handle client disconnection"""
        # Remove from all topic subscriptions
        for subscribers in self.topic_subscriptions.values():
            subscribers.discard(client_id)
        
        # Remove from clients
        if client_id in self.clients:
            del self.clients[client_id]
        
        logger.info(f"WebSocket client disconnected: {client_id}")
    
    async def send_to_client(self, client_id: str, message: Dict[str, Any]):
        """Send message to specific client"""
        if client_id in self.clients:
            websocket = self.clients[client_id]
            try:
                await websocket.send(json.dumps(message))
            except websockets.exceptions.ConnectionClosed:
                await self.disconnect_client(client_id)
    
    async def broadcast_to_topic(self, topic: str, event: Event):
        """Broadcast event to all subscribers of topic"""
        if topic in self.topic_subscriptions:
            message = {
                "type": "event",
                "topic": topic,
                "event": event.to_dict()
            }
            
            disconnected_clients = []
            
            for client_id in self.topic_subscriptions[topic]:
                try:
                    await self.send_to_client(client_id, message)
                except:
                    disconnected_clients.append(client_id)
            
            # Clean up disconnected clients
            for client_id in disconnected_clients:
                await self.disconnect_client(client_id)

class EventRouter:
    def __init__(self):
        self.routes = {}
        self.filters = []
        self.transformers = []
    
    def add_route(self, event_type: EventType, destination: str, condition: Callable[[Event], bool] = None):
        """Add routing rule"""
        if event_type not in self.routes:
            self.routes[event_type] = []
        
        self.routes[event_type].append({
            "destination": destination,
            "condition": condition
        })
    
    def add_filter(self, filter_func: Callable[[Event], bool]):
        """Add event filter"""
        self.filters.append(filter_func)
    
    def add_transformer(self, transformer_func: Callable[[Event], Event]):
        """Add event transformer"""
        self.transformers.append(transformer_func)
    
    async def route_event(self, event: Event) -> List[str]:
        """Route event to destinations"""
        # Apply filters
        for filter_func in self.filters:
            if not filter_func(event):
                return []
        
        # Apply transformers
        for transformer in self.transformers:
            event = transformer(event)
        
        # Find matching routes
        destinations = []
        routes = self.routes.get(event.type, [])
        
        for route in routes:
            condition = route.get("condition")
            if condition is None or condition(event):
                destinations.append(route["destination"])
        
        return destinations

class EventStreamManager:
    def __init__(self, config: StreamingConfig):
        self.config = config
        self.producer = EventProducer(config)
        self.consumers = {}
        self.message_queues = {}
        self.websocket_manager = WebSocketManager(config) 
        self.event_router = EventRouter()
        self.event_store = None
        self.running = False
    
    async def initialize(self):
        """Initialize event stream manager"""
        try:
            await self.producer.initialize()
            
            if self.config.enable_websockets:
                await self.websocket_manager.start_server()
            
            logger.info("Event stream manager initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize event stream manager: {e}")
            raise
    
    async def create_consumer(self, consumer_group: str) -> EventConsumer:
        """Create event consumer"""
        consumer = EventConsumer(self.config, consumer_group)
        await consumer.initialize()
        self.consumers[consumer_group] = consumer
        return consumer
    
    async def create_queue(self, queue_name: str) -> MessageQueue:
        """Create message queue"""
        queue = MessageQueue(queue_name, self.config)
        await queue.initialize()
        self.message_queues[queue_name] = queue
        return queue
    
    async def publish_event(self, event: Event) -> bool:
        """Publish event to all configured destinations"""
        success = True
        
        try:
            # Publish to main stream
            result = await self.producer.publish_event(event)
            success = success and result
            
            # Route to specific destinations
            destinations = await self.event_router.route_event(event)
            for destination in destinations:
                if destination.startswith("queue:"):
                    queue_name = destination[6:]
                    if queue_name in self.message_queues:
                        await self.message_queues[queue_name].enqueue(event.to_dict())
            
            # Broadcast to WebSocket subscribers
            if self.config.enable_websockets:
                topic = f"blncs.{event.type.value}"
                await self.websocket_manager.broadcast_to_topic(topic, event)
            
        except Exception as e:
            logger.error(f"Error publishing event {event.id}: {e}")
            success = False
        
        return success
    
    async def create_event(self, event_type: EventType, data: Dict[str, Any], 
                          user_id: str = None, tenant_id: str = None,
                          correlation_id: str = None) -> Event:
        """Create new event"""
        event = Event(
            id=str(uuid.uuid4()),
            type=event_type,
            data=data,
            user_id=user_id,
            tenant_id=tenant_id,
            correlation_id=correlation_id
        )
        
        return event
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get streaming statistics"""
        stats = {
            "producer_stats": {},
            "consumer_stats": {},
            "queue_stats": {},
            "websocket_clients": len(self.websocket_manager.clients)
        }
        
        # Get queue stats
        for name, queue in self.message_queues.items():
            stats["queue_stats"][name] = await queue.get_stats()
        
        return stats
    
    async def shutdown(self):
        """Shutdown event stream manager"""
        self.running = False
        
        # Stop all consumers
        for consumer in self.consumers.values():
            await consumer.stop_consuming()
        
        # Close producer
        await self.producer.close()
        
        logger.info("Event stream manager shutdown completed")

# Global event stream manager
_event_stream_manager = None

async def get_event_stream_manager(config: Optional[StreamingConfig] = None) -> EventStreamManager:
    """Get or create event stream manager"""
    global _event_stream_manager
    
    if _event_stream_manager is None:
        if config is None:
            config = StreamingConfig()
        
        _event_stream_manager = EventStreamManager(config)
        await _event_stream_manager.initialize()
    
    return _event_stream_manager

async def initialize_streaming(config: StreamingConfig) -> EventStreamManager:
    """Initialize streaming with custom config"""
    manager = EventStreamManager(config)
    await manager.initialize()
    return manager