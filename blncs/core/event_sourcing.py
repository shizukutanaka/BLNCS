#!/usr/bin/env python3
"""
Event Sourcing and CQRS Implementation for BLNCS
Provides comprehensive event sourcing with command/query separation for Lightning Network operations
"""

import asyncio
import json
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Type, Union, Callable, AsyncGenerator
import logging
import sqlite3
import threading
from contextlib import asynccontextmanager

from blncs.core.async_memory_manager import track_async_task, lightning_operation_context
from blncs.core.exceptions import BLNCSError

logger = logging.getLogger(__name__)

class EventType(Enum):
    """Event types for Lightning Network operations"""
    # Node events
    NODE_STARTED = "node_started"
    NODE_STOPPED = "node_stopped"
    NODE_INFO_UPDATED = "node_info_updated"
    
    # Channel events
    CHANNEL_OPENING_INITIATED = "channel_opening_initiated"
    CHANNEL_OPENED = "channel_opened"
    CHANNEL_CLOSING_INITIATED = "channel_closing_initiated"
    CHANNEL_CLOSED = "channel_closed"
    CHANNEL_UPDATED = "channel_updated"
    CHANNEL_BALANCE_CHANGED = "channel_balance_changed"
    
    # Payment events
    PAYMENT_INITIATED = "payment_initiated"
    PAYMENT_SENT = "payment_sent"
    PAYMENT_RECEIVED = "payment_received"
    PAYMENT_FAILED = "payment_failed"
    PAYMENT_HTLC_ADDED = "payment_htlc_added"
    PAYMENT_HTLC_SETTLED = "payment_htlc_settled"
    PAYMENT_HTLC_FAILED = "payment_htlc_failed"
    
    # Invoice events
    INVOICE_CREATED = "invoice_created"
    INVOICE_SETTLED = "invoice_settled"
    INVOICE_EXPIRED = "invoice_expired"
    INVOICE_CANCELLED = "invoice_cancelled"
    
    # Multi-path payment events
    MPP_PAYMENT_STARTED = "mpp_payment_started"
    MPP_PATH_ADDED = "mpp_path_added"
    MPP_PATH_SUCCEEDED = "mpp_path_succeeded"
    MPP_PATH_FAILED = "mpp_path_failed"
    MPP_PAYMENT_COMPLETED = "mpp_payment_completed"
    
    # System events
    SYSTEM_STARTED = "system_started"
    SYSTEM_STOPPED = "system_stopped"
    CONFIG_UPDATED = "config_updated"
    BACKUP_CREATED = "backup_created"
    ERROR_OCCURRED = "error_occurred"
    ALERT_TRIGGERED = "alert_triggered"

@dataclass
class Event:
    """Base event class"""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: EventType = EventType.SYSTEM_STARTED
    aggregate_id: str = ""
    aggregate_type: str = ""
    event_data: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    version: int = 1
    user_id: Optional[str] = None
    correlation_id: Optional[str] = None
    causation_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Event':
        """Create event from dictionary"""
        return cls(
            event_id=data.get('event_id', str(uuid.uuid4())),
            event_type=EventType(data['event_type']),
            aggregate_id=data.get('aggregate_id', ''),
            aggregate_type=data.get('aggregate_type', ''),
            event_data=data.get('event_data', {}),
            metadata=data.get('metadata', {}),
            timestamp=data.get('timestamp', time.time()),
            version=data.get('version', 1),
            user_id=data.get('user_id'),
            correlation_id=data.get('correlation_id'),
            causation_id=data.get('causation_id')
        )

@dataclass
class Command:
    """Base command class for CQRS"""
    command_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    command_type: str = ""
    aggregate_id: str = ""
    command_data: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    user_id: Optional[str] = None
    correlation_id: Optional[str] = None
    expected_version: Optional[int] = None

@dataclass
class CommandResult:
    """Command execution result"""
    success: bool
    events: List[Event] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    aggregate_version: Optional[int] = None
    execution_time: float = 0.0

class EventStore(ABC):
    """Abstract event store interface"""
    
    @abstractmethod
    async def append_events(self, aggregate_id: str, events: List[Event], 
                           expected_version: Optional[int] = None) -> bool:
        """Append events to aggregate stream"""
        pass
    
    @abstractmethod
    async def get_events(self, aggregate_id: str, from_version: int = 0) -> List[Event]:
        """Get events for aggregate"""
        pass
    
    @abstractmethod
    async def get_all_events(self, from_timestamp: Optional[float] = None, 
                           to_timestamp: Optional[float] = None,
                           event_types: Optional[List[EventType]] = None) -> AsyncGenerator[Event, None]:
        """Get all events with optional filtering"""
        pass
    
    @abstractmethod
    async def get_aggregate_version(self, aggregate_id: str) -> int:
        """Get current version of aggregate"""
        pass
    
    @abstractmethod
    async def snapshot_aggregate(self, aggregate_id: str, snapshot_data: Dict[str, Any], version: int):
        """Save aggregate snapshot"""
        pass
    
    @abstractmethod
    async def get_snapshot(self, aggregate_id: str) -> Optional[Dict[str, Any]]:
        """Get latest aggregate snapshot"""
        pass

class SQLiteEventStore(EventStore):
    """SQLite implementation of event store"""
    
    def __init__(self, database_path: str = ":memory:"):
        self.database_path = database_path
        self._connection: Optional[sqlite3.Connection] = None
        self._lock = threading.RLock()
        self._initialize_db()
    
    def _initialize_db(self):
        """Initialize database schema"""
        with self._get_connection() as conn:
            # Events table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    event_type TEXT NOT NULL,
                    aggregate_id TEXT NOT NULL,
                    aggregate_type TEXT NOT NULL,
                    event_data TEXT NOT NULL,
                    metadata TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    version INTEGER NOT NULL,
                    user_id TEXT,
                    correlation_id TEXT,
                    causation_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Snapshots table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    aggregate_id TEXT NOT NULL,
                    aggregate_type TEXT NOT NULL,
                    snapshot_data TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(aggregate_id, version)
                )
            """)
            
            # Indexes for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_aggregate ON events(aggregate_id, version)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_snapshots_aggregate ON snapshots(aggregate_id)")
            
            conn.commit()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection"""
        with self._lock:
            if not self._connection:
                self._connection = sqlite3.connect(self.database_path, check_same_thread=False)
                self._connection.row_factory = sqlite3.Row
            return self._connection
    
    async def append_events(self, aggregate_id: str, events: List[Event], 
                           expected_version: Optional[int] = None) -> bool:
        """Append events to aggregate stream"""
        if not events:
            return True
        
        try:
            with self._get_connection() as conn:
                # Check expected version if provided
                if expected_version is not None:
                    current_version = await self.get_aggregate_version(aggregate_id)
                    if current_version != expected_version:
                        raise BLNCSError(f"Concurrency conflict: expected version {expected_version}, got {current_version}")
                
                # Insert events
                for event in events:
                    conn.execute("""
                        INSERT INTO events (
                            event_id, event_type, aggregate_id, aggregate_type,
                            event_data, metadata, timestamp, version,
                            user_id, correlation_id, causation_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        event.event_id,
                        event.event_type.value,
                        event.aggregate_id,
                        event.aggregate_type,
                        json.dumps(event.event_data),
                        json.dumps(event.metadata),
                        event.timestamp,
                        event.version,
                        event.user_id,
                        event.correlation_id,
                        event.causation_id
                    ))
                
                conn.commit()
                logger.debug(f"Appended {len(events)} events for aggregate {aggregate_id}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to append events: {e}")
            return False
    
    async def get_events(self, aggregate_id: str, from_version: int = 0) -> List[Event]:
        """Get events for aggregate"""
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("""
                    SELECT event_id, event_type, aggregate_id, aggregate_type,
                           event_data, metadata, timestamp, version,
                           user_id, correlation_id, causation_id
                    FROM events 
                    WHERE aggregate_id = ? AND version >= ?
                    ORDER BY version ASC
                """, (aggregate_id, from_version))
                
                events = []
                for row in cursor:
                    event = Event(
                        event_id=row['event_id'],
                        event_type=EventType(row['event_type']),
                        aggregate_id=row['aggregate_id'],
                        aggregate_type=row['aggregate_type'],
                        event_data=json.loads(row['event_data']),
                        metadata=json.loads(row['metadata']),
                        timestamp=row['timestamp'],
                        version=row['version'],
                        user_id=row['user_id'],
                        correlation_id=row['correlation_id'],
                        causation_id=row['causation_id']
                    )
                    events.append(event)
                
                return events
                
        except Exception as e:
            logger.error(f"Failed to get events for aggregate {aggregate_id}: {e}")
            return []
    
    async def get_all_events(self, from_timestamp: Optional[float] = None, 
                           to_timestamp: Optional[float] = None,
                           event_types: Optional[List[EventType]] = None) -> AsyncGenerator[Event, None]:
        """Get all events with optional filtering"""
        try:
            with self._get_connection() as conn:
                # Build query
                query = "SELECT * FROM events WHERE 1=1"
                params = []
                
                if from_timestamp:
                    query += " AND timestamp >= ?"
                    params.append(from_timestamp)
                
                if to_timestamp:
                    query += " AND timestamp <= ?"
                    params.append(to_timestamp)
                
                if event_types:
                    type_placeholders = ','.join('?' * len(event_types))
                    query += f" AND event_type IN ({type_placeholders})"
                    params.extend([et.value for et in event_types])
                
                query += " ORDER BY timestamp ASC"
                
                cursor = conn.execute(query, params)
                
                for row in cursor:
                    event = Event(
                        event_id=row['event_id'],
                        event_type=EventType(row['event_type']),
                        aggregate_id=row['aggregate_id'],
                        aggregate_type=row['aggregate_type'],
                        event_data=json.loads(row['event_data']),
                        metadata=json.loads(row['metadata']),
                        timestamp=row['timestamp'],
                        version=row['version'],
                        user_id=row['user_id'],
                        correlation_id=row['correlation_id'],
                        causation_id=row['causation_id']
                    )
                    yield event
                    
        except Exception as e:
            logger.error(f"Failed to get all events: {e}")
    
    async def get_aggregate_version(self, aggregate_id: str) -> int:
        """Get current version of aggregate"""
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("""
                    SELECT MAX(version) as max_version 
                    FROM events 
                    WHERE aggregate_id = ?
                """, (aggregate_id,))
                
                row = cursor.fetchone()
                return row['max_version'] or 0
                
        except Exception as e:
            logger.error(f"Failed to get aggregate version: {e}")
            return 0
    
    async def snapshot_aggregate(self, aggregate_id: str, snapshot_data: Dict[str, Any], version: int):
        """Save aggregate snapshot"""
        try:
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO snapshots 
                    (aggregate_id, aggregate_type, snapshot_data, version)
                    VALUES (?, ?, ?, ?)
                """, (
                    aggregate_id,
                    snapshot_data.get('aggregate_type', 'unknown'),
                    json.dumps(snapshot_data),
                    version
                ))
                
                conn.commit()
                logger.debug(f"Created snapshot for aggregate {aggregate_id} at version {version}")
                
        except Exception as e:
            logger.error(f"Failed to create snapshot: {e}")
    
    async def get_snapshot(self, aggregate_id: str) -> Optional[Dict[str, Any]]:
        """Get latest aggregate snapshot"""
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("""
                    SELECT snapshot_data, version 
                    FROM snapshots 
                    WHERE aggregate_id = ? 
                    ORDER BY version DESC 
                    LIMIT 1
                """, (aggregate_id,))
                
                row = cursor.fetchone()
                if row:
                    snapshot_data = json.loads(row['snapshot_data'])
                    snapshot_data['snapshot_version'] = row['version']
                    return snapshot_data
                
                return None
                
        except Exception as e:
            logger.error(f"Failed to get snapshot: {e}")
            return None

class Aggregate(ABC):
    """Base aggregate class"""
    
    def __init__(self, aggregate_id: str):
        self.aggregate_id = aggregate_id
        self.version = 0
        self.uncommitted_events: List[Event] = []
    
    @abstractmethod
    def apply_event(self, event: Event):
        """Apply event to aggregate state"""
        pass
    
    def raise_event(self, event_type: EventType, event_data: Dict[str, Any],
                   metadata: Optional[Dict[str, Any]] = None,
                   user_id: Optional[str] = None,
                   correlation_id: Optional[str] = None):
        """Raise new event"""
        event = Event(
            event_type=event_type,
            aggregate_id=self.aggregate_id,
            aggregate_type=self.__class__.__name__,
            event_data=event_data,
            metadata=metadata or {},
            version=self.version + 1,
            user_id=user_id,
            correlation_id=correlation_id
        )
        
        self.uncommitted_events.append(event)
        self.apply_event(event)
        self.version += 1
    
    def mark_events_committed(self):
        """Mark events as committed"""
        self.uncommitted_events.clear()
    
    def load_from_history(self, events: List[Event]):
        """Load aggregate from event history"""
        for event in events:
            self.apply_event(event)
            self.version = max(self.version, event.version)

class LightningNodeAggregate(Aggregate):
    """Lightning node aggregate"""
    
    def __init__(self, node_id: str):
        super().__init__(node_id)
        self.alias = ""
        self.pubkey = ""
        self.network = ""
        self.status = "offline"
        self.channels: Dict[str, Dict[str, Any]] = {}
        self.balance = {
            'total': 0,
            'confirmed': 0,
            'channel_local': 0,
            'channel_remote': 0
        }
    
    def apply_event(self, event: Event):
        """Apply event to node state"""
        if event.event_type == EventType.NODE_STARTED:
            self.status = "online"
            self.alias = event.event_data.get('alias', '')
            self.pubkey = event.event_data.get('pubkey', '')
            self.network = event.event_data.get('network', '')
            
        elif event.event_type == EventType.NODE_STOPPED:
            self.status = "offline"
            
        elif event.event_type == EventType.CHANNEL_OPENED:
            channel_id = event.event_data['channel_id']
            self.channels[channel_id] = event.event_data
            
        elif event.event_type == EventType.CHANNEL_CLOSED:
            channel_id = event.event_data['channel_id']
            self.channels.pop(channel_id, None)
            
        elif event.event_type == EventType.CHANNEL_BALANCE_CHANGED:
            channel_id = event.event_data['channel_id']
            if channel_id in self.channels:
                self.channels[channel_id]['local_balance'] = event.event_data.get('local_balance')
                self.channels[channel_id]['remote_balance'] = event.event_data.get('remote_balance')
            
            # Update total balance
            self.balance.update(event.event_data.get('new_balance', {}))

class CommandHandler(ABC):
    """Base command handler"""
    
    @abstractmethod
    async def handle(self, command: Command) -> CommandResult:
        """Handle command"""
        pass

class LightningCommandHandler(CommandHandler):
    """Lightning Network command handler"""
    
    def __init__(self, event_store: EventStore, lightning_client=None):
        self.event_store = event_store
        self.lightning_client = lightning_client
    
    @track_async_task("handle_lightning_command")
    async def handle(self, command: Command) -> CommandResult:
        """Handle Lightning Network commands"""
        async with lightning_operation_context(f"command_{command.command_type}"):
            start_time = time.time()
            
            try:
                # Load aggregate
                aggregate = await self._load_aggregate(command.aggregate_id)
                
                # Process command
                if command.command_type == "StartNode":
                    await self._handle_start_node(aggregate, command)
                elif command.command_type == "OpenChannel":
                    await self._handle_open_channel(aggregate, command)
                elif command.command_type == "SendPayment":
                    await self._handle_send_payment(aggregate, command)
                elif command.command_type == "CreateInvoice":
                    await self._handle_create_invoice(aggregate, command)
                else:
                    raise BLNCSError(f"Unknown command type: {command.command_type}")
                
                # Save events
                if aggregate.uncommitted_events:
                    success = await self.event_store.append_events(
                        aggregate.aggregate_id,
                        aggregate.uncommitted_events,
                        command.expected_version
                    )
                    
                    if not success:
                        return CommandResult(
                            success=False,
                            errors=["Failed to save events"],
                            execution_time=time.time() - start_time
                        )
                    
                    events = list(aggregate.uncommitted_events)
                    aggregate.mark_events_committed()
                    
                    return CommandResult(
                        success=True,
                        events=events,
                        aggregate_version=aggregate.version,
                        execution_time=time.time() - start_time
                    )
                
                return CommandResult(
                    success=True,
                    aggregate_version=aggregate.version,
                    execution_time=time.time() - start_time
                )
                
            except Exception as e:
                logger.error(f"Command handling error: {e}")
                return CommandResult(
                    success=False,
                    errors=[str(e)],
                    execution_time=time.time() - start_time
                )
    
    async def _load_aggregate(self, aggregate_id: str) -> LightningNodeAggregate:
        """Load aggregate from event store"""
        # Try to load from snapshot first
        snapshot = await self.event_store.get_snapshot(aggregate_id)
        
        aggregate = LightningNodeAggregate(aggregate_id)
        
        if snapshot:
            # Load from snapshot
            aggregate.version = snapshot.get('snapshot_version', 0)
            aggregate.alias = snapshot.get('alias', '')
            aggregate.pubkey = snapshot.get('pubkey', '')
            aggregate.network = snapshot.get('network', '')
            aggregate.status = snapshot.get('status', 'offline')
            aggregate.channels = snapshot.get('channels', {})
            aggregate.balance = snapshot.get('balance', {})
            
            # Load events after snapshot
            events = await self.event_store.get_events(aggregate_id, aggregate.version + 1)
        else:
            # Load all events
            events = await self.event_store.get_events(aggregate_id)
        
        # Apply events
        aggregate.load_from_history(events)
        
        return aggregate
    
    async def _handle_start_node(self, aggregate: LightningNodeAggregate, command: Command):
        """Handle start node command"""
        if aggregate.status == "online":
            return  # Already online
        
        # Get node info from Lightning client
        node_info = {}
        if self.lightning_client:
            try:
                node_info = await self.lightning_client.get_info()
            except Exception as e:
                logger.error(f"Failed to get node info: {e}")
        
        aggregate.raise_event(
            EventType.NODE_STARTED,
            {
                'alias': node_info.get('alias', 'BLNCS-Node'),
                'pubkey': node_info.get('identity_pubkey', ''),
                'network': node_info.get('network', 'testnet'),
                'version': node_info.get('version', '0.17.0-beta')
            },
            user_id=command.user_id,
            correlation_id=command.correlation_id
        )
    
    async def _handle_open_channel(self, aggregate: LightningNodeAggregate, command: Command):
        """Handle open channel command"""
        channel_data = command.command_data
        
        # Create channel opening event
        aggregate.raise_event(
            EventType.CHANNEL_OPENING_INITIATED,
            {
                'channel_id': channel_data.get('channel_id', str(uuid.uuid4())),
                'remote_pubkey': channel_data['remote_pubkey'],
                'local_funding_amount': channel_data['local_funding_amount'],
                'push_amount': channel_data.get('push_amount', 0),
                'private': channel_data.get('private', False)
            },
            user_id=command.user_id,
            correlation_id=command.correlation_id
        )
    
    async def _handle_send_payment(self, aggregate: LightningNodeAggregate, command: Command):
        """Handle send payment command"""
        payment_data = command.command_data
        
        # Create payment initiated event
        aggregate.raise_event(
            EventType.PAYMENT_INITIATED,
            {
                'payment_hash': payment_data.get('payment_hash', str(uuid.uuid4())),
                'payment_request': payment_data['payment_request'],
                'amount_msat': payment_data['amount_msat'],
                'timeout_seconds': payment_data.get('timeout_seconds', 60)
            },
            user_id=command.user_id,
            correlation_id=command.correlation_id
        )
    
    async def _handle_create_invoice(self, aggregate: LightningNodeAggregate, command: Command):
        """Handle create invoice command"""
        invoice_data = command.command_data
        
        # Create invoice created event
        aggregate.raise_event(
            EventType.INVOICE_CREATED,
            {
                'payment_hash': invoice_data.get('payment_hash', str(uuid.uuid4())),
                'amount_msat': invoice_data['amount_msat'],
                'description': invoice_data.get('description', ''),
                'expiry': invoice_data.get('expiry', 3600),
                'payment_request': invoice_data.get('payment_request', '')
            },
            user_id=command.user_id,
            correlation_id=command.correlation_id
        )

class EventProcessor:
    """Event processor for building read models and handling side effects"""
    
    def __init__(self, event_store: EventStore):
        self.event_store = event_store
        self.processors: Dict[EventType, List[Callable[[Event], None]]] = {}
        self.last_processed_timestamp = 0.0
        self.processing_task: Optional[asyncio.Task] = None
        self._stop_processing = False
    
    def register_processor(self, event_type: EventType, processor: Callable[[Event], None]):
        """Register event processor"""
        if event_type not in self.processors:
            self.processors[event_type] = []
        self.processors[event_type].append(processor)
    
    async def start_processing(self):
        """Start event processing"""
        if self.processing_task:
            return
        
        self._stop_processing = False
        self.processing_task = asyncio.create_task(self._processing_loop())
    
    async def stop_processing(self):
        """Stop event processing"""
        self._stop_processing = True
        
        if self.processing_task:
            self.processing_task.cancel()
            try:
                await self.processing_task
            except asyncio.CancelledError:
                pass
            self.processing_task = None
    
    async def _processing_loop(self):
        """Main event processing loop"""
        while not self._stop_processing:
            try:
                # Process events from last checkpoint
                async for event in self.event_store.get_all_events(
                    from_timestamp=self.last_processed_timestamp
                ):
                    await self._process_event(event)
                    self.last_processed_timestamp = max(
                        self.last_processed_timestamp, 
                        event.timestamp
                    )
                
                # Wait before next check
                await asyncio.sleep(1.0)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Event processing error: {e}")
                await asyncio.sleep(5.0)
    
    async def _process_event(self, event: Event):
        """Process individual event"""
        if event.event_type in self.processors:
            for processor in self.processors[event.event_type]:
                try:
                    if asyncio.iscoroutinefunction(processor):
                        await processor(event)
                    else:
                        processor(event)
                except Exception as e:
                    logger.error(f"Event processor error for {event.event_type}: {e}")

class EventSourcingManager:
    """Main event sourcing and CQRS manager"""
    
    def __init__(self, event_store: Optional[EventStore] = None):
        self.event_store = event_store or SQLiteEventStore()
        self.command_handlers: Dict[str, CommandHandler] = {}
        self.event_processor = EventProcessor(self.event_store)
        
        # Statistics
        self.stats = {
            'commands_processed': 0,
            'events_stored': 0,
            'events_processed': 0,
            'snapshots_created': 0
        }
    
    def register_command_handler(self, command_type: str, handler: CommandHandler):
        """Register command handler"""
        self.command_handlers[command_type] = handler
        logger.info(f"Registered command handler: {command_type}")
    
    def register_event_processor(self, event_type: EventType, processor: Callable[[Event], None]):
        """Register event processor"""
        self.event_processor.register_processor(event_type, processor)
        logger.info(f"Registered event processor: {event_type.value}")
    
    @track_async_task("handle_command")
    async def handle_command(self, command: Command) -> CommandResult:
        """Handle command through appropriate handler"""
        async with lightning_operation_context(f"handle_{command.command_type}"):
            if command.command_type not in self.command_handlers:
                return CommandResult(
                    success=False,
                    errors=[f"No handler for command type: {command.command_type}"]
                )
            
            handler = self.command_handlers[command.command_type]
            result = await handler.handle(command)
            
            # Update statistics
            self.stats['commands_processed'] += 1
            if result.success:
                self.stats['events_stored'] += len(result.events)
            
            return result
    
    async def get_aggregate_events(self, aggregate_id: str) -> List[Event]:
        """Get all events for aggregate"""
        return await self.event_store.get_events(aggregate_id)
    
    async def create_snapshot(self, aggregate_id: str, snapshot_data: Dict[str, Any], version: int):
        """Create aggregate snapshot"""
        await self.event_store.snapshot_aggregate(aggregate_id, snapshot_data, version)
        self.stats['snapshots_created'] += 1
    
    async def start(self):
        """Start event sourcing system"""
        await self.event_processor.start_processing()
        logger.info("Event sourcing system started")
    
    async def stop(self):
        """Stop event sourcing system"""
        await self.event_processor.stop_processing()
        logger.info("Event sourcing system stopped")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get system statistics"""
        return {
            **self.stats,
            'registered_command_handlers': len(self.command_handlers),
            'registered_event_processors': sum(len(processors) for processors in self.event_processor.processors.values()),
            'last_processed_timestamp': self.event_processor.last_processed_timestamp
        }

# Factory function
async def create_event_sourcing_manager(database_path: str = ":memory:",
                                      lightning_client=None) -> EventSourcingManager:
    """Create event sourcing manager"""
    event_store = SQLiteEventStore(database_path)
    manager = EventSourcingManager(event_store)
    
    # Register default Lightning command handler
    lightning_handler = LightningCommandHandler(event_store, lightning_client)
    manager.register_command_handler("StartNode", lightning_handler)
    manager.register_command_handler("OpenChannel", lightning_handler)
    manager.register_command_handler("SendPayment", lightning_handler)
    manager.register_command_handler("CreateInvoice", lightning_handler)
    
    logger.info(f"Created event sourcing manager with database: {database_path}")
    return manager

# Context manager for event sourcing
@asynccontextmanager
async def event_sourcing_system(database_path: str = ":memory:", lightning_client=None):
    """Context manager for event sourcing system"""
    manager = await create_event_sourcing_manager(database_path, lightning_client)
    
    try:
        await manager.start()
        yield manager
    finally:
        await manager.stop()

# Export main classes and functions
__all__ = [
    'EventType',
    'Event',
    'Command',
    'CommandResult',
    'EventStore',
    'SQLiteEventStore',
    'Aggregate',
    'LightningNodeAggregate',
    'CommandHandler',
    'LightningCommandHandler',
    'EventProcessor',
    'EventSourcingManager',
    'create_event_sourcing_manager',
    'event_sourcing_system'
]