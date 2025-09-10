#!/usr/bin/env python3
"""
WebSocket Real-time Communication Manager for BLNCS
Implements comprehensive real-time communication for Lightning Network events
"""

import asyncio
import json
import jwt
import time
import uuid
import weakref
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Callable, Union
import logging
import websockets
from websockets.server import serve, WebSocketServerProtocol
from websockets.exceptions import ConnectionClosed, ConnectionClosedError, ConnectionClosedOK
from contextlib import asynccontextmanager
import ssl

from blncs.core.async_memory_manager import track_async_task, lightning_operation_context
from blncs.core.exceptions import BLNCSError
from blncs.security.rate_limiting import AdvancedRateLimiter, RequestContext

logger = logging.getLogger(__name__)

class MessageType(Enum):
    """WebSocket message types"""
    # Connection management
    AUTHENTICATE = "authenticate"
    HEARTBEAT = "heartbeat"
    SUBSCRIBE = "subscribe"
    UNSUBSCRIBE = "unsubscribe"
    ERROR = "error"
    
    # Lightning Network events
    CHANNEL_UPDATE = "channel_update"
    PAYMENT_RECEIVED = "payment_received"
    PAYMENT_SENT = "payment_sent"
    INVOICE_CREATED = "invoice_created"
    INVOICE_PAID = "invoice_paid"
    NODE_UPDATE = "node_update"
    
    # System events
    SYSTEM_ALERT = "system_alert"
    HEALTH_UPDATE = "health_update"
    BALANCE_UPDATE = "balance_update"
    
    # Multi-path payment events
    MPP_STARTED = "mpp_started"
    MPP_PATH_UPDATE = "mpp_path_update"
    MPP_COMPLETED = "mpp_completed"

class SubscriptionType(Enum):
    """WebSocket subscription types"""
    ALL = "all"
    PAYMENTS = "payments"
    CHANNELS = "channels"
    INVOICES = "invoices"
    SYSTEM = "system"
    NODE_SPECIFIC = "node_specific"
    USER_SPECIFIC = "user_specific"

@dataclass
class WebSocketMessage:
    """WebSocket message structure"""
    message_type: MessageType
    data: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'type': self.message_type.value,
            'data': self.data,
            'timestamp': self.timestamp,
            'message_id': self.message_id,
            'correlation_id': self.correlation_id
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WebSocketMessage':
        """Create from dictionary"""
        return cls(
            message_type=MessageType(data['type']),
            data=data.get('data', {}),
            timestamp=data.get('timestamp', time.time()),
            message_id=data.get('message_id', str(uuid.uuid4())),
            correlation_id=data.get('correlation_id')
        )

@dataclass
class ClientConnection:
    """WebSocket client connection information"""
    connection_id: str
    websocket: WebSocketServerProtocol
    user_id: Optional[str] = None
    node_id: Optional[str] = None
    authenticated: bool = False
    subscriptions: Set[SubscriptionType] = field(default_factory=set)
    custom_filters: Dict[str, Any] = field(default_factory=dict)
    connected_at: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)
    message_count: int = 0
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

class AuthenticationManager:
    """WebSocket authentication and authorization"""
    
    def __init__(self, jwt_secret: str, jwt_algorithm: str = "HS256"):
        self.jwt_secret = jwt_secret
        self.jwt_algorithm = jwt_algorithm
        self.authenticated_connections: Dict[str, ClientConnection] = {}
    
    async def authenticate_connection(self, websocket: WebSocketServerProtocol, 
                                    auth_message: WebSocketMessage) -> Optional[ClientConnection]:
        """Authenticate WebSocket connection"""
        try:
            token = auth_message.data.get('token')
            if not token:
                await self._send_error(websocket, "Missing authentication token")
                return None
            
            # Decode JWT token
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            
            # Extract user information
            user_id = payload.get('user_id')
            node_id = payload.get('node_id')
            permissions = payload.get('permissions', [])
            
            # Create client connection
            connection = ClientConnection(
                connection_id=str(uuid.uuid4()),
                websocket=websocket,
                user_id=user_id,
                node_id=node_id,
                authenticated=True,
                ip_address=websocket.remote_address[0] if websocket.remote_address else None,
                user_agent=websocket.request_headers.get('User-Agent')
            )
            
            # Store authenticated connection
            self.authenticated_connections[connection.connection_id] = connection
            
            # Send authentication success
            success_message = WebSocketMessage(
                message_type=MessageType.AUTHENTICATE,
                data={
                    'status': 'success',
                    'connection_id': connection.connection_id,
                    'user_id': user_id,
                    'permissions': permissions
                },
                correlation_id=auth_message.message_id
            )
            
            await self._send_message(websocket, success_message)
            logger.info(f"Authenticated WebSocket connection: {connection.connection_id} (user: {user_id})")
            
            return connection
            
        except jwt.ExpiredSignatureError:
            await self._send_error(websocket, "Token expired")
        except jwt.InvalidTokenError:
            await self._send_error(websocket, "Invalid token")
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            await self._send_error(websocket, "Authentication failed")
        
        return None
    
    async def _send_message(self, websocket: WebSocketServerProtocol, message: WebSocketMessage):
        """Send message to WebSocket"""
        try:
            await websocket.send(json.dumps(message.to_dict()))
        except Exception as e:
            logger.error(f"Error sending WebSocket message: {e}")
    
    async def _send_error(self, websocket: WebSocketServerProtocol, error_message: str):
        """Send error message"""
        error_msg = WebSocketMessage(
            message_type=MessageType.ERROR,
            data={'error': error_message}
        )
        await self._send_message(websocket, error_msg)

class SubscriptionManager:
    """Manage client subscriptions and message filtering"""
    
    def __init__(self):
        self.subscriptions: Dict[SubscriptionType, Set[str]] = {
            sub_type: set() for sub_type in SubscriptionType
        }
        self.client_subscriptions: Dict[str, Set[SubscriptionType]] = {}
        self.custom_filters: Dict[str, Dict[str, Any]] = {}
    
    async def subscribe_client(self, connection: ClientConnection, 
                             subscription_types: List[SubscriptionType],
                             custom_filters: Dict[str, Any] = None):
        """Subscribe client to message types"""
        connection_id = connection.connection_id
        
        # Add to subscription mappings
        if connection_id not in self.client_subscriptions:
            self.client_subscriptions[connection_id] = set()
        
        for sub_type in subscription_types:
            self.subscriptions[sub_type].add(connection_id)
            self.client_subscriptions[connection_id].add(sub_type)
            connection.subscriptions.add(sub_type)
        
        # Store custom filters
        if custom_filters:
            self.custom_filters[connection_id] = custom_filters
            connection.custom_filters = custom_filters
        
        logger.info(f"Client {connection_id} subscribed to: {[s.value for s in subscription_types]}")
    
    async def unsubscribe_client(self, connection_id: str, 
                               subscription_types: List[SubscriptionType] = None):
        """Unsubscribe client from message types"""
        if subscription_types is None:
            # Unsubscribe from all
            if connection_id in self.client_subscriptions:
                subscription_types = list(self.client_subscriptions[connection_id])
        
        # Remove from subscription mappings
        for sub_type in subscription_types:
            self.subscriptions[sub_type].discard(connection_id)
            if connection_id in self.client_subscriptions:
                self.client_subscriptions[connection_id].discard(sub_type)
        
        # Clean up empty subscriptions
        if connection_id in self.client_subscriptions and not self.client_subscriptions[connection_id]:
            del self.client_subscriptions[connection_id]
        
        if connection_id in self.custom_filters:
            del self.custom_filters[connection_id]
        
        logger.info(f"Client {connection_id} unsubscribed from: {[s.value for s in subscription_types]}")
    
    def get_subscribers(self, message_type: MessageType) -> Set[str]:
        """Get subscribers for message type"""
        subscribers = set()
        
        # Map message types to subscription types
        message_to_subscription = {
            MessageType.CHANNEL_UPDATE: SubscriptionType.CHANNELS,
            MessageType.PAYMENT_RECEIVED: SubscriptionType.PAYMENTS,
            MessageType.PAYMENT_SENT: SubscriptionType.PAYMENTS,
            MessageType.INVOICE_CREATED: SubscriptionType.INVOICES,
            MessageType.INVOICE_PAID: SubscriptionType.INVOICES,
            MessageType.NODE_UPDATE: SubscriptionType.SYSTEM,
            MessageType.SYSTEM_ALERT: SubscriptionType.SYSTEM,
            MessageType.HEALTH_UPDATE: SubscriptionType.SYSTEM,
            MessageType.BALANCE_UPDATE: SubscriptionType.SYSTEM,
            MessageType.MPP_STARTED: SubscriptionType.PAYMENTS,
            MessageType.MPP_PATH_UPDATE: SubscriptionType.PAYMENTS,
            MessageType.MPP_COMPLETED: SubscriptionType.PAYMENTS
        }
        
        # Add subscribers for specific subscription type
        subscription_type = message_to_subscription.get(message_type)
        if subscription_type:
            subscribers.update(self.subscriptions[subscription_type])
        
        # Add ALL subscribers
        subscribers.update(self.subscriptions[SubscriptionType.ALL])
        
        return subscribers
    
    def should_send_to_client(self, connection_id: str, message: WebSocketMessage) -> bool:
        """Check if message should be sent to specific client based on filters"""
        if connection_id not in self.custom_filters:
            return True
        
        filters = self.custom_filters[connection_id]
        
        # Apply node-specific filtering
        if 'node_id' in filters:
            message_node_id = message.data.get('node_id')
            if message_node_id and message_node_id != filters['node_id']:
                return False
        
        # Apply user-specific filtering
        if 'user_id' in filters:
            message_user_id = message.data.get('user_id')
            if message_user_id and message_user_id != filters['user_id']:
                return False
        
        # Apply amount filtering for payments
        if 'min_amount' in filters and message.message_type in [MessageType.PAYMENT_RECEIVED, MessageType.PAYMENT_SENT]:
            amount = message.data.get('amount_msat', 0)
            if amount < filters['min_amount']:
                return False
        
        return True

class RealTimeManager:
    """Main WebSocket real-time communication manager"""
    
    def __init__(self, jwt_secret: str, rate_limiter: Optional[AdvancedRateLimiter] = None):
        self.auth_manager = AuthenticationManager(jwt_secret)
        self.subscription_manager = SubscriptionManager()
        self.rate_limiter = rate_limiter
        
        # Connection management
        self.connections: Dict[str, ClientConnection] = {}
        self.websocket_server = None
        
        # Message queue for high-throughput scenarios
        self.message_queue: asyncio.Queue = asyncio.Queue()
        self.broadcast_task: Optional[asyncio.Task] = None
        
        # Health monitoring
        self.heartbeat_interval = 30  # seconds
        self.heartbeat_task: Optional[asyncio.Task] = None
        
        # Statistics
        self.stats = {
            'total_connections': 0,
            'active_connections': 0,
            'messages_sent': 0,
            'messages_received': 0,
            'auth_failures': 0
        }
    
    async def start_server(self, host: str = "0.0.0.0", port: int = 8765, 
                          ssl_context: Optional[ssl.SSLContext] = None):
        """Start WebSocket server"""
        logger.info(f"Starting WebSocket server on {host}:{port}")
        
        # Start background tasks
        self.broadcast_task = asyncio.create_task(self._broadcast_worker())
        self.heartbeat_task = asyncio.create_task(self._heartbeat_worker())
        
        # Start WebSocket server
        self.websocket_server = await serve(
            self._handle_connection,
            host,
            port,
            ssl=ssl_context,
            max_size=1024*1024,  # 1MB max message size
            max_queue=100,       # Max queued messages per connection
            ping_interval=20,    # Ping every 20 seconds
            ping_timeout=10      # Wait 10 seconds for pong
        )
        
        logger.info(f"WebSocket server started on {host}:{port}")
    
    async def stop_server(self):
        """Stop WebSocket server"""
        logger.info("Stopping WebSocket server")
        
        # Stop background tasks
        if self.broadcast_task:
            self.broadcast_task.cancel()
        if self.heartbeat_task:
            self.heartbeat_task.cancel()
        
        # Close all connections
        for connection in list(self.connections.values()):
            try:
                await connection.websocket.close(code=1001, reason="Server shutdown")
            except Exception as e:
                logger.error(f"Error closing connection: {e}")
        
        # Stop WebSocket server
        if self.websocket_server:
            self.websocket_server.close()
            await self.websocket_server.wait_closed()
        
        logger.info("WebSocket server stopped")
    
    async def _handle_connection(self, websocket: WebSocketServerProtocol, path: str):
        """Handle new WebSocket connection"""
        connection_id = str(uuid.uuid4())
        connection = None
        
        try:
            # Rate limiting check
            if self.rate_limiter:
                client_ip = websocket.remote_address[0] if websocket.remote_address else "unknown"
                context = RequestContext(
                    client_ip=client_ip,
                    endpoint="/ws",
                    method="WS",
                    user_agent=websocket.request_headers.get('User-Agent')
                )
                
                allowed, result = await self.rate_limiter.check_request(context)
                if not allowed:
                    await websocket.close(code=1008, reason="Rate limit exceeded")
                    return
            
            self.stats['total_connections'] += 1
            self.stats['active_connections'] += 1
            
            logger.info(f"New WebSocket connection: {connection_id} from {websocket.remote_address}")
            
            # Handle messages
            async for message in websocket:
                try:
                    data = json.loads(message)
                    ws_message = WebSocketMessage.from_dict(data)
                    self.stats['messages_received'] += 1
                    
                    await self._process_message(websocket, ws_message, connection)
                    
                except json.JSONDecodeError:
                    await self._send_error(websocket, "Invalid JSON format")
                except Exception as e:
                    logger.error(f"Error processing message: {e}")
                    await self._send_error(websocket, "Message processing error")
        
        except ConnectionClosed:
            logger.info(f"WebSocket connection closed: {connection_id}")
        except Exception as e:
            logger.error(f"WebSocket connection error: {e}")
        finally:
            # Cleanup connection
            if connection:
                await self._cleanup_connection(connection)
            
            self.stats['active_connections'] -= 1
    
    @track_async_task("process_websocket_message")
    async def _process_message(self, websocket: WebSocketServerProtocol, 
                             message: WebSocketMessage, connection: Optional[ClientConnection]):
        """Process incoming WebSocket message"""
        async with lightning_operation_context(f"ws_{message.message_type.value}"):
            if message.message_type == MessageType.AUTHENTICATE:
                # Handle authentication
                connection = await self.auth_manager.authenticate_connection(websocket, message)
                if connection:
                    self.connections[connection.connection_id] = connection
                else:
                    self.stats['auth_failures'] += 1
                    await websocket.close(code=1008, reason="Authentication failed")
            
            elif message.message_type == MessageType.HEARTBEAT:
                # Handle heartbeat
                if connection and connection.authenticated:
                    connection.last_heartbeat = time.time()
                    await self._send_heartbeat_response(websocket, message)
                else:
                    await websocket.close(code=1008, reason="Not authenticated")
            
            elif message.message_type == MessageType.SUBSCRIBE:
                # Handle subscription
                if connection and connection.authenticated:
                    await self._handle_subscription(connection, message)
                else:
                    await self._send_error(websocket, "Authentication required")
            
            elif message.message_type == MessageType.UNSUBSCRIBE:
                # Handle unsubscription
                if connection and connection.authenticated:
                    await self._handle_unsubscription(connection, message)
                else:
                    await self._send_error(websocket, "Authentication required")
            
            else:
                await self._send_error(websocket, f"Unknown message type: {message.message_type.value}")
    
    async def _handle_subscription(self, connection: ClientConnection, message: WebSocketMessage):
        """Handle subscription request"""
        try:
            subscription_types_str = message.data.get('types', [])
            subscription_types = [SubscriptionType(t) for t in subscription_types_str]
            custom_filters = message.data.get('filters', {})
            
            await self.subscription_manager.subscribe_client(
                connection, subscription_types, custom_filters
            )
            
            # Send confirmation
            response = WebSocketMessage(
                message_type=MessageType.SUBSCRIBE,
                data={
                    'status': 'success',
                    'subscriptions': subscription_types_str,
                    'filters': custom_filters
                },
                correlation_id=message.message_id
            )
            
            await self._send_message(connection.websocket, response)
            
        except Exception as e:
            logger.error(f"Subscription error: {e}")
            await self._send_error(connection.websocket, "Subscription failed")
    
    async def _handle_unsubscription(self, connection: ClientConnection, message: WebSocketMessage):
        """Handle unsubscription request"""
        try:
            subscription_types_str = message.data.get('types', [])
            subscription_types = [SubscriptionType(t) for t in subscription_types_str] if subscription_types_str else None
            
            await self.subscription_manager.unsubscribe_client(
                connection.connection_id, subscription_types
            )
            
            # Send confirmation
            response = WebSocketMessage(
                message_type=MessageType.UNSUBSCRIBE,
                data={
                    'status': 'success',
                    'unsubscribed': subscription_types_str or 'all'
                },
                correlation_id=message.message_id
            )
            
            await self._send_message(connection.websocket, response)
            
        except Exception as e:
            logger.error(f"Unsubscription error: {e}")
            await self._send_error(connection.websocket, "Unsubscription failed")
    
    async def _send_heartbeat_response(self, websocket: WebSocketServerProtocol, 
                                     request_message: WebSocketMessage):
        """Send heartbeat response"""
        response = WebSocketMessage(
            message_type=MessageType.HEARTBEAT,
            data={'status': 'alive', 'server_time': time.time()},
            correlation_id=request_message.message_id
        )
        await self._send_message(websocket, response)
    
    async def _send_message(self, websocket: WebSocketServerProtocol, message: WebSocketMessage):
        """Send message to WebSocket with error handling"""
        try:
            await websocket.send(json.dumps(message.to_dict()))
            self.stats['messages_sent'] += 1
        except ConnectionClosed:
            # Connection already closed, ignore
            pass
        except Exception as e:
            logger.error(f"Error sending WebSocket message: {e}")
    
    async def _send_error(self, websocket: WebSocketServerProtocol, error_message: str):
        """Send error message"""
        error_msg = WebSocketMessage(
            message_type=MessageType.ERROR,
            data={'error': error_message}
        )
        await self._send_message(websocket, error_msg)
    
    async def _cleanup_connection(self, connection: ClientConnection):
        """Clean up connection resources"""
        try:
            # Remove from connections
            self.connections.pop(connection.connection_id, None)
            
            # Remove from subscriptions
            await self.subscription_manager.unsubscribe_client(connection.connection_id)
            
            # Remove from auth manager
            self.auth_manager.authenticated_connections.pop(connection.connection_id, None)
            
            logger.info(f"Cleaned up connection: {connection.connection_id}")
            
        except Exception as e:
            logger.error(f"Error cleaning up connection: {e}")
    
    async def _broadcast_worker(self):
        """Background worker for broadcasting messages"""
        while True:
            try:
                # Get message from queue
                message = await self.message_queue.get()
                
                # Get subscribers
                subscribers = self.subscription_manager.get_subscribers(message.message_type)
                
                # Send to all subscribers
                tasks = []
                for connection_id in subscribers:
                    if connection_id in self.connections:
                        connection = self.connections[connection_id]
                        
                        # Apply custom filters
                        if self.subscription_manager.should_send_to_client(connection_id, message):
                            task = asyncio.create_task(
                                self._send_message(connection.websocket, message)
                            )
                            tasks.append(task)
                
                # Wait for all sends to complete
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
                
                # Mark task as done
                self.message_queue.task_done()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Broadcast worker error: {e}")
    
    async def _heartbeat_worker(self):
        """Background worker for heartbeat monitoring"""
        while True:
            try:
                await asyncio.sleep(self.heartbeat_interval)
                
                now = time.time()
                timeout = self.heartbeat_interval * 2  # 2x interval timeout
                
                # Check for stale connections
                stale_connections = []
                for connection in self.connections.values():
                    if now - connection.last_heartbeat > timeout:
                        stale_connections.append(connection)
                
                # Close stale connections
                for connection in stale_connections:
                    try:
                        await connection.websocket.close(code=1000, reason="Heartbeat timeout")
                    except Exception as e:
                        logger.error(f"Error closing stale connection: {e}")
                
                if stale_connections:
                    logger.info(f"Closed {len(stale_connections)} stale connections")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Heartbeat worker error: {e}")
    
    # Public API methods for broadcasting Lightning Network events
    
    async def broadcast_channel_update(self, channel_data: Dict[str, Any]):
        """Broadcast channel update event"""
        message = WebSocketMessage(
            message_type=MessageType.CHANNEL_UPDATE,
            data=channel_data
        )
        await self.message_queue.put(message)
    
    async def broadcast_payment_received(self, payment_data: Dict[str, Any]):
        """Broadcast payment received event"""
        message = WebSocketMessage(
            message_type=MessageType.PAYMENT_RECEIVED,
            data=payment_data
        )
        await self.message_queue.put(message)
    
    async def broadcast_payment_sent(self, payment_data: Dict[str, Any]):
        """Broadcast payment sent event"""
        message = WebSocketMessage(
            message_type=MessageType.PAYMENT_SENT,
            data=payment_data
        )
        await self.message_queue.put(message)
    
    async def broadcast_invoice_created(self, invoice_data: Dict[str, Any]):
        """Broadcast invoice created event"""
        message = WebSocketMessage(
            message_type=MessageType.INVOICE_CREATED,
            data=invoice_data
        )
        await self.message_queue.put(message)
    
    async def broadcast_invoice_paid(self, invoice_data: Dict[str, Any]):
        """Broadcast invoice paid event"""
        message = WebSocketMessage(
            message_type=MessageType.INVOICE_PAID,
            data=invoice_data
        )
        await self.message_queue.put(message)
    
    async def broadcast_system_alert(self, alert_data: Dict[str, Any]):
        """Broadcast system alert"""
        message = WebSocketMessage(
            message_type=MessageType.SYSTEM_ALERT,
            data=alert_data
        )
        await self.message_queue.put(message)
    
    async def broadcast_multipath_payment_update(self, payment_id: str, update_type: str, data: Dict[str, Any]):
        """Broadcast multi-path payment update"""
        message_type_map = {
            'started': MessageType.MPP_STARTED,
            'path_update': MessageType.MPP_PATH_UPDATE,
            'completed': MessageType.MPP_COMPLETED
        }
        
        message_type = message_type_map.get(update_type, MessageType.MPP_PATH_UPDATE)
        
        message = WebSocketMessage(
            message_type=message_type,
            data={'payment_id': payment_id, **data}
        )
        await self.message_queue.put(message)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get WebSocket server statistics"""
        return {
            **self.stats,
            'queue_size': self.message_queue.qsize(),
            'active_subscriptions': {
                sub_type.value: len(connections) 
                for sub_type, connections in self.subscription_manager.subscriptions.items()
            }
        }

# Factory function
async def create_realtime_manager(jwt_secret: str, 
                                rate_limiter: Optional[AdvancedRateLimiter] = None) -> RealTimeManager:
    """Create real-time WebSocket manager"""
    manager = RealTimeManager(jwt_secret, rate_limiter)
    
    logger.info("Created WebSocket real-time manager")
    return manager

# Context manager for easy server management
@asynccontextmanager
async def websocket_server(jwt_secret: str, host: str = "0.0.0.0", port: int = 8765,
                          ssl_context: Optional[ssl.SSLContext] = None,
                          rate_limiter: Optional[AdvancedRateLimiter] = None):
    """Context manager for WebSocket server"""
    manager = await create_realtime_manager(jwt_secret, rate_limiter)
    
    try:
        await manager.start_server(host, port, ssl_context)
        yield manager
    finally:
        await manager.stop_server()

# Export main classes and functions
__all__ = [
    'MessageType',
    'SubscriptionType',
    'WebSocketMessage',
    'ClientConnection',
    'AuthenticationManager',
    'SubscriptionManager',
    'RealTimeManager',
    'create_realtime_manager',
    'websocket_server'
]