# BLRCS WebSocket Module
# Real-time bidirectional communication
import asyncio
import json
import time
import secrets
from typing import Dict, Set, Any, Optional, Callable, List
from dataclasses import dataclass
from enum import Enum
import websockets
from websockets.server import WebSocketServerProtocol

class MessageType(Enum):
    """WebSocket message types"""
    CONNECT = "connect"
    DISCONNECT = "disconnect"
    MESSAGE = "message"
    BROADCAST = "broadcast"
    SUBSCRIBE = "subscribe"
    UNSUBSCRIBE = "unsubscribe"
    PING = "ping"
    PONG = "pong"
    ERROR = "error"

@dataclass
class WSMessage:
    """WebSocket message structure"""
    type: MessageType
    data: Any
    client_id: Optional[str] = None
    timestamp: float = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps({
            'type': self.type.value,
            'data': self.data,
            'client_id': self.client_id,
            'timestamp': self.timestamp
        })
    
    @classmethod
    def from_json(cls, json_str: str) -> 'WSMessage':
        """Create from JSON string"""
        data = json.loads(json_str)
        return cls(
            type=MessageType(data['type']),
            data=data['data'],
            client_id=data.get('client_id'),
            timestamp=data.get('timestamp')
        )

class WebSocketClient:
    """WebSocket client representation"""
    
    def __init__(self, websocket: WebSocketServerProtocol, client_id: str = None):
        self.websocket = websocket
        self.client_id = client_id or secrets.token_urlsafe(16)
        self.connected_at = time.time()
        self.last_ping = time.time()
        self.subscriptions: Set[str] = set()
        self.metadata: Dict[str, Any] = {}
    
    async def send(self, message: WSMessage):
        """Send message to client"""
        try:
            await self.websocket.send(message.to_json())
        except websockets.exceptions.ConnectionClosed:
            pass
    
    async def ping(self):
        """Send ping to client"""
        await self.send(WSMessage(MessageType.PING, {}))
        self.last_ping = time.time()
    
    def is_alive(self, timeout: int = 60) -> bool:
        """Check if client is still alive"""
        return (time.time() - self.last_ping) < timeout

class WebSocketServer:
    """
    WebSocket server for real-time communication.
    Supports pub/sub, broadcasting, and direct messaging.
    """
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8765):
        self.host = host
        self.port = port
        self.clients: Dict[str, WebSocketClient] = {}
        self.channels: Dict[str, Set[str]] = {}  # channel -> client_ids
        self.message_handlers: Dict[MessageType, List[Callable]] = {
            msg_type: [] for msg_type in MessageType
        }
        self.running = False
        self.server = None
    
    def add_handler(self, message_type: MessageType, handler: Callable):
        """Add message handler"""
        self.message_handlers[message_type].append(handler)
    
    async def handle_client(self, websocket: WebSocketServerProtocol, path: str):
        """Handle client connection"""
        client = WebSocketClient(websocket)
        self.clients[client.client_id] = client
        
        # Send connection confirmation
        await client.send(WSMessage(
            MessageType.CONNECT,
            {'client_id': client.client_id, 'path': path}
        ))
        
        # Notify handlers
        await self._trigger_handlers(MessageType.CONNECT, client, {})
        
        try:
            # Handle messages
            async for message in websocket:
                await self.handle_message(client, message)
        
        except websockets.exceptions.ConnectionClosed:
            pass
        
        finally:
            # Clean up
            await self.disconnect_client(client)
    
    async def handle_message(self, client: WebSocketClient, message: str):
        """Handle incoming message from client"""
        try:
            msg = WSMessage.from_json(message)
            msg.client_id = client.client_id
            
            # Handle ping/pong
            if msg.type == MessageType.PING:
                await client.send(WSMessage(MessageType.PONG, {}))
                return
            
            elif msg.type == MessageType.PONG:
                client.last_ping = time.time()
                return
            
            # Handle subscriptions
            elif msg.type == MessageType.SUBSCRIBE:
                channel = msg.data.get('channel')
                if channel:
                    await self.subscribe_client(client.client_id, channel)
                return
            
            elif msg.type == MessageType.UNSUBSCRIBE:
                channel = msg.data.get('channel')
                if channel:
                    await self.unsubscribe_client(client.client_id, channel)
                return
            
            # Handle broadcast
            elif msg.type == MessageType.BROADCAST:
                await self.broadcast(msg, exclude_client=client.client_id)
                return
            
            # Trigger handlers for other message types
            await self._trigger_handlers(msg.type, client, msg.data)
        
        except Exception as e:
            # Send error to client
            await client.send(WSMessage(
                MessageType.ERROR,
                {'error': str(e)}
            ))
    
    async def disconnect_client(self, client: WebSocketClient):
        """Disconnect client and clean up"""
        # Remove from all channels
        for channel in list(client.subscriptions):
            await self.unsubscribe_client(client.client_id, channel)
        
        # Remove from clients
        if client.client_id in self.clients:
            del self.clients[client.client_id]
        
        # Notify handlers
        await self._trigger_handlers(MessageType.DISCONNECT, client, {})
    
    async def subscribe_client(self, client_id: str, channel: str):
        """Subscribe client to channel"""
        if client_id not in self.clients:
            return
        
        client = self.clients[client_id]
        client.subscriptions.add(channel)
        
        if channel not in self.channels:
            self.channels[channel] = set()
        
        self.channels[channel].add(client_id)
    
    async def unsubscribe_client(self, client_id: str, channel: str):
        """Unsubscribe client from channel"""
        if client_id not in self.clients:
            return
        
        client = self.clients[client_id]
        client.subscriptions.discard(channel)
        
        if channel in self.channels:
            self.channels[channel].discard(client_id)
            
            # Remove empty channel
            if not self.channels[channel]:
                del self.channels[channel]
    
    async def send_to_client(self, client_id: str, message: WSMessage):
        """Send message to specific client"""
        if client_id in self.clients:
            await self.clients[client_id].send(message)
    
    async def send_to_channel(self, channel: str, message: WSMessage):
        """Send message to all clients in channel"""
        if channel not in self.channels:
            return
        
        tasks = []
        for client_id in self.channels[channel]:
            if client_id in self.clients:
                tasks.append(self.clients[client_id].send(message))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def broadcast(self, message: WSMessage, exclude_client: Optional[str] = None):
        """Broadcast message to all connected clients"""
        tasks = []
        
        for client_id, client in self.clients.items():
            if client_id != exclude_client:
                tasks.append(client.send(message))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _trigger_handlers(self, message_type: MessageType, 
                               client: WebSocketClient, data: Any):
        """Trigger registered handlers"""
        handlers = self.message_handlers.get(message_type, [])
        
        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(client, data)
                else:
                    handler(client, data)
            except Exception:
                pass
    
    async def ping_clients(self):
        """Periodic ping to keep connections alive"""
        while self.running:
            tasks = []
            dead_clients = []
            
            for client_id, client in self.clients.items():
                if not client.is_alive():
                    dead_clients.append(client)
                else:
                    tasks.append(client.ping())
            
            # Remove dead clients
            for client in dead_clients:
                await self.disconnect_client(client)
            
            # Send pings
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            
            await asyncio.sleep(30)  # Ping every 30 seconds
    
    async def start(self):
        """Start WebSocket server"""
        self.running = True
        
        # Start ping task
        asyncio.create_task(self.ping_clients())
        
        # Start server
        self.server = await websockets.serve(
            self.handle_client,
            self.host,
            self.port
        )
        
        print(f"WebSocket server started on ws://{self.host}:{self.port}")
    
    async def stop(self):
        """Stop WebSocket server"""
        self.running = False
        
        # Close all client connections
        for client in list(self.clients.values()):
            await client.websocket.close()
        
        # Close server
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        self.clients.clear()
        self.channels.clear()

class WebSocketClientConnection:
    """WebSocket client for connecting to server"""
    
    def __init__(self, uri: str):
        self.uri = uri
        self.websocket = None
        self.running = False
        self.message_handlers: Dict[MessageType, Callable] = {}
    
    def on(self, message_type: MessageType, handler: Callable):
        """Register message handler"""
        self.message_handlers[message_type] = handler
    
    async def connect(self):
        """Connect to WebSocket server"""
        self.websocket = await websockets.connect(self.uri)
        self.running = True
        
        # Start message handler
        asyncio.create_task(self._handle_messages())
    
    async def disconnect(self):
        """Disconnect from server"""
        self.running = False
        
        if self.websocket:
            await self.websocket.close()
    
    async def send(self, message_type: MessageType, data: Any):
        """Send message to server"""
        if self.websocket:
            msg = WSMessage(message_type, data)
            await self.websocket.send(msg.to_json())
    
    async def subscribe(self, channel: str):
        """Subscribe to channel"""
        await self.send(MessageType.SUBSCRIBE, {'channel': channel})
    
    async def unsubscribe(self, channel: str):
        """Unsubscribe from channel"""
        await self.send(MessageType.UNSUBSCRIBE, {'channel': channel})
    
    async def _handle_messages(self):
        """Handle incoming messages"""
        try:
            async for message in self.websocket:
                msg = WSMessage.from_json(message)
                
                # Trigger handler
                handler = self.message_handlers.get(msg.type)
                if handler:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(msg.data)
                    else:
                        handler(msg.data)
        
        except websockets.exceptions.ConnectionClosed:
            self.running = False

# Example usage functions
async def create_websocket_server(host: str = "127.0.0.1", 
                                 port: int = 8765) -> WebSocketServer:
    """Create and start WebSocket server"""
    server = WebSocketServer(host, port)
    
    # Add example handlers
    async def on_connect(client: WebSocketClient, data: Any):
        print(f"Client connected: {client.client_id}")
    
    async def on_message(client: WebSocketClient, data: Any):
        print(f"Message from {client.client_id}: {data}")
        
        # Echo back
        await client.send(WSMessage(
            MessageType.MESSAGE,
            {'echo': data}
        ))
    
    async def on_disconnect(client: WebSocketClient, data: Any):
        print(f"Client disconnected: {client.client_id}")
    
    server.add_handler(MessageType.CONNECT, on_connect)
    server.add_handler(MessageType.MESSAGE, on_message)
    server.add_handler(MessageType.DISCONNECT, on_disconnect)
    
    await server.start()
    return server