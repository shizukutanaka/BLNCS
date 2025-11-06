"""
Simple WebSocket Server for BLNCS
Real-time updates and notifications
"""

import asyncio
import json
import time
import weakref
from typing import Dict, Set, Any, Optional, List
import threading
from dataclasses import dataclass, asdict

from blncs.core.unified_logging import get_logger

# Optional WebSocket support
try:
    import websockets
    from websockets.server import serve
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False


@dataclass
class WSMessage:
    """WebSocket message structure"""
    type: str
    data: Dict[str, Any]
    timestamp: float = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()

    def to_json(self) -> str:
        return json.dumps(asdict(self))


logger = get_logger(__name__)


class SimpleWebSocketServer:
    """Lightweight WebSocket server for real-time updates"""

    def __init__(self, host: str = "localhost", port: int = 8081, allowed_origins: Optional[List[str]] = None):
        self.host = host
        self.port = port
        self.clients: Set[Any] = weakref.WeakSet()
        self.running = False
        self.server = None
        self.message_queue = asyncio.Queue() if HAS_WEBSOCKETS else None
        self.stats = {
            'connected_clients': 0,
            'messages_sent': 0,
            'messages_received': 0,
            'start_time': None
        }
        self.allowed_origins = allowed_origins or []

    async def register_client(self, websocket):
        """Register new WebSocket client"""
        if not HAS_WEBSOCKETS:
            return

        self.clients.add(websocket)
        self.stats['connected_clients'] = len(self.clients)
        logger.info(
            "websocket client connected",
            client_count=self.stats['connected_clients'],
            client_id=id(websocket)
        )

        # Send welcome message
        welcome = WSMessage(
            type="welcome",
            data={
                "server": "BLNCS WebSocket",
                "timestamp": time.time(),
                "client_id": id(websocket)
            }
        )
        await websocket.send(welcome.to_json())

    async def unregister_client(self, websocket):
        """Unregister WebSocket client"""
        if websocket in self.clients:
            self.clients.remove(websocket)
        self.stats['connected_clients'] = len(self.clients)
        logger.info(
            "websocket client disconnected",
            client_count=self.stats['connected_clients'],
            client_id=id(websocket)
        )

    async def broadcast_message(self, message: WSMessage):
        """Broadcast message to all connected clients"""
        if not self.clients:
            return

        message_json = message.to_json()
        disconnected = []

        for client in self.clients.copy():
            try:
                await client.send(message_json)
                self.stats['messages_sent'] += 1
            except Exception:
                disconnected.append(client)
                logger.warning(
                    "websocket broadcast failed",
                    client_id=id(client)
                )

        # Remove disconnected clients
        for client in disconnected:
            await self.unregister_client(client)

    async def handle_client_message(self, websocket, message: str):
        """Handle message from client"""
        try:
            data = json.loads(message)
            self.stats['messages_received'] += 1

            # Handle different message types
            if data.get('type') == 'ping':
                response = WSMessage(
                    type="pong",
                    data={"timestamp": time.time()}
                )
                await websocket.send(response.to_json())

            elif data.get('type') == 'subscribe':
                # Client subscribing to specific events
                response = WSMessage(
                    type="subscribed",
                    data={"events": data.get('events', [])}
                )
                await websocket.send(response.to_json())

            elif data.get('type') == 'get_stats':
                # Send server stats
                stats = WSMessage(
                    type="stats",
                    data=self.stats.copy()
                )
                await websocket.send(stats.to_json())

        except json.JSONDecodeError:
            error = WSMessage(
                type="error",
                data={"message": "Invalid JSON"}
            )
            await websocket.send(error.to_json())
            logger.warning("websocket received invalid JSON", client_id=id(websocket))

    async def client_handler(self, websocket, path):
        """Handle individual client connection"""
        if self.allowed_origins:
            origin = websocket.request_headers.get('Origin') if hasattr(websocket, 'request_headers') else None
            if not origin or origin not in self.allowed_origins:
                try:
                    await websocket.close(code=4403, reason="origin not allowed")
                    logger.warning(
                        "websocket origin rejected",
                        origin=origin
                    )
                finally:
                    return

        await self.register_client(websocket)

        try:
            async for message in websocket:
                await self.handle_client_message(websocket, message)
        except Exception:
            pass
        finally:
            await self.unregister_client(websocket)

    async def start_server(self):
        """Start the WebSocket server"""
        if not HAS_WEBSOCKETS:
            raise ImportError("websockets library not installed")

        self.stats['start_time'] = time.time()
        self.running = True

        self.server = await serve(
            self.client_handler,
            self.host,
            self.port,
            ping_interval=20,
            ping_timeout=10,
            origins=None if not self.allowed_origins else self.allowed_origins
        )

        logger.info(
            "websocket server started",
            host=self.host,
            port=self.port
        )
        return self.server

    def stop_server(self):
        """Stop the WebSocket server"""
        self.running = False
        if self.server:
            self.server.close()
            logger.info(
                "websocket server stopping",
                host=self.host,
                port=self.port
            )

    # Convenience methods for common events
    async def notify_invoice_created(self, invoice_data: Dict[str, Any]):
        """Notify clients about new invoice"""
        message = WSMessage(
            type="invoice_created",
            data=invoice_data
        )
        await self.broadcast_message(message)

    async def notify_payment_received(self, payment_data: Dict[str, Any]):
        """Notify clients about payment received"""
        message = WSMessage(
            type="payment_received",
            data=payment_data
        )
        await self.broadcast_message(message)

    async def notify_node_status_change(self, status_data: Dict[str, Any]):
        """Notify clients about node status change"""
        message = WSMessage(
            type="node_status_change",
            data=status_data
        )
        await self.broadcast_message(message)

    async def send_system_alert(self, alert_data: Dict[str, Any]):
        """Send system alert to all clients"""
        message = WSMessage(
            type="system_alert",
            data=alert_data
        )
        await self.broadcast_message(message)

    def get_stats(self) -> Dict[str, Any]:
        """Get server statistics"""
        stats = self.stats.copy()
        if stats['start_time']:
            stats['uptime'] = time.time() - stats['start_time']
        return stats


class WebSocketManager:
    """Manage WebSocket server lifecycle"""

    def __init__(self):
        self.server = None
        self.loop = None
        self.thread = None
        self.allowed_origins: Optional[List[str]] = None

    def start(self, host: str = "localhost", port: int = 8081, allowed_origins: Optional[List[str]] = None) -> bool:
        """Start WebSocket server in background thread"""
        if not HAS_WEBSOCKETS:
            logger.error("websocket support not available", dependency='websockets')
            return False

        self.allowed_origins = allowed_origins
        self.server = SimpleWebSocketServer(host, port, allowed_origins=allowed_origins)

        def run_server():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)

            try:
                self.loop.run_until_complete(self.server.start_server())
                self.loop.run_forever()
            except Exception as e:
                logger.exception("websocket server error", exc_info=True, host=host, port=port)

        self.thread = threading.Thread(target=run_server, daemon=True)
        self.thread.start()
        time.sleep(0.1)  # Brief pause for startup
        return True

    def stop(self):
        """Stop WebSocket server"""
        if self.server:
            self.server.stop_server()
        if self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)

    def notify_async(self, event_type: str, data: Dict[str, Any]):
        """Send notification asynchronously"""
        if not self.server or not self.loop:
            return

        message = WSMessage(type=event_type, data=data)
        asyncio.run_coroutine_threadsafe(
            self.server.broadcast_message(message),
            self.loop
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get server stats"""
        if self.server:
            return self.server.get_stats()
        return {}


# Global WebSocket manager
_ws_manager = None


def get_websocket_manager() -> WebSocketManager:
    """Get global WebSocket manager"""
    global _ws_manager
    if _ws_manager is None:
        _ws_manager = WebSocketManager()
    return _ws_manager


def start_websocket_server(host: str = "localhost", port: int = 8081, allowed_origins: Optional[List[str]] = None) -> bool:
    """Start WebSocket server"""
    return get_websocket_manager().start(host, port, allowed_origins=allowed_origins)


def stop_websocket_server():
    """Stop WebSocket server"""
    get_websocket_manager().stop()


def notify_clients(event_type: str, data: Dict[str, Any]):
    """Send notification to WebSocket clients"""
    get_websocket_manager().notify_async(event_type, data)


# Integration with Lightning events
def setup_lightning_notifications(lightning_client):
    """Setup Lightning Network event notifications"""

    # Monkey patch Lightning client to send WebSocket notifications
    original_create_invoice = lightning_client.create_invoice
    original_pay_invoice = lightning_client.pay_invoice

    def create_invoice_with_notification(*args, **kwargs):
        result = original_create_invoice(*args, **kwargs)
        if 'payment_request' in result:
            notify_clients('invoice_created', result)
        return result

    def pay_invoice_with_notification(*args, **kwargs):
        result = original_pay_invoice(*args, **kwargs)
        if 'status' in result:
            notify_clients('payment_update', result)
        return result

    lightning_client.create_invoice = create_invoice_with_notification
    lightning_client.pay_invoice = pay_invoice_with_notification

    return lightning_client


__all__ = [
    'SimpleWebSocketServer', 'WebSocketManager', 'WSMessage',
    'get_websocket_manager', 'start_websocket_server', 'stop_websocket_server',
    'notify_clients', 'setup_lightning_notifications'
]