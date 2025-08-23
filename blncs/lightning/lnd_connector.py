# BLNCS LND Connector
# High-performance Lightning Network Daemon integration
import asyncio
import grpc
import json
import base64
import hashlib
import time
import ssl
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Callable, AsyncIterator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import threading
from collections import defaultdict, deque
import codecs

# Lightning Network Protocol Buffers (would be generated from LND .proto files)
# For this implementation, we'll use simplified data structures

class ChannelState(Enum):
    """Lightning channel states"""
    PENDING_OPEN = "pending_open"
    OPEN = "open"
    PENDING_CLOSE = "pending_close"
    CLOSED = "closed"
    FORCE_CLOSED = "force_closed"
    WAITING_CLOSE = "waiting_close"

class InvoiceState(Enum):
    """Invoice states"""
    OPEN = "open"
    SETTLED = "settled"
    CANCELED = "canceled"
    ACCEPTED = "accepted"

class PaymentStatus(Enum):
    """Payment status"""
    UNKNOWN = "unknown"
    IN_FLIGHT = "in_flight"
    SUCCEEDED = "succeeded"
    FAILED = "failed"

@dataclass
class LightningChannel:
    """Lightning channel information"""
    channel_id: str
    remote_pubkey: str
    capacity: int
    local_balance: int
    remote_balance: int
    commit_fee: int
    active: bool
    private: bool
    state: ChannelState = ChannelState.OPEN
    channel_point: str = ""
    csv_delay: int = 0
    num_updates: int = 0
    unsettled_balance: int = 0
    total_satoshis_sent: int = 0
    total_satoshis_received: int = 0
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'channel_id': self.channel_id,
            'remote_pubkey': self.remote_pubkey,
            'capacity': self.capacity,
            'local_balance': self.local_balance,
            'remote_balance': self.remote_balance,
            'commit_fee': self.commit_fee,
            'active': self.active,
            'private': self.private,
            'state': self.state.value,
            'channel_point': self.channel_point,
            'csv_delay': self.csv_delay,
            'num_updates': self.num_updates,
            'unsettled_balance': self.unsettled_balance,
            'total_satoshis_sent': self.total_satoshis_sent,
            'total_satoshis_received': self.total_satoshis_received,
            'created_at': self.created_at.isoformat()
        }
    
    def get_liquidity_ratio(self) -> float:
        """Get local liquidity ratio (0.0 to 1.0)"""
        if self.capacity == 0:
            return 0.0
        return self.local_balance / self.capacity
    
    def get_utilization(self) -> float:
        """Get channel utilization based on transaction volume"""
        total_volume = self.total_satoshis_sent + self.total_satoshis_received
        if self.capacity == 0:
            return 0.0
        return min(total_volume / self.capacity, 1.0)

@dataclass
class LightningInvoice:
    """Lightning invoice information"""
    payment_hash: str
    payment_request: str
    r_hash: bytes
    value: int
    memo: str = ""
    state: InvoiceState = InvoiceState.OPEN
    creation_date: datetime = field(default_factory=datetime.now)
    settle_date: Optional[datetime] = None
    expiry: int = 3600  # 1 hour default
    cltv_expiry: int = 144
    private: bool = False
    route_hints: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'payment_hash': self.payment_hash,
            'payment_request': self.payment_request,
            'r_hash': base64.b64encode(self.r_hash).decode() if self.r_hash else "",
            'value': self.value,
            'memo': self.memo,
            'state': self.state.value,
            'creation_date': self.creation_date.isoformat(),
            'settle_date': self.settle_date.isoformat() if self.settle_date else None,
            'expiry': self.expiry,
            'cltv_expiry': self.cltv_expiry,
            'private': self.private,
            'route_hints': self.route_hints
        }
    
    def is_expired(self) -> bool:
        """Check if invoice is expired"""
        if self.state != InvoiceState.OPEN:
            return False
        
        expiry_time = self.creation_date + timedelta(seconds=self.expiry)
        return datetime.now() > expiry_time

@dataclass
class LightningPayment:
    """Lightning payment information"""
    payment_hash: str
    payment_preimage: str
    value: int
    fee: int
    status: PaymentStatus
    creation_date: datetime = field(default_factory=datetime.now)
    failure_reason: str = ""
    payment_request: str = ""
    hops: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'payment_hash': self.payment_hash,
            'payment_preimage': self.payment_preimage,
            'value': self.value,
            'fee': self.fee,
            'status': self.status.value,
            'creation_date': self.creation_date.isoformat(),
            'failure_reason': self.failure_reason,
            'payment_request': self.payment_request,
            'hops': self.hops
        }

@dataclass
class NodeInfo:
    """Lightning node information"""
    pub_key: str
    alias: str
    color: str
    num_channels: int
    total_capacity: int
    addresses: List[Dict[str, str]] = field(default_factory=list)
    features: Dict[str, bool] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'pub_key': self.pub_key,
            'alias': self.alias,
            'color': self.color,
            'num_channels': self.num_channels,
            'total_capacity': self.total_capacity,
            'addresses': self.addresses,
            'features': self.features
        }

class LNDConnectionManager:
    """Manages connection to LND node"""
    
    def __init__(self, 
                 host: str = "localhost",
                 port: int = 10009,
                 tls_cert_path: Optional[Path] = None,
                 macaroon_path: Optional[Path] = None,
                 network: str = "mainnet"):
        
        self.host = host
        self.port = port
        self.tls_cert_path = tls_cert_path
        self.macaroon_path = macaroon_path
        self.network = network
        
        # Connection state
        self.channel: Optional[grpc.aio.Channel] = None
        self.connected = False
        self.connection_attempts = 0
        self.max_connection_attempts = 5
        self.retry_delay = 5.0
        
        # Authentication
        self.credentials = None
        self.metadata = None
        
        # Connection monitoring
        self.last_heartbeat = time.time()
        self.heartbeat_interval = 30.0
        self.heartbeat_task: Optional[asyncio.Task] = None
    
    async def connect(self) -> bool:
        """Connect to LND node"""
        try:
            # Load TLS certificate
            if self.tls_cert_path and self.tls_cert_path.exists():
                with open(self.tls_cert_path, 'rb') as f:
                    cert_data = f.read()
                self.credentials = grpc.ssl_channel_credentials(cert_data)
            else:
                # Use system CA certificates
                self.credentials = grpc.ssl_channel_credentials()
            
            # Load macaroon for authentication
            if self.macaroon_path and self.macaroon_path.exists():
                with open(self.macaroon_path, 'rb') as f:
                    macaroon_data = f.read()
                macaroon_hex = codecs.encode(macaroon_data, 'hex').decode()
                self.metadata = [('macaroon', macaroon_hex)]
            
            # Create gRPC channel
            self.channel = grpc.aio.secure_channel(
                f"{self.host}:{self.port}",
                self.credentials,
                options=[
                    ('grpc.keepalive_time_ms', 30000),
                    ('grpc.keepalive_timeout_ms', 5000),
                    ('grpc.keepalive_permit_without_calls', True),
                    ('grpc.http2.max_pings_without_data', 0),
                    ('grpc.http2.min_time_between_pings_ms', 10000),
                    ('grpc.http2.min_ping_interval_without_data_ms', 300000)
                ]
            )
            
            # Test connection
            await self._test_connection()
            
            self.connected = True
            self.connection_attempts = 0
            
            # Start heartbeat
            self.heartbeat_task = asyncio.create_task(self._heartbeat_loop())
            
            print(f"Connected to LND node at {self.host}:{self.port}")
            return True
            
        except Exception as e:
            print(f"Failed to connect to LND: {e}")
            self.connection_attempts += 1
            return False
    
    async def disconnect(self):
        """Disconnect from LND node"""
        self.connected = False
        
        if self.heartbeat_task:
            self.heartbeat_task.cancel()
            try:
                await self.heartbeat_task
            except asyncio.CancelledError:
                pass
        
        if self.channel:
            await self.channel.close()
            self.channel = None
    
    async def _test_connection(self):
        """Test LND connection"""
        # This would use actual LND gRPC calls
        # For now, we'll simulate a connection test
        await asyncio.sleep(0.1)  # Simulate network delay
        
        # In real implementation:
        # stub = lightning_pb2_grpc.LightningStub(self.channel)
        # await stub.GetInfo(lightning_pb2.GetInfoRequest(), metadata=self.metadata)
    
    async def _heartbeat_loop(self):
        """Keep connection alive with periodic heartbeats"""
        while self.connected:
            try:
                await asyncio.sleep(self.heartbeat_interval)
                
                # Perform heartbeat (GetInfo call)
                # In real implementation, this would be an actual RPC call
                self.last_heartbeat = time.time()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Heartbeat failed: {e}")
                self.connected = False
                break
    
    def is_healthy(self) -> bool:
        """Check if connection is healthy"""
        if not self.connected:
            return False
        
        # Check heartbeat timeout
        heartbeat_timeout = self.heartbeat_interval * 2
        return (time.time() - self.last_heartbeat) < heartbeat_timeout

class LNDConnector:
    """Main LND connector with high-level Lightning Network operations"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Connection manager
        self.connection = LNDConnectionManager(
            host=self.config.get('host', 'localhost'),
            port=self.config.get('port', 10009),
            tls_cert_path=Path(self.config['tls_cert_path']) if self.config.get('tls_cert_path') else None,
            macaroon_path=Path(self.config['macaroon_path']) if self.config.get('macaroon_path') else None,
            network=self.config.get('network', 'mainnet')
        )
        
        # State management
        self.node_info: Optional[NodeInfo] = None
        self.channels: Dict[str, LightningChannel] = {}
        self.invoices: Dict[str, LightningInvoice] = {}
        self.payments: Dict[str, LightningPayment] = {}
        
        # Event handlers
        self.event_handlers: Dict[str, List[Callable]] = defaultdict(list)
        
        # Monitoring
        self.last_update = time.time()
        self.update_interval = 10.0  # 10 seconds
        self.monitoring = False
        self.monitor_task: Optional[asyncio.Task] = None
        
        # Performance metrics
        self.metrics = {
            'total_channels': 0,
            'active_channels': 0,
            'total_capacity': 0,
            'local_balance': 0,
            'remote_balance': 0,
            'pending_htlcs': 0,
            'total_payments': 0,
            'successful_payments': 0,
            'failed_payments': 0,
            'total_invoices': 0,
            'settled_invoices': 0
        }
    
    async def start(self) -> bool:
        """Start LND connector"""
        # Connect to LND
        if not await self.connection.connect():
            return False
        
        # Load initial state
        await self._load_initial_state()
        
        # Start monitoring
        self.monitoring = True
        self.monitor_task = asyncio.create_task(self._monitor_loop())
        
        return True
    
    async def stop(self):
        """Stop LND connector"""
        self.monitoring = False
        
        if self.monitor_task:
            self.monitor_task.cancel()
            try:
                await self.monitor_task
            except asyncio.CancelledError:
                pass
        
        await self.connection.disconnect()
    
    async def _load_initial_state(self):
        """Load initial state from LND"""
        try:
            # Load node info
            self.node_info = await self._get_node_info()
            
            # Load channels
            channels = await self._list_channels()
            for channel in channels:
                self.channels[channel.channel_id] = channel
            
            # Load recent invoices
            invoices = await self._list_invoices()
            for invoice in invoices:
                self.invoices[invoice.payment_hash] = invoice
            
            # Load recent payments
            payments = await self._list_payments()
            for payment in payments:
                self.payments[payment.payment_hash] = payment
            
            # Update metrics
            self._update_metrics()
            
        except Exception as e:
            print(f"Failed to load initial state: {e}")
    
    async def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                # Check connection health
                if not self.connection.is_healthy():
                    await self._handle_connection_loss()
                    continue
                
                # Update state
                await self._update_state()
                
                # Process events
                await self._process_events()
                
                await asyncio.sleep(self.update_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Monitor loop error: {e}")
                await asyncio.sleep(self.update_interval)
    
    async def _handle_connection_loss(self):
        """Handle connection loss and attempt reconnection"""
        print("LND connection lost, attempting reconnection...")
        
        # Try to reconnect
        for attempt in range(self.connection.max_connection_attempts):
            if await self.connection.connect():
                print("Reconnected to LND")
                await self._load_initial_state()
                return
            
            await asyncio.sleep(self.connection.retry_delay * (attempt + 1))
        
        print("Failed to reconnect to LND")
        self.monitoring = False
    
    async def _update_state(self):
        """Update state from LND"""
        try:
            # Update channels
            updated_channels = await self._list_channels()
            
            # Check for new/closed channels
            current_channel_ids = set(self.channels.keys())
            new_channel_ids = set(channel.channel_id for channel in updated_channels)
            
            # Handle new channels
            for channel_id in new_channel_ids - current_channel_ids:
                channel = next(c for c in updated_channels if c.channel_id == channel_id)
                self.channels[channel_id] = channel
                await self._emit_event('channel_opened', channel)
            
            # Handle closed channels
            for channel_id in current_channel_ids - new_channel_ids:
                old_channel = self.channels.pop(channel_id)
                await self._emit_event('channel_closed', old_channel)
            
            # Update existing channels
            for channel in updated_channels:
                if channel.channel_id in self.channels:
                    old_channel = self.channels[channel.channel_id]
                    self.channels[channel.channel_id] = channel
                    
                    # Check for balance changes
                    if old_channel.local_balance != channel.local_balance:
                        await self._emit_event('channel_balance_changed', {
                            'channel': channel,
                            'old_balance': old_channel.local_balance,
                            'new_balance': channel.local_balance
                        })
            
            # Update recent invoices and payments
            await self._update_invoices()
            await self._update_payments()
            
            # Update metrics
            self._update_metrics()
            
            self.last_update = time.time()
            
        except Exception as e:
            print(f"State update error: {e}")
    
    async def _update_invoices(self):
        """Update invoice state"""
        # In real implementation, this would subscribe to invoice updates
        recent_invoices = await self._list_invoices(limit=100)
        
        for invoice in recent_invoices:
            old_invoice = self.invoices.get(invoice.payment_hash)
            self.invoices[invoice.payment_hash] = invoice
            
            if old_invoice and old_invoice.state != invoice.state:
                await self._emit_event('invoice_state_changed', {
                    'invoice': invoice,
                    'old_state': old_invoice.state,
                    'new_state': invoice.state
                })
    
    async def _update_payments(self):
        """Update payment state"""
        # In real implementation, this would track payment status changes
        recent_payments = await self._list_payments(limit=100)
        
        for payment in recent_payments:
            old_payment = self.payments.get(payment.payment_hash)
            self.payments[payment.payment_hash] = payment
            
            if old_payment and old_payment.status != payment.status:
                await self._emit_event('payment_state_changed', {
                    'payment': payment,
                    'old_status': old_payment.status,
                    'new_status': payment.status
                })
    
    def _update_metrics(self):
        """Update performance metrics"""
        active_channels = [c for c in self.channels.values() if c.active]
        
        self.metrics.update({
            'total_channels': len(self.channels),
            'active_channels': len(active_channels),
            'total_capacity': sum(c.capacity for c in self.channels.values()),
            'local_balance': sum(c.local_balance for c in self.channels.values()),
            'remote_balance': sum(c.remote_balance for c in self.channels.values()),
            'pending_htlcs': sum(c.unsettled_balance for c in self.channels.values()),
            'total_payments': len(self.payments),
            'successful_payments': len([p for p in self.payments.values() if p.status == PaymentStatus.SUCCEEDED]),
            'failed_payments': len([p for p in self.payments.values() if p.status == PaymentStatus.FAILED]),
            'total_invoices': len(self.invoices),
            'settled_invoices': len([i for i in self.invoices.values() if i.state == InvoiceState.SETTLED])
        })
    
    async def _process_events(self):
        """Process Lightning Network events"""
        # This would process real-time events from LND
        # For now, we'll emit a periodic heartbeat event
        await self._emit_event('heartbeat', {
            'timestamp': datetime.now(),
            'connected': self.connection.connected,
            'channels': len(self.channels),
            'node_info': self.node_info.to_dict() if self.node_info else None
        })
    
    async def _emit_event(self, event_type: str, data: Any):
        """Emit event to registered handlers"""
        for handler in self.event_handlers[event_type]:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event_type, data)
                else:
                    handler(event_type, data)
            except Exception as e:
                print(f"Event handler error: {e}")
    
    # Public API methods
    def add_event_handler(self, event_type: str, handler: Callable):
        """Add event handler"""
        self.event_handlers[event_type].append(handler)
    
    def remove_event_handler(self, event_type: str, handler: Callable):
        """Remove event handler"""
        if handler in self.event_handlers[event_type]:
            self.event_handlers[event_type].remove(handler)
    
    async def get_node_info(self) -> Optional[NodeInfo]:
        """Get current node information"""
        return self.node_info
    
    async def get_channels(self, active_only: bool = False) -> List[LightningChannel]:
        """Get list of channels"""
        channels = list(self.channels.values())
        if active_only:
            channels = [c for c in channels if c.active]
        return channels
    
    async def get_channel(self, channel_id: str) -> Optional[LightningChannel]:
        """Get specific channel"""
        return self.channels.get(channel_id)
    
    async def create_invoice(self, 
                           value: int, 
                           memo: str = "", 
                           expiry: int = 3600,
                           private: bool = False) -> Optional[LightningInvoice]:
        """Create Lightning invoice"""
        try:
            # This would call LND's AddInvoice RPC
            # For now, we'll create a mock invoice
            
            payment_hash = hashlib.sha256(f"{value}{memo}{time.time()}".encode()).hexdigest()
            r_hash = bytes.fromhex(payment_hash)
            
            invoice = LightningInvoice(
                payment_hash=payment_hash,
                payment_request=f"lnbc{value}u1p{payment_hash[:20]}...",  # Simplified
                r_hash=r_hash,
                value=value,
                memo=memo,
                expiry=expiry,
                private=private
            )
            
            self.invoices[invoice.payment_hash] = invoice
            await self._emit_event('invoice_created', invoice)
            
            return invoice
            
        except Exception as e:
            print(f"Failed to create invoice: {e}")
            return None
    
    async def send_payment(self, 
                          payment_request: str,
                          timeout_seconds: int = 60) -> Optional[LightningPayment]:
        """Send Lightning payment"""
        try:
            # This would call LND's SendPaymentSync RPC
            # For now, we'll create a mock payment
            
            payment_hash = hashlib.sha256(payment_request.encode()).hexdigest()
            
            payment = LightningPayment(
                payment_hash=payment_hash,
                payment_preimage="",  # Would be filled by LND
                value=1000,  # Would be parsed from payment request
                fee=1,  # Would be calculated by LND
                status=PaymentStatus.IN_FLIGHT,
                payment_request=payment_request
            )
            
            self.payments[payment.payment_hash] = payment
            await self._emit_event('payment_initiated', payment)
            
            # Simulate payment completion (in real implementation, this would be async)
            await asyncio.sleep(1)
            payment.status = PaymentStatus.SUCCEEDED
            payment.payment_preimage = hashlib.sha256(f"preimage{payment_hash}".encode()).hexdigest()
            
            await self._emit_event('payment_completed', payment)
            
            return payment
            
        except Exception as e:
            print(f"Failed to send payment: {e}")
            return None
    
    async def open_channel(self, 
                          node_pubkey: str, 
                          local_funding_amount: int,
                          push_sat: int = 0,
                          private: bool = False) -> bool:
        """Open Lightning channel"""
        try:
            # This would call LND's OpenChannelSync RPC
            print(f"Opening channel with {node_pubkey}, amount: {local_funding_amount}")
            
            # In real implementation, this would return immediately and 
            # the channel would appear in subsequent channel list updates
            
            return True
            
        except Exception as e:
            print(f"Failed to open channel: {e}")
            return False
    
    async def close_channel(self, channel_id: str, force: bool = False) -> bool:
        """Close Lightning channel"""
        try:
            if channel_id not in self.channels:
                return False
            
            # This would call LND's CloseChannel RPC
            print(f"Closing channel {channel_id}, force: {force}")
            
            return True
            
        except Exception as e:
            print(f"Failed to close channel: {e}")
            return False
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics"""
        return {
            **self.metrics,
            'last_update': self.last_update,
            'connected': self.connection.connected,
            'connection_attempts': self.connection.connection_attempts
        }
    
    # Mock methods that would use real LND gRPC calls
    async def _get_node_info(self) -> NodeInfo:
        """Get node information from LND"""
        # Mock node info
        return NodeInfo(
            pub_key="03" + "a" * 64,  # Mock pubkey
            alias="BLNCS Node",
            color="#3399ff",
            num_channels=len(self.channels),
            total_capacity=sum(c.capacity for c in self.channels.values())
        )
    
    async def _list_channels(self) -> List[LightningChannel]:
        """List channels from LND"""
        # In real implementation, this would call LND's ListChannels RPC
        # For now, return existing channels with some mock updates
        channels = []
        for i, (channel_id, channel) in enumerate(self.channels.items()):
            # Simulate minor balance changes
            balance_change = (-10 + (i % 20)) * 1000  # +/- 10k sats
            new_local = max(0, channel.local_balance + balance_change)
            new_remote = channel.capacity - new_local - channel.commit_fee
            
            updated_channel = LightningChannel(
                channel_id=channel_id,
                remote_pubkey=channel.remote_pubkey,
                capacity=channel.capacity,
                local_balance=new_local,
                remote_balance=new_remote,
                commit_fee=channel.commit_fee,
                active=channel.active,
                private=channel.private,
                state=channel.state,
                channel_point=channel.channel_point,
                csv_delay=channel.csv_delay,
                num_updates=channel.num_updates + 1,
                unsettled_balance=channel.unsettled_balance,
                total_satoshis_sent=channel.total_satoshis_sent,
                total_satoshis_received=channel.total_satoshis_received
            )
            channels.append(updated_channel)
        
        # Add mock channel if none exist
        if not channels:
            channels.append(LightningChannel(
                channel_id="1234567890123456789",
                remote_pubkey="03" + "b" * 64,
                capacity=1000000,  # 1M sats
                local_balance=500000,  # 500k sats
                remote_balance=480000,  # 480k sats
                commit_fee=20000,  # 20k sats
                active=True,
                private=False,
                channel_point="abcd1234:0"
            ))
        
        return channels
    
    async def _list_invoices(self, limit: int = 100) -> List[LightningInvoice]:
        """List invoices from LND"""
        # Return existing invoices
        return list(self.invoices.values())[-limit:]
    
    async def _list_payments(self, limit: int = 100) -> List[LightningPayment]:
        """List payments from LND"""
        # Return existing payments
        return list(self.payments.values())[-limit:]

# Factory function
def create_lnd_connector(config: Dict[str, Any] = None) -> LNDConnector:
    """Create LND connector instance"""
    return LNDConnector(config)

# Export main classes
__all__ = [
    'ChannelState', 'InvoiceState', 'PaymentStatus',
    'LightningChannel', 'LightningInvoice', 'LightningPayment', 'NodeInfo',
    'LNDConnector', 'LNDConnectionManager', 'create_lnd_connector'
]