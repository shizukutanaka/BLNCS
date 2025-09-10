"""
Domain Events - Events representing important business occurrences
Implements event-driven architecture for decoupled system components.
"""

from typing import Any, Dict, Optional
from datetime import datetime, timezone
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
import uuid

from .models import ChannelId, NodeId, Amount, PaymentStatus, ChannelState


@dataclass(frozen=True)
class DomainEvent(ABC):
    """Base class for all domain events."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    version: int = 1
    
    @property
    @abstractmethod
    def event_type(self) -> str:
        """Get the event type identifier."""
        pass
    
    @abstractmethod
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary representation."""
        pass


@dataclass(frozen=True)
class ChannelEvent(DomainEvent):
    """Base class for channel-related events."""
    channel_id: ChannelId
    node_id: NodeId


@dataclass(frozen=True)
class ChannelOpened(ChannelEvent):
    """Event fired when a channel is opened."""
    remote_node_id: NodeId
    capacity: Amount
    initial_balance: Amount
    is_private: bool = False
    
    @property
    def event_type(self) -> str:
        return "channel.opened"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'occurred_at': self.occurred_at.isoformat(),
            'version': self.version,
            'channel_id': self.channel_id.channel_point,
            'node_id': self.node_id.public_key,
            'remote_node_id': self.remote_node_id.public_key,
            'capacity': self.capacity.satoshis,
            'initial_balance': self.initial_balance.satoshis,
            'is_private': self.is_private
        }


@dataclass(frozen=True) 
class ChannelClosed(ChannelEvent):
    """Event fired when a channel is closed."""
    closing_type: str  # 'cooperative', 'force', 'breach'
    final_local_balance: Amount
    final_remote_balance: Amount
    closing_tx_id: Optional[str] = None
    
    @property
    def event_type(self) -> str:
        return "channel.closed"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'occurred_at': self.occurred_at.isoformat(),
            'version': self.version,
            'channel_id': self.channel_id.channel_point,
            'node_id': self.node_id.public_key,
            'closing_type': self.closing_type,
            'final_local_balance': self.final_local_balance.satoshis,
            'final_remote_balance': self.final_remote_balance.satoshis,
            'closing_tx_id': self.closing_tx_id
        }


@dataclass(frozen=True)
class ChannelBalanceChanged(ChannelEvent):
    """Event fired when channel balance changes significantly."""
    old_local_balance: Amount
    new_local_balance: Amount
    old_remote_balance: Amount
    new_remote_balance: Amount
    change_amount: Amount
    change_direction: str  # 'inbound', 'outbound'
    
    @property
    def event_type(self) -> str:
        return "channel.balance_changed"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'occurred_at': self.occurred_at.isoformat(),
            'version': self.version,
            'channel_id': self.channel_id.channel_point,
            'node_id': self.node_id.public_key,
            'old_local_balance': self.old_local_balance.satoshis,
            'new_local_balance': self.new_local_balance.satoshis,
            'old_remote_balance': self.old_remote_balance.satoshis,
            'new_remote_balance': self.new_remote_balance.satoshis,
            'change_amount': self.change_amount.satoshis,
            'change_direction': self.change_direction
        }


@dataclass(frozen=True)
class ChannelStateChanged(ChannelEvent):
    """Event fired when channel state changes."""
    old_state: ChannelState
    new_state: ChannelState
    reason: Optional[str] = None
    
    @property
    def event_type(self) -> str:
        return "channel.state_changed"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'occurred_at': self.occurred_at.isoformat(),
            'version': self.version,
            'channel_id': self.channel_id.channel_point,
            'node_id': self.node_id.public_key,
            'old_state': self.old_state.value,
            'new_state': self.new_state.value,
            'reason': self.reason
        }


@dataclass(frozen=True)
class FeeUpdated(ChannelEvent):
    """Event fired when channel fee policy is updated."""
    old_base_fee_msat: int
    new_base_fee_msat: int
    old_fee_rate_ppm: int
    new_fee_rate_ppm: int
    reason: Optional[str] = None
    
    @property
    def event_type(self) -> str:
        return "channel.fee_updated"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'occurred_at': self.occurred_at.isoformat(),
            'version': self.version,
            'channel_id': self.channel_id.channel_point,
            'node_id': self.node_id.public_key,
            'old_base_fee_msat': self.old_base_fee_msat,
            'new_base_fee_msat': self.new_base_fee_msat,
            'old_fee_rate_ppm': self.old_fee_rate_ppm,
            'new_fee_rate_ppm': self.new_fee_rate_ppm,
            'reason': self.reason
        }


@dataclass(frozen=True)
class PaymentEvent(DomainEvent):
    """Base class for payment-related events."""
    payment_id: str
    payment_hash: str
    amount: Amount
    destination: NodeId


@dataclass(frozen=True)
class PaymentInitiated(PaymentEvent):
    """Event fired when a payment is initiated."""
    max_fee: Optional[Amount] = None
    timeout_seconds: Optional[int] = None
    
    @property
    def event_type(self) -> str:
        return "payment.initiated"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'occurred_at': self.occurred_at.isoformat(),
            'version': self.version,
            'payment_id': self.payment_id,
            'payment_hash': self.payment_hash,
            'amount': self.amount.satoshis,
            'destination': self.destination.public_key,
            'max_fee': self.max_fee.satoshis if self.max_fee else None,
            'timeout_seconds': self.timeout_seconds
        }


@dataclass(frozen=True)
class PaymentCompleted(PaymentEvent):
    """Event fired when a payment completes successfully."""
    preimage: str
    fee_paid: Amount
    route_hops: int
    completion_time_seconds: float
    
    @property
    def event_type(self) -> str:
        return "payment.completed"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'occurred_at': self.occurred_at.isoformat(),
            'version': self.version,
            'payment_id': self.payment_id,
            'payment_hash': self.payment_hash,
            'amount': self.amount.satoshis,
            'destination': self.destination.public_key,
            'preimage': self.preimage,
            'fee_paid': self.fee_paid.satoshis,
            'route_hops': self.route_hops,
            'completion_time_seconds': self.completion_time_seconds
        }


@dataclass(frozen=True)
class PaymentFailed(PaymentEvent):
    """Event fired when a payment fails."""
    failure_reason: str
    attempt_count: int
    last_hop_pubkey: Optional[str] = None
    can_retry: bool = False
    
    @property
    def event_type(self) -> str:
        return "payment.failed"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'occurred_at': self.occurred_at.isoformat(),
            'version': self.version,
            'payment_id': self.payment_id,
            'payment_hash': self.payment_hash,
            'amount': self.amount.satoshis,
            'destination': self.destination.public_key,
            'failure_reason': self.failure_reason,
            'attempt_count': self.attempt_count,
            'last_hop_pubkey': self.last_hop_pubkey,
            'can_retry': self.can_retry
        }


@dataclass(frozen=True)
class InvoiceEvent(DomainEvent):
    """Base class for invoice-related events."""
    invoice_id: str
    payment_hash: str
    amount: Amount


@dataclass(frozen=True)
class InvoiceCreated(InvoiceEvent):
    """Event fired when an invoice is created."""
    payment_request: str
    description: str
    expiry_seconds: int
    
    @property
    def event_type(self) -> str:
        return "invoice.created"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'occurred_at': self.occurred_at.isoformat(),
            'version': self.version,
            'invoice_id': self.invoice_id,
            'payment_hash': self.payment_hash,
            'amount': self.amount.satoshis,
            'payment_request': self.payment_request,
            'description': self.description,
            'expiry_seconds': self.expiry_seconds
        }


@dataclass(frozen=True)
class InvoiceSettled(InvoiceEvent):
    """Event fired when an invoice is settled."""
    settled_amount: Amount
    settle_time_seconds: float
    
    @property
    def event_type(self) -> str:
        return "invoice.settled"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'occurred_at': self.occurred_at.isoformat(),
            'version': self.version,
            'invoice_id': self.invoice_id,
            'payment_hash': self.payment_hash,
            'amount': self.amount.satoshis,
            'settled_amount': self.settled_amount.satoshis,
            'settle_time_seconds': self.settle_time_seconds
        }


@dataclass(frozen=True)
class InvoiceExpired(InvoiceEvent):
    """Event fired when an invoice expires."""
    
    @property
    def event_type(self) -> str:
        return "invoice.expired"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'occurred_at': self.occurred_at.isoformat(),
            'version': self.version,
            'invoice_id': self.invoice_id,
            'payment_hash': self.payment_hash,
            'amount': self.amount.satoshis
        }


@dataclass(frozen=True)
class NodeEvent(DomainEvent):
    """Base class for node-related events."""
    node_id: NodeId


@dataclass(frozen=True)
class NodeConnected(NodeEvent):
    """Event fired when a node connects."""
    node_alias: str
    node_version: Optional[str] = None
    connection_address: Optional[str] = None
    
    @property
    def event_type(self) -> str:
        return "node.connected"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'occurred_at': self.occurred_at.isoformat(),
            'version': self.version,
            'node_id': self.node_id.public_key,
            'node_alias': self.node_alias,
            'node_version': self.node_version,
            'connection_address': self.connection_address
        }


@dataclass(frozen=True)
class NodeDisconnected(NodeEvent):
    """Event fired when a node disconnects."""
    disconnect_reason: Optional[str] = None
    connection_duration_seconds: Optional[float] = None
    
    @property
    def event_type(self) -> str:
        return "node.disconnected"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'occurred_at': self.occurred_at.isoformat(),
            'version': self.version,
            'node_id': self.node_id.public_key,
            'disconnect_reason': self.disconnect_reason,
            'connection_duration_seconds': self.connection_duration_seconds
        }


@dataclass(frozen=True)
class RebalancingEvent(DomainEvent):
    """Base class for rebalancing-related events."""
    source_channel_id: ChannelId
    target_channel_id: ChannelId
    amount: Amount


@dataclass(frozen=True)
class RebalancingInitiated(RebalancingEvent):
    """Event fired when channel rebalancing is initiated."""
    strategy: str
    max_fee: Amount
    
    @property
    def event_type(self) -> str:
        return "rebalancing.initiated"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'occurred_at': self.occurred_at.isoformat(),
            'version': self.version,
            'source_channel_id': self.source_channel_id.channel_point,
            'target_channel_id': self.target_channel_id.channel_point,
            'amount': self.amount.satoshis,
            'strategy': self.strategy,
            'max_fee': self.max_fee.satoshis
        }


@dataclass(frozen=True)
class RebalancingCompleted(RebalancingEvent):
    """Event fired when channel rebalancing completes."""
    actual_fee: Amount
    completion_time_seconds: float
    success: bool
    
    @property
    def event_type(self) -> str:
        return "rebalancing.completed"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'occurred_at': self.occurred_at.isoformat(),
            'version': self.version,
            'source_channel_id': self.source_channel_id.channel_point,
            'target_channel_id': self.target_channel_id.channel_point,
            'amount': self.amount.satoshis,
            'actual_fee': self.actual_fee.satoshis,
            'completion_time_seconds': self.completion_time_seconds,
            'success': self.success
        }


@dataclass(frozen=True)
class SystemEvent(DomainEvent):
    """Base class for system-level events."""
    component: str


@dataclass(frozen=True)
class HealthCheckFailed(SystemEvent):
    """Event fired when a health check fails."""
    check_name: str
    failure_reason: str
    severity: str  # 'warning', 'error', 'critical'
    
    @property
    def event_type(self) -> str:
        return "system.health_check_failed"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'occurred_at': self.occurred_at.isoformat(),
            'version': self.version,
            'component': self.component,
            'check_name': self.check_name,
            'failure_reason': self.failure_reason,
            'severity': self.severity
        }


@dataclass(frozen=True)
class PerformanceThresholdExceeded(SystemEvent):
    """Event fired when performance threshold is exceeded."""
    metric_name: str
    threshold_value: float
    actual_value: float
    duration_seconds: float
    
    @property
    def event_type(self) -> str:
        return "system.performance_threshold_exceeded"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'occurred_at': self.occurred_at.isoformat(),
            'version': self.version,
            'component': self.component,
            'metric_name': self.metric_name,
            'threshold_value': self.threshold_value,
            'actual_value': self.actual_value,
            'duration_seconds': self.duration_seconds
        }


# Event Bus Interface
class EventBus(ABC):
    """Abstract event bus for publishing and subscribing to domain events."""
    
    @abstractmethod
    async def publish(self, event: DomainEvent) -> None:
        """Publish a domain event."""
        pass
    
    @abstractmethod
    async def subscribe(self, event_type: str, handler) -> None:
        """Subscribe to events of a specific type."""
        pass
    
    @abstractmethod
    async def unsubscribe(self, event_type: str, handler) -> None:
        """Unsubscribe from events."""
        pass


# Event Handler Interface
class EventHandler(ABC):
    """Abstract base class for event handlers."""
    
    @abstractmethod
    async def handle(self, event: DomainEvent) -> None:
        """Handle a domain event."""
        pass
    
    @property
    @abstractmethod
    def event_types(self) -> list[str]:
        """Get list of event types this handler processes."""
        pass