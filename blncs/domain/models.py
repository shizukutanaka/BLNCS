"""
Domain Models - Core Lightning Network Entities
Implements domain models following DDD principles with rich behavior.
"""

import uuid
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timezone
from decimal import Decimal
from dataclasses import dataclass, field
from enum import Enum
import hashlib


class PaymentStatus(Enum):
    """Payment status enumeration."""
    PENDING = "pending"
    IN_FLIGHT = "in_flight" 
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ChannelState(Enum):
    """Channel state enumeration."""
    PENDING = "pending"
    ACTIVE = "active"
    INACTIVE = "inactive"
    CLOSING = "closing"
    CLOSED = "closed"
    FORCE_CLOSING = "force_closing"


class NodeStatus(Enum):
    """Node connection status."""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    SYNCING = "syncing"
    ERROR = "error"


class FeeStrategy(Enum):
    """Fee optimization strategy."""
    CONSERVATIVE = "conservative"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"
    ML_OPTIMIZED = "ml_optimized"


@dataclass(frozen=True)
class NodeId:
    """Value object representing a Lightning Node identifier."""
    public_key: str
    
    def __post_init__(self):
        if not self.public_key or len(self.public_key) != 66:
            raise ValueError("Invalid node public key")
        
        if not self.public_key.startswith(('02', '03')):
            raise ValueError("Invalid node public key format")
    
    def short_form(self) -> str:
        """Return shortened form of node ID."""
        return f"{self.public_key[:8]}...{self.public_key[-8:]}"


@dataclass(frozen=True)
class ChannelId:
    """Value object representing a channel identifier."""
    channel_point: str
    
    def __post_init__(self):
        if not self.channel_point or ':' not in self.channel_point:
            raise ValueError("Invalid channel point format")
    
    @property
    def txid(self) -> str:
        """Get transaction ID from channel point."""
        return self.channel_point.split(':')[0]
    
    @property
    def output_index(self) -> int:
        """Get output index from channel point."""
        return int(self.channel_point.split(':')[1])


@dataclass(frozen=True)
class Amount:
    """Value object representing satoshi amounts with validation."""
    satoshis: int
    
    def __post_init__(self):
        if self.satoshis < 0:
            raise ValueError("Amount cannot be negative")
    
    def to_btc(self) -> Decimal:
        """Convert to BTC."""
        return Decimal(self.satoshis) / Decimal(100_000_000)
    
    def to_msat(self) -> int:
        """Convert to millisatoshis."""
        return self.satoshis * 1000
    
    def __add__(self, other: 'Amount') -> 'Amount':
        return Amount(self.satoshis + other.satoshis)
    
    def __sub__(self, other: 'Amount') -> 'Amount':
        result = self.satoshis - other.satoshis
        if result < 0:
            raise ValueError("Subtraction would result in negative amount")
        return Amount(result)
    
    def __mul__(self, multiplier: Union[int, float, Decimal]) -> 'Amount':
        return Amount(int(self.satoshis * multiplier))
    
    def __str__(self) -> str:
        return f"{self.satoshis:,} sats"


@dataclass
class LightningNode:
    """Domain model representing a Lightning Network node."""
    node_id: NodeId
    alias: str
    color: str = "#000000"
    addresses: List[str] = field(default_factory=list)
    features: Dict[str, bool] = field(default_factory=dict)
    status: NodeStatus = NodeStatus.DISCONNECTED
    last_seen: Optional[datetime] = None
    version: Optional[str] = None
    
    # Domain behavior
    def connect(self) -> None:
        """Mark node as connected."""
        self.status = NodeStatus.CONNECTED
        self.last_seen = datetime.now(timezone.utc)
    
    def disconnect(self) -> None:
        """Mark node as disconnected."""
        self.status = NodeStatus.DISCONNECTED
        self.last_seen = datetime.now(timezone.utc)
    
    def is_online(self) -> bool:
        """Check if node is currently online."""
        return self.status == NodeStatus.CONNECTED
    
    def supports_feature(self, feature: str) -> bool:
        """Check if node supports specific feature."""
        return self.features.get(feature, False)
    
    def update_info(self, alias: str, color: str, addresses: List[str]) -> None:
        """Update node information."""
        self.alias = alias
        self.color = color
        self.addresses = addresses.copy()


@dataclass
class ChannelBalance:
    """Value object representing channel balance distribution."""
    local_balance: Amount
    remote_balance: Amount
    capacity: Amount
    
    def __post_init__(self):
        total = self.local_balance + self.remote_balance
        if total.satoshis > self.capacity.satoshis:
            raise ValueError("Total balance exceeds capacity")
    
    @property
    def local_ratio(self) -> float:
        """Get local balance as ratio of capacity."""
        return self.local_balance.satoshis / self.capacity.satoshis
    
    @property
    def remote_ratio(self) -> float:
        """Get remote balance as ratio of capacity."""
        return self.remote_balance.satoshis / self.capacity.satoshis
    
    @property
    def balance_ratio(self) -> float:
        """Get balance ratio (-1 to 1, where 0 is perfectly balanced)."""
        return (self.local_balance.satoshis - self.remote_balance.satoshis) / self.capacity.satoshis
    
    def is_balanced(self, threshold: float = 0.1) -> bool:
        """Check if channel is balanced within threshold."""
        return abs(self.balance_ratio) <= threshold
    
    def needs_rebalancing(self, min_threshold: float = 0.05) -> bool:
        """Check if channel needs rebalancing."""
        return min(self.local_ratio, self.remote_ratio) < min_threshold


@dataclass
class FeePolicy:
    """Channel fee policy with business rules."""
    base_fee_msat: int = 1000
    fee_rate_ppm: int = 1
    time_lock_delta: int = 40
    min_htlc_msat: int = 1000
    max_htlc_msat: Optional[int] = None
    strategy: FeeStrategy = FeeStrategy.BALANCED
    
    def calculate_fee(self, amount: Amount) -> Amount:
        """Calculate fee for given amount."""
        amount_msat = amount.to_msat()
        fee_msat = self.base_fee_msat + (amount_msat * self.fee_rate_ppm // 1_000_000)
        return Amount(fee_msat // 1000)
    
    def is_competitive(self, market_average_ppm: int) -> bool:
        """Check if fee policy is competitive."""
        return self.fee_rate_ppm <= market_average_ppm * 1.2
    
    def optimize_for_revenue(self, routing_volume: Amount, success_rate: float) -> 'FeePolicy':
        """Create optimized fee policy for revenue."""
        if success_rate < 0.8:
            # Lower fees to increase success rate
            new_fee_rate = max(1, int(self.fee_rate_ppm * 0.8))
        elif success_rate > 0.95 and routing_volume.satoshis > 1_000_000:
            # Increase fees if high success rate and volume
            new_fee_rate = min(5000, int(self.fee_rate_ppm * 1.2))
        else:
            new_fee_rate = self.fee_rate_ppm
        
        return FeePolicy(
            base_fee_msat=self.base_fee_msat,
            fee_rate_ppm=new_fee_rate,
            time_lock_delta=self.time_lock_delta,
            min_htlc_msat=self.min_htlc_msat,
            max_htlc_msat=self.max_htlc_msat,
            strategy=FeeStrategy.ML_OPTIMIZED
        )


@dataclass
class Channel:
    """Domain model representing a Lightning Network channel."""
    channel_id: ChannelId
    node_id: NodeId
    remote_node: NodeId
    balance: ChannelBalance
    fee_policy: FeePolicy
    state: ChannelState = ChannelState.PENDING
    is_private: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Metrics
    total_sent: Amount = field(default_factory=lambda: Amount(0))
    total_received: Amount = field(default_factory=lambda: Amount(0))
    routing_revenue: Amount = field(default_factory=lambda: Amount(0))
    routing_count: int = 0
    uptime_percentage: float = 100.0
    
    def open(self) -> None:
        """Open the channel."""
        if self.state != ChannelState.PENDING:
            raise ValueError("Channel must be pending to open")
        
        self.state = ChannelState.ACTIVE
        self.updated_at = datetime.now(timezone.utc)
    
    def close(self, force: bool = False) -> None:
        """Close the channel."""
        if self.state not in [ChannelState.ACTIVE, ChannelState.INACTIVE]:
            raise ValueError("Channel must be active or inactive to close")
        
        self.state = ChannelState.FORCE_CLOSING if force else ChannelState.CLOSING
        self.updated_at = datetime.now(timezone.utc)
    
    def update_balance(self, local: Amount, remote: Amount) -> None:
        """Update channel balance."""
        self.balance = ChannelBalance(local, remote, self.balance.capacity)
        self.updated_at = datetime.now(timezone.utc)
    
    def update_fee_policy(self, policy: FeePolicy) -> None:
        """Update channel fee policy."""
        self.fee_policy = policy
        self.updated_at = datetime.now(timezone.utc)
    
    def record_routing(self, amount: Amount, fee: Amount) -> None:
        """Record successful routing through this channel."""
        self.routing_count += 1
        self.routing_revenue += fee
        
        # Determine if this was outbound or inbound
        # This is simplified - in reality we'd need more context
        if self.balance.local_balance.satoshis > amount.satoshis:
            self.total_sent += amount
            self.balance = ChannelBalance(
                self.balance.local_balance - amount,
                self.balance.remote_balance + amount,
                self.balance.capacity
            )
        
        self.updated_at = datetime.now(timezone.utc)
    
    def calculate_health_score(self) -> float:
        """Calculate channel health score (0-100)."""
        # Balance health (0-40 points)
        balance_score = 40 * (1 - abs(self.balance.balance_ratio))
        
        # Activity health (0-30 points)
        activity_score = min(30, self.routing_count / 100 * 30)
        
        # Uptime health (0-30 points)
        uptime_score = self.uptime_percentage / 100 * 30
        
        return balance_score + activity_score + uptime_score
    
    def needs_attention(self) -> bool:
        """Check if channel needs attention."""
        return (
            self.calculate_health_score() < 50 or
            self.balance.needs_rebalancing() or
            self.uptime_percentage < 95.0
        )


@dataclass
class PaymentRoute:
    """Value object representing a payment route."""
    hops: List[NodeId]
    total_amt: Amount
    total_fees: Amount
    time_lock: int
    probability: float = 1.0
    
    @property
    def hop_count(self) -> int:
        """Get number of hops in route."""
        return len(self.hops)
    
    @property
    def fee_rate(self) -> float:
        """Get fee rate as percentage of payment amount."""
        return (self.total_fees.satoshis / self.total_amt.satoshis) * 100
    
    def is_direct(self) -> bool:
        """Check if this is a direct payment (single hop)."""
        return self.hop_count == 1


@dataclass
class Payment:
    """Domain model representing a Lightning Network payment."""
    payment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    payment_hash: str = field(default="")
    preimage: Optional[str] = None
    amount: Amount = field(default_factory=lambda: Amount(0))
    destination: NodeId = field(default_factory=lambda: NodeId("0" * 66))
    status: PaymentStatus = PaymentStatus.PENDING
    route: Optional[PaymentRoute] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    failure_reason: Optional[str] = None
    attempts: int = 0
    max_attempts: int = 3
    
    def __post_init__(self):
        if not self.payment_hash:
            # Generate payment hash from payment_id for consistency
            self.payment_hash = hashlib.sha256(self.payment_id.encode()).hexdigest()
    
    def attempt_payment(self, route: PaymentRoute) -> None:
        """Attempt payment with given route."""
        self.attempts += 1
        self.route = route
        self.status = PaymentStatus.IN_FLIGHT
        self.updated_at = datetime.now(timezone.utc)
    
    def complete(self, preimage: str) -> None:
        """Mark payment as completed."""
        if self.status != PaymentStatus.IN_FLIGHT:
            raise ValueError("Payment must be in flight to complete")
        
        self.preimage = preimage
        self.status = PaymentStatus.SUCCEEDED
        self.completed_at = datetime.now(timezone.utc)
        self.updated_at = self.completed_at
    
    def fail(self, reason: str) -> None:
        """Mark payment as failed."""
        self.failure_reason = reason
        
        if self.attempts >= self.max_attempts:
            self.status = PaymentStatus.FAILED
        else:
            self.status = PaymentStatus.PENDING
        
        self.updated_at = datetime.now(timezone.utc)
    
    def cancel(self) -> None:
        """Cancel the payment."""
        if self.status in [PaymentStatus.SUCCEEDED, PaymentStatus.FAILED]:
            raise ValueError("Cannot cancel completed or failed payment")
        
        self.status = PaymentStatus.CANCELLED
        self.updated_at = datetime.now(timezone.utc)
    
    def can_retry(self) -> bool:
        """Check if payment can be retried."""
        return (
            self.status == PaymentStatus.PENDING and
            self.attempts < self.max_attempts
        )
    
    @property
    def duration(self) -> Optional[float]:
        """Get payment duration in seconds."""
        if self.completed_at:
            return (self.completed_at - self.created_at).total_seconds()
        return None
    
    @property
    def is_successful(self) -> bool:
        """Check if payment was successful."""
        return self.status == PaymentStatus.SUCCEEDED


@dataclass
class Invoice:
    """Domain model representing a Lightning Network invoice."""
    invoice_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    payment_hash: str = field(default="")
    payment_request: str = ""
    amount: Amount = field(default_factory=lambda: Amount(0))
    description: str = ""
    expiry: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    settled_at: Optional[datetime] = None
    is_settled: bool = False
    settle_amount: Optional[Amount] = None
    
    def __post_init__(self):
        if not self.payment_hash:
            # Generate payment hash from invoice_id for consistency
            self.payment_hash = hashlib.sha256(self.invoice_id.encode()).hexdigest()
    
    def settle(self, amount: Optional[Amount] = None) -> None:
        """Settle the invoice."""
        if self.is_settled:
            raise ValueError("Invoice already settled")
        
        if self.is_expired():
            raise ValueError("Cannot settle expired invoice")
        
        self.is_settled = True
        self.settled_at = datetime.now(timezone.utc)
        self.settle_amount = amount or self.amount
    
    def is_expired(self) -> bool:
        """Check if invoice has expired."""
        return datetime.now(timezone.utc) > self.expiry
    
    def time_until_expiry(self) -> float:
        """Get time until expiry in seconds."""
        delta = self.expiry - datetime.now(timezone.utc)
        return max(0, delta.total_seconds())


@dataclass
class ChannelUpdate:
    """Domain event representing a channel state change."""
    channel_id: ChannelId
    node_id: NodeId
    timestamp: datetime
    old_state: Dict[str, Any]
    new_state: Dict[str, Any]
    event_type: str
    
    @classmethod
    def balance_changed(cls, channel: Channel, old_balance: ChannelBalance) -> 'ChannelUpdate':
        """Create balance change event."""
        return cls(
            channel_id=channel.channel_id,
            node_id=channel.node_id,
            timestamp=datetime.now(timezone.utc),
            old_state={'balance': old_balance},
            new_state={'balance': channel.balance},
            event_type='balance_changed'
        )
    
    @classmethod
    def fee_policy_updated(cls, channel: Channel, old_policy: FeePolicy) -> 'ChannelUpdate':
        """Create fee policy update event."""
        return cls(
            channel_id=channel.channel_id,
            node_id=channel.node_id,
            timestamp=datetime.now(timezone.utc),
            old_state={'fee_policy': old_policy},
            new_state={'fee_policy': channel.fee_policy},
            event_type='fee_policy_updated'
        )