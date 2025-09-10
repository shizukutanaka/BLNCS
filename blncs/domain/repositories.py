"""
Domain Repositories - Abstract interfaces for data persistence
Defines contracts for data access following Repository pattern.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from datetime import datetime

from .models import (
    Channel, ChannelId, NodeId, Payment, Invoice, LightningNode,
    FeePolicy, Amount, PaymentStatus, ChannelState
)


class ChannelRepository(ABC):
    """Repository interface for channel persistence."""
    
    @abstractmethod
    async def save(self, channel: Channel) -> None:
        """Save or update a channel."""
        pass
    
    @abstractmethod
    async def find_by_id(self, channel_id: ChannelId) -> Optional[Channel]:
        """Find channel by ID."""
        pass
    
    @abstractmethod
    async def find_by_node(self, node_id: NodeId) -> List[Channel]:
        """Find all channels for a node."""
        pass
    
    @abstractmethod
    async def find_active(self, node_id: Optional[NodeId] = None) -> List[Channel]:
        """Find active channels, optionally filtered by node."""
        pass
    
    @abstractmethod
    async def find_by_state(self, state: ChannelState) -> List[Channel]:
        """Find channels by state."""
        pass
    
    @abstractmethod
    async def find_needing_rebalancing(self, threshold: float = 0.05) -> List[Channel]:
        """Find channels that need rebalancing."""
        pass
    
    @abstractmethod
    async def find_low_health(self, threshold: float = 50.0) -> List[Channel]:
        """Find channels with low health scores."""
        pass
    
    @abstractmethod
    async def delete(self, channel_id: ChannelId) -> None:
        """Delete a channel."""
        pass
    
    @abstractmethod
    async def get_total_capacity(self, node_id: NodeId) -> Amount:
        """Get total channel capacity for a node."""
        pass
    
    @abstractmethod
    async def get_routing_stats(self, channel_id: ChannelId, days: int = 30) -> Dict[str, Any]:
        """Get routing statistics for a channel."""
        pass


class PaymentRepository(ABC):
    """Repository interface for payment persistence."""
    
    @abstractmethod
    async def save(self, payment: Payment) -> None:
        """Save or update a payment."""
        pass
    
    @abstractmethod
    async def find_by_id(self, payment_id: str) -> Optional[Payment]:
        """Find payment by ID."""
        pass
    
    @abstractmethod
    async def find_by_hash(self, payment_hash: str) -> Optional[Payment]:
        """Find payment by hash."""
        pass
    
    @abstractmethod
    async def find_by_status(self, status: PaymentStatus) -> List[Payment]:
        """Find payments by status."""
        pass
    
    @abstractmethod
    async def find_pending_retries(self) -> List[Payment]:
        """Find payments that can be retried."""
        pass
    
    @abstractmethod
    async def find_recent(self, node_id: NodeId, limit: int = 100) -> List[Payment]:
        """Find recent payments for a node."""
        pass
    
    @abstractmethod
    async def find_by_destination(self, destination: NodeId) -> List[Payment]:
        """Find payments to a specific destination."""
        pass
    
    @abstractmethod
    async def get_payment_stats(self, node_id: NodeId, days: int = 30) -> Dict[str, Any]:
        """Get payment statistics for a node."""
        pass
    
    @abstractmethod
    async def delete_old(self, cutoff_date: datetime) -> int:
        """Delete old payment records."""
        pass


class InvoiceRepository(ABC):
    """Repository interface for invoice persistence."""
    
    @abstractmethod
    async def save(self, invoice: Invoice) -> None:
        """Save or update an invoice."""
        pass
    
    @abstractmethod
    async def find_by_id(self, invoice_id: str) -> Optional[Invoice]:
        """Find invoice by ID."""
        pass
    
    @abstractmethod
    async def find_by_hash(self, payment_hash: str) -> Optional[Invoice]:
        """Find invoice by payment hash."""
        pass
    
    @abstractmethod
    async def find_by_payment_request(self, payment_request: str) -> Optional[Invoice]:
        """Find invoice by payment request."""
        pass
    
    @abstractmethod
    async def find_unsettled(self, node_id: NodeId) -> List[Invoice]:
        """Find unsettled invoices for a node."""
        pass
    
    @abstractmethod
    async def find_expired(self) -> List[Invoice]:
        """Find expired invoices."""
        pass
    
    @abstractmethod
    async def find_recent(self, node_id: NodeId, limit: int = 100) -> List[Invoice]:
        """Find recent invoices for a node."""
        pass
    
    @abstractmethod
    async def get_invoice_stats(self, node_id: NodeId, days: int = 30) -> Dict[str, Any]:
        """Get invoice statistics for a node."""
        pass
    
    @abstractmethod
    async def cleanup_expired(self, cutoff_date: datetime) -> int:
        """Clean up expired invoices."""
        pass


class NodeRepository(ABC):
    """Repository interface for node persistence."""
    
    @abstractmethod
    async def save(self, node: LightningNode) -> None:
        """Save or update a node."""
        pass
    
    @abstractmethod
    async def find_by_id(self, node_id: NodeId) -> Optional[LightningNode]:
        """Find node by ID."""
        pass
    
    @abstractmethod
    async def find_by_alias(self, alias: str) -> List[LightningNode]:
        """Find nodes by alias (partial match)."""
        pass
    
    @abstractmethod
    async def find_connected(self) -> List[LightningNode]:
        """Find all connected nodes."""
        pass
    
    @abstractmethod
    async def find_peers(self, node_id: NodeId) -> List[LightningNode]:
        """Find peer nodes (nodes with channels)."""
        pass
    
    @abstractmethod
    async def find_recommended(self, node_id: NodeId, limit: int = 10) -> List[LightningNode]:
        """Find recommended nodes for connections."""
        pass
    
    @abstractmethod
    async def update_last_seen(self, node_id: NodeId, timestamp: datetime) -> None:
        """Update node last seen timestamp."""
        pass
    
    @abstractmethod
    async def delete(self, node_id: NodeId) -> None:
        """Delete a node."""
        pass


class FeeRepository(ABC):
    """Repository interface for fee policy persistence."""
    
    @abstractmethod
    async def save_policy(self, channel_id: ChannelId, policy: FeePolicy) -> None:
        """Save fee policy for a channel."""
        pass
    
    @abstractmethod
    async def get_policy(self, channel_id: ChannelId) -> Optional[FeePolicy]:
        """Get fee policy for a channel."""
        pass
    
    @abstractmethod
    async def get_node_policies(self, node_id: NodeId) -> List[tuple[ChannelId, FeePolicy]]:
        """Get all fee policies for a node's channels."""
        pass
    
    @abstractmethod
    async def save_policy_history(self, channel_id: ChannelId, old_policy: FeePolicy, 
                                 new_policy: FeePolicy, timestamp: datetime) -> None:
        """Save fee policy change history."""
        pass
    
    @abstractmethod
    async def get_policy_history(self, channel_id: ChannelId, days: int = 30) -> List[Dict[str, Any]]:
        """Get fee policy change history."""
        pass
    
    @abstractmethod
    async def get_market_rates(self, capacity_range: tuple[int, int]) -> Dict[str, float]:
        """Get market fee rates for capacity range."""
        pass


class MetricsRepository(ABC):
    """Repository interface for metrics persistence."""
    
    @abstractmethod
    async def save_channel_metrics(self, channel_id: ChannelId, metrics: Dict[str, Any], 
                                  timestamp: datetime) -> None:
        """Save channel metrics snapshot."""
        pass
    
    @abstractmethod
    async def get_channel_metrics(self, channel_id: ChannelId, start: datetime, 
                                 end: datetime) -> List[Dict[str, Any]]:
        """Get channel metrics for time range."""
        pass
    
    @abstractmethod
    async def save_node_metrics(self, node_id: NodeId, metrics: Dict[str, Any], 
                               timestamp: datetime) -> None:
        """Save node metrics snapshot."""
        pass
    
    @abstractmethod
    async def get_node_metrics(self, node_id: NodeId, start: datetime, 
                              end: datetime) -> List[Dict[str, Any]]:
        """Get node metrics for time range."""
        pass
    
    @abstractmethod
    async def save_payment_metrics(self, payment: Payment, metrics: Dict[str, Any]) -> None:
        """Save payment performance metrics."""
        pass
    
    @abstractmethod
    async def get_routing_statistics(self, node_id: NodeId, days: int = 30) -> Dict[str, Any]:
        """Get routing statistics for a node."""
        pass
    
    @abstractmethod
    async def get_revenue_statistics(self, node_id: NodeId, days: int = 30) -> Dict[str, Any]:
        """Get revenue statistics for a node."""
        pass
    
    @abstractmethod
    async def cleanup_old_metrics(self, cutoff_date: datetime) -> int:
        """Clean up old metrics data."""
        pass


class EventRepository(ABC):
    """Repository interface for event persistence."""
    
    @abstractmethod
    async def save_event(self, event_type: str, entity_id: str, data: Dict[str, Any], 
                        timestamp: datetime) -> None:
        """Save domain event."""
        pass
    
    @abstractmethod
    async def get_events(self, entity_id: Optional[str] = None, event_type: Optional[str] = None,
                        start: Optional[datetime] = None, end: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Get events with optional filtering."""
        pass
    
    @abstractmethod
    async def get_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent events."""
        pass
    
    @abstractmethod
    async def cleanup_old_events(self, cutoff_date: datetime) -> int:
        """Clean up old events."""
        pass