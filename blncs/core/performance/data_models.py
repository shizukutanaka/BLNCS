"""
Performance Data Models
Clean data structures for performance metrics.
"""

from datetime import datetime
from dataclasses import dataclass
from typing import Optional


@dataclass
class PerformanceMetric:
    """Performance measurement data structure"""
    timestamp: datetime
    metric_name: str
    value: float
    unit: str
    threshold_warning: Optional[float] = None
    threshold_critical: Optional[float] = None


@dataclass
class WalletMetric:
    """Wallet measurement data structure"""
    timestamp: datetime
    wallet_balance: int
    channel_local: int
    channel_remote: int
    channel_capacity: int
    total_balance: int
    active_channels: int
    total_channels: int