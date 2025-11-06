#!/usr/bin/env python3
"""
Lightning Network Liquidity Management
Implements best practices for channel management and liquidity optimization
Based on 2024-2025 Lightning Network research
"""

import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ChannelType(Enum):
    """Types of Lightning channels"""
    FEE_FARM = "fee_farm"  # Drain from outbound to inbound
    ROUTING = "routing"     # For general routing
    LIQUIDITY = "liquidity" # For liquidity provision


class RebalanceStrategy(Enum):
    """Strategies for channel rebalancing"""
    PASSIVE = "passive"    # Wait for natural flows
    ACTIVE = "active"      # Proactive rebalancing with fee-farm
    DYNAMIC = "dynamic"    # Adjust based on metrics


@dataclass
class ChannelMetrics:
    """Metrics for a single channel"""
    channel_id: str
    peer_id: str
    capacity_sat: int
    local_balance_sat: int
    remote_balance_sat: int
    channel_type: ChannelType
    fee_rate_ppm: int
    uptime_percent: float
    throughput_sat: float
    activity_score: float  # 0-100, higher is better


@dataclass
class LiquidityHealth:
    """Overall liquidity health status"""
    total_capacity: int
    total_inbound: int
    total_outbound: int
    inbound_percent: float
    outbound_percent: float
    num_channels: int
    num_fee_farm: int
    num_routing: int
    health_score: float  # 0-100


class LiquidityManager:
    """
    Manages Lightning Network channel liquidity optimization
    Implements best practices from Lightning engineering docs
    """

    # Practical thresholds
    MIN_CHANNEL_SIZE = 100_000  # 100k sats minimum for practical use
    MIN_FEE_THRESHOLD = 10_000  # 10,000 ppm = 1% as baseline
    MAX_FEE_THRESHOLD = 1_000_000  # Cap at 100% to avoid channel abandonment
    OPTIMAL_INBOUND_PERCENT = 0.4  # 40% inbound is optimal
    HEALTHY_CHANNEL_THRESHOLD = 0.3  # 30% healthy activity

    def __init__(self, node_id: str, strategy: RebalanceStrategy = RebalanceStrategy.DYNAMIC):
        self.node_id = node_id
        self.strategy = strategy
        self.channels: Dict[str, ChannelMetrics] = {}

    def add_channel(self, metrics: ChannelMetrics) -> None:
        """Register a channel for liquidity management"""
        if metrics.capacity_sat < self.MIN_CHANNEL_SIZE:
            logger.warning(
                f"Channel {metrics.channel_id}: Capacity {metrics.capacity_sat} "
                f"below practical minimum {self.MIN_CHANNEL_SIZE}"
            )
        self.channels[metrics.channel_id] = metrics

    def calculate_liquidity_health(self) -> LiquidityHealth:
        """Calculate overall liquidity health status"""
        if not self.channels:
            return LiquidityHealth(0, 0, 0, 0, 0, 0, 0, 0, 0)

        total_capacity = sum(c.capacity_sat for c in self.channels.values())
        total_inbound = sum(c.remote_balance_sat for c in self.channels.values())
        total_outbound = sum(c.local_balance_sat for c in self.channels.values())

        inbound_percent = total_inbound / total_capacity if total_capacity > 0 else 0
        outbound_percent = total_outbound / total_capacity if total_capacity > 0 else 0

        num_fee_farm = sum(1 for c in self.channels.values() if c.channel_type == ChannelType.FEE_FARM)
        num_routing = sum(1 for c in self.channels.values() if c.channel_type == ChannelType.ROUTING)

        # Calculate health score based on balance and activity
        health_score = self._calculate_health_score(inbound_percent, outbound_percent)

        return LiquidityHealth(
            total_capacity=total_capacity,
            total_inbound=total_inbound,
            total_outbound=total_outbound,
            inbound_percent=inbound_percent,
            outbound_percent=outbound_percent,
            num_channels=len(self.channels),
            num_fee_farm=num_fee_farm,
            num_routing=num_routing,
            health_score=health_score
        )

    def get_rebalancing_recommendations(self) -> List[Dict]:
        """Get channels that need rebalancing"""
        recommendations = []
        health = self.calculate_liquidity_health()

        for channel_id, channel in self.channels.items():
            balance_ratio = channel.remote_balance_sat / channel.capacity_sat if channel.capacity_sat > 0 else 0
            activity = channel.activity_score

            # Recommendation logic based on balance
            if balance_ratio > 0.8:
                recommendations.append({
                    'channel_id': channel_id,
                    'action': 'send_out',
                    'reason': 'Too much inbound liquidity',
                    'target_balance': channel.capacity_sat * 0.4,
                    'current_balance': channel.remote_balance_sat
                })
            elif balance_ratio < 0.2:
                recommendations.append({
                    'channel_id': channel_id,
                    'action': 'receive_in',
                    'reason': 'Too much outbound liquidity',
                    'target_balance': channel.capacity_sat * 0.4,
                    'current_balance': channel.remote_balance_sat
                })
            elif activity < self.HEALTHY_CHANNEL_THRESHOLD:
                recommendations.append({
                    'channel_id': channel_id,
                    'action': 'monitor',
                    'reason': 'Low activity, may consider closing',
                    'activity_score': activity
                })

        return recommendations

    def optimize_fee_rates(self) -> Dict[str, int]:
        """
        Calculate optimal fee rates for channels
        Based on activity, network demand, and channel type
        """
        fee_rates = {}

        for channel_id, channel in self.channels.items():
            base_fee = self.MIN_FEE_THRESHOLD

            # Adjust based on channel type
            if channel.channel_type == ChannelType.FEE_FARM:
                # Fee farm channels can have higher fees
                if channel.activity_score > 70:
                    multiplier = 2.0  # 2x base fee for high activity
                elif channel.activity_score > 40:
                    multiplier = 1.5
                else:
                    multiplier = 1.0

                calculated_fee = int(base_fee * multiplier)
            else:
                # Routing channels should have competitive fees
                calculated_fee = int(base_fee * 0.8)

            # Enforce limits
            fee_rates[channel_id] = max(
                self.MIN_FEE_THRESHOLD,
                min(calculated_fee, self.MAX_FEE_THRESHOLD)
            )

        return fee_rates

    def identify_peer_opportunities(self) -> List[Dict]:
        """
        Identify peers that might offer liquidity optimization opportunities
        Based on network analysis and metrics
        """
        opportunities = []

        for channel_id, channel in self.channels.items():
            # Look for well-connected peers
            if channel.activity_score > 60 and channel.channel_type == ChannelType.ROUTING:
                opportunities.append({
                    'peer_id': channel.peer_id,
                    'channel_id': channel_id,
                    'opportunity_type': 'high_activity_peer',
                    'recommendation': 'Consider increasing capacity with this peer',
                    'current_capacity': channel.capacity_sat
                })

            # Look for passive channels with potential
            if (channel.activity_score < 30 and
                channel.capacity_sat > self.MIN_CHANNEL_SIZE * 2 and
                channel.channel_type == ChannelType.ROUTING):
                opportunities.append({
                    'peer_id': channel.peer_id,
                    'channel_id': channel_id,
                    'opportunity_type': 'underutilized_capacity',
                    'recommendation': 'Consider closing or rebalancing this channel',
                    'current_capacity': channel.capacity_sat,
                    'activity_score': channel.activity_score
                })

        return opportunities

    @staticmethod
    def _calculate_health_score(inbound_percent: float, outbound_percent: float) -> float:
        """
        Calculate health score based on liquidity balance
        Optimal is 40% inbound / 60% outbound
        """
        # Perfect balance would be at 40/60 split
        optimal_inbound = 0.4
        distance = abs(inbound_percent - optimal_inbound)

        # Score ranges from 0-100, perfect 40/60 = 100
        health_score = max(0, 100 - (distance * 100))
        return health_score

    def get_summary(self) -> Dict:
        """Get comprehensive liquidity summary"""
        health = self.calculate_liquidity_health()
        recommendations = self.get_rebalancing_recommendations()
        fee_rates = self.optimize_fee_rates()
        opportunities = self.identify_peer_opportunities()

        return {
            'node_id': self.node_id,
            'strategy': self.strategy.value,
            'health': {
                'total_capacity': health.total_capacity,
                'health_score': round(health.health_score, 2),
                'inbound_percent': round(health.inbound_percent * 100, 2),
                'outbound_percent': round(health.outbound_percent * 100, 2),
                'num_channels': health.num_channels,
            },
            'recommendations': recommendations,
            'fee_rates': fee_rates,
            'opportunities': opportunities
        }


class ChannelBalancer:
    """Helper for channel rebalancing operations"""

    @staticmethod
    def calculate_rebalance_amount(
        channel_capacity: int,
        current_remote_balance: int,
        target_ratio: float = 0.4
    ) -> int:
        """
        Calculate the amount needed to reach target balance ratio
        Returns positive for sending out, negative for receiving
        """
        target_balance = int(channel_capacity * target_ratio)
        return current_remote_balance - target_balance

    @staticmethod
    def is_balancing_needed(
        channel_capacity: int,
        current_remote_balance: int,
        threshold: float = 0.1
    ) -> bool:
        """
        Check if channel needs rebalancing
        Threshold is how far from 50/50 split before rebalancing
        """
        balance_ratio = current_remote_balance / channel_capacity if channel_capacity > 0 else 0
        return abs(balance_ratio - 0.5) > threshold


__all__ = [
    'ChannelType',
    'RebalanceStrategy',
    'ChannelMetrics',
    'LiquidityHealth',
    'LiquidityManager',
    'ChannelBalancer',
]
