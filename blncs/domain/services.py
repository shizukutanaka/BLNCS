"""
Domain Services - Business logic that doesn't belong to a single entity
Implements complex business rules spanning multiple domain objects.
"""

from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime, timezone, timedelta
from decimal import Decimal
import asyncio
import statistics

from .models import (
    Channel, ChannelId, NodeId, Payment, Invoice, LightningNode,
    FeePolicy, Amount, PaymentStatus, ChannelState, PaymentRoute,
    FeeStrategy, ChannelBalance
)
from .repositories import (
    ChannelRepository, PaymentRepository, NodeRepository,
    FeeRepository, MetricsRepository, EventRepository
)


class ChannelManagementService:
    """Domain service for channel management operations."""
    
    def __init__(self, channel_repo: ChannelRepository, node_repo: NodeRepository,
                 metrics_repo: MetricsRepository, event_repo: EventRepository):
        self.channel_repo = channel_repo
        self.node_repo = node_repo
        self.metrics_repo = metrics_repo
        self.event_repo = event_repo
    
    async def analyze_channel_health(self, channel_id: ChannelId) -> Dict[str, Any]:
        """Analyze channel health and provide recommendations."""
        channel = await self.channel_repo.find_by_id(channel_id)
        if not channel:
            raise ValueError(f"Channel {channel_id} not found")
        
        # Get routing statistics
        routing_stats = await self.channel_repo.get_routing_stats(channel_id, days=30)
        
        # Calculate health metrics
        health_score = channel.calculate_health_score()
        balance_analysis = self._analyze_balance(channel.balance)
        activity_analysis = self._analyze_activity(routing_stats)
        
        # Generate recommendations
        recommendations = await self._generate_channel_recommendations(channel, routing_stats)
        
        return {
            'channel_id': channel_id.channel_point,
            'health_score': health_score,
            'balance_analysis': balance_analysis,
            'activity_analysis': activity_analysis,
            'recommendations': recommendations,
            'routing_stats': routing_stats
        }
    
    def _analyze_balance(self, balance: ChannelBalance) -> Dict[str, Any]:
        """Analyze channel balance distribution."""
        return {
            'local_ratio': balance.local_ratio,
            'remote_ratio': balance.remote_ratio,
            'balance_ratio': balance.balance_ratio,
            'is_balanced': balance.is_balanced(),
            'needs_rebalancing': balance.needs_rebalancing(),
            'capacity_utilization': (balance.local_balance + balance.remote_balance).satoshis / balance.capacity.satoshis
        }
    
    def _analyze_activity(self, routing_stats: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze channel routing activity."""
        return {
            'routing_volume_30d': routing_stats.get('routing_volume', 0),
            'routing_count_30d': routing_stats.get('routing_count', 0),
            'revenue_30d': routing_stats.get('revenue', 0),
            'average_payment_size': routing_stats.get('avg_payment_size', 0),
            'success_rate': routing_stats.get('success_rate', 0.0),
            'activity_trend': routing_stats.get('trend', 'stable')
        }
    
    async def _generate_channel_recommendations(self, channel: Channel, 
                                              routing_stats: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate actionable recommendations for channel optimization."""
        recommendations = []
        
        # Balance recommendations
        if channel.balance.needs_rebalancing():
            if channel.balance.local_ratio < 0.1:
                recommendations.append({
                    'type': 'rebalance_inbound',
                    'priority': 'high',
                    'description': 'Channel has very low local balance. Consider rebalancing inbound.',
                    'suggested_amount': int(channel.balance.capacity.satoshis * 0.3)
                })
            elif channel.balance.remote_ratio < 0.1:
                recommendations.append({
                    'type': 'rebalance_outbound',
                    'priority': 'high', 
                    'description': 'Channel has very low remote balance. Consider rebalancing outbound.',
                    'suggested_amount': int(channel.balance.capacity.satoshis * 0.3)
                })
        
        # Fee recommendations
        success_rate = routing_stats.get('success_rate', 1.0)
        if success_rate < 0.8:
            recommendations.append({
                'type': 'reduce_fees',
                'priority': 'medium',
                'description': f'Low success rate ({success_rate:.1%}). Consider reducing fees.',
                'current_fee_rate': channel.fee_policy.fee_rate_ppm,
                'suggested_fee_rate': max(1, int(channel.fee_policy.fee_rate_ppm * 0.8))
            })
        elif success_rate > 0.95 and routing_stats.get('routing_count', 0) > 10:
            recommendations.append({
                'type': 'increase_fees',
                'priority': 'low',
                'description': f'High success rate ({success_rate:.1%}) with good volume. Consider increasing fees.',
                'current_fee_rate': channel.fee_policy.fee_rate_ppm,
                'suggested_fee_rate': min(5000, int(channel.fee_policy.fee_rate_ppm * 1.2))
            })
        
        # Capacity recommendations
        if routing_stats.get('routing_count', 0) == 0:
            recommendations.append({
                'type': 'investigate_connectivity',
                'priority': 'high',
                'description': 'No routing activity detected. Check channel connectivity and peer status.'
            })
        
        return recommendations
    
    async def optimize_channel_fees(self, node_id: NodeId) -> Dict[str, Any]:
        """Optimize fees for all channels of a node."""
        channels = await self.channel_repo.find_active(node_id)
        optimized_count = 0
        results = []
        
        for channel in channels:
            routing_stats = await self.channel_repo.get_routing_stats(channel.channel_id, days=30)
            success_rate = routing_stats.get('success_rate', 1.0)
            routing_volume = Amount(routing_stats.get('routing_volume', 0))
            
            # Generate optimized fee policy
            optimized_policy = channel.fee_policy.optimize_for_revenue(routing_volume, success_rate)
            
            # Only update if there's a meaningful change
            if optimized_policy.fee_rate_ppm != channel.fee_policy.fee_rate_ppm:
                old_policy = channel.fee_policy
                channel.update_fee_policy(optimized_policy)
                await self.channel_repo.save(channel)
                
                # Record the change
                await self.event_repo.save_event(
                    'fee_policy_optimized',
                    channel.channel_id.channel_point,
                    {
                        'old_fee_rate': old_policy.fee_rate_ppm,
                        'new_fee_rate': optimized_policy.fee_rate_ppm,
                        'success_rate': success_rate,
                        'routing_volume': routing_volume.satoshis
                    },
                    datetime.now(timezone.utc)
                )
                
                results.append({
                    'channel_id': channel.channel_id.channel_point,
                    'old_fee_rate': old_policy.fee_rate_ppm,
                    'new_fee_rate': optimized_policy.fee_rate_ppm,
                    'change_reason': self._get_fee_change_reason(old_policy, optimized_policy, success_rate)
                })
                
                optimized_count += 1
        
        return {
            'optimized_channels': optimized_count,
            'total_channels': len(channels),
            'changes': results
        }
    
    def _get_fee_change_reason(self, old_policy: FeePolicy, new_policy: FeePolicy, 
                              success_rate: float) -> str:
        """Get human-readable reason for fee change."""
        if new_policy.fee_rate_ppm > old_policy.fee_rate_ppm:
            return f"Increased fees due to high success rate ({success_rate:.1%})"
        else:
            return f"Reduced fees due to low success rate ({success_rate:.1%})"


class PaymentService:
    """Domain service for payment operations."""
    
    def __init__(self, payment_repo: PaymentRepository, channel_repo: ChannelRepository,
                 node_repo: NodeRepository, metrics_repo: MetricsRepository):
        self.payment_repo = payment_repo
        self.channel_repo = channel_repo
        self.node_repo = node_repo
        self.metrics_repo = metrics_repo
    
    async def find_optimal_route(self, source: NodeId, destination: NodeId, 
                                amount: Amount, max_fee: Optional[Amount] = None) -> Optional[PaymentRoute]:
        """Find optimal payment route considering fees, reliability, and liquidity."""
        # Get all active channels for source node
        source_channels = await self.channel_repo.find_active(source)
        
        # For simplicity, implement a basic route finding algorithm
        # In a real implementation, this would use graph algorithms and consider:
        # - Channel liquidity
        # - Historical success rates
        # - Fee policies
        # - Channel balances
        
        best_route = None
        best_score = 0
        
        for channel in source_channels:
            if channel.balance.local_balance.satoshis >= amount.satoshis:
                # Calculate route score based on multiple factors
                fee = channel.fee_policy.calculate_fee(amount)
                
                if max_fee and fee > max_fee:
                    continue
                
                # Get channel routing history
                routing_stats = await self.channel_repo.get_routing_stats(channel.channel_id, days=7)
                success_rate = routing_stats.get('success_rate', 0.5)
                
                # Calculate composite score (higher is better)
                fee_score = 1.0 / (1.0 + fee.satoshis / amount.satoshis)  # Lower fees = higher score
                reliability_score = success_rate
                liquidity_score = min(1.0, channel.balance.local_balance.satoshis / amount.satoshis / 2)
                
                composite_score = (fee_score * 0.3 + reliability_score * 0.5 + liquidity_score * 0.2)
                
                if composite_score > best_score:
                    best_score = composite_score
                    best_route = PaymentRoute(
                        hops=[source, channel.remote_node],
                        total_amt=amount,
                        total_fees=fee,
                        time_lock=channel.fee_policy.time_lock_delta,
                        probability=success_rate
                    )
        
        return best_route
    
    async def analyze_payment_patterns(self, node_id: NodeId, days: int = 30) -> Dict[str, Any]:
        """Analyze payment patterns and performance."""
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)
        
        # Get payment statistics
        payment_stats = await self.payment_repo.get_payment_stats(node_id, days)
        
        # Get recent payments for detailed analysis
        recent_payments = await self.payment_repo.find_recent(node_id, limit=1000)
        
        # Analyze success rates by amount ranges
        amount_analysis = self._analyze_by_amount_ranges(recent_payments)
        
        # Analyze timing patterns
        timing_analysis = self._analyze_timing_patterns(recent_payments)
        
        # Analyze failure reasons
        failure_analysis = self._analyze_failure_patterns(recent_payments)
        
        return {
            'period': f'{days} days',
            'total_payments': payment_stats.get('total_count', 0),
            'successful_payments': payment_stats.get('successful_count', 0),
            'failed_payments': payment_stats.get('failed_count', 0),
            'total_amount': payment_stats.get('total_amount', 0),
            'total_fees': payment_stats.get('total_fees', 0),
            'average_payment_size': payment_stats.get('avg_amount', 0),
            'success_rate': payment_stats.get('success_rate', 0.0),
            'amount_analysis': amount_analysis,
            'timing_analysis': timing_analysis,
            'failure_analysis': failure_analysis
        }
    
    def _analyze_by_amount_ranges(self, payments: List[Payment]) -> Dict[str, Any]:
        """Analyze success rates by payment amount ranges."""
        ranges = [
            (0, 1000),           # Micro payments
            (1000, 10000),       # Small payments  
            (10000, 100000),     # Medium payments
            (100000, 1000000),   # Large payments
            (1000000, float('inf'))  # Very large payments
        ]
        
        analysis = {}
        for min_amt, max_amt in ranges:
            range_payments = [p for p in payments 
                            if min_amt <= p.amount.satoshis < max_amt]
            
            if range_payments:
                successful = [p for p in range_payments if p.is_successful]
                range_name = f"{min_amt:,}-{max_amt:,}" if max_amt != float('inf') else f"{min_amt:,}+"
                
                analysis[range_name] = {
                    'count': len(range_payments),
                    'success_rate': len(successful) / len(range_payments),
                    'avg_amount': statistics.mean(p.amount.satoshis for p in range_payments),
                    'total_amount': sum(p.amount.satoshis for p in range_payments)
                }
        
        return analysis
    
    def _analyze_timing_patterns(self, payments: List[Payment]) -> Dict[str, Any]:
        """Analyze payment timing patterns."""
        if not payments:
            return {}
        
        # Success rates by hour of day
        hourly_stats = {}
        for hour in range(24):
            hour_payments = [p for p in payments 
                           if p.created_at.hour == hour]
            if hour_payments:
                successful = [p for p in hour_payments if p.is_successful]
                hourly_stats[hour] = {
                    'count': len(hour_payments),
                    'success_rate': len(successful) / len(hour_payments)
                }
        
        # Average completion times
        completed_payments = [p for p in payments if p.duration is not None]
        avg_duration = statistics.mean(p.duration for p in completed_payments) if completed_payments else 0
        
        return {
            'hourly_patterns': hourly_stats,
            'average_completion_time_seconds': avg_duration,
            'fastest_payment': min((p.duration for p in completed_payments), default=0),
            'slowest_payment': max((p.duration for p in completed_payments), default=0)
        }
    
    def _analyze_failure_patterns(self, payments: List[Payment]) -> Dict[str, Any]:
        """Analyze payment failure patterns."""
        failed_payments = [p for p in payments if p.status == PaymentStatus.FAILED]
        
        if not failed_payments:
            return {'failure_rate': 0.0, 'common_reasons': []}
        
        # Group by failure reason
        failure_reasons = {}
        for payment in failed_payments:
            reason = payment.failure_reason or 'Unknown'
            failure_reasons[reason] = failure_reasons.get(reason, 0) + 1
        
        # Sort by frequency
        common_reasons = sorted(failure_reasons.items(), key=lambda x: x[1], reverse=True)
        
        return {
            'failure_rate': len(failed_payments) / len(payments),
            'total_failures': len(failed_payments),
            'common_reasons': [{'reason': reason, 'count': count} 
                             for reason, count in common_reasons[:10]]  # Top 10
        }


class LiquidityManagementService:
    """Domain service for liquidity management operations."""
    
    def __init__(self, channel_repo: ChannelRepository, payment_repo: PaymentRepository,
                 metrics_repo: MetricsRepository):
        self.channel_repo = channel_repo
        self.payment_repo = payment_repo
        self.metrics_repo = metrics_repo
    
    async def analyze_liquidity_distribution(self, node_id: NodeId) -> Dict[str, Any]:
        """Analyze liquidity distribution across channels."""
        channels = await self.channel_repo.find_active(node_id)
        
        if not channels:
            return {'error': 'No active channels found'}
        
        total_capacity = sum(ch.balance.capacity.satoshis for ch in channels)
        total_local = sum(ch.balance.local_balance.satoshis for ch in channels)
        total_remote = sum(ch.balance.remote_balance.satoshis for ch in channels)
        
        # Calculate distribution metrics
        local_ratios = [ch.balance.local_ratio for ch in channels]
        channel_analysis = []
        
        for channel in channels:
            routing_stats = await self.channel_repo.get_routing_stats(channel.channel_id, days=30)
            
            channel_analysis.append({
                'channel_id': channel.channel_id.channel_point,
                'capacity': channel.balance.capacity.satoshis,
                'local_balance': channel.balance.local_balance.satoshis,
                'remote_balance': channel.balance.remote_balance.satoshis,
                'local_ratio': channel.balance.local_ratio,
                'balance_score': 1.0 - abs(channel.balance.balance_ratio),  # Higher = more balanced
                'routing_volume_30d': routing_stats.get('routing_volume', 0),
                'needs_rebalancing': channel.balance.needs_rebalancing()
            })
        
        # Find rebalancing opportunities
        rebalancing_suggestions = await self._find_rebalancing_opportunities(channels)
        
        return {
            'summary': {
                'total_channels': len(channels),
                'total_capacity': total_capacity,
                'total_local_balance': total_local,
                'total_remote_balance': total_remote,
                'overall_local_ratio': total_local / total_capacity,
                'average_local_ratio': statistics.mean(local_ratios),
                'balance_distribution_std': statistics.stdev(local_ratios) if len(local_ratios) > 1 else 0
            },
            'channels': channel_analysis,
            'rebalancing_suggestions': rebalancing_suggestions
        }
    
    async def _find_rebalancing_opportunities(self, channels: List[Channel]) -> List[Dict[str, Any]]:
        """Find optimal rebalancing opportunities between channels."""
        suggestions = []
        
        # Find channels that need inbound liquidity
        need_inbound = [ch for ch in channels if ch.balance.local_ratio > 0.9]
        
        # Find channels that need outbound liquidity  
        need_outbound = [ch for ch in channels if ch.balance.local_ratio < 0.1]
        
        # Match channels for circular rebalancing
        for outbound_ch in need_inbound:  # High local balance (can send out)
            for inbound_ch in need_outbound:  # Low local balance (needs inbound)
                if outbound_ch.channel_id != inbound_ch.channel_id:
                    # Calculate optimal rebalancing amount
                    max_send = int(outbound_ch.balance.local_balance.satoshis * 0.4)
                    max_receive = int(inbound_ch.balance.capacity.satoshis * 0.4 - 
                                    inbound_ch.balance.local_balance.satoshis)
                    
                    rebalance_amount = min(max_send, max_receive)
                    
                    if rebalance_amount > 10000:  # Only suggest meaningful amounts
                        suggestions.append({
                            'type': 'circular_rebalancing',
                            'source_channel': outbound_ch.channel_id.channel_point,
                            'target_channel': inbound_ch.channel_id.channel_point,
                            'suggested_amount': rebalance_amount,
                            'estimated_cost': self._estimate_rebalancing_cost(rebalance_amount),
                            'priority': self._calculate_rebalancing_priority(outbound_ch, inbound_ch)
                        })
        
        # Sort by priority
        suggestions.sort(key=lambda x: x['priority'], reverse=True)
        
        return suggestions[:10]  # Return top 10 suggestions
    
    def _estimate_rebalancing_cost(self, amount: int) -> int:
        """Estimate cost of rebalancing operation."""
        # Simplified cost estimation
        # In practice, this would consider routing fees and success probability
        base_fee = 1000  # Base fee in msat
        rate_fee = amount * 100 // 1_000_000  # 100 ppm
        return (base_fee + rate_fee) // 1000  # Convert to sats
    
    def _calculate_rebalancing_priority(self, source: Channel, target: Channel) -> float:
        """Calculate priority score for rebalancing suggestion."""
        # Higher priority for more imbalanced channels
        source_imbalance = abs(source.balance.balance_ratio)
        target_imbalance = abs(target.balance.balance_ratio)
        
        # Consider channel capacity (larger channels = higher priority)
        capacity_factor = (source.balance.capacity + target.balance.capacity).satoshis / 2_000_000
        
        return (source_imbalance + target_imbalance) * min(capacity_factor, 2.0)


class FeeOptimizationService:
    """Domain service for advanced fee optimization."""
    
    def __init__(self, channel_repo: ChannelRepository, fee_repo: FeeRepository,
                 metrics_repo: MetricsRepository):
        self.channel_repo = channel_repo
        self.fee_repo = fee_repo
        self.metrics_repo = metrics_repo
    
    async def optimize_network_fees(self, node_id: NodeId) -> Dict[str, Any]:
        """Optimize fees across entire node network."""
        channels = await self.channel_repo.find_active(node_id)
        
        optimization_results = []
        total_revenue_impact = 0
        
        for channel in channels:
            result = await self._optimize_single_channel_fees(channel)
            if result['changed']:
                optimization_results.append(result)
                total_revenue_impact += result.get('estimated_revenue_impact', 0)
        
        return {
            'optimized_channels': len(optimization_results),
            'total_channels': len(channels),
            'estimated_revenue_impact': total_revenue_impact,
            'changes': optimization_results
        }
    
    async def _optimize_single_channel_fees(self, channel: Channel) -> Dict[str, Any]:
        """Optimize fees for a single channel."""
        # Get historical data
        routing_stats = await self.channel_repo.get_routing_stats(channel.channel_id, days=30)
        market_rates = await self.fee_repo.get_market_rates(
            (channel.balance.capacity.satoshis, channel.balance.capacity.satoshis)
        )
        
        current_policy = channel.fee_policy
        success_rate = routing_stats.get('success_rate', 0.5)
        routing_volume = routing_stats.get('routing_volume', 0)
        
        # Calculate optimal fee rate using simplified ML approach
        optimal_rate = self._calculate_optimal_fee_rate(
            current_policy.fee_rate_ppm,
            success_rate,
            routing_volume,
            market_rates.get('median_rate', current_policy.fee_rate_ppm)
        )
        
        if abs(optimal_rate - current_policy.fee_rate_ppm) > 5:  # Only change if meaningful
            new_policy = FeePolicy(
                base_fee_msat=current_policy.base_fee_msat,
                fee_rate_ppm=optimal_rate,
                time_lock_delta=current_policy.time_lock_delta,
                min_htlc_msat=current_policy.min_htlc_msat,
                max_htlc_msat=current_policy.max_htlc_msat,
                strategy=FeeStrategy.ML_OPTIMIZED
            )
            
            # Estimate revenue impact
            revenue_impact = self._estimate_revenue_impact(
                routing_volume, current_policy.fee_rate_ppm, optimal_rate, success_rate
            )
            
            return {
                'channel_id': channel.channel_id.channel_point,
                'changed': True,
                'old_fee_rate': current_policy.fee_rate_ppm,
                'new_fee_rate': optimal_rate,
                'reason': self._get_optimization_reason(current_policy.fee_rate_ppm, optimal_rate, success_rate),
                'estimated_revenue_impact': revenue_impact
            }
        
        return {
            'channel_id': channel.channel_id.channel_point,
            'changed': False,
            'current_fee_rate': current_policy.fee_rate_ppm
        }
    
    def _calculate_optimal_fee_rate(self, current_rate: int, success_rate: float,
                                   volume: int, market_rate: int) -> int:
        """Calculate optimal fee rate using heuristic approach."""
        # Start with market rate as baseline
        optimal_rate = market_rate
        
        # Adjust based on success rate
        if success_rate < 0.7:
            # Low success rate - reduce fees significantly
            optimal_rate = min(optimal_rate, int(current_rate * 0.7))
        elif success_rate < 0.85:
            # Moderate success rate - slight reduction
            optimal_rate = min(optimal_rate, int(current_rate * 0.9))
        elif success_rate > 0.95 and volume > 100000:
            # High success rate with good volume - can increase
            optimal_rate = min(5000, int(current_rate * 1.3))
        
        # Ensure reasonable bounds
        return max(1, min(optimal_rate, 5000))
    
    def _estimate_revenue_impact(self, volume: int, old_rate: int, new_rate: int,
                                success_rate: float) -> float:
        """Estimate monthly revenue impact of fee change."""
        if volume == 0:
            return 0.0
        
        old_revenue = volume * old_rate / 1_000_000 * success_rate
        
        # Estimate new success rate based on fee change
        if new_rate < old_rate:
            # Lower fees should improve success rate
            improvement_factor = min(1.2, (old_rate / new_rate) * 0.1 + 1)
            new_success_rate = min(1.0, success_rate * improvement_factor)
        else:
            # Higher fees might reduce success rate
            reduction_factor = max(0.8, 1 - (new_rate / old_rate - 1) * 0.3)
            new_success_rate = success_rate * reduction_factor
        
        new_revenue = volume * new_rate / 1_000_000 * new_success_rate
        
        return new_revenue - old_revenue
    
    def _get_optimization_reason(self, old_rate: int, new_rate: int, success_rate: float) -> str:
        """Get human-readable reason for fee optimization."""
        if new_rate > old_rate:
            return f"Increased fees due to high success rate ({success_rate:.1%}) - opportunity for more revenue"
        else:
            return f"Reduced fees due to low success rate ({success_rate:.1%}) - prioritizing volume over rate"