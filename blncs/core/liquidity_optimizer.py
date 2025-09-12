"""
Lightning Network Liquidity Management System
Comprehensive liquidity optimization and management for Lightning Network channels.
Combines advanced analytics with practical management tools.
"""

from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from collections import defaultdict, deque
import statistics
import time

from .logger import get_logger
from .config_manager import get_config_manager
from .cache_unified import get_cache
from .exceptions import LightningError


@dataclass
class LiquidityMetric:
    """Represents liquidity metrics for a channel"""
    channel_id: str
    local_balance: int
    remote_balance: int
    capacity: int
    local_ratio: float
    remote_ratio: float
    inbound_liquidity: int
    outbound_liquidity: int
    routing_volume_24h: int = 0
    fee_earnings_24h: int = 0
    payment_failures: int = 0
    last_activity: datetime = None


class LiquidityOptimizer:
    """Advanced liquidity management and optimization"""
    
    def __init__(self, client=None):
        self.logger = get_logger(__name__)
        self.config_manager = get_config_manager()
        self.cache = get_cache()
        self.client = client
        
        # Configuration
        self.optimal_ratio_min = self.config_manager.get('liquidity.optimal_ratio_min', 0.3)  # 30%
        self.optimal_ratio_max = self.config_manager.get('liquidity.optimal_ratio_max', 0.7)  # 70%
        self.min_channel_size = self.config_manager.get('liquidity.min_channel_size', 1000000)  # 1M sats
        self.min_inbound_liquidity = self.config_manager.get('liquidity.min_inbound_liquidity', 500000)  # 500k sats
        self.min_outbound_liquidity = self.config_manager.get('liquidity.min_outbound_liquidity', 500000)  # 500k sats
        
        # Historical data storage
        self.liquidity_history = deque(maxlen=1000)
        self.performance_history = deque(maxlen=1000)
        
    def analyze_liquidity(self) -> Dict[str, LiquidityMetric]:
        """Analyze current liquidity across all channels"""
        if not self.client:
            self.logger.error("No Lightning client available for liquidity analysis")
            return {}
        
        try:
            channels = self.client.list_channels()
            liquidity_metrics = {}
            
            for channel in channels:
                chan_id = channel.get('chan_id', '')
                if not chan_id:
                    continue
                
                local_balance = int(channel.get('local_balance', 0))
                remote_balance = int(channel.get('remote_balance', 0))
                capacity = int(channel.get('capacity', 0))
                
                if capacity == 0:
                    continue
                
                # Calculate liquidity metrics
                local_ratio = local_balance / capacity if capacity > 0 else 0
                remote_ratio = remote_balance / capacity if capacity > 0 else 0
                
                # Inbound liquidity = what we can receive
                inbound_liquidity = remote_balance
                # Outbound liquidity = what we can send
                outbound_liquidity = local_balance
                
                # Get additional channel info
                last_update = channel.get('last_update', 0)
                last_activity = datetime.fromtimestamp(last_update) if last_update > 0 else None
                
                metric = LiquidityMetric(
                    channel_id=chan_id,
                    local_balance=local_balance,
                    remote_balance=remote_balance,
                    capacity=capacity,
                    local_ratio=local_ratio,
                    remote_ratio=remote_ratio,
                    inbound_liquidity=inbound_liquidity,
                    outbound_liquidity=outbound_liquidity,
                    last_activity=last_activity
                )
                
                liquidity_metrics[chan_id] = metric
            
            return liquidity_metrics
            
        except Exception as e:
            self.logger.error(f"Liquidity analysis error: {e}")
            return {}
    
    def get_liquidity_score(self, metric: LiquidityMetric) -> float:
        """Calculate a liquidity health score (0-100)"""
        score = 100.0
        
        # Penalize channels that are too imbalanced
        if metric.local_ratio < self.optimal_ratio_min:
            # Too little outbound liquidity
            shortage = self.optimal_ratio_min - metric.local_ratio
            score -= shortage * 200  # Heavy penalty for imbalance
        elif metric.local_ratio > self.optimal_ratio_max:
            # Too much outbound liquidity (not enough inbound)
            excess = metric.local_ratio - self.optimal_ratio_max
            score -= excess * 200
        
        # Penalize very small channels
        if metric.capacity < self.min_channel_size:
            size_penalty = (self.min_channel_size - metric.capacity) / self.min_channel_size * 30
            score -= size_penalty
        
        # Penalize insufficient inbound/outbound liquidity
        if metric.inbound_liquidity < self.min_inbound_liquidity:
            inbound_penalty = (self.min_inbound_liquidity - metric.inbound_liquidity) / self.min_inbound_liquidity * 20
            score -= inbound_penalty
        
        if metric.outbound_liquidity < self.min_outbound_liquidity:
            outbound_penalty = (self.min_outbound_liquidity - metric.outbound_liquidity) / self.min_outbound_liquidity * 20
            score -= outbound_penalty
        
        return max(0.0, min(100.0, score))
    
    def identify_liquidity_issues(self, metrics: Dict[str, LiquidityMetric]) -> List[Dict[str, Any]]:
        """Identify specific liquidity problems and provide recommendations"""
        issues = []
        
        for chan_id, metric in metrics.items():
            channel_issues = []
            
            # Check for severe imbalances
            if metric.local_ratio < 0.1:  # Less than 10% local
                channel_issues.append({
                    'type': 'severe_outbound_shortage',
                    'severity': 'critical',
                    'description': f'Severe outbound liquidity shortage: {metric.local_ratio:.1%}',
                    'recommendation': 'Urgently need to increase outbound liquidity via Loop Out or rebalancing'
                })
            elif metric.local_ratio < self.optimal_ratio_min:
                channel_issues.append({
                    'type': 'outbound_shortage',
                    'severity': 'warning',
                    'description': f'Low outbound liquidity: {metric.local_ratio:.1%}',
                    'recommendation': 'Consider increasing outbound liquidity'
                })
            
            if metric.local_ratio > 0.9:  # More than 90% local
                channel_issues.append({
                    'type': 'severe_inbound_shortage',
                    'severity': 'critical',
                    'description': f'Severe inbound liquidity shortage: {metric.remote_ratio:.1%}',
                    'recommendation': 'Urgently need to increase inbound liquidity via Loop In or spending'
                })
            elif metric.local_ratio > self.optimal_ratio_max:
                channel_issues.append({
                    'type': 'inbound_shortage',
                    'severity': 'warning',
                    'description': f'Low inbound liquidity: {metric.remote_ratio:.1%}',
                    'recommendation': 'Consider increasing inbound liquidity'
                })
            
            # Check for small channels
            if metric.capacity < self.min_channel_size:
                channel_issues.append({
                    'type': 'small_channel',
                    'severity': 'info',
                    'description': f'Channel size is below recommended minimum: {metric.capacity:,} sats',
                    'recommendation': f'Consider increasing channel size to at least {self.min_channel_size:,} sats'
                })
            
            # Check for inactive channels
            if metric.last_activity:
                inactive_hours = (datetime.now() - metric.last_activity).total_seconds() / 3600
                if inactive_hours > 168:  # 7 days
                    channel_issues.append({
                        'type': 'inactive_channel',
                        'severity': 'info',
                        'description': f'Channel inactive for {inactive_hours/24:.1f} days',
                        'recommendation': 'Consider closing if consistently inactive'
                    })
            
            if channel_issues:
                issues.append({
                    'channel_id': chan_id,
                    'liquidity_score': self.get_liquidity_score(metric),
                    'issues': channel_issues,
                    'capacity': metric.capacity,
                    'local_ratio': metric.local_ratio,
                    'remote_ratio': metric.remote_ratio
                })
        
        # Sort by severity and liquidity score
        issues.sort(key=lambda x: (
            sum(1 for issue in x['issues'] if issue['severity'] == 'critical'),
            sum(1 for issue in x['issues'] if issue['severity'] == 'warning'),
            -x['liquidity_score']
        ), reverse=True)
        
        return issues
    
    def generate_liquidity_plan(self, metrics: Dict[str, LiquidityMetric]) -> Dict[str, Any]:
        """Generate a comprehensive liquidity optimization plan"""
        plan = {
            'overall_health': 'unknown',
            'total_capacity': 0,
            'total_inbound': 0,
            'total_outbound': 0,
            'average_liquidity_score': 0,
            'immediate_actions': [],
            'optimization_opportunities': [],
            'channel_recommendations': []
        }
        
        if not metrics:
            return plan
        
        # Calculate overall metrics
        total_capacity = sum(m.capacity for m in metrics.values())
        total_inbound = sum(m.inbound_liquidity for m in metrics.values())
        total_outbound = sum(m.outbound_liquidity for m in metrics.values())
        
        liquidity_scores = [self.get_liquidity_score(m) for m in metrics.values()]
        avg_score = statistics.mean(liquidity_scores) if liquidity_scores else 0
        
        plan.update({
            'total_capacity': total_capacity,
            'total_inbound': total_inbound,
            'total_outbound': total_outbound,
            'average_liquidity_score': avg_score
        })
        
        # Determine overall health
        if avg_score >= 80:
            plan['overall_health'] = 'excellent'
        elif avg_score >= 60:
            plan['overall_health'] = 'good'
        elif avg_score >= 40:
            plan['overall_health'] = 'fair'
        else:
            plan['overall_health'] = 'poor'
        
        # Identify immediate actions needed
        issues = self.identify_liquidity_issues(metrics)
        critical_issues = [issue for issue in issues if any(i['severity'] == 'critical' for i in issue['issues'])]
        
        if critical_issues:
            plan['immediate_actions'] = [
                f"Address critical liquidity issues in {len(critical_issues)} channels",
                "Consider emergency rebalancing or Loop operations",
                "Monitor these channels closely"
            ]
        
        # Generate optimization opportunities
        optimization_ops = []
        
        # Check for rebalancing opportunities
        high_outbound = [m for m in metrics.values() if m.local_ratio > 0.8]
        high_inbound = [m for m in metrics.values() if m.local_ratio < 0.2]
        
        if high_outbound and high_inbound:
            optimization_ops.append({
                'type': 'rebalancing',
                'description': f'Rebalance {len(high_outbound)} high-outbound channels with {len(high_inbound)} high-inbound channels',
                'potential_improvement': 'Improve routing capability and fee earnings'
            })
        
        # Check for small channels that could be consolidated
        small_channels = [m for m in metrics.values() if m.capacity < self.min_channel_size]
        if len(small_channels) >= 2:
            optimization_ops.append({
                'type': 'consolidation',
                'description': f'Consider consolidating {len(small_channels)} small channels',
                'potential_improvement': 'Reduce on-chain fees and improve routing efficiency'
            })
        
        # Check for highly imbalanced but large channels
        large_imbalanced = [m for m in metrics.values() if m.capacity > 5000000 and (m.local_ratio < 0.2 or m.local_ratio > 0.8)]
        if large_imbalanced:
            optimization_ops.append({
                'type': 'priority_rebalancing',
                'description': f'{len(large_imbalanced)} large channels are severely imbalanced',
                'potential_improvement': 'High impact rebalancing for better routing'
            })
        
        plan['optimization_opportunities'] = optimization_ops
        
        # Generate per-channel recommendations
        for chan_id, metric in metrics.items():
            score = self.get_liquidity_score(metric)
            
            if score < 50:  # Only recommend for problematic channels
                recommendation = self._generate_channel_recommendation(metric)
                if recommendation:
                    plan['channel_recommendations'].append({
                        'channel_id': chan_id,
                        'score': score,
                        'recommendation': recommendation
                    })
        
        return plan
    
    def _generate_channel_recommendation(self, metric: LiquidityMetric) -> Optional[str]:
        """Generate specific recommendation for a channel"""
        if metric.local_ratio < 0.1:
            return f"Critical: Add {self.min_outbound_liquidity:,} sats outbound liquidity via Loop Out"
        elif metric.local_ratio < self.optimal_ratio_min:
            needed = int((self.optimal_ratio_min - metric.local_ratio) * metric.capacity)
            return f"Add {needed:,} sats outbound liquidity via rebalancing or Loop Out"
        elif metric.local_ratio > 0.9:
            return f"Critical: Add {self.min_inbound_liquidity:,} sats inbound liquidity via Loop In or spending"
        elif metric.local_ratio > self.optimal_ratio_max:
            needed = int((metric.local_ratio - self.optimal_ratio_max) * metric.capacity)
            return f"Use {needed:,} sats by making payments or rebalancing to other channels"
        elif metric.capacity < self.min_channel_size:
            return f"Consider increasing channel size by {self.min_channel_size - metric.capacity:,} sats"
        
        return None
    
    def get_liquidity_summary(self) -> Dict[str, Any]:
        """Get high-level liquidity summary"""
        metrics = self.analyze_liquidity()
        
        if not metrics:
            return {'status': 'no_data'}
        
        # Calculate summary statistics
        total_capacity = sum(m.capacity for m in metrics.values())
        total_local = sum(m.local_balance for m in metrics.values())
        total_remote = sum(m.remote_balance for m in metrics.values())
        
        balanced_channels = sum(1 for m in metrics.values() 
                              if self.optimal_ratio_min <= m.local_ratio <= self.optimal_ratio_max)
        
        liquidity_scores = [self.get_liquidity_score(m) for m in metrics.values()]
        avg_score = statistics.mean(liquidity_scores) if liquidity_scores else 0
        
        return {
            'total_channels': len(metrics),
            'balanced_channels': balanced_channels,
            'imbalanced_channels': len(metrics) - balanced_channels,
            'total_capacity': total_capacity,
            'total_local_balance': total_local,
            'total_remote_balance': total_remote,
            'overall_local_ratio': total_local / total_capacity if total_capacity > 0 else 0,
            'average_liquidity_score': avg_score,
            'health_status': 'excellent' if avg_score >= 80 else 'good' if avg_score >= 60 else 'fair' if avg_score >= 40 else 'poor',
            'last_update': datetime.now().isoformat()
        }
    
    def monitor_liquidity_changes(self) -> Dict[str, Any]:
        """Monitor and track liquidity changes over time"""
        current_metrics = self.analyze_liquidity()
        
        # Store current metrics for historical tracking
        timestamp = datetime.now()
        self.liquidity_history.append((timestamp, current_metrics))
        
        changes = {
            'timestamp': timestamp.isoformat(),
            'channels_monitored': len(current_metrics),
            'significant_changes': []
        }
        
        # Compare with previous measurements if available
        if len(self.liquidity_history) >= 2:
            prev_timestamp, prev_metrics = self.liquidity_history[-2]
            
            for chan_id, current_metric in current_metrics.items():
                if chan_id in prev_metrics:
                    prev_metric = prev_metrics[chan_id]
                    
                    # Check for significant balance changes
                    balance_change = current_metric.local_balance - prev_metric.local_balance
                    capacity = current_metric.capacity
                    
                    if abs(balance_change) > capacity * 0.1:  # 10% of capacity
                        changes['significant_changes'].append({
                            'channel_id': chan_id,
                            'balance_change': balance_change,
                            'change_ratio': balance_change / capacity,
                            'new_local_ratio': current_metric.local_ratio,
                            'prev_local_ratio': prev_metric.local_ratio
                        })
        
        return changes
    
    def estimate_rebalancing_cost(self, amount: int, hops: int = 3) -> Dict[str, Any]:
        """Estimate rebalancing cost for given amount"""
        base_fee = 1000  # 1 sat base fee
        fee_rate = 500   # 500 ppm (0.05%)
        
        estimated_fee = base_fee + (amount * fee_rate // 1000000)
        estimated_fee *= hops  # Multiply by number of hops
        
        return {
            'amount': amount,
            'estimated_fee': estimated_fee,
            'fee_rate_ppm': (estimated_fee * 1000000) // amount if amount > 0 else 0,
            'cost_ratio': estimated_fee / amount if amount > 0 else 0,
            'recommended': estimated_fee < (amount * 0.01),  # Recommend if less than 1%
            'hops': hops
        }
    
    def get_quick_liquidity_check(self, channels: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Quick lightweight liquidity check without full analysis"""
        if not channels:
            return {'status': 'no_channels'}
        
        total_capacity = 0
        total_local = 0
        total_remote = 0
        unbalanced_count = 0
        active_channels = 0
        
        for ch in channels:
            if not ch.get('active', False):
                continue
                
            active_channels += 1
            capacity = ch.get('capacity', 0)
            local_balance = ch.get('local_balance', 0)
            remote_balance = ch.get('remote_balance', 0)
            
            total_capacity += capacity
            total_local += local_balance
            total_remote += remote_balance
            
            if capacity > 0:
                local_ratio = local_balance / capacity
                if local_ratio < 0.2 or local_ratio > 0.8:
                    unbalanced_count += 1
        
        overall_ratio = total_local / total_capacity if total_capacity > 0 else 0
        health = self._calculate_liquidity_health(overall_ratio)
        
        return {
            'status': 'active',
            'active_channels': active_channels,
            'unbalanced_channels': unbalanced_count,
            'total_capacity': total_capacity,
            'overall_balance_ratio': overall_ratio,
            'liquidity_health': health,
            'needs_attention': unbalanced_count > 0 or health in ['poor', 'fair']
        }
    
    def _calculate_liquidity_health(self, balance_ratio: float) -> str:
        """Calculate liquidity health status"""
        if 0.4 <= balance_ratio <= 0.6:
            return "excellent"
        elif 0.3 <= balance_ratio <= 0.7:
            return "good"
        elif 0.2 <= balance_ratio <= 0.8:
            return "fair"
        else:
            return "poor"


# Global liquidity optimizer instance
_liquidity_optimizer = None

def get_liquidity_optimizer(client=None) -> LiquidityOptimizer:
    """Get or create global liquidity optimizer instance"""
    global _liquidity_optimizer
    if _liquidity_optimizer is None:
        _liquidity_optimizer = LiquidityOptimizer(client)
    return _liquidity_optimizer

# Alias for backward compatibility
def get_liquidity_manager(client=None) -> LiquidityOptimizer:
    """Alias for get_liquidity_optimizer for backward compatibility"""
    return get_liquidity_optimizer(client)