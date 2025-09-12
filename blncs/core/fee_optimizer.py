"""
Fee Optimization for Lightning Channels
Practical fee optimization based on routing performance and market conditions.
"""

import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
import statistics

from .logger import get_logger
from .config_manager import get_config_manager
from .database import get_database_manager
from .metrics import get_metrics_collector, set_gauge, increment_counter


@dataclass
class ChannelMetrics:
    """Metrics for a specific channel"""
    chan_id: str
    capacity: int
    local_balance: int
    remote_balance: int
    current_fee_rate: int
    current_base_fee: int
    
    # Performance metrics
    successful_forwards: int = 0
    failed_forwards: int = 0
    total_volume: int = 0
    total_fees_earned: int = 0
    avg_forward_size: float = 0
    utilization_rate: float = 0
    
    # Market data
    peer_avg_fee_rate: int = 1000
    network_avg_fee_rate: int = 1000
    
    # Time-based data
    last_forward: Optional[datetime] = None
    last_update: datetime = field(default_factory=datetime.now)
    
    @property
    def local_ratio(self) -> float:
        """Local balance ratio"""
        return self.local_balance / self.capacity if self.capacity > 0 else 0
    
    @property
    def success_rate(self) -> float:
        """Forward success rate"""
        total = self.successful_forwards + self.failed_forwards
        return self.successful_forwards / total if total > 0 else 1.0
    
    @property
    def fee_per_forward(self) -> float:
        """Average fee per forward"""
        return self.total_fees_earned / self.successful_forwards if self.successful_forwards > 0 else 0


@dataclass
class FeeOptimizationResult:
    """Result of fee optimization"""
    chan_id: str
    current_fee_rate: int
    recommended_fee_rate: int
    current_base_fee: int
    recommended_base_fee: int
    confidence: float
    reasoning: str
    expected_change_pct: float = 0


class AdvancedFeeOptimizer:
    """Advanced fee optimizer using machine learning-like algorithms"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config_manager = get_config_manager()
        self.db = get_database_manager()
        self.metrics = get_metrics_collector()
        
        # Configuration
        self.config = self.config_manager.get('fee_optimization', {})
        self.optimization_interval = self.config.get('interval_hours', 6) * 3600
        self.min_sample_size = self.config.get('min_forwards_required', 10)
        self.max_fee_change_pct = self.config.get('max_change_percent', 50)
        self.target_success_rate = self.config.get('target_success_rate', 0.98)
        
        # Data storage
        self.channel_metrics: Dict[str, ChannelMetrics] = {}
        self.historical_data: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.market_data: Dict[str, float] = {}
        
        # Threading
        self.optimization_thread = None
        self.running = False
        self.lock = threading.RLock()
        
        # Performance tracking
        self.optimizations_performed = 0
        self.total_fee_changes = 0
        self.revenue_impact = 0
    
    def start(self) -> bool:
        """Start the fee optimization service"""
        if self.running:
            return True
        
        self.running = True
        self.optimization_thread = threading.Thread(
            target=self._optimization_loop,
            daemon=True,
            name="FeeOptimizer"
        )
        self.optimization_thread.start()
        
        self.logger.info("Advanced fee optimizer started")
        return True
    
    def stop(self):
        """Stop the fee optimization service"""
        self.running = False
        if self.optimization_thread:
            self.optimization_thread.join(timeout=5)
        self.logger.info("Advanced fee optimizer stopped")
    
    def _optimization_loop(self):
        """Main optimization loop"""
        while self.running:
            try:
                self._run_optimization_cycle()
                time.sleep(self.optimization_interval)
            except Exception as e:
                self.logger.error(f"Optimization loop error: {e}")
                time.sleep(60)  # Wait before retrying
    
    def _run_optimization_cycle(self):
        """Run a complete optimization cycle"""
        try:
            self.logger.info("Starting fee optimization cycle")
            
            # Update channel metrics
            self._update_channel_metrics()
            
            # Analyze market conditions
            self._analyze_market_conditions()
            
            # Generate optimization recommendations
            recommendations = self._generate_recommendations()
            
            # Apply recommendations (if configured to do so)
            if self.config.get('auto_apply', False):
                applied = self._apply_recommendations(recommendations)
                self.logger.info(f"Applied {applied} fee optimizations automatically")
            else:
                self.logger.info(f"Generated {len(recommendations)} fee recommendations")
                # Store recommendations for manual review
                self._store_recommendations(recommendations)
            
            # Update metrics
            set_gauge('fee_optimizer_recommendations', len(recommendations))
            increment_counter('fee_optimizer_cycles')
            
        except Exception as e:
            self.logger.error(f"Optimization cycle failed: {e}")
    
    def _update_channel_metrics(self):
        """Update metrics for all channels"""
        try:
            # This would typically get data from Lightning client
            # For now, we'll simulate with database data
            channels = self._get_channels_data()
            forwarding_data = self._get_forwarding_data()
            
            with self.lock:
                for channel in channels:
                    chan_id = str(channel['chan_id'])
                    
                    # Create or update channel metrics
                    if chan_id not in self.channel_metrics:
                        self.channel_metrics[chan_id] = ChannelMetrics(
                            chan_id=chan_id,
                            capacity=channel['capacity'],
                            local_balance=channel['local_balance'],
                            remote_balance=channel['remote_balance'],
                            current_fee_rate=channel.get('fee_rate', 1000),
                            current_base_fee=channel.get('base_fee', 1000)
                        )
                    
                    metrics = self.channel_metrics[chan_id]
                    
                    # Update basic data
                    metrics.local_balance = channel['local_balance']
                    metrics.remote_balance = channel['remote_balance']
                    metrics.last_update = datetime.now()
                    
                    # Update forwarding metrics
                    chan_forwards = forwarding_data.get(chan_id, [])
                    if chan_forwards:
                        metrics.successful_forwards = len([f for f in chan_forwards if f['status'] == 'settled'])
                        metrics.failed_forwards = len([f for f in chan_forwards if f['status'] == 'failed'])
                        metrics.total_volume = sum(f['amount'] for f in chan_forwards if f['status'] == 'settled')
                        metrics.total_fees_earned = sum(f['fee'] for f in chan_forwards if f['status'] == 'settled')
                        
                        if chan_forwards:
                            metrics.avg_forward_size = statistics.mean(f['amount'] for f in chan_forwards)
                            metrics.last_forward = max(f['timestamp'] for f in chan_forwards)
                    
                    # Calculate utilization
                    if metrics.capacity > 0:
                        volume_7d = sum(f['amount'] for f in chan_forwards 
                                      if (datetime.now() - f['timestamp']).days <= 7)
                        metrics.utilization_rate = volume_7d / (metrics.capacity * 7)  # Daily utilization
                    
        except Exception as e:
            self.logger.error(f"Failed to update channel metrics: {e}")
    
    def _analyze_market_conditions(self):
        """Analyze market conditions for fee optimization"""
        try:
            # Calculate network-wide fee statistics
            all_channels = list(self.channel_metrics.values())
            
            if not all_channels:
                return
            
            fee_rates = [ch.current_fee_rate for ch in all_channels if ch.current_fee_rate > 0]
            
            if fee_rates:
                self.market_data.update({
                    'network_median_fee': statistics.median(fee_rates),
                    'network_mean_fee': statistics.mean(fee_rates),
                    'network_75th_percentile': statistics.quantiles(fee_rates, n=4)[2] if len(fee_rates) > 4 else statistics.median(fee_rates),
                    'network_25th_percentile': statistics.quantiles(fee_rates, n=4)[0] if len(fee_rates) > 4 else statistics.median(fee_rates)
                })
            
            # Update metrics
            if 'network_median_fee' in self.market_data:
                set_gauge('network_median_fee_rate', self.market_data['network_median_fee'])
        
        except Exception as e:
            self.logger.error(f"Failed to analyze market conditions: {e}")
    
    def _generate_recommendations(self) -> List[FeeOptimizationResult]:
        """Generate fee optimization recommendations"""
        recommendations = []
        
        try:
            for chan_id, metrics in self.channel_metrics.items():
                recommendation = self._analyze_channel_fees(metrics)
                if recommendation:
                    recommendations.append(recommendation)
        
        except Exception as e:
            self.logger.error(f"Failed to generate recommendations: {e}")
        
        return recommendations
    
    def _analyze_channel_fees(self, metrics: ChannelMetrics) -> Optional[FeeOptimizationResult]:
        """Analyze and recommend fees for a specific channel"""
        try:
            # Skip if insufficient data
            if metrics.successful_forwards < self.min_sample_size:
                return None
            
            current_fee = metrics.current_fee_rate
            recommended_fee = current_fee
            confidence = 0.0
            reasoning = []
            
            # Factor 1: Success rate analysis
            success_rate = metrics.success_rate
            if success_rate < self.target_success_rate:
                # Low success rate - reduce fees
                fee_reduction = min(20, (self.target_success_rate - success_rate) * 100)
                recommended_fee = max(1, int(current_fee * (1 - fee_reduction / 100)))
                reasoning.append(f"Low success rate ({success_rate:.1%}) suggests fees too high")
                confidence += 0.3
            elif success_rate > 0.99 and metrics.utilization_rate > 0.5:
                # Very high success rate with good utilization - can increase fees
                fee_increase = min(15, (success_rate - 0.99) * 500)
                recommended_fee = int(current_fee * (1 + fee_increase / 100))
                reasoning.append(f"High success rate ({success_rate:.1%}) with good utilization")
                confidence += 0.2
            
            # Factor 2: Liquidity position
            local_ratio = metrics.local_ratio
            if local_ratio > 0.8:
                # Too much outbound liquidity - increase fees to reduce usage
                fee_increase = min(25, (local_ratio - 0.8) * 125)
                recommended_fee = max(recommended_fee, int(current_fee * (1 + fee_increase / 100)))
                reasoning.append(f"High local balance ({local_ratio:.1%}) - increase fees")
                confidence += 0.25
            elif local_ratio < 0.2:
                # Too much inbound liquidity - decrease fees to encourage usage
                fee_reduction = min(20, (0.2 - local_ratio) * 100)
                recommended_fee = min(recommended_fee, max(1, int(current_fee * (1 - fee_reduction / 100))))
                reasoning.append(f"Low local balance ({local_ratio:.1%}) - decrease fees")
                confidence += 0.25
            
            # Factor 3: Market comparison
            if 'network_median_fee' in self.market_data:
                market_median = self.market_data['network_median_fee']
                
                if current_fee > market_median * 1.5 and metrics.utilization_rate < 0.1:
                    # Much higher than market with low usage
                    recommended_fee = min(recommended_fee, int(market_median * 1.2))
                    reasoning.append(f"Fee much higher than market median ({market_median:.0f} ppm)")
                    confidence += 0.15
                elif current_fee < market_median * 0.7 and metrics.utilization_rate > 0.8:
                    # Much lower than market with high usage
                    recommended_fee = max(recommended_fee, int(market_median * 0.8))
                    reasoning.append(f"Fee much lower than market median ({market_median:.0f} ppm)")
                    confidence += 0.15
            
            # Factor 4: Revenue optimization
            if metrics.total_fees_earned > 0 and metrics.successful_forwards > 20:
                # Calculate revenue per forward trend
                revenue_per_forward = metrics.fee_per_forward
                if revenue_per_forward < current_fee / 1000000 * metrics.avg_forward_size * 0.5:
                    # Low actual revenue suggests room for fee increase
                    recommended_fee = max(recommended_fee, int(current_fee * 1.1))
                    reasoning.append("Low revenue per forward suggests fee increase opportunity")
                    confidence += 0.1
            
            # Apply maximum change limits
            max_change = int(current_fee * self.max_fee_change_pct / 100)
            if recommended_fee > current_fee + max_change:
                recommended_fee = current_fee + max_change
            elif recommended_fee < current_fee - max_change:
                recommended_fee = max(1, current_fee - max_change)
            
            # Only recommend if change is significant and confidence is reasonable
            if abs(recommended_fee - current_fee) < max(10, current_fee * 0.05) or confidence < 0.3:
                return None
            
            expected_change = ((recommended_fee - current_fee) / current_fee) * 100 if current_fee > 0 else 0
            
            return FeeOptimizationResult(
                chan_id=metrics.chan_id,
                current_fee_rate=current_fee,
                recommended_fee_rate=recommended_fee,
                current_base_fee=metrics.current_base_fee,
                recommended_base_fee=metrics.current_base_fee,  # Keep base fee unchanged for now
                confidence=confidence,
                reasoning="; ".join(reasoning),
                expected_change_pct=expected_change
            )
        
        except Exception as e:
            self.logger.error(f"Failed to analyze channel {metrics.chan_id}: {e}")
            return None
    
    def _apply_recommendations(self, recommendations: List[FeeOptimizationResult]) -> int:
        """Apply fee recommendations automatically"""
        applied = 0
        
        # This would typically use Lightning client to update fees
        # For now, we'll just log what would be done
        for rec in recommendations:
            if rec.confidence > 0.6:  # Only apply high-confidence recommendations
                self.logger.info(f"Would update channel {rec.chan_id[:8]}... fee: {rec.current_fee_rate} -> {rec.recommended_fee_rate} ppm")
                applied += 1
        
        self.total_fee_changes += applied
        return applied
    
    def _store_recommendations(self, recommendations: List[FeeOptimizationResult]):
        """Store recommendations in database for manual review"""
        try:
            for rec in recommendations:
                self.db.record_event(
                    event_type='fee_recommendation',
                    severity='info',
                    message=f"Fee optimization for channel {rec.chan_id[:8]}...",
                    details={
                        'chan_id': rec.chan_id,
                        'current_fee_rate': rec.current_fee_rate,
                        'recommended_fee_rate': rec.recommended_fee_rate,
                        'confidence': rec.confidence,
                        'reasoning': rec.reasoning,
                        'expected_change_pct': rec.expected_change_pct
                    }
                )
        except Exception as e:
            self.logger.error(f"Failed to store recommendations: {e}")
    
    def _get_channels_data(self) -> List[Dict]:
        """Get channels data (would normally come from Lightning client)"""
        try:
            # Simulate channel data - in real implementation, get from Lightning client
            return [
                {
                    'chan_id': '12345',
                    'capacity': 1000000,
                    'local_balance': 500000,
                    'remote_balance': 500000,
                    'fee_rate': 1000,
                    'base_fee': 1000
                }
            ]
        except Exception:
            return []
    
    def _get_forwarding_data(self) -> Dict[str, List[Dict]]:
        """Get forwarding data (would normally come from Lightning client)"""
        try:
            # Simulate forwarding data - in real implementation, get from Lightning client
            end_time = datetime.now()
            start_time = end_time - timedelta(days=30)
            
            return {
                '12345': [
                    {
                        'timestamp': datetime.now() - timedelta(hours=i),
                        'amount': 10000 + (i * 1000),
                        'fee': 10 + i,
                        'status': 'settled' if i % 10 != 0 else 'failed'
                    }
                    for i in range(100)
                ]
            }
        except Exception:
            return {}
    
    def get_optimization_stats(self) -> Dict[str, Any]:
        """Get optimization statistics"""
        return {
            'optimizations_performed': self.optimizations_performed,
            'total_fee_changes': self.total_fee_changes,
            'active_channels': len(self.channel_metrics),
            'market_data': self.market_data.copy(),
            'last_optimization': datetime.now().isoformat()
        }
    
    def get_channel_analysis(self, chan_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed analysis for a specific channel"""
        metrics = self.channel_metrics.get(chan_id)
        if not metrics:
            return None
        
        recommendation = self._analyze_channel_fees(metrics)
        
        return {
            'metrics': {
                'capacity': metrics.capacity,
                'local_ratio': metrics.local_ratio,
                'success_rate': metrics.success_rate,
                'utilization_rate': metrics.utilization_rate,
                'successful_forwards': metrics.successful_forwards,
                'total_fees_earned': metrics.total_fees_earned,
                'fee_per_forward': metrics.fee_per_forward
            },
            'current_fees': {
                'fee_rate': metrics.current_fee_rate,
                'base_fee': metrics.current_base_fee
            },
            'recommendation': {
                'recommended_fee_rate': recommendation.recommended_fee_rate if recommendation else metrics.current_fee_rate,
                'confidence': recommendation.confidence if recommendation else 0,
                'reasoning': recommendation.reasoning if recommendation else "Insufficient data",
                'expected_change_pct': recommendation.expected_change_pct if recommendation else 0
            }
        }


    def get_lightning_fee_recommendation(self, amount: int) -> 'FeeRecommendation':
        """Get Lightning Network fee recommendation (compatibility method)"""
        # Use network median or default
        fee_rate = self.market_data.get('network_median_fee', 1000)  # ppm
        estimated_cost = int(amount * fee_rate / 1000000)  # Convert to sats
        
        return FeeRecommendation(
            fee_rate=fee_rate,
            confirmation_time='instant',
            estimated_cost=estimated_cost,
            network='lightning'
        )
    
    def get_onchain_fee_recommendation(self, priority: str = 'medium', tx_size: int = 250) -> 'FeeRecommendation':
        """Get on-chain fee recommendation (compatibility method)"""
        base_rates = {
            'fast': 20,    # 1-2 blocks
            'medium': 10,  # 3-6 blocks  
            'slow': 3      # 6+ blocks
        }
        
        fee_rate = base_rates.get(priority, 10)
        estimated_cost = fee_rate * tx_size
        
        conf_times = {
            'fast': '10-20分',
            'medium': '30-60分', 
            'slow': '1-3時間'
        }
        
        return FeeRecommendation(
            fee_rate=fee_rate,
            confirmation_time=conf_times.get(priority, '30-60分'),
            estimated_cost=estimated_cost,
            network='onchain'
        )
    
    def optimize_payment_method(self, amount: int, urgent: bool = False) -> Dict[str, Any]:
        """Optimize payment method selection (compatibility method)"""
        ln_rec = self.get_lightning_fee_recommendation(amount)
        onchain_priority = 'fast' if urgent else 'medium'
        onchain_rec = self.get_onchain_fee_recommendation(onchain_priority)
        
        if ln_rec.estimated_cost < onchain_rec.estimated_cost * 0.8:
            return {
                'recommended_method': 'Lightning Network',
                'reason': 'Lower fees',
                'savings': onchain_rec.estimated_cost - ln_rec.estimated_cost
            }
        else:
            return {
                'recommended_method': 'On-chain',
                'reason': 'More reliable for large amounts',
                'savings': 0
            }


@dataclass
class FeeRecommendation:
    """Fee recommendation for backward compatibility"""
    fee_rate: int  # sat/vbyte for on-chain, ppm for lightning
    confirmation_time: str  # 'fast', 'medium', 'slow' or time estimate
    estimated_cost: int  # satoshi
    network: str  # 'lightning', 'onchain'


# Global instance
_fee_optimizer = None

def get_advanced_fee_optimizer() -> AdvancedFeeOptimizer:
    """Get global advanced fee optimizer instance"""
    global _fee_optimizer
    if _fee_optimizer is None:
        _fee_optimizer = AdvancedFeeOptimizer()
    return _fee_optimizer

# Backward compatibility alias
def get_fee_optimizer() -> AdvancedFeeOptimizer:
    """Get fee optimizer instance (backward compatibility)"""
    return get_advanced_fee_optimizer()