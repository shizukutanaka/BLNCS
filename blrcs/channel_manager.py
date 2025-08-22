# BLRCS Channel Manager
# Advanced Lightning channel management and optimization system
import asyncio
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import statistics
import math

from .lnd_connector import (
    LightningChannel, ChannelState, LNDConnector,
    create_lnd_connector
)

class ChannelStrategy(Enum):
    """Channel management strategies"""
    BALANCED = "balanced"
    INBOUND_FOCUSED = "inbound_focused"
    OUTBOUND_FOCUSED = "outbound_focused"
    HIGH_VOLUME = "high_volume"
    LOW_MAINTENANCE = "low_maintenance"
    ROUTING_FOCUSED = "routing_focused"

class RebalanceMethod(Enum):
    """Channel rebalancing methods"""
    CIRCULAR = "circular"
    SWAP = "swap"
    SPLICING = "splicing"
    LOOP_OUT = "loop_out"
    LOOP_IN = "loop_in"

class ChannelAlert(Enum):
    """Channel alert types"""
    LOW_LIQUIDITY = "low_liquidity"
    HIGH_FEES = "high_fees"
    CHANNEL_OFFLINE = "channel_offline"
    FORCE_CLOSE = "force_close"
    HIGH_UTILIZATION = "high_utilization"
    IMBALANCED = "imbalanced"
    STUCK_HTLC = "stuck_htlc"

@dataclass
class ChannelMetrics:
    """Channel performance metrics"""
    channel_id: str
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Liquidity metrics
    liquidity_ratio: float = 0.0  # local_balance / capacity
    available_inbound: int = 0
    available_outbound: int = 0
    
    # Performance metrics
    routing_volume_24h: int = 0
    routing_fees_24h: int = 0
    routing_count_24h: int = 0
    success_rate: float = 0.0
    avg_htlc_size: float = 0.0
    
    # Efficiency metrics
    capital_efficiency: float = 0.0  # volume / capacity
    fee_rate: float = 0.0  # fees / volume
    uptime_percentage: float = 0.0
    
    # Risk metrics
    counterparty_score: float = 0.0
    force_close_risk: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'channel_id': self.channel_id,
            'timestamp': self.timestamp.isoformat(),
            'liquidity_ratio': self.liquidity_ratio,
            'available_inbound': self.available_inbound,
            'available_outbound': self.available_outbound,
            'routing_volume_24h': self.routing_volume_24h,
            'routing_fees_24h': self.routing_fees_24h,
            'routing_count_24h': self.routing_count_24h,
            'success_rate': self.success_rate,
            'avg_htlc_size': self.avg_htlc_size,
            'capital_efficiency': self.capital_efficiency,
            'fee_rate': self.fee_rate,
            'uptime_percentage': self.uptime_percentage,
            'counterparty_score': self.counterparty_score,
            'force_close_risk': self.force_close_risk
        }

@dataclass
class RebalanceOperation:
    """Channel rebalancing operation"""
    operation_id: str
    source_channel_id: str
    target_channel_id: str
    amount: int
    method: RebalanceMethod
    max_fee: int
    status: str = "pending"
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    actual_fee: Optional[int] = None
    error_message: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'operation_id': self.operation_id,
            'source_channel_id': self.source_channel_id,
            'target_channel_id': self.target_channel_id,
            'amount': self.amount,
            'method': self.method.value,
            'max_fee': self.max_fee,
            'status': self.status,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'actual_fee': self.actual_fee,
            'error_message': self.error_message
        }

@dataclass
class ChannelRecommendation:
    """Channel management recommendation"""
    channel_id: str
    action: str  # open, close, rebalance, adjust_fees
    priority: str  # high, medium, low
    reason: str
    estimated_benefit: float
    estimated_cost: int
    parameters: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'channel_id': self.channel_id,
            'action': self.action,
            'priority': self.priority,
            'reason': self.reason,
            'estimated_benefit': self.estimated_benefit,
            'estimated_cost': self.estimated_cost,
            'parameters': self.parameters
        }

class ChannelAnalyzer:
    """Analyzes channel performance and health"""
    
    def __init__(self):
        self.metrics_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.performance_baselines: Dict[str, float] = {}
        
        # Analysis thresholds
        self.thresholds = {
            'low_liquidity': 0.1,      # 10% liquidity ratio
            'high_liquidity': 0.9,     # 90% liquidity ratio
            'min_success_rate': 0.95,  # 95% success rate
            'min_uptime': 0.98,        # 98% uptime
            'max_fee_rate': 0.01,      # 1% fee rate
            'min_efficiency': 0.1      # 10% capital efficiency
        }
    
    def analyze_channel(self, channel: LightningChannel, 
                       historical_data: List[Dict[str, Any]] = None) -> ChannelMetrics:
        """Analyze channel performance"""
        
        # Calculate basic metrics
        liquidity_ratio = channel.get_liquidity_ratio()
        available_inbound = channel.remote_balance
        available_outbound = channel.local_balance
        
        # Calculate performance metrics from historical data
        routing_volume_24h = 0
        routing_fees_24h = 0
        routing_count_24h = 0
        success_rate = 1.0
        avg_htlc_size = 0.0
        
        if historical_data:
            # Analyze routing data
            recent_data = [d for d in historical_data 
                          if d.get('timestamp', 0) > time.time() - 86400]  # 24h
            
            routing_volume_24h = sum(d.get('amount', 0) for d in recent_data)
            routing_fees_24h = sum(d.get('fee', 0) for d in recent_data)
            routing_count_24h = len(recent_data)
            
            if recent_data:
                success_count = sum(1 for d in recent_data if d.get('success', True))
                success_rate = success_count / len(recent_data)
                avg_htlc_size = routing_volume_24h / routing_count_24h
        
        # Calculate efficiency metrics
        capital_efficiency = 0.0
        if channel.capacity > 0:
            capital_efficiency = routing_volume_24h / channel.capacity
        
        fee_rate = 0.0
        if routing_volume_24h > 0:
            fee_rate = routing_fees_24h / routing_volume_24h
        
        # Calculate uptime (simplified)
        uptime_percentage = 0.99 if channel.active else 0.0
        
        # Calculate counterparty score (simplified)
        counterparty_score = self._calculate_counterparty_score(channel)
        
        # Calculate force close risk
        force_close_risk = self._calculate_force_close_risk(channel)
        
        metrics = ChannelMetrics(
            channel_id=channel.channel_id,
            liquidity_ratio=liquidity_ratio,
            available_inbound=available_inbound,
            available_outbound=available_outbound,
            routing_volume_24h=routing_volume_24h,
            routing_fees_24h=routing_fees_24h,
            routing_count_24h=routing_count_24h,
            success_rate=success_rate,
            avg_htlc_size=avg_htlc_size,
            capital_efficiency=capital_efficiency,
            fee_rate=fee_rate,
            uptime_percentage=uptime_percentage,
            counterparty_score=counterparty_score,
            force_close_risk=force_close_risk
        )
        
        # Store metrics in history
        self.metrics_history[channel.channel_id].append(metrics)
        
        return metrics
    
    def _calculate_counterparty_score(self, channel: LightningChannel) -> float:
        """Calculate counterparty reliability score"""
        # Simplified scoring based on channel characteristics
        score = 0.5  # Base score
        
        # Large capacity indicates serious node
        if channel.capacity > 10_000_000:  # > 10M sats
            score += 0.2
        elif channel.capacity > 1_000_000:  # > 1M sats
            score += 0.1
        
        # Active channel is good
        if channel.active:
            score += 0.2
        
        # High utilization indicates good routing node
        utilization = channel.get_utilization()
        if utilization > 0.5:
            score += 0.1
        
        return min(score, 1.0)
    
    def _calculate_force_close_risk(self, channel: LightningChannel) -> float:
        """Calculate risk of force closure"""
        risk = 0.0
        
        # Inactive channel has higher risk
        if not channel.active:
            risk += 0.3
        
        # Very imbalanced channels have higher risk
        liquidity_ratio = channel.get_liquidity_ratio()
        if liquidity_ratio < 0.05 or liquidity_ratio > 0.95:
            risk += 0.2
        
        # High unsettled balance indicates stuck HTLCs
        if channel.unsettled_balance > channel.capacity * 0.1:
            risk += 0.3
        
        # Old channels with low activity might be abandoned
        if channel.num_updates < 10:  # Very few updates
            risk += 0.2
        
        return min(risk, 1.0)
    
    def detect_anomalies(self, channel_id: str, current_metrics: ChannelMetrics) -> List[str]:
        """Detect anomalies in channel performance"""
        anomalies = []
        history = list(self.metrics_history[channel_id])
        
        if len(history) < 10:  # Need enough data
            return anomalies
        
        # Get baseline metrics
        recent_history = history[-10:]
        
        # Check liquidity anomalies
        avg_liquidity = statistics.mean(m.liquidity_ratio for m in recent_history[:-1])
        if abs(current_metrics.liquidity_ratio - avg_liquidity) > 0.3:
            anomalies.append("Significant liquidity change detected")
        
        # Check success rate anomalies
        avg_success_rate = statistics.mean(m.success_rate for m in recent_history[:-1])
        if current_metrics.success_rate < avg_success_rate - 0.1:
            anomalies.append("Success rate degradation detected")
        
        # Check fee rate anomalies
        if len([m for m in recent_history[:-1] if m.fee_rate > 0]) > 0:
            avg_fee_rate = statistics.mean(m.fee_rate for m in recent_history[:-1] if m.fee_rate > 0)
            if current_metrics.fee_rate > avg_fee_rate * 2:
                anomalies.append("Fee rate spike detected")
        
        return anomalies
    
    def get_channel_score(self, metrics: ChannelMetrics) -> float:
        """Calculate overall channel performance score"""
        score = 0.0
        
        # Liquidity score (balanced is better)
        liquidity_score = 1.0 - abs(metrics.liquidity_ratio - 0.5) * 2
        score += liquidity_score * 0.2
        
        # Success rate score
        score += metrics.success_rate * 0.25
        
        # Capital efficiency score
        efficiency_score = min(metrics.capital_efficiency / 1.0, 1.0)  # Cap at 100%
        score += efficiency_score * 0.25
        
        # Uptime score
        score += metrics.uptime_percentage * 0.15
        
        # Counterparty score
        score += metrics.counterparty_score * 0.1
        
        # Risk penalty
        score -= metrics.force_close_risk * 0.05
        
        return max(0.0, min(score, 1.0))

class RebalanceEngine:
    """Handles channel rebalancing operations"""
    
    def __init__(self, lnd_connector: LNDConnector):
        self.lnd_connector = lnd_connector
        self.active_operations: Dict[str, RebalanceOperation] = {}
        self.operation_history: deque = deque(maxlen=1000)
        
        # Rebalancing parameters
        self.max_fee_rate = 0.005  # 0.5% max fee rate
        self.target_liquidity = 0.5  # 50% target liquidity ratio
        self.liquidity_tolerance = 0.1  # 10% tolerance
        self.min_rebalance_amount = 100_000  # 100k sats minimum
    
    async def suggest_rebalance(self, channels: List[LightningChannel]) -> List[RebalanceOperation]:
        """Suggest rebalancing operations"""
        suggestions = []
        
        # Find imbalanced channels
        low_liquidity_channels = []
        high_liquidity_channels = []
        
        for channel in channels:
            if not channel.active:
                continue
            
            liquidity_ratio = channel.get_liquidity_ratio()
            
            if liquidity_ratio < self.target_liquidity - self.liquidity_tolerance:
                low_liquidity_channels.append((channel, liquidity_ratio))
            elif liquidity_ratio > self.target_liquidity + self.liquidity_tolerance:
                high_liquidity_channels.append((channel, liquidity_ratio))
        
        # Sort by imbalance severity
        low_liquidity_channels.sort(key=lambda x: x[1])  # Most depleted first
        high_liquidity_channels.sort(key=lambda x: x[1], reverse=True)  # Most excess first
        
        # Create rebalancing pairs
        for low_channel, low_ratio in low_liquidity_channels:
            for high_channel, high_ratio in high_liquidity_channels:
                if low_channel.channel_id == high_channel.channel_id:
                    continue
                
                # Calculate optimal rebalance amount
                amount = self._calculate_rebalance_amount(low_channel, high_channel)
                
                if amount >= self.min_rebalance_amount:
                    max_fee = int(amount * self.max_fee_rate)
                    
                    operation = RebalanceOperation(
                        operation_id=f"rebal_{int(time.time())}_{len(suggestions)}",
                        source_channel_id=high_channel.channel_id,
                        target_channel_id=low_channel.channel_id,
                        amount=amount,
                        method=RebalanceMethod.CIRCULAR,
                        max_fee=max_fee
                    )
                    
                    suggestions.append(operation)
        
        return suggestions
    
    def _calculate_rebalance_amount(self, low_channel: LightningChannel, 
                                  high_channel: LightningChannel) -> int:
        """Calculate optimal rebalance amount"""
        # Calculate how much each channel needs to reach target
        low_target = int(low_channel.capacity * self.target_liquidity)
        low_needed = low_target - low_channel.local_balance
        
        high_target = int(high_channel.capacity * self.target_liquidity)
        high_excess = high_channel.local_balance - high_target
        
        # Use the minimum of what's needed and what's available
        amount = min(low_needed, high_excess)
        
        # Ensure we don't drain channels completely
        max_from_high = high_channel.local_balance - high_channel.commit_fee - 50_000  # Keep 50k buffer
        amount = min(amount, max_from_high)
        
        return max(0, amount)
    
    async def execute_rebalance(self, operation: RebalanceOperation) -> bool:
        """Execute rebalancing operation"""
        try:
            self.active_operations[operation.operation_id] = operation
            operation.status = "executing"
            
            # Execute based on method
            if operation.method == RebalanceMethod.CIRCULAR:
                success = await self._execute_circular_rebalance(operation)
            else:
                # Other methods would be implemented here
                success = False
                operation.error_message = f"Method {operation.method.value} not implemented"
            
            # Update operation status
            operation.completed_at = datetime.now()
            operation.status = "completed" if success else "failed"
            
            # Move to history
            self.operation_history.append(operation)
            del self.active_operations[operation.operation_id]
            
            return success
            
        except Exception as e:
            operation.status = "failed"
            operation.error_message = str(e)
            operation.completed_at = datetime.now()
            return False
    
    async def _execute_circular_rebalance(self, operation: RebalanceOperation) -> bool:
        """Execute circular rebalancing"""
        try:
            # This would implement actual circular rebalancing logic
            # For now, we'll simulate the operation
            
            print(f"Executing circular rebalance: {operation.amount} sats "
                  f"from {operation.source_channel_id} to {operation.target_channel_id}")
            
            # Simulate processing time
            await asyncio.sleep(2)
            
            # Simulate fee calculation
            operation.actual_fee = int(operation.amount * 0.001)  # 0.1% fee
            
            # Check if fee is acceptable
            if operation.actual_fee <= operation.max_fee:
                return True
            else:
                operation.error_message = f"Fee too high: {operation.actual_fee} > {operation.max_fee}"
                return False
                
        except Exception as e:
            operation.error_message = str(e)
            return False
    
    def get_rebalance_stats(self) -> Dict[str, Any]:
        """Get rebalancing statistics"""
        total_operations = len(self.operation_history)
        successful_operations = len([op for op in self.operation_history if op.status == "completed"])
        
        total_amount = sum(op.amount for op in self.operation_history if op.status == "completed")
        total_fees = sum(op.actual_fee or 0 for op in self.operation_history if op.status == "completed")
        
        return {
            'total_operations': total_operations,
            'successful_operations': successful_operations,
            'success_rate': successful_operations / max(1, total_operations),
            'total_amount_rebalanced': total_amount,
            'total_fees_paid': total_fees,
            'avg_fee_rate': total_fees / max(1, total_amount),
            'active_operations': len(self.active_operations)
        }

class ChannelManager:
    """Main channel management system"""
    
    def __init__(self, lnd_connector: LNDConnector = None, config: Dict[str, Any] = None):
        self.config = config or {}
        self.lnd_connector = lnd_connector or create_lnd_connector(self.config.get('lnd', {}))
        
        # Core components
        self.analyzer = ChannelAnalyzer()
        self.rebalance_engine = RebalanceEngine(self.lnd_connector)
        
        # Management state
        self.strategy = ChannelStrategy(self.config.get('strategy', 'balanced'))
        self.auto_rebalance = self.config.get('auto_rebalance', False)
        self.auto_fee_adjustment = self.config.get('auto_fee_adjustment', False)
        
        # Monitoring
        self.monitoring = False
        self.monitor_task: Optional[asyncio.Task] = None
        self.monitor_interval = self.config.get('monitor_interval', 300)  # 5 minutes
        
        # Alerts and recommendations
        self.alerts: deque = deque(maxlen=1000)
        self.recommendations: List[ChannelRecommendation] = []
        
        # Event handlers
        self.event_handlers: Dict[str, List[Callable]] = defaultdict(list)
        
        # Performance tracking
        self.performance_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.last_analysis = time.time()
    
    async def start(self) -> bool:
        """Start channel manager"""
        # Start LND connector if not already started
        if not self.lnd_connector.connection.connected:
            if not await self.lnd_connector.start():
                return False
        
        # Register for LND events
        self.lnd_connector.add_event_handler('channel_opened', self._handle_channel_opened)
        self.lnd_connector.add_event_handler('channel_closed', self._handle_channel_closed)
        self.lnd_connector.add_event_handler('channel_balance_changed', self._handle_balance_changed)
        
        # Start monitoring
        self.monitoring = True
        self.monitor_task = asyncio.create_task(self._monitor_loop())
        
        print("Channel manager started")
        return True
    
    async def stop(self):
        """Stop channel manager"""
        self.monitoring = False
        
        if self.monitor_task:
            self.monitor_task.cancel()
            try:
                await self.monitor_task
            except asyncio.CancelledError:
                pass
    
    async def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                # Analyze all channels
                await self._analyze_channels()
                
                # Generate recommendations
                await self._generate_recommendations()
                
                # Execute auto-actions if enabled
                if self.auto_rebalance:
                    await self._auto_rebalance()
                
                if self.auto_fee_adjustment:
                    await self._auto_adjust_fees()
                
                # Check for alerts
                await self._check_alerts()
                
                await asyncio.sleep(self.monitor_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"🔍 チャネル監視中にエラーが発生しました: {e}")
                await asyncio.sleep(self.monitor_interval)
    
    async def _analyze_channels(self):
        """Analyze all channels"""
        channels = await self.lnd_connector.get_channels()
        
        for channel in channels:
            # Get historical data (would come from database in real implementation)
            historical_data = []
            
            # Analyze channel
            metrics = self.analyzer.analyze_channel(channel, historical_data)
            
            # Store performance data
            self.performance_history[channel.channel_id].append({
                'timestamp': time.time(),
                'metrics': metrics,
                'score': self.analyzer.get_channel_score(metrics)
            })
            
            # Check for anomalies
            anomalies = self.analyzer.detect_anomalies(channel.channel_id, metrics)
            for anomaly in anomalies:
                await self._emit_alert(ChannelAlert.HIGH_UTILIZATION, channel.channel_id, anomaly)
        
        self.last_analysis = time.time()
    
    async def _generate_recommendations(self):
        """Generate channel management recommendations"""
        self.recommendations.clear()
        channels = await self.lnd_connector.get_channels()
        
        for channel in channels:
            metrics_history = list(self.performance_history[channel.channel_id])
            if not metrics_history:
                continue
            
            latest_metrics = metrics_history[-1]['metrics']
            channel_score = metrics_history[-1]['score']
            
            # Low liquidity recommendation
            if latest_metrics.liquidity_ratio < 0.2:
                self.recommendations.append(ChannelRecommendation(
                    channel_id=channel.channel_id,
                    action="rebalance",
                    priority="high",
                    reason="Low outbound liquidity",
                    estimated_benefit=0.3,
                    estimated_cost=10000,
                    parameters={'target_ratio': 0.5, 'amount': channel.capacity // 4}
                ))
            
            # High liquidity recommendation
            elif latest_metrics.liquidity_ratio > 0.8:
                self.recommendations.append(ChannelRecommendation(
                    channel_id=channel.channel_id,
                    action="rebalance",
                    priority="medium",
                    reason="Low inbound liquidity",
                    estimated_benefit=0.2,
                    estimated_cost=5000,
                    parameters={'target_ratio': 0.5, 'amount': channel.capacity // 4}
                ))
            
            # Poor performance recommendation
            if channel_score < 0.3:
                self.recommendations.append(ChannelRecommendation(
                    channel_id=channel.channel_id,
                    action="close",
                    priority="low",
                    reason="Poor channel performance",
                    estimated_benefit=0.1,
                    estimated_cost=channel.commit_fee,
                    parameters={'force': False}
                ))
            
            # Fee adjustment recommendation
            if latest_metrics.fee_rate > 0.01:  # > 1%
                self.recommendations.append(ChannelRecommendation(
                    channel_id=channel.channel_id,
                    action="adjust_fees",
                    priority="medium",
                    reason="High fee rate may reduce volume",
                    estimated_benefit=0.15,
                    estimated_cost=0,
                    parameters={'new_fee_rate': 0.005}
                ))
    
    async def _auto_rebalance(self):
        """Perform automatic rebalancing"""
        try:
            channels = await self.lnd_connector.get_channels(active_only=True)
            suggestions = await self.rebalance_engine.suggest_rebalance(channels)
            
            # Execute high-priority rebalances
            for suggestion in suggestions[:3]:  # Limit to 3 operations
                if suggestion.amount > 500_000:  # Only large imbalances
                    await self.rebalance_engine.execute_rebalance(suggestion)
                    await asyncio.sleep(10)  # Wait between operations
                    
        except Exception as e:
            print(f"Auto-rebalance error: {e}")
    
    async def _auto_adjust_fees(self):
        """Automatically adjust channel fees"""
        try:
            channels = await self.lnd_connector.get_channels(active_only=True)
            
            for channel in channels:
                metrics_history = list(self.performance_history[channel.channel_id])
                if not metrics_history:
                    continue
                
                latest_metrics = metrics_history[-1]['metrics']
                
                # Adjust fees based on liquidity and utilization
                optimal_fee_rate = self._calculate_optimal_fee_rate(latest_metrics)
                
                # Update fees if significantly different
                if abs(latest_metrics.fee_rate - optimal_fee_rate) > 0.001:  # 0.1% difference
                    await self._update_channel_fees(channel.channel_id, optimal_fee_rate)
                    
        except Exception as e:
            print(f"Auto-fee adjustment error: {e}")
    
    def _calculate_optimal_fee_rate(self, metrics: ChannelMetrics) -> float:
        """Calculate optimal fee rate for channel"""
        base_fee_rate = 0.001  # 0.1% base rate
        
        # Increase fees for low liquidity (encourage inbound)
        if metrics.liquidity_ratio < 0.3:
            base_fee_rate *= (1.0 + (0.3 - metrics.liquidity_ratio) * 2)
        
        # Decrease fees for high liquidity (encourage outbound)
        elif metrics.liquidity_ratio > 0.7:
            base_fee_rate *= (1.0 - (metrics.liquidity_ratio - 0.7) * 0.5)
        
        # Adjust based on success rate
        if metrics.success_rate < 0.9:
            base_fee_rate *= 0.8  # Lower fees to improve success rate
        
        # Cap fees
        return min(max(base_fee_rate, 0.0001), 0.01)  # 0.01% to 1%
    
    async def _update_channel_fees(self, channel_id: str, fee_rate: float):
        """Update channel fee policy"""
        # This would call LND's UpdateChannelPolicy RPC
        print(f"Updating fees for channel {channel_id}: {fee_rate:.4f}")
    
    async def _check_alerts(self):
        """Check for channel alerts"""
        channels = await self.lnd_connector.get_channels()
        
        for channel in channels:
            metrics_history = list(self.performance_history[channel.channel_id])
            if not metrics_history:
                continue
            
            latest_metrics = metrics_history[-1]['metrics']
            
            # Low liquidity alert
            if latest_metrics.liquidity_ratio < 0.1:
                await self._emit_alert(ChannelAlert.LOW_LIQUIDITY, channel.channel_id,
                                     f"Channel liquidity at {latest_metrics.liquidity_ratio:.1%}")
            
            # High force close risk alert
            if latest_metrics.force_close_risk > 0.7:
                await self._emit_alert(ChannelAlert.FORCE_CLOSE, channel.channel_id,
                                     f"High force close risk: {latest_metrics.force_close_risk:.1%}")
            
            # Channel offline alert
            if not channel.active:
                await self._emit_alert(ChannelAlert.CHANNEL_OFFLINE, channel.channel_id,
                                     "Channel is offline")
            
            # High utilization alert
            utilization = channel.get_utilization()
            if utilization > 2.0:  # More than 2x capacity in volume
                await self._emit_alert(ChannelAlert.HIGH_UTILIZATION, channel.channel_id,
                                     f"High utilization: {utilization:.1f}x capacity")
    
    async def _emit_alert(self, alert_type: ChannelAlert, channel_id: str, message: str):
        """Emit channel alert"""
        alert = {
            'timestamp': datetime.now(),
            'type': alert_type.value,
            'channel_id': channel_id,
            'message': message
        }
        
        self.alerts.append(alert)
        
        # Notify event handlers
        for handler in self.event_handlers['alert']:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(alert)
                else:
                    handler(alert)
            except Exception as e:
                print(f"Alert handler error: {e}")
    
    # Event handlers
    async def _handle_channel_opened(self, event_type: str, data: Any):
        """Handle channel opened event"""
        channel = data
        print(f"New channel opened: {channel.channel_id}")
        await self._emit_alert(ChannelAlert.HIGH_UTILIZATION, channel.channel_id, "New channel opened")
    
    async def _handle_channel_closed(self, event_type: str, data: Any):
        """Handle channel closed event"""
        channel = data
        print(f"Channel closed: {channel.channel_id}")
        
        # Clean up historical data
        if channel.channel_id in self.performance_history:
            del self.performance_history[channel.channel_id]
    
    async def _handle_balance_changed(self, event_type: str, data: Any):
        """Handle channel balance change"""
        channel = data['channel']
        old_balance = data['old_balance']
        new_balance = data['new_balance']
        
        print(f"Balance changed in {channel.channel_id}: {old_balance} -> {new_balance}")
    
    # Public API methods
    def add_event_handler(self, event_type: str, handler: Callable):
        """Add event handler"""
        self.event_handlers[event_type].append(handler)
    
    async def get_channel_recommendations(self, channel_id: str = None) -> List[ChannelRecommendation]:
        """Get channel recommendations"""
        if channel_id:
            return [r for r in self.recommendations if r.channel_id == channel_id]
        return self.recommendations.copy()
    
    async def get_channel_metrics(self, channel_id: str) -> Optional[ChannelMetrics]:
        """Get latest channel metrics"""
        history = self.performance_history.get(channel_id, [])
        if history:
            return history[-1]['metrics']
        return None
    
    async def get_rebalance_suggestions(self) -> List[RebalanceOperation]:
        """Get rebalancing suggestions"""
        channels = await self.lnd_connector.get_channels(active_only=True)
        return await self.rebalance_engine.suggest_rebalance(channels)
    
    async def execute_recommendation(self, recommendation: ChannelRecommendation) -> bool:
        """Execute channel recommendation"""
        try:
            if recommendation.action == "rebalance":
                # Create and execute rebalance operation
                channels = await self.lnd_connector.get_channels()
                target_channel = next((c for c in channels if c.channel_id == recommendation.channel_id), None)
                
                if not target_channel:
                    return False
                
                # Find source channel (simplified)
                source_channels = [c for c in channels 
                                 if c.channel_id != recommendation.channel_id and c.get_liquidity_ratio() > 0.6]
                
                if not source_channels:
                    return False
                
                operation = RebalanceOperation(
                    operation_id=f"rec_{int(time.time())}",
                    source_channel_id=source_channels[0].channel_id,
                    target_channel_id=recommendation.channel_id,
                    amount=recommendation.parameters.get('amount', 100000),
                    method=RebalanceMethod.CIRCULAR,
                    max_fee=recommendation.estimated_cost
                )
                
                return await self.rebalance_engine.execute_rebalance(operation)
            
            elif recommendation.action == "close":
                return await self.lnd_connector.close_channel(
                    recommendation.channel_id,
                    recommendation.parameters.get('force', False)
                )
            
            elif recommendation.action == "adjust_fees":
                fee_rate = recommendation.parameters.get('new_fee_rate', 0.001)
                await self._update_channel_fees(recommendation.channel_id, fee_rate)
                return True
            
            return False
            
        except Exception as e:
            print(f"Failed to execute recommendation: {e}")
            return False
    
    def get_manager_stats(self) -> Dict[str, Any]:
        """Get channel manager statistics"""
        channels_analyzed = len(self.performance_history)
        total_alerts = len(self.alerts)
        pending_recommendations = len(self.recommendations)
        
        rebalance_stats = self.rebalance_engine.get_rebalance_stats()
        
        return {
            'channels_analyzed': channels_analyzed,
            'total_alerts': total_alerts,
            'pending_recommendations': pending_recommendations,
            'last_analysis': self.last_analysis,
            'strategy': self.strategy.value,
            'auto_rebalance': self.auto_rebalance,
            'auto_fee_adjustment': self.auto_fee_adjustment,
            'rebalancing': rebalance_stats
        }

# Factory function
def create_channel_manager(lnd_connector: LNDConnector = None, 
                          config: Dict[str, Any] = None) -> ChannelManager:
    """Create channel manager instance"""
    return ChannelManager(lnd_connector, config)

# Export main classes
__all__ = [
    'ChannelStrategy', 'RebalanceMethod', 'ChannelAlert',
    'ChannelMetrics', 'RebalanceOperation', 'ChannelRecommendation',
    'ChannelAnalyzer', 'RebalanceEngine', 'ChannelManager',
    'create_channel_manager'
]