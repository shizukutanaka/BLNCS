"""
Automated Channel Rebalancing System
Implements intelligent channel rebalancing to maintain optimal liquidity distribution.
"""

import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, NamedTuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum
import statistics

from .logger import get_logger
from .config_manager import get_config_manager
from .database import get_database_manager
from .metrics import get_metrics_collector, increment_counter, set_gauge, observe_histogram


class RebalanceStrategy(Enum):
    """Rebalancing strategies"""
    CONSERVATIVE = "conservative"  # Small, safe rebalances
    BALANCED = "balanced"         # Moderate rebalancing
    AGGRESSIVE = "aggressive"     # Large rebalances for maximum efficiency


class RebalanceMethod(Enum):
    """Methods for rebalancing"""
    CIRCULAR = "circular"         # Circular rebalancing
    DIRECT = "direct"            # Direct channel-to-channel
    LOOP_OUT = "loop_out"        # Loop out to on-chain
    SUBMARINE_SWAP = "submarine_swap"  # Submarine swap


@dataclass
class RebalanceTarget:
    """Target configuration for a channel"""
    channel_id: str
    target_local_ratio: float  # 0.0 to 1.0
    min_local_ratio: float     # Minimum acceptable ratio
    max_local_ratio: float     # Maximum acceptable ratio
    priority: int = 5          # 1 (high) to 10 (low)
    enabled: bool = True


@dataclass
class RebalanceOperation:
    """A rebalancing operation"""
    operation_id: str
    source_channel: str
    target_channel: str
    amount_sats: int
    method: RebalanceMethod
    estimated_cost: int
    estimated_duration: int  # seconds
    priority: int
    created_at: datetime
    status: str = "pending"  # pending, in_progress, completed, failed


class ChannelRebalancer:
    """Manages automated channel rebalancing"""
    
    def __init__(self, lightning_client=None):
        self.logger = get_logger(__name__)
        self.config = get_config_manager()
        self.db = get_database_manager()
        self.lightning_client = lightning_client
        
        # Metrics
        self.metrics = get_metrics_collector()
        
        # State management
        self.is_running = False
        self.rebalance_thread = None
        self._stop_event = threading.Event()
        
        # Rebalancing state
        self.pending_operations: deque = deque()
        self.active_operations: Dict[str, RebalanceOperation] = {}
        self.operation_history: deque = deque(maxlen=500)
        
        # Configuration
        self.check_interval = self.config.get('rebalancer.check_interval_minutes', 15) * 60
        self.strategy = RebalanceStrategy(self.config.get('rebalancer.strategy', 'balanced'))
        self.max_concurrent_operations = self.config.get('rebalancer.max_concurrent_operations', 2)
        self.min_rebalance_amount = self.config.get('rebalancer.min_rebalance_amount_sats', 100000)
        self.max_rebalance_amount = self.config.get('rebalancer.max_rebalance_amount_sats', 5000000)
        
        # Channel targets
        self.channel_targets: Dict[str, RebalanceTarget] = {}
        self._load_channel_targets()
        
        # Performance tracking
        self.rebalance_stats = {
            'total_operations': 0,
            'successful_operations': 0,
            'failed_operations': 0,
            'total_volume_sats': 0,
            'total_fees_paid': 0,
            'last_operation_time': None
        }
        
        self.logger.info(f"Channel rebalancer initialized with {self.strategy.value} strategy")
    
    def _load_channel_targets(self):
        """Load channel rebalancing targets from configuration"""
        targets_config = self.config.get('rebalancer.targets', {})
        
        # Default targets based on strategy
        default_targets = {
            RebalanceStrategy.CONSERVATIVE: {'target': 0.5, 'min': 0.3, 'max': 0.7},
            RebalanceStrategy.BALANCED: {'target': 0.5, 'min': 0.2, 'max': 0.8},
            RebalanceStrategy.AGGRESSIVE: {'target': 0.5, 'min': 0.1, 'max': 0.9}
        }
        
        strategy_defaults = default_targets.get(self.strategy, default_targets[RebalanceStrategy.BALANCED])
        
        # Apply targets from config or use defaults
        for channel_id, target_config in targets_config.items():
            self.channel_targets[channel_id] = RebalanceTarget(
                channel_id=channel_id,
                target_local_ratio=target_config.get('target', strategy_defaults['target']),
                min_local_ratio=target_config.get('min', strategy_defaults['min']),
                max_local_ratio=target_config.get('max', strategy_defaults['max']),
                priority=target_config.get('priority', 5),
                enabled=target_config.get('enabled', True)
            )
    
    def start_rebalancing(self) -> bool:
        """Start automated channel rebalancing"""
        if self.is_running:
            self.logger.warning("Channel rebalancing is already running")
            return False
        
        if not self.lightning_client:
            self.logger.error("Cannot start rebalancing without Lightning client")
            return False
        
        self.is_running = True
        self._stop_event.clear()
        
        self.rebalance_thread = threading.Thread(
            target=self._rebalancing_loop,
            name="ChannelRebalancingThread",
            daemon=True
        )
        self.rebalance_thread.start()
        
        self.logger.info("Automated channel rebalancing started")
        increment_counter('rebalancer_starts_total')
        return True
    
    def stop_rebalancing(self) -> bool:
        """Stop automated channel rebalancing"""
        if not self.is_running:
            return False
        
        self.is_running = False
        self._stop_event.set()
        
        if self.rebalance_thread and self.rebalance_thread.is_alive():
            self.rebalance_thread.join(timeout=10)
        
        self.logger.info("Automated channel rebalancing stopped")
        increment_counter('rebalancer_stops_total')
        return True
    
    def _rebalancing_loop(self):
        """Main rebalancing loop"""
        self.logger.info(f"Rebalancing loop started (check interval: {self.check_interval}s)")
        
        while not self._stop_event.wait(self.check_interval):
            try:
                start_time = time.time()
                
                # Update active operations status
                self._update_active_operations()
                
                # Analyze channel states
                channel_analysis = self._analyze_channels()
                
                if not channel_analysis:
                    self.logger.debug("No channel data available, skipping rebalancing cycle")
                    continue
                
                # Identify rebalancing opportunities
                opportunities = self._identify_rebalancing_opportunities(channel_analysis)
                
                # Plan rebalancing operations
                operations = self._plan_rebalancing_operations(opportunities)
                
                # Execute new operations (if not at max capacity)
                operations_started = self._execute_rebalancing_operations(operations)
                
                # Update metrics
                duration = time.time() - start_time
                observe_histogram('rebalancer_check_duration_seconds', duration)
                set_gauge('rebalancer_active_operations', len(self.active_operations))
                set_gauge('rebalancer_pending_operations', len(self.pending_operations))
                
                if operations_started > 0:
                    self.logger.info(f"Rebalancing cycle completed: {operations_started} new operations started")
                    increment_counter('rebalancer_cycles_with_operations_total')
                else:
                    increment_counter('rebalancer_cycles_no_operations_total')
                
            except Exception as e:
                self.logger.error(f"Rebalancing loop error: {e}")
                increment_counter('rebalancer_errors_total')
        
        self.logger.info("Rebalancing loop stopped")
    
    def _analyze_channels(self) -> Optional[Dict[str, Any]]:
        """Analyze current channel states"""
        try:
            if not self.lightning_client:
                return None
            
            self.lightning_client.connect()
            channels = self.lightning_client.list_channels()
            self.lightning_client.disconnect()
            
            channel_analysis = {}
            
            for channel in channels:
                channel_id = channel.get('channel_id', '')
                if not channel_id or not channel.get('active', False):
                    continue
                
                capacity = channel.get('capacity', 0)
                local_balance = channel.get('local_balance', 0)
                remote_balance = channel.get('remote_balance', 0)
                
                if capacity == 0:
                    continue
                
                local_ratio = local_balance / capacity
                remote_ratio = remote_balance / capacity
                
                # Get target configuration
                target = self.channel_targets.get(channel_id)
                if not target:
                    # Create default target
                    target = RebalanceTarget(
                        channel_id=channel_id,
                        target_local_ratio=0.5,
                        min_local_ratio=0.2,
                        max_local_ratio=0.8,
                        priority=5,
                        enabled=True
                    )
                    self.channel_targets[channel_id] = target
                
                # Calculate rebalancing need
                deviation = abs(local_ratio - target.target_local_ratio)
                needs_rebalancing = (
                    local_ratio < target.min_local_ratio or 
                    local_ratio > target.max_local_ratio
                )
                
                channel_analysis[channel_id] = {
                    'capacity': capacity,
                    'local_balance': local_balance,
                    'remote_balance': remote_balance,
                    'local_ratio': local_ratio,
                    'remote_ratio': remote_ratio,
                    'target': target,
                    'deviation': deviation,
                    'needs_rebalancing': needs_rebalancing,
                    'peer_alias': channel.get('peer_alias', 'Unknown'),
                    'channel_data': channel
                }
            
            return channel_analysis
            
        except Exception as e:
            self.logger.error(f"Failed to analyze channels: {e}")
            try:
                self.lightning_client.disconnect()
            except:
                pass
            return None
    
    def _identify_rebalancing_opportunities(self, channel_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify channels that need rebalancing"""
        opportunities = []
        
        # Find channels that need liquidity (low outbound) and channels that can provide liquidity (high outbound)
        needs_inbound = []  # Channels with too much outbound liquidity
        needs_outbound = []  # Channels with too little outbound liquidity
        
        for channel_id, analysis in channel_analysis.items():
            target = analysis['target']
            
            if not target.enabled or not analysis['needs_rebalancing']:
                continue
            
            local_ratio = analysis['local_ratio']
            
            if local_ratio > target.max_local_ratio:
                # Channel has too much outbound liquidity
                excess_amount = int((local_ratio - target.target_local_ratio) * analysis['capacity'])
                if excess_amount >= self.min_rebalance_amount:
                    needs_inbound.append({
                        'channel_id': channel_id,
                        'excess_amount': excess_amount,
                        'priority': target.priority,
                        'analysis': analysis
                    })
            
            elif local_ratio < target.min_local_ratio:
                # Channel needs more outbound liquidity
                needed_amount = int((target.target_local_ratio - local_ratio) * analysis['capacity'])
                if needed_amount >= self.min_rebalance_amount:
                    needs_outbound.append({
                        'channel_id': channel_id,
                        'needed_amount': needed_amount,
                        'priority': target.priority,
                        'analysis': analysis
                    })
        
        # Match channels that can provide liquidity with channels that need it
        # Sort by priority (lower number = higher priority)
        needs_inbound.sort(key=lambda x: x['priority'])
        needs_outbound.sort(key=lambda x: x['priority'])
        
        for need_out in needs_outbound:
            for need_in in needs_inbound:
                if need_out['channel_id'] == need_in['channel_id']:
                    continue  # Same channel
                
                # Calculate optimal transfer amount
                transfer_amount = min(
                    need_out['needed_amount'],
                    need_in['excess_amount'],
                    self.max_rebalance_amount
                )
                
                if transfer_amount >= self.min_rebalance_amount:
                    opportunities.append({
                        'source_channel': need_in['channel_id'],
                        'target_channel': need_out['channel_id'],
                        'amount': transfer_amount,
                        'priority': min(need_in['priority'], need_out['priority']),
                        'source_analysis': need_in['analysis'],
                        'target_analysis': need_out['analysis']
                    })
        
        # Sort opportunities by priority
        opportunities.sort(key=lambda x: x['priority'])
        
        return opportunities
    
    def _plan_rebalancing_operations(self, opportunities: List[Dict[str, Any]]) -> List[RebalanceOperation]:
        """Plan rebalancing operations from opportunities"""
        operations = []
        
        for i, opp in enumerate(opportunities):
            # Determine best rebalancing method
            method = self._select_rebalancing_method(opp)
            
            # Estimate costs and duration
            estimated_cost = self._estimate_rebalancing_cost(opp, method)
            estimated_duration = self._estimate_rebalancing_duration(opp, method)
            
            # Create operation
            operation = RebalanceOperation(
                operation_id=f"rebalance_{int(time.time())}_{i}",
                source_channel=opp['source_channel'],
                target_channel=opp['target_channel'],
                amount_sats=opp['amount'],
                method=method,
                estimated_cost=estimated_cost,
                estimated_duration=estimated_duration,
                priority=opp['priority'],
                created_at=datetime.now()
            )
            
            operations.append(operation)
        
        return operations
    
    def _select_rebalancing_method(self, opportunity: Dict[str, Any]) -> RebalanceMethod:
        """Select the best rebalancing method for an opportunity"""
        amount = opportunity['amount']
        
        # For now, use circular rebalancing as the primary method
        # In a real implementation, you would consider:
        # - Available routes and their costs
        # - Channel policies and fees
        # - Network topology
        # - Amount size and urgency
        
        if amount < 500000:  # Small amounts
            return RebalanceMethod.CIRCULAR
        elif amount < 2000000:  # Medium amounts
            return RebalanceMethod.CIRCULAR
        else:  # Large amounts
            return RebalanceMethod.LOOP_OUT
    
    def _estimate_rebalancing_cost(self, opportunity: Dict[str, Any], method: RebalanceMethod) -> int:
        """Estimate the cost of a rebalancing operation"""
        amount = opportunity['amount']
        
        # Rough cost estimates (in satoshis)
        cost_estimates = {
            RebalanceMethod.CIRCULAR: max(100, int(amount * 0.001)),  # 0.1% + 100 sats base
            RebalanceMethod.DIRECT: max(50, int(amount * 0.0005)),    # 0.05% + 50 sats base
            RebalanceMethod.LOOP_OUT: max(1000, int(amount * 0.002)), # 0.2% + 1000 sats base
            RebalanceMethod.SUBMARINE_SWAP: max(500, int(amount * 0.0015))  # 0.15% + 500 sats base
        }
        
        return cost_estimates.get(method, int(amount * 0.001))
    
    def _estimate_rebalancing_duration(self, opportunity: Dict[str, Any], method: RebalanceMethod) -> int:
        """Estimate the duration of a rebalancing operation in seconds"""
        duration_estimates = {
            RebalanceMethod.CIRCULAR: 300,      # 5 minutes
            RebalanceMethod.DIRECT: 180,        # 3 minutes
            RebalanceMethod.LOOP_OUT: 3600,     # 1 hour (including confirmations)
            RebalanceMethod.SUBMARINE_SWAP: 1800  # 30 minutes
        }
        
        return duration_estimates.get(method, 300)
    
    def _execute_rebalancing_operations(self, operations: List[RebalanceOperation]) -> int:
        """Execute rebalancing operations"""
        if not operations:
            return 0
        
        # Check how many operations we can start
        available_slots = self.max_concurrent_operations - len(self.active_operations)
        if available_slots <= 0:
            # Add to pending queue
            self.pending_operations.extend(operations)
            return 0
        
        operations_started = 0
        
        for operation in operations[:available_slots]:
            try:
                # For now, we'll simulate the rebalancing operation
                # In a real implementation, this would call actual rebalancing logic
                success = self._simulate_rebalancing_operation(operation)
                
                if success:
                    operation.status = "in_progress"
                    self.active_operations[operation.operation_id] = operation
                    operations_started += 1
                    
                    self.logger.info(f"Started rebalancing operation {operation.operation_id}: "
                                   f"{operation.amount_sats:,} sats from {operation.source_channel[:12]}... "
                                   f"to {operation.target_channel[:12]}...")
                    
                    increment_counter('rebalancer_operations_started_total')
                else:
                    operation.status = "failed"
                    self.operation_history.append(operation)
                    increment_counter('rebalancer_operations_failed_total')
                
            except Exception as e:
                self.logger.error(f"Failed to start rebalancing operation: {e}")
                operation.status = "failed"
                self.operation_history.append(operation)
        
        # Add remaining operations to pending queue
        if len(operations) > available_slots:
            self.pending_operations.extend(operations[available_slots:])
        
        return operations_started
    
    def _simulate_rebalancing_operation(self, operation: RebalanceOperation) -> bool:
        """Simulate a rebalancing operation (placeholder implementation)"""
        # In a real implementation, this would:
        # 1. Find a route for the rebalancing
        # 2. Execute the payment(s)
        # 3. Monitor progress
        # 4. Handle failures and retries
        
        # For simulation, we'll assume 80% success rate
        import random
        return random.random() > 0.2
    
    def _update_active_operations(self):
        """Update status of active rebalancing operations"""
        completed_operations = []
        
        for operation_id, operation in list(self.active_operations.items()):
            # Simulate operation completion based on estimated duration
            elapsed_time = (datetime.now() - operation.created_at).total_seconds()
            
            if elapsed_time >= operation.estimated_duration:
                # Operation should be completed
                import random
                if random.random() > 0.1:  # 90% success rate for completion
                    operation.status = "completed"
                    self.rebalance_stats['successful_operations'] += 1
                    self.rebalance_stats['total_volume_sats'] += operation.amount_sats
                    self.rebalance_stats['total_fees_paid'] += operation.estimated_cost
                    
                    self.logger.info(f"Rebalancing operation {operation_id} completed successfully")
                    increment_counter('rebalancer_operations_completed_total')
                else:
                    operation.status = "failed"
                    self.rebalance_stats['failed_operations'] += 1
                    
                    self.logger.warning(f"Rebalancing operation {operation_id} failed")
                    increment_counter('rebalancer_operations_failed_total')
                
                completed_operations.append(operation_id)
                self.operation_history.append(operation)
                self.rebalance_stats['total_operations'] += 1
                self.rebalance_stats['last_operation_time'] = datetime.now()
        
        # Remove completed operations from active list
        for operation_id in completed_operations:
            del self.active_operations[operation_id]
        
        # Start pending operations if we have capacity
        if self.pending_operations and len(self.active_operations) < self.max_concurrent_operations:
            available_slots = self.max_concurrent_operations - len(self.active_operations)
            pending_to_start = []
            
            for _ in range(min(available_slots, len(self.pending_operations))):
                pending_to_start.append(self.pending_operations.popleft())
            
            if pending_to_start:
                self._execute_rebalancing_operations(pending_to_start)
    
    def get_rebalancing_status(self) -> Dict[str, Any]:
        """Get current rebalancing status"""
        return {
            'is_running': self.is_running,
            'strategy': self.strategy.value,
            'check_interval_minutes': self.check_interval // 60,
            'max_concurrent_operations': self.max_concurrent_operations,
            'active_operations': len(self.active_operations),
            'pending_operations': len(self.pending_operations),
            'configured_targets': len(self.channel_targets),
            'enabled_targets': len([t for t in self.channel_targets.values() if t.enabled]),
            'statistics': self.rebalance_stats.copy()
        }
    
    def get_operation_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent rebalancing operation history"""
        recent_operations = list(self.operation_history)[-limit:]
        
        return [
            {
                'operation_id': op.operation_id,
                'source_channel': op.source_channel,
                'target_channel': op.target_channel,
                'amount_sats': op.amount_sats,
                'method': op.method.value,
                'estimated_cost': op.estimated_cost,
                'estimated_duration': op.estimated_duration,
                'priority': op.priority,
                'created_at': op.created_at.isoformat(),
                'status': op.status
            }
            for op in recent_operations
        ]
    
    def add_channel_target(self, channel_id: str, target_ratio: float, 
                          min_ratio: float, max_ratio: float, priority: int = 5) -> bool:
        """Add or update a channel rebalancing target"""
        try:
            self.channel_targets[channel_id] = RebalanceTarget(
                channel_id=channel_id,
                target_local_ratio=target_ratio,
                min_local_ratio=min_ratio,
                max_local_ratio=max_ratio,
                priority=priority,
                enabled=True
            )
            self.logger.info(f"Added rebalancing target for channel {channel_id}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to add channel target: {e}")
            return False
    
    def remove_channel_target(self, channel_id: str) -> bool:
        """Remove a channel rebalancing target"""
        if channel_id in self.channel_targets:
            del self.channel_targets[channel_id]
            self.logger.info(f"Removed rebalancing target for channel {channel_id}")
            return True
        return False


# Global channel rebalancer instance
_channel_rebalancer = None

def get_channel_rebalancer(lightning_client=None) -> ChannelRebalancer:
    """Get global channel rebalancer instance"""
    global _channel_rebalancer
    if _channel_rebalancer is None:
        _channel_rebalancer = ChannelRebalancer(lightning_client)
    return _channel_rebalancer

def stop_channel_rebalancer():
    """Stop the global channel rebalancer"""
    global _channel_rebalancer
    if _channel_rebalancer:
        _channel_rebalancer.stop_rebalancing()
        _channel_rebalancer = None