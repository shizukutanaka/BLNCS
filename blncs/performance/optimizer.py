"""
Performance Optimization System for BLNCS
Intelligent optimization of Lightning Network operations for maximum efficiency.
"""

import time
import asyncio
import threading
from typing import Dict, List, Optional, Any, Tuple, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from collections import deque, defaultdict
import statistics

from ..core.logger import get_logger
from ..core.metrics import get_metrics_collector
from ..core.config_manager import get_config_manager
from ..lightning.client import LightningClient
from ..lightning.channel_manager import ChannelManager
from ..lightning.payment_manager import PaymentManager


class OptimizationTarget(Enum):
    """Optimization targets"""
    ROUTING_FEES = "routing_fees"
    PAYMENT_SUCCESS = "payment_success"
    CHANNEL_BALANCE = "channel_balance"
    LIQUIDITY_FLOW = "liquidity_flow"
    NETWORK_EFFICIENCY = "network_efficiency"
    RESOURCE_USAGE = "resource_usage"


class OptimizationStrategy(Enum):
    """Optimization strategies"""
    AGGRESSIVE = "aggressive"
    BALANCED = "balanced"
    CONSERVATIVE = "conservative"
    ADAPTIVE = "adaptive"


@dataclass
class OptimizationGoal:
    """Performance optimization goal"""
    target: OptimizationTarget
    strategy: OptimizationStrategy
    priority: int = 5  # 1-10 scale
    enabled: bool = True
    constraints: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, float] = field(default_factory=dict)


@dataclass
class OptimizationAction:
    """Optimization action to be taken"""
    action_type: str
    target_id: str  # Channel ID, peer ID, etc.
    parameters: Dict[str, Any]
    expected_impact: float
    risk_level: str = "medium"  # low, medium, high
    estimated_cost: int = 0
    requires_approval: bool = False


@dataclass
class PerformanceMetrics:
    """Performance metrics tracking"""
    timestamp: datetime
    payment_success_rate: float = 0.0
    avg_payment_time: float = 0.0
    routing_revenue_sats: int = 0
    channel_utilization: float = 0.0
    liquidity_efficiency: float = 0.0
    network_centrality: float = 0.0
    resource_efficiency: float = 0.0


class PerformanceOptimizer:
    """Intelligent performance optimization system"""
    
    def __init__(self, client: LightningClient):
        self.client = client
        self.logger = get_logger(__name__)
        self.metrics = get_metrics_collector()
        self.config = get_config_manager().get_all()
        
        # Components
        self.channel_manager = ChannelManager(client)
        self.payment_manager = PaymentManager(client)
        
        # Optimization state
        self.optimization_active = False
        self.optimization_thread: Optional[threading.Thread] = None
        self.stop_optimization = threading.Event()
        
        # Goals and actions
        self.optimization_goals: Dict[str, OptimizationGoal] = {}
        self.pending_actions: List[OptimizationAction] = []
        self.completed_actions: deque = deque(maxlen=1000)
        
        # Performance tracking
        self.performance_history: deque = deque(maxlen=2880)  # 48 hours at 1-minute intervals
        self.baseline_metrics: Optional[PerformanceMetrics] = None
        
        # Optimization parameters
        self.optimization_interval = self.config.get('optimization', {}).get('interval_seconds', 300)
        self.min_improvement_threshold = self.config.get('optimization', {}).get('min_improvement', 0.05)
        self.max_actions_per_cycle = self.config.get('optimization', {}).get('max_actions_per_cycle', 3)
        
        # Analysis cache
        self.analysis_cache: Dict[str, Any] = {}
        self.cache_ttl = 600  # 10 minutes
        
        # Setup default goals
        self._setup_default_goals()
    
    def _setup_default_goals(self):
        """Setup default optimization goals"""
        
        # Maximize routing fees
        self.add_optimization_goal(OptimizationGoal(
            target=OptimizationTarget.ROUTING_FEES,
            strategy=OptimizationStrategy.BALANCED,
            priority=8,
            constraints={
                'max_fee_rate': 0.005,  # 0.5%
                'min_base_fee': 1,
                'preserve_routing': True
            }
        ))
        
        # Optimize payment success
        self.add_optimization_goal(OptimizationGoal(
            target=OptimizationTarget.PAYMENT_SUCCESS,
            strategy=OptimizationStrategy.ADAPTIVE,
            priority=9,
            constraints={
                'min_success_rate': 0.95,
                'max_retry_attempts': 3
            }
        ))
        
        # Balance channel liquidity
        self.add_optimization_goal(OptimizationGoal(
            target=OptimizationTarget.CHANNEL_BALANCE,
            strategy=OptimizationStrategy.BALANCED,
            priority=7,
            constraints={
                'target_balance_ratio': 0.5,
                'tolerance': 0.2,
                'rebalance_threshold': 0.1
            }
        ))
        
        # Improve liquidity flow
        self.add_optimization_goal(OptimizationGoal(
            target=OptimizationTarget.LIQUIDITY_FLOW,
            strategy=OptimizationStrategy.ADAPTIVE,
            priority=6,
            constraints={
                'flow_efficiency_target': 0.8,
                'max_stuck_liquidity_ratio': 0.3
            }
        ))
        
        # Optimize resource usage
        self.add_optimization_goal(OptimizationGoal(
            target=OptimizationTarget.RESOURCE_USAGE,
            strategy=OptimizationStrategy.CONSERVATIVE,
            priority=4,
            constraints={
                'max_cpu_usage': 0.8,
                'max_memory_usage': 0.85,
                'max_bandwidth_usage': 0.9
            }
        ))
    
    def add_optimization_goal(self, goal: OptimizationGoal):
        """Add optimization goal"""
        goal_id = f"{goal.target.value}_{goal.strategy.value}"
        self.optimization_goals[goal_id] = goal
        self.logger.info(f"Added optimization goal: {goal_id}")
    
    def remove_optimization_goal(self, goal_id: str):
        """Remove optimization goal"""
        if goal_id in self.optimization_goals:
            del self.optimization_goals[goal_id]
            self.logger.info(f"Removed optimization goal: {goal_id}")
    
    def start_optimization(self, interval: int = None):
        """Start performance optimization"""
        if self.optimization_active:
            return
        
        if interval:
            self.optimization_interval = interval
        
        self.optimization_active = True
        self.stop_optimization.clear()
        
        self.optimization_thread = threading.Thread(
            target=self._optimization_loop,
            daemon=True
        )
        self.optimization_thread.start()
        
        self.logger.info("Performance optimization started")
    
    def stop_optimization_system(self):
        """Stop performance optimization"""
        if not self.optimization_active:
            return
        
        self.stop_optimization.set()
        if self.optimization_thread:
            self.optimization_thread.join(timeout=10)
        
        self.optimization_active = False
        self.logger.info("Performance optimization stopped")
    
    def _optimization_loop(self):
        """Main optimization loop"""
        while not self.stop_optimization.wait(self.optimization_interval):
            try:
                self._collect_performance_metrics()
                self._analyze_performance()
                self._generate_optimization_actions()
                self._execute_approved_actions()
                self._update_optimization_goals()
                
            except Exception as e:
                self.logger.error(f"Optimization loop error: {e}")
    
    def _collect_performance_metrics(self):
        """Collect current performance metrics"""
        try:
            metrics = PerformanceMetrics(timestamp=datetime.now())
            
            # Payment performance
            payment_summary = self.payment_manager.get_payment_summary()
            payments_data = payment_summary.get('payments', {})
            metrics.payment_success_rate = payments_data.get('success_rate', 0.0)
            
            # Channel performance
            channels = self.channel_manager.get_all_channels()
            if channels:
                active_channels = [ch for ch in channels if ch.state.value == 'active']
                if active_channels:
                    total_capacity = sum(ch.capacity for ch in active_channels)
                    utilized_capacity = sum(abs(ch.capacity - ch.local_balance - ch.remote_balance) for ch in active_channels)
                    metrics.channel_utilization = utilized_capacity / total_capacity if total_capacity > 0 else 0
                    
                    # Calculate liquidity efficiency
                    balance_scores = [ch.metrics.get('balance_score', 0) for ch in active_channels]
                    metrics.liquidity_efficiency = 1.0 - (sum(balance_scores) / len(balance_scores)) if balance_scores else 0
            
            # Network efficiency (mock calculation)
            metrics.network_centrality = 0.5  # Would calculate actual centrality
            metrics.resource_efficiency = self._calculate_resource_efficiency()
            
            # Store metrics
            self.performance_history.append(metrics)
            
            # Set baseline if not exists
            if self.baseline_metrics is None:
                self.baseline_metrics = metrics
            
            # Record to metrics system
            self.metrics.record_metric('performance.payment_success_rate', metrics.payment_success_rate)
            self.metrics.record_metric('performance.channel_utilization', metrics.channel_utilization)
            self.metrics.record_metric('performance.liquidity_efficiency', metrics.liquidity_efficiency)
            
        except Exception as e:
            self.logger.error(f"Failed to collect performance metrics: {e}")
    
    def _calculate_resource_efficiency(self) -> float:
        """Calculate resource efficiency score"""
        try:
            # Mock implementation - would calculate actual resource usage
            import psutil
            cpu_usage = psutil.cpu_percent(interval=1) / 100.0
            memory_usage = psutil.virtual_memory().percent / 100.0
            
            # Higher efficiency for lower resource usage
            efficiency = (2.0 - cpu_usage - memory_usage) / 2.0
            return max(0.0, min(1.0, efficiency))
            
        except:
            return 0.8  # Default efficiency
    
    def _analyze_performance(self):
        """Analyze current performance trends"""
        try:
            if len(self.performance_history) < 2:
                return
            
            # Clear old cache
            current_time = time.time()
            self.analysis_cache = {k: v for k, v in self.analysis_cache.items() 
                                 if current_time - v.get('timestamp', 0) < self.cache_ttl}
            
            # Analyze trends
            recent_metrics = list(self.performance_history)[-10:]  # Last 10 data points
            
            analysis = {
                'timestamp': current_time,
                'trends': self._calculate_trends(recent_metrics),
                'anomalies': self._detect_anomalies(recent_metrics),
                'bottlenecks': self._identify_bottlenecks(),
                'opportunities': self._identify_opportunities(recent_metrics)
            }
            
            self.analysis_cache['performance_analysis'] = analysis
            
        except Exception as e:
            self.logger.error(f"Performance analysis failed: {e}")
    
    def _calculate_trends(self, metrics: List[PerformanceMetrics]) -> Dict[str, str]:
        """Calculate performance trends"""
        if len(metrics) < 2:
            return {}
        
        trends = {}
        
        # Success rate trend
        success_rates = [m.payment_success_rate for m in metrics]
        if len(success_rates) > 1:
            trend = "improving" if success_rates[-1] > success_rates[0] else "declining"
            trends['payment_success'] = trend
        
        # Channel utilization trend
        utilizations = [m.channel_utilization for m in metrics]
        if len(utilizations) > 1:
            trend = "increasing" if utilizations[-1] > utilizations[0] else "decreasing"
            trends['channel_utilization'] = trend
        
        # Liquidity efficiency trend
        efficiencies = [m.liquidity_efficiency for m in metrics]
        if len(efficiencies) > 1:
            trend = "improving" if efficiencies[-1] > efficiencies[0] else "declining"
            trends['liquidity_efficiency'] = trend
        
        return trends
    
    def _detect_anomalies(self, metrics: List[PerformanceMetrics]) -> List[Dict[str, Any]]:
        """Detect performance anomalies"""
        anomalies = []
        
        if len(metrics) < 5:
            return anomalies
        
        try:
            # Check for success rate drops
            success_rates = [m.payment_success_rate for m in metrics]
            avg_success = statistics.mean(success_rates)
            current_success = success_rates[-1]
            
            if current_success < avg_success * 0.8:  # 20% below average
                anomalies.append({
                    'type': 'payment_success_drop',
                    'severity': 'high',
                    'current_value': current_success,
                    'expected_value': avg_success,
                    'deviation': (avg_success - current_success) / avg_success
                })
            
            # Check for channel utilization spikes
            utilizations = [m.channel_utilization for m in metrics]
            avg_utilization = statistics.mean(utilizations)
            current_utilization = utilizations[-1]
            
            if current_utilization > avg_utilization * 1.5:  # 50% above average
                anomalies.append({
                    'type': 'channel_utilization_spike',
                    'severity': 'medium',
                    'current_value': current_utilization,
                    'expected_value': avg_utilization,
                    'deviation': (current_utilization - avg_utilization) / avg_utilization
                })
            
        except Exception as e:
            self.logger.error(f"Anomaly detection failed: {e}")
        
        return anomalies
    
    def _identify_bottlenecks(self) -> List[Dict[str, Any]]:
        """Identify performance bottlenecks"""
        bottlenecks = []
        
        try:
            # Channel imbalance bottlenecks
            imbalanced_channels = self.channel_manager.get_imbalanced_channels(threshold=0.1)
            if len(imbalanced_channels) > 0:
                bottlenecks.append({
                    'type': 'channel_imbalance',
                    'severity': 'medium',
                    'count': len(imbalanced_channels),
                    'description': f"{len(imbalanced_channels)} channels severely imbalanced"
                })
            
            # Payment failure bottlenecks
            if self.performance_history:
                recent_success = self.performance_history[-1].payment_success_rate
                if recent_success < 0.9:
                    bottlenecks.append({
                        'type': 'payment_failures',
                        'severity': 'high' if recent_success < 0.8 else 'medium',
                        'success_rate': recent_success,
                        'description': f"Payment success rate below optimal ({recent_success:.1%})"
                    })
            
            # Resource bottlenecks
            resource_efficiency = self._calculate_resource_efficiency()
            if resource_efficiency < 0.6:
                bottlenecks.append({
                    'type': 'resource_constraints',
                    'severity': 'medium',
                    'efficiency': resource_efficiency,
                    'description': "System resource usage impacting performance"
                })
            
        except Exception as e:
            self.logger.error(f"Bottleneck identification failed: {e}")
        
        return bottlenecks
    
    def _identify_opportunities(self, metrics: List[PerformanceMetrics]) -> List[Dict[str, Any]]:
        """Identify optimization opportunities"""
        opportunities = []
        
        try:
            # Fee optimization opportunities
            channels = self.channel_manager.get_all_channels()
            low_fee_channels = [ch for ch in channels if ch.fee_rate < 0.0001]
            if len(low_fee_channels) > 0:
                opportunities.append({
                    'type': 'fee_optimization',
                    'potential_impact': 'medium',
                    'count': len(low_fee_channels),
                    'description': f"{len(low_fee_channels)} channels with suboptimal fees"
                })
            
            # Rebalancing opportunities
            if metrics:
                avg_liquidity_efficiency = statistics.mean([m.liquidity_efficiency for m in metrics])
                if avg_liquidity_efficiency < 0.7:
                    opportunities.append({
                        'type': 'liquidity_rebalancing',
                        'potential_impact': 'high',
                        'efficiency': avg_liquidity_efficiency,
                        'description': "Liquidity rebalancing could improve efficiency"
                    })
            
            # Channel opening opportunities
            total_capacity = sum(ch.capacity for ch in channels)
            if total_capacity > 0:
                utilization = sum(abs(ch.capacity - ch.local_balance - ch.remote_balance) for ch in channels) / total_capacity
                if utilization > 0.8:
                    opportunities.append({
                        'type': 'capacity_expansion',
                        'potential_impact': 'high',
                        'utilization': utilization,
                        'description': "High utilization suggests need for more capacity"
                    })
            
        except Exception as e:
            self.logger.error(f"Opportunity identification failed: {e}")
        
        return opportunities
    
    def _generate_optimization_actions(self):
        """Generate optimization actions based on analysis"""
        try:
            analysis = self.analysis_cache.get('performance_analysis', {})
            if not analysis:
                return
            
            bottlenecks = analysis.get('bottlenecks', [])
            opportunities = analysis.get('opportunities', [])
            
            new_actions = []
            
            # Generate actions for bottlenecks
            for bottleneck in bottlenecks:
                actions = self._generate_bottleneck_actions(bottleneck)
                new_actions.extend(actions)
            
            # Generate actions for opportunities
            for opportunity in opportunities:
                actions = self._generate_opportunity_actions(opportunity)
                new_actions.extend(actions)
            
            # Filter and prioritize actions
            filtered_actions = self._filter_actions(new_actions)
            
            # Add to pending actions
            self.pending_actions.extend(filtered_actions)
            
            # Limit pending actions
            self.pending_actions = self.pending_actions[-100:]  # Keep last 100
            
        except Exception as e:
            self.logger.error(f"Action generation failed: {e}")
    
    def _generate_bottleneck_actions(self, bottleneck: Dict[str, Any]) -> List[OptimizationAction]:
        """Generate actions to address bottlenecks"""
        actions = []
        
        try:
            if bottleneck['type'] == 'channel_imbalance':
                # Generate rebalancing actions
                imbalanced_channels = self.channel_manager.get_imbalanced_channels()
                for channel in imbalanced_channels[:3]:  # Limit to top 3
                    balance_ratio = channel.local_balance / channel.capacity if channel.capacity > 0 else 0.5
                    
                    if balance_ratio < 0.2:  # Need inbound liquidity
                        amount = int(channel.capacity * 0.3)
                        actions.append(OptimizationAction(
                            action_type="rebalance_inbound",
                            target_id=channel.channel_id,
                            parameters={'amount': amount, 'max_fee': 1000},
                            expected_impact=0.3,
                            risk_level="medium"
                        ))
                    elif balance_ratio > 0.8:  # Need outbound liquidity
                        amount = int(channel.capacity * 0.3)
                        actions.append(OptimizationAction(
                            action_type="rebalance_outbound",
                            target_id=channel.channel_id,
                            parameters={'amount': amount, 'max_fee': 1000},
                            expected_impact=0.3,
                            risk_level="medium"
                        ))
            
            elif bottleneck['type'] == 'payment_failures':
                # Generate actions to improve payment success
                actions.append(OptimizationAction(
                    action_type="optimize_payment_routes",
                    target_id="global",
                    parameters={'increase_retry_attempts': True, 'diversify_routes': True},
                    expected_impact=0.2,
                    risk_level="low"
                ))
        
        except Exception as e:
            self.logger.error(f"Bottleneck action generation failed: {e}")
        
        return actions
    
    def _generate_opportunity_actions(self, opportunity: Dict[str, Any]) -> List[OptimizationAction]:
        """Generate actions to capitalize on opportunities"""
        actions = []
        
        try:
            if opportunity['type'] == 'fee_optimization':
                # Generate fee adjustment actions
                channels = self.channel_manager.get_all_channels()
                low_fee_channels = [ch for ch in channels if ch.fee_rate < 0.0001]
                
                for channel in low_fee_channels[:5]:  # Limit to top 5
                    new_fee_rate = min(0.001, channel.fee_rate * 2)  # Double fee but cap at 0.1%
                    actions.append(OptimizationAction(
                        action_type="adjust_channel_fees",
                        target_id=channel.channel_id,
                        parameters={'fee_rate': new_fee_rate, 'base_fee': max(1, channel.base_fee)},
                        expected_impact=0.15,
                        risk_level="low"
                    ))
            
            elif opportunity['type'] == 'capacity_expansion':
                # Generate channel opening actions
                actions.append(OptimizationAction(
                    action_type="analyze_channel_opportunities",
                    target_id="global",
                    parameters={'min_capacity': 5000000, 'target_peers': 3},
                    expected_impact=0.4,
                    risk_level="high",
                    requires_approval=True
                ))
        
        except Exception as e:
            self.logger.error(f"Opportunity action generation failed: {e}")
        
        return actions
    
    def _filter_actions(self, actions: List[OptimizationAction]) -> List[OptimizationAction]:
        """Filter and prioritize optimization actions"""
        try:
            # Remove duplicates
            unique_actions = []
            seen_combinations = set()
            
            for action in actions:
                key = (action.action_type, action.target_id)
                if key not in seen_combinations:
                    unique_actions.append(action)
                    seen_combinations.add(key)
            
            # Sort by expected impact (descending)
            unique_actions.sort(key=lambda x: x.expected_impact, reverse=True)
            
            # Filter by risk constraints
            filtered_actions = []
            for action in unique_actions:
                # Check if action meets current strategy constraints
                if self._action_meets_constraints(action):
                    filtered_actions.append(action)
            
            return filtered_actions[:self.max_actions_per_cycle]
            
        except Exception as e:
            self.logger.error(f"Action filtering failed: {e}")
            return actions
    
    def _action_meets_constraints(self, action: OptimizationAction) -> bool:
        """Check if action meets optimization constraints"""
        try:
            # Check risk tolerance based on current strategy
            risk_tolerance = self._get_current_risk_tolerance()
            
            if action.risk_level == "high" and risk_tolerance < 0.7:
                return False
            if action.risk_level == "medium" and risk_tolerance < 0.4:
                return False
            
            # Check if minimum expected impact is met
            if action.expected_impact < self.min_improvement_threshold:
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Constraint checking failed: {e}")
            return True  # Default to allowing action
    
    def _get_current_risk_tolerance(self) -> float:
        """Get current risk tolerance based on system state"""
        # Mock implementation - would analyze current performance and stability
        if self.performance_history:
            recent_success = self.performance_history[-1].payment_success_rate
            if recent_success > 0.95:
                return 0.8  # High risk tolerance when performing well
            elif recent_success > 0.9:
                return 0.5  # Medium risk tolerance
            else:
                return 0.2  # Low risk tolerance when having issues
        
        return 0.5  # Default medium risk tolerance
    
    def _execute_approved_actions(self):
        """Execute optimization actions that don't require approval"""
        try:
            executable_actions = [action for action in self.pending_actions 
                                if not action.requires_approval]
            
            for action in executable_actions[:self.max_actions_per_cycle]:
                try:
                    self._execute_single_action(action)
                    
                    # Move to completed actions
                    self.completed_actions.append(action)
                    self.pending_actions.remove(action)
                    
                except Exception as e:
                    self.logger.error(f"Action execution failed: {action.action_type} - {e}")
        
        except Exception as e:
            self.logger.error(f"Action execution loop failed: {e}")
    
    def _execute_single_action(self, action: OptimizationAction):
        """Execute a single optimization action"""
        self.logger.info(f"Executing optimization action: {action.action_type}")
        
        try:
            if action.action_type == "rebalance_inbound":
                # Execute channel rebalancing
                self.channel_manager.rebalance_channel(
                    action.target_id,
                    action.parameters['amount'],
                    action.parameters.get('max_fee', 1000)
                )
            
            elif action.action_type == "adjust_channel_fees":
                # Adjust channel fees
                self.channel_manager.update_channel_policy(
                    action.target_id,
                    fee_rate=action.parameters.get('fee_rate'),
                    base_fee=action.parameters.get('base_fee')
                )
            
            elif action.action_type == "optimize_payment_routes":
                # Optimize payment routing (mock implementation)
                self.logger.info("Payment route optimization applied")
            
            elif action.action_type == "analyze_channel_opportunities":
                # Analyze channel opportunities (mock implementation)
                self.logger.info("Channel opportunity analysis completed")
            
            # Record successful action
            self.metrics.record_metric('optimization.action_executed', 1, {
                'action_type': action.action_type,
                'expected_impact': action.expected_impact,
                'risk_level': action.risk_level
            })
            
        except Exception as e:
            self.logger.error(f"Failed to execute action {action.action_type}: {e}")
            raise
    
    def _update_optimization_goals(self):
        """Update optimization goals based on performance"""
        try:
            if not self.performance_history:
                return
            
            current_metrics = self.performance_history[-1]
            
            for goal_id, goal in self.optimization_goals.items():
                if not goal.enabled:
                    continue
                
                # Update goal metrics based on current performance
                if goal.target == OptimizationTarget.PAYMENT_SUCCESS:
                    goal.metrics['current_success_rate'] = current_metrics.payment_success_rate
                    goal.metrics['target_success_rate'] = goal.constraints.get('min_success_rate', 0.95)
                
                elif goal.target == OptimizationTarget.CHANNEL_BALANCE:
                    goal.metrics['current_utilization'] = current_metrics.channel_utilization
                    goal.metrics['liquidity_efficiency'] = current_metrics.liquidity_efficiency
                
                elif goal.target == OptimizationTarget.RESOURCE_USAGE:
                    goal.metrics['resource_efficiency'] = current_metrics.resource_efficiency
                
                # Adjust strategy based on performance
                self._adjust_goal_strategy(goal, current_metrics)
        
        except Exception as e:
            self.logger.error(f"Goal update failed: {e}")
    
    def _adjust_goal_strategy(self, goal: OptimizationGoal, current_metrics: PerformanceMetrics):
        """Adjust optimization strategy based on performance"""
        try:
            if goal.target == OptimizationTarget.PAYMENT_SUCCESS:
                # Be more aggressive if success rate is low
                if current_metrics.payment_success_rate < 0.9:
                    goal.strategy = OptimizationStrategy.AGGRESSIVE
                elif current_metrics.payment_success_rate > 0.98:
                    goal.strategy = OptimizationStrategy.CONSERVATIVE
                else:
                    goal.strategy = OptimizationStrategy.BALANCED
            
            elif goal.target == OptimizationTarget.ROUTING_FEES:
                # Be more conservative with fees if payment success is low
                if current_metrics.payment_success_rate < 0.95:
                    goal.strategy = OptimizationStrategy.CONSERVATIVE
                else:
                    goal.strategy = OptimizationStrategy.BALANCED
        
        except Exception as e:
            self.logger.error(f"Strategy adjustment failed: {e}")
    
    def get_optimization_status(self) -> Dict[str, Any]:
        """Get optimization system status"""
        return {
            'optimization_active': self.optimization_active,
            'total_goals': len(self.optimization_goals),
            'active_goals': len([g for g in self.optimization_goals.values() if g.enabled]),
            'pending_actions': len(self.pending_actions),
            'completed_actions_today': len([a for a in self.completed_actions 
                                          if hasattr(a, 'executed_at') and 
                                          (datetime.now() - getattr(a, 'executed_at', datetime.min)).days < 1]),
            'performance_data_points': len(self.performance_history),
            'last_optimization': self.performance_history[-1].timestamp.isoformat() if self.performance_history else None,
            'optimization_interval_seconds': self.optimization_interval,
            'current_performance': self._get_current_performance_summary()
        }
    
    def _get_current_performance_summary(self) -> Dict[str, Any]:
        """Get current performance summary"""
        if not self.performance_history:
            return {}
        
        current = self.performance_history[-1]
        baseline = self.baseline_metrics
        
        summary = {
            'payment_success_rate': current.payment_success_rate,
            'channel_utilization': current.channel_utilization,
            'liquidity_efficiency': current.liquidity_efficiency,
            'resource_efficiency': current.resource_efficiency
        }
        
        if baseline:
            summary['improvements'] = {
                'payment_success_rate': current.payment_success_rate - baseline.payment_success_rate,
                'channel_utilization': current.channel_utilization - baseline.channel_utilization,
                'liquidity_efficiency': current.liquidity_efficiency - baseline.liquidity_efficiency,
                'resource_efficiency': current.resource_efficiency - baseline.resource_efficiency
            }
        
        return summary
    
    def approve_pending_action(self, action_index: int) -> bool:
        """Approve a pending action for execution"""
        try:
            if 0 <= action_index < len(self.pending_actions):
                action = self.pending_actions[action_index]
                if action.requires_approval:
                    action.requires_approval = False
                    self.logger.info(f"Action approved: {action.action_type}")
                    return True
            return False
        
        except Exception as e:
            self.logger.error(f"Action approval failed: {e}")
            return False
    
    def get_optimization_report(self) -> Dict[str, Any]:
        """Generate comprehensive optimization report"""
        try:
            recent_metrics = list(self.performance_history)[-24:]  # Last 24 data points
            
            report = {
                'report_timestamp': datetime.now().isoformat(),
                'optimization_period': f"{len(recent_metrics)} data points",
                'performance_summary': self._get_current_performance_summary(),
                'optimization_goals': {
                    goal_id: {
                        'target': goal.target.value,
                        'strategy': goal.strategy.value,
                        'priority': goal.priority,
                        'enabled': goal.enabled,
                        'current_metrics': goal.metrics
                    }
                    for goal_id, goal in self.optimization_goals.items()
                },
                'recent_actions': [
                    {
                        'action_type': action.action_type,
                        'target': action.target_id,
                        'expected_impact': action.expected_impact,
                        'risk_level': action.risk_level
                    }
                    for action in list(self.completed_actions)[-10:]
                ],
                'pending_actions': [
                    {
                        'action_type': action.action_type,
                        'target': action.target_id,
                        'expected_impact': action.expected_impact,
                        'requires_approval': action.requires_approval
                    }
                    for action in self.pending_actions
                ],
                'performance_trends': self._calculate_trends(recent_metrics) if recent_metrics else {},
                'recommendations': self._generate_recommendations()
            }
            
            return report
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            return {'error': str(e)}
    
    def _generate_recommendations(self) -> List[str]:
        """Generate optimization recommendations"""
        recommendations = []
        
        try:
            if self.performance_history:
                current = self.performance_history[-1]
                
                if current.payment_success_rate < 0.9:
                    recommendations.append("Consider increasing payment retry attempts and diversifying routes")
                
                if current.channel_utilization > 0.8:
                    recommendations.append("High channel utilization detected - consider opening additional channels")
                
                if current.liquidity_efficiency < 0.7:
                    recommendations.append("Liquidity imbalance detected - rebalancing could improve efficiency")
                
                if current.resource_efficiency < 0.6:
                    recommendations.append("System resources are constrained - consider hardware optimization")
        
        except Exception as e:
            self.logger.error(f"Recommendation generation failed: {e}")
        
        return recommendations


def get_performance_optimizer(client: Optional[LightningClient] = None) -> PerformanceOptimizer:
    """Get performance optimizer instance"""
    if client is None:
        from ..lightning.client import LightningClient
        config = get_config_manager().get_all()
        client = LightningClient(config)
    
    return PerformanceOptimizer(client)