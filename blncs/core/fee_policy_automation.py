"""
Automated Fee Policy Adjustment System
Implements intelligent fee policy management with dynamic adjustments based on network conditions.
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
from .fee_optimizer_advanced import get_advanced_fee_optimizer
from .metrics import get_metrics_collector, increment_counter, set_gauge, observe_histogram


@dataclass
class FeeAdjustmentRule:
    """Fee adjustment rule configuration"""
    name: str
    trigger_condition: str  # 'low_volume', 'high_volume', 'low_success_rate', 'high_demand'
    channel_filter: str  # 'all', 'outbound_low', 'inbound_low', 'high_capacity'
    adjustment_type: str  # 'increase', 'decrease', 'optimize'
    adjustment_factor: float = 1.1  # Multiplication factor
    min_fee_rate: int = 1  # Minimum fee rate in ppm
    max_fee_rate: int = 5000  # Maximum fee rate in ppm
    cooldown_minutes: int = 30  # Minimum time between adjustments
    enabled: bool = True


@dataclass
class FeeAdjustmentHistory:
    """History of fee adjustments"""
    timestamp: datetime
    channel_id: str
    old_fee_rate: int
    new_fee_rate: int
    rule_name: str
    reason: str
    success: bool = True


class AutomatedFeePolicyManager:
    """Manages automated fee policy adjustments"""
    
    def __init__(self, lightning_client=None):
        self.logger = get_logger(__name__)
        self.config = get_config_manager()
        self.db = get_database_manager()
        self.fee_optimizer = get_advanced_fee_optimizer()
        self.lightning_client = lightning_client
        
        # Metrics
        self.metrics = get_metrics_collector()
        
        # State management
        self.is_running = False
        self.adjustment_thread = None
        self._stop_event = threading.Event()
        
        # Fee adjustment history
        self.adjustment_history: deque = deque(maxlen=1000)
        self.last_adjustments: Dict[str, datetime] = {}  # channel_id -> last_adjustment_time
        
        # Performance tracking
        self.performance_window = deque(maxlen=144)  # 24 hours of 10-minute intervals
        
        # Configuration
        self.check_interval = self.config.get('fee_automation.check_interval_minutes', 10) * 60
        self.enabled_rules = self._load_fee_rules()
        
        self.logger.info("Automated fee policy manager initialized")
    
    def _load_fee_rules(self) -> List[FeeAdjustmentRule]:
        """Load fee adjustment rules from configuration"""
        default_rules = [
            FeeAdjustmentRule(
                name="Low Volume Decrease",
                trigger_condition="low_volume",
                channel_filter="all",
                adjustment_type="decrease",
                adjustment_factor=0.9,
                min_fee_rate=1,
                max_fee_rate=5000,
                cooldown_minutes=60
            ),
            FeeAdjustmentRule(
                name="High Demand Increase",
                trigger_condition="high_demand",
                channel_filter="outbound_low",
                adjustment_type="increase", 
                adjustment_factor=1.2,
                min_fee_rate=10,
                max_fee_rate=2000,
                cooldown_minutes=30
            ),
            FeeAdjustmentRule(
                name="Low Success Rate Increase",
                trigger_condition="low_success_rate",
                channel_filter="all",
                adjustment_type="increase",
                adjustment_factor=1.15,
                min_fee_rate=5,
                max_fee_rate=3000,
                cooldown_minutes=45
            ),
            FeeAdjustmentRule(
                name="Optimization Balance",
                trigger_condition="optimization_needed",
                channel_filter="all",
                adjustment_type="optimize",
                adjustment_factor=1.0,
                min_fee_rate=1,
                max_fee_rate=5000,
                cooldown_minutes=120
            )
        ]
        
        # Allow configuration override
        config_rules = self.config.get('fee_automation.rules', [])
        if config_rules:
            try:
                return [FeeAdjustmentRule(**rule) for rule in config_rules]
            except Exception as e:
                self.logger.warning(f"Failed to load fee rules from config: {e}, using defaults")
        
        return default_rules
    
    def start_automation(self) -> bool:
        """Start automated fee policy adjustments"""
        if self.is_running:
            self.logger.warning("Fee automation is already running")
            return False
        
        if not self.lightning_client:
            self.logger.error("Cannot start fee automation without Lightning client")
            return False
        
        self.is_running = True
        self._stop_event.clear()
        
        self.adjustment_thread = threading.Thread(
            target=self._automation_loop,
            name="FeeAutomationThread",
            daemon=True
        )
        self.adjustment_thread.start()
        
        self.logger.info("Automated fee policy adjustments started")
        increment_counter('fee_automation_starts_total')
        return True
    
    def stop_automation(self) -> bool:
        """Stop automated fee policy adjustments"""
        if not self.is_running:
            return False
        
        self.is_running = False
        self._stop_event.set()
        
        if self.adjustment_thread and self.adjustment_thread.is_alive():
            self.adjustment_thread.join(timeout=10)
        
        self.logger.info("Automated fee policy adjustments stopped")
        increment_counter('fee_automation_stops_total')
        return True
    
    def _automation_loop(self):
        """Main automation loop"""
        self.logger.info(f"Fee automation loop started (check interval: {self.check_interval}s)")
        
        while not self._stop_event.wait(self.check_interval):
            try:
                start_time = time.time()
                
                # Collect network and channel data
                network_state = self._analyze_network_state()
                channel_data = self._get_channel_performance_data()
                
                # Process each enabled rule
                adjustments_made = 0
                for rule in self.enabled_rules:
                    if not rule.enabled:
                        continue
                    
                    try:
                        adjustments = self._process_rule(rule, network_state, channel_data)
                        adjustments_made += len(adjustments)
                        
                        # Record adjustments
                        for adjustment in adjustments:
                            self.adjustment_history.append(adjustment)
                            self.last_adjustments[adjustment.channel_id] = adjustment.timestamp
                    
                    except Exception as e:
                        self.logger.error(f"Error processing rule {rule.name}: {e}")
                
                # Update metrics
                duration = time.time() - start_time
                observe_histogram('fee_automation_check_duration_seconds', duration)
                set_gauge('fee_automation_adjustments_last_cycle', adjustments_made)
                
                if adjustments_made > 0:
                    self.logger.info(f"Fee automation cycle completed: {adjustments_made} adjustments made")
                    increment_counter('fee_automation_cycles_with_adjustments_total')
                else:
                    increment_counter('fee_automation_cycles_no_adjustments_total')
                
            except Exception as e:
                self.logger.error(f"Fee automation loop error: {e}")
                increment_counter('fee_automation_errors_total')
        
        self.logger.info("Fee automation loop stopped")
    
    def _analyze_network_state(self) -> Dict[str, Any]:
        """Analyze current network conditions"""
        try:
            network_state = {
                'timestamp': datetime.now(),
                'network_fee_median': 1000,  # Default fallback
                'network_fee_mean': 1200,
                'network_capacity_utilization': 0.7,
                'recent_forwarding_volume': 0,
                'recent_forwarding_count': 0,
                'avg_success_rate': 0.95
            }
            
            # Get recent forwarding data
            if self.lightning_client:
                try:
                    # Get last hour of forwarding events
                    end_time = int(time.time())
                    start_time = end_time - 3600
                    
                    forwarding_events = self.lightning_client.get_forwarding_events(start_time, end_time)
                    if forwarding_events:
                        successful_events = [e for e in forwarding_events if e.get('status') == 'settled']
                        
                        network_state['recent_forwarding_count'] = len(successful_events)
                        network_state['recent_forwarding_volume'] = sum(
                            e.get('amt_out_msat', 0) // 1000 for e in successful_events
                        )
                        
                        if len(forwarding_events) > 0:
                            network_state['avg_success_rate'] = len(successful_events) / len(forwarding_events)
                        
                        # Calculate fee rates
                        if successful_events:
                            fee_rates = []
                            for event in successful_events:
                                amt_out = event.get('amt_out_msat', 0) // 1000
                                fee = event.get('fee_msat', 0) // 1000
                                if amt_out > 0:
                                    fee_rate = (fee / amt_out) * 1000000  # ppm
                                    fee_rates.append(fee_rate)
                            
                            if fee_rates:
                                network_state['network_fee_median'] = statistics.median(fee_rates)
                                network_state['network_fee_mean'] = statistics.mean(fee_rates)
                
                except Exception as e:
                    self.logger.warning(f"Failed to get forwarding data: {e}")
            
            return network_state
            
        except Exception as e:
            self.logger.error(f"Failed to analyze network state: {e}")
            return {'timestamp': datetime.now(), 'error': str(e)}
    
    def _get_channel_performance_data(self) -> Dict[str, Any]:
        """Get channel performance data"""
        try:
            channel_data = {}
            
            if self.lightning_client:
                try:
                    self.lightning_client.connect()
                    channels = self.lightning_client.list_channels()
                    
                    for channel in channels:
                        channel_id = channel.get('channel_id', '')
                        if not channel_id:
                            continue
                        
                        # Get current channel policy
                        try:
                            policy = self.lightning_client.get_channel_policy(channel_id)
                            current_fee_rate = policy.get('fee_rate_milli_msat', 1000) // 1000  # Convert to ppm
                        except:
                            current_fee_rate = 1000  # Default
                        
                        channel_data[channel_id] = {
                            'capacity': channel.get('capacity', 0),
                            'local_balance': channel.get('local_balance', 0),
                            'remote_balance': channel.get('remote_balance', 0),
                            'current_fee_rate': current_fee_rate,
                            'active': channel.get('active', False),
                            'outbound_ratio': channel.get('local_balance', 0) / max(channel.get('capacity', 1), 1),
                            'inbound_ratio': channel.get('remote_balance', 0) / max(channel.get('capacity', 1), 1)
                        }
                    
                    self.lightning_client.disconnect()
                    
                except Exception as e:
                    self.logger.warning(f"Failed to get channel data: {e}")
                    try:
                        self.lightning_client.disconnect()
                    except:
                        pass
            
            return channel_data
            
        except Exception as e:
            self.logger.error(f"Failed to get channel performance data: {e}")
            return {}
    
    def _process_rule(self, rule: FeeAdjustmentRule, network_state: Dict[str, Any], 
                     channel_data: Dict[str, Any]) -> List[FeeAdjustmentHistory]:
        """Process a specific fee adjustment rule"""
        adjustments = []
        
        # Check if rule conditions are met
        if not self._evaluate_rule_trigger(rule, network_state):
            return adjustments
        
        # Filter channels based on rule criteria
        target_channels = self._filter_channels(rule, channel_data)
        
        if not target_channels:
            return adjustments
        
        self.logger.info(f"Processing rule '{rule.name}' for {len(target_channels)} channels")
        
        # Apply fee adjustments
        for channel_id in target_channels:
            # Check cooldown
            if self._is_in_cooldown(channel_id, rule.cooldown_minutes):
                continue
            
            try:
                adjustment = self._apply_fee_adjustment(
                    channel_id, rule, channel_data[channel_id], network_state
                )
                if adjustment:
                    adjustments.append(adjustment)
                    increment_counter('fee_automation_adjustments_total', {"rule": rule.name})
            
            except Exception as e:
                self.logger.error(f"Failed to adjust fees for channel {channel_id}: {e}")
        
        return adjustments
    
    def _evaluate_rule_trigger(self, rule: FeeAdjustmentRule, network_state: Dict[str, Any]) -> bool:
        """Evaluate if rule trigger conditions are met"""
        condition = rule.trigger_condition
        
        if condition == "low_volume":
            # Trigger if recent volume is below threshold
            volume_threshold = self.config.get('fee_automation.low_volume_threshold', 100000)  # sats
            return network_state.get('recent_forwarding_volume', 0) < volume_threshold
        
        elif condition == "high_demand":
            # Trigger if recent forwarding count is above threshold
            count_threshold = self.config.get('fee_automation.high_demand_threshold', 50)
            return network_state.get('recent_forwarding_count', 0) > count_threshold
        
        elif condition == "low_success_rate":
            # Trigger if success rate is below threshold
            success_threshold = self.config.get('fee_automation.low_success_rate_threshold', 0.9)
            return network_state.get('avg_success_rate', 1.0) < success_threshold
        
        elif condition == "optimization_needed":
            # Always allow optimization (cooldown will limit frequency)
            return True
        
        else:
            self.logger.warning(f"Unknown rule trigger condition: {condition}")
            return False
    
    def _filter_channels(self, rule: FeeAdjustmentRule, channel_data: Dict[str, Any]) -> List[str]:
        """Filter channels based on rule criteria"""
        filtered_channels = []
        
        for channel_id, data in channel_data.items():
            if not data.get('active', False):
                continue  # Skip inactive channels
            
            filter_type = rule.channel_filter
            
            if filter_type == "all":
                filtered_channels.append(channel_id)
            
            elif filter_type == "outbound_low":
                # Channels with low outbound liquidity
                if data.get('outbound_ratio', 0) < 0.3:
                    filtered_channels.append(channel_id)
            
            elif filter_type == "inbound_low":
                # Channels with low inbound liquidity
                if data.get('inbound_ratio', 0) < 0.3:
                    filtered_channels.append(channel_id)
            
            elif filter_type == "high_capacity":
                # High capacity channels (top 30%)
                capacity_threshold = 1000000  # 1M sats
                if data.get('capacity', 0) > capacity_threshold:
                    filtered_channels.append(channel_id)
        
        return filtered_channels
    
    def _is_in_cooldown(self, channel_id: str, cooldown_minutes: int) -> bool:
        """Check if channel is in cooldown period"""
        if channel_id not in self.last_adjustments:
            return False
        
        last_adjustment = self.last_adjustments[channel_id]
        cooldown_delta = timedelta(minutes=cooldown_minutes)
        
        return datetime.now() - last_adjustment < cooldown_delta
    
    def _apply_fee_adjustment(self, channel_id: str, rule: FeeAdjustmentRule, 
                            channel_data: Dict[str, Any], network_state: Dict[str, Any]) -> Optional[FeeAdjustmentHistory]:
        """Apply fee adjustment to a specific channel"""
        try:
            current_fee = channel_data.get('current_fee_rate', 1000)
            
            if rule.adjustment_type == "increase":
                new_fee = int(current_fee * rule.adjustment_factor)
            elif rule.adjustment_type == "decrease":
                new_fee = int(current_fee / rule.adjustment_factor)
            elif rule.adjustment_type == "optimize":
                # Use advanced fee optimizer
                optimization = self.fee_optimizer.optimize_channel_fees(channel_id)
                if optimization and 'recommended_fee' in optimization:
                    new_fee = optimization['recommended_fee']
                else:
                    return None  # No optimization recommendation
            else:
                return None
            
            # Apply min/max constraints
            new_fee = max(rule.min_fee_rate, min(rule.max_fee_rate, new_fee))
            
            # Don't make trivial adjustments
            if abs(new_fee - current_fee) < 10:  # Less than 10 ppm difference
                return None
            
            # Apply the fee change via Lightning client
            success = self._update_channel_fee(channel_id, new_fee)
            
            # Create adjustment history record
            adjustment = FeeAdjustmentHistory(
                timestamp=datetime.now(),
                channel_id=channel_id,
                old_fee_rate=current_fee,
                new_fee_rate=new_fee,
                rule_name=rule.name,
                reason=f"Rule: {rule.name}, Trigger: {rule.trigger_condition}",
                success=success
            )
            
            if success:
                self.logger.info(f"Fee adjusted for {channel_id}: {current_fee} -> {new_fee} ppm ({rule.name})")
            else:
                self.logger.warning(f"Failed to adjust fee for {channel_id}")
            
            return adjustment
            
        except Exception as e:
            self.logger.error(f"Error applying fee adjustment to {channel_id}: {e}")
            return None
    
    def _update_channel_fee(self, channel_id: str, new_fee_rate: int) -> bool:
        """Update channel fee rate via Lightning client"""
        try:
            if not self.lightning_client:
                return False
            
            # Update channel policy with new fee rate
            success = self.lightning_client.update_channel_policy(
                channel_id=channel_id,
                fee_rate=new_fee_rate * 1000,  # Convert ppm to milli-msat
                base_fee=1000  # 1 msat base fee
            )
            
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to update channel fee: {e}")
            return False
    
    def get_automation_status(self) -> Dict[str, Any]:
        """Get current automation status"""
        return {
            'is_running': self.is_running,
            'enabled_rules': len([r for r in self.enabled_rules if r.enabled]),
            'total_rules': len(self.enabled_rules),
            'check_interval_minutes': self.check_interval // 60,
            'total_adjustments': len(self.adjustment_history),
            'recent_adjustments': len([
                adj for adj in self.adjustment_history 
                if (datetime.now() - adj.timestamp).total_seconds() < 3600
            ]),
            'rules': [
                {
                    'name': rule.name,
                    'enabled': rule.enabled,
                    'trigger_condition': rule.trigger_condition,
                    'channel_filter': rule.channel_filter,
                    'adjustment_type': rule.adjustment_type,
                    'cooldown_minutes': rule.cooldown_minutes
                }
                for rule in self.enabled_rules
            ]
        }
    
    def get_adjustment_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent fee adjustment history"""
        recent_adjustments = list(self.adjustment_history)[-limit:]
        
        return [
            {
                'timestamp': adj.timestamp.isoformat(),
                'channel_id': adj.channel_id,
                'old_fee_rate': adj.old_fee_rate,
                'new_fee_rate': adj.new_fee_rate,
                'rule_name': adj.rule_name,
                'reason': adj.reason,
                'success': adj.success
            }
            for adj in recent_adjustments
        ]


# Global fee policy manager instance
_fee_policy_manager = None

def get_fee_policy_manager(lightning_client=None) -> AutomatedFeePolicyManager:
    """Get global fee policy manager instance"""
    global _fee_policy_manager
    if _fee_policy_manager is None:
        _fee_policy_manager = AutomatedFeePolicyManager(lightning_client)
    return _fee_policy_manager

def stop_fee_policy_manager():
    """Stop the global fee policy manager"""
    global _fee_policy_manager
    if _fee_policy_manager:
        _fee_policy_manager.stop_automation()
        _fee_policy_manager = None