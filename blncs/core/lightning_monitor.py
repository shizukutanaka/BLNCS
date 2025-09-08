"""
Lightning Network Monitoring System
Practical monitoring for Lightning Network operations.
"""

import time
import threading
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta
from collections import deque
from dataclasses import dataclass, field

from .logger import get_logger
from .config import get_config
from .cache import get_cache
from ..lightning.client import LightningClient


@dataclass
class ChannelMetrics:
    """Channel performance metrics"""
    channel_id: str
    local_balance: int = 0
    remote_balance: int = 0
    capacity: int = 0
    fee_earnings: int = 0
    routing_count: int = 0
    success_rate: float = 100.0
    last_activity: datetime = field(default_factory=datetime.now)
    health_score: float = 100.0


@dataclass
class NodeMetrics:
    """Node performance metrics"""
    online: bool = False
    num_channels: int = 0
    num_active_channels: int = 0
    total_capacity: int = 0
    total_local_balance: int = 0
    total_remote_balance: int = 0
    routing_fees_earned: int = 0
    payments_sent: int = 0
    payments_received: int = 0
    uptime_percentage: float = 0.0
    last_check: datetime = field(default_factory=datetime.now)


class LightningMonitor:
    """Monitor Lightning Network operations"""
    
    def __init__(self, client: Optional[LightningClient] = None):
        self.logger = get_logger(__name__)
        self.config = get_config()
        self.cache = get_cache()
        self.client = client or LightningClient()
        
        # Monitoring settings
        self.enabled = self.config.get('monitor.lightning_enabled', True)
        self.check_interval = self.config.get('monitor.lightning_interval', 60)
        self.alert_thresholds = {
            'channel_balance_min': self.config.get('monitor.channel_balance_min', 10),  # %
            'channel_balance_max': self.config.get('monitor.channel_balance_max', 90),  # %
            'node_uptime_min': self.config.get('monitor.node_uptime_min', 95),  # %
            'channel_inactive_hours': self.config.get('monitor.channel_inactive_hours', 24)
        }
        
        # Metrics storage
        self.node_metrics = NodeMetrics()
        self.channel_metrics: Dict[str, ChannelMetrics] = {}
        self.alerts: deque = deque(maxlen=100)
        self.metrics_history = deque(maxlen=1000)
        
        # Monitoring thread
        self._monitor_thread = None
        self._stop_monitoring = threading.Event()
        
        # Alert callbacks
        self.alert_callbacks: List[Callable[[Dict[str, Any]], None]] = []
    
    def start(self) -> None:
        """Start monitoring"""
        if not self.enabled:
            self.logger.info("Lightning monitoring is disabled")
            return
        
        if self._monitor_thread and self._monitor_thread.is_alive():
            self.logger.warning("Monitoring already running")
            return
        
        self._stop_monitoring.clear()
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        self.logger.info("Lightning monitoring started")
    
    def stop(self) -> None:
        """Stop monitoring"""
        self._stop_monitoring.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        self.logger.info("Lightning monitoring stopped")
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop"""
        while not self._stop_monitoring.is_set():
            try:
                # Collect metrics
                self._collect_node_metrics()
                self._collect_channel_metrics()
                
                # Check for issues
                self._check_alerts()
                
                # Store metrics history
                self._store_metrics()
                
                # Wait for next check
                self._stop_monitoring.wait(self.check_interval)
                
            except Exception as e:
                self.logger.error(f"Monitoring error: {e}")
                self._stop_monitoring.wait(30)  # Wait before retry
    
    def _collect_node_metrics(self) -> None:
        """Collect node-level metrics"""
        try:
            # Get node info
            info = self.client.get_info()
            balance = self.client.get_balance()
            
            # Update metrics
            self.node_metrics.online = info.get("synced_to_chain", False)
            self.node_metrics.num_channels = info.get("num_channels", 0)
            self.node_metrics.total_local_balance = balance.get("channel_local", 0)
            self.node_metrics.total_remote_balance = balance.get("channel_remote", 0)
            self.node_metrics.total_capacity = (
                self.node_metrics.total_local_balance + 
                self.node_metrics.total_remote_balance
            )
            self.node_metrics.last_check = datetime.now()
            
            # Calculate uptime
            if hasattr(self, '_uptime_checks'):
                self._uptime_checks.append(self.node_metrics.online)
                if len(self._uptime_checks) > 100:
                    self._uptime_checks.pop(0)
                self.node_metrics.uptime_percentage = (
                    sum(self._uptime_checks) / len(self._uptime_checks) * 100
                )
            else:
                self._uptime_checks = [self.node_metrics.online]
            
        except Exception as e:
            self.logger.error(f"Failed to collect node metrics: {e}")
            self.node_metrics.online = False
    
    def _collect_channel_metrics(self) -> None:
        """Collect channel-level metrics"""
        try:
            channels = self.client.list_channels()
            
            for channel in channels:
                chan_id = channel.get("chan_id", "")
                if not chan_id:
                    continue
                
                # Get or create channel metrics
                if chan_id not in self.channel_metrics:
                    self.channel_metrics[chan_id] = ChannelMetrics(channel_id=chan_id)
                
                metrics = self.channel_metrics[chan_id]
                
                # Update metrics
                metrics.local_balance = int(channel.get("local_balance", 0))
                metrics.remote_balance = int(channel.get("remote_balance", 0))
                metrics.capacity = int(channel.get("capacity", 0))
                
                # Calculate health score
                if metrics.capacity > 0:
                    balance_ratio = metrics.local_balance / metrics.capacity * 100
                    # Optimal balance is 50%, score decreases as it deviates
                    balance_score = 100 - abs(50 - balance_ratio)
                    
                    # Check if channel is active
                    active = channel.get("active", False)
                    active_score = 100 if active else 50
                    
                    # Combined health score
                    metrics.health_score = (balance_score + active_score) / 2
                
                # Update activity
                if channel.get("active", False):
                    metrics.last_activity = datetime.now()
                    self.node_metrics.num_active_channels += 1
                    
        except Exception as e:
            self.logger.error(f"Failed to collect channel metrics: {e}")
    
    def _check_alerts(self) -> None:
        """Check for alert conditions"""
        alerts = []
        
        # Check node uptime
        if self.node_metrics.uptime_percentage < self.alert_thresholds['node_uptime_min']:
            alerts.append({
                "type": "node_uptime",
                "severity": "warning",
                "message": f"Node uptime is low: {self.node_metrics.uptime_percentage:.1f}%",
                "timestamp": datetime.now()
            })
        
        # Check channel balances
        for chan_id, metrics in self.channel_metrics.items():
            if metrics.capacity > 0:
                balance_ratio = metrics.local_balance / metrics.capacity * 100
                
                if balance_ratio < self.alert_thresholds['channel_balance_min']:
                    alerts.append({
                        "type": "channel_balance",
                        "severity": "warning",
                        "channel_id": chan_id,
                        "message": f"Channel {chan_id} has low local balance: {balance_ratio:.1f}%",
                        "timestamp": datetime.now()
                    })
                elif balance_ratio > self.alert_thresholds['channel_balance_max']:
                    alerts.append({
                        "type": "channel_balance",
                        "severity": "warning",
                        "channel_id": chan_id,
                        "message": f"Channel {chan_id} has high local balance: {balance_ratio:.1f}%",
                        "timestamp": datetime.now()
                    })
                
                # Check channel inactivity
                inactive_hours = (datetime.now() - metrics.last_activity).total_seconds() / 3600
                if inactive_hours > self.alert_thresholds['channel_inactive_hours']:
                    alerts.append({
                        "type": "channel_inactive",
                        "severity": "info",
                        "channel_id": chan_id,
                        "message": f"Channel {chan_id} inactive for {inactive_hours:.1f} hours",
                        "timestamp": datetime.now()
                    })
        
        # Process alerts
        for alert in alerts:
            self.alerts.append(alert)
            self.logger.warning(f"Alert: {alert['message']}")
            
            # Trigger callbacks
            for callback in self.alert_callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    self.logger.error(f"Alert callback error: {e}")
    
    def _store_metrics(self) -> None:
        """Store metrics snapshot"""
        snapshot = {
            "timestamp": datetime.now(),
            "node": {
                "online": self.node_metrics.online,
                "channels": self.node_metrics.num_channels,
                "active_channels": self.node_metrics.num_active_channels,
                "capacity": self.node_metrics.total_capacity,
                "uptime": self.node_metrics.uptime_percentage
            },
            "channels": {
                chan_id: {
                    "local": m.local_balance,
                    "remote": m.remote_balance,
                    "health": m.health_score
                }
                for chan_id, m in self.channel_metrics.items()
            }
        }
        self.metrics_history.append(snapshot)
    
    def get_status(self) -> Dict[str, Any]:
        """Get current monitoring status"""
        return {
            "monitoring": self._monitor_thread.is_alive() if self._monitor_thread else False,
            "node_online": self.node_metrics.online,
            "channels_total": self.node_metrics.num_channels,
            "channels_active": self.node_metrics.num_active_channels,
            "total_capacity": self.node_metrics.total_capacity,
            "uptime_percentage": self.node_metrics.uptime_percentage,
            "recent_alerts": list(self.alerts)[-10:],
            "last_check": self.node_metrics.last_check.isoformat()
        }
    
    def get_channel_recommendations(self) -> List[Dict[str, Any]]:
        """Get channel management recommendations"""
        recommendations = []
        
        for chan_id, metrics in self.channel_metrics.items():
            if metrics.capacity == 0:
                continue
            
            balance_ratio = metrics.local_balance / metrics.capacity * 100
            
            # Recommend rebalancing
            if balance_ratio < 20:
                recommendations.append({
                    "channel_id": chan_id,
                    "action": "rebalance_inbound",
                    "reason": f"Low local balance ({balance_ratio:.1f}%)",
                    "priority": "high"
                })
            elif balance_ratio > 80:
                recommendations.append({
                    "channel_id": chan_id,
                    "action": "rebalance_outbound",
                    "reason": f"High local balance ({balance_ratio:.1f}%)",
                    "priority": "high"
                })
            
            # Recommend closing inactive channels
            inactive_hours = (datetime.now() - metrics.last_activity).total_seconds() / 3600
            if inactive_hours > 168:  # 7 days
                recommendations.append({
                    "channel_id": chan_id,
                    "action": "consider_closing",
                    "reason": f"Inactive for {inactive_hours/24:.1f} days",
                    "priority": "low"
                })
        
        return recommendations
    
    def register_alert_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Register callback for alerts"""
        self.alert_callbacks.append(callback)


# Global monitor instance
_monitor = None

def get_lightning_monitor(client: Optional[LightningClient] = None) -> LightningMonitor:
    """Get or create global Lightning monitor instance"""
    global _monitor
    if _monitor is None:
        _monitor = LightningMonitor(client)
    return _monitor