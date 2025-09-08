"""
Wallet Monitoring Module
Handles wallet balance and channel state monitoring.
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Callable
import logging
import threading

from .data_models import WalletMetric


class WalletMonitor:
    """Handles wallet balance and channel monitoring"""
    
    def __init__(self, logger: logging.Logger, config, history_recorder):
        self.logger = logger
        self.config = config
        self.history_recorder = history_recorder
        
        # Configuration
        self.alert_threshold = config.get('monitor.alert_threshold', 10000)  # sats
        
        # State tracking
        self.last_balance = None
        self.last_channel_balance = None
        self.alerts = []
        self.alert_callbacks = []
        self.monitor_lock = threading.Lock()
    
    def check_wallet_status(self, client) -> Optional[WalletMetric]:
        """Check current wallet status and return metrics"""
        try:
            balance = client.get_balance()
            channels = client.list_channels()
            
            # Calculate channel totals
            channel_local = sum(ch.get('local_balance', 0) for ch in channels)
            channel_remote = sum(ch.get('remote_balance', 0) for ch in channels)
            channel_capacity = sum(ch.get('capacity', 0) for ch in channels)
            
            return WalletMetric(
                timestamp=datetime.now(),
                wallet_balance=balance.get('total', 0),
                channel_local=channel_local,
                channel_remote=channel_remote,
                channel_capacity=channel_capacity,
                total_balance=balance.get('total', 0) + channel_local,
                active_channels=len([ch for ch in channels if ch.get('active', False)]),
                total_channels=len(channels)
            )
        except Exception as e:
            self.logger.warning(f"Wallet status check error: {e}")
            return None
    
    def check_balance_changes(self, wallet_metric: WalletMetric) -> None:
        """Check for balance changes and record them"""
        if self.last_balance is None:
            self.last_balance = wallet_metric.total_balance
            self.last_channel_balance = wallet_metric.channel_local
            return
        
        # Detect balance changes
        balance_change = wallet_metric.total_balance - self.last_balance
        channel_change = wallet_metric.channel_local - self.last_channel_balance
        
        if abs(balance_change) > 0:
            self.logger.info(f"Balance change detected: {balance_change:+} sats (total: {wallet_metric.total_balance} sats)")
            
            # Record to history
            self.history_recorder('balance_change', {
                'previous': self.last_balance,
                'current': wallet_metric.total_balance,
                'change': balance_change,
                'type': 'increase' if balance_change > 0 else 'decrease'
            })
        
        if abs(channel_change) > 0:
            self.logger.info(f"Channel balance change: {channel_change:+} sats")
        
        # Update tracking
        self.last_balance = wallet_metric.total_balance
        self.last_channel_balance = wallet_metric.channel_local
    
    def check_alerts(self, wallet_metric: WalletMetric) -> None:
        """Check for wallet alert conditions"""
        alerts_triggered = []
        
        # Low balance alert
        if wallet_metric.total_balance < self.alert_threshold:
            alerts_triggered.append({
                'type': 'low_balance',
                'message': f"Balance below threshold: {wallet_metric.total_balance} sats < {self.alert_threshold} sats",
                'severity': 'warning',
                'timestamp': datetime.now()
            })
        
        # No channels alert
        if wallet_metric.total_channels == 0:
            alerts_triggered.append({
                'type': 'no_channels',
                'message': "No active channels available",
                'severity': 'info',
                'timestamp': datetime.now()
            })
        
        # Inactive channels alert
        inactive_channels = wallet_metric.total_channels - wallet_metric.active_channels
        if inactive_channels > 0:
            alerts_triggered.append({
                'type': 'inactive_channels',
                'message': f"{inactive_channels} inactive channels detected",
                'severity': 'info',
                'timestamp': datetime.now()
            })
        
        # Process alerts
        for alert in alerts_triggered:
            self._handle_alert(alert)
    
    def add_alert_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Add alert callback function"""
        self.alert_callbacks.append(callback)
    
    def get_wallet_summary(self, wallet_history: List[WalletMetric]) -> Dict[str, Any]:
        """Generate wallet summary from history"""
        if not wallet_history:
            return {'status': 'no_data'}
        
        latest = wallet_history[-1]
        
        # Calculate 24-hour statistics
        cutoff_time = datetime.now() - timedelta(hours=24)
        history_24h = [w for w in wallet_history if w.timestamp >= cutoff_time]
        
        change_24h = 0
        if len(history_24h) > 1:
            balance_24h_ago = history_24h[0].total_balance
            change_24h = latest.total_balance - balance_24h_ago
        
        return {
            'current_balance': latest.total_balance,
            'wallet_balance': latest.wallet_balance,
            'channel_balance': latest.channel_local,
            'channel_capacity': latest.channel_capacity,
            'active_channels': latest.active_channels,
            'total_channels': latest.total_channels,
            'change_24h': change_24h,
            'last_update': latest.timestamp.isoformat()
        }
    
    def _handle_alert(self, alert: Dict[str, Any]) -> None:
        """Handle wallet alert with deduplication"""
        with self.monitor_lock:
            # Check for duplicate alerts (within 5 minutes)
            recent_alerts = [
                a for a in self.alerts 
                if a['type'] == alert['type'] 
                and (datetime.now() - a['timestamp']).total_seconds() < 300
            ]
            
            if not recent_alerts:
                self.alerts.append(alert)
                self.logger.warning(f"Wallet alert: {alert['message']}")
                
                # Execute callbacks
                for callback in self.alert_callbacks:
                    try:
                        callback(alert)
                    except Exception as e:
                        self.logger.error(f"Alert callback error: {e}")