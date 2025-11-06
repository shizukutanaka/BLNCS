"""
BLNCS Lightning Watchtower
Lightweight watchtower functionality for Lightning Network security
"""

import time
import json
import logging
import threading
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, asdict
from pathlib import Path
from collections import defaultdict, deque


@dataclass
class ChannelAlert:
    """Channel security alert"""
    channel_id: str
    alert_type: str  # 'breach_attempt', 'old_state', 'force_close'
    severity: str    # 'low', 'medium', 'high', 'critical'
    description: str
    detected_at: float
    block_height: int
    tx_id: Optional[str] = None
    resolved: bool = False


@dataclass
class ChannelState:
    """Tracked channel state"""
    channel_id: str
    local_balance: int
    remote_balance: int
    commitment_number: int
    last_update: float
    node_pubkey: str
    is_active: bool = True


class LightningWatchtower:
    """Lightweight Lightning Network watchtower"""

    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)

        self.monitored_channels: Dict[str, ChannelState] = {}
        self.alerts: List[ChannelAlert] = []
        self.alert_handlers: List[callable] = []

        self.channels_file = self.data_dir / "watched_channels.json"
        self.alerts_file = self.data_dir / "watchtower_alerts.json"

        self.monitoring_active = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.check_interval = 30  # seconds

        self.logger = logging.getLogger("BLNCS_Watchtower")

        self._load_data()

    def _load_data(self):
        """Load watchtower data from storage"""
        # Load monitored channels
        if self.channels_file.exists():
            try:
                with open(self.channels_file, 'r') as f:
                    data = json.load(f)
                    for channel_id, channel_data in data.items():
                        self.monitored_channels[channel_id] = ChannelState(**channel_data)

                self.logger.info(f"Loaded {len(self.monitored_channels)} monitored channels")
            except Exception as e:
                self.logger.error(f"Failed to load channels: {e}")

        # Load alerts
        if self.alerts_file.exists():
            try:
                with open(self.alerts_file, 'r') as f:
                    data = json.load(f)
                    for alert_data in data:
                        self.alerts.append(ChannelAlert(**alert_data))

                self.logger.info(f"Loaded {len(self.alerts)} alerts")
            except Exception as e:
                self.logger.error(f"Failed to load alerts: {e}")

    def _save_data(self):
        """Save watchtower data to storage"""
        try:
            # Save channels
            channel_data = {
                channel_id: asdict(channel)
                for channel_id, channel in self.monitored_channels.items()
            }
            with open(self.channels_file, 'w') as f:
                json.dump(channel_data, f, indent=2)

            # Save alerts
            alert_data = [asdict(alert) for alert in self.alerts]
            with open(self.alerts_file, 'w') as f:
                json.dump(alert_data, f, indent=2)

        except Exception as e:
            self.logger.error(f"Failed to save data: {e}")

    def add_channel_watch(self, channel_id: str, node_pubkey: str,
                         local_balance: int, remote_balance: int,
                         commitment_number: int = 0):
        """Add channel to watchtower monitoring"""
        channel_state = ChannelState(
            channel_id=channel_id,
            local_balance=local_balance,
            remote_balance=remote_balance,
            commitment_number=commitment_number,
            last_update=time.time(),
            node_pubkey=node_pubkey
        )

        self.monitored_channels[channel_id] = channel_state
        self._save_data()

        self.logger.info(f"Added channel to watchtower: {channel_id[:16]}...")

    def remove_channel_watch(self, channel_id: str):
        """Remove channel from watchtower monitoring"""
        if channel_id in self.monitored_channels:
            del self.monitored_channels[channel_id]
            self._save_data()
            self.logger.info(f"Removed channel from watchtower: {channel_id[:16]}...")

    def update_channel_state(self, channel_id: str, local_balance: int,
                           remote_balance: int, commitment_number: int):
        """Update channel state information"""
        if channel_id not in self.monitored_channels:
            self.logger.warning(f"Channel not monitored: {channel_id[:16]}...")
            return

        channel = self.monitored_channels[channel_id]

        # Check for potential issues
        if commitment_number < channel.commitment_number:
            self._create_alert(
                channel_id,
                "old_state",
                "high",
                f"Old commitment state detected: {commitment_number} < {channel.commitment_number}",
                0  # Block height would be retrieved from chain
            )

        # Detect significant balance changes
        balance_change = abs(local_balance - channel.local_balance)
        if balance_change > (channel.local_balance + channel.remote_balance) * 0.5:
            self._create_alert(
                channel_id,
                "large_balance_change",
                "medium",
                f"Large balance change detected: {balance_change} sats",
                0
            )

        # Update state
        channel.local_balance = local_balance
        channel.remote_balance = remote_balance
        channel.commitment_number = commitment_number
        channel.last_update = time.time()

        self._save_data()

    def _create_alert(self, channel_id: str, alert_type: str, severity: str,
                     description: str, block_height: int, tx_id: str = None):
        """Create and process security alert"""
        alert = ChannelAlert(
            channel_id=channel_id,
            alert_type=alert_type,
            severity=severity,
            description=description,
            detected_at=time.time(),
            block_height=block_height,
            tx_id=tx_id
        )

        self.alerts.append(alert)
        self._save_data()

        # Log alert
        log_level = {
            'low': self.logger.info,
            'medium': self.logger.warning,
            'high': self.logger.error,
            'critical': self.logger.critical
        }.get(severity, self.logger.info)

        log_level(f"WATCHTOWER ALERT [{severity.upper()}]: {description}")

        # Notify handlers
        for handler in self.alert_handlers:
            try:
                handler(alert)
            except Exception as e:
                self.logger.error(f"Alert handler error: {e}")

    def add_alert_handler(self, handler: callable):
        """Add alert notification handler"""
        self.alert_handlers.append(handler)

    def start_monitoring(self):
        """Start watchtower monitoring"""
        if self.monitoring_active:
            return

        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()

        self.logger.info("Watchtower monitoring started")

    def stop_monitoring(self):
        """Stop watchtower monitoring"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)

        self.logger.info("Watchtower monitoring stopped")

    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                self._check_all_channels()
                time.sleep(self.check_interval)
            except Exception as e:
                self.logger.error(f"Monitoring loop error: {e}")
                time.sleep(60)  # Longer wait on error

    def _check_all_channels(self):
        """Check all monitored channels for issues"""
        current_time = time.time()

        for channel_id, channel in self.monitored_channels.items():
            # Check for stale channel data
            if current_time - channel.last_update > 3600:  # 1 hour
                self._create_alert(
                    channel_id,
                    "stale_data",
                    "low",
                    f"Channel data stale for {(current_time - channel.last_update):.0f} seconds",
                    0
                )

            # Check if channel is still active
            if channel.is_active and current_time - channel.last_update > 86400:  # 24 hours
                channel.is_active = False
                self._create_alert(
                    channel_id,
                    "channel_inactive",
                    "medium",
                    "Channel appears to be inactive",
                    0
                )

    def simulate_breach_attempt(self, channel_id: str, old_commitment: int):
        """Simulate breach attempt detection (for testing)"""
        if channel_id not in self.monitored_channels:
            return

        self._create_alert(
            channel_id,
            "breach_attempt",
            "critical",
            f"Simulated breach attempt with old commitment {old_commitment}",
            750000,  # Simulated block height
            "abc123...def456"  # Simulated transaction ID
        )

    def get_active_alerts(self, severity: str = None) -> List[ChannelAlert]:
        """Get active (unresolved) alerts"""
        alerts = [alert for alert in self.alerts if not alert.resolved]

        if severity:
            alerts = [alert for alert in alerts if alert.severity == severity]

        return sorted(alerts, key=lambda a: a.detected_at, reverse=True)

    def resolve_alert(self, alert_index: int) -> bool:
        """Mark alert as resolved"""
        if 0 <= alert_index < len(self.alerts):
            self.alerts[alert_index].resolved = True
            self._save_data()
            self.logger.info(f"Alert resolved: {self.alerts[alert_index].alert_type}")
            return True
        return False

    def get_watchtower_stats(self) -> Dict[str, Any]:
        """Get watchtower statistics"""
        total_alerts = len(self.alerts)
        active_alerts = len(self.get_active_alerts())
        critical_alerts = len(self.get_active_alerts("critical"))

        alert_types = defaultdict(int)
        for alert in self.alerts:
            alert_types[alert.alert_type] += 1

        return {
            "monitored_channels": len(self.monitored_channels),
            "active_channels": sum(1 for ch in self.monitored_channels.values() if ch.is_active),
            "total_alerts": total_alerts,
            "active_alerts": active_alerts,
            "critical_alerts": critical_alerts,
            "alert_types": dict(alert_types),
            "monitoring_active": self.monitoring_active,
            "check_interval_seconds": self.check_interval
        }

    def cleanup_old_alerts(self, days_old: int = 30) -> int:
        """Remove old resolved alerts"""
        cutoff_time = time.time() - (days_old * 24 * 3600)

        old_alerts = [
            i for i, alert in enumerate(self.alerts)
            if alert.resolved and alert.detected_at < cutoff_time
        ]

        # Remove old alerts (in reverse order to maintain indices)
        for i in reversed(old_alerts):
            del self.alerts[i]

        if old_alerts:
            self._save_data()
            self.logger.info(f"Cleaned up {len(old_alerts)} old alerts")

        return len(old_alerts)


def create_watchtower(data_dir: str = "data") -> LightningWatchtower:
    """Create watchtower instance"""
    return LightningWatchtower(data_dir)


if __name__ == "__main__":
    # Test watchtower
    print("👁️ Testing Lightning Watchtower...")

    watchtower = create_watchtower("test_data")

    # Add test channel
    watchtower.add_channel_watch(
        "test_channel_12345678901234567890123456789012345678901234567890",
        "0234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12",
        1000000,  # 1M sats local
        500000,   # 500k sats remote
        100       # commitment number
    )

    # Start monitoring
    watchtower.start_monitoring()

    # Update channel state
    watchtower.update_channel_state(
        "test_channel_12345678901234567890123456789012345678901234567890",
        800000, 700000, 101
    )

    # Simulate security event
    watchtower.simulate_breach_attempt(
        "test_channel_12345678901234567890123456789012345678901234567890",
        95  # Old commitment number
    )

    # Get statistics
    stats = watchtower.get_watchtower_stats()
    print(f"👁️ Monitoring: {stats['monitored_channels']} channels")
    print(f"🚨 Active alerts: {stats['active_alerts']}")
    print(f"⚠️ Critical alerts: {stats['critical_alerts']}")

    # Get alerts
    alerts = watchtower.get_active_alerts()
    for alert in alerts:
        severity_icon = {"low": "ℹ️", "medium": "⚠️", "high": "🚨", "critical": "🔥"}
        icon = severity_icon.get(alert.severity, "📢")
        print(f"  {icon} {alert.alert_type}: {alert.description}")

    # Stop monitoring
    watchtower.stop_monitoring()

    # Cleanup
    import shutil
    shutil.rmtree("test_data", ignore_errors=True)

    print("✅ Watchtower test completed!")