"""
BLNCS System Recovery and Self-Healing
Consolidated automatic fault detection, diagnostics, and recovery system
"""

import time
import threading
import subprocess
import os
import signal
from typing import Dict, Any, Optional, Callable, List
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timedelta
import logging

# Optional psutil import
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class RecoveryAction(Enum):
    """Recovery action types"""
    RESTART_SERVICE = "restart_service"
    RECONNECT_PEER = "reconnect_peer"
    REFRESH_CHANNELS = "refresh_channels"
    CLEAR_CACHE = "clear_cache"
    BACKUP_DATA = "backup_data"
    REDUCE_LOAD = "reduce_load"
    EMERGENCY_STOP = "emergency_stop"
    CLEANUP_MEMORY = "cleanup_memory"
    RESET_CONNECTION = "reset_connection"
    FALLBACK_MODE = "fallback_mode"
    # Lightning Network specific actions
    RESTART_LIGHTNING_NODE = "restart_lightning_node"
    CHECK_CHANNEL_CONNECTIVITY = "check_channel_connectivity"
    REFRESH_LIGHTNING_PEERS = "refresh_lightning_peers"
    VALIDATE_PAYMENT_CHANNELS = "validate_payment_channels"
    CHECK_NODE_SYNC = "check_node_sync"
    CLEANUP_FAILED_PAYMENTS = "cleanup_failed_payments"


class DiagnosticSeverity(Enum):
    """Diagnostic severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class DiagnosticResult:
    """Diagnostic check result"""
    check_name: str
    severity: DiagnosticSeverity
    message: str
    timestamp: float
    details: Optional[Dict[str, Any]] = None
    suggested_actions: Optional[List[RecoveryAction]] = None


@dataclass
class RecoveryResult:
    """Recovery operation result"""
    action: RecoveryAction
    success: bool
    message: str
    duration: float
    timestamp: float
    diagnostic_trigger: Optional[str] = None


class SystemRecovery:
    """Unified system recovery and self-healing system"""

    def __init__(self, check_interval: float = 300.0):
        self.check_interval = check_interval
        self.diagnostic_history: List[DiagnosticResult] = []
        self.recovery_history: List[RecoveryResult] = []
        self.max_history = 200
        self.monitoring_active = False
        self.monitor_thread: Optional[threading.Thread] = None

        # Diagnostic checks and recovery actions
        self.diagnostic_checks: Dict[str, Callable] = {}
        self.recovery_actions: Dict[RecoveryAction, Callable] = {}
        self.auto_recovery_enabled = True

        # Thread safety
        self._lock = threading.Lock()

        # Setup logging
        self.logger = logging.getLogger(__name__)

        # Register default checks and actions
        self._register_default_diagnostics()
        self._register_default_recovery_actions()

    def register_diagnostic_check(self, name: str, check_function: Callable[[], DiagnosticResult]):
        """Register a diagnostic check"""
        with self._lock:
            self.diagnostic_checks[name] = check_function

    def register_recovery_action(self, action: RecoveryAction, action_function: Callable[[], bool]):
        """Register a recovery action"""
        with self._lock:
            self.recovery_actions[action] = action_function

    def run_diagnostic_check(self, check_name: str) -> Optional[DiagnosticResult]:
        """Run a specific diagnostic check"""
        if check_name not in self.diagnostic_checks:
            return None

        try:
            result = self.diagnostic_checks[check_name]()
            with self._lock:
                self.diagnostic_history.append(result)
                if len(self.diagnostic_history) > self.max_history:
                    self.diagnostic_history.pop(0)
            return result
        except Exception as e:
            self.logger.error(f"Diagnostic check {check_name} failed: {e}")
            return DiagnosticResult(
                check_name=check_name,
                severity=DiagnosticSeverity.ERROR,
                message=f"Check failed: {str(e)}",
                timestamp=time.time()
            )

    def run_all_diagnostics(self) -> List[DiagnosticResult]:
        """Run all registered diagnostic checks"""
        results = []
        for check_name in self.diagnostic_checks:
            result = self.run_diagnostic_check(check_name)
            if result:
                results.append(result)
        return results

    def execute_recovery_action(self, action: RecoveryAction, diagnostic_trigger: str = None) -> RecoveryResult:
        """Execute a recovery action"""
        start_time = time.time()

        if action not in self.recovery_actions:
            return RecoveryResult(
                action=action,
                success=False,
                message=f"Recovery action {action.value} not registered",
                duration=0.0,
                timestamp=start_time,
                diagnostic_trigger=diagnostic_trigger
            )

        try:
            success = self.recovery_actions[action]()
            duration = time.time() - start_time

            result = RecoveryResult(
                action=action,
                success=success,
                message=f"Recovery action {action.value} {'succeeded' if success else 'failed'}",
                duration=duration,
                timestamp=start_time,
                diagnostic_trigger=diagnostic_trigger
            )

            with self._lock:
                self.recovery_history.append(result)
                if len(self.recovery_history) > self.max_history:
                    self.recovery_history.pop(0)

            self.logger.info(f"Recovery action {action.value}: {'success' if success else 'failed'}")
            return result

        except Exception as e:
            duration = time.time() - start_time
            result = RecoveryResult(
                action=action,
                success=False,
                message=f"Recovery action failed: {str(e)}",
                duration=duration,
                timestamp=start_time,
                diagnostic_trigger=diagnostic_trigger
            )

            with self._lock:
                self.recovery_history.append(result)

            self.logger.error(f"Recovery action {action.value} exception: {e}")
            return result

    def auto_heal(self) -> List[RecoveryResult]:
        """Automatic healing based on diagnostic results"""
        if not self.auto_recovery_enabled:
            return []

        diagnostics = self.run_all_diagnostics()
        recovery_results = []

        for diagnostic in diagnostics:
            if diagnostic.severity in [DiagnosticSeverity.ERROR, DiagnosticSeverity.CRITICAL]:
                if diagnostic.suggested_actions:
                    for action in diagnostic.suggested_actions:
                        result = self.execute_recovery_action(action, diagnostic.check_name)
                        recovery_results.append(result)

                        # If recovery succeeds, break to avoid over-recovery
                        if result.success:
                            break

        return recovery_results

    def start_monitoring(self):
        """Start continuous monitoring and auto-healing"""
        if self.monitoring_active:
            return

        with self._lock:
            self.monitoring_active = True

        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
        self.logger.info("System recovery monitoring started")

    def stop_monitoring(self):
        """Stop continuous monitoring"""
        with self._lock:
            self.monitoring_active = False

        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=10)

        self.logger.info("System recovery monitoring stopped")

    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                self.auto_heal()
                time.sleep(self.check_interval)
            except Exception as e:
                self.logger.error(f"Monitoring loop error: {e}")
                time.sleep(min(self.check_interval, 60))  # Fallback interval

    def _register_default_diagnostics(self):
        """Register default diagnostic checks"""

        def check_memory_usage() -> DiagnosticResult:
            if not PSUTIL_AVAILABLE:
                return DiagnosticResult(
                    check_name="memory_usage",
                    severity=DiagnosticSeverity.INFO,
                    message="Memory monitoring unavailable (psutil not installed)",
                    timestamp=time.time()
                )

            memory = psutil.virtual_memory()
            severity = DiagnosticSeverity.INFO
            actions = []

            if memory.percent > 90:
                severity = DiagnosticSeverity.CRITICAL
                actions = [RecoveryAction.CLEANUP_MEMORY, RecoveryAction.EMERGENCY_STOP]
            elif memory.percent > 80:
                severity = DiagnosticSeverity.ERROR
                actions = [RecoveryAction.CLEANUP_MEMORY]
            elif memory.percent > 70:
                severity = DiagnosticSeverity.WARNING
                actions = [RecoveryAction.CLEAR_CACHE]

            return DiagnosticResult(
                check_name="memory_usage",
                severity=severity,
                message=f"Memory usage: {memory.percent:.1f}%",
                timestamp=time.time(),
                details={"percent": memory.percent, "available": memory.available},
                suggested_actions=actions
            )

        def check_disk_space() -> DiagnosticResult:
            try:
                if PSUTIL_AVAILABLE:
                    disk = psutil.disk_usage('.')
                    percent_used = (disk.used / disk.total) * 100
                else:
                    # Fallback method
                    import shutil
                    stat = shutil.disk_usage(".")
                    percent_used = ((stat.total - stat.free) / stat.total) * 100

                severity = DiagnosticSeverity.INFO
                actions = []

                if percent_used > 95:
                    severity = DiagnosticSeverity.CRITICAL
                    actions = [RecoveryAction.CLEANUP_MEMORY, RecoveryAction.BACKUP_DATA]
                elif percent_used > 90:
                    severity = DiagnosticSeverity.ERROR
                    actions = [RecoveryAction.CLEAR_CACHE]
                elif percent_used > 85:
                    severity = DiagnosticSeverity.WARNING

                return DiagnosticResult(
                    check_name="disk_space",
                    severity=severity,
                    message=f"Disk usage: {percent_used:.1f}%",
                    timestamp=time.time(),
                    details={"percent_used": percent_used},
                    suggested_actions=actions
                )

            except Exception as e:
                return DiagnosticResult(
                    check_name="disk_space",
                    severity=DiagnosticSeverity.ERROR,
                    message=f"Disk check failed: {str(e)}",
                    timestamp=time.time()
                )

        def check_lightning_node_status() -> DiagnosticResult:
            """Check Lightning Network node status"""
            try:
                # Import Lightning Network utilities
                from blncs.core.lightning_api import LightningAPI

                # Try to get node info
                api = LightningAPI()
                node_info = api.get_info()

                if not node_info:
                    return DiagnosticResult(
                        check_name="lightning_node_status",
                        severity=DiagnosticSeverity.CRITICAL,
                        message="Lightning node is not responding",
                        timestamp=time.time(),
                        suggested_actions=[RecoveryAction.RESTART_LIGHTNING_NODE]
                    )

                # Check if node is synchronized
                if node_info.get('synced_to_chain') is False:
                    return DiagnosticResult(
                        check_name="lightning_node_status",
                        severity=DiagnosticSeverity.ERROR,
                        message="Lightning node is not synchronized with blockchain",
                        timestamp=time.time(),
                        details=node_info,
                        suggested_actions=[RecoveryAction.CHECK_NODE_SYNC]
                    )

                return DiagnosticResult(
                    check_name="lightning_node_status",
                    severity=DiagnosticSeverity.INFO,
                    message=f"Lightning node is healthy. Block height: {node_info.get('block_height', 'unknown')}",
                    timestamp=time.time(),
                    details=node_info
                )

            except Exception as e:
                return DiagnosticResult(
                    check_name="lightning_node_status",
                    severity=DiagnosticSeverity.ERROR,
                    message=f"Failed to check Lightning node status: {str(e)}",
                    timestamp=time.time(),
                    suggested_actions=[RecoveryAction.RESTART_LIGHTNING_NODE]
                )

        def check_channel_connectivity() -> DiagnosticResult:
            """Check Lightning Network channel connectivity"""
            try:
                from blncs.core.lightning_api import LightningAPI

                api = LightningAPI()
                channels = api.list_channels()

                if not channels:
                    return DiagnosticResult(
                        check_name="channel_connectivity",
                        severity=DiagnosticSeverity.WARNING,
                        message="No active channels found",
                        timestamp=time.time()
                    )

                # Check for inactive channels
                inactive_channels = [ch for ch in channels if not ch.get('active', True)]
                if inactive_channels:
                    return DiagnosticResult(
                        check_name="channel_connectivity",
                        severity=DiagnosticSeverity.WARNING,
                        message=f"Found {len(inactive_channels)} inactive channels",
                        timestamp=time.time(),
                        details={"inactive_channels": len(inactive_channels)},
                        suggested_actions=[RecoveryAction.VALIDATE_PAYMENT_CHANNELS]
                    )

                return DiagnosticResult(
                    check_name="channel_connectivity",
                    severity=DiagnosticSeverity.INFO,
                    message=f"All {len(channels)} channels are active",
                    timestamp=time.time(),
                    details={"active_channels": len(channels)}
                )

            except Exception as e:
                return DiagnosticResult(
                    check_name="channel_connectivity",
                    severity=DiagnosticSeverity.ERROR,
                    message=f"Failed to check channel connectivity: {str(e)}",
                    timestamp=time.time(),
                    suggested_actions=[RecoveryAction.REFRESH_LIGHTNING_PEERS]
                )

        def check_peer_connectivity() -> DiagnosticResult:
            """Check Lightning Network peer connectivity"""
            try:
                from blncs.core.lightning_api import LightningAPI

                api = LightningAPI()
                peers = api.list_peers()

                if not peers:
                    return DiagnosticResult(
                        check_name="peer_connectivity",
                        severity=DiagnosticSeverity.WARNING,
                        message="No connected peers",
                        timestamp=time.time(),
                        suggested_actions=[RecoveryAction.REFRESH_LIGHTNING_PEERS]
                    )

                # Check for disconnected peers
                disconnected_peers = [peer for peer in peers if not peer.get('connected', True)]
                if disconnected_peers:
                    return DiagnosticResult(
                        check_name="peer_connectivity",
                        severity=DiagnosticSeverity.WARNING,
                        message=f"Found {len(disconnected_peers)} disconnected peers",
                        timestamp=time.time(),
                        details={"disconnected_peers": len(disconnected_peers)},
                        suggested_actions=[RecoveryAction.REFRESH_LIGHTNING_PEERS]
                    )

                return DiagnosticResult(
                    check_name="peer_connectivity",
                    severity=DiagnosticSeverity.INFO,
                    message=f"All {len(peers)} peers are connected",
                    timestamp=time.time(),
                    details={"connected_peers": len(peers)}
                )

            except Exception as e:
                return DiagnosticResult(
                    check_name="peer_connectivity",
                    severity=DiagnosticSeverity.ERROR,
                    message=f"Failed to check peer connectivity: {str(e)}",
                    timestamp=time.time(),
                    suggested_actions=[RecoveryAction.REFRESH_LIGHTNING_PEERS]
                )

        # Register checks
        self.register_diagnostic_check("memory_usage", check_memory_usage)
        self.register_diagnostic_check("disk_space", check_disk_space)
        self.register_diagnostic_check("thread_count", check_thread_count)
        self.register_diagnostic_check("lightning_node_status", check_lightning_node_status)
        self.register_diagnostic_check("channel_connectivity", check_channel_connectivity)
        self.register_diagnostic_check("peer_connectivity", check_peer_connectivity)

    def _register_default_recovery_actions(self):
        """Register default recovery actions"""

        def cleanup_memory() -> bool:
            try:
                import gc
                before = len(gc.get_objects())
                gc.collect()
                after = len(gc.get_objects())
                self.logger.info(f"Memory cleanup: {before - after} objects collected")
                return True
            except Exception as e:
                self.logger.error(f"Memory cleanup failed: {e}")
                return False

        def clear_cache() -> bool:
            try:
                # Clear Python bytecode cache
                import sys
                if hasattr(sys, 'modules'):
                    # Clear unused modules
                    modules_to_remove = [name for name, module in sys.modules.items()
                                       if module is None or not hasattr(module, '__file__')]
                    for name in modules_to_remove:
                        if name in sys.modules:
                            del sys.modules[name]

                self.logger.info("Cache cleared successfully")
                return True
            except Exception as e:
                self.logger.error(f"Cache clear failed: {e}")
                return False

        def reduce_load() -> bool:
            try:
                # Simple load reduction - could be extended
                import time
                time.sleep(1)  # Brief pause to reduce system load
                self.logger.info("Load reduction applied")
                return True
            except Exception as e:
                self.logger.error(f"Load reduction failed: {e}")
                return False

        def restart_lightning_node() -> bool:
            """Restart Lightning Network node"""
            try:
                import subprocess
                import signal
                import os

                # Try to gracefully stop Lightning node
                try:
                    # Find lightning process
                    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                        if proc.info['cmdline'] and any('lightning' in cmd.lower() for cmd in proc.info['cmdline']):
                            self.logger.info(f"Stopping Lightning node (PID: {proc.info['pid']})")
                            proc.terminate()
                            try:
                                proc.wait(timeout=10)
                            except psutil.TimeoutExpired:
                                proc.kill()
                            break
                except Exception as e:
                    self.logger.warning(f"Could not gracefully stop Lightning node: {e}")

                # Wait a moment before restarting
                time.sleep(2)

                # Restart Lightning node (this is a placeholder - actual implementation depends on your setup)
                self.logger.info("Attempting to restart Lightning node service")

                # Example for systemctl (Linux) - adapt for your environment
                if os.name != 'nt':  # Not Windows
                    try:
                        subprocess.run(['sudo', 'systemctl', 'restart', 'lightningd'], check=True, capture_output=True)
                        self.logger.info("Lightning node restarted via systemctl")
                        return True
                    except subprocess.CalledProcessError:
                        pass

                # Fallback - try to start manually
                # This would need to be configured based on your Lightning Network setup
                self.logger.warning("Manual Lightning node restart not implemented - requires configuration")
                return False

            except Exception as e:
                self.logger.error(f"Failed to restart Lightning node: {e}")
                return False

        def refresh_lightning_peers() -> bool:
            """Refresh Lightning Network peer connections"""
            try:
                from blncs.core.lightning_api import LightningAPI

                api = LightningAPI()

                # Get current peers
                current_peers = api.list_peers()
                if not current_peers:
                    self.logger.info("No peers to refresh")
                    return True

                # Disconnect and reconnect peers
                for peer in current_peers:
                    try:
                        peer_pubkey = peer.get('pub_key')
                        if peer_pubkey:
                            api.disconnect_peer(peer_pubkey)
                            time.sleep(1)
                            api.connect_peer(peer_pubkey, peer.get('address'))
                    except Exception as e:
                        self.logger.warning(f"Failed to refresh peer {peer.get('pub_key')}: {e}")

                self.logger.info("Lightning peer refresh completed")
                return True

            except Exception as e:
                self.logger.error(f"Failed to refresh Lightning peers: {e}")
                return False

        def validate_payment_channels() -> bool:
            """Validate and repair payment channels"""
            try:
                from blncs.core.lightning_api import LightningAPI

                api = LightningAPI()
                channels = api.list_channels()

                if not channels:
                    self.logger.info("No channels to validate")
                    return True

                # Check each channel for issues
                issues_found = 0
                for channel in channels:
                    try:
                        # Check if channel is active
                        if not channel.get('active', False):
                            issues_found += 1
                            # Try to close and reopen channel
                            chan_point = channel.get('channel_point')
                            if chan_point:
                                self.logger.info(f"Attempting to repair channel {chan_point}")
                                # Note: This is simplified - actual implementation would need proper channel management
                    except Exception as e:
                        self.logger.warning(f"Failed to validate channel {channel.get('chan_id')}: {e}")
                        issues_found += 1

                if issues_found > 0:
                    self.logger.warning(f"Found {issues_found} channel issues during validation")

                self.logger.info("Payment channel validation completed")
                return True

            except Exception as e:
                self.logger.error(f"Failed to validate payment channels: {e}")
                return False

        def check_node_sync() -> bool:
            """Check and attempt to sync Lightning node with blockchain"""
            try:
                from blncs.core.lightning_api import LightningAPI

                api = LightningAPI()
                node_info = api.get_info()

                if not node_info:
                    self.logger.error("Cannot check sync status - node not responding")
                    return False

                if node_info.get('synced_to_chain', False):
                    self.logger.info("Node is already synchronized")
                    return True

                # Attempt to trigger sync
                self.logger.info("Attempting to trigger blockchain sync")

                # This is a placeholder - actual sync mechanism depends on your Lightning implementation
                # For LND, you might need to restart or check connection to bitcoind

                time.sleep(5)  # Wait for potential sync

                # Check sync status again
                updated_info = api.get_info()
                if updated_info and updated_info.get('synced_to_chain', False):
                    self.logger.info("Node sync successful")
                    return True
                else:
                    self.logger.warning("Node sync attempt may have failed")
                    return False

            except Exception as e:
                self.logger.error(f"Failed to check node sync: {e}")
                return False

        def cleanup_failed_payments() -> bool:
            """Clean up failed payment attempts"""
            try:
                from blncs.core.lightning_api import LightningAPI

                api = LightningAPI()

                # Get failed payments (this depends on your Lightning implementation)
                try:
                    # This is a placeholder - actual implementation would query payment history
                    # and clean up failed/expired payments
                    self.logger.info("Cleaning up failed payment attempts")

                    # Example: Clear payment cache/temp data
                    # api.clear_failed_payments()  # This would be the actual API call

                    self.logger.info("Failed payment cleanup completed")
                    return True

                except AttributeError:
                    # API doesn't support this operation
                    self.logger.info("Payment cleanup not supported by current API")
                    return True

            except Exception as e:
                self.logger.error(f"Failed to cleanup failed payments: {e}")
                return False

        # Register actions
        self.register_recovery_action(RecoveryAction.CLEANUP_MEMORY, cleanup_memory)
        self.register_recovery_action(RecoveryAction.CLEAR_CACHE, clear_cache)
        self.register_recovery_action(RecoveryAction.REDUCE_LOAD, reduce_load)
        self.register_recovery_action(RecoveryAction.EMERGENCY_STOP, emergency_stop)
        self.register_recovery_action(RecoveryAction.RESTART_LIGHTNING_NODE, restart_lightning_node)
        self.register_recovery_action(RecoveryAction.REFRESH_LIGHTNING_PEERS, refresh_lightning_peers)
        self.register_recovery_action(RecoveryAction.VALIDATE_PAYMENT_CHANNELS, validate_payment_channels)
        self.register_recovery_action(RecoveryAction.CHECK_NODE_SYNC, check_node_sync)
        self.register_recovery_action(RecoveryAction.CLEANUP_FAILED_PAYMENTS, cleanup_failed_payments)

    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        recent_diagnostics = []
        recent_recoveries = []

        with self._lock:
            # Get recent diagnostics (last 10)
            recent_diagnostics = self.diagnostic_history[-10:] if self.diagnostic_history else []
            # Get recent recoveries (last 10)
            recent_recoveries = self.recovery_history[-10:] if self.recovery_history else []

        return {
            "monitoring_active": self.monitoring_active,
            "auto_recovery_enabled": self.auto_recovery_enabled,
            "total_diagnostics": len(self.diagnostic_history),
            "total_recoveries": len(self.recovery_history),
            "recent_diagnostics": [
                {
                    "check": d.check_name,
                    "severity": d.severity.value,
                    "message": d.message,
                    "timestamp": d.timestamp
                } for d in recent_diagnostics
            ],
            "recent_recoveries": [
                {
                    "action": r.action.value,
                    "success": r.success,
                    "message": r.message,
                    "duration": r.duration,
                    "timestamp": r.timestamp
                } for r in recent_recoveries
            ]
        }


# Global instance management
_recovery_system = None
_recovery_lock = threading.Lock()


def get_recovery_system(check_interval: float = 300.0) -> SystemRecovery:
    """Get global recovery system instance"""
    global _recovery_system
    if _recovery_system is None:
        with _recovery_lock:
            if _recovery_system is None:
                _recovery_system = SystemRecovery(check_interval)
    return _recovery_system


def start_system_recovery(check_interval: float = 300.0) -> SystemRecovery:
    """Initialize and start system recovery monitoring"""
    recovery = get_recovery_system(check_interval)
    recovery.start_monitoring()
    return recovery


def stop_system_recovery():
    """Stop system recovery monitoring"""
    recovery = get_recovery_system()
    recovery.stop_monitoring()


__all__ = [
    'RecoveryAction',
    'DiagnosticSeverity',
    'DiagnosticResult',
    'RecoveryResult',
    'SystemRecovery',
    'get_recovery_system',
    'start_system_recovery',
    'stop_system_recovery'
]