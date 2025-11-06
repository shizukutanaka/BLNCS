#!/usr/bin/env python3
"""
BLNCS Lightweight System Monitor
Real-time system monitoring with minimal overhead
"""

import os
import sys
import time
import json
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class SystemSnapshot:
    """System state snapshot"""
    timestamp: float
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    network_io: Dict[str, int]
    process_count: int
    thread_count: int

class LightweightSystemMonitor:
    """Lightweight system monitoring"""

    def __init__(self):
        self.last_snapshot: Optional[SystemSnapshot] = None
        self.history: list = []
        self.max_history = 100

    def take_snapshot(self) -> SystemSnapshot:
        """Take a system snapshot"""
        try:
            import psutil

            snapshot = SystemSnapshot(
                timestamp=time.time(),
                cpu_percent=psutil.cpu_percent(interval=0.1),
                memory_percent=psutil.virtual_memory().percent,
                disk_percent=psutil.disk_usage('/').percent,
                network_io=self._get_network_io(),
                process_count=len(psutil.pids()),
                thread_count=sum(p.num_threads() for p in psutil.process_iter() if p.num_threads())
            )

            self.last_snapshot = snapshot
            self.history.append(snapshot)

            if len(self.history) > self.max_history:
                self.history.pop(0)

            return snapshot

        except ImportError:
            # Fallback without psutil
            snapshot = SystemSnapshot(
                timestamp=time.time(),
                cpu_percent=0,
                memory_percent=0,
                disk_percent=0,
                network_io={'bytes_sent': 0, 'bytes_recv': 0},
                process_count=0,
                thread_count=0
            )
            return snapshot

    def _get_network_io(self) -> Dict[str, int]:
        """Get network I/O statistics"""
        try:
            import psutil
            net_io = psutil.net_io_counters()
            return {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv
            }
        except:
            return {'bytes_sent': 0, 'bytes_recv': 0}

    def get_health_score(self) -> int:
        """Calculate system health score"""
        if not self.last_snapshot:
            return 0

        score = 100

        # CPU usage penalty
        if self.last_snapshot.cpu_percent > 80:
            score -= 30
        elif self.last_snapshot.cpu_percent > 60:
            score -= 15

        # Memory usage penalty
        if self.last_snapshot.memory_percent > 85:
            score -= 25
        elif self.last_snapshot.memory_percent > 70:
            score -= 10

        # Disk usage penalty
        if self.last_snapshot.disk_percent > 90:
            score -= 20
        elif self.last_snapshot.disk_percent > 80:
            score -= 10

        return max(0, score)

    def get_trends(self) -> Dict[str, Any]:
        """Get system trends"""
        if len(self.history) < 2:
            return {'cpu_trend': 'stable', 'memory_trend': 'stable', 'disk_trend': 'stable'}

        recent = self.history[-5:]  # Last 5 snapshots

        def get_trend(values):
            if len(values) < 2:
                return 'stable'

            recent_avg = sum(values[-3:]) / 3
            earlier_avg = sum(values[:2]) / 2

            if recent_avg > earlier_avg * 1.2:
                return 'increasing'
            elif recent_avg < earlier_avg * 0.8:
                return 'decreasing'
            else:
                return 'stable'

        cpu_values = [s.cpu_percent for s in recent]
        memory_values = [s.memory_percent for s in recent]
        disk_values = [s.disk_percent for s in recent]

        return {
            'cpu_trend': get_trend(cpu_values),
            'memory_trend': get_trend(memory_values),
            'disk_trend': get_trend(disk_values)
        }

    def get_monitoring_report(self) -> Dict[str, Any]:
        """Get comprehensive monitoring report"""
        if not self.last_snapshot:
            self.take_snapshot()

        snapshot = self.last_snapshot
        trends = self.get_trends()

        return {
            'health_score': self.get_health_score(),
            'current_usage': {
                'cpu_percent': snapshot.cpu_percent,
                'memory_percent': snapshot.memory_percent,
                'disk_percent': snapshot.disk_percent
            },
            'system_info': {
                'process_count': snapshot.process_count,
                'thread_count': snapshot.thread_count,
                'network_io': snapshot.network_io
            },
            'trends': trends,
            'timestamp': snapshot.timestamp,
            'history_points': len(self.history)
        }

# Global monitor instance
_monitor_instance = None

def get_lightweight_system_monitor() -> LightweightSystemMonitor:
    """Get global system monitor instance"""
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = LightweightSystemMonitor()
    return _monitor_instance

def take_system_snapshot() -> Dict[str, Any]:
    """Take a system snapshot and return report"""
    monitor = get_lightweight_system_monitor()
    snapshot = monitor.take_snapshot()
    return monitor.get_monitoring_report()

def get_system_health() -> int:
    """Get system health score"""
    monitor = get_lightweight_system_monitor()
    return monitor.get_health_score()

def get_system_trends() -> Dict[str, Any]:
    """Get system trends"""
    monitor = get_lightweight_system_monitor()
    return monitor.get_trends()

if __name__ == '__main__':
    # Test lightweight system monitor
    monitor = get_lightweight_system_monitor()

    # Take multiple snapshots
    for i in range(3):
        snapshot = take_system_snapshot()
        print(f"✅ Snapshot {i+1}: Health score = {snapshot['health_score']}")
        time.sleep(0.5)

    # Get trends
    trends = get_system_trends()
    print(f"✅ System trends: {trends}")

    # Get final report
    report = take_system_snapshot()
    print(f"✅ Monitoring report: {json.dumps(report, indent=2)}")

    print("🎉 Lightweight system monitor test completed!")
