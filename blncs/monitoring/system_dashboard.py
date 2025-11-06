#!/usr/bin/env python3
"""
BLNCS System Health Dashboard
Real-time system monitoring and health dashboard
"""

import os
import sys
import time
import json
from typing import Dict, Any, List, Optional
from pathlib import Path

class SystemHealthDashboard:
    """Real-time system health dashboard"""

    def __init__(self):
        self.metrics = {}
        self.last_update = time.time()
        self.update_interval = 5  # seconds

    def collect_system_metrics(self) -> Dict[str, Any]:
        """Collect comprehensive system metrics"""
        metrics = {
            'timestamp': time.time(),
            'system': self._get_system_info(),
            'performance': self._get_performance_metrics(),
            'health': self._get_health_status(),
            'resources': self._get_resource_usage()
        }

        self.metrics = metrics
        self.last_update = time.time()
        return metrics

    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information"""
        return {
            'python_version': sys.version.split()[0],
            'platform': sys.platform,
            'hostname': os.uname().nodename if hasattr(os, 'uname') else 'unknown',
            'uptime': time.time() - self.last_update,
            'working_directory': str(Path.cwd())
        }

    def _get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics"""
        try:
            import psutil
            process = psutil.Process()

            return {
                'cpu_percent': process.cpu_percent(interval=0.1),
                'memory_rss': process.memory_info().rss,
                'memory_percent': process.memory_percent(),
                'threads': process.num_threads(),
                'connections': len(process.connections()),
                'open_files': len(process.open_files())
            }
        except ImportError:
            return {
                'cpu_percent': 0,
                'memory_rss': 0,
                'memory_percent': 0,
                'threads': 0,
                'connections': 0,
                'open_files': 0
            }

    def _get_health_status(self) -> Dict[str, Any]:
        """Get health status"""
        performance = self._get_performance_metrics()

        # Calculate health score
        cpu_score = max(0, 100 - performance['cpu_percent'])
        memory_score = max(0, 100 - performance['memory_percent'])

        overall_score = (cpu_score + memory_score) / 2

        status = 'healthy'
        if overall_score < 50:
            status = 'critical'
        elif overall_score < 75:
            status = 'warning'
        elif overall_score < 90:
            status = 'good'

        return {
            'overall_score': overall_score,
            'status': status,
            'cpu_health': cpu_score,
            'memory_health': memory_score,
            'last_check': time.time()
        }

    def _get_resource_usage(self) -> Dict[str, Any]:
        """Get resource usage"""
        try:
            import psutil

            disk_usage = psutil.disk_usage('/')
            network_io = psutil.net_io_counters()

            return {
                'disk_total': disk_usage.total,
                'disk_used': disk_usage.used,
                'disk_percent': disk_usage.percent,
                'network_sent': network_io.bytes_sent,
                'network_recv': network_io.bytes_recv,
                'swap_total': psutil.swap_memory().total,
                'swap_used': psutil.swap_memory().used
            }
        except ImportError:
            return {
                'disk_total': 0,
                'disk_used': 0,
                'disk_percent': 0,
                'network_sent': 0,
                'network_recv': 0,
                'swap_total': 0,
                'swap_used': 0
            }

    def generate_dashboard_report(self) -> Dict[str, Any]:
        """Generate comprehensive dashboard report"""
        metrics = self.collect_system_metrics()

        # Add summary information
        summary = {
            'total_checks': 1,
            'health_trend': 'stable',
            'performance_trend': 'stable',
            'recommendations': self._generate_recommendations(metrics)
        }

        return {
            'dashboard': {
                'version': '1.0.0',
                'last_update': self.last_update,
                'update_interval': self.update_interval
            },
            'summary': summary,
            'metrics': metrics
        }

    def _generate_recommendations(self, metrics: Dict[str, Any]) -> List[str]:
        """Generate system recommendations"""
        recommendations = []
        health = metrics['health']
        performance = metrics['performance']

        if health['overall_score'] < 50:
            recommendations.append("Critical system health - immediate attention required")
        elif health['overall_score'] < 75:
            recommendations.append("System health needs improvement")

        if performance['cpu_percent'] > 80:
            recommendations.append("High CPU usage - consider optimizing CPU-intensive operations")

        if performance['memory_percent'] > 85:
            recommendations.append("High memory usage - consider memory optimization")

        if metrics['resources']['disk_percent'] > 90:
            recommendations.append("Low disk space - consider cleanup or expansion")

        return recommendations

    def export_metrics_json(self) -> str:
        """Export metrics as JSON"""
        report = self.generate_dashboard_report()
        return json.dumps(report, indent=2, ensure_ascii=False)

    def export_metrics_csv(self) -> str:
        """Export metrics as CSV"""
        metrics = self.collect_system_metrics()
        health = metrics['health']
        performance = metrics['performance']

        csv_lines = [
            "Metric,Value,Timestamp",
            f"Health Score,{health['overall_score']:.1f},{self.last_update}",
            f"CPU Usage,{performance['cpu_percent']:.1f},{self.last_update}",
            f"Memory Usage,{performance['memory_percent']:.1f},{self.last_update}",
            f"Thread Count,{performance['threads']},{self.last_update}"
        ]

        return "\n".join(csv_lines)

# Global dashboard instance
_dashboard_instance = None

def get_system_health_dashboard() -> SystemHealthDashboard:
    """Get global dashboard instance"""
    global _dashboard_instance
    if _dashboard_instance is None:
        _dashboard_instance = SystemHealthDashboard()
    return _dashboard_instance

def get_system_metrics() -> Dict[str, Any]:
    """Get system metrics"""
    dashboard = get_system_health_dashboard()
    return dashboard.collect_system_metrics()

def get_health_status() -> Dict[str, Any]:
    """Get health status"""
    dashboard = get_system_health_dashboard()
    return dashboard._get_health_status()

def get_dashboard_report() -> Dict[str, Any]:
    """Get dashboard report"""
    dashboard = get_system_health_dashboard()
    return dashboard.generate_dashboard_report()

def export_metrics_json() -> str:
    """Export metrics as JSON"""
    dashboard = get_system_health_dashboard()
    return dashboard.export_metrics_json()

def export_metrics_csv() -> str:
    """Export metrics as CSV"""
    dashboard = get_system_health_dashboard()
    return dashboard.export_metrics_csv()

if __name__ == '__main__':
    # Test system health dashboard
    dashboard = get_system_health_dashboard()

    # Collect metrics
    metrics = get_system_metrics()
    print(f"✅ System metrics collected: {len(metrics)} categories")

    # Get health status
    health = get_health_status()
    print(f"✅ Health status: {health['status']} ({health['overall_score']:.1f}%)")

    # Generate dashboard report
    report = get_dashboard_report()
    print(f"✅ Dashboard report: {len(report['summary']['recommendations'])} recommendations")

    # Export metrics
    json_metrics = export_metrics_json()
    csv_metrics = export_metrics_csv()

    print(f"✅ JSON export: {len(json_metrics)} characters")
    print(f"✅ CSV export: {len(csv_metrics)} lines")

    print("🎉 System health dashboard test completed!")
