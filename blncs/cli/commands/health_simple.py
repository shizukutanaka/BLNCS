"""
Simple Health Check Command
Lightweight health check without complex dependencies.
"""

import click
import os
import shutil
from datetime import datetime

# Fallback system info without psutil
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    psutil = None

def get_basic_system_info():
    """Get basic system info without psutil"""
    info = {}
    
    # Try to get CPU info from /proc/cpuinfo
    try:
        with open('/proc/cpuinfo', 'r') as f:
            cpu_lines = f.readlines()
            info['cpu_count'] = len([line for line in cpu_lines if line.startswith('processor')])
    except:
        info['cpu_count'] = 'unknown'
    
    # Try to get memory info from /proc/meminfo
    try:
        with open('/proc/meminfo', 'r') as f:
            lines = f.readlines()
            mem_total = None
            mem_available = None
            for line in lines:
                if line.startswith('MemTotal:'):
                    mem_total = int(line.split()[1]) * 1024  # Convert KB to bytes
                elif line.startswith('MemAvailable:'):
                    mem_available = int(line.split()[1]) * 1024
            if mem_total and mem_available:
                info['memory_used_percent'] = ((mem_total - mem_available) / mem_total) * 100
    except:
        info['memory_used_percent'] = None
    
    # Try to get disk usage
    try:
        total, used, free = shutil.disk_usage('/')
        info['disk_used_percent'] = (used / total) * 100
    except:
        info['disk_used_percent'] = None
    
    return info

def check_system_health():
    """Check basic system health metrics"""
    from typing import Dict, Any
    
    health = {
        'timestamp': datetime.now().isoformat(),
        'status': 'healthy',
        'checks': {}
    }
    
    if HAS_PSUTIL:
        # Use psutil if available
        cpu_percent = psutil.cpu_percent(interval=1)
        health['checks']['cpu'] = {
            'value': cpu_percent,
            'status': 'ok' if cpu_percent < 80 else 'warning' if cpu_percent < 90 else 'critical',
            'message': f'CPU usage: {cpu_percent:.1f}%'
        }
        
        memory = psutil.virtual_memory()
        health['checks']['memory'] = {
            'value': memory.percent,
            'status': 'ok' if memory.percent < 80 else 'warning' if memory.percent < 90 else 'critical',
            'message': f'Memory usage: {memory.percent:.1f}%'
        }
        
        disk = psutil.disk_usage('/')
        health['checks']['disk'] = {
            'value': disk.percent,
            'status': 'ok' if disk.percent < 80 else 'warning' if disk.percent < 90 else 'critical',
            'message': f'Disk usage: {disk.percent:.1f}%'
        }
    else:
        # Fallback without psutil
        sys_info = get_basic_system_info()
        
        health['checks']['cpu'] = {
            'status': 'ok',
            'message': f"CPU cores: {sys_info.get('cpu_count', 'unknown')}"
        }
        
        if sys_info.get('memory_used_percent') is not None:
            mem_percent = sys_info['memory_used_percent']
            health['checks']['memory'] = {
                'value': mem_percent,
                'status': 'ok' if mem_percent < 80 else 'warning' if mem_percent < 90 else 'critical',
                'message': f'Memory usage: {mem_percent:.1f}%'
            }
        else:
            health['checks']['memory'] = {
                'status': 'unknown',
                'message': 'Memory usage: Unable to determine'
            }
        
        if sys_info.get('disk_used_percent') is not None:
            disk_percent = sys_info['disk_used_percent']
            health['checks']['disk'] = {
                'value': disk_percent,
                'status': 'ok' if disk_percent < 80 else 'warning' if disk_percent < 90 else 'critical',
                'message': f'Disk usage: {disk_percent:.1f}%'
            }
        else:
            health['checks']['disk'] = {
                'status': 'unknown',
                'message': 'Disk usage: Unable to determine'
            }
    
    # Lightning connection check
    try:
        from ...lightning.client_simple import get_lightning_client
        client = get_lightning_client()
        client.connect()
        info = client.get_info()
        health['checks']['lightning'] = {
            'status': 'ok' if info.get('synced_to_chain') else 'warning',
            'message': f"Lightning node: {'Synced' if info.get('synced_to_chain') else 'Syncing'}"
        }
    except Exception as e:
        health['checks']['lightning'] = {
            'status': 'error',
            'message': f'Lightning node: Disconnected'
        }
    
    # Overall status
    statuses = [check['status'] for check in health['checks'].values()]
    if 'critical' in statuses or 'error' in statuses:
        health['status'] = 'unhealthy'
    elif 'warning' in statuses:
        health['status'] = 'degraded'
    else:
        health['status'] = 'healthy'
    
    return health

@click.command()
@click.option('--json', 'output_json', is_flag=True, help='Output as JSON')
def health_check(output_json):
    """Check system health"""
    import json
    from typing import Dict, Any
    
    health = check_system_health()
    
    if output_json:
        click.echo(json.dumps(health, indent=2))
    else:
        # Display formatted output
        click.echo("🏥 SYSTEM HEALTH CHECK")
        click.echo("=" * 50)
        
        # Overall status
        status_icon = {
            'healthy': '✅',
            'degraded': '⚠️',
            'unhealthy': '❌'
        }.get(health['status'], '❓')
        
        click.echo(f"\nOverall Status: {status_icon} {health['status'].upper()}")
        click.echo(f"Timestamp: {health['timestamp']}")
        click.echo("\nDetailed Checks:")
        click.echo("-" * 40)
        
        for check_name, check_data in health['checks'].items():
            status_icon = {
                'ok': '✅',
                'warning': '⚠️',
                'critical': '❌',
                'error': '❌'
            }.get(check_data['status'], '❓')
            
            click.echo(f"{status_icon} {check_name.upper()}: {check_data['message']}")
        
        click.echo("\n" + "=" * 50)

def show_health():
    """Simple health display for dashboard"""
    health = check_system_health()
    return health