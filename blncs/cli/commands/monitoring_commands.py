"""
Performance Monitoring CLI Commands
Provides commands for managing performance monitoring and alerts.
"""

import click
from datetime import datetime
from typing import Dict, Any

from ...core.performance_alerting import get_performance_monitoring, AlertSeverity
from ...core.exceptions import format_error_for_cli


def get_client_from_context(ctx):
    """Get Lightning client from context"""
    return ctx.obj.get('client') or ctx.obj['get_client']()


@click.command()
@click.pass_context
def monitoring_status(ctx: click.Context) -> None:
    """Show performance monitoring status"""
    try:
        client = get_client_from_context(ctx)
        monitoring = get_performance_monitoring(client)
        
        status = monitoring.get_monitoring_status()
        
        click.echo("Performance Monitoring Status")
        click.echo("=" * 40)
        
        # Main status
        status_icon = "🟢 Running" if status['is_running'] else "🔴 Stopped"
        click.echo(f"Status: {status_icon}")
        click.echo(f"Monitor Interval: {status['monitoring_interval_seconds']} seconds")
        click.echo(f"Data Retention: {status['retention_hours']} hours")
        
        # Alert rules
        click.echo(f"\nAlert Rules:")
        click.echo(f"  Total: {status['total_alert_rules']}")
        click.echo(f"  Enabled: {status['enabled_alert_rules']}")
        
        # Current alerts
        click.echo(f"\nAlerts:")
        click.echo(f"  Active: {status['active_alerts']}")
        
        # Performance data
        click.echo(f"\nPerformance Data:")
        click.echo(f"  Snapshots Collected: {status['performance_snapshots']}")
        
        # Current snapshot
        if status['current_snapshot']:
            snapshot = status['current_snapshot']
            timestamp = datetime.fromisoformat(snapshot['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            
            click.echo(f"\nCurrent Metrics ({timestamp}):")
            click.echo(f"  CPU Usage: {snapshot['cpu_percent']:.1f}%")
            click.echo(f"  Memory Usage: {snapshot['memory_percent']:.1f}%")
            click.echo(f"  Disk Usage: {snapshot['disk_usage_percent']:.1f}%")
            click.echo(f"  Active Channels: {snapshot['active_channels']}")
            click.echo(f"  Node Connected: {'Yes' if snapshot['node_connectivity'] else 'No'}")
            click.echo(f"  Recent Forwards: {snapshot['recent_forwards']}")
            click.echo(f"  Cache Hit Rate: {snapshot['cache_hit_rate']:.1f}%")
    
    except Exception as e:
        click.echo(f"Error getting monitoring status: {format_error_for_cli(e)}", err=True)


@click.command()
@click.pass_context
def monitoring_start(ctx: click.Context) -> None:
    """Start performance monitoring"""
    try:
        client = get_client_from_context(ctx)
        monitoring = get_performance_monitoring(client)
        
        if monitoring.is_running:
            click.echo("Performance monitoring is already running")
            return
        
        click.echo("Starting performance monitoring...")
        
        success = monitoring.start_monitoring()
        
        if success:
            click.echo("✅ Performance monitoring started successfully")
            click.echo("System metrics and alerts are now active")
        else:
            click.echo("❌ Failed to start performance monitoring", err=True)
    
    except Exception as e:
        click.echo(f"Error starting performance monitoring: {format_error_for_cli(e)}", err=True)


@click.command()
@click.pass_context
def monitoring_stop(ctx: click.Context) -> None:
    """Stop performance monitoring"""
    try:
        client = get_client_from_context(ctx)
        monitoring = get_performance_monitoring(client)
        
        if not monitoring.is_running:
            click.echo("Performance monitoring is not running")
            return
        
        click.echo("Stopping performance monitoring...")
        
        success = monitoring.stop_monitoring()
        
        if success:
            click.echo("✅ Performance monitoring stopped successfully")
        else:
            click.echo("❌ Failed to stop performance monitoring", err=True)
    
    except Exception as e:
        click.echo(f"Error stopping performance monitoring: {format_error_for_cli(e)}", err=True)


@click.command()
@click.option('--severity', type=click.Choice(['INFO', 'WARNING', 'ERROR', 'CRITICAL', 'EMERGENCY']),
              help='Filter alerts by severity level')
@click.pass_context
def monitoring_alerts(ctx: click.Context, severity: str) -> None:
    """Show active alerts"""
    try:
        client = get_client_from_context(ctx)
        monitoring = get_performance_monitoring(client)
        
        alerts = monitoring.get_active_alerts()
        
        # Filter by severity if specified
        if severity:
            alerts = [alert for alert in alerts if alert['severity'] == severity]
        
        if not alerts:
            severity_text = f" ({severity})" if severity else ""
            click.echo(f"No active alerts{severity_text}")
            return
        
        click.echo(f"Active Alerts ({len(alerts)})")
        click.echo("=" * 50)
        
        # Group by severity
        severity_groups = {}
        for alert in alerts:
            sev = alert['severity']
            if sev not in severity_groups:
                severity_groups[sev] = []
            severity_groups[sev].append(alert)
        
        # Display alerts by severity (highest first)
        severity_order = ['EMERGENCY', 'CRITICAL', 'ERROR', 'WARNING', 'INFO']
        
        for sev in severity_order:
            if sev not in severity_groups:
                continue
            
            # Severity icon
            severity_icons = {
                'EMERGENCY': '🚨',
                'CRITICAL': '🔴',
                'ERROR': '🟠',
                'WARNING': '🟡',
                'INFO': '🔵'
            }
            icon = severity_icons.get(sev, '⚪')
            
            click.echo(f"\n{icon} {sev} ({len(severity_groups[sev])})")
            
            for alert in severity_groups[sev]:
                timestamp = datetime.fromisoformat(alert['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                
                click.echo(f"  [{alert['alert_id'][:8]}...] {alert['message']}")
                click.echo(f"    Time: {timestamp}")
                click.echo(f"    Rule: {alert['rule_name']}")
                click.echo(f"    Metric: {alert['metric_name']} = {alert['current_value']:.1f} (threshold: {alert['threshold']:.1f})")
                if alert.get('acknowledgement'):
                    click.echo(f"    Acknowledged: {alert['acknowledgement']}")
                click.echo()
    
    except Exception as e:
        click.echo(f"Error getting alerts: {format_error_for_cli(e)}", err=True)


@click.command()
@click.option('--limit', '-l', default=20, help='Number of recent alerts to show')
@click.pass_context
def monitoring_history(ctx: click.Context, limit: int) -> None:
    """Show alert history"""
    try:
        client = get_client_from_context(ctx)
        monitoring = get_performance_monitoring(client)
        
        history = monitoring.get_alert_history(limit)
        
        if not history:
            click.echo("No alert history found")
            return
        
        click.echo(f"Recent Alert History (last {len(history)})")
        click.echo("=" * 60)
        
        for alert in reversed(history):  # Show newest first
            timestamp = datetime.fromisoformat(alert['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            
            # Severity icon
            severity_icons = {
                'EMERGENCY': '🚨',
                'CRITICAL': '🔴',
                'ERROR': '🟠',
                'WARNING': '🟡',
                'INFO': '🔵'
            }
            icon = severity_icons.get(alert['severity'], '⚪')
            
            # Resolution status
            if alert['resolved']:
                if alert['resolved_at']:
                    resolved_time = datetime.fromisoformat(alert['resolved_at']).strftime('%H:%M:%S')
                    status = f"✅ Resolved at {resolved_time}"
                else:
                    status = "✅ Resolved"
            else:
                status = "🔄 Active"
            
            click.echo(f"{icon} {timestamp} - {alert['severity']}")
            click.echo(f"   {alert['message']}")
            click.echo(f"   Rule: {alert['rule_name']}")
            click.echo(f"   Status: {status}")
            click.echo()
    
    except Exception as e:
        click.echo(f"Error getting alert history: {format_error_for_cli(e)}", err=True)


@click.command()
@click.argument('alert_id')
@click.argument('message')
@click.pass_context
def monitoring_ack(ctx: click.Context, alert_id: str, message: str) -> None:
    """Acknowledge an active alert"""
    try:
        client = get_client_from_context(ctx)
        monitoring = get_performance_monitoring(client)
        
        success = monitoring.acknowledge_alert(alert_id, message)
        
        if success:
            click.echo(f"✅ Alert {alert_id[:8]}... acknowledged")
            click.echo(f"Message: {message}")
        else:
            click.echo(f"❌ Alert {alert_id} not found or already resolved", err=True)
    
    except Exception as e:
        click.echo(f"Error acknowledging alert: {format_error_for_cli(e)}", err=True)


@click.command()
@click.argument('alert_id')
@click.pass_context
def monitoring_resolve(ctx: click.Context, alert_id: str) -> None:
    """Manually resolve an active alert"""
    try:
        client = get_client_from_context(ctx)
        monitoring = get_performance_monitoring(client)
        
        success = monitoring.resolve_alert(alert_id)
        
        if success:
            click.echo(f"✅ Alert {alert_id[:8]}... resolved manually")
        else:
            click.echo(f"❌ Alert {alert_id} not found or already resolved", err=True)
    
    except Exception as e:
        click.echo(f"Error resolving alert: {format_error_for_cli(e)}", err=True)


@click.command()
@click.pass_context
def monitoring_metrics(ctx: click.Context) -> None:
    """Show current performance metrics"""
    try:
        client = get_client_from_context(ctx)
        monitoring = get_performance_monitoring(client)
        
        status = monitoring.get_monitoring_status()
        
        if not status['current_snapshot']:
            click.echo("No performance data available")
            return
        
        snapshot = status['current_snapshot']
        timestamp = datetime.fromisoformat(snapshot['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        
        click.echo("Current Performance Metrics")
        click.echo("=" * 40)
        click.echo(f"Collected: {timestamp}")
        click.echo()
        
        # System metrics
        click.echo("System Resources:")
        cpu_icon = "🔴" if snapshot['cpu_percent'] > 80 else "🟡" if snapshot['cpu_percent'] > 60 else "🟢"
        memory_icon = "🔴" if snapshot['memory_percent'] > 80 else "🟡" if snapshot['memory_percent'] > 60 else "🟢"
        disk_icon = "🔴" if snapshot['disk_usage_percent'] > 90 else "🟡" if snapshot['disk_usage_percent'] > 75 else "🟢"
        
        click.echo(f"  {cpu_icon} CPU Usage: {snapshot['cpu_percent']:.1f}%")
        click.echo(f"  {memory_icon} Memory Usage: {snapshot['memory_percent']:.1f}%")
        click.echo(f"  {disk_icon} Disk Usage: {snapshot['disk_usage_percent']:.1f}%")
        
        # Network and connectivity
        click.echo(f"\nConnectivity:")
        node_icon = "🟢" if snapshot['node_connectivity'] else "🔴"
        click.echo(f"  {node_icon} Lightning Node: {'Connected' if snapshot['node_connectivity'] else 'Disconnected'}")
        click.echo(f"  🌐 Network Connections: {snapshot['network_connections']}")
        
        # Lightning Network metrics
        click.echo(f"\nLightning Network:")
        click.echo(f"  ⚡ Active Channels: {snapshot['active_channels']}")
        click.echo(f"  📊 Recent Forwards (1h): {snapshot['recent_forwards']}")
        
        # Performance metrics
        click.echo(f"\nPerformance:")
        cache_icon = "🟢" if snapshot['cache_hit_rate'] > 80 else "🟡" if snapshot['cache_hit_rate'] > 60 else "🔴"
        click.echo(f"  {cache_icon} Cache Hit Rate: {snapshot['cache_hit_rate']:.1f}%")
        click.echo(f"  💾 Database Size: {snapshot['database_size_mb']:.1f} MB")
    
    except Exception as e:
        click.echo(f"Error getting performance metrics: {format_error_for_cli(e)}", err=True)