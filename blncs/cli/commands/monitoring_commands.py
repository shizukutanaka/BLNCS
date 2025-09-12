#!/usr/bin/env python3
"""
BLNCS Monitoring CLI Commands
Command-line interface for production monitoring and alerting.
"""

import click
import json
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any

try:
    from ...monitoring import ProductionMonitor, MonitoringDashboard
    from ...monitoring.config import get_config, config_manager
except ImportError:
    # For standalone testing
    sys.path.append(str(Path(__file__).parent.parent.parent))
    from monitoring import ProductionMonitor, MonitoringDashboard
    from monitoring.config import get_config, config_manager


@click.group()
def monitoring():
    """Production monitoring and alerting commands"""
    pass


@monitoring.command()
@click.option('--interval', '-i', default=30, help='Collection interval in seconds')
@click.option('--duration', '-d', default=0, help='Duration to run (0 for infinite)')
@click.option('--output', '-o', help='Output file for metrics data')
@click.option('--format', 'output_format', default='json', type=click.Choice(['json', 'csv']))
def collect(interval: int, duration: int, output: str, output_format: str):
    """Collect and display metrics data"""
    click.echo("Starting metrics collection...")
    
    monitor = ProductionMonitor()
    
    try:
        monitor.start()
        click.echo(f"✅ Production monitor started (interval: {interval}s)")
        
        start_time = datetime.now()
        collected_data = []
        
        while True:
            try:
                # Collect all metrics
                timestamp = datetime.now()
                
                system_metrics = monitor.metrics_collector.collect_system_metrics()
                lightning_metrics = monitor.metrics_collector.collect_lightning_metrics()
                database_metrics = monitor.metrics_collector.collect_database_metrics()
                app_metrics = monitor.metrics_collector.collect_application_metrics()
                
                # Combine metrics
                all_metrics = {
                    'timestamp': timestamp.isoformat(),
                    'system': system_metrics,
                    'lightning': lightning_metrics,
                    'database': database_metrics,
                    'application': app_metrics
                }
                
                collected_data.append(all_metrics)
                
                # Display current metrics
                click.echo(f"\n[{timestamp.strftime('%H:%M:%S')}] Current Metrics:")
                click.echo(f"  CPU: {system_metrics.get('cpu_percent', 0):.1f}%")
                click.echo(f"  Memory: {system_metrics.get('memory_percent', 0):.1f}%")
                click.echo(f"  Lightning Channels: {lightning_metrics.get('channels_active', 0)}")
                click.echo(f"  Database Connections: {database_metrics.get('connections_active', 0)}")
                
                # Check if duration exceeded
                if duration > 0:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    if elapsed >= duration:
                        click.echo(f"\n✅ Collection completed ({elapsed:.1f}s)")
                        break
                
                time.sleep(interval)
                
            except KeyboardInterrupt:
                click.echo("\n⚠️ Collection interrupted by user")
                break
            except Exception as e:
                click.echo(f"❌ Error collecting metrics: {e}", err=True)
                time.sleep(interval)
        
        # Save data if output specified
        if output and collected_data:
            save_metrics_data(collected_data, output, output_format)
            click.echo(f"📁 Data saved to {output}")
    
    finally:
        monitor.stop()
        click.echo("🛑 Production monitor stopped")


@monitoring.command()
def dashboard():
    """Launch monitoring dashboard GUI"""
    click.echo("Launching monitoring dashboard...")
    
    try:
        dashboard = MonitoringDashboard()
        dashboard.run()
    except Exception as e:
        click.echo(f"❌ Failed to start dashboard: {e}", err=True)
        return 1


@monitoring.command()
@click.option('--format', 'output_format', default='table', type=click.Choice(['table', 'json']))
def status(output_format: str):
    """Show current system status"""
    click.echo("Checking system status...")
    
    monitor = ProductionMonitor()
    
    try:
        monitor.start()
        
        # Collect current metrics
        system_metrics = monitor.metrics_collector.collect_system_metrics()
        lightning_metrics = monitor.metrics_collector.collect_lightning_metrics()
        database_metrics = monitor.metrics_collector.collect_database_metrics()
        
        # Run health checks
        health_results = monitor.health_checker.check_all_health()
        
        if output_format == 'json':
            status_data = {
                'timestamp': datetime.now().isoformat(),
                'system': system_metrics,
                'lightning': lightning_metrics,
                'database': database_metrics,
                'health': health_results
            }
            click.echo(json.dumps(status_data, indent=2))
        else:
            # Table format
            click.echo("\n📊 System Status Report")
            click.echo("=" * 50)
            
            click.echo(f"\n🖥️ System Metrics:")
            click.echo(f"  CPU Usage: {system_metrics.get('cpu_percent', 0):.1f}%")
            click.echo(f"  Memory Usage: {system_metrics.get('memory_percent', 0):.1f}%")
            click.echo(f"  Disk Usage: {system_metrics.get('disk_percent', 0):.1f}%")
            
            click.echo(f"\n⚡ Lightning Network:")
            click.echo(f"  Total Channels: {lightning_metrics.get('channels_total', 0)}")
            click.echo(f"  Active Channels: {lightning_metrics.get('channels_active', 0)}")
            click.echo(f"  Balance: {lightning_metrics.get('balance_local', 0)} sats")
            
            click.echo(f"\n💾 Database:")
            click.echo(f"  Active Connections: {database_metrics.get('connections_active', 0)}")
            click.echo(f"  Query Time (avg): {database_metrics.get('query_time_avg', 0):.1f}ms")
            
            click.echo(f"\n🏥 Health Checks:")
            for component, health_data in health_results.items():
                status_icon = "✅" if health_data.get('healthy', False) else "❌"
                click.echo(f"  {status_icon} {component}: {health_data.get('status', 'Unknown')}")
    
    finally:
        monitor.stop()


@monitoring.command()
@click.option('--level', default='WARNING', type=click.Choice(['INFO', 'WARNING', 'CRITICAL']))
@click.option('--last-hours', default=24, help='Show alerts from last N hours')
def alerts(level: str, last_hours: int):
    """Show recent alerts"""
    click.echo(f"Showing {level}+ alerts from last {last_hours} hours...")
    
    # This would typically read from a persistent alert store
    # For now, we'll show a placeholder
    click.echo("\n📢 Recent Alerts:")
    click.echo("-" * 40)
    click.echo("No recent alerts found")
    click.echo("\nNote: Alert history requires persistent monitoring to be running")


@monitoring.command()
def config():
    """Show monitoring configuration"""
    config = get_config()
    
    click.echo("\n⚙️ Monitoring Configuration:")
    click.echo("=" * 40)
    click.echo(f"System metrics interval: {config.system_metrics_interval}s")
    click.echo(f"Lightning metrics interval: {config.lightning_metrics_interval}s")
    click.echo(f"Database metrics interval: {config.database_metrics_interval}s")
    click.echo(f"Health check interval: {config.health_check_interval}s")
    click.echo(f"Metrics retention: {config.metrics_retention_days} days")
    click.echo(f"Alert cooldown: {config.alert_cooldown_minutes} minutes")
    
    # Show thresholds
    click.echo(f"\n📊 Metric Thresholds:")
    for name, threshold in config_manager.thresholds.items():
        if threshold.enabled:
            click.echo(f"  {name}: {threshold.warning_threshold}/{threshold.critical_threshold}")
    
    # Show alert channels
    click.echo(f"\n📨 Alert Channels:")
    for name, channel in config_manager.alert_channels.items():
        status = "✅ Enabled" if channel.enabled else "❌ Disabled"
        click.echo(f"  {channel.type} ({name}): {status}")


@monitoring.command()
@click.argument('component', type=click.Choice(['system', 'lightning', 'database', 'all']))
@click.option('--duration', '-d', default=60, help='Test duration in seconds')
def test(component: str, duration: int):
    """Test monitoring components"""
    click.echo(f"Testing {component} monitoring for {duration} seconds...")
    
    monitor = ProductionMonitor()
    
    try:
        monitor.start()
        start_time = datetime.now()
        
        while (datetime.now() - start_time).total_seconds() < duration:
            if component == 'system' or component == 'all':
                metrics = monitor.metrics_collector.collect_system_metrics()
                click.echo(f"System: CPU={metrics.get('cpu_percent', 0):.1f}% Memory={metrics.get('memory_percent', 0):.1f}%")
            
            if component == 'lightning' or component == 'all':
                metrics = monitor.metrics_collector.collect_lightning_metrics()
                click.echo(f"Lightning: Channels={metrics.get('channels_active', 0)}/{metrics.get('channels_total', 0)}")
            
            if component == 'database' or component == 'all':
                metrics = monitor.metrics_collector.collect_database_metrics()
                click.echo(f"Database: Connections={metrics.get('connections_active', 0)}")
            
            time.sleep(5)
        
        click.echo("✅ Test completed successfully")
    
    except Exception as e:
        click.echo(f"❌ Test failed: {e}", err=True)
    finally:
        monitor.stop()


def save_metrics_data(data: list, filename: str, format: str):
    """Save metrics data to file"""
    if format == 'json':
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    elif format == 'csv':
        import csv
        
        if not data:
            return
        
        # Flatten the data structure
        fieldnames = set()
        flattened_data = []
        
        for record in data:
            flat_record = {'timestamp': record['timestamp']}
            
            for category in ['system', 'lightning', 'database', 'application']:
                if category in record:
                    for key, value in record[category].items():
                        field_name = f"{category}_{key}"
                        flat_record[field_name] = value
                        fieldnames.add(field_name)
            
            flattened_data.append(flat_record)
            fieldnames.update(flat_record.keys())
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=sorted(fieldnames))
            writer.writeheader()
            writer.writerows(flattened_data)


if __name__ == '__main__':
    monitoring()