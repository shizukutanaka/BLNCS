"""
Metrics Commands for BLNCS
Performance monitoring and metrics display.
"""

import click
import time
import json
from typing import Dict, Any

@click.group(name='metrics')
def metrics_commands():
    """Performance metrics and monitoring"""
    pass

@metrics_commands.command()
@click.option('--format', '-f', default='table', type=click.Choice(['table', 'json']), help='Output format')
@click.option('--refresh', '-r', default=0, help='Auto-refresh interval in seconds')
def show(format, refresh):
    """Show current metrics"""
    try:
        from blncs.core.metrics_lightweight import get_metrics_collector
        
        def display_metrics():
            collector = get_metrics_collector()
            metrics = collector.get_all_metrics()
            
            if format == 'json':
                click.echo(json.dumps(metrics, indent=2))
            else:
                click.clear()
                click.echo("=== BLNCS System Metrics ===")
                click.echo(f"Updated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
                
                # Counters
                if metrics.get('counters'):
                    click.echo("\n=== Counters ===")
                    for name, value in metrics['counters'].items():
                        click.echo(f"  {name:<30} {value:>15.0f}")
                
                # Gauges
                if metrics.get('gauges'):
                    click.echo("\n=== Gauges ===")
                    for name, value in metrics['gauges'].items():
                        if 'percent' in name:
                            click.echo(f"  {name:<30} {value:>12.1f}%")
                        elif 'mb' in name.lower() or 'gb' in name.lower():
                            click.echo(f"  {name:<30} {value:>12.1f}")
                        else:
                            click.echo(f"  {name:<30} {value:>15.2f}")
                
                # Timers
                if metrics.get('timers'):
                    click.echo("\n=== Timers ===")
                    click.echo(f"  {'Name':<25} {'Count':<8} {'Avg':<8} {'Min':<8} {'Max':<8}")
                    click.echo("  " + "-" * 57)
                    for name, stats in metrics['timers'].items():
                        count = stats.get('count', 0)
                        avg = stats.get('avg', 0) * 1000  # Convert to ms
                        min_val = stats.get('min', 0) * 1000
                        max_val = stats.get('max', 0) * 1000
                        
                        click.echo(f"  {name:<25} {count:<8} {avg:<8.1f} {min_val:<8.1f} {max_val:<8.1f}")
        
        if refresh > 0:
            click.echo("Press Ctrl+C to stop monitoring")
            try:
                while True:
                    display_metrics()
                    time.sleep(refresh)
            except KeyboardInterrupt:
                click.echo("\nMonitoring stopped")
        else:
            display_metrics()
            
    except Exception as e:
        click.echo(f"Error displaying metrics: {e}")

@metrics_commands.command()
@click.argument('metric_name')
@click.option('--limit', '-l', default=50, help='Number of data points to show')
@click.option('--format', '-f', default='table', type=click.Choice(['table', 'json']), help='Output format')
def history(metric_name, limit, format):
    """Show metric history"""
    try:
        from blncs.core.metrics_lightweight import get_metrics_collector
        
        collector = get_metrics_collector()
        history_data = collector.get_metric_history(metric_name, limit)
        
        if not history_data:
            click.echo(f"No history found for metric: {metric_name}")
            return
        
        if format == 'json':
            click.echo(json.dumps(history_data, indent=2))
        else:
            click.echo(f"=== History for {metric_name} ===")
            click.echo(f"{'Timestamp':<20} {'Value':<15} {'Tags'}")
            click.echo("-" * 50)
            
            for point in history_data[-limit:]:
                timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(point['timestamp']))
                value = point['value']
                tags = point.get('tags', {})
                tags_str = ', '.join(f"{k}={v}" for k, v in tags.items()) if tags else ''
                
                if isinstance(value, float):
                    if 'percent' in metric_name:
                        value_str = f"{value:.1f}%"
                    elif any(unit in metric_name for unit in ['ms', 'seconds', 'time']):
                        value_str = f"{value:.3f}"
                    else:
                        value_str = f"{value:.2f}"
                else:
                    value_str = str(value)
                
                click.echo(f"{timestamp:<20} {value_str:<15} {tags_str}")
        
    except Exception as e:
        click.echo(f"Error getting metric history: {e}")

@metrics_commands.command()
@click.option('--file', '-f', help='Export to file')
def export(file):
    """Export metrics to JSON"""
    try:
        from blncs.core.metrics_lightweight import get_metrics_collector
        
        collector = get_metrics_collector()
        
        if file:
            json_data = collector.export_json(file)
            click.echo(f"Metrics exported to: {file}")
        else:
            json_data = collector.export_json()
            click.echo(json_data)
            
    except Exception as e:
        click.echo(f"Error exporting metrics: {e}")

@metrics_commands.command()
@click.argument('metric_name', required=False)
@click.option('--all', is_flag=True, help='Reset all metrics')
def reset(metric_name, all):
    """Reset metrics"""
    try:
        from blncs.core.metrics_lightweight import get_metrics_collector
        
        collector = get_metrics_collector()
        
        if all:
            collector.reset_all()
            click.echo("All metrics reset")
        elif metric_name:
            collector.reset_metric(metric_name)
            click.echo(f"Metric '{metric_name}' reset")
        else:
            click.echo("Please specify a metric name or use --all")
            
    except Exception as e:
        click.echo(f"Error resetting metrics: {e}")

@metrics_commands.command()
@click.option('--age', default=3600, help='Maximum age in seconds')
def cleanup(age):
    """Clean up old metrics"""
    try:
        from blncs.core.metrics_lightweight import get_metrics_collector
        
        collector = get_metrics_collector()
        removed = collector.cleanup_old_metrics(age)
        
        if removed:
            click.echo(f"Cleaned up {removed} old metric points")
        else:
            click.echo("No old metrics to clean up")
            
    except Exception as e:
        click.echo(f"Error cleaning up metrics: {e}")

@metrics_commands.command()
def record():
    """Record test metrics for demonstration"""
    try:
        from blncs.core.metrics_lightweight import get_metrics_collector
        import random
        
        collector = get_metrics_collector()
        
        # Record some sample metrics
        collector.counter('test.operations', 1)
        collector.gauge('test.cpu_usage', random.uniform(10, 90))
        collector.gauge('test.memory_usage', random.uniform(30, 80))
        collector.timer('test.response_time', random.uniform(0.1, 2.0))
        
        click.echo("Test metrics recorded:")
        click.echo("  - test.operations (counter)")
        click.echo("  - test.cpu_usage (gauge)")
        click.echo("  - test.memory_usage (gauge)")
        click.echo("  - test.response_time (timer)")
        
    except Exception as e:
        click.echo(f"Error recording test metrics: {e}")

@metrics_commands.command()
@click.option('--count', default=100, help='Number of test operations')
@click.option('--delay', default=0.01, help='Delay between operations in seconds')
def benchmark(count, delay):
    """Run performance benchmark with metrics"""
    try:
        from blncs.core.metrics_lightweight import get_metrics_collector, timing
        import time
        import random
        
        collector = get_metrics_collector()
        
        click.echo(f"Running benchmark: {count} operations with {delay}s delay")
        
        start_time = time.time()
        
        for i in range(count):
            # Simulate different operations
            with timing('benchmark.operation'):
                time.sleep(delay + random.uniform(0, delay))
            
            # Record various metrics
            collector.counter('benchmark.operations')
            collector.gauge('benchmark.progress', (i + 1) / count * 100)
            
            if (i + 1) % 10 == 0:
                click.echo(f"Progress: {i + 1}/{count} operations")
        
        total_time = time.time() - start_time
        ops_per_sec = count / total_time
        
        collector.gauge('benchmark.total_time', total_time)
        collector.gauge('benchmark.ops_per_second', ops_per_sec)
        
        click.echo(f"\nBenchmark completed!")
        click.echo(f"Total time: {total_time:.2f} seconds")
        click.echo(f"Operations/second: {ops_per_sec:.1f}")
        
        # Show timing stats
        timing_stats = collector.get_timer_stats('benchmark.operation')
        click.echo(f"Average operation time: {timing_stats['avg']*1000:.1f}ms")
        click.echo(f"Min operation time: {timing_stats['min']*1000:.1f}ms")
        click.echo(f"Max operation time: {timing_stats['max']*1000:.1f}ms")
        
    except Exception as e:
        click.echo(f"Error running benchmark: {e}")

if __name__ == '__main__':
    metrics_commands()