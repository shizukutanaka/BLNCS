"""
Enhanced Dashboard and Monitoring Commands
Practical real-time monitoring and comprehensive system overview.
"""

import click
import time
import sys
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from ...lightning.client import LightningClient
from ...core.exceptions import format_error_for_cli
from ...core.health import get_health_checker
from ...core.performance_manager import get_performance_manager
from ...core.security_enhanced import get_enhanced_security_manager
from ...core.liquidity_optimizer import get_liquidity_optimizer


def clear_screen():
    """Clear terminal screen"""
    import os
    os.system('cls' if os.name == 'nt' else 'clear')


def format_uptime(seconds: float) -> str:
    """Format uptime in human readable format"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}m"
    elif seconds < 86400:
        return f"{seconds/3600:.1f}h"
    else:
        return f"{seconds/86400:.1f}d"


def get_status_emoji(status: str) -> str:
    """Get emoji for status"""
    status_map = {
        'healthy': '🟢',
        'warning': '🟡',
        'critical': '🔴',
        'unknown': '⚪',
        'good': '🟢',
        'fair': '🟡',
        'poor': '🔴',
        'excellent': '🟢'
    }
    return status_map.get(status.lower(), '⚪')


@click.command()
@click.option('--refresh', '-r', default=0, help='Auto-refresh interval in seconds (0 = no refresh)')
@click.option('--compact', '-c', is_flag=True, help='Compact view')
@click.pass_context
def dashboard(ctx: click.Context, refresh: int, compact: bool):
    """Real-time system dashboard"""
    
    def display_dashboard():
        """Display the dashboard"""
        try:
            if not compact:
                clear_screen()
            
            client: LightningClient = ctx.obj['client']
            
            # Header
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            click.echo(f"{'=' * 80}")
            click.echo(f"🚀 BLNCS Dashboard - {now}")
            click.echo(f"{'=' * 80}")
            
            # System Status Section
            click.echo("\n📊 SYSTEM STATUS")
            click.echo("-" * 40)
            
            # Lightning Node Status
            try:
                client.connect()
                node_info = client.get_info()
                status_emoji = '🟢'
                connection_status = 'Connected'
            except Exception:
                status_emoji = '🔴'
                connection_status = 'Disconnected'
                node_info = {}
            
            click.echo(f"{status_emoji} Lightning Node: {connection_status}")
            
            if node_info:
                alias = node_info.get('alias', 'Unknown')
                network = node_info.get('network', 'Unknown')
                channels = node_info.get('num_channels', 0)
                peers = node_info.get('num_peers', 0)
                
                click.echo(f"   Node: {alias} ({network})")
                click.echo(f"   Channels: {channels}, Peers: {peers}")
                
                # Sync status
                chain_sync = node_info.get('synced_to_chain', False)
                graph_sync = node_info.get('synced_to_graph', False)
                sync_emoji = '🟢' if (chain_sync and graph_sync) else '🟡'
                click.echo(f"   {sync_emoji} Sync Status: Chain={'✓' if chain_sync else '✗'}, Graph={'✓' if graph_sync else '✗'}")
            
            # Balance Overview
            if not compact:
                click.echo("\n💰 BALANCE OVERVIEW")
                click.echo("-" * 40)
                
                try:
                    balance_data = client.get_balance()
                    
                    onchain_total = balance_data.get('confirmed', 0)
                    lightning_local = balance_data.get('channel_local', 0)
                    lightning_remote = balance_data.get('channel_remote', 0)
                    
                    click.echo(f"On-chain: {onchain_total:,} sats")
                    click.echo(f"Lightning Local: {lightning_local:,} sats")
                    click.echo(f"Lightning Remote: {lightning_remote:,} sats")
                    
                    total_available = onchain_total + lightning_local
                    total_capacity = lightning_local + lightning_remote
                    
                    click.echo(f"Available Balance: {total_available:,} sats")
                    click.echo(f"Total Lightning Capacity: {total_capacity:,} sats")
                    
                    if total_capacity > 0:
                        local_ratio = lightning_local / total_capacity
                        balance_emoji = '🟢' if 0.3 <= local_ratio <= 0.7 else '🟡' if 0.2 <= local_ratio <= 0.8 else '🔴'
                        click.echo(f"{balance_emoji} Lightning Balance: {local_ratio:.1%} local")
                    
                except Exception as e:
                    click.echo(f"🔴 Balance: Error fetching data")
            
            # Performance Metrics
            try:
                pm = get_performance_manager()
                perf_status = pm.get_current_performance()
                
                if perf_status.get('status') != 'no_data':
                    click.echo("\n⚡ PERFORMANCE")
                    click.echo("-" * 40)
                    
                    sys_metrics = perf_status.get('system', {})
                    cache_metrics = perf_status.get('cache', {})
                    
                    # CPU and Memory
                    cpu_percent = sys_metrics.get('cpu_percent', 0)
                    memory_percent = sys_metrics.get('memory_percent', 0)
                    
                    cpu_emoji = '🟢' if cpu_percent < 70 else '🟡' if cpu_percent < 85 else '🔴'
                    mem_emoji = '🟢' if memory_percent < 80 else '🟡' if memory_percent < 90 else '🔴'
                    
                    click.echo(f"{cpu_emoji} CPU: {cpu_percent:.1f}%")
                    click.echo(f"{mem_emoji} Memory: {memory_percent:.1f}%")
                    
                    # Cache Performance
                    hit_rate = cache_metrics.get('hit_rate', 0)
                    cache_emoji = '🟢' if hit_rate > 0.8 else '🟡' if hit_rate > 0.6 else '🔴'
                    click.echo(f"{cache_emoji} Cache Hit Rate: {hit_rate:.1%}")
                    
            except Exception:
                pass
            
            # Security Status
            try:
                sm = get_enhanced_security_manager()
                security_status = sm.get_security_status()
                
                click.echo("\n🔒 SECURITY")
                click.echo("-" * 40)
                
                encryption_status = '🟢' if security_status.get('encryption_available') else '🔴'
                click.echo(f"{encryption_status} Encryption: {'Available' if security_status.get('encryption_available') else 'Not Available'}")
                
                monitoring_status = '🟢' if security_status.get('monitoring_enabled') else '🟡'
                click.echo(f"{monitoring_status} Security Monitoring: {'Active' if security_status.get('monitoring_enabled') else 'Inactive'}")
                
                blocked_ips = security_status.get('temp_blocked_ips', 0)
                if blocked_ips > 0:
                    click.echo(f"🔴 Blocked IPs: {blocked_ips}")
                
            except Exception:
                pass
            
            # Liquidity Health (if channels exist)
            if node_info.get('num_channels', 0) > 0:
                try:
                    optimizer = get_liquidity_optimizer(client)
                    summary = optimizer.get_liquidity_summary()
                    
                    if summary.get('status') != 'no_data':
                        click.echo("\n💧 LIQUIDITY HEALTH")
                        click.echo("-" * 40)
                        
                        health_status = summary.get('health_status', 'unknown')
                        health_emoji = get_status_emoji(health_status)
                        liquidity_score = summary.get('average_liquidity_score', 0)
                        
                        click.echo(f"{health_emoji} Overall Health: {health_status.title()} ({liquidity_score:.1f}/100)")
                        click.echo(f"Balanced Channels: {summary.get('balanced_channels', 0)}/{summary.get('total_channels', 0)}")
                        
                        if summary.get('imbalanced_channels', 0) > 0:
                            click.echo(f"🟡 Imbalanced Channels: {summary['imbalanced_channels']}")
                
                except Exception:
                    pass
            
            # Recent Activity (if available)
            if not compact:
                click.echo("\n📋 QUICK ACTIONS")
                click.echo("-" * 40)
                click.echo("Run 'blncs health' for detailed health check")
                click.echo("Run 'blncs liquidity analyze' for liquidity analysis")
                click.echo("Run 'blncs channels' for channel details")
                click.echo("Run 'blncs monitor' for continuous monitoring")
            
            if refresh > 0:
                click.echo(f"\n🔄 Auto-refreshing every {refresh}s (Press Ctrl+C to stop)")
            
        except KeyboardInterrupt:
            click.echo("\n👋 Dashboard stopped by user")
            sys.exit(0)
        except Exception as e:
            click.echo(f"\n🔴 Dashboard Error: {format_error_for_cli(e)}", err=True)
    
    # Main dashboard loop
    try:
        if refresh <= 0:
            # Single display
            display_dashboard()
        else:
            # Auto-refresh loop
            while True:
                display_dashboard()
                time.sleep(refresh)
    except KeyboardInterrupt:
        click.echo("\n👋 Dashboard stopped")


@click.command()
@click.option('--interval', '-i', default=60, help='Monitoring interval in seconds')
@click.option('--alert-threshold', default=80, help='Alert threshold percentage for CPU/Memory')
@click.pass_context
def monitor(ctx: click.Context, interval: int, alert_threshold: int):
    """Continuous system monitoring with alerts"""
    
    client: LightningClient = ctx.obj['client']
    start_time = time.time()
    alert_count = 0
    
    click.echo("🔍 Starting BLNCS Continuous Monitoring...")
    click.echo(f"Monitoring interval: {interval}s")
    click.echo(f"Alert threshold: {alert_threshold}%")
    click.echo("Press Ctrl+C to stop\n")
    
    try:
        while True:
            timestamp = datetime.now().strftime("%H:%M:%S")
            alerts = []
            
            # Check Lightning connection
            try:
                client.connect()
                node_info = client.get_info()
                click.echo(f"[{timestamp}] ✅ Lightning: Connected ({node_info.get('num_channels', 0)} channels)")
                
                # Check sync status
                if not node_info.get('synced_to_chain', True):
                    alerts.append("⚠️  Chain not synced")
                if not node_info.get('synced_to_graph', True):
                    alerts.append("⚠️  Graph not synced")
                
            except Exception as e:
                alerts.append(f"🔴 Lightning: Connection failed - {str(e)[:50]}")
            
            # Check performance
            try:
                pm = get_performance_manager()
                perf_status = pm.get_current_performance()
                
                if perf_status.get('status') != 'no_data':
                    sys_metrics = perf_status.get('system', {})
                    
                    cpu_percent = sys_metrics.get('cpu_percent', 0)
                    memory_percent = sys_metrics.get('memory_percent', 0)
                    
                    click.echo(f"[{timestamp}] 📊 Performance: CPU {cpu_percent:.1f}%, Memory {memory_percent:.1f}%")
                    
                    if cpu_percent > alert_threshold:
                        alerts.append(f"🔴 High CPU usage: {cpu_percent:.1f}%")
                    
                    if memory_percent > alert_threshold:
                        alerts.append(f"🔴 High memory usage: {memory_percent:.1f}%")
            
            except Exception:
                pass
            
            # Check security
            try:
                sm = get_enhanced_security_manager()
                security_status = sm.get_security_status()
                
                blocked_ips = security_status.get('temp_blocked_ips', 0)
                if blocked_ips > 0:
                    alerts.append(f"🔒 {blocked_ips} IPs temporarily blocked")
                
                recent_events = security_status.get('recent_events', 0)
                if recent_events > 10:  # More than 10 events in 24h
                    alerts.append(f"⚠️  High security activity: {recent_events} events")
            
            except Exception:
                pass
            
            # Display alerts
            if alerts:
                alert_count += len(alerts)
                click.echo(f"[{timestamp}] 🚨 ALERTS ({len(alerts)}):")
                for alert in alerts:
                    click.echo(f"  {alert}")
                click.echo()
            
            # Status summary
            uptime = time.time() - start_time
            click.echo(f"[{timestamp}] 📈 Monitor uptime: {format_uptime(uptime)}, Total alerts: {alert_count}")
            click.echo("-" * 60)
            
            time.sleep(interval)
            
    except KeyboardInterrupt:
        uptime = time.time() - start_time
        click.echo(f"\n👋 Monitoring stopped after {format_uptime(uptime)}")
        click.echo(f"Total alerts generated: {alert_count}")


@click.command()
@click.pass_context
def health(ctx: click.Context):
    """Comprehensive system health check"""
    
    client: LightningClient = ctx.obj['client']
    
    click.echo("🏥 BLNCS System Health Check")
    click.echo("=" * 50)
    
    overall_score = 0
    total_checks = 0
    issues = []
    
    # Lightning Node Health
    click.echo("\n🔗 Lightning Node Health")
    click.echo("-" * 30)
    
    try:
        client.connect()
        node_info = client.get_info()
        
        # Connection check
        click.echo("✅ Connection: OK")
        overall_score += 20
        
        # Sync checks
        chain_synced = node_info.get('synced_to_chain', False)
        graph_synced = node_info.get('synced_to_graph', False)
        
        if chain_synced:
            click.echo("✅ Chain Sync: OK")
            overall_score += 15
        else:
            click.echo("❌ Chain Sync: Not synced")
            issues.append("Chain not synced to latest block")
        
        if graph_synced:
            click.echo("✅ Graph Sync: OK")
            overall_score += 15
        else:
            click.echo("❌ Graph Sync: Not synced")
            issues.append("Network graph not synced")
        
        # Channel health
        num_channels = node_info.get('num_channels', 0)
        num_peers = node_info.get('num_peers', 0)
        
        click.echo(f"📊 Channels: {num_channels}, Peers: {num_peers}")
        
        if num_channels > 0:
            overall_score += 10
        elif num_peers > 0:
            overall_score += 5
            issues.append("Node has peers but no channels")
        else:
            issues.append("No channels or peers connected")
        
    except Exception as e:
        click.echo(f"❌ Connection: FAILED - {str(e)[:50]}")
        issues.append(f"Lightning node connection failed: {e}")
    
    total_checks += 4
    
    # System Performance Health
    click.echo("\n⚡ Performance Health")
    click.echo("-" * 30)
    
    try:
        pm = get_performance_manager()
        perf_status = pm.get_current_performance()
        
        if perf_status.get('status') != 'no_data':
            sys_metrics = perf_status.get('system', {})
            cache_metrics = perf_status.get('cache', {})
            
            # CPU Health
            cpu_percent = sys_metrics.get('cpu_percent', 0)
            if cpu_percent < 70:
                click.echo(f"✅ CPU Usage: {cpu_percent:.1f}% (Good)")
                overall_score += 10
            elif cpu_percent < 85:
                click.echo(f"⚠️  CPU Usage: {cpu_percent:.1f}% (High)")
                issues.append(f"High CPU usage: {cpu_percent:.1f}%")
                overall_score += 5
            else:
                click.echo(f"❌ CPU Usage: {cpu_percent:.1f}% (Critical)")
                issues.append(f"Critical CPU usage: {cpu_percent:.1f}%")
            
            # Memory Health
            memory_percent = sys_metrics.get('memory_percent', 0)
            if memory_percent < 80:
                click.echo(f"✅ Memory Usage: {memory_percent:.1f}% (Good)")
                overall_score += 10
            elif memory_percent < 90:
                click.echo(f"⚠️  Memory Usage: {memory_percent:.1f}% (High)")
                issues.append(f"High memory usage: {memory_percent:.1f}%")
                overall_score += 5
            else:
                click.echo(f"❌ Memory Usage: {memory_percent:.1f}% (Critical)")
                issues.append(f"Critical memory usage: {memory_percent:.1f}%")
            
            # Cache Health
            hit_rate = cache_metrics.get('hit_rate', 0)
            if hit_rate > 0.8:
                click.echo(f"✅ Cache Hit Rate: {hit_rate:.1%} (Excellent)")
                overall_score += 10
            elif hit_rate > 0.6:
                click.echo(f"⚠️  Cache Hit Rate: {hit_rate:.1%} (Fair)")
                overall_score += 5
            else:
                click.echo(f"❌ Cache Hit Rate: {hit_rate:.1%} (Poor)")
                issues.append(f"Poor cache performance: {hit_rate:.1%}")
        
        total_checks += 3
        
    except Exception:
        click.echo("❌ Performance monitoring unavailable")
        issues.append("Performance monitoring system not available")
    
    # Security Health
    click.echo("\n🔒 Security Health")
    click.echo("-" * 30)
    
    try:
        sm = get_enhanced_security_manager()
        security_status = sm.get_security_status()
        
        # Encryption
        if security_status.get('encryption_available'):
            click.echo("✅ Encryption: Available")
            overall_score += 10
        else:
            click.echo("⚠️  Encryption: Not available")
            issues.append("Encryption not available - install cryptography package")
        
        # Monitoring
        if security_status.get('monitoring_enabled'):
            click.echo("✅ Security Monitoring: Active")
            overall_score += 5
        else:
            click.echo("⚠️  Security Monitoring: Inactive")
            issues.append("Security monitoring is disabled")
        
        # Recent security events
        recent_events = security_status.get('recent_events', 0)
        if recent_events == 0:
            click.echo("✅ Security Events: None (24h)")
            overall_score += 5
        elif recent_events < 10:
            click.echo(f"⚠️  Security Events: {recent_events} (24h)")
            issues.append(f"Some security events detected: {recent_events}")
        else:
            click.echo(f"❌ Security Events: {recent_events} (24h)")
            issues.append(f"High security activity: {recent_events} events")
        
        total_checks += 3
        
    except Exception:
        click.echo("❌ Security system unavailable")
        issues.append("Security system not available")
    
    # Calculate final score
    final_score = (overall_score / (total_checks * 10)) * 100 if total_checks > 0 else 0
    
    # Health Summary
    click.echo("\n📋 HEALTH SUMMARY")
    click.echo("=" * 50)
    click.echo(f"Overall Health Score: {final_score:.1f}/100")
    
    if final_score >= 90:
        click.secho("🟢 EXCELLENT - System operating optimally", fg='green', bold=True)
    elif final_score >= 75:
        click.secho("🟢 GOOD - System healthy with minor issues", fg='green')
    elif final_score >= 60:
        click.secho("🟡 FAIR - System functional but needs attention", fg='yellow')
    elif final_score >= 40:
        click.secho("🟠 POOR - System has significant issues", fg='yellow')
    else:
        click.secho("🔴 CRITICAL - System requires immediate attention", fg='red', bold=True)
    
    # Issues and Recommendations
    if issues:
        click.echo(f"\n⚠️  ISSUES FOUND ({len(issues)}):")
        for i, issue in enumerate(issues, 1):
            click.echo(f"  {i}. {issue}")
        
        click.echo("\n💡 RECOMMENDATIONS:")
        
        if "Lightning node connection failed" in str(issues):
            click.echo("  • Check Lightning node is running and accessible")
            click.echo("  • Verify macaroon and TLS certificate paths")
            click.echo("  • Check network connectivity and firewall settings")
        
        if any("CPU" in issue for issue in issues):
            click.echo("  • Check for resource-intensive processes")
            click.echo("  • Consider optimizing system performance")
        
        if any("Memory" in issue for issue in issues):
            click.echo("  • Check for memory leaks or excessive usage")
            click.echo("  • Consider increasing system memory")
        
        if any("Cache" in issue for issue in issues):
            click.echo("  • Review cache configuration and size")
            click.echo("  • Clear cache or increase cache memory")
        
        if "No channels" in str(issues):
            click.echo("  • Open Lightning channels to start routing")
            click.echo("  • Connect to well-connected peers")
        
        if "sync" in str(issues).lower():
            click.echo("  • Wait for node synchronization to complete")
            click.echo("  • Check node logs for sync issues")
    
    else:
        click.echo("\n🎉 NO ISSUES FOUND - System is healthy!")
    
    return final_score >= 75  # Return success for CI/automation


@click.command()
@click.option('--format', 'output_format', default='table', type=click.Choice(['table', 'json', 'csv']),
              help='Output format')
@click.pass_context
def report(ctx: click.Context, output_format: str):
    """Generate comprehensive system report"""
    
    client: LightningClient = ctx.obj['client']
    report_data = {
        'timestamp': datetime.now().isoformat(),
        'node_info': {},
        'balance': {},
        'performance': {},
        'security': {},
        'liquidity': {},
        'health_score': 0
    }
    
    try:
        # Node information
        client.connect()
        report_data['node_info'] = client.get_info()
        
        # Balance information
        report_data['balance'] = client.get_balance()
        
        # Performance data
        pm = get_performance_manager()
        report_data['performance'] = pm.get_current_performance()
        
        # Security status
        sm = get_enhanced_security_manager()
        report_data['security'] = sm.get_security_status()
        
        # Liquidity analysis
        if report_data['node_info'].get('num_channels', 0) > 0:
            optimizer = get_liquidity_optimizer(client)
            report_data['liquidity'] = optimizer.get_liquidity_summary()
        
    except Exception as e:
        report_data['error'] = str(e)
    
    # Output based on format
    if output_format == 'json':
        import json
        click.echo(json.dumps(report_data, indent=2))
    
    elif output_format == 'csv':
        # Simple CSV output for key metrics
        click.echo("metric,value,timestamp")
        timestamp = report_data['timestamp']
        
        if report_data.get('node_info'):
            ni = report_data['node_info']
            click.echo(f"channels,{ni.get('num_channels', 0)},{timestamp}")
            click.echo(f"peers,{ni.get('num_peers', 0)},{timestamp}")
            click.echo(f"block_height,{ni.get('block_height', 0)},{timestamp}")
        
        if report_data.get('balance'):
            bal = report_data['balance']
            click.echo(f"onchain_confirmed,{bal.get('confirmed', 0)},{timestamp}")
            click.echo(f"lightning_local,{bal.get('channel_local', 0)},{timestamp}")
            click.echo(f"lightning_remote,{bal.get('channel_remote', 0)},{timestamp}")
        
    else:
        # Table format (default)
        click.echo("📊 BLNCS System Report")
        click.echo("=" * 60)
        click.echo(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if report_data.get('node_info'):
            ni = report_data['node_info']
            click.echo(f"\n🔗 Node: {ni.get('alias', 'Unknown')}")
            click.echo(f"Network: {ni.get('network', 'Unknown')}")
            click.echo(f"Channels: {ni.get('num_channels', 0)}")
            click.echo(f"Peers: {ni.get('num_peers', 0)}")
            click.echo(f"Block Height: {ni.get('block_height', 0):,}")
        
        if report_data.get('balance'):
            bal = report_data['balance']
            total_available = bal.get('confirmed', 0) + bal.get('channel_local', 0)
            click.echo(f"\n💰 Balance Summary:")
            click.echo(f"On-chain: {bal.get('confirmed', 0):,} sats")
            click.echo(f"Lightning: {bal.get('channel_local', 0):,} sats")
            click.echo(f"Available: {total_available:,} sats")
        
        if report_data.get('liquidity') and report_data['liquidity'].get('status') != 'no_data':
            liq = report_data['liquidity']
            click.echo(f"\n💧 Liquidity Health: {liq.get('health_status', 'unknown').title()}")
            click.echo(f"Health Score: {liq.get('average_liquidity_score', 0):.1f}/100")
            click.echo(f"Balanced Channels: {liq.get('balanced_channels', 0)}/{liq.get('total_channels', 0)}")
        
        click.echo(f"\n📄 Report saved to: blncs_report_{int(time.time())}.txt")
        
        # Save detailed report to file
        filename = f"blncs_report_{int(time.time())}.txt"
        try:
            import json
            with open(filename, 'w') as f:
                f.write("BLNCS System Report\n")
                f.write("=" * 50 + "\n")
                f.write(f"Generated: {datetime.now()}\n\n")
                f.write(json.dumps(report_data, indent=2))
            click.echo(f"✅ Detailed report saved to {filename}")
        except Exception as e:
            click.echo(f"⚠️  Failed to save report file: {e}")


# Add commands to the main CLI
__all__ = ['dashboard', 'monitor', 'health', 'report']