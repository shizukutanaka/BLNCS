"""
Simple Dashboard Command
Lightweight dashboard without heavy dependencies.
"""

import click
import time
from datetime import datetime
from typing import Dict, Any, Optional

from ...core.logger import get_logger
from ...core.exceptions import format_error_for_cli

logger = get_logger(__name__)


def format_sats(sats: int) -> str:
    """Format satoshi amount with commas"""
    return f"{sats:,}"


def get_balance_bar(local: int, capacity: int, width: int = 20) -> str:
    """Create a visual balance bar"""
    if capacity == 0:
        return "░" * width
    
    ratio = local / capacity
    filled = int(width * ratio)
    return "█" * filled + "░" * (width - filled)


@click.command()
@click.option('--refresh', '-r', default=0, help='Auto-refresh interval in seconds (0 = no refresh)')
@click.pass_context
def dashboard(ctx: click.Context, refresh: int) -> None:
    """Display Lightning node dashboard"""
    
    def render_dashboard():
        """Render the dashboard once"""
        try:
            from ...lightning.client import LightningClient
            from ...core.health import get_health_checker
            from ...core.network_monitor import get_network_monitor
            
            client: LightningClient = ctx.obj.get('client') or ctx.obj['get_client']()
            
            # Clear screen for refresh mode
            if refresh > 0:
                click.clear()
            
            # Header
            click.echo("=" * 80)
            click.echo("                    ⚡ BLNCS Lightning Dashboard ⚡")
            click.echo("=" * 80)
            click.echo(f"Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            click.echo()
            
            # Node Info Section
            try:
                info = client.get_info()
                
                click.echo("📡 NODE INFORMATION")
                click.echo("-" * 40)
                click.echo(f"Alias:       {info.get('alias', 'Unknown')}")
                click.echo(f"Public Key:  {info.get('identity_pubkey', 'N/A')[:20]}...")
                click.echo(f"Network:     {info.get('chains', [{}])[0].get('network', 'Unknown')}")
                click.echo(f"Block Height: {format_sats(info.get('block_height', 0))}")
                
                # Sync status
                chain_sync = "✅" if info.get('synced_to_chain') else "⏳"
                graph_sync = "✅" if info.get('synced_to_graph') else "⏳"
                click.echo(f"Sync Status: Chain {chain_sync}  Graph {graph_sync}")
                click.echo()
                
            except Exception as e:
                click.echo(f"Node Info: ❌ Error - {str(e)[:50]}")
                click.echo()
            
            # Balance Section
            try:
                wallet = client.wallet_balance()
                channel = client.channel_balance()
                
                click.echo("💰 BALANCES")
                click.echo("-" * 40)
                
                # On-chain
                confirmed = int(wallet.get('confirmed_balance', 0))
                unconfirmed = int(wallet.get('unconfirmed_balance', 0))
                click.echo(f"On-chain:    {format_sats(confirmed)} sats")
                if unconfirmed > 0:
                    click.echo(f"  Pending:   {format_sats(unconfirmed)} sats")
                
                # Lightning
                local_balance = int(channel.get('balance', 0))
                click.echo(f"Lightning:   {format_sats(local_balance)} sats")
                
                # Total
                total = confirmed + local_balance
                click.echo(f"Total Value: {format_sats(total)} sats")
                
                if total >= 100000:
                    btc_value = total / 100000000
                    click.echo(f"             ({btc_value:.8f} BTC)")
                click.echo()
                
            except Exception as e:
                click.echo(f"Balances: ❌ Error - {str(e)[:50]}")
                click.echo()
            
            # Channels Section
            try:
                channels = client.list_channels()
                
                click.echo("⚡ CHANNELS")
                click.echo("-" * 40)
                
                if not channels:
                    click.echo("No channels")
                else:
                    active_count = sum(1 for ch in channels if ch.get('active'))
                    total_capacity = sum(int(ch.get('capacity', 0)) for ch in channels)
                    total_local = sum(int(ch.get('local_balance', 0)) for ch in channels)
                    total_remote = sum(int(ch.get('remote_balance', 0)) for ch in channels)
                    
                    click.echo(f"Total Channels: {len(channels)} ({active_count} active)")
                    click.echo(f"Total Capacity: {format_sats(total_capacity)} sats")
                    
                    if total_capacity > 0:
                        local_pct = (total_local / total_capacity) * 100
                        click.echo(f"Local/Remote:   {local_pct:.1f}% / {100-local_pct:.1f}%")
                        
                        # Visual balance bar
                        bar = get_balance_bar(total_local, total_capacity, 30)
                        click.echo(f"Balance:        [{bar}]")
                    
                    # Show top channels
                    click.echo("\nTop Channels by Capacity:")
                    sorted_channels = sorted(channels, key=lambda x: int(x.get('capacity', 0)), reverse=True)
                    for i, ch in enumerate(sorted_channels[:3], 1):
                        capacity = int(ch.get('capacity', 0))
                        local = int(ch.get('local_balance', 0))
                        active = "✅" if ch.get('active') else "❌"
                        bar = get_balance_bar(local, capacity, 15)
                        click.echo(f"  {i}. {active} {format_sats(capacity):>12} sats [{bar}]")
                
                click.echo()
                
            except Exception as e:
                click.echo(f"Channels: ❌ Error - {str(e)[:50]}")
                click.echo()
            
            # System Health Section
            try:
                health_checker = get_health_checker()
                health_status = health_checker.get_quick_status()
                
                network_monitor = get_network_monitor()
                network_health = network_monitor.get_network_health()
                
                click.echo("🏥 SYSTEM HEALTH")
                click.echo("-" * 40)
                
                # Overall health
                health_icon = {
                    'healthy': '✅',
                    'warning': '⚠️',
                    'critical': '❌',
                    'unknown': '❓'
                }.get(health_status.get('status', 'unknown'), '❓')
                
                click.echo(f"Overall Status: {health_icon} {health_status.get('status', 'unknown').upper()}")
                
                # System resources (if available)
                if 'system' in health_status and 'cpu_percent' in health_status['system']:
                    sys_info = health_status['system']
                    click.echo(f"CPU Usage:      {sys_info['cpu_percent']}%")
                    click.echo(f"Memory Usage:   {sys_info['memory_percent']}%")
                
                # Network status
                net_icon = {
                    'healthy': '✅',
                    'degraded': '⚠️',
                    'critical': '❌'
                }.get(network_health.get('status', 'unknown'), '❓')
                
                click.echo(f"Network Status: {net_icon} {network_health.get('status', 'unknown').upper()}")
                
                if 'metrics' in network_health:
                    metrics = network_health['metrics']
                    if metrics.get('avg_latency_ms'):
                        click.echo(f"Avg Latency:    {metrics['avg_latency_ms']:.1f}ms")
                
                click.echo()
                
            except Exception as e:
                click.echo(f"Health: ❌ Error - {str(e)[:50]}")
                click.echo()
            
            # Recent Activity Section (if we have payment history)
            try:
                # This would show recent payments/invoices if available
                click.echo("📊 RECENT ACTIVITY")
                click.echo("-" * 40)
                click.echo("(Payment history not yet implemented)")
                click.echo()
                
            except Exception:
                pass
            
            # Footer
            click.echo("=" * 80)
            
            if refresh > 0:
                click.echo(f"Auto-refresh every {refresh} seconds. Press Ctrl+C to exit.")
            else:
                click.echo("Use --refresh N to auto-refresh every N seconds")
                
        except Exception as e:
            click.echo(f"❌ Dashboard Error: {format_error_for_cli(e)}", err=True)
    
    # Main execution
    try:
        if refresh > 0:
            # Auto-refresh mode
            click.echo("Starting dashboard with auto-refresh...")
            while True:
                try:
                    render_dashboard()
                    time.sleep(refresh)
                except KeyboardInterrupt:
                    click.echo("\n\nDashboard stopped.")
                    break
        else:
            # Single render
            render_dashboard()
            
    except Exception as e:
        click.echo(f"❌ Error: {format_error_for_cli(e)}", err=True)


@click.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Quick status overview (simpler than dashboard)"""
    try:
        from ...lightning.client import LightningClient
        from ...core.health import get_health_status
        
        client: LightningClient = ctx.obj.get('client') or ctx.obj['get_client']()
        
        # Get basic info
        info = client.get_info()
        wallet = client.wallet_balance()
        channels = client.list_channels()
        health = get_health_status()
        
        # Display status
        click.echo("⚡ BLNCS Status")
        click.echo("=" * 40)
        
        # Connection
        if info:
            click.echo(f"✅ Connected to: {info.get('alias', 'Unknown')}")
            click.echo(f"   Synced: {'Yes' if info.get('synced_to_chain') else 'No'}")
        else:
            click.echo("❌ Not connected to Lightning node")
            return
        
        # Balance
        total_sats = int(wallet.get('confirmed_balance', 0)) + int(wallet.get('unconfirmed_balance', 0))
        click.echo(f"💰 Balance: {format_sats(total_sats)} sats")
        
        # Channels
        active_channels = sum(1 for ch in channels if ch.get('active'))
        click.echo(f"⚡ Channels: {active_channels}/{len(channels)} active")
        
        # Health
        health_icon = "✅" if health.get('status') == 'healthy' else "⚠️"
        click.echo(f"🏥 Health: {health_icon} {health.get('status', 'unknown')}")
        
        click.echo("=" * 40)
        click.echo("Run 'dashboard' for detailed view")
        
    except Exception as e:
        click.echo(f"❌ Error: {format_error_for_cli(e)}", err=True)