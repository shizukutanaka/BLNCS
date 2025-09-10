"""
Simple Lightning Network Dashboard
Clean, practical dashboard without unnecessary complexity.
"""

import click
import time
import os
from datetime import datetime, timedelta
from typing import Dict, Any, List

from ...lightning.client import LightningClient
from ...core.exceptions import format_error_for_cli
from ...core.database import get_database_manager
from ...core.health import get_health_checker
from ...core.config_manager import get_config_manager


def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')


def format_sats(amount: int) -> str:
    """Format satoshi amounts with appropriate units"""
    if amount == 0:
        return "0 sats"
    elif amount < 1000:
        return f"{amount} sats"
    elif amount < 1000000:
        return f"{amount/1000:.1f}K sats"
    else:
        return f"{amount/1000000:.2f}M sats"


def format_percentage(ratio: float) -> str:
    """Format ratio as percentage"""
    return f"{ratio*100:.1f}%"


@click.command()
@click.option('--refresh', '-r', default=0, help='Auto-refresh interval in seconds (0 = no refresh)')
@click.option('--compact', '-c', is_flag=True, help='Compact view with less detail')
@click.pass_context
def dashboard(ctx: click.Context, refresh: int, compact: bool) -> None:
    """Simple system dashboard with essential information"""
    
    def display_dashboard():
        try:
            # Clear screen for refresh
            if refresh > 0:
                clear_screen()
            
            # Get client
            client = ctx.obj.get('client') or ctx.obj['get_client']()
            
            # Header
            click.echo("BLNCS Dashboard")
            click.echo("=" * 50)
            click.echo(f"Updated: {datetime.now().strftime('%H:%M:%S')}")
            click.echo()
            
            # System Status
            click.echo("System Status:")
            system_status = get_system_status()
            for component, status in system_status.items():
                status_text = "OK" if status['healthy'] else "ERROR"
                click.echo(f"  {component}: {status_text}")
                if not status['healthy'] and 'error' in status:
                    click.echo(f"    Error: {status['error']}")
            click.echo()
            
            # Lightning Node Status
            click.echo("Lightning Node:")
            node_info = get_node_info(client)
            
            if node_info['connected']:
                info = node_info['info']
                balance = node_info['balance']
                channels = node_info['channels']
                
                click.echo(f"  Node: {info.get('alias', 'Unknown')}")
                click.echo(f"  Network: {info.get('network', 'unknown')}")
                click.echo(f"  Synced: {'Yes' if info.get('synced_to_chain') else 'No'}")
                click.echo(f"  Block: {info.get('block_height', 0):,}")
                click.echo(f"  Peers: {info.get('num_peers', 0)}")
                click.echo()
                
                # Balances
                click.echo("Balances:")
                click.echo(f"  Wallet: {format_sats(balance.get('confirmed', 0))}")
                click.echo(f"  Channel Local: {format_sats(balance.get('channel_local', 0))}")
                click.echo(f"  Channel Remote: {format_sats(balance.get('channel_remote', 0))}")
                click.echo()
                
                # Channels
                if channels:
                    active_channels = [ch for ch in channels if ch.get('active')]
                    total_capacity = sum(ch.get('capacity', 0) for ch in channels)
                    total_local = sum(ch.get('local_balance', 0) for ch in channels)
                    local_ratio = total_local / total_capacity if total_capacity > 0 else 0
                    
                    click.echo("Channels:")
                    click.echo(f"  Active: {len(active_channels)}/{len(channels)}")
                    click.echo(f"  Total Capacity: {format_sats(total_capacity)}")
                    click.echo(f"  Local Balance: {format_percentage(local_ratio)}")
                    
                    if not compact and len(channels) > 0:
                        click.echo()
                        click.echo("Top Channels:")
                        sorted_channels = sorted(channels, key=lambda x: x.get('capacity', 0), reverse=True)
                        for i, ch in enumerate(sorted_channels[:5], 1):
                            capacity = ch.get('capacity', 0)
                            local_bal = ch.get('local_balance', 0)
                            local_pct = (local_bal / capacity) if capacity > 0 else 0
                            active_text = "Active" if ch.get('active') else "Inactive"
                            click.echo(f"    {i}. {format_sats(capacity)} ({format_percentage(local_pct)} local) - {active_text}")
                else:
                    click.echo("Channels: No channels found")
                
                click.echo()
                
                # Recent Activity (if not compact)
                if not compact:
                    activity = get_recent_activity(client)
                    click.echo("Recent Activity (24h):")
                    click.echo(f"  Forwards: {activity['forward_count']}")
                    click.echo(f"  Volume: {format_sats(activity['volume_forwarded'])}")
                    click.echo(f"  Fees Earned: {format_sats(activity['fees_earned'])}")
                    if activity['avg_fee_rate'] > 0:
                        click.echo(f"  Avg Fee Rate: {activity['avg_fee_rate']:.0f} ppm")
                    click.echo()
                
            else:
                click.echo(f"  Status: Disconnected")
                if 'error' in node_info:
                    click.echo(f"  Error: {node_info['error']}")
                click.echo()
            
            # Quick Actions
            if not compact:
                click.echo("Quick Commands:")
                click.echo("  blncs balance          - Show detailed balance")
                click.echo("  blncs channels         - List all channels")  
                click.echo("  blncs quick-connect    - Connect to Lightning network")
                click.echo("  blncs node-discover    - Find Lightning nodes")
                click.echo()
            
        except Exception as e:
            click.echo(f"Dashboard error: {format_error_for_cli(e)}")
    
    # Main display loop
    try:
        if refresh > 0:
            click.echo(f"Auto-refreshing every {refresh} seconds. Press Ctrl+C to stop.")
            while True:
                display_dashboard()
                time.sleep(refresh)
        else:
            display_dashboard()
            
    except KeyboardInterrupt:
        if refresh > 0:
            click.echo("\nDashboard stopped.")


@click.command()
@click.pass_context  
def system_overview(ctx: click.Context) -> None:
    """Quick system overview with essential metrics"""
    try:
        client = ctx.obj.get('client') or ctx.obj['get_client']()
        
        click.echo("BLNCS System Overview")
        click.echo("=" * 30)
        
        # System health
        system_status = get_system_status()
        all_healthy = all(status['healthy'] for status in system_status.values())
        overall_status = "Healthy" if all_healthy else "Issues Detected"
        click.echo(f"Overall Status: {overall_status}")
        
        if not all_healthy:
            click.echo("Issues:")
            for component, status in system_status.items():
                if not status['healthy']:
                    click.echo(f"  - {component}: {status.get('error', 'Unknown error')}")
        
        click.echo()
        
        # Lightning status
        node_info = get_node_info(client)
        if node_info['connected']:
            info = node_info['info']
            balance = node_info['balance']
            channels = node_info['channels']
            
            click.echo("Lightning Network:")
            click.echo(f"  Node: {info.get('alias', 'Unknown')}")
            click.echo(f"  Wallet: {format_sats(balance.get('confirmed', 0))}")
            
            if channels:
                active_channels = len([ch for ch in channels if ch.get('active')])
                total_capacity = sum(ch.get('capacity', 0) for ch in channels)
                click.echo(f"  Channels: {active_channels}/{len(channels)} active")
                click.echo(f"  Capacity: {format_sats(total_capacity)}")
            else:
                click.echo("  Channels: None")
        else:
            click.echo("Lightning Network: Not connected")
        
        click.echo()
        
        # Database status
        db_status = get_database_status()
        click.echo("Database:")
        click.echo(f"  Status: {db_status['status']}")
        if db_status['size_mb'] > 0:
            click.echo(f"  Size: {db_status['size_mb']:.1f} MB")
        
        # Recent activity summary
        if node_info['connected']:
            activity = get_recent_activity(client)
            if activity['forward_count'] > 0:
                click.echo()
                click.echo("Recent Activity (24h):")
                click.echo(f"  {activity['forward_count']} forwards")
                click.echo(f"  {format_sats(activity['fees_earned'])} fees earned")
        
    except Exception as e:
        click.echo(f"System overview error: {format_error_for_cli(e)}", err=True)


def get_system_status() -> Dict[str, Dict[str, Any]]:
    """Get system component status"""
    status = {}
    
    # Database
    try:
        db = get_database_manager()
        # Simple database test
        db.execute_query("SELECT 1")
        status['Database'] = {'healthy': True}
    except Exception as e:
        status['Database'] = {'healthy': False, 'error': str(e)}
    
    # Configuration
    try:
        config = get_config_manager()
        config_data = config.get_all()
        status['Configuration'] = {'healthy': bool(config_data)}
    except Exception as e:
        status['Configuration'] = {'healthy': False, 'error': str(e)}
    
    # Health checker
    try:
        health = get_health_checker()
        quick_status = health.get_quick_status()
        status['Health Monitor'] = {
            'healthy': quick_status.get('status') != 'critical',
            'status': quick_status.get('status', 'unknown')
        }
    except Exception as e:
        status['Health Monitor'] = {'healthy': False, 'error': str(e)}
    
    return status


def get_node_info(client: LightningClient) -> Dict[str, Any]:
    """Get Lightning node information"""
    try:
        client.connect()
        
        info = client.get_info()
        balance = client.get_balance() 
        channels = client.list_channels()
        
        client.disconnect()
        
        return {
            'connected': True,
            'info': info,
            'balance': balance,
            'channels': channels
        }
        
    except Exception as e:
        try:
            client.disconnect()
        except:
            pass
        
        return {
            'connected': False,
            'error': str(e)
        }


def get_recent_activity(client: LightningClient) -> Dict[str, Any]:
    """Get recent Lightning activity"""
    try:
        # Get forwarding events from last 24 hours
        end_time = int(datetime.now().timestamp())
        start_time = end_time - (24 * 3600)  # 24 hours ago
        
        forwards = client.get_forwarding_events(start_time, end_time)
        
        total_volume = sum(event.get('amt_in_msat', 0) for event in forwards) // 1000
        total_fees = sum(event.get('fee_msat', 0) for event in forwards) // 1000
        
        avg_fee_rate = 0
        if total_volume > 0:
            avg_fee_rate = (total_fees / total_volume) * 1000000  # Convert to ppm
        
        return {
            'forward_count': len(forwards),
            'volume_forwarded': total_volume,
            'fees_earned': total_fees,
            'avg_fee_rate': avg_fee_rate
        }
        
    except Exception:
        return {
            'forward_count': 0,
            'volume_forwarded': 0,
            'fees_earned': 0,
            'avg_fee_rate': 0
        }


def get_database_status() -> Dict[str, Any]:
    """Get database status information"""
    try:
        db = get_database_manager()
        
        # Get database file size
        import os
        db_path = db.db_path
        size_mb = 0
        
        if os.path.exists(db_path):
            size_bytes = os.path.getsize(db_path)
            size_mb = size_bytes / (1024 * 1024)
        
        return {
            'status': 'Connected',
            'path': db_path,
            'size_mb': size_mb
        }
        
    except Exception as e:
        return {
            'status': 'Error',
            'error': str(e),
            'size_mb': 0
        }