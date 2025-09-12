"""
Basic Lightning Network Commands
Lightweight implementations without heavy dependencies.
"""

import click
import json
from typing import Dict, Any, Optional
from ...core.logger import get_logger
from ...core.exceptions import format_error_for_cli

logger = get_logger(__name__)


@click.command()
@click.pass_context
def info(ctx: click.Context) -> None:
    """Show Lightning node information"""
    try:
        from ...lightning.client import LightningClient
        client: LightningClient = ctx.obj.get('client') or ctx.obj['get_client']()
        
        info_data = client.get_info()
        
        click.echo("⚡ Lightning Node Information")
        click.echo("=" * 50)
        click.echo(f"Alias: {info_data.get('alias', 'Unknown')}")
        click.echo(f"Public Key: {info_data.get('identity_pubkey', 'N/A')[:20]}...")
        click.echo(f"Version: {info_data.get('version', 'Unknown')}")
        click.echo(f"Chain: {info_data.get('chains', [{}])[0].get('chain', 'Unknown')}")
        click.echo(f"Network: {info_data.get('chains', [{}])[0].get('network', 'Unknown')}")
        click.echo(f"Block Height: {info_data.get('block_height', 0):,}")
        click.echo(f"Synced to Chain: {'✅' if info_data.get('synced_to_chain') else '❌'}")
        click.echo(f"Synced to Graph: {'✅' if info_data.get('synced_to_graph') else '❌'}")
        click.echo(f"Active Channels: {info_data.get('num_active_channels', 0)}")
        click.echo(f"Peers: {info_data.get('num_peers', 0)}")
        
    except Exception as e:
        click.echo(f"❌ Error: {format_error_for_cli(e)}", err=True)


@click.command()
@click.pass_context
def balance(ctx: click.Context) -> None:
    """Show wallet and channel balances"""
    try:
        from ...lightning.client import LightningClient
        client: LightningClient = ctx.obj.get('client') or ctx.obj['get_client']()
        
        # Get wallet balance
        wallet = client.wallet_balance()
        channel = client.channel_balance()
        
        click.echo("💰 Balances")
        click.echo("=" * 50)
        
        # Wallet balance
        click.echo("\n📱 On-chain Wallet:")
        confirmed = int(wallet.get('confirmed_balance', 0))
        unconfirmed = int(wallet.get('unconfirmed_balance', 0))
        total_wallet = confirmed + unconfirmed
        
        click.echo(f"  Confirmed:   {confirmed:>12,} sats")
        if unconfirmed > 0:
            click.echo(f"  Unconfirmed: {unconfirmed:>12,} sats")
        click.echo(f"  Total:       {total_wallet:>12,} sats")
        
        # Channel balance
        click.echo("\n⚡ Lightning Channels:")
        local_balance = int(channel.get('balance', 0))
        pending_open = int(channel.get('pending_open_balance', 0))
        
        click.echo(f"  Available:   {local_balance:>12,} sats")
        if pending_open > 0:
            click.echo(f"  Pending:     {pending_open:>12,} sats")
        
        # Total
        click.echo("\n💎 Total Value:")
        total_value = total_wallet + local_balance + pending_open
        click.echo(f"  {total_value:>12,} sats")
        
        # Show in BTC if large enough
        if total_value >= 100000:
            btc_value = total_value / 100000000
            click.echo(f"  ({btc_value:.8f} BTC)")
            
    except Exception as e:
        click.echo(f"❌ Error: {format_error_for_cli(e)}", err=True)


@click.command()
@click.pass_context
def channels(ctx: click.Context) -> None:
    """List Lightning channels"""
    try:
        from ...lightning.client import LightningClient
        client: LightningClient = ctx.obj.get('client') or ctx.obj['get_client']()
        
        channels_list = client.list_channels()
        
        if not channels_list:
            click.echo("No channels found")
            return
        
        click.echo(f"⚡ Lightning Channels ({len(channels_list)} total)")
        click.echo("=" * 80)
        
        total_capacity = 0
        total_local = 0
        total_remote = 0
        
        for ch in channels_list:
            capacity = int(ch.get('capacity', 0))
            local = int(ch.get('local_balance', 0))
            remote = int(ch.get('remote_balance', 0))
            
            total_capacity += capacity
            total_local += local
            total_remote += remote
            
            # Channel info
            chan_id = ch.get('chan_id', 'Unknown')
            active = ch.get('active', False)
            status = "✅" if active else "❌"
            
            # Calculate balance ratio
            ratio = (local / capacity * 100) if capacity > 0 else 0
            
            click.echo(f"\nChannel: {chan_id}")
            click.echo(f"  Status: {status} {'Active' if active else 'Inactive'}")
            click.echo(f"  Capacity: {capacity:,} sats")
            click.echo(f"  Local:    {local:,} sats ({ratio:.1f}%)")
            click.echo(f"  Remote:   {remote:,} sats ({100-ratio:.1f}%)")
            
            # Show balance bar
            bar_length = 30
            filled = int(bar_length * ratio / 100)
            bar = "█" * filled + "░" * (bar_length - filled)
            click.echo(f"  Balance: [{bar}]")
        
        # Summary
        click.echo("\n" + "=" * 80)
        click.echo(f"Total Capacity: {total_capacity:,} sats")
        click.echo(f"Total Local:    {total_local:,} sats")
        click.echo(f"Total Remote:   {total_remote:,} sats")
        
        if total_capacity > 0:
            overall_ratio = (total_local / total_capacity * 100)
            click.echo(f"Overall Balance: {overall_ratio:.1f}% local / {100-overall_ratio:.1f}% remote")
            
    except Exception as e:
        click.echo(f"❌ Error: {format_error_for_cli(e)}", err=True)


@click.command()
@click.pass_context
def lightning_ping(ctx: click.Context) -> None:
    """Test Lightning node connectivity"""
    try:
        from ...lightning.client import LightningClient
        import time
        
        client: LightningClient = ctx.obj.get('client') or ctx.obj['get_client']()
        
        click.echo("🏓 Testing Lightning node connectivity...")
        
        # Measure response time
        start = time.time()
        info = client.get_info()
        response_time = (time.time() - start) * 1000
        
        if info:
            click.echo(f"✅ Lightning node is responding")
            click.echo(f"   Response time: {response_time:.1f}ms")
            click.echo(f"   Node: {info.get('alias', 'Unknown')}")
            click.echo(f"   Synced: {'Yes' if info.get('synced_to_chain') else 'No'}")
        else:
            click.echo("❌ No response from Lightning node")
            
    except Exception as e:
        click.echo(f"❌ Connection failed: {format_error_for_cli(e)}", err=True)


@click.command()
@click.pass_context  
def connectivity_check(ctx: click.Context) -> None:
    """Check overall connectivity status"""
    try:
        from ...core.network_monitor import get_network_monitor
        from ...lightning.client import LightningClient
        
        click.echo("🔍 Connectivity Check")
        click.echo("=" * 50)
        
        # Network connectivity
        monitor = get_network_monitor()
        network_health = monitor.get_network_health()
        
        click.echo(f"\n📡 Network Status: {network_health['status'].upper()}")
        if 'endpoints' in network_health:
            endpoints = network_health['endpoints']
            click.echo(f"   Healthy endpoints: {endpoints.get('healthy', 0)}/{endpoints.get('total', 0)}")
        
        # Lightning connectivity
        try:
            client: LightningClient = ctx.obj.get('client') or ctx.obj['get_client']()
            info = client.get_info()
            
            click.echo(f"\n⚡ Lightning Status: {'CONNECTED' if info else 'DISCONNECTED'}")
            if info:
                click.echo(f"   Node: {info.get('alias', 'Unknown')}")
                click.echo(f"   Peers: {info.get('num_peers', 0)}")
                click.echo(f"   Channels: {info.get('num_active_channels', 0)}")
        except:
            click.echo("\n⚡ Lightning Status: DISCONNECTED")
        
        # Overall status
        overall_status = "✅ All systems operational" if network_health['status'] == 'healthy' else "⚠️ Some issues detected"
        click.echo(f"\n{overall_status}")
        
    except Exception as e:
        click.echo(f"❌ Error: {format_error_for_cli(e)}", err=True)


@click.command()
@click.pass_context
def system_info(ctx: click.Context) -> None:
    """Show system information and resource usage"""
    try:
        import platform
        import os
        from pathlib import Path
        
        click.echo("🖥️ System Information")
        click.echo("=" * 50)
        
        # Basic system info
        click.echo(f"Platform: {platform.system()} {platform.release()}")
        click.echo(f"Python: {platform.python_version()}")
        click.echo(f"Architecture: {platform.machine()}")
        
        # Try to get resource info if psutil available
        try:
            import psutil
            
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            click.echo(f"\n💻 CPU: {cpu_percent}% ({cpu_count} cores)")
            
            # Memory
            memory = psutil.virtual_memory()
            mem_used_gb = memory.used / (1024**3)
            mem_total_gb = memory.total / (1024**3)
            click.echo(f"💾 Memory: {memory.percent}% ({mem_used_gb:.1f}/{mem_total_gb:.1f} GB)")
            
            # Disk
            disk = psutil.disk_usage('/')
            disk_used_gb = disk.used / (1024**3)
            disk_total_gb = disk.total / (1024**3)
            click.echo(f"💿 Disk: {disk.percent}% ({disk_used_gb:.1f}/{disk_total_gb:.1f} GB)")
            
        except ImportError:
            click.echo("\n(Install psutil for detailed resource information)")
        
        # BLNCS info
        click.echo("\n📦 BLNCS Information")
        click.echo(f"Config path: {ctx.obj['config'].get('config_path', 'default')}")
        
        # Check important directories
        data_dir = Path(ctx.obj['config'].get('data_dir', './data'))
        if data_dir.exists():
            click.echo(f"Data directory: {data_dir} ✅")
        else:
            click.echo(f"Data directory: {data_dir} ❌ (not found)")
            
    except Exception as e:
        click.echo(f"❌ Error: {format_error_for_cli(e)}", err=True)


@click.command()
@click.option('--key', required=True, help='Configuration key to get')
@click.pass_context
def config_get(ctx: click.Context, key: str) -> None:
    """Get configuration value"""
    try:
        from ...core.config_manager import get_config_manager
        
        config_manager = get_config_manager()
        value = config_manager.get(key)
        
        if value is not None:
            if isinstance(value, (dict, list)):
                click.echo(json.dumps(value, indent=2))
            else:
                click.echo(value)
        else:
            click.echo(f"Configuration key '{key}' not found", err=True)
            
    except Exception as e:
        click.echo(f"❌ Error: {format_error_for_cli(e)}", err=True)


@click.command()
@click.option('--key', required=True, help='Configuration key to set')
@click.option('--value', required=True, help='Value to set')
@click.pass_context
def config_set(ctx: click.Context, key: str, value: str) -> None:
    """Set configuration value"""
    try:
        from ...core.config_manager import get_config_manager
        
        config_manager = get_config_manager()
        
        # Try to parse as JSON if it looks like JSON
        parsed_value = value
        if value.startswith('{') or value.startswith('['):
            try:
                parsed_value = json.loads(value)
            except:
                pass  # Use as string
        
        config_manager.set(key, parsed_value)
        config_manager.save()
        
        click.echo(f"✅ Set {key} = {parsed_value}")
        
    except Exception as e:
        click.echo(f"❌ Error: {format_error_for_cli(e)}", err=True)


@click.command()
@click.option('--quick', is_flag=True, help='Quick health check only')
@click.pass_context
def health_check(ctx: click.Context, quick: bool) -> None:
    """System health check"""
    try:
        from ...core.health import get_health_checker
        
        checker = get_health_checker()
        
        if quick:
            # Quick status check
            status = checker.get_quick_status()
            
            click.echo("🏥 Quick Health Check")
            click.echo("=" * 50)
            click.echo(f"Overall Status: {status['status'].upper()}")
            
            if 'lightning_node' in status:
                ln = status['lightning_node']
                click.echo(f"\n⚡ Lightning: {ln.get('status', 'unknown').upper()}")
                if ln.get('alias'):
                    click.echo(f"   Node: {ln['alias']}")
                    click.echo(f"   Synced: {'Yes' if ln.get('synced') else 'No'}")
            
            if 'system' in status:
                sys = status['system']
                if 'cpu_percent' in sys:
                    click.echo(f"\n💻 System:")
                    click.echo(f"   CPU: {sys['cpu_percent']}%")
                    click.echo(f"   Memory: {sys['memory_percent']}%")
        else:
            # Full health check
            click.echo("🏥 Running full health check...")
            report = checker.run_full_health_check()
            
            click.echo("\n" + "=" * 50)
            click.echo(f"Overall Status: {report['overall_status'].upper()}")
            click.echo(f"Health Score: {report['health_score']}/100")
            click.echo(f"Check Duration: {report['check_duration']:.2f}s")
            
            # Show individual check results
            click.echo("\n📊 Check Results:")
            for check_name, check_data in report['checks'].items():
                status_icon = "✅" if check_data['status'] == 'healthy' else "⚠️" if check_data['status'] == 'warning' else "❌"
                click.echo(f"  {status_icon} {check_name}: {check_data['status']}")
                if check_data.get('message'):
                    click.echo(f"     {check_data['message']}")
            
            # Show suggestions if any
            if report.get('recovery_suggestions'):
                click.echo("\n💡 Suggestions:")
                for suggestion in report['recovery_suggestions']:
                    click.echo(f"  • {suggestion}")
                    
    except Exception as e:
        click.echo(f"❌ Error: {format_error_for_cli(e)}", err=True)