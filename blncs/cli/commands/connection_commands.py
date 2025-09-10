"""
One-Click Connection CLI Commands
Simple Lightning Network connection management.
"""

import click
from datetime import datetime
from typing import Dict, Any

from ...core.one_click_connector import get_one_click_connector
from ...core.exceptions import format_error_for_cli


@click.command()
@click.option('--network', default='testnet', type=click.Choice(['mainnet', 'testnet', 'regtest']),
              help='Bitcoin network to connect to')
@click.option('--timeout', default=30, help='Connection timeout in seconds')
def quick_connect(network: str, timeout: int) -> None:
    """One-click Lightning Network connection"""
    try:
        connector = get_one_click_connector()
        
        click.echo(f"Starting one-click connection to {network} network...")
        click.echo("Scanning for available Lightning nodes...")
        
        result = connector.quick_connect(network=network, timeout=timeout)
        
        if result.success:
            node_info = result.node_info or {}
            click.echo("Connection successful!")
            click.echo(f"  Node: {result.config.name}")
            click.echo(f"  Alias: {node_info.get('alias', 'Unknown')}")
            click.echo(f"  Network: {result.config.network}")
            click.echo(f"  Host: {result.config.host}:{result.config.port}")
            if result.config.auto_detected:
                click.echo("  Auto-detected configuration")
            click.echo(f"  Response time: {result.response_time * 1000:.0f}ms")
            
            # Show basic node info
            if node_info:
                click.echo(f"\nNode Information:")
                click.echo(f"  Public Key: {node_info.get('identity_pubkey', 'Unknown')[:20]}...")
                click.echo(f"  Channels: {node_info.get('num_channels', 0)}")
                click.echo(f"  Peers: {node_info.get('num_peers', 0)}")
                click.echo(f"  Synced: {'Yes' if node_info.get('synced_to_chain') else 'No'}")
        else:
            click.echo("Connection failed!", err=True)
            click.echo(f"Error: {result.error}", err=True)
            click.echo("\nTry running 'connection scan' to see available options")
            
    except Exception as e:
        click.echo(f"Error during quick connect: {format_error_for_cli(e)}", err=True)


@click.command()
@click.option('--network', default='testnet', type=click.Choice(['mainnet', 'testnet', 'regtest']),
              help='Bitcoin network to scan')
def connection_scan(network: str) -> None:
    """Scan for available Lightning nodes"""
    try:
        connector = get_one_click_connector()
        
        click.echo(f"Scanning for Lightning nodes on {network} network...")
        
        results = connector.scan_network(network)
        
        if not results:
            click.echo("No nodes found during scan")
            return
        
        successful = [r for r in results if r.success]
        failed = [r for r in results if not r.success]
        
        if successful:
            click.echo(f"\nAvailable Nodes ({len(successful)}):")
            click.echo("=" * 50)
            
            for result in successful:
                node_info = result.node_info or {}
                status_icon = "✅"
                if result.config.auto_detected:
                    status_icon += " 🔍"
                
                click.echo(f"{status_icon} {result.config.name}")
                click.echo(f"    Host: {result.config.host}:{result.config.port}")
                click.echo(f"    Network: {result.config.network}")
                click.echo(f"    Alias: {node_info.get('alias', 'Unknown')}")
                click.echo(f"    Response: {result.response_time * 1000:.0f}ms")
                if result.config.macaroon_path:
                    click.echo(f"    Auth: Macaroon available")
                click.echo()
        
        if failed:
            click.echo(f"\nUnavailable Nodes ({len(failed)}):")
            click.echo("=" * 30)
            
            for result in failed[:5]:  # Show only first 5 failures
                click.echo(f"❌ {result.config.name}")
                click.echo(f"    Host: {result.config.host}:{result.config.port}")
                click.echo(f"    Error: {result.error}")
                click.echo()
            
            if len(failed) > 5:
                click.echo(f"... and {len(failed) - 5} more")
        
        if successful:
            click.echo("Use 'quick-connect' to connect to the best available node")
        else:
            click.echo("No working Lightning nodes found. Check your setup.")
            
    except Exception as e:
        click.echo(f"Error during scan: {format_error_for_cli(e)}", err=True)


@click.command()
def connection_reconnect() -> None:
    """Reconnect to the last successful connection"""
    try:
        connector = get_one_click_connector()
        
        click.echo("Attempting to reconnect to last successful connection...")
        
        result = connector.reconnect_last()
        
        if result.success:
            node_info = result.node_info or {}
            click.echo("Reconnection successful!")
            click.echo(f"  Node: {result.config.name}")
            click.echo(f"  Alias: {node_info.get('alias', 'Unknown')}")
            click.echo(f"  Network: {result.config.network}")
            click.echo(f"  Response time: {result.response_time * 1000:.0f}ms")
        else:
            click.echo("Reconnection failed!", err=True)
            click.echo(f"Error: {result.error}", err=True)
            click.echo("\nTry running 'quick-connect' to find a new connection")
            
    except Exception as e:
        click.echo(f"Error during reconnect: {format_error_for_cli(e)}", err=True)


@click.command()
def connection_setup() -> None:
    """Interactive Lightning Network setup wizard"""
    try:
        connector = get_one_click_connector()
        
        result = connector.setup_wizard(interactive=True)
        
        if result.success:
            click.echo("\nSetup completed successfully!")
            click.echo("You can now use other BLNCS commands.")
        else:
            click.echo("\nSetup failed. Please check your Lightning node configuration.")
            
    except KeyboardInterrupt:
        click.echo("\nSetup cancelled by user")
    except Exception as e:
        click.echo(f"Error during setup: {format_error_for_cli(e)}", err=True)


@click.command()
def connection_history() -> None:
    """Show connection history"""
    try:
        connector = get_one_click_connector()
        
        history = connector.get_connection_history()
        
        if not history:
            click.echo("No connection history found")
            return
        
        click.echo("Connection History:")
        click.echo("=" * 40)
        
        for entry in history[-10:]:  # Show last 10
            timestamp = datetime.fromtimestamp(entry.get('timestamp', 0))
            click.echo(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} - {entry.get('name', 'Unknown')}")
            config = entry.get('config', {})
            click.echo(f"  {config.get('host', 'Unknown')}:{config.get('port', 'Unknown')} ({config.get('network', 'Unknown')})")
            click.echo()
            
    except Exception as e:
        click.echo(f"Error getting connection history: {format_error_for_cli(e)}", err=True)


@click.command()
@click.option('--network', default='testnet', type=click.Choice(['mainnet', 'testnet', 'regtest']),
              help='Bitcoin network')
def connection_status() -> None:
    """Show current connection status"""
    try:
        from ...core.config_manager import get_config_manager
        from ...lightning.client import LightningClient
        
        config_manager = get_config_manager()
        lightning_config = config_manager.get('lightning', {})
        
        if not lightning_config:
            click.echo("No Lightning connection configured")
            click.echo("Run 'connection setup' or 'quick-connect' to get started")
            return
        
        click.echo("Current Connection Configuration:")
        click.echo("=" * 40)
        click.echo(f"Host: {lightning_config.get('host', 'Unknown')}")
        click.echo(f"Port: {lightning_config.get('port', 'Unknown')}")
        click.echo(f"Network: {lightning_config.get('network', 'Unknown')}")
        click.echo(f"Auto-detected: {'Yes' if lightning_config.get('auto_detected') else 'No'}")
        
        # Test current connection
        click.echo("\nTesting connection...")
        try:
            client = LightningClient()
            info = client.get_info()
            
            if info and info.get('identity_pubkey'):
                click.echo("✅ Connection active")
                click.echo(f"  Alias: {info.get('alias', 'Unknown')}")
                click.echo(f"  Public Key: {info.get('identity_pubkey', 'Unknown')[:20]}...")
                click.echo(f"  Channels: {info.get('num_channels', 0)}")
                click.echo(f"  Peers: {info.get('num_peers', 0)}")
                click.echo(f"  Synced: {'Yes' if info.get('synced_to_chain') else 'No'}")
            else:
                click.echo("❌ Connection failed - Invalid response")
                
        except Exception as e:
            click.echo(f"❌ Connection failed - {e}")
            click.echo("Try running 'connection reconnect' or 'quick-connect'")
            
    except Exception as e:
        click.echo(f"Error checking connection status: {format_error_for_cli(e)}", err=True)