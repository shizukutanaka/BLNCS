"""
Core CLI Commands
Following Pike: do one thing well - essential Lightning Network operations only.
"""

import click
from typing import Optional
from pathlib import Path


@click.group(name='blncs')
@click.version_option(version='1.0.0')
@click.option('--config', '-c', help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.pass_context
def cli(ctx, config, verbose):
    """Bitcoin Lightning Network Control System - Simple and Direct"""
    ctx.ensure_object(dict)
    ctx.obj['config'] = config
    ctx.obj['verbose'] = verbose


@cli.command()
@click.pass_context
def info(ctx):
    """Show Lightning node information"""
    try:
        from blncs.lightning.client import create_client
        from blncs.core import get_config
        
        config = get_config()
        client = create_client(config.get_all())
        
        if client.connect():
            info = client.get_info()
            click.echo(f"Node ID: {info.get('identity_pubkey', 'Unknown')}")
            click.echo(f"Alias: {info.get('alias', 'Unknown')}")
            click.echo(f"Block Height: {info.get('block_height', 0)}")
            click.echo(f"Synced: {info.get('synced_to_chain', False)}")
        else:
            click.echo("Failed to connect to Lightning node", err=True)
            
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


@cli.command()
@click.pass_context
def balance(ctx):
    """Show wallet and channel balances"""
    try:
        from blncs.lightning.client import create_client
        from blncs.core import get_config
        
        config = get_config()
        client = create_client(config.get_all())
        
        if client.connect():
            balance_data = client.get_balance()
            click.echo(f"Wallet Balance: {balance_data.get('wallet', 0):,} sats")
            click.echo(f"Channel Balance: {balance_data.get('channel', 0):,} sats")
            click.echo(f"Total Balance: {balance_data.get('total', 0):,} sats")
        else:
            click.echo("Failed to connect to Lightning node", err=True)
            
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


@cli.command()
@click.pass_context 
def channels(ctx):
    """List Lightning channels"""
    try:
        from blncs.lightning.client import create_client
        from blncs.core import get_config
        
        config = get_config()
        client = create_client(config.get_all())
        
        if client.connect():
            channels = client.get_channels()
            if channels:
                click.echo(f"Found {len(channels)} channels:")
                for i, channel in enumerate(channels, 1):
                    click.echo(f"{i}. {channel.get('chan_id', 'Unknown')} - "
                              f"Capacity: {channel.get('capacity', 0):,} sats")
            else:
                click.echo("No channels found")
        else:
            click.echo("Failed to connect to Lightning node", err=True)
            
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


@cli.command()
@click.argument('amount', type=int)
@click.option('--memo', '-m', default='', help='Invoice memo')
@click.pass_context
def invoice(ctx, amount, memo):
    """Create payment invoice"""
    try:
        from blncs.lightning.client import create_client
        from blncs.core import get_config
        
        config = get_config()
        client = create_client(config.get_all())
        
        if client.connect():
            payment_request = client.create_invoice(amount, memo)
            click.echo(f"Payment Request: {payment_request}")
        else:
            click.echo("Failed to connect to Lightning node", err=True)
            
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


@cli.command()
@click.argument('payment_request')
@click.pass_context
def pay(ctx, payment_request):
    """Send Lightning payment"""
    try:
        from blncs.lightning.client import create_client
        from blncs.core import get_config
        
        config = get_config()
        client = create_client(config.get_all())
        
        if client.connect():
            result = client.send_payment(payment_request)
            if result.get('payment_error'):
                click.echo(f"Payment failed: {result['payment_error']}", err=True)
            else:
                click.echo("Payment sent successfully")
                click.echo(f"Payment Hash: {result.get('payment_hash', 'Unknown')}")
        else:
            click.echo("Failed to connect to Lightning node", err=True)
            
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


@cli.command()
@click.pass_context
def status(ctx):
    """Show system status"""
    try:
        from blncs.utils.lightweight_fallbacks import LightweightSystemMonitor
        from blncs.core import get_database
        
        monitor = LightweightSystemMonitor()
        info = monitor.get_system_info()
        db = get_database()
        db_stats = db.get_database_stats()
        
        click.echo("=== System Status ===")
        click.echo(f"CPU Usage: {info.cpu_percent:.1f}%")
        click.echo(f"Memory Usage: {info.memory_percent:.1f}%") 
        click.echo(f"Disk Usage: {info.disk_usage:.1f}%")
        click.echo(f"Processes: {info.process_count}")
        click.echo(f"Database Size: {db_stats.get('database_size_mb', 0):.1f} MB")
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


@cli.command()
@click.option('--host', default='localhost', help='Lightning node host')
@click.option('--port', default=8080, type=int, help='Lightning node port')
@click.pass_context
def setup(ctx, host, port):
    """Quick setup for Lightning node connection"""
    try:
        from blncs.core import get_config
        
        config = get_config()
        
        # Update lightning configuration
        config.set('lightning.host', host)
        config.set('lightning.port', port)
        
        click.echo(f"Configuration updated:")
        click.echo(f"  Host: {host}")
        click.echo(f"  Port: {port}")
        click.echo("Use 'blncs info' to test connection")
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


def main():
    """Main CLI entry point"""
    cli()


if __name__ == '__main__':
    main()