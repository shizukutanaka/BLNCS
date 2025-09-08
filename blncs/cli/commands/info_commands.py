"""
Information Commands
Simple, focused commands for system information.
"""

import click
from typing import Dict, Any

from ...lightning.client import LightningClient
from ...core.exceptions import format_error_for_cli
from ...core.health import get_health_checker


@click.command()
@click.pass_context
def info(ctx: click.Context) -> None:
    """Display node information"""
    try:
        client: LightningClient = ctx.obj['client']
        node_info = client.get_info()

        click.echo("Lightning Node Information")
        click.echo("-" * 40)
        click.echo(f"Alias: {node_info.get('alias', 'Unknown')}")
        click.echo(f"Network: {node_info.get('network', 'Unknown')}")
        click.echo(f"Version: {node_info.get('version', 'Unknown')}")
        click.echo(f"Channels: {node_info.get('num_channels', 0)}")
        click.echo(f"Peers: {node_info.get('num_peers', 0)}")
        click.echo(f"Block Height: {node_info.get('block_height', 0):,}")

        # Sync status
        chain_sync = "YES" if node_info.get('synced_to_chain') else "NO"
        graph_sync = "YES" if node_info.get('synced_to_graph') else "NO"
        click.echo(f"Chain Sync: {chain_sync}")
        click.echo(f"Graph Sync: {graph_sync}")

    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)


@click.command()
@click.pass_context
def balance(ctx: click.Context) -> None:
    """Show wallet balance"""
    try:
        client: LightningClient = ctx.obj['client']
        balance_data = client.get_balance()

        click.echo("Wallet Balance")
        click.echo("-" * 40)
        click.echo(f"On-chain Total: {balance_data.get('total', 0):,} sats")
        click.echo(f"On-chain Confirmed: {balance_data.get('confirmed', 0):,} sats")
        click.echo(f"On-chain Unconfirmed: {balance_data.get('unconfirmed', 0):,} sats")
        click.echo(f"Lightning Local: {balance_data.get('channel_local', 0):,} sats")
        click.echo(f"Lightning Remote: {balance_data.get('channel_remote', 0):,} sats")

        # Total available
        total_available = balance_data.get('confirmed', 0) + balance_data.get('channel_local', 0)
        click.echo(f"\nTotal Available: {total_available:,} sats")

    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)


@click.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show BLNCS system status"""
    try:
        client: LightningClient = ctx.obj['client']

        click.echo(" BLNCS System Status")
        click.echo("=" * 50)

        # Connection status
        try:
            client.connect()
            click.echo(" Lightning Connection: [OK] Connected")
        except Exception:
            click.echo(" Lightning Connection: [ERROR] Disconnected")

        # Node info
        try:
            node_info = client.get_info()
            click.echo(f" Node: {node_info.get('alias', 'Unknown')}")
            click.echo(f" Network: {node_info.get('network', 'Unknown')}")
        except Exception:
            click.echo(" Node: [ERROR] Unable to fetch info")

        # Balance summary
        try:
            balance_data = client.get_balance()
            total = balance_data.get('confirmed', 0) + balance_data.get('channel_local', 0)
            click.echo(f" Available Balance: {total:,} sats")
        except Exception:
            click.echo(" Balance: [ERROR] Unable to fetch balance")

    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)


@click.command()
@click.option('--quick', is_flag=True, help='Quick health check')
@click.pass_context
def health(ctx: click.Context, quick: bool) -> None:
    """Run system health check"""
    try:
        checker = get_health_checker()

        if quick:
            click.echo(" Quick Health Check")
            click.echo("-" * 30)

            status_data = checker.get_quick_status()

            # Status indicators
            overall_status = status_data.get('status', 'unknown')
            status_emoji = {'healthy': '[OK]', 'warning': '[WARNING]', 'critical': '[ERROR]'}.get(overall_status, '[?]')

            click.echo(f"Overall Status: {status_emoji} {overall_status.title()}")
            click.echo(f"Lightning Node: {status_data.get('lightning_node', 'unknown')}")

            if 'cpu_percent' in status_data:
                click.echo(f"CPU Usage: {status_data['cpu_percent']:.1f}%")
            if 'memory_percent' in status_data:
                click.echo(f"Memory Usage: {status_data['memory_percent']:.1f}%")

        else:
            click.echo(" Full Health Check")
            click.echo("-" * 30)
            click.echo("Running comprehensive health check...")

            report = checker.run_full_health_check()

            # Overall status
            overall_status = report.get('overall_status', 'unknown')
            status_emoji = {'healthy': '[OK]', 'warning': '[WARNING]', 'critical': '[ERROR]'}.get(overall_status, '[?]')

            click.echo(f"\nOverall Status: {status_emoji} {overall_status.title()}")
            click.echo(f"Health Score: {report.get('health_score', 'N/A')}")

            # Individual checks
            checks = report.get('checks', {})
            for check_name, check_result in checks.items():
                check_status = check_result.get('status', 'unknown')
                check_emoji = {'healthy': '[OK]', 'warning': '[WARNING]', 'critical': '[ERROR]'}.get(check_status, '[?]')
                click.echo(f" {check_name}: {check_emoji} {check_status}")

    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)