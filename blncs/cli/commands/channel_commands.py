"""
Channel Management Commands
Lightning channel operations with full type safety.
"""

import click
from typing import Dict, Any, List, Optional

from ...lightning.client import LightningClient
from ...core.exceptions import format_error_for_cli


@click.command()
@click.pass_context
def channels(ctx: click.Context) -> None:
    """List all channels"""
    try:
        client: LightningClient = ctx.obj['client']
        channels_data: List[Dict[str, Any]] = client.list_channels()

        if not channels_data:
            click.echo("No channels found")
            return

        click.echo(f" Lightning Channels ({len(channels_data)})")
        click.echo("=" * 80)

        for i, channel in enumerate(channels_data, 1):
            channel_id: str = channel.get('channel_id', 'Unknown')
            capacity: int = channel.get('capacity', 0)
            local_balance: int = channel.get('local_balance', 0)
            remote_balance: int = channel.get('remote_balance', 0)
            active: bool = channel.get('active', False)

            # Status indicator
            status_emoji = "[OK]" if active else "[ERROR]"

            # Balance percentage
            local_pct = (local_balance / capacity * 100) if capacity > 0 else 0

            click.echo(f"{i}. Channel {channel_id[:16]}...")
            click.echo(f" Status: {status_emoji} {'Active' if active else 'Inactive'}")
            click.echo(f" Capacity: {capacity:,} sats")
            click.echo(f" Local: {local_balance:,} sats ({local_pct:.1f}%)")
            click.echo(f" Remote: {remote_balance:,} sats")
            click.echo()

    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)


@click.command('open-channel')
@click.argument('node_pubkey', type=str)
@click.argument('amount', type=int)
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
@click.pass_context
def open_channel(ctx: click.Context, node_pubkey: str, amount: int, confirm: bool) -> None:
    """Open a new channel"""
    try:
        if len(node_pubkey) != 66:
            click.echo("[ERROR] Invalid node pubkey (must be 66 characters hex)", err=True)
            return

        if amount < 20000:
            click.echo("[ERROR] Amount too small (minimum: 20,000 sats)", err=True)
            return

        if not confirm:
            click.echo(f"Opening channel:")
            click.echo(f" Node: {node_pubkey}")
            click.echo(f" Amount: {amount:,} sats")

            if not click.confirm("Continue?"):
                click.echo("Channel opening cancelled")
                return

        client: LightningClient = ctx.obj['client']

        click.echo("Opening channel...")
        funding_txid: str = client.open_channel(node_pubkey, amount)

        if funding_txid:
            click.echo(f"[OK] Channel opening initiated")
            click.echo(f"Funding TX: {funding_txid}")
            click.echo("Note: Channel will be active after confirmations")
        else:
            click.echo("[ERROR] Failed to open channel", err=True)

    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)


@click.command('close-channel')
@click.argument('channel_id', type=str)
@click.option('--force', is_flag=True, help='Force close channel')
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
@click.pass_context
def close_channel(ctx: click.Context, channel_id: str, force: bool, confirm: bool) -> None:
    """Close a channel"""
    try:
        if not confirm:
            close_type = "Force close" if force else "Cooperative close"
            click.echo(f"{close_type} channel:")
            click.echo(f" Channel ID: {channel_id}")

            if force:
                click.echo("[WARNING] WARNING: Force close may result in higher fees")

            if not click.confirm("Continue?"):
                click.echo("Channel closing cancelled")
                return

        client: LightningClient = ctx.obj['client']

        click.echo("Closing channel...")
        success: bool = client.close_channel(channel_id, force=force)

        if success:
            close_type = "Force closed" if force else "Closed"
            click.echo(f"[OK] Channel {close_type}")
        else:
            click.echo("[ERROR] Failed to close channel", err=True)

    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)