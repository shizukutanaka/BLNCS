"""
Daily Operation Commands
Essential commands for Lightning Network node operators' daily tasks.
"""

import click
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List
import json

from ...lightning.client import LightningClient
from ...core.exceptions import format_error_for_cli
from ...core.database import get_database_manager
from ...core.config_manager import get_config_manager
from ...core.monitor import get_monitor


@click.command()
@click.option('--hours', '-h', default=24, help='Hours to look back for earnings')
@click.pass_context
def earnings(ctx: click.Context, hours: int) -> None:
    """Show routing earnings for the specified period"""
    try:
        client: LightningClient = ctx.obj['client']
        db = get_database_manager()
        
        # Calculate time range
        end_time = int(time.time())
        start_time = end_time - (hours * 3600)
        
        click.echo(f"Lightning Node Earnings Report")
        click.echo(f"Period: Last {hours} hours")
        click.echo("=" * 50)
        
        # Get forwarding events
        forwards = client.get_forwarding_events(start_time, end_time)
        
        if not forwards:
            click.echo("No forwarding events found in this period")
            return
        
        # Calculate earnings
        total_earned = 0
        total_volume = 0
        successful_forwards = 0
        
        for forward in forwards:
            if forward.get('status') == 'settled':
                fee = forward.get('fee_msat', 0) // 1000  # Convert to sats
                amount = forward.get('amt_out_msat', 0) // 1000
                total_earned += fee
                total_volume += amount
                successful_forwards += 1
        
        # Calculate rates
        avg_fee_rate = (total_earned / total_volume * 1000000) if total_volume > 0 else 0
        hourly_rate = total_earned / hours if hours > 0 else 0
        
        click.echo(f"Successful Forwards: {successful_forwards}")
        click.echo(f"Total Volume: {total_volume:,} sats")
        click.echo(f"Total Earnings: {total_earned:,} sats")
        click.echo(f"Average Fee Rate: {avg_fee_rate:.1f} ppm")
        click.echo(f"Hourly Rate: {hourly_rate:.2f} sats/hour")
        
        # Daily projection
        daily_projection = hourly_rate * 24
        click.echo(f"Daily Projection: {daily_projection:.0f} sats/day")
        
    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)


@click.command()
@click.option('--limit', '-l', default=10, help='Number of top channels to show')
@click.pass_context
def top_channels(ctx: click.Context, limit: int) -> None:
    """Show top performing channels by routing volume"""
    try:
        client: LightningClient = ctx.obj['client']
        channels = client.list_channels()
        
        if not channels:
            click.echo("No channels found")
            return
        
        # Get forwarding events for last 7 days
        end_time = int(time.time())
        start_time = end_time - (7 * 24 * 3600)
        forwards = client.get_forwarding_events(start_time, end_time)
        
        # Calculate per-channel statistics
        channel_stats = {}
        for channel in channels:
            chan_id = str(channel.get('chan_id', ''))
            channel_stats[chan_id] = {
                'channel': channel,
                'volume_out': 0,
                'volume_in': 0,
                'fees_earned': 0,
                'forwards': 0
            }
        
        # Process forwarding events
        for forward in forwards:
            chan_id_in = str(forward.get('chan_id_in', ''))
            chan_id_out = str(forward.get('chan_id_out', ''))
            amount = forward.get('amt_out_msat', 0) // 1000
            fee = forward.get('fee_msat', 0) // 1000
            
            if chan_id_out in channel_stats:
                channel_stats[chan_id_out]['volume_out'] += amount
                channel_stats[chan_id_out]['fees_earned'] += fee
                channel_stats[chan_id_out]['forwards'] += 1
            
            if chan_id_in in channel_stats:
                channel_stats[chan_id_in]['volume_in'] += amount
        
        # Sort by total volume
        sorted_channels = sorted(
            channel_stats.values(),
            key=lambda x: x['volume_out'] + x['volume_in'],
            reverse=True
        )
        
        click.echo(f"Top {limit} Channels by Volume (Last 7 Days)")
        click.echo("=" * 70)
        
        for i, stats in enumerate(sorted_channels[:limit], 1):
            channel = stats['channel']
            alias = channel.get('peer_alias', 'Unknown')[:20]
            capacity = channel.get('capacity', 0)
            total_volume = stats['volume_out'] + stats['volume_in']
            utilization = (total_volume / capacity) * 100 if capacity > 0 else 0
            
            click.echo(f"{i:2d}. {alias}")
            click.echo(f"    Volume: {total_volume:,} sats (out: {stats['volume_out']:,}, in: {stats['volume_in']:,})")
            click.echo(f"    Fees: {stats['fees_earned']:,} sats, Forwards: {stats['forwards']}")
            click.echo(f"    Utilization: {utilization:.1f}% of {capacity:,} sats capacity")
            click.echo()
        
    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)


@click.command()
@click.option('--threshold', '-t', default=10, help='Minimum fee rate threshold in ppm')
@click.pass_context
def fee_analysis(ctx: click.Context, threshold: int) -> None:
    """Analyze and suggest fee optimizations"""
    try:
        client: LightningClient = ctx.obj['client']
        channels = client.list_channels()
        
        if not channels:
            click.echo("No channels found")
            return
        
        click.echo("Channel Fee Analysis")
        click.echo("=" * 50)
        
        low_fee_channels = []
        high_fee_channels = []
        balanced_channels = []
        
        for channel in channels:
            chan_id = channel.get('chan_id', 0)
            alias = channel.get('peer_alias', 'Unknown')[:15]
            local_balance = channel.get('local_balance', 0)
            remote_balance = channel.get('remote_balance', 0)
            capacity = channel.get('capacity', 0)
            
            # Get channel policy
            try:
                policy = client.get_channel_policy(chan_id)
                fee_rate = policy.get('fee_rate_milli_msat', 0) // 1000  # Convert to ppm
            except:
                fee_rate = 0
            
            local_ratio = (local_balance / capacity) if capacity > 0 else 0
            
            channel_info = {
                'alias': alias,
                'chan_id': chan_id,
                'fee_rate': fee_rate,
                'local_ratio': local_ratio,
                'capacity': capacity
            }
            
            if fee_rate < threshold:
                low_fee_channels.append(channel_info)
            elif fee_rate > threshold * 3:
                high_fee_channels.append(channel_info)
            else:
                balanced_channels.append(channel_info)
        
        # Recommendations
        if low_fee_channels:
            click.echo(f"\n🔸 Low Fee Channels ({len(low_fee_channels)}) - Consider increasing:")
            for ch in low_fee_channels[:5]:
                suggested_fee = threshold if ch['local_ratio'] < 0.3 else threshold * 2
                click.echo(f"  {ch['alias']}: {ch['fee_rate']} ppm → {suggested_fee} ppm (local: {ch['local_ratio']:.1%})")
        
        if high_fee_channels:
            click.echo(f"\n🔸 High Fee Channels ({len(high_fee_channels)}) - Consider reducing:")
            for ch in high_fee_channels[:5]:
                suggested_fee = threshold * 2 if ch['local_ratio'] > 0.7 else threshold
                click.echo(f"  {ch['alias']}: {ch['fee_rate']} ppm → {suggested_fee} ppm (local: {ch['local_ratio']:.1%})")
        
        click.echo(f"\n✅ Balanced Fee Channels: {len(balanced_channels)}")
        click.echo(f"\nRecommendations based on {threshold} ppm threshold")
        
    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)


@click.command()
@click.pass_context
def health_check(ctx: click.Context) -> None:
    """Quick health check of the Lightning node"""
    try:
        client: LightningClient = ctx.obj['client']
        
        click.echo("Lightning Node Health Check")
        click.echo("=" * 40)
        
        # Basic connectivity
        info = client.get_info()
        click.echo(f"✅ Node Connection: OK")
        click.echo(f"   Alias: {info.get('alias', 'Unknown')}")
        
        # Sync status
        chain_synced = info.get('synced_to_chain', False)
        graph_synced = info.get('synced_to_graph', False)
        
        click.echo(f"{'✅' if chain_synced else '❌'} Chain Sync: {'OK' if chain_synced else 'SYNCING'}")
        click.echo(f"{'✅' if graph_synced else '❌'} Graph Sync: {'OK' if graph_synced else 'SYNCING'}")
        
        # Channel status
        channels = client.list_channels()
        active_channels = sum(1 for ch in channels if ch.get('active', False))
        inactive_channels = len(channels) - active_channels
        
        click.echo(f"📊 Channels: {len(channels)} total ({active_channels} active, {inactive_channels} inactive)")
        
        # Balance distribution
        if channels:
            total_local = sum(ch.get('local_balance', 0) for ch in channels)
            total_remote = sum(ch.get('remote_balance', 0) for ch in channels)
            total_capacity = sum(ch.get('capacity', 0) for ch in channels)
            
            local_ratio = (total_local / total_capacity) if total_capacity > 0 else 0
            
            balance_status = "⚖️ BALANCED" if 0.3 <= local_ratio <= 0.7 else "⚠️ UNBALANCED"
            click.echo(f"{balance_status} Local/Remote: {local_ratio:.1%} / {1-local_ratio:.1%}")
        
        # Recent activity
        try:
            end_time = int(time.time())
            start_time = end_time - (24 * 3600)  # Last 24 hours
            forwards = client.get_forwarding_events(start_time, end_time)
            
            if forwards:
                successful_forwards = sum(1 for f in forwards if f.get('status') == 'settled')
                click.echo(f"📈 Recent Activity: {successful_forwards} forwards (24h)")
            else:
                click.echo("📈 Recent Activity: No forwarding events (24h)")
        except:
            click.echo("📈 Recent Activity: Unable to fetch")
        
        click.echo("\n💡 Run 'blncs fee-analysis' for fee optimization suggestions")
        
    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)


@click.command()
@click.option('--days', '-d', default=7, help='Days of data to backup')
@click.pass_context
def backup_data(ctx: click.Context, days: int) -> None:
    """Create a backup of node data and metrics"""
    try:
        from pathlib import Path
        import gzip
        
        backup_dir = Path("backups")
        backup_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = backup_dir / f"blncs_backup_{timestamp}.json.gz"
        
        # Collect data
        client: LightningClient = ctx.obj['client']
        config_manager = get_config_manager()
        db = get_database_manager()
        
        click.echo(f"Creating backup for last {days} days...")
        
        backup_data = {
            'timestamp': datetime.now().isoformat(),
            'days': days,
            'node_info': client.get_info(),
            'channels': client.list_channels(),
            'balance': client.get_balance(),
            'config': config_manager.get_all(),
            'database_stats': db.get_database_stats()
        }
        
        # Add forwarding history if available
        try:
            end_time = int(time.time())
            start_time = end_time - (days * 24 * 3600)
            backup_data['forwarding_events'] = client.get_forwarding_events(start_time, end_time)
        except:
            click.echo("⚠️ Could not backup forwarding events")
        
        # Compress and save
        with gzip.open(backup_file, 'wt', encoding='utf-8') as f:
            json.dump(backup_data, f, indent=2, default=str)
        
        file_size = backup_file.stat().st_size
        click.echo(f"✅ Backup created: {backup_file}")
        click.echo(f"   Size: {file_size / 1024:.1f} KB")
        click.echo(f"   Contains: Node info, channels, balance, {days} days of forwarding data")
        
        # Cleanup old backups (keep last 5)
        backup_files = sorted(backup_dir.glob("blncs_backup_*.json.gz"))
        if len(backup_files) > 5:
            for old_backup in backup_files[:-5]:
                old_backup.unlink()
                click.echo(f"🗑️ Removed old backup: {old_backup.name}")
        
    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)


@click.command()
@click.option('--min-capacity', default=1000000, help='Minimum channel capacity in sats')
@click.option('--max-fee', default=1000, help='Maximum fee rate in ppm')
@click.pass_context
def rebalance_suggestions(ctx: click.Context, min_capacity: int, max_fee: int) -> None:
    """Suggest channels for rebalancing based on current state"""
    try:
        client: LightningClient = ctx.obj['client']
        channels = client.list_channels()
        
        if not channels:
            click.echo("No channels found")
            return
        
        click.echo("Rebalancing Suggestions")
        click.echo("=" * 50)
        
        # Analyze channels
        needs_outbound = []  # High remote balance
        needs_inbound = []   # High local balance
        
        for channel in channels:
            if not channel.get('active', False):
                continue
            
            capacity = channel.get('capacity', 0)
            if capacity < min_capacity:
                continue
            
            local_balance = channel.get('local_balance', 0)
            remote_balance = channel.get('remote_balance', 0)
            alias = channel.get('peer_alias', 'Unknown')[:20]
            
            local_ratio = local_balance / capacity if capacity > 0 else 0
            
            channel_info = {
                'alias': alias,
                'chan_id': channel.get('chan_id', 0),
                'capacity': capacity,
                'local_balance': local_balance,
                'remote_balance': remote_balance,
                'local_ratio': local_ratio
            }
            
            if local_ratio > 0.8:  # Too much outbound liquidity
                needs_inbound.append(channel_info)
            elif local_ratio < 0.2:  # Too much inbound liquidity
                needs_outbound.append(channel_info)
        
        if needs_outbound:
            click.echo(f"\n🔄 Channels needing OUTBOUND liquidity ({len(needs_outbound)}):")
            for ch in sorted(needs_outbound, key=lambda x: x['local_ratio'])[:5]:
                click.echo(f"  {ch['alias']}: {ch['local_ratio']:.1%} local ({ch['local_balance']:,} / {ch['capacity']:,})")
        
        if needs_inbound:
            click.echo(f"\n🔄 Channels needing INBOUND liquidity ({len(needs_inbound)}):")
            for ch in sorted(needs_inbound, key=lambda x: x['local_ratio'], reverse=True)[:5]:
                click.echo(f"  {ch['alias']}: {ch['local_ratio']:.1%} local ({ch['local_balance']:,} / {ch['capacity']:,})")
        
        if needs_outbound and needs_inbound:
            click.echo(f"\n💡 Rebalancing Strategy:")
            click.echo(f"   Send from high-local channels to low-local channels")
            click.echo(f"   Target: 40-60% local balance ratio")
            click.echo(f"   Consider circular rebalancing or submarine swaps")
        elif not needs_outbound and not needs_inbound:
            click.echo(f"\n✅ Channels appear well balanced!")
        
    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)