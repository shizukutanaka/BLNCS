"""
Channel Rebalancer CLI Commands
Provides commands for managing automated channel rebalancing.
"""

import click
from datetime import datetime
from typing import Dict, Any

from ...core.channel_rebalancer import get_channel_rebalancer, RebalanceStrategy
from ...core.exceptions import format_error_for_cli


def get_client_from_context(ctx):
    """Get Lightning client from context"""
    return ctx.obj.get('client') or ctx.obj['get_client']()


@click.command()
@click.pass_context
def rebalancer_status(ctx: click.Context) -> None:
    """Show channel rebalancer status and statistics"""
    try:
        client = get_client_from_context(ctx)
        rebalancer = get_channel_rebalancer(client)
        
        status = rebalancer.get_rebalancing_status()
        
        click.echo("Channel Rebalancer Status")
        click.echo("=" * 40)
        
        # Main status
        status_icon = "🟢 Running" if status['is_running'] else "🔴 Stopped"
        click.echo(f"Status: {status_icon}")
        click.echo(f"Strategy: {status['strategy'].title()}")
        click.echo(f"Check Interval: {status['check_interval_minutes']} minutes")
        click.echo(f"Max Concurrent Operations: {status['max_concurrent_operations']}")
        
        # Current operations
        click.echo(f"\nOperations:")
        click.echo(f"  Active: {status['active_operations']}")
        click.echo(f"  Pending: {status['pending_operations']}")
        
        # Channel targets
        click.echo(f"\nChannel Targets:")
        click.echo(f"  Configured: {status['configured_targets']}")
        click.echo(f"  Enabled: {status['enabled_targets']}")
        
        # Statistics
        stats = status['statistics']
        click.echo(f"\nStatistics:")
        click.echo(f"  Total Operations: {stats['total_operations']}")
        click.echo(f"  Successful: {stats['successful_operations']}")
        click.echo(f"  Failed: {stats['failed_operations']}")
        
        if stats['total_operations'] > 0:
            success_rate = (stats['successful_operations'] / stats['total_operations']) * 100
            click.echo(f"  Success Rate: {success_rate:.1f}%")
        
        click.echo(f"  Total Volume: {stats['total_volume_sats']:,} sats")
        click.echo(f"  Total Fees Paid: {stats['total_fees_paid']:,} sats")
        
        if stats['last_operation_time']:
            last_op = datetime.fromisoformat(stats['last_operation_time']).strftime('%Y-%m-%d %H:%M:%S')
            click.echo(f"  Last Operation: {last_op}")
    
    except Exception as e:
        click.echo(f"Error getting rebalancer status: {format_error_for_cli(e)}", err=True)


@click.command()
@click.option('--strategy', type=click.Choice(['conservative', 'balanced', 'aggressive']), 
              help='Rebalancing strategy to use')
@click.pass_context
def rebalancer_start(ctx: click.Context, strategy: str) -> None:
    """Start automated channel rebalancing"""
    try:
        client = get_client_from_context(ctx)
        rebalancer = get_channel_rebalancer(client)
        
        if rebalancer.is_running:
            click.echo("Channel rebalancing is already running")
            return
        
        # Update strategy if provided
        if strategy:
            rebalancer.strategy = RebalanceStrategy(strategy)
            click.echo(f"Using {strategy} rebalancing strategy")
        
        click.echo("Starting channel rebalancing...")
        
        success = rebalancer.start_rebalancing()
        
        if success:
            click.echo("✅ Channel rebalancing started successfully")
            click.echo("Automated channel rebalancing is now active")
        else:
            click.echo("❌ Failed to start channel rebalancing", err=True)
    
    except Exception as e:
        click.echo(f"Error starting channel rebalancing: {format_error_for_cli(e)}", err=True)


@click.command()
@click.pass_context
def rebalancer_stop(ctx: click.Context) -> None:
    """Stop automated channel rebalancing"""
    try:
        client = get_client_from_context(ctx)
        rebalancer = get_channel_rebalancer(client)
        
        if not rebalancer.is_running:
            click.echo("Channel rebalancing is not running")
            return
        
        click.echo("Stopping channel rebalancing...")
        
        success = rebalancer.stop_rebalancing()
        
        if success:
            click.echo("✅ Channel rebalancing stopped successfully")
        else:
            click.echo("❌ Failed to stop channel rebalancing", err=True)
    
    except Exception as e:
        click.echo(f"Error stopping channel rebalancing: {format_error_for_cli(e)}", err=True)


@click.command()
@click.option('--limit', '-l', default=20, help='Number of recent operations to show')
@click.pass_context
def rebalancer_history(ctx: click.Context, limit: int) -> None:
    """Show rebalancing operation history"""
    try:
        client = get_client_from_context(ctx)
        rebalancer = get_channel_rebalancer(client)
        
        history = rebalancer.get_operation_history(limit)
        
        if not history:
            click.echo("No rebalancing operations found")
            return
        
        click.echo(f"Recent Rebalancing Operations (last {len(history)})")
        click.echo("=" * 60)
        
        for operation in reversed(history):  # Show newest first
            created_at = datetime.fromisoformat(operation['created_at']).strftime('%Y-%m-%d %H:%M:%S')
            source_id = operation['source_channel'][:12] + "..."
            target_id = operation['target_channel'][:12] + "..."
            amount = operation['amount_sats']
            method = operation['method']
            status = operation['status']
            estimated_cost = operation['estimated_cost']
            
            # Status icon
            if status == "completed":
                status_icon = "✅"
            elif status == "failed":
                status_icon = "❌"
            elif status == "in_progress":
                status_icon = "🔄"
            else:
                status_icon = "⏳"
            
            click.echo(f"{status_icon} {created_at}")
            click.echo(f"   Operation: {operation['operation_id']}")
            click.echo(f"   Amount: {amount:,} sats")
            click.echo(f"   From: {source_id}")
            click.echo(f"   To: {target_id}")
            click.echo(f"   Method: {method}")
            click.echo(f"   Estimated Cost: {estimated_cost:,} sats")
            click.echo(f"   Status: {status}")
            click.echo()
    
    except Exception as e:
        click.echo(f"Error getting rebalancing history: {format_error_for_cli(e)}", err=True)


@click.command()
@click.pass_context
def rebalancer_analyze(ctx: click.Context) -> None:
    """Analyze channels and show rebalancing opportunities"""
    try:
        client = get_client_from_context(ctx)
        rebalancer = get_channel_rebalancer(client)
        
        click.echo("Analyzing channels for rebalancing opportunities...")
        click.echo("=" * 50)
        
        # Get channel analysis
        channel_analysis = rebalancer._analyze_channels()
        
        if not channel_analysis:
            click.echo("No channel data available")
            return
        
        # Show channel status
        click.echo("Channel Status:")
        channels_needing_rebalance = 0
        
        for channel_id, analysis in channel_analysis.items():
            short_id = channel_id[:12] + "..."
            local_ratio = analysis['local_ratio']
            target = analysis['target']
            needs_rebalancing = analysis['needs_rebalancing']
            
            if needs_rebalancing:
                channels_needing_rebalance += 1
                status_icon = "⚠️"
            else:
                status_icon = "✅"
            
            click.echo(f"  {status_icon} {short_id} ({analysis['peer_alias'][:15]})")
            click.echo(f"     Local: {local_ratio:.1%} (target: {target.target_local_ratio:.1%})")
            click.echo(f"     Range: {target.min_local_ratio:.1%} - {target.max_local_ratio:.1%}")
            click.echo(f"     Balance: {analysis['local_balance']:,} / {analysis['capacity']:,} sats")
            
            if needs_rebalancing:
                if local_ratio > target.max_local_ratio:
                    excess = int((local_ratio - target.target_local_ratio) * analysis['capacity'])
                    click.echo(f"     Action: Reduce outbound by {excess:,} sats")
                else:
                    needed = int((target.target_local_ratio - local_ratio) * analysis['capacity'])
                    click.echo(f"     Action: Increase outbound by {needed:,} sats")
            
            click.echo()
        
        # Identify rebalancing opportunities
        opportunities = rebalancer._identify_rebalancing_opportunities(channel_analysis)
        
        click.echo(f"Summary:")
        click.echo(f"  Total Channels: {len(channel_analysis)}")
        click.echo(f"  Need Rebalancing: {channels_needing_rebalance}")
        click.echo(f"  Rebalancing Opportunities: {len(opportunities)}")
        
        if opportunities:
            click.echo(f"\nTop Rebalancing Opportunities:")
            for i, opp in enumerate(opportunities[:5], 1):
                source_short = opp['source_channel'][:12] + "..."
                target_short = opp['target_channel'][:12] + "..."
                amount = opp['amount']
                priority = opp['priority']
                
                click.echo(f"  {i}. {amount:,} sats: {source_short} → {target_short} (priority: {priority})")
        
        if channels_needing_rebalance > 0:
            click.echo(f"\n💡 To start automatic rebalancing:")
            click.echo(f"   python -m blncs.cli.main rebalancer_start")
    
    except Exception as e:
        click.echo(f"Error analyzing channels: {format_error_for_cli(e)}", err=True)


@click.command()
@click.argument('channel_id')
@click.option('--target', type=float, required=True, help='Target local ratio (0.0-1.0)')
@click.option('--min-ratio', type=float, help='Minimum local ratio (0.0-1.0)')
@click.option('--max-ratio', type=float, help='Maximum local ratio (0.0-1.0)')
@click.option('--priority', type=int, default=5, help='Priority (1=high, 10=low)')
@click.pass_context
def rebalancer_add_target(ctx: click.Context, channel_id: str, target: float, 
                         min_ratio: float, max_ratio: float, priority: int) -> None:
    """Add or update a channel rebalancing target"""
    try:
        # Validate ratios
        if not 0.0 <= target <= 1.0:
            click.echo("Target ratio must be between 0.0 and 1.0", err=True)
            return
        
        # Set defaults for min/max if not provided
        if min_ratio is None:
            min_ratio = max(0.0, target - 0.2)
        if max_ratio is None:
            max_ratio = min(1.0, target + 0.2)
        
        if not 0.0 <= min_ratio <= 1.0 or not 0.0 <= max_ratio <= 1.0:
            click.echo("Min and max ratios must be between 0.0 and 1.0", err=True)
            return
        
        if min_ratio >= max_ratio:
            click.echo("Min ratio must be less than max ratio", err=True)
            return
        
        if not min_ratio <= target <= max_ratio:
            click.echo("Target ratio must be between min and max ratios", err=True)
            return
        
        client = get_client_from_context(ctx)
        rebalancer = get_channel_rebalancer(client)
        
        success = rebalancer.add_channel_target(
            channel_id=channel_id,
            target_ratio=target,
            min_ratio=min_ratio,
            max_ratio=max_ratio,
            priority=priority
        )
        
        if success:
            short_id = channel_id[:12] + "..."
            click.echo(f"✅ Added rebalancing target for channel {short_id}")
            click.echo(f"   Target: {target:.1%}")
            click.echo(f"   Range: {min_ratio:.1%} - {max_ratio:.1%}")
            click.echo(f"   Priority: {priority}")
        else:
            click.echo("❌ Failed to add channel target", err=True)
    
    except Exception as e:
        click.echo(f"Error adding channel target: {format_error_for_cli(e)}", err=True)


@click.command()
@click.argument('channel_id')
@click.pass_context
def rebalancer_remove_target(ctx: click.Context, channel_id: str) -> None:
    """Remove a channel rebalancing target"""
    try:
        client = get_client_from_context(ctx)
        rebalancer = get_channel_rebalancer(client)
        
        success = rebalancer.remove_channel_target(channel_id)
        
        if success:
            short_id = channel_id[:12] + "..."
            click.echo(f"✅ Removed rebalancing target for channel {short_id}")
        else:
            click.echo("❌ Channel target not found", err=True)
    
    except Exception as e:
        click.echo(f"Error removing channel target: {format_error_for_cli(e)}", err=True)