"""
Advanced Lightning Network Liquidity Management Commands
Practical commands for managing channel liquidity and rebalancing.
"""

import click
from typing import Dict, Any
from datetime import datetime

from blncs.lightning.client import LightningClient
from blncs.core.rebalancer import get_rebalancer
from blncs.core.liquidity_optimizer import get_liquidity_optimizer
from blncs.core.exceptions import format_error_for_cli


def format_sats(amount: int) -> str:
    """Format satoshi amounts with commas for readability"""
    return f"{amount:,}"


def format_percentage(ratio: float) -> str:
    """Format ratio as percentage"""
    return f"{ratio:.1%}"


@click.command('liquidity-status')
def liquidity_status():
    """Show current liquidity status across all channels"""
    try:
        client = LightningClient()
        optimizer = get_liquidity_optimizer(client)
        
        summary = optimizer.get_liquidity_summary()
        
        if summary.get('status') == 'no_data':
            click.echo("No channel data available")
            return
        
        click.echo("\n📊 Liquidity Status Summary")
        click.echo("=" * 50)
        
        click.echo(f"Total Channels: {summary['total_channels']}")
        click.echo(f"Balanced Channels: {summary['balanced_channels']}")
        click.echo(f"Imbalanced Channels: {summary['imbalanced_channels']}")
        click.echo(f"Overall Health: {summary['health_status'].title()}")
        
        click.echo(f"\n💰 Capacity Overview:")
        click.echo(f"Total Capacity: {format_sats(summary['total_capacity'])} sats")
        click.echo(f"Local Balance: {format_sats(summary['total_local_balance'])} sats ({format_percentage(summary['overall_local_ratio'])})")
        click.echo(f"Remote Balance: {format_sats(summary['total_remote_balance'])} sats")
        
        click.echo(f"\n📈 Health Score: {summary['average_liquidity_score']:.1f}/100")
        
        # Color code the health status
        if summary['average_liquidity_score'] >= 80:
            click.echo("🟢 Excellent liquidity management")
        elif summary['average_liquidity_score'] >= 60:
            click.echo("🟡 Good liquidity, some optimization possible")
        elif summary['average_liquidity_score'] >= 40:
            click.echo("🟠 Fair liquidity, optimization recommended")
        else:
            click.echo("🔴 Poor liquidity, immediate attention needed")
        
    except Exception as e:
        click.echo(format_error_for_cli(e))


@click.command('analyze-liquidity')
@click.option('--detailed', is_flag=True, help='Show detailed channel analysis')
def analyze_liquidity(detailed):
    """Analyze liquidity and identify optimization opportunities"""
    try:
        client = LightningClient()
        optimizer = get_liquidity_optimizer(client)
        
        metrics = optimizer.analyze_liquidity()
        if not metrics:
            click.echo("No channels available for analysis")
            return
        
        click.echo("\n🔍 Liquidity Analysis")
        click.echo("=" * 50)
        
        # Show per-channel analysis if detailed
        if detailed:
            click.echo(f"\n📋 Channel Details:")
            for chan_id, metric in metrics.items():
                score = optimizer.get_liquidity_score(metric)
                click.echo(f"\nChannel: {chan_id[:16]}...")
                click.echo(f"  Capacity: {format_sats(metric.capacity)} sats")
                click.echo(f"  Local Balance: {format_sats(metric.local_balance)} sats ({format_percentage(metric.local_ratio)})")
                click.echo(f"  Remote Balance: {format_sats(metric.remote_balance)} sats ({format_percentage(metric.remote_ratio)})")
                click.echo(f"  Liquidity Score: {score:.1f}/100")
                
                if score < 60:
                    if metric.local_ratio < 0.3:
                        click.echo("  🔴 Low outbound liquidity")
                    elif metric.local_ratio > 0.7:
                        click.echo("  🔴 Low inbound liquidity")
                    if metric.capacity < 1000000:
                        click.echo("  🟡 Small channel size")
        
        # Generate optimization plan
        plan = optimizer.generate_liquidity_plan(metrics)
        
        click.echo(f"\n🎯 Optimization Plan")
        click.echo(f"Overall Health: {plan['overall_health'].title()}")
        
        if plan['immediate_actions']:
            click.echo(f"\n⚠️  Immediate Actions Required:")
            for action in plan['immediate_actions']:
                click.echo(f"  • {action}")
        
        if plan['optimization_opportunities']:
            click.echo(f"\n💡 Optimization Opportunities:")
            for opportunity in plan['optimization_opportunities']:
                click.echo(f"  • {opportunity['description']}")
                click.echo(f"    → {opportunity['potential_improvement']}")
        
        if plan['channel_recommendations']:
            click.echo(f"\n🔧 Channel Recommendations:")
            for rec in plan['channel_recommendations'][:5]:  # Show top 5
                click.echo(f"  • {rec['channel_id'][:16]}... (Score: {rec['score']:.1f})")
                click.echo(f"    → {rec['recommendation']}")
        
    except Exception as e:
        click.echo(format_error_for_cli(e))


@click.command('rebalance-status')
def rebalance_status():
    """Show current rebalancing status and recommendations"""
    try:
        client = LightningClient()
        rebalancer = get_rebalancer(client)
        
        status = rebalancer.get_status()
        
        click.echo("\n⚖️  Rebalancing Status")
        click.echo("=" * 50)
        
        click.echo(f"Rebalancer Enabled: {'Yes' if status['enabled'] else 'No'}")
        click.echo(f"Total Channels: {status['total_channels']}")
        click.echo(f"Balanced Channels: {status['balanced_channels']}")
        click.echo(f"Need Outbound: {status['needs_outbound']}")
        click.echo(f"Need Inbound: {status['needs_inbound']}")
        
        # Show configuration
        config = status['configuration']
        click.echo(f"\n⚙️  Configuration:")
        click.echo(f"Target Balance: {format_percentage(config['target_balance_ratio'])}")
        click.echo(f"Imbalance Threshold: {format_percentage(config['min_imbalance_threshold'])}")
        click.echo(f"Max Fee Rate: {format_percentage(config['max_fee_rate'])}")
        click.echo(f"Amount Range: {format_sats(config['min_rebalance_amount'])} - {format_sats(config['max_rebalance_amount'])} sats")
        
        # Get recommendations
        recommendations = rebalancer.get_rebalancing_recommendations()
        
        if recommendations:
            click.echo(f"\n📋 Rebalancing Recommendations:")
            for i, rec in enumerate(recommendations[:5], 1):
                click.echo(f"\n{i}. {rec['description']}")
                click.echo(f"   Amount: {format_sats(rec['amount'])} sats")
                click.echo(f"   Estimated Fee: {format_sats(rec['estimated_fee'])} sats ({format_percentage(rec['fee_rate'])})")
                click.echo(f"   Priority: {rec['priority']:.2f}")
        else:
            click.echo("\n✅ No rebalancing needed - channels are well balanced!")
        
    except Exception as e:
        click.echo(format_error_for_cli(e))


@click.command('auto-rebalance')
@click.option('--max-operations', default=3, help='Maximum number of rebalancing operations')
@click.option('--dry-run', is_flag=True, help='Show what would be done without executing')
def auto_rebalance(max_operations, dry_run):
    """Perform automatic channel rebalancing"""
    try:
        client = LightningClient()
        rebalancer = get_rebalancer(client)
        
        if dry_run:
            click.echo("\n🔍 Dry Run - Rebalancing Preview")
            click.echo("=" * 50)
            
            recommendations = rebalancer.get_rebalancing_recommendations()
            
            if not recommendations:
                click.echo("✅ No rebalancing operations needed")
                return
            
            click.echo(f"Would perform up to {max_operations} operations:")
            
            for i, rec in enumerate(recommendations[:max_operations], 1):
                click.echo(f"\n{i}. {rec['description']}")
                click.echo(f"   Amount: {format_sats(rec['amount'])} sats")
                click.echo(f"   Estimated Fee: {format_sats(rec['estimated_fee'])} sats")
            
            click.echo(f"\nUse --no-dry-run to execute these operations")
            return
        
        click.echo("\n⚖️  Starting Automatic Rebalancing")
        click.echo("=" * 50)
        
        # Confirm before proceeding
        if not click.confirm("Proceed with automatic rebalancing?"):
            click.echo("Cancelled")
            return
        
        results = rebalancer.auto_rebalance(max_operations)
        
        if results['success']:
            click.echo(f"\n✅ Rebalancing Complete")
            click.echo(f"Operations: {results['operations_performed']}/{results['operations_attempted']}")
            click.echo(f"Amount Rebalanced: {format_sats(results['total_amount_rebalanced'])} sats")
            click.echo(f"Total Fees: {format_sats(results['total_fees'])} sats")
            
            if results['errors']:
                click.echo(f"\n⚠️  Errors encountered:")
                for error in results['errors'][:3]:
                    click.echo(f"  • {error}")
        else:
            click.echo(f"\n❌ Rebalancing failed")
            if results.get('errors'):
                for error in results['errors']:
                    click.echo(f"Error: {error}")
        
    except Exception as e:
        click.echo(format_error_for_cli(e))


@click.command('channel-health')
@click.option('--channel-id', help='Specific channel ID to analyze')
@click.option('--sort-by', default='score', type=click.Choice(['score', 'capacity', 'imbalance']), help='Sort by metric')
def channel_health(channel_id, sort_by):
    """Analyze individual channel health and provide recommendations"""
    try:
        client = LightningClient()
        optimizer = get_liquidity_optimizer(client)
        
        metrics = optimizer.analyze_liquidity()
        if not metrics:
            click.echo("No channels available for analysis")
            return
        
        # Filter to specific channel if requested
        if channel_id:
            if channel_id not in metrics:
                # Try partial match
                matching = [cid for cid in metrics.keys() if cid.startswith(channel_id)]
                if not matching:
                    click.echo(f"Channel not found: {channel_id}")
                    return
                elif len(matching) > 1:
                    click.echo(f"Multiple channels match '{channel_id}':")
                    for match in matching:
                        click.echo(f"  {match}")
                    return
                else:
                    channel_id = matching[0]
            
            metrics = {channel_id: metrics[channel_id]}
        
        click.echo("\n🏥 Channel Health Report")
        click.echo("=" * 50)
        
        # Sort channels
        if sort_by == 'score':
            sorted_channels = sorted(metrics.items(), key=lambda x: optimizer.get_liquidity_score(x[1]), reverse=True)
        elif sort_by == 'capacity':
            sorted_channels = sorted(metrics.items(), key=lambda x: x[1].capacity, reverse=True)
        else:  # imbalance
            sorted_channels = sorted(metrics.items(), key=lambda x: abs(x[1].local_ratio - 0.5), reverse=True)
        
        for chan_id, metric in sorted_channels:
            score = optimizer.get_liquidity_score(metric)
            
            # Health indicator
            if score >= 80:
                health_indicator = "🟢"
            elif score >= 60:
                health_indicator = "🟡"
            elif score >= 40:
                health_indicator = "🟠"
            else:
                health_indicator = "🔴"
            
            click.echo(f"\n{health_indicator} Channel: {chan_id[:24]}...")
            click.echo(f"   Health Score: {score:.1f}/100")
            click.echo(f"   Capacity: {format_sats(metric.capacity)} sats")
            click.echo(f"   Balance: {format_sats(metric.local_balance)} / {format_sats(metric.remote_balance)} sats")
            click.echo(f"   Ratio: {format_percentage(metric.local_ratio)} local / {format_percentage(metric.remote_ratio)} remote")
            
            # Show specific recommendation
            recommendation = optimizer._generate_channel_recommendation(metric)
            if recommendation:
                click.echo(f"   💡 Recommendation: {recommendation}")
            
            # Show activity if available
            if metric.last_activity:
                hours_ago = (datetime.now() - metric.last_activity).total_seconds() / 3600
                if hours_ago < 1:
                    click.echo(f"   🕐 Last activity: {hours_ago*60:.0f} minutes ago")
                elif hours_ago < 24:
                    click.echo(f"   🕐 Last activity: {hours_ago:.1f} hours ago")
                else:
                    click.echo(f"   🕐 Last activity: {hours_ago/24:.1f} days ago")
        
    except Exception as e:
        click.echo(format_error_for_cli(e))


# Export all commands
__all__ = [
    'liquidity_status',
    'analyze_liquidity', 
    'rebalance_status',
    'auto_rebalance',
    'channel_health'
]