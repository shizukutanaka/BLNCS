"""
Lightning Network liquidity management commands
Advanced liquidity management and rebalancing tools.
"""

import click
from typing import Dict, Any

from ...core.exceptions import format_error_for_cli
from ...lightning.client import LightningClient
from ...core.rebalancer import get_rebalancer
from ...core.liquidity_optimizer import get_liquidity_optimizer


def format_sats(amount: int) -> str:
    """Format satoshi amounts with commas"""
    return f"{amount:,}"


def format_percentage(ratio: float) -> str:
    """Format ratio as percentage"""
    return f"{ratio:.1%}"


@click.group()
def liquidity():
    """Lightning Network liquidity management commands"""
    pass


@liquidity.command()
@click.option('--detailed', '-d', is_flag=True, help='Show detailed channel analysis')
def analyze(detailed: bool):
    """Analyze channel liquidity and identify optimization opportunities"""
    try:
        client = LightningClient()
        optimizer = get_liquidity_optimizer(client)
        
        summary = optimizer.get_liquidity_summary()
        if summary.get('status') == 'no_data':
            click.echo("No channel data available")
            return
        
        click.echo("\n📊 Liquidity Analysis")
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
        
        # Health status with colors
        if summary['average_liquidity_score'] >= 80:
            click.secho("🟢 Excellent liquidity management", fg='green')
        elif summary['average_liquidity_score'] >= 60:
            click.secho("🟡 Good liquidity, some optimization possible", fg='yellow')
        elif summary['average_liquidity_score'] >= 40:
            click.secho("🟠 Fair liquidity, optimization recommended", fg='yellow')
        else:
            click.secho("🔴 Poor liquidity, immediate attention needed", fg='red')
        
        if detailed:
            metrics = optimizer.analyze_liquidity()
            if metrics:
                click.echo("\n📋 Channel Details:")
                for chan_id, metric in list(metrics.items())[:10]:  # Show top 10
                    score = optimizer.get_liquidity_score(metric)
                    status = "✅" if score >= 60 else "🟡" if score >= 40 else "🔴"
                    click.echo(f"{status} {chan_id[:16]}... "
                              f"Score: {score:.1f} "
                              f"Local: {format_percentage(metric.local_ratio)} "
                              f"({format_sats(metric.capacity)} sats)")
                
    except Exception as e:
        click.echo(format_error_for_cli(e))


@liquidity.command()
@click.option('--limit', '-l', default=5, help='Maximum number of suggestions to show')
def suggest(limit: int):
    """Get rebalancing suggestions based on current channel states"""
    try:
        client = LightningClient()
        rebalancer = get_rebalancer(client)
        
        recommendations = rebalancer.get_rebalancing_recommendations()
        
        if not recommendations:
            click.echo("✅ No rebalancing needed - channels are well balanced!")
            return
        
        click.echo("\n⚖️  Rebalancing Suggestions")
        click.echo("=" * 50)
        
        for i, rec in enumerate(recommendations[:limit], 1):
            # Priority color coding
            if rec['priority'] > 0.7:
                priority_color = 'red'
                priority_emoji = "🔴"
            elif rec['priority'] > 0.4:
                priority_color = 'yellow'
                priority_emoji = "🟡"
            else:
                priority_color = 'green'
                priority_emoji = "🟢"
            
            click.echo(f"\n{i}. {rec['description']}")
            click.echo(f"   Priority: ", nl=False)
            click.secho(f"{priority_emoji} {rec['priority']:.2f}", fg=priority_color)
            click.echo(f"   Amount: {format_sats(rec['amount'])} sats")
            click.echo(f"   Estimated Fee: {format_sats(rec['estimated_fee'])} sats ({format_percentage(rec['fee_rate'])})")
            
            # Cost effectiveness indicator
            if rec['fee_rate'] < 0.005:  # Less than 0.5%
                click.echo(f"   💡 Cost effective rebalancing opportunity")
            elif rec['fee_rate'] < 0.01:  # Less than 1%
                click.echo(f"   ⚠️  Moderate cost")
            else:
                click.echo(f"   🔴 High cost - consider alternatives")
        
        click.echo(f"\nUse 'blncs liquidity rebalance --dry-run' to preview operations")
        
    except Exception as e:
        click.echo(format_error_for_cli(e))


@liquidity.command()
@click.option('--max-operations', default=3, help='Maximum number of rebalancing operations')
@click.option('--dry-run', is_flag=True, help='Show what would be done without executing')
def rebalance(max_operations: int, dry_run: bool):
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
                click.echo(f"   Fee Rate: {format_percentage(rec['fee_rate'])}")
            
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
            click.echo(f"Operations Performed: {results['operations_performed']}/{results['operations_attempted']}")
            click.echo(f"Total Amount Rebalanced: {format_sats(results['total_amount_rebalanced'])} sats")
            click.echo(f"Total Fees: {format_sats(results['total_fees'])} sats")
            
            if results['errors']:
                click.echo(f"\n⚠️  Errors encountered:")
                for error in results['errors'][:3]:  # Show first 3 errors
                    click.echo(f"  • {error}")
        else:
            click.echo(f"\n❌ Rebalancing failed")
            if results.get('errors'):
                for error in results['errors']:
                    click.echo(f"Error: {error}")
        
    except Exception as e:
        click.echo(format_error_for_cli(e))


@liquidity.command()
def recommendations():
    """Get comprehensive liquidity improvement recommendations"""
    try:
        client = LightningClient()
        optimizer = get_liquidity_optimizer(client)
        
        metrics = optimizer.analyze_liquidity()
        if not metrics:
            click.echo("No channels available for analysis")
            return
        
        plan = optimizer.generate_liquidity_plan(metrics)
        
        click.echo("\n💡 Liquidity Improvement Recommendations")
        click.echo("=" * 50)
        
        click.echo(f"Overall Health: {plan['overall_health'].title()}")
        
        # Immediate actions
        if plan['immediate_actions']:
            click.echo(f"\n🚨 Immediate Actions Required:")
            for action in plan['immediate_actions']:
                click.echo(f"  • {action}")
        
        # Optimization opportunities
        if plan['optimization_opportunities']:
            click.echo(f"\n🎯 Optimization Opportunities:")
            for opportunity in plan['optimization_opportunities']:
                click.echo(f"  • {opportunity['description']}")
                click.echo(f"    → {opportunity['potential_improvement']}")
        
        # Channel-specific recommendations
        if plan['channel_recommendations']:
            click.echo(f"\n🔧 Channel-Specific Recommendations:")
            for rec in plan['channel_recommendations'][:5]:  # Top 5 most important
                click.echo(f"\n  Channel: {rec['channel_id'][:16]}...")
                click.echo(f"  Health Score: {rec['score']:.1f}/100")
                click.echo(f"  Recommendation: {rec['recommendation']}")
        
        # Summary statistics
        click.echo(f"\n📊 Summary:")
        click.echo(f"  Total Capacity: {format_sats(plan['total_capacity'])} sats")
        click.echo(f"  Total Inbound: {format_sats(plan['total_inbound'])} sats")
        click.echo(f"  Total Outbound: {format_sats(plan['total_outbound'])} sats")
        click.echo(f"  Average Score: {plan['average_liquidity_score']:.1f}/100")
        
    except Exception as e:
        click.echo(format_error_for_cli(e))


@liquidity.command()
@click.option('--channel-id', help='Analyze specific channel')
@click.option('--sort-by', default='score', type=click.Choice(['score', 'capacity', 'imbalance']), 
              help='Sort channels by metric')
def health(channel_id: str, sort_by: str):
    """Analyze individual channel health and provide specific recommendations"""
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
                health_color = 'green'
            elif score >= 60:
                health_indicator = "🟡"
                health_color = 'yellow'
            elif score >= 40:
                health_indicator = "🟠"
                health_color = 'yellow'
            else:
                health_indicator = "🔴"
                health_color = 'red'
            
            click.echo(f"\n{health_indicator} Channel: {chan_id[:24]}...")
            click.echo(f"   Health Score: ", nl=False)
            click.secho(f"{score:.1f}/100", fg=health_color)
            click.echo(f"   Capacity: {format_sats(metric.capacity)} sats")
            click.echo(f"   Local Balance: {format_sats(metric.local_balance)} sats ({format_percentage(metric.local_ratio)})")
            click.echo(f"   Remote Balance: {format_sats(metric.remote_balance)} sats ({format_percentage(metric.remote_ratio)})")
            
            # Show specific recommendation
            recommendation = optimizer._generate_channel_recommendation(metric)
            if recommendation:
                click.echo(f"   💡 Recommendation: {recommendation}")
            else:
                click.echo(f"   ✅ Channel is well balanced")
            
            # Show activity if available
            if metric.last_activity:
                from datetime import datetime
                hours_ago = (datetime.now() - metric.last_activity).total_seconds() / 3600
                if hours_ago < 1:
                    click.echo(f"   🕐 Last activity: {hours_ago*60:.0f} minutes ago")
                elif hours_ago < 24:
                    click.echo(f"   🕐 Last activity: {hours_ago:.1f} hours ago")
                else:
                    click.echo(f"   🕐 Last activity: {hours_ago/24:.1f} days ago")
        
    except Exception as e:
        click.echo(format_error_for_cli(e))


@liquidity.command()
def status():
    """Show current liquidity status and rebalancer configuration"""
    try:
        client = LightningClient()
        rebalancer = get_rebalancer(client)
        optimizer = get_liquidity_optimizer(client)
        
        # Get rebalancer status
        status = rebalancer.get_status()
        
        click.echo("\n⚖️  Liquidity & Rebalancing Status")
        click.echo("=" * 50)
        
        click.echo(f"Rebalancer Enabled: {'Yes' if status['enabled'] else 'No'}")
        click.echo(f"Total Channels: {status['total_channels']}")
        click.echo(f"Balanced Channels: {status['balanced_channels']}")
        click.echo(f"Need Outbound Liquidity: {status['needs_outbound']}")
        click.echo(f"Need Inbound Liquidity: {status['needs_inbound']}")
        
        # Get liquidity summary
        summary = optimizer.get_liquidity_summary()
        if summary.get('status') != 'no_data':
            click.echo(f"\n📊 Liquidity Overview:")
            click.echo(f"Health Score: {summary['average_liquidity_score']:.1f}/100")
            click.echo(f"Overall Balance: {format_percentage(summary['overall_local_ratio'])} local")
            click.echo(f"Total Capacity: {format_sats(summary['total_capacity'])} sats")
        
        # Show configuration
        config = status['configuration']
        click.echo(f"\n⚙️  Configuration:")
        click.echo(f"Target Balance: {format_percentage(config['target_balance_ratio'])}")
        click.echo(f"Imbalance Threshold: {format_percentage(config['min_imbalance_threshold'])}")
        click.echo(f"Max Fee Rate: {format_percentage(config['max_fee_rate'])}")
        click.echo(f"Rebalance Range: {format_sats(config['min_rebalance_amount'])} - {format_sats(config['max_rebalance_amount'])} sats")
        
    except Exception as e:
        click.echo(format_error_for_cli(e))