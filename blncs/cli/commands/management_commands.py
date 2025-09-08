"""
Lightning Network Management Commands
Advanced channel management and analysis commands.
"""

import click
from typing import Dict, List, Any

from ...lightning.client import LightningClient  
from ...core.exceptions import format_error_for_cli
from ...utils.lightning_helpers import (
    calculate_channel_health_score,
    recommend_channel_actions,
    format_channel_id,
    format_satoshis,
    estimate_routing_fee,
    check_node_connectivity,
    format_node_connectivity_report,
    analyze_payment_failure
)


@click.command('analyze-channels')
@click.option('--detailed', is_flag=True, help='Show detailed analysis')
@click.pass_context
def analyze_channels(ctx: click.Context, detailed: bool) -> None:
    """Analyze channel health and provide recommendations"""
    try:
        client: LightningClient = ctx.obj['client']
        channels = client.list_channels()
        
        if not channels:
            click.echo("No channels found")
            click.echo("\nRecommendation: Open your first Lightning channel to start")
            return
            
        click.echo(f"Channel Analysis Report ({len(channels)} channels)")
        click.echo("=" * 60)
        
        # Calculate overall statistics
        total_capacity = sum(ch.get('capacity', 0) for ch in channels)
        total_local = sum(ch.get('local_balance', 0) for ch in channels)
        total_remote = sum(ch.get('remote_balance', 0) for ch in channels)
        active_channels = len([ch for ch in channels if ch.get('active', False)])
        
        click.echo(f"Active Channels: {active_channels}/{len(channels)}")
        click.echo(f"Total Capacity: {format_satoshis(total_capacity)}")
        click.echo(f"Local Balance: {format_satoshis(total_local)} ({(total_local/total_capacity*100) if total_capacity > 0 else 0:.1f}%)")
        click.echo(f"Remote Balance: {format_satoshis(total_remote)} ({(total_remote/total_capacity*100) if total_capacity > 0 else 0:.1f}%)")
        click.echo()
        
        # Health analysis
        if detailed:
            click.echo("Individual Channel Health:")
            click.echo("-" * 40)
            
            for i, channel in enumerate(channels, 1):
                channel_id = format_channel_id(channel.get('channel_id', ''), short=True)
                capacity = channel.get('capacity', 0)
                local_balance = channel.get('local_balance', 0)
                active = channel.get('active', False)
                
                health_score, issues = calculate_channel_health_score(channel)
                
                status_icon = "[OK]" if active else "[ERROR]"
                health_color = "Good" if health_score >= 80 else "Fair" if health_score >= 60 else "Poor"
                
                click.echo(f"{i}. {channel_id} - {status_icon}")
                click.echo(f"   Capacity: {format_satoshis(capacity)}")
                click.echo(f"   Local: {format_satoshis(local_balance)}")
                click.echo(f"   Health: {health_score}/100 ({health_color})")
                if issues != "Healthy":
                    click.echo(f"   Issues: {issues}")
                click.echo()
        
        # Recommendations
        recommendations = recommend_channel_actions(channels)
        if recommendations:
            click.echo("Recommendations:")
            click.echo("-" * 30)
            for rec in recommendations:
                priority_icon = {"high": "[!]", "medium": "[*]", "low": "[-]"}.get(rec['priority'], "[?]")
                click.echo(f"{priority_icon} {rec['action']}")
                click.echo(f"    Reason: {rec['reason']}")
                click.echo()
        else:
            click.echo("[OK] No specific recommendations at this time")
            
    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)


@click.command('connectivity')
@click.pass_context
def connectivity_check(ctx: click.Context) -> None:
    """Check node connectivity and network status"""
    try:
        client: LightningClient = ctx.obj['client']
        node_info = client.get_info()
        
        connectivity = check_node_connectivity(node_info)
        report = format_node_connectivity_report(connectivity)
        
        click.echo(report)
        
    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)


@click.command('fee-estimate')
@click.argument('amount', type=int)
@click.option('--hops', default=2, help='Expected number of hops (default: 2)')
@click.pass_context
def fee_estimate(ctx: click.Context, amount: int, hops: int) -> None:
    """Estimate routing fees for Lightning payment"""
    try:
        if amount <= 0:
            click.echo("[ERROR] Amount must be positive", err=True)
            return
            
        if hops < 1 or hops > 20:
            click.echo("[ERROR] Hops must be between 1 and 20", err=True)
            return
            
        estimate = estimate_routing_fee(amount, hops)
        
        click.echo("Lightning Payment Fee Estimate")
        click.echo("-" * 40)
        click.echo(f"Amount: {format_satoshis(amount)}")
        click.echo(f"Estimated Fee: {format_satoshis(estimate['estimated_fee_sats'])}")
        click.echo(f"Fee Percentage: {estimate['fee_percentage']:.3f}%")
        click.echo(f"Routing Hops: {hops}")
        click.echo()
        
        # Fee comparison
        if estimate['fee_percentage'] < 0.1:
            click.echo("[OK] Fee rate is excellent (< 0.1%)")
        elif estimate['fee_percentage'] < 0.5:
            click.echo("[OK] Fee rate is good (< 0.5%)")
        elif estimate['fee_percentage'] < 1.0:
            click.echo("[WARNING] Fee rate is moderate (< 1%)")
        else:
            click.echo("[WARNING] Fee rate is high (>= 1%)")
            
        click.echo("\nNote: This is an estimate. Actual fees may vary.")
        
    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)


@click.command('payment-debug')
@click.argument('error_message')
def payment_debug(error_message: str) -> None:
    """Analyze payment failure and suggest solutions"""
    try:
        analysis = analyze_payment_failure(error_message)
        
        click.echo("Payment Failure Analysis")
        click.echo("-" * 40)
        click.echo(f"Category: {analysis['category'].replace('_', ' ').title()}")
        click.echo(f"Description: {analysis['description']}")
        click.echo()
        click.echo("Suggested Solution:")
        click.echo(f"  {analysis['suggestion']}")
        click.echo()
        
        # Additional general tips
        click.echo("General Troubleshooting Tips:")
        click.echo("- Check your channel balances with: blncs channels")
        click.echo("- Verify node connectivity with: blncs connectivity")
        click.echo("- Monitor Lightning node logs for detailed error information")
        
    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)


@click.command('channel-summary')
@click.pass_context
def channel_summary(ctx: click.Context) -> None:
    """Show quick channel summary"""
    try:
        client: LightningClient = ctx.obj['client']
        channels = client.list_channels()
        
        if not channels:
            click.echo("No channels found")
            return
            
        # Quick stats
        active = len([ch for ch in channels if ch.get('active', False)])
        total_capacity = sum(ch.get('capacity', 0) for ch in channels)
        total_local = sum(ch.get('local_balance', 0) for ch in channels)
        
        health_scores = [calculate_channel_health_score(ch)[0] for ch in channels]
        avg_health = sum(health_scores) / len(health_scores) if health_scores else 0
        
        click.echo("Channel Summary")
        click.echo("-" * 30)
        click.echo(f"Channels: {active}/{len(channels)} active")
        click.echo(f"Capacity: {format_satoshis(total_capacity)}")
        click.echo(f"Available: {format_satoshis(total_local)}")
        click.echo(f"Avg Health: {avg_health:.0f}/100")
        
        # Quick recommendations
        if avg_health < 60:
            click.echo("[WARNING] Consider running 'blncs analyze-channels --detailed' for improvements")
        elif active < len(channels):
            click.echo("[INFO] Some channels are inactive. Check connectivity.")
        else:
            click.echo("[OK] Channels look healthy")
            
    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)