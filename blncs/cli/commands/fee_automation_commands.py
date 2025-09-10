"""
Fee Automation CLI Commands
Provides commands for managing automated fee policy adjustments.
"""

import click
from datetime import datetime
from typing import Dict, Any

from ...core.fee_policy_automation import get_fee_policy_manager
from ...core.exceptions import format_error_for_cli


def get_client_from_context(ctx):
    """Get Lightning client from context"""
    return ctx.obj.get('client') or ctx.obj['get_client']()


@click.command()
@click.pass_context
def fee_automation_status(ctx: click.Context) -> None:
    """Show fee automation status and statistics"""
    try:
        client = get_client_from_context(ctx)
        fee_manager = get_fee_policy_manager(client)
        
        status = fee_manager.get_automation_status()
        
        click.echo("Fee Automation Status")
        click.echo("=" * 40)
        
        # Main status
        status_icon = "🟢 Running" if status['is_running'] else "🔴 Stopped"
        click.echo(f"Status: {status_icon}")
        click.echo(f"Check Interval: {status['check_interval_minutes']} minutes")
        click.echo(f"Active Rules: {status['enabled_rules']}/{status['total_rules']}")
        
        # Statistics
        click.echo(f"\nStatistics:")
        click.echo(f"  Total Adjustments: {status['total_adjustments']}")
        click.echo(f"  Recent Adjustments (1h): {status['recent_adjustments']}")
        
        # Rules summary
        if status['rules']:
            click.echo(f"\nConfigured Rules:")
            for rule in status['rules']:
                status_icon = "✅" if rule['enabled'] else "❌"
                click.echo(f"  {status_icon} {rule['name']}")
                click.echo(f"    Trigger: {rule['trigger_condition']}")
                click.echo(f"    Filter: {rule['channel_filter']}")
                click.echo(f"    Action: {rule['adjustment_type']}")
                click.echo(f"    Cooldown: {rule['cooldown_minutes']} min")
        else:
            click.echo("\nNo rules configured")
    
    except Exception as e:
        click.echo(f"Error getting fee automation status: {format_error_for_cli(e)}", err=True)


@click.command()
@click.pass_context
def fee_automation_start(ctx: click.Context) -> None:
    """Start automated fee policy adjustments"""
    try:
        client = get_client_from_context(ctx)
        fee_manager = get_fee_policy_manager(client)
        
        if fee_manager.is_running:
            click.echo("Fee automation is already running")
            return
        
        click.echo("Starting fee automation...")
        
        success = fee_manager.start_automation()
        
        if success:
            click.echo("✅ Fee automation started successfully")
            click.echo("Automated fee adjustments are now active")
        else:
            click.echo("❌ Failed to start fee automation", err=True)
    
    except Exception as e:
        click.echo(f"Error starting fee automation: {format_error_for_cli(e)}", err=True)


@click.command()
@click.pass_context
def fee_automation_stop(ctx: click.Context) -> None:
    """Stop automated fee policy adjustments"""
    try:
        client = get_client_from_context(ctx)
        fee_manager = get_fee_policy_manager(client)
        
        if not fee_manager.is_running:
            click.echo("Fee automation is not running")
            return
        
        click.echo("Stopping fee automation...")
        
        success = fee_manager.stop_automation()
        
        if success:
            click.echo("✅ Fee automation stopped successfully")
        else:
            click.echo("❌ Failed to stop fee automation", err=True)
    
    except Exception as e:
        click.echo(f"Error stopping fee automation: {format_error_for_cli(e)}", err=True)


@click.command()
@click.option('--limit', '-l', default=20, help='Number of recent adjustments to show')
@click.pass_context
def fee_automation_history(ctx: click.Context, limit: int) -> None:
    """Show fee adjustment history"""
    try:
        client = get_client_from_context(ctx)
        fee_manager = get_fee_policy_manager(client)
        
        history = fee_manager.get_adjustment_history(limit)
        
        if not history:
            click.echo("No fee adjustments found")
            return
        
        click.echo(f"Recent Fee Adjustments (last {len(history)})")
        click.echo("=" * 60)
        
        for adjustment in reversed(history):  # Show newest first
            timestamp = datetime.fromisoformat(adjustment['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            channel_id = adjustment['channel_id'][:12] + "..."
            old_fee = adjustment['old_fee_rate']
            new_fee = adjustment['new_fee_rate']
            rule = adjustment['rule_name']
            success_icon = "✅" if adjustment['success'] else "❌"
            
            # Calculate change
            if old_fee > 0:
                change_pct = ((new_fee - old_fee) / old_fee) * 100
                change_str = f"{change_pct:+.1f}%"
            else:
                change_str = "N/A"
            
            click.echo(f"{success_icon} {timestamp}")
            click.echo(f"   Channel: {channel_id}")
            click.echo(f"   Fee: {old_fee} → {new_fee} ppm ({change_str})")
            click.echo(f"   Rule: {rule}")
            if adjustment.get('reason'):
                click.echo(f"   Reason: {adjustment['reason']}")
            click.echo()
    
    except Exception as e:
        click.echo(f"Error getting fee adjustment history: {format_error_for_cli(e)}", err=True)


@click.command()
@click.pass_context  
def fee_automation_test(ctx: click.Context) -> None:
    """Test fee automation rules (dry run)"""
    try:
        client = get_client_from_context(ctx)
        fee_manager = get_fee_policy_manager(client)
        
        click.echo("Testing fee automation rules...")
        click.echo("This is a dry run - no actual changes will be made")
        click.echo("=" * 50)
        
        # Get network state and channel data
        network_state = fee_manager._analyze_network_state()
        channel_data = fee_manager._get_channel_performance_data()
        
        # Show network conditions
        click.echo("Current Network Conditions:")
        click.echo(f"  Recent Volume: {network_state.get('recent_forwarding_volume', 0):,} sats")
        click.echo(f"  Recent Count: {network_state.get('recent_forwarding_count', 0)} forwards")
        click.echo(f"  Success Rate: {network_state.get('avg_success_rate', 0):.1%}")
        click.echo(f"  Network Fee (median): {network_state.get('network_fee_median', 0):.0f} ppm")
        
        # Test each rule
        total_potential_adjustments = 0
        
        for rule in fee_manager.enabled_rules:
            if not rule.enabled:
                continue
                
            click.echo(f"\n📋 Testing Rule: {rule.name}")
            click.echo(f"   Trigger: {rule.trigger_condition}")
            click.echo(f"   Filter: {rule.channel_filter}")
            click.echo(f"   Action: {rule.adjustment_type}")
            
            # Check if rule would trigger
            would_trigger = fee_manager._evaluate_rule_trigger(rule, network_state)
            trigger_icon = "✅" if would_trigger else "❌"
            click.echo(f"   Would Trigger: {trigger_icon}")
            
            if would_trigger:
                # Get channels that would be affected
                target_channels = fee_manager._filter_channels(rule, channel_data)
                
                # Filter out channels in cooldown
                eligible_channels = [
                    ch for ch in target_channels 
                    if not fee_manager._is_in_cooldown(ch, rule.cooldown_minutes)
                ]
                
                click.echo(f"   Target Channels: {len(target_channels)}")
                click.echo(f"   Eligible (not in cooldown): {len(eligible_channels)}")
                
                total_potential_adjustments += len(eligible_channels)
                
                # Show a few example adjustments
                if eligible_channels:
                    click.echo("   Example adjustments:")
                    for i, channel_id in enumerate(eligible_channels[:3]):
                        channel_info = channel_data.get(channel_id, {})
                        current_fee = channel_info.get('current_fee_rate', 1000)
                        
                        # Simulate fee calculation
                        if rule.adjustment_type == "increase":
                            new_fee = int(current_fee * rule.adjustment_factor)
                        elif rule.adjustment_type == "decrease":
                            new_fee = int(current_fee / rule.adjustment_factor)
                        else:
                            new_fee = current_fee  # Optimization would need actual calculation
                        
                        new_fee = max(rule.min_fee_rate, min(rule.max_fee_rate, new_fee))
                        
                        short_id = channel_id[:12] + "..."
                        click.echo(f"     {short_id}: {current_fee} → {new_fee} ppm")
        
        click.echo(f"\n📊 Summary:")
        click.echo(f"   Total potential adjustments: {total_potential_adjustments}")
        
        if total_potential_adjustments > 0:
            click.echo(f"\n💡 To apply these adjustments, start fee automation with:")
            click.echo(f"   python -m blncs.cli.main fee_automation_start")
        else:
            click.echo(f"\n✨ No adjustments would be made at this time")
    
    except Exception as e:
        click.echo(f"Error testing fee automation: {format_error_for_cli(e)}", err=True)