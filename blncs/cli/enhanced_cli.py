#!/usr/bin/env python3
"""
BLNCS Enhanced CLI - Comprehensive Lightning Network Management
Advanced CLI with all integrated features and intelligent automation.
"""

import sys
import click
import json
import asyncio
import time
from typing import Optional, Dict, Any
from datetime import datetime

# Add project root to path
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from blncs.core.config_manager import get_config_manager
from blncs.core.logger import get_logger
from blncs.lightning.client import LightningClient
from blncs.lightning.channel_manager import get_channel_manager
from blncs.lightning.payment_manager import get_payment_manager
from blncs.monitoring.alert_manager import get_alert_manager
from blncs.automation.backup_automation import get_backup_automation
from blncs.performance.optimizer import get_performance_optimizer

def get_components():
    """Initialize and return all BLNCS components"""
    try:
        config = get_config_manager().get_all()
        client = LightningClient(config)
        
        components = {
            'config': config,
            'client': client,
            'channel_manager': get_channel_manager(client),
            'payment_manager': get_payment_manager(client),
            'alert_manager': get_alert_manager(client),
            'performance_optimizer': get_performance_optimizer(client),
            'logger': get_logger(__name__)
        }
        
        # Initialize backup automation (requires alert manager)
        components['backup_automation'] = get_backup_automation(client, components['alert_manager'])
        
        return components
    except Exception as e:
        click.echo(f"Failed to initialize components: {e}")
        return {}

@click.group()
@click.option('--config', '-c', type=click.Path(), help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--json-output', '-j', is_flag=True, help='JSON output format')
@click.pass_context
def cli(ctx: click.Context, config: str, verbose: bool, json_output: bool) -> None:
    """
    BLNCS - Bitcoin Lightning Network Control System
    
    Advanced Lightning Network management with intelligent automation,
    comprehensive monitoring, and performance optimization.
    
    Features:
    ✓ Channel Management & Optimization
    ✓ Payment Processing & Routing
    ✓ Automated Monitoring & Alerts
    ✓ Backup & Disaster Recovery
    ✓ Performance Optimization
    ✓ Real-time Analytics
    """
    ctx.ensure_object(dict)
    ctx.obj.update({
        'verbose': verbose,
        'json_output': json_output,
        'components': get_components()
    })

# === Node Information Commands ===

@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show comprehensive system status"""
    components = ctx.obj['components']
    if not components:
        click.echo("❌ Failed to initialize BLNCS components")
        return
    
    try:
        client = components['client']
        
        # Get node info
        node_info = client.get_info()
        connected = node_info is not None
        
        # Get channel summary
        channel_summary = components['channel_manager'].get_channel_summary()
        
        # Get payment summary  
        payment_summary = components['payment_manager'].get_payment_summary()
        
        # Get alert status
        alert_stats = components['alert_manager'].get_alert_statistics()
        
        # Get backup status
        backup_status = components['backup_automation'].get_backup_status()
        
        # Get optimization status
        optimization_status = components['performance_optimizer'].get_optimization_status()
        
        if ctx.obj['json_output']:
            status_data = {
                'node_connected': connected,
                'node_info': node_info,
                'channels': channel_summary,
                'payments': payment_summary,
                'alerts': alert_stats,
                'backup': backup_status,
                'optimization': optimization_status,
                'timestamp': datetime.now().isoformat()
            }
            click.echo(json.dumps(status_data, indent=2))
        else:
            # Formatted output
            click.echo("🚀 BLNCS System Status")
            click.echo("=" * 50)
            
            # Node status
            status_icon = "✅" if connected else "❌"
            click.echo(f"{status_icon} Lightning Node: {'Connected' if connected else 'Disconnected'}")
            
            if connected and node_info:
                click.echo(f"   Block Height: {node_info.get('block_height', 'Unknown')}")
                click.echo(f"   Synced: {'Yes' if node_info.get('synced_to_chain') else 'No'}")
                click.echo(f"   Peers: {node_info.get('num_peers', 0)}")
            
            # Channel status
            click.echo(f"\n📡 Channels: {channel_summary.get('total_channels', 0)} total, {channel_summary.get('active_channels', 0)} active")
            click.echo(f"   Total Capacity: {channel_summary.get('total_capacity', 0):,} sats")
            click.echo(f"   Local Balance: {channel_summary.get('total_local_balance', 0):,} sats")
            click.echo(f"   Imbalanced: {channel_summary.get('imbalanced_channels', 0)} channels")
            
            # Payment status
            payments = payment_summary.get('payments', {})
            click.echo(f"\n💳 Payments: {payments.get('total_count', 0)} total")
            click.echo(f"   Success Rate: {payments.get('success_rate', 0):.1%}")
            click.echo(f"   Total Sent: {payments.get('total_sent_msat', 0) // 1000:,} sats")
            click.echo(f"   Total Fees: {payments.get('total_fees_msat', 0) // 1000:,} sats")
            
            # Alert status
            active_alerts = alert_stats.get('active_alerts', 0)
            alert_icon = "🚨" if active_alerts > 0 else "✅"
            click.echo(f"\n{alert_icon} Alerts: {active_alerts} active")
            if active_alerts > 0:
                click.echo(f"   Critical: {alert_stats.get('critical_alerts', 0)}")
                click.echo(f"   Warning: {alert_stats.get('warning_alerts', 0)}")
            
            # Backup status
            backup_icon = "✅" if backup_status.get('automation_active') else "⚠️"
            click.echo(f"\n{backup_icon} Backup: {'Active' if backup_status.get('automation_active') else 'Inactive'}")
            click.echo(f"   Success Rate (24h): {backup_status.get('success_rate_24h', 0):.1%}")
            click.echo(f"   Last Successful: {backup_status.get('last_successful_backup', 'Never')}")
            
            # Optimization status  
            opt_icon = "🚀" if optimization_status.get('optimization_active') else "⚠️"
            click.echo(f"\n{opt_icon} Optimization: {'Active' if optimization_status.get('optimization_active') else 'Inactive'}")
            click.echo(f"   Pending Actions: {optimization_status.get('pending_actions', 0)}")
            
            current_perf = optimization_status.get('current_performance', {})
            if current_perf:
                click.echo(f"   Payment Success: {current_perf.get('payment_success_rate', 0):.1%}")
                click.echo(f"   Liquidity Efficiency: {current_perf.get('liquidity_efficiency', 0):.1%}")
                
    except Exception as e:
        click.echo(f"❌ Status check failed: {e}")

@cli.command()
@click.pass_context
def info(ctx: click.Context) -> None:
    """Show detailed node information"""
    components = ctx.obj['components']
    if not components:
        return
        
    try:
        node_info = components['client'].get_info()
        
        if ctx.obj['json_output']:
            click.echo(json.dumps(node_info, indent=2))
        else:
            if node_info:
                click.echo("⚡ Lightning Node Information")
                click.echo("=" * 40)
                click.echo(f"Alias: {node_info.get('alias', 'Unknown')}")
                click.echo(f"Public Key: {node_info.get('identity_pubkey', 'Unknown')}")
                click.echo(f"Version: {node_info.get('version', 'Unknown')}")
                click.echo(f"Block Height: {node_info.get('block_height', 0):,}")
                click.echo(f"Network: {node_info.get('chains', [{}])[0].get('network', 'Unknown')}")
                click.echo(f"Peers: {node_info.get('num_peers', 0)}")
                click.echo(f"Active Channels: {node_info.get('num_active_channels', 0)}")
                click.echo(f"Pending Channels: {node_info.get('num_pending_channels', 0)}")
                click.echo(f"Synced to Chain: {'Yes' if node_info.get('synced_to_chain') else 'No'}")
            else:
                click.echo("❌ Unable to retrieve node information")
                
    except Exception as e:
        click.echo(f"❌ Info retrieval failed: {e}")

# === Channel Management Commands ===

@cli.group()
def channel():
    """Channel management operations"""
    pass

@channel.command('list')
@click.option('--active-only', is_flag=True, help='Show only active channels')
@click.pass_context
def channel_list(ctx: click.Context, active_only: bool) -> None:
    """List all channels"""
    components = ctx.obj['components']
    if not components:
        return
        
    try:
        channels = components['channel_manager'].get_all_channels()
        
        if active_only:
            channels = [ch for ch in channels if ch.state.value == 'active']
        
        if ctx.obj['json_output']:
            channel_data = [{
                'channel_id': ch.channel_id,
                'peer_id': ch.peer_id,
                'capacity': ch.capacity,
                'local_balance': ch.local_balance,
                'remote_balance': ch.remote_balance,
                'state': ch.state.value,
                'fee_rate': ch.fee_rate,
                'balance_score': ch.metrics.get('balance_score', 0)
            } for ch in channels]
            click.echo(json.dumps(channel_data, indent=2))
        else:
            click.echo(f"📡 Channels ({len(channels)} total)")
            click.echo("=" * 80)
            
            for ch in channels:
                state_icon = "✅" if ch.state.value == 'active' else "⚠️"
                balance_ratio = ch.local_balance / ch.capacity if ch.capacity > 0 else 0
                
                click.echo(f"{state_icon} {ch.channel_id[:16]}...")
                click.echo(f"   Capacity: {ch.capacity:,} sats | Local: {ch.local_balance:,} ({balance_ratio:.1%}) | Remote: {ch.remote_balance:,}")
                click.echo(f"   Peer: {ch.peer_id[:16]}... | Fee Rate: {ch.fee_rate:.4f} | State: {ch.state.value}")
                if ch.metrics.get('balance_score', 0) > 0.3:
                    click.echo("   ⚠️  Channel imbalanced - rebalancing recommended")
                click.echo()
                
    except Exception as e:
        click.echo(f"❌ Channel list failed: {e}")

@channel.command('rebalance')
@click.argument('channel_id')
@click.option('--amount', type=int, help='Amount to rebalance (sats)')
@click.option('--max-fee', type=int, default=1000, help='Maximum fee (sats)')
@click.pass_context
def channel_rebalance(ctx: click.Context, channel_id: str, amount: int, max_fee: int) -> None:
    """Rebalance a channel"""
    components = ctx.obj['components']
    if not components:
        return
        
    try:
        result = components['channel_manager'].rebalance_channel(channel_id, amount, max_fee)
        
        if ctx.obj['json_output']:
            click.echo(json.dumps(result, indent=2))
        else:
            click.echo(f"🔄 Rebalancing channel {channel_id[:16]}...")
            click.echo(f"Amount: {amount:,} sats")
            click.echo(f"Max Fee: {max_fee:,} sats")
            click.echo(f"Status: {result.get('status', 'Unknown')}")
            
    except Exception as e:
        click.echo(f"❌ Channel rebalance failed: {e}")

@channel.command('recommendations')
@click.pass_context
def channel_recommendations(ctx: click.Context) -> None:
    """Get channel optimization recommendations"""
    components = ctx.obj['components']
    if not components:
        return
        
    try:
        recommendations = components['channel_manager'].get_channel_recommendations()
        
        if ctx.obj['json_output']:
            rec_data = [{
                'channel_id': rec.channel_id,
                'action': rec.action,
                'priority': rec.priority,
                'reason': rec.reason,
                'expected_benefit': rec.expected_benefit,
                'estimated_cost': rec.estimated_cost
            } for rec in recommendations]
            click.echo(json.dumps(rec_data, indent=2))
        else:
            click.echo(f"💡 Channel Recommendations ({len(recommendations)} total)")
            click.echo("=" * 60)
            
            for rec in recommendations:
                priority_icon = "🔴" if rec.priority == "high" else "🟡" if rec.priority == "medium" else "🟢"
                
                click.echo(f"{priority_icon} {rec.action.upper()} - {rec.priority.title()} Priority")
                click.echo(f"   Channel: {rec.channel_id[:16]}...")
                click.echo(f"   Reason: {rec.reason}")
                click.echo(f"   Benefit: {rec.expected_benefit}")
                if rec.estimated_cost > 0:
                    click.echo(f"   Cost: {rec.estimated_cost:,} sats")
                click.echo()
                
    except Exception as e:
        click.echo(f"❌ Recommendations failed: {e}")

# === Payment Commands ===

@cli.group()
def payment():
    """Payment processing operations"""
    pass

@payment.command('send')
@click.argument('payment_request')
@click.option('--max-fee', type=int, default=10000, help='Maximum fee (msats)')
@click.pass_context
def payment_send(ctx: click.Context, payment_request: str, max_fee: int) -> None:
    """Send a Lightning payment"""
    components = ctx.obj['components']
    if not components:
        return
        
    try:
        result = components['payment_manager'].send_payment(payment_request)
        
        if ctx.obj['json_output']:
            click.echo(json.dumps({
                'payment_hash': result.payment_hash,
                'status': result.status.value,
                'amount_msat': result.amount_msat,
                'fee_msat': result.fee_msat,
                'total_time_seconds': result.total_time_seconds
            }, indent=2))
        else:
            status_icon = "✅" if result.status.value == "succeeded" else "❌"
            click.echo(f"{status_icon} Payment {result.status.value.title()}")
            click.echo(f"Hash: {result.payment_hash}")
            click.echo(f"Amount: {result.amount_msat // 1000:,} sats")
            click.echo(f"Fee: {result.fee_msat // 1000:,} sats ({result.fee_msat/result.amount_msat:.2%})")
            click.echo(f"Time: {result.total_time_seconds:.1f}s")
            
            if result.failure_reason:
                click.echo(f"Failure: {result.failure_reason}")
                
    except Exception as e:
        click.echo(f"❌ Payment failed: {e}")

@payment.command('invoice')
@click.argument('amount', type=int)
@click.argument('description')
@click.option('--expiry', type=int, default=3600, help='Expiry time (seconds)')
@click.pass_context
def payment_invoice(ctx: click.Context, amount: int, description: str, expiry: int) -> None:
    """Create a Lightning invoice"""
    components = ctx.obj['components']
    if not components:
        return
        
    try:
        invoice = components['payment_manager'].create_invoice(
            amount_msat=amount * 1000,
            description=description,
            expiry=expiry
        )
        
        if ctx.obj['json_output']:
            click.echo(json.dumps({
                'payment_request': invoice.payment_request,
                'payment_hash': invoice.payment_hash,
                'amount_msat': invoice.amount_msat,
                'expiry': invoice.expiry
            }, indent=2))
        else:
            click.echo("📄 Invoice Created")
            click.echo(f"Amount: {amount:,} sats")
            click.echo(f"Description: {description}")
            click.echo(f"Expiry: {expiry}s")
            click.echo(f"\nPayment Request:")
            click.echo(invoice.payment_request)
            
    except Exception as e:
        click.echo(f"❌ Invoice creation failed: {e}")

@payment.command('history')
@click.option('--limit', type=int, default=20, help='Number of payments to show')
@click.pass_context
def payment_history(ctx: click.Context, limit: int) -> None:
    """Show payment history"""
    components = ctx.obj['components']
    if not components:
        return
        
    try:
        payments = components['payment_manager'].get_payment_history(limit=limit)
        
        if ctx.obj['json_output']:
            payment_data = [{
                'payment_hash': p.payment_hash,
                'status': p.status.value,
                'amount_msat': p.amount_msat,
                'fee_msat': p.fee_msat,
                'created_at': p.created_at.isoformat()
            } for p in payments]
            click.echo(json.dumps(payment_data, indent=2))
        else:
            click.echo(f"💳 Payment History (Last {len(payments)} payments)")
            click.echo("=" * 70)
            
            for payment in payments:
                status_icon = "✅" if payment.status.value == "succeeded" else "❌"
                
                click.echo(f"{status_icon} {payment.payment_hash[:16]}... | {payment.status.value.title()}")
                click.echo(f"   Amount: {payment.amount_msat // 1000:,} sats | Fee: {payment.fee_msat // 1000:,} sats")
                click.echo(f"   Time: {payment.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
                click.echo()
                
    except Exception as e:
        click.echo(f"❌ Payment history failed: {e}")

# === Alert Commands ===

@cli.group()
def alert():
    """Alert management operations"""
    pass

@alert.command('list')
@click.option('--severity', type=click.Choice(['info', 'warning', 'critical', 'emergency']), help='Filter by severity')
@click.pass_context
def alert_list(ctx: click.Context, severity: str) -> None:
    """List active alerts"""
    components = ctx.obj['components']
    if not components:
        return
        
    try:
        from blncs.monitoring.alert_manager import AlertSeverity
        
        severity_filter = AlertSeverity(severity) if severity else None
        alerts = components['alert_manager'].get_active_alerts(severity=severity_filter)
        
        if ctx.obj['json_output']:
            alert_data = [alert.to_dict() for alert in alerts]
            click.echo(json.dumps(alert_data, indent=2))
        else:
            click.echo(f"🚨 Active Alerts ({len(alerts)} total)")
            click.echo("=" * 60)
            
            if not alerts:
                click.echo("✅ No active alerts")
            else:
                for alert in alerts:
                    severity_icon = {"emergency": "🔴", "critical": "🟠", "warning": "🟡", "info": "🔵"}.get(alert.severity.value, "⚪")
                    
                    click.echo(f"{severity_icon} {alert.title} [{alert.severity.value.upper()}]")
                    click.echo(f"   {alert.description}")
                    click.echo(f"   Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
                    click.echo(f"   ID: {alert.id}")
                    if alert.acknowledged:
                        click.echo("   ✓ Acknowledged")
                    click.echo()
                    
    except Exception as e:
        click.echo(f"❌ Alert list failed: {e}")

@alert.command('ack')
@click.argument('alert_id')
@click.pass_context
def alert_acknowledge(ctx: click.Context, alert_id: str) -> None:
    """Acknowledge an alert"""
    components = ctx.obj['components']
    if not components:
        return
        
    try:
        success = components['alert_manager'].acknowledge_alert(alert_id)
        
        if success:
            click.echo(f"✅ Alert {alert_id} acknowledged")
        else:
            click.echo(f"❌ Alert {alert_id} not found")
            
    except Exception as e:
        click.echo(f"❌ Alert acknowledgment failed: {e}")

# === Backup Commands ===

@cli.group()
def backup():
    """Backup and recovery operations"""
    pass

@backup.command('create')
@click.option('--policy', default='critical_daily', help='Backup policy to use')
@click.pass_context
def backup_create(ctx: click.Context, policy: str) -> None:
    """Create a manual backup"""
    components = ctx.obj['components']
    if not components:
        return
        
    try:
        job_id = components['backup_automation'].trigger_manual_backup(policy)
        click.echo(f"✅ Backup job started: {job_id}")
        
    except Exception as e:
        click.echo(f"❌ Backup creation failed: {e}")

@backup.command('status')
@click.pass_context
def backup_status(ctx: click.Context) -> None:
    """Show backup system status"""
    components = ctx.obj['components']
    if not components:
        return
        
    try:
        status = components['backup_automation'].get_backup_status()
        
        if ctx.obj['json_output']:
            click.echo(json.dumps(status, indent=2))
        else:
            automation_icon = "✅" if status.get('automation_active') else "⚠️"
            click.echo(f"{automation_icon} Backup System Status")
            click.echo("=" * 40)
            click.echo(f"Automation: {'Active' if status.get('automation_active') else 'Inactive'}")
            click.echo(f"Policies: {status.get('enabled_policies', 0)}/{status.get('total_policies', 0)} enabled")
            click.echo(f"Jobs (24h): {status.get('successful_jobs_last_24h', 0)} successful, {status.get('failed_jobs_last_24h', 0)} failed")
            click.echo(f"Success Rate: {status.get('success_rate_24h', 0):.1%}")
            click.echo(f"Last Success: {status.get('last_successful_backup', 'Never')}")
            
    except Exception as e:
        click.echo(f"❌ Backup status failed: {e}")

# === Performance Commands ===

@cli.group()
def performance():
    """Performance optimization operations"""
    pass

@performance.command('status')
@click.pass_context
def performance_status(ctx: click.Context) -> None:
    """Show performance optimization status"""
    components = ctx.obj['components']
    if not components:
        return
        
    try:
        status = components['performance_optimizer'].get_optimization_status()
        
        if ctx.obj['json_output']:
            click.echo(json.dumps(status, indent=2))
        else:
            opt_icon = "🚀" if status.get('optimization_active') else "⚠️"
            click.echo(f"{opt_icon} Performance Optimization Status")
            click.echo("=" * 45)
            
            click.echo(f"Optimization: {'Active' if status.get('optimization_active') else 'Inactive'}")
            click.echo(f"Goals: {status.get('active_goals', 0)}/{status.get('total_goals', 0)} active")
            click.echo(f"Pending Actions: {status.get('pending_actions', 0)}")
            
            current_perf = status.get('current_performance', {})
            if current_perf:
                click.echo("\n📊 Current Performance:")
                click.echo(f"   Payment Success: {current_perf.get('payment_success_rate', 0):.1%}")
                click.echo(f"   Channel Utilization: {current_perf.get('channel_utilization', 0):.1%}")
                click.echo(f"   Liquidity Efficiency: {current_perf.get('liquidity_efficiency', 0):.1%}")
                click.echo(f"   Resource Efficiency: {current_perf.get('resource_efficiency', 0):.1%}")
                
                improvements = current_perf.get('improvements', {})
                if improvements:
                    click.echo("\n📈 Improvements from Baseline:")
                    for metric, improvement in improvements.items():
                        if improvement != 0:
                            direction = "↗️" if improvement > 0 else "↘️"
                            click.echo(f"   {metric}: {direction} {improvement:+.1%}")
            
    except Exception as e:
        click.echo(f"❌ Performance status failed: {e}")

@performance.command('report')
@click.pass_context
def performance_report(ctx: click.Context) -> None:
    """Generate performance optimization report"""
    components = ctx.obj['components']
    if not components:
        return
        
    try:
        report = components['performance_optimizer'].get_optimization_report()
        
        if ctx.obj['json_output']:
            click.echo(json.dumps(report, indent=2))
        else:
            click.echo("📊 Performance Optimization Report")
            click.echo("=" * 50)
            click.echo(f"Generated: {report.get('report_timestamp', 'Unknown')}")
            
            # Performance summary
            perf_summary = report.get('performance_summary', {})
            if perf_summary:
                click.echo("\n🎯 Current Performance:")
                click.echo(f"   Payment Success Rate: {perf_summary.get('payment_success_rate', 0):.1%}")
                click.echo(f"   Channel Utilization: {perf_summary.get('channel_utilization', 0):.1%}")
                click.echo(f"   Liquidity Efficiency: {perf_summary.get('liquidity_efficiency', 0):.1%}")
            
            # Recent actions
            recent_actions = report.get('recent_actions', [])
            if recent_actions:
                click.echo(f"\n⚡ Recent Actions ({len(recent_actions)}):")
                for action in recent_actions[:5]:
                    click.echo(f"   • {action.get('action_type', 'Unknown')} - Impact: {action.get('expected_impact', 0):.1%}")
            
            # Pending actions
            pending_actions = report.get('pending_actions', [])
            if pending_actions:
                click.echo(f"\n⏳ Pending Actions ({len(pending_actions)}):")
                for action in pending_actions[:5]:
                    approval_text = " (Needs Approval)" if action.get('requires_approval') else ""
                    click.echo(f"   • {action.get('action_type', 'Unknown')} - Impact: {action.get('expected_impact', 0):.1%}{approval_text}")
            
            # Recommendations
            recommendations = report.get('recommendations', [])
            if recommendations:
                click.echo(f"\n💡 Recommendations:")
                for rec in recommendations:
                    click.echo(f"   • {rec}")
                    
    except Exception as e:
        click.echo(f"❌ Performance report failed: {e}")

# === Automation Commands ===

@cli.group()
def automation():
    """Automation system management"""
    pass

@automation.command('start')
@click.option('--all', 'start_all', is_flag=True, help='Start all automation systems')
@click.option('--alerts', is_flag=True, help='Start alert monitoring')
@click.option('--backup', is_flag=True, help='Start backup automation')
@click.option('--optimization', is_flag=True, help='Start performance optimization')
@click.pass_context
def automation_start(ctx: click.Context, start_all: bool, alerts: bool, backup: bool, optimization: bool) -> None:
    """Start automation systems"""
    components = ctx.obj['components']
    if not components:
        return
        
    try:
        started = []
        
        if start_all or alerts:
            components['alert_manager'].start_monitoring()
            started.append("Alert Monitoring")
            
        if start_all or backup:
            components['backup_automation'].start_automation()
            started.append("Backup Automation")
            
        if start_all or optimization:
            components['performance_optimizer'].start_optimization()
            started.append("Performance Optimization")
        
        if started:
            click.echo("🚀 Started automation systems:")
            for system in started:
                click.echo(f"   ✅ {system}")
        else:
            click.echo("⚠️  No systems specified. Use --all or specific flags.")
            
    except Exception as e:
        click.echo(f"❌ Automation start failed: {e}")

@automation.command('stop')
@click.option('--all', 'stop_all', is_flag=True, help='Stop all automation systems')
@click.option('--alerts', is_flag=True, help='Stop alert monitoring')
@click.option('--backup', is_flag=True, help='Stop backup automation')  
@click.option('--optimization', is_flag=True, help='Stop performance optimization')
@click.pass_context
def automation_stop(ctx: click.Context, stop_all: bool, alerts: bool, backup: bool, optimization: bool) -> None:
    """Stop automation systems"""
    components = ctx.obj['components']
    if not components:
        return
        
    try:
        stopped = []
        
        if stop_all or alerts:
            components['alert_manager'].stop_monitoring_system()
            stopped.append("Alert Monitoring")
            
        if stop_all or backup:
            components['backup_automation'].stop_automation_system()
            stopped.append("Backup Automation")
            
        if stop_all or optimization:
            components['performance_optimizer'].stop_optimization_system()
            stopped.append("Performance Optimization")
        
        if stopped:
            click.echo("⏹️  Stopped automation systems:")
            for system in stopped:
                click.echo(f"   ✅ {system}")
        else:
            click.echo("⚠️  No systems specified. Use --all or specific flags.")
            
    except Exception as e:
        click.echo(f"❌ Automation stop failed: {e}")

# === Main CLI Entry Point ===

if __name__ == '__main__':
    cli()