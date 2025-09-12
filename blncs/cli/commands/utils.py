"""
Utility Commands
Useful tools and utilities for Lightning Network management.
"""

import click
import json
import time
from datetime import datetime, timedelta
from pathlib import Path

@click.command()
@click.argument('satoshis', type=int)
def sats_to_btc(satoshis):
    """Convert satoshis to BTC"""
    try:
        btc = satoshis / 100_000_000
        click.echo(f"💰 Conversion Result:")
        click.echo(f"{satoshis:,} sats = {btc:.8f} BTC")
        
        # Show common amounts for reference
        if btc >= 1:
            click.echo(f"≈ {btc:.2f} BTC")
        elif btc >= 0.001:
            click.echo(f"≈ {btc*1000:.3f} mBTC")
        elif btc >= 0.000001:
            click.echo(f"≈ {btc*1_000_000:.0f} μBTC")
        
        # USD approximation (mock rate)
        usd_rate = 45000  # Mock BTC/USD rate
        usd_value = btc * usd_rate
        click.echo(f"≈ ${usd_value:.2f} USD (estimated)")
        
    except Exception as e:
        click.echo(f"❌ Conversion failed: {e}", err=True)

@click.command()
@click.argument('btc', type=float)
def btc_to_sats(btc):
    """Convert BTC to satoshis"""
    try:
        satoshis = int(btc * 100_000_000)
        click.echo(f"💰 Conversion Result:")
        click.echo(f"{btc} BTC = {satoshis:,} sats")
        
        # Show breakdown
        if satoshis >= 1_000_000:
            millions = satoshis // 1_000_000
            remainder = satoshis % 1_000_000
            click.echo(f"= {millions:,}M + {remainder:,} sats")
        
    except Exception as e:
        click.echo(f"❌ Conversion failed: {e}", err=True)

@click.command()
@click.argument('invoice')
def decode_invoice(invoice):
    """Decode Lightning invoice (basic info extraction)"""
    try:
        if not invoice.startswith(('lnbc', 'lntb', 'lnbcrt')):
            click.echo("❌ Invalid Lightning invoice format", err=True)
            return
        
        click.echo(f"⚡ Lightning Invoice Analysis")
        click.echo("=" * 50)
        click.echo(f"Raw Invoice: {invoice[:50]}{'...' if len(invoice) > 50 else ''}")
        click.echo()
        
        # Basic prefix analysis
        if invoice.startswith('lnbc'):
            network = "mainnet"
        elif invoice.startswith('lntb'):
            network = "testnet"
        elif invoice.startswith('lnbcrt'):
            network = "regtest"
        else:
            network = "unknown"
        
        click.echo(f"Network: {network}")
        click.echo(f"Length: {len(invoice)} characters")
        
        # Try to extract amount from prefix (very basic)
        prefix = invoice[:10]
        amount_str = ""
        for char in prefix[4:]:  # Skip 'lnbc'
            if char.isdigit():
                amount_str += char
            else:
                break
        
        if amount_str:
            click.echo(f"Amount: {amount_str} (encoded)")
        else:
            click.echo("Amount: Not specified or zero")
        
        click.echo()
        click.echo("💡 Note: This is basic analysis.")
        click.echo("For full decoding, use a proper Lightning library.")
        
    except Exception as e:
        click.echo(f"❌ Invoice decoding failed: {e}", err=True)

@click.command()
@click.option('--days', default=7, help='Number of days to show')
def uptime(days):
    """Show mock uptime and availability statistics"""
    try:
        import random
        
        click.echo(f"📊 Node Uptime Report ({days} days)")
        click.echo("=" * 50)
        
        # Generate mock uptime data
        total_hours = days * 24
        current_time = datetime.now()
        
        # Mock data - high uptime with occasional downtime
        random.seed(int(time.time()) // 86400)  # Daily seed
        uptime_percentage = random.uniform(94.5, 99.8)
        downtime_hours = total_hours * (100 - uptime_percentage) / 100
        
        click.echo(f"Period: {days} days ({total_hours} hours)")
        click.echo(f"Uptime: {uptime_percentage:.2f}%")
        click.echo(f"Downtime: {downtime_hours:.1f} hours")
        
        # Quality assessment
        if uptime_percentage >= 99.5:
            status = "🟢 Excellent"
        elif uptime_percentage >= 98.0:
            status = "🟡 Good"
        elif uptime_percentage >= 95.0:
            status = "🟠 Fair"
        else:
            status = "🔴 Poor"
        
        click.echo(f"Quality: {status}")
        
        # Mock downtime events
        click.echo("\n📉 Recent Downtime Events:")
        if downtime_hours > 0:
            events = min(3, int(downtime_hours))
            for i in range(events):
                event_time = current_time - timedelta(hours=random.randint(1, days*24))
                duration = random.randint(5, int(downtime_hours*60/events))
                click.echo(f"  • {event_time.strftime('%Y-%m-%d %H:%M')} - {duration} minutes")
        else:
            click.echo("  No downtime events")
        
        click.echo(f"\n📈 Comparison:")
        click.echo(f"  Network Average: 98.5%")
        click.echo(f"  Your Node: {uptime_percentage:.2f}%")
        if uptime_percentage > 98.5:
            click.echo("  🎉 Above average!")
        else:
            click.echo("  📊 Below average")
        
    except Exception as e:
        click.echo(f"❌ Uptime calculation failed: {e}", err=True)

@click.command()
def node_score():
    """Calculate mock node performance score"""
    try:
        import random
        
        click.echo("🏆 Node Performance Score")
        click.echo("=" * 50)
        
        # Generate mock scores
        random.seed(int(time.time()) // 3600)  # Hourly seed
        
        metrics = {
            'Uptime': random.uniform(85, 99),
            'Channel Balance': random.uniform(70, 95),
            'Routing Success': random.uniform(75, 98),
            'Network Connectivity': random.uniform(80, 100),
            'Security': random.uniform(90, 100)
        }
        
        total_score = 0
        max_score = 0
        
        for metric, score in metrics.items():
            total_score += score
            max_score += 100
            
            # Color coding
            if score >= 90:
                color = "🟢"
            elif score >= 75:
                color = "🟡"
            elif score >= 60:
                color = "🟠"
            else:
                color = "🔴"
            
            click.echo(f"{color} {metric}: {score:.1f}/100")
        
        overall_score = total_score / len(metrics)
        
        click.echo(f"\n🎯 Overall Score: {overall_score:.1f}/100")
        
        # Grade assignment
        if overall_score >= 95:
            grade = "A+"
        elif overall_score >= 90:
            grade = "A"
        elif overall_score >= 85:
            grade = "B+"
        elif overall_score >= 80:
            grade = "B"
        elif overall_score >= 75:
            grade = "C+"
        else:
            grade = "C"
        
        click.echo(f"📊 Grade: {grade}")
        
        # Recommendations
        click.echo("\n💡 Recommendations:")
        lowest_metric = min(metrics.items(), key=lambda x: x[1])
        if lowest_metric[1] < 85:
            click.echo(f"  • Focus on improving: {lowest_metric[0]}")
        
        if overall_score >= 90:
            click.echo("  • Excellent performance! Keep it up!")
        elif overall_score >= 75:
            click.echo("  • Good performance with room for improvement")
        else:
            click.echo("  • Consider reviewing node configuration")
        
    except Exception as e:
        click.echo(f"❌ Score calculation failed: {e}", err=True)

@click.command()
@click.option('--format', 'output_format', default='table', type=click.Choice(['table', 'json', 'csv']))
def node_stats(output_format):
    """Show comprehensive node statistics"""
    try:
        from ...lightning.client_simple import get_lightning_client
        client = get_lightning_client()
        client.connect()
        
        # Gather all data
        info = client.get_info()
        balance = client.get_balance()
        channels = client.list_channels()
        network_info = client.get_network_info()
        
        stats = {
            'node_info': {
                'alias': info.get('alias', 'Unknown'),
                'version': info.get('version', 'Unknown'),
                'network': info.get('chains', [{}])[0].get('network', 'Unknown'),
                'peers': info.get('num_peers', 0),
                'active_channels': info.get('num_active_channels', 0),
                'block_height': info.get('block_height', 0)
            },
            'balances': {
                'wallet_sats': balance.get('wallet', 0),
                'channels_sats': balance.get('channels', 0),
                'total_sats': balance.get('total', 0),
                'wallet_btc': balance.get('wallet', 0) / 100_000_000,
                'channels_btc': balance.get('channels', 0) / 100_000_000,
                'total_btc': balance.get('total', 0) / 100_000_000
            },
            'network': {
                'total_nodes': network_info.get('num_nodes', 0),
                'total_channels': network_info.get('num_channels', 0),
                'network_capacity': network_info.get('total_capacity', 0)
            },
            'timestamp': datetime.now().isoformat()
        }
        
        if output_format == 'json':
            click.echo(json.dumps(stats, indent=2))
        elif output_format == 'csv':
            # Flatten stats for CSV
            click.echo("category,metric,value")
            for category, metrics in stats.items():
                if isinstance(metrics, dict):
                    for metric, value in metrics.items():
                        click.echo(f"{category},{metric},{value}")
                else:
                    click.echo(f"general,{category},{metrics}")
        else:  # table format
            click.echo("📊 Node Statistics")
            click.echo("=" * 50)
            
            for category, metrics in stats.items():
                if category == 'timestamp':
                    continue
                    
                click.echo(f"\n{category.replace('_', ' ').title()}:")
                if isinstance(metrics, dict):
                    for metric, value in metrics.items():
                        if isinstance(value, float):
                            click.echo(f"  {metric}: {value:.8f}")
                        elif isinstance(value, int):
                            click.echo(f"  {metric}: {value:,}")
                        else:
                            click.echo(f"  {metric}: {value}")
            
            click.echo(f"\nGenerated: {stats['timestamp']}")
        
    except Exception as e:
        click.echo(f"❌ Stats generation failed: {e}", err=True)