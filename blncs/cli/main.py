#!/usr/bin/env python3
"""
BLNCS - Bitcoin Lightning Network Control System
Consolidated CLI with practical Lightning Network management features.
"""

import sys
import click
import logging
from pathlib import Path
from typing import Optional, Dict, Any

# Setup basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Lazy imports for faster CLI startup
def get_lightning_client(config: Dict[str, Any]):
    """Create Lightning client"""
    from blncs.lightning.client import create_client
    return create_client(config)

def get_exceptions():
    """Lazy import exceptions"""
    from blncs.core.exceptions import (
        BLNCSError, ConnectionError, LightningError, ConfigError, 
        ValidationError, PaymentError, ChannelError, SecurityError,
        format_error_for_cli, handle_error
    )
    return {
        'BLNCSError': BLNCSError,
        'ConnectionError': ConnectionError,
        'LightningError': LightningError,
        'format_error_for_cli': format_error_for_cli
    }

def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration using unified config system"""
    from blncs.core.config_manager import get_config_manager
    config_manager = get_config_manager(config_path)
    return config_manager.get_all()

def validate_setup() -> Dict[str, bool]:
    """Validate system setup for dashboard"""
    validation = {}
    
    try:
        from blncs.core.config_manager import get_config_manager
        config = get_config_manager()
        config_data = config.get_all()
        validation['Configuration'] = bool(config_data)
    except Exception:
        validation['Configuration'] = False
    
    try:
        from blncs.core.database import get_database
        db = get_database()
        db.execute("SELECT 1")
        validation['Database'] = True
    except Exception:
        validation['Database'] = False
    
    try:
        from blncs.core.monitoring_unified import UnifiedMonitor
        monitor = UnifiedMonitor()
        validation['Monitoring'] = True
    except Exception:
        validation['Monitoring'] = False
    
    return validation


@click.group()
@click.option('--config', '-c', type=click.Path(exists=True), help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output mode')
@click.option('--quiet', '-q', is_flag=True, help='Quiet mode (errors only)')
@click.option('--debug', is_flag=True, help='Enable debug output')
@click.pass_context
def cli(ctx: click.Context, config: str, verbose: bool, quiet: bool, debug: bool) -> None:
    """
    BLNCS - Bitcoin Lightning Network Control System
    
    Practical Lightning Network management tool
    
    Common commands:
        blncs status                    # System status check
        blncs info                      # Node information
        blncs balance                   # Balance check
        blncs health                    # Quick health check
        blncs setup                     # Initial setup
    """
    ctx.ensure_object(dict)
    
    # Set logging level
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
    elif quiet:
        logging.getLogger().setLevel(logging.ERROR)
    elif verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Load configuration
    config_data = load_config(config)
    ctx.obj['config'] = config_data
    ctx.obj['verbose'] = verbose
    ctx.obj['quiet'] = quiet
    ctx.obj['debug'] = debug
    
    # Lightning client created on demand
    ctx.obj['_client'] = None
    ctx.obj['get_client'] = lambda: get_client(ctx)

def get_client(ctx):
    """Get or create Lightning client on demand"""
    if ctx.obj['_client'] is None:
        ctx.obj['_client'] = get_lightning_client(ctx.obj['config'])
    return ctx.obj['_client']


# Basic Information Commands
@cli.command()
@click.pass_context
def info(ctx):
    """Display Lightning node information"""
    exceptions = get_exceptions()
    client = get_client(ctx)
    
    try:
        client.connect()
        node_info = client.get_info()
        
        click.echo("Lightning Node Information:")
        click.echo(f"  Alias: {node_info.get('alias', 'Unknown')}")
        click.echo(f"  PubKey: {node_info.get('identity_pubkey', '')[:20]}...")
        click.echo(f"  Network: {node_info.get('network', 'unknown')}")
        click.echo(f"  Version: {node_info.get('version', 'unknown')}")
        click.echo(f"  Chain Synced: {'Yes' if node_info.get('synced_to_chain', False) else 'No'}")
        click.echo(f"  Graph Synced: {'Yes' if node_info.get('synced_to_graph', False) else 'No'}")
        
    except Exception as e:
        click.echo(exceptions['format_error_for_cli'](e), err=True)
        sys.exit(1)
    finally:
        try:
            client.disconnect()
        except:
            pass

@cli.command()
@click.pass_context
def balance(ctx):
    """Show wallet and channel balances"""
    exceptions = get_exceptions()
    client = get_client(ctx)
    
    try:
        client.connect()
        balance_info = client.get_balance()
        
        click.echo("Balance Information:")
        click.echo(f"  Total Balance: {balance_info.get('total', 0):,} sats")
        click.echo(f"  Wallet Balance: {balance_info.get('wallet', 0):,} sats")
        click.echo(f"  Channel Balance: {balance_info.get('channel', 0):,} sats")
        if 'pending' in balance_info:
            click.echo(f"  Pending: {balance_info['pending']:,} sats")
            
    except Exception as e:
        click.echo(exceptions['format_error_for_cli'](e), err=True)
        sys.exit(1)
    finally:
        try:
            client.disconnect()
        except:
            pass

@cli.command()
@click.pass_context
def channels(ctx):
    """List all channels"""
    exceptions = get_exceptions()
    client = get_client(ctx)
    
    try:
        client.connect()
        channels_info = client.get_channels()
        
        if not channels_info:
            click.echo("No channels found")
            return
        
        click.echo(f"Channels ({len(channels_info)} total):")
        for i, channel in enumerate(channels_info, 1):
            status = "Active" if channel.get('active', False) else "Inactive"
            capacity = channel.get('capacity', 0)
            local_balance = channel.get('local_balance', 0)
            remote_balance = channel.get('remote_balance', 0)
            
            click.echo(f"  {i}. [{status}] Capacity: {capacity:,} sats")
            click.echo(f"     Local: {local_balance:,} | Remote: {remote_balance:,}")
            
    except Exception as e:
        click.echo(exceptions['format_error_for_cli'](e), err=True)
        sys.exit(1)
    finally:
        try:
            client.disconnect()
        except:
            pass


# System Commands
@cli.command()
@click.pass_context
def system_info(ctx):
    """Display system information"""
    try:
        from blncs.utils.system_info import get_system_info
        system_data = get_system_info()
        
        click.echo("System Information:")
        click.echo(f"  Platform: {system_data.get('platform', 'Unknown')}")
        click.echo(f"  Python: {system_data.get('python_version', 'Unknown')}")
        click.echo(f"  CPU Cores: {system_data.get('cpu_count', 'Unknown')}")
        click.echo(f"  Memory: {system_data.get('memory_gb', 'Unknown')} GB")
        click.echo(f"  Disk Space: {system_data.get('disk_gb', 'Unknown')} GB available")
        
    except ImportError:
        click.echo("System information not available")
    except Exception as e:
        click.echo(f"Error getting system info: {e}", err=True)

@cli.command()
@click.option('--quick', '-q', is_flag=True, help='Quick health check only')
@click.pass_context
def health(ctx, quick):
    """Check system health"""
    try:
        from blncs.core import get_health_checker
        checker = get_health_checker()
        
        if quick:
            click.echo("Quick Health Check:")
            result = checker.get_quick_status()
            
            status_icon = {"healthy": "✓", "warning": "⚠", "critical": "✗"}.get(result.get('status'), "?")
            click.echo(f"  Status: {status_icon} {result.get('status', 'unknown')}")
            
            if 'cpu_percent' in result:
                click.echo(f"  CPU: {result['cpu_percent']:.1f}%")
            if 'memory_percent' in result:
                click.echo(f"  Memory: {result['memory_percent']:.1f}%")
            if 'lightning_node' in result:
                ln_status = "Connected" if result['lightning_node'] == 'connected' else "Disconnected"
                click.echo(f"  Lightning Node: {ln_status}")
        else:
            click.echo("Full Health Check:")
            result = checker.run_full_health_check()
            
            status_icon = {"healthy": "✓", "warning": "⚠", "critical": "✗"}.get(result['overall_status'], "?")
            click.echo(f"  Overall: {status_icon} {result['overall_status']} ({result.get('health_score', 'N/A')})")
            
            for check_name, check_result in result.get('checks', {}).items():
                status = check_result.get('status', 'unknown')
                status_icon = {"healthy": "✓", "warning": "⚠", "critical": "✗"}.get(status, "?")
                check_display = check_name.replace('_', ' ').title()
                click.echo(f"  {check_display}: {status_icon} {status}")
                
    except ImportError:
        click.echo("Health check not available")
    except Exception as e:
        click.echo(f"Health check error: {e}", err=True)


# Status and Setup Commands
@cli.command()
@click.pass_context
def status(ctx):
    """Show BLNCS system status"""
    try:
        validation = validate_setup()
        
        click.echo("BLNCS System Status:")
        for item, status in validation.items():
            status_icon = "✓" if status else "✗"
            click.echo(f"  {status_icon} {item}")
        
        all_good = all(validation.values())
        if all_good:
            click.echo("\nSystem is operational")
        else:
            click.echo("\nSome components need attention. Run 'blncs setup' to configure.")
            
    except Exception as e:
        click.echo(f"Status check error: {e}", err=True)
        sys.exit(1)

@cli.command()
@click.option('--force', is_flag=True, help='Force overwrite existing configuration')
@click.pass_context
def setup(ctx, force):
    """Interactive setup wizard"""
    try:
        from blncs.utils.setup_helper import run_full_setup
        
        click.echo("BLNCS Setup starting...")
        result = run_full_setup()
        
        if result.get('created_dirs'):
            click.echo(f"Created directories: {', '.join(result['created_dirs'])}")
        
        if result.get('config_file'):
            click.echo(f"Configuration file: {result['config_file']}")
        
        if result.get('env_suggestions'):
            click.echo("\nRecommended environment variables:")
            for suggestion in result['env_suggestions']:
                click.echo(f"  {suggestion}")
        
        validation = result.get('validation', {})
        if validation:
            click.echo("\nSetup Status:")
            for item, status in validation.items():
                status_icon = "✓" if status else "✗"
                click.echo(f"  {status_icon} {item}")
        
        if result.get('success'):
            click.echo("\nSetup completed successfully!")
        else:
            click.echo("\nSetup encountered issues. Check the status above.")
            if result.get('error'):
                click.echo(f"Error: {result['error']}")
                
    except ImportError:
        click.echo("Setup wizard not available")
    except Exception as e:
        click.echo(f"Setup error: {e}", err=True)
        sys.exit(1)


# Payment Commands
@cli.group()
def payment():
    """Payment operations"""
    pass

@payment.command('send')
@click.argument('invoice')
@click.pass_context
def pay_invoice(ctx, invoice):
    """Pay a Lightning invoice"""
    exceptions = get_exceptions()
    client = get_client(ctx)
    
    try:
        client.connect()
        result = client.send_payment(invoice)
        
        click.echo("Payment sent:")
        click.echo(f"  Hash: {result['payment_hash']}")
        click.echo(f"  Amount: {result['amount']} sats")
        click.echo(f"  Status: {result['status']}")
        
    except Exception as e:
        click.echo(exceptions['format_error_for_cli'](e), err=True)
        sys.exit(1)
    finally:
        try:
            client.disconnect()
        except:
            pass

@payment.command('receive')
@click.argument('amount', type=int)
@click.option('--memo', help='Payment memo')
@click.pass_context
def create_invoice(ctx, amount, memo):
    """Create a payment invoice"""
    exceptions = get_exceptions()
    client = get_client(ctx)
    
    try:
        client.connect()
        invoice = client.create_invoice(amount, memo or "")
        
        click.echo("Invoice created:")
        click.echo(f"  {invoice}")
        
    except Exception as e:
        click.echo(exceptions['format_error_for_cli'](e), err=True)
        sys.exit(1)
    finally:
        try:
            client.disconnect()
        except:
            pass

@payment.command('history')
@click.option('--limit', default=10, help='Number of payments to show')
@click.pass_context
def payment_history(ctx, limit):
    """Show payment history"""
    try:
        from blncs.core.history import get_history_manager
        hist = get_history_manager()
        
        transactions = hist.get_recent_transactions(limit)
        
        if not transactions:
            click.echo("No payment history found")
            return
        
        click.echo(f"Recent payments ({limit} latest):")
        for i, tx in enumerate(transactions, 1):
            timestamp = tx.get('timestamp', 'N/A')
            tx_type = tx.get('type', 'unknown')
            data = tx.get('data', {})
            
            click.echo(f"\n{i}. [{tx_type}] {timestamp}")
            if 'amount' in data:
                click.echo(f"   Amount: {data['amount']} sats")
            if 'memo' in data and data['memo']:
                click.echo(f"   Memo: {data['memo']}")
            if 'success' in data:
                status = "Success" if data['success'] else "Failed"
                click.echo(f"   Status: {status}")
                
    except ImportError:
        click.echo("Payment history not available")
    except Exception as e:
        click.echo(f"Payment history error: {e}", err=True)


# Configuration Commands
@cli.group()
def config():
    """Configuration management"""
    pass

@config.command('get')
@click.argument('key', required=False)
@click.pass_context
def config_get(ctx, key):
    """Get configuration value"""
    try:
        from blncs.core.config_manager import get_config_manager
        config_manager = get_config_manager()
        
        if key:
            value = config_manager.get(key)
            if value is not None:
                click.echo(f"{key} = {value}")
            else:
                click.echo(f"Configuration key '{key}' not found")
        else:
            # Show all configuration
            import yaml
            click.echo("Current configuration:")
            click.echo(yaml.dump(config_manager.get_all(), default_flow_style=False))
            
    except Exception as e:
        click.echo(f"Configuration error: {e}", err=True)

@config.command('set')
@click.argument('key')
@click.argument('value')
@click.option('--persist', is_flag=True, help='Save to configuration file')
@click.pass_context
def config_set(ctx, key, value, persist):
    """Set configuration value"""
    try:
        from blncs.core.config_manager import get_config_manager
        config_manager = get_config_manager()
        
        # Try to convert value to appropriate type
        if value.lower() in ('true', 'false'):
            value = value.lower() == 'true'
        elif value.isdigit():
            value = int(value)
        elif '.' in value and value.replace('.', '').isdigit():
            value = float(value)
        
        config_manager.set(key, value, persist)
        click.echo(f"Set {key} = {value}")
        if persist:
            click.echo("Configuration saved to file")
            
    except Exception as e:
        click.echo(f"Configuration error: {e}", err=True)

@config.command('validate')
@click.pass_context
def config_validate(ctx):
    """Validate configuration"""
    try:
        from blncs.core.config_manager import get_config_manager
        config_manager = get_config_manager()
        
        if config_manager.validate():
            click.echo("Configuration is valid")
        else:
            click.echo("Configuration has validation errors")
            
    except Exception as e:
        click.echo(f"Configuration validation error: {e}", err=True)


# Utility Commands
@cli.command()
@click.argument('satoshis', type=int)
def sats_to_btc(satoshis):
    """Convert satoshis to BTC"""
    btc = satoshis / 100000000
    click.echo(f"{satoshis:,} sats = {btc:.8f} BTC")

@cli.command()
@click.argument('btc', type=float)
def btc_to_sats(btc):
    """Convert BTC to satoshis"""
    satoshis = int(btc * 100000000)
    click.echo(f"{btc:.8f} BTC = {satoshis:,} sats")

@cli.command()
@click.argument('text')
@click.option('--size', default=21, help='QR code size')
@click.option('--save', help='Save to file')
def qr(text, size, save):
    """Generate QR code for text/invoice"""
    try:
        from blncs.utils.qr_enhanced import generate_qr_code
        qr_code = generate_qr_code(text, size, save_to_file=save)
        if not save:
            click.echo(qr_code)
        else:
            click.echo(f"QR code saved to: {save}")
    except ImportError:
        click.echo("QR code generation not available")
    except Exception as e:
        click.echo(f"QR code error: {e}", err=True)

# Network Testing Commands
@cli.command()
@click.option('--host', default='8.8.8.8', help='Host to test')
@click.option('--count', default=4, help='Number of tests')
def nettest(host, count):
    """Test network connectivity"""
    try:
        from blncs.utils.network_test import test_connectivity
        result = test_connectivity(host, count)
        
        click.echo(f"Network test to {host}:")
        click.echo(f"  Success rate: {result.get('success_rate', 0):.1%}")
        click.echo(f"  Average latency: {result.get('avg_latency', 0):.1f}ms")
        
    except ImportError:
        click.echo("Network testing not available")
    except Exception as e:
        click.echo(f"Network test error: {e}", err=True)

# Version command
@cli.command()
def version():
    """Show BLNCS version"""
    try:
        from blncs import __version__
        click.echo(f"BLNCS {__version__}")
    except ImportError:
        click.echo("BLNCS Lightning Network Control System")
    click.echo("Bitcoin Lightning Network Control System")


# Add command groups
def add_command_groups():
    """Add command groups to CLI"""
    try:
        from .commands.system import system_commands
        cli.add_command(system_commands)
    except ImportError:
        pass
    
    try:
        from .commands.connect import connect_commands
        cli.add_command(connect_commands)
    except ImportError:
        pass
    
    try:
        from .commands.wallet import wallet_commands
        cli.add_command(wallet_commands)
    except ImportError:
        pass
    
    try:
        from .commands.metrics import metrics_commands
        cli.add_command(metrics_commands)
    except ImportError:
        pass
    
    try:
        from .commands.maintenance import maintenance_commands
        cli.add_command(maintenance_commands)
    except ImportError:
        pass

# Initialize command groups
add_command_groups()


def main():
    """Main entry point with graceful shutdown"""
    try:
        cli()
    except KeyboardInterrupt:
        click.echo("\nOperation cancelled", err=True)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    main()