"""
Setup Helper Command
Interactive setup wizard for BLNCS configuration.
"""

import click
import os
import json
from pathlib import Path
from typing import Dict, Any, Optional

from ...core.logger import get_logger
from ...core.exceptions import format_error_for_cli

logger = get_logger(__name__)


def test_lightning_connection(config: Dict[str, Any]) -> bool:
    """Test Lightning node connection with given config"""
    try:
        from ...lightning.client import LightningClient
        client = LightningClient(config)
        info = client.get_info()
        return info is not None
    except Exception:
        return False


@click.command()
@click.pass_context
def setup(ctx: click.Context) -> None:
    """Interactive setup wizard for BLNCS"""
    
    click.echo("🚀 BLNCS Setup Wizard")
    click.echo("=" * 50)
    click.echo("This wizard will help you configure BLNCS to connect to your Lightning node.\n")
    
    # Check if config already exists
    config_path = Path.home() / '.blncs' / 'config.json'
    if config_path.exists():
        if not click.confirm("⚠️ Configuration already exists. Overwrite?"):
            click.echo("Setup cancelled.")
            return
    
    config = {}
    
    # Lightning node type
    click.echo("\n📡 Lightning Node Configuration")
    click.echo("-" * 40)
    
    node_types = ['lnd', 'core-lightning', 'eclair']
    for i, node_type in enumerate(node_types, 1):
        click.echo(f"{i}. {node_type}")
    
    choice = click.prompt("Select your Lightning node type", type=int, default=1)
    if 1 <= choice <= len(node_types):
        config['node_type'] = node_types[choice - 1]
    else:
        config['node_type'] = 'lnd'
    
    # Connection details
    click.echo(f"\n🔌 {config['node_type'].upper()} Connection Details")
    click.echo("-" * 40)
    
    # Host
    config['host'] = click.prompt(
        "Lightning node host",
        default="localhost",
        type=str
    )
    
    # Port
    default_ports = {
        'lnd': 10009,
        'core-lightning': 9735,
        'eclair': 8080
    }
    config['port'] = click.prompt(
        "Lightning node port",
        default=default_ports.get(config['node_type'], 8080),
        type=int
    )
    
    # LND specific configuration
    if config['node_type'] == 'lnd':
        click.echo("\n🔐 LND Authentication")
        click.echo("-" * 40)
        
        # TLS Certificate
        default_tls = Path.home() / '.lnd' / 'tls.cert'
        tls_path = click.prompt(
            "Path to TLS certificate",
            default=str(default_tls) if default_tls.exists() else "",
            type=click.Path(exists=True)
        )
        config['tls_cert_path'] = tls_path
        
        # Macaroon
        default_macaroon = Path.home() / '.lnd' / 'data' / 'chain' / 'bitcoin' / 'mainnet' / 'admin.macaroon'
        macaroon_path = click.prompt(
            "Path to admin macaroon",
            default=str(default_macaroon) if default_macaroon.exists() else "",
            type=click.Path(exists=True)
        )
        config['macaroon_path'] = macaroon_path
    
    # Data directories
    click.echo("\n📂 Data Storage")
    click.echo("-" * 40)
    
    data_dir = click.prompt(
        "Data directory for BLNCS",
        default=str(Path.home() / '.blncs' / 'data'),
        type=click.Path()
    )
    config['data_dir'] = data_dir
    
    # Create directories
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    
    # Test connection
    click.echo("\n🔍 Testing Lightning connection...")
    
    test_config = {
        'lightning': config
    }
    
    if test_lightning_connection(test_config):
        click.echo("✅ Successfully connected to Lightning node!")
        
        # Get node info for confirmation
        try:
            from ...lightning.client import LightningClient
            client = LightningClient(test_config)
            info = client.get_info()
            
            click.echo(f"\n📊 Node Information:")
            click.echo(f"  Alias: {info.get('alias', 'Unknown')}")
            click.echo(f"  Network: {info.get('chains', [{}])[0].get('network', 'Unknown')}")
            click.echo(f"  Block Height: {info.get('block_height', 0):,}")
            click.echo(f"  Active Channels: {info.get('num_active_channels', 0)}")
            
        except Exception as e:
            logger.warning(f"Could not get node info: {e}")
    else:
        click.echo("⚠️ Could not connect to Lightning node.")
        click.echo("Please check your settings and try again.")
        
        if not click.confirm("Continue anyway?"):
            click.echo("Setup cancelled.")
            return
    
    # Additional settings
    click.echo("\n⚙️ Additional Settings")
    click.echo("-" * 40)
    
    # Monitoring interval
    config['monitoring_interval'] = click.prompt(
        "Health monitoring interval (seconds)",
        default=300,
        type=int
    )
    
    # Log level
    log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR']
    click.echo("\nLog level:")
    for i, level in enumerate(log_levels, 1):
        click.echo(f"{i}. {level}")
    
    choice = click.prompt("Select log level", type=int, default=2)
    if 1 <= choice <= len(log_levels):
        config['log_level'] = log_levels[choice - 1]
    else:
        config['log_level'] = 'INFO'
    
    # Save configuration
    click.echo("\n💾 Saving Configuration")
    click.echo("-" * 40)
    
    # Prepare full config structure
    full_config = {
        'lightning': {
            'type': config.pop('node_type', 'lnd'),
            'host': config.pop('host', 'localhost'),
            'port': config.pop('port', 10009)
        },
        'system': {
            'data_dir': config.pop('data_dir', str(Path.home() / '.blncs' / 'data')),
            'log_level': config.pop('log_level', 'INFO')
        },
        'monitoring': {
            'interval': config.pop('monitoring_interval', 300)
        }
    }
    
    # Add LND specific fields if present
    if 'tls_cert_path' in config:
        full_config['lightning']['tls_cert_path'] = config['tls_cert_path']
    if 'macaroon_path' in config:
        full_config['lightning']['macaroon_path'] = config['macaroon_path']
    
    # Save to file
    config_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(config_path, 'w') as f:
        json.dump(full_config, f, indent=2)
    
    click.echo(f"✅ Configuration saved to: {config_path}")
    
    # Create other necessary directories
    dirs_to_create = [
        Path(full_config['system']['data_dir']),
        Path(full_config['system']['data_dir']) / 'logs',
        Path(full_config['system']['data_dir']) / 'backups',
        Path(full_config['system']['data_dir']) / 'cache'
    ]
    
    for dir_path in dirs_to_create:
        dir_path.mkdir(parents=True, exist_ok=True)
    
    click.echo(f"✅ Created data directories in: {full_config['system']['data_dir']}")
    
    # Next steps
    click.echo("\n🎉 Setup Complete!")
    click.echo("=" * 50)
    click.echo("\nNext steps:")
    click.echo("1. Test connection:    blncs info")
    click.echo("2. Check balance:      blncs balance")
    click.echo("3. View channels:      blncs channels")
    click.echo("4. Check health:       blncs health-check")
    click.echo("5. View dashboard:     blncs dashboard")
    click.echo("\nFor help: blncs --help")


@click.command()
@click.pass_context
def validate_config(ctx: click.Context) -> None:
    """Validate current configuration"""
    try:
        from ...core.config_manager import get_config_manager
        
        config_manager = get_config_manager()
        config = config_manager.get_all()
        
        click.echo("🔍 Validating Configuration")
        click.echo("=" * 50)
        
        issues = []
        warnings = []
        
        # Check Lightning configuration
        if 'lightning' not in config:
            issues.append("Missing 'lightning' section")
        else:
            ln_config = config['lightning']
            
            # Required fields
            required_fields = ['host', 'port']
            for field in required_fields:
                if field not in ln_config:
                    issues.append(f"Missing lightning.{field}")
            
            # LND specific checks
            if ln_config.get('type') == 'lnd':
                if 'tls_cert_path' in ln_config:
                    tls_path = Path(ln_config['tls_cert_path'])
                    if not tls_path.exists():
                        issues.append(f"TLS certificate not found: {tls_path}")
                
                if 'macaroon_path' in ln_config:
                    mac_path = Path(ln_config['macaroon_path'])
                    if not mac_path.exists():
                        issues.append(f"Macaroon not found: {mac_path}")
        
        # Check system configuration
        if 'system' in config:
            sys_config = config['system']
            
            if 'data_dir' in sys_config:
                data_dir = Path(sys_config['data_dir'])
                if not data_dir.exists():
                    warnings.append(f"Data directory does not exist: {data_dir}")
        
        # Test Lightning connection
        click.echo("\n📡 Testing Lightning Connection...")
        
        try:
            from ...lightning.client import LightningClient
            client = LightningClient(config)
            info = client.get_info()
            
            if info:
                click.echo(f"✅ Connected to: {info.get('alias', 'Unknown')}")
                click.echo(f"   Network: {info.get('chains', [{}])[0].get('network', 'Unknown')}")
                click.echo(f"   Synced: {'Yes' if info.get('synced_to_chain') else 'No'}")
            else:
                issues.append("Could not get node information")
                
        except Exception as e:
            issues.append(f"Connection failed: {str(e)[:100]}")
        
        # Display results
        click.echo("\n📊 Validation Results")
        click.echo("-" * 40)
        
        if not issues and not warnings:
            click.echo("✅ Configuration is valid!")
        else:
            if issues:
                click.echo("\n❌ Issues found:")
                for issue in issues:
                    click.echo(f"  • {issue}")
            
            if warnings:
                click.echo("\n⚠️ Warnings:")
                for warning in warnings:
                    click.echo(f"  • {warning}")
            
            click.echo("\nRun 'blncs setup' to reconfigure")
            
    except Exception as e:
        click.echo(f"❌ Error: {format_error_for_cli(e)}", err=True)