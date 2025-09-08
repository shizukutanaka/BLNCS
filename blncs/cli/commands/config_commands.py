"""
Configuration Management Commands
Unified configuration management and validation commands.
"""

import click
import yaml
import json
from pathlib import Path
from typing import Dict, Any

from ...core.config_manager import get_config_manager
from ...core.enhanced_validator import get_enhanced_validator
from ...core.exceptions import format_error_for_cli
from ...utils.setup_helper import run_basic_setup


@click.command('config')
@click.option('--show', is_flag=True, help='Show current configuration')
@click.option('--validate', is_flag=True, help='Validate configuration')
@click.option('--repair', is_flag=True, help='Repair configuration issues')
@click.option('--init', is_flag=True, help='Initialize new configuration')
@click.option('--section', help='Show specific configuration section')
@click.option('--format', 'output_format', default='yaml', type=click.Choice(['yaml', 'json']), help='Output format')
def config_management(show: bool, validate: bool, repair: bool, init: bool, section: str, output_format: str) -> None:
    """Unified configuration management"""
    try:
        if init:
            click.echo("Initializing BLNCS configuration...")
            results = run_basic_setup()
            click.echo(f"Setup completed with {len(results)} operations")
            for result in results[:5]:  # Show first 5 results
                status_icon = "[OK]" if result.get('success', False) else "[ERROR]"
                click.echo(f"  {status_icon} {result.get('description', 'Unknown operation')}")
            return
            
        config_manager = get_config_manager()
        
        if show:
            click.echo("Current Configuration:")
            click.echo("=" * 40)
            
            if section:
                section_data = config_manager.get_all().get(section, {})
                if section_data:
                    if output_format == 'json':
                        click.echo(json.dumps(section_data, indent=2))
                    else:
                        click.echo(yaml.dump(section_data, default_flow_style=False))
                else:
                    click.echo(f"Section '{section}' not found")
            else:
                if output_format == 'json':
                    click.echo(json.dumps(config_manager.get_all(), indent=2))
                else:
                    click.echo(yaml.dump(config_manager.get_all(), default_flow_style=False))
            
        elif validate:
            click.echo("Validating configuration...")
            
            # Enhanced validation
            try:
                is_valid = config_manager.validate()
                
                if is_valid:
                    click.echo("\n[OK] Configuration validation passed")
                else:
                    click.echo(f"\n[ERROR] Configuration validation failed")
                    
                # Additional validation with enhanced validator
                validator = get_enhanced_validator()
                stats = validator.get_statistics()
                if stats:
                    click.echo(f"  Validation statistics: {stats}")
                    
            except Exception as e:
                click.echo(f"\n[WARNING] Validation failed: {str(e)}")
        
        elif repair:
            click.echo("Repairing configuration...")
            
            try:
                # Reload configuration to repair any issues
                config_manager.reload()
                
                # Validate after reload
                is_valid = config_manager.validate()
                
                if is_valid:
                    click.echo("[OK] Configuration repaired successfully")
                else:
                    click.echo("[ERROR] Configuration still has validation issues")
                    
            except Exception as e:
                click.echo(f"[ERROR] Repair failed: {str(e)}")
        
        else:
            # Show config summary
            click.echo("Configuration Summary:")
            click.echo("-" * 30)
            click.echo(f"Config file: {config_manager.config_path}")
            click.echo(f"Sections: {len(config_manager.get_all())}")
            
            # Show section names
            config_data = config_manager.get_all()
            if config_data:
                sections = list(config_data.keys())
                click.echo(f"Available sections: {', '.join(sections)}")
                
            click.echo("\nOptions:")
            click.echo("  --show      Show configuration")
            click.echo("  --validate  Validate configuration") 
            click.echo("  --repair    Repair configuration issues")
            click.echo("  --init      Initialize new configuration")
            
    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)


@click.command('config-get')
@click.argument('key')
@click.option('--default', help='Default value if key not found')
def config_get(key: str, default: str) -> None:
    """Get specific configuration value"""
    try:
        config_manager = get_config_manager()
        
        # Use config manager's get method with dot notation
        value = config_manager.get(key, default)
        
        if value is None and default is None:
            click.echo(f"Key '{key}' not found", err=True)
            return
        
        # Output the value
        if isinstance(value, (dict, list)):
            click.echo(yaml.dump(value, default_flow_style=False))
        else:
            click.echo(str(value))
            
    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)


@click.command('config-set')
@click.argument('key')
@click.argument('value')
@click.option('--type', 'value_type', default='string', type=click.Choice(['string', 'int', 'float', 'bool']), 
              help='Value type')
def config_set(key: str, value: str, value_type: str) -> None:
    """Set configuration value"""
    try:
        config_manager = get_config_manager()
        
        # Convert value based on type
        if value_type == 'int':
            converted_value = int(value)
        elif value_type == 'float':
            converted_value = float(value)
        elif value_type == 'bool':
            converted_value = value.lower() in ('true', '1', 'yes', 'on')
        else:
            converted_value = value
        
        # Use config manager's set method
        config_manager.set(key, converted_value, persist=True)
        
        click.echo(f"Set {key} = {converted_value}")
        
    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)


@click.command('config-list')
@click.option('--section', help='List keys in specific section')
def config_list(section: str) -> None:
    """List all configuration keys"""
    try:
        config_manager = get_config_manager()
        
        def list_keys(data: Dict[str, Any], prefix: str = "") -> None:
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                if isinstance(value, dict):
                    click.echo(f"{full_key}/ (section)")
                    list_keys(value, full_key)
                else:
                    click.echo(f"{full_key} = {value}")
        
        config_data = config_manager.get_all()
        
        if section:
            if section in config_data:
                section_data = config_data[section]
                if isinstance(section_data, dict):
                    list_keys(section_data, section)
                else:
                    click.echo(f"{section} = {section_data}")
            else:
                click.echo(f"Section '{section}' not found")
        else:
            list_keys(config_data)
            
    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)


@click.command('env-template')
def env_template() -> None:
    """Generate .env template file"""
    try:
        # Generate template using config manager
        try:
            template_content = config_manager.export_env_template()
        except:
            # Fallback template
            template_content = """# BLNCS Environment Variables Template
# Copy this to .env and customize values

# Lightning Node Configuration
LND_DIR=/path/to/lnd
LN_HOST=localhost
LN_PORT=9735

# Bitcoin Core Configuration  
BITCOIN_DATADIR=/path/to/bitcoin
BITCOIN_RPC_HOST=localhost
BITCOIN_RPC_PORT=8332
BITCOIN_RPC_USER=username
BITCOIN_RPC_PASSWORD=password

# BLNCS Configuration
BLNCS_CONFIG=/path/to/config.yaml
BLNCS_LOG_LEVEL=INFO
BLNCS_LOG_FILE=/path/to/logs/blncs.log

# Network
NETWORK=mainnet

# Security (Optional)
MACAROON_PATH=/path/to/admin.macaroon
TLS_CERT_PATH=/path/to/tls.cert
"""
        
        env_file = Path(".env.template")
        with open(env_file, 'w') as f:
            f.write(template_content)
            
        click.echo(f"Environment template created: {env_file}")
        click.echo("Copy to .env and customize the values")
        
    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)