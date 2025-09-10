#!/usr/bin/env python3
"""
BLNCS Simple CLI - Basic Lightning Network operations
Simplified CLI interface without complex dependencies.
"""

import sys
import click
import json
from typing import Optional, Dict, Any

def get_config():
    """Get basic configuration"""
    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
        from blncs.core.config_manager import get_config_manager
        config_manager = get_config_manager()
        return config_manager.get_all()
    except Exception as e:
        return {}

def get_logger():
    """Get basic logger"""
    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
        from blncs.core.logger import get_logger
        return get_logger(__name__)
    except:
        import logging
        return logging.getLogger(__name__)

@click.group()
@click.option('--config', '-c', type=click.Path(), help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.pass_context
def cli(ctx: click.Context, config: str, verbose: bool) -> None:
    """
    BLNCS - Bitcoin Lightning Network Control System
    Simple Lightning Network management tool
    """
    ctx.ensure_object(dict)
    ctx.obj['config'] = get_config()
    ctx.obj['verbose'] = verbose
    ctx.obj['logger'] = get_logger()

@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show system status"""
    try:
        config = ctx.obj.get('config', {})
        click.echo("BLNCS System Status:")
        click.echo(f"Configuration: {'✓ Loaded' if config else '✗ Error'}")
        
        # Test core modules
        try:
            import sys
            import os
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
            from blncs.core.exceptions import BLNCSError
            click.echo("Core modules: ✓ Available")
        except Exception as e:
            click.echo(f"Core modules: ✗ Error - {e}")
            
        # Test Lightning client basic import
        try:
            import sys
            import os
            import importlib.util
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
            spec = importlib.util.find_spec('blncs.lightning.client')
            if spec:
                click.echo("Lightning client: ✓ Available") 
            else:
                click.echo("Lightning client: ✗ Not found")
        except Exception as e:
            click.echo(f"Lightning client: ✗ Error - {e}")
            
    except Exception as e:
        click.echo(f"Status check failed: {e}")

@cli.command()
@click.pass_context
def info(ctx: click.Context) -> None:
    """Show node information"""
    click.echo("BLNCS Information:")
    click.echo("Version: 1.0.0")
    click.echo("Type: Lightning Network Control System")
    
    config = ctx.obj.get('config', {})
    if config:
        click.echo("\nConfiguration:")
        click.echo(f"  Lightning Node: {config.get('lightning', {}).get('host', 'Not configured')}")
        click.echo(f"  Database: {config.get('database', {}).get('path', 'blncs.db')}")
    else:
        click.echo("Configuration: Not loaded")

@cli.command()
@click.pass_context  
def test(ctx: click.Context) -> None:
    """Run basic system tests"""
    click.echo("Running BLNCS basic tests...")
    
    try:
        # Test configuration
        config = ctx.obj.get('config', {})
        if config:
            click.echo("✓ Configuration system")
        else:
            click.echo("✗ Configuration system")
            
        # Test imports
        try:
            import sys
            import os
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
            from blncs.core.exceptions import BLNCSError
            from blncs.core.logger import get_logger
            click.echo("✓ Core modules")
        except Exception as e:
            click.echo(f"✗ Core modules: {e}")
            
        # Test database
        try:
            import sys
            import os
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
            from blncs.core.database import get_database_manager
            db = get_database_manager()
            click.echo("✓ Database system")
        except Exception as e:
            click.echo(f"✗ Database system: {e}")
            
        click.echo("Basic tests completed.")
        
    except Exception as e:
        click.echo(f"Test failed: {e}")

@cli.command()
@click.pass_context
def config_show(ctx: click.Context) -> None:
    """Show current configuration"""
    config = ctx.obj.get('config', {})
    if config:
        click.echo(json.dumps(config, indent=2))
    else:
        click.echo("No configuration loaded")

if __name__ == '__main__':
    cli()