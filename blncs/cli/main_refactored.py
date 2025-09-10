#!/usr/bin/env python3
"""
BLNCS - Bitcoin Lightning Network Control System
Refactored modular CLI implementation with improved organization.
"""

import sys
import click
from typing import Optional, Dict, Any

# Core CLI components
from .core.cli_context import CLIContext, create_cli_context, pass_cli_context
from .core.command_registry import get_command_registry
from .core.group_factory import create_cli_application, add_command_aliases

# Error handling
from ..core.error_handler import get_error_handler
from ..core.exceptions import BLNCSError, format_error_for_cli
from ..core.async_cli_wrapper import handle_cli_error, success_message, info_message


def setup_error_handling():
    """Setup global error handling for CLI"""
    def handle_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            print("\n\n👋 Interrupted by user")
            sys.exit(1)
        elif issubclass(exc_type, BLNCSError):
            handle_cli_error(exc_value, "application")
            sys.exit(1)
        else:
            # Let normal exception handling proceed
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
    
    sys.excepthook = handle_exception


def create_optimized_cli():
    """Create optimized CLI with lazy loading and better organization"""
    
    @click.group()
    @click.option('--config', '-c', type=click.Path(), 
                  help='Configuration file path')
    @click.option('--verbose', '-v', is_flag=True, 
                  help='Enable verbose output mode')
    @click.option('--quiet', '-q', is_flag=True, 
                  help='Quiet mode (errors only)')
    @click.version_option(version='2.0.0', prog_name='BLNCS')
    @click.pass_context
    def cli(ctx: click.Context, config: str, verbose: bool, quiet: bool):
        """
        🚀 BLNCS - Bitcoin Lightning Network Control System
        
        A lightweight, practical Lightning Network management tool.
        
        \b
        Quick Start:
        -----------
        blncs info              # Node information
        blncs balance           # Check balances  
        blncs channels          # List channels
        blncs health-check      # System diagnosis
        
        \b
        Configuration:
        -------------
        blncs config set lightning.host localhost
        blncs config set lightning.port 8080
        blncs config set lightning.network testnet
        
        \b
        Common Operations:
        -----------------
        blncs dashboard         # Overview dashboard
        blncs finance earnings  # Earnings analysis
        blncs tools qr create   # Generate QR codes
        blncs system backup     # Backup data
        
        Use 'blncs COMMAND --help' for detailed help on any command.
        """
        ctx.ensure_object(dict)
        
        # Create CLI context with proper error handling
        try:
            cli_context = create_cli_context(config, verbose, quiet)
            ctx.obj['cli_context'] = cli_context
            ctx.obj['config'] = cli_context.config
            ctx.obj['verbose'] = verbose
            ctx.obj['quiet'] = quiet
            
            # Legacy compatibility
            ctx.obj['get_client'] = lambda: cli_context.client
            
        except Exception as e:
            if not quiet:
                handle_cli_error(e, "initialization")
            sys.exit(1)
    
    return cli


def add_core_commands(cli_app):
    """Add essential commands directly to main CLI"""
    
    @cli_app.command()
    @pass_cli_context
    def info(cli_context: CLIContext):
        """📊 Display Lightning node information"""
        try:
            client = cli_context.client
            node_info = client.get_info()
            
            if node_info:
                click.echo("\n🚀 Lightning Node Information")
                click.echo("=" * 40)
                click.echo(f"Node Alias:     {node_info.get('alias', 'Unknown')}")
                click.echo(f"Public Key:     {node_info.get('identity_pubkey', '')[:20]}...")
                click.echo(f"Network:        {node_info.get('network', 'unknown')}")
                click.echo(f"Version:        {node_info.get('version', 'unknown')}")
                click.echo(f"Channels:       {node_info.get('num_channels', 0)}")
                click.echo(f"Peers:          {node_info.get('num_peers', 0)}")
                click.echo(f"Block Height:   {node_info.get('block_height', 0)}")
                click.echo(f"Chain Synced:   {'✅' if node_info.get('synced_to_chain') else '❌'}")
                click.echo(f"Graph Synced:   {'✅' if node_info.get('synced_to_graph') else '❌'}")
                success_message("Node information retrieved successfully")
            else:
                click.echo("❌ Could not retrieve node information")
                
        except Exception as e:
            handle_cli_error(e, "info command")
    
    @cli_app.command()
    @pass_cli_context
    def balance(cli_context: CLIContext):
        """💰 Display wallet and channel balances"""
        try:
            client = cli_context.client
            balances = client.get_balance()
            
            if balances:
                click.echo("\n💰 Balance Information")
                click.echo("=" * 30)
                click.echo(f"On-chain Balance:")
                click.echo(f"  Total:        {balances.get('total', 0):,} sats")
                click.echo(f"  Confirmed:    {balances.get('confirmed', 0):,} sats")
                click.echo(f"  Unconfirmed:  {balances.get('unconfirmed', 0):,} sats")
                click.echo(f"\nChannel Balance:")
                click.echo(f"  Local:        {balances.get('channel_local', 0):,} sats")
                click.echo(f"  Remote:       {balances.get('channel_remote', 0):,} sats")
                
                total_balance = balances.get('total', 0) + balances.get('channel_local', 0)
                click.echo(f"\nTotal Available: {total_balance:,} sats")
                success_message("Balance information retrieved successfully")
            else:
                click.echo("❌ Could not retrieve balance information")
                
        except Exception as e:
            handle_cli_error(e, "balance command")
    
    @cli_app.command()
    @pass_cli_context
    def status(cli_context: CLIContext):
        """🔍 Quick system status check"""
        try:
            client = cli_context.client
            
            click.echo("\n🔍 System Status Check")
            click.echo("=" * 25)
            
            # Connection test
            click.echo("Testing connection...", nl=False)
            if cli_context.validate_connection():
                click.echo(" ✅")
            else:
                click.echo(" ❌")
                return
            
            # Get basic info
            info = client.get_info()
            if info:
                sync_status = "✅ Synced" if info.get('synced_to_chain') and info.get('synced_to_graph') else "⚠️  Syncing"
                click.echo(f"Node Status:     {sync_status}")
                click.echo(f"Channels:        {info.get('num_channels', 0)}")
                click.echo(f"Peers:           {info.get('num_peers', 0)}")
            
            success_message("System status check completed")
            
        except Exception as e:
            handle_cli_error(e, "status command")
    
    @cli_app.command(name='health-check')
    @pass_cli_context  
    @click.option('--quick', is_flag=True, help='Quick health check only')
    def health_check(cli_context: CLIContext, quick: bool):
        """🏥 Comprehensive health check"""
        try:
            client = cli_context.client
            
            click.echo("\n🏥 Health Check")
            click.echo("=" * 20)
            
            # Connection health
            click.echo("🔗 Connection Health:", nl=False)
            if cli_context.validate_connection():
                click.echo(" ✅ Connected")
            else:
                click.echo(" ❌ Connection Failed")
                return
            
            if not quick:
                # Node sync health
                info = client.get_info()
                if info:
                    chain_synced = info.get('synced_to_chain', False)
                    graph_synced = info.get('synced_to_graph', False)
                    
                    click.echo(f"⛓️  Chain Sync:     {'✅' if chain_synced else '❌'}")
                    click.echo(f"📊 Graph Sync:     {'✅' if graph_synced else '❌'}")
                    
                    # Channel health
                    channels = client.list_channels()
                    active_channels = [ch for ch in channels if ch.get('active')]
                    click.echo(f"🔀 Channels:       {len(active_channels)}/{len(channels)} active")
            
            success_message("Health check completed")
            
        except Exception as e:
            handle_cli_error(e, "health check")


def create_main_cli():
    """Create the main CLI application"""
    setup_error_handling()
    
    # Create base CLI
    cli_app = create_optimized_cli()
    
    # Add core commands
    add_core_commands(cli_app)
    
    # Add command groups from factory
    try:
        full_cli = create_cli_application()
        
        # Merge commands from full CLI
        for name, command in full_cli.commands.items():
            if name not in cli_app.commands:
                cli_app.add_command(command)
        
        # Add command aliases
        add_command_aliases(cli_app)
        
    except ImportError as e:
        # If command modules are not available, continue with core commands only
        info_message(f"Some command modules unavailable: {e}")
    except Exception as e:
        # Log error but continue with available commands
        error_handler = get_error_handler()
        error_handler.handle_error(e, suppress=True)
    
    return cli_app


# Create CLI application
cli = create_main_cli()


def main():
    """Main entry point"""
    try:
        cli()
    except Exception as e:
        handle_cli_error(e, "application")
        sys.exit(1)


if __name__ == '__main__':
    main()


__all__ = [
    'cli',
    'main',
    'create_main_cli'
]