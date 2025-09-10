"""
CLI group factory for BLNCS
Creates organized Click command groups with proper structure and help text.
"""

import click
from typing import Dict, Any, List, Optional
from ...core.async_cli_wrapper import AsyncClickGroup
from .command_registry import get_command_registry
from .cli_context import create_cli_context


class CLIGroupFactory:
    """Factory for creating organized CLI command groups"""
    
    def __init__(self):
        self.registry = get_command_registry()
    
    def create_main_group(self) -> click.Group:
        """Create main CLI group with all subcommands"""
        
        @click.group(cls=AsyncClickGroup)
        @click.option('--config', '-c', type=click.Path(exists=True), help='Configuration file path')
        @click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
        @click.option('--quiet', '-q', is_flag=True, help='Quiet mode (errors only)')
        @click.pass_context
        def cli(ctx: click.Context, config: str, verbose: bool, quiet: bool) -> None:
            """
            BLNCS - Bitcoin Lightning Network Control System

            Lightweight and practical Lightning Network management tool

            Common commands:
                blncs info          # Node information
                blncs balance       # Balance check
                blncs channels      # Channel list
                blncs health-check  # Quick system diagnosis

            First time setup:
                blncs config-set lightning.host localhost
                blncs config-set lightning.port 8080
            """
            ctx.ensure_object(dict)
            
            # Create CLI context
            cli_context = create_cli_context(config, verbose, quiet)
            ctx.obj['cli_context'] = cli_context
            
            # Legacy compatibility
            ctx.obj['config'] = cli_context.config
            ctx.obj['verbose'] = verbose
            ctx.obj['quiet'] = quiet
            ctx.obj['get_client'] = lambda: cli_context.client
        
        return cli
    
    def create_info_group(self) -> click.Group:
        """Create information commands group"""
        
        @click.group()
        def info():
            """Information and status commands"""
            pass
        
        # Add commands from registry
        commands = self.registry.get_commands_by_group('info')
        for command in commands:
            if command:
                info.add_command(command)
        
        return info
    
    def create_channel_group(self) -> click.Group:
        """Create channel management group"""
        
        @click.group()
        def channels():
            """Channel management and analysis commands"""
            pass
        
        commands = self.registry.get_commands_by_group('channels')
        for command in commands:
            if command:
                channels.add_command(command)
        
        return channels
    
    def create_config_group(self) -> click.Group:
        """Create configuration group"""
        
        @click.group()
        def config():
            """Configuration management commands"""
            pass
        
        commands = self.registry.get_commands_by_group('config')
        for command in commands:
            if command:
                config.add_command(command)
        
        return config
    
    def create_finance_group(self) -> click.Group:
        """Create financial analysis group"""
        
        @click.group()
        def finance():
            """Financial analysis and fee management commands"""
            pass
        
        commands = self.registry.get_commands_by_group('finance')
        for command in commands:
            if command:
                finance.add_command(command)
        
        return finance
    
    def create_system_group(self) -> click.Group:
        """Create system management group"""
        
        @click.group()
        def system():
            """System management and maintenance commands"""
            pass
        
        commands = self.registry.get_commands_by_group('system')
        for command in commands:
            if command:
                system.add_command(command)
        
        return system
    
    def create_automation_group(self) -> click.Group:
        """Create automation group"""
        
        @click.group()
        def automation():
            """Automation and scheduling commands"""
            pass
        
        # Add fee automation subgroup
        fee_auto = click.Group(name='fees')
        fee_commands = self.registry.get_commands_by_group('fee_automation')
        for command in fee_commands:
            if command:
                fee_auto.add_command(command)
        automation.add_command(fee_auto)
        
        # Add rebalancer subgroup
        rebalancer = click.Group(name='rebalancer')
        rebalancer_commands = self.registry.get_commands_by_group('rebalancer')
        for command in rebalancer_commands:
            if command:
                rebalancer.add_command(command)
        automation.add_command(rebalancer)
        
        return automation
    
    def create_security_group(self) -> click.Group:
        """Create security group"""
        
        @click.group()
        def security():
            """Security monitoring and hardening commands"""
            pass
        
        commands = self.registry.get_commands_by_group('security')
        for command in commands:
            if command:
                security.add_command(command)
        
        return security
    
    def create_tools_group(self) -> click.Group:
        """Create tools group"""
        
        @click.group()
        def tools():
            """Utility tools and helpers"""
            pass
        
        # QR code tools
        qr_tools = click.Group(name='qr')
        qr_commands = self.registry.get_commands_by_group('qr')
        for command in qr_commands:
            if command:
                qr_tools.add_command(command)
        tools.add_command(qr_tools)
        
        # Node discovery tools
        discovery = click.Group(name='discovery')
        discovery_commands = self.registry.get_commands_by_group('discovery')
        for command in discovery_commands:
            if command:
                discovery.add_command(command)
        tools.add_command(discovery)
        
        # Connection tools
        connection = click.Group(name='connection')
        connection_commands = self.registry.get_commands_by_group('connection')
        for command in connection_commands:
            if command:
                connection.add_command(command)
        tools.add_command(connection)
        
        return tools
    
    def create_maintenance_group(self) -> click.Group:
        """Create maintenance group"""
        
        @click.group()
        def maintenance():
            """Database and system maintenance commands"""
            pass
        
        # Database maintenance
        database = click.Group(name='database')
        db_commands = self.registry.get_commands_by_group('database')
        for command in db_commands:
            if command:
                database.add_command(command)
        maintenance.add_command(database)
        
        # Backup management
        backup = click.Group(name='backup')
        backup_commands = self.registry.get_commands_by_group('backup')
        for command in backup_commands:
            if command:
                backup.add_command(command)
        maintenance.add_command(backup)
        
        # Update management
        update = click.Group(name='update')
        update_commands = self.registry.get_commands_by_group('update')
        for command in update_commands:
            if command:
                update.add_command(command)
        maintenance.add_command(update)
        
        return maintenance
    
    def create_monitoring_group(self) -> click.Group:
        """Create monitoring group"""
        
        @click.group()
        def monitoring():
            """System monitoring and alerting commands"""
            pass
        
        commands = self.registry.get_commands_by_group('monitoring')
        for command in commands:
            if command:
                monitoring.add_command(command)
        
        return monitoring
    
    def build_complete_cli(self) -> click.Group:
        """Build complete CLI with all groups and commands"""
        main_cli = self.create_main_group()
        
        # Add individual commands to main group
        info_commands = self.registry.get_commands_by_group('info')
        for command in info_commands:
            if command and hasattr(command, 'name'):
                main_cli.add_command(command)
        
        # Add grouped commands
        main_cli.add_command(self.create_channel_group())
        main_cli.add_command(self.create_config_group())
        main_cli.add_command(self.create_finance_group())
        main_cli.add_command(self.create_system_group())
        main_cli.add_command(self.create_automation_group())
        main_cli.add_command(self.create_security_group())
        main_cli.add_command(self.create_tools_group())
        main_cli.add_command(self.create_maintenance_group())
        main_cli.add_command(self.create_monitoring_group())
        
        return main_cli


def create_cli_application() -> click.Group:
    """Create complete CLI application"""
    factory = CLIGroupFactory()
    return factory.build_complete_cli()


# Command aliases for common operations
def add_command_aliases(cli_group: click.Group):
    """Add common command aliases"""
    aliases = {
        'st': 'info',           # Status
        'bal': 'balance',       # Balance
        'ch': 'channels',       # Channels
        'cfg': 'config',        # Config
        'hc': 'health-check',   # Health check
        'dash': 'dashboard',    # Dashboard
    }
    
    for alias, original in aliases.items():
        original_command = cli_group.commands.get(original)
        if original_command:
            # Create alias command
            alias_command = click.Command(
                alias,
                callback=original_command.callback,
                params=original_command.params,
                help=f"Alias for '{original}'"
            )
            cli_group.add_command(alias_command)


__all__ = [
    'CLIGroupFactory',
    'create_cli_application',
    'add_command_aliases'
]