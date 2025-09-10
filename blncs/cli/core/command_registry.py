"""
Command registry for BLNCS CLI
Manages and organizes CLI commands in logical groups.
"""

import click
from typing import Dict, Any, List, Callable
from importlib import import_module
import logging

from ...core.logger import get_logger
from ...core.error_handler import get_error_handler


class CommandRegistry:
    """Registry for managing CLI commands"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.error_handler = get_error_handler()
        self.commands: Dict[str, Any] = {}
        self.command_groups: Dict[str, List[str]] = {}
    
    def register_command_group(self, group_name: str, module_path: str, command_names: List[str]):
        """Register a group of commands from a module"""
        try:
            module = import_module(module_path)
            
            for command_name in command_names:
                if hasattr(module, command_name):
                    command = getattr(module, command_name)
                    self.commands[command_name] = command
                    
                    # Add to group
                    if group_name not in self.command_groups:
                        self.command_groups[group_name] = []
                    self.command_groups[group_name].append(command_name)
                else:
                    self.logger.warning(f"Command '{command_name}' not found in module '{module_path}'")
                    
        except ImportError as e:
            self.logger.error(f"Failed to import module '{module_path}': {e}")
        except Exception as e:
            self.error_handler.handle_error(e, suppress=True)
    
    def get_command(self, name: str) -> Any:
        """Get command by name"""
        return self.commands.get(name)
    
    def get_commands_by_group(self, group_name: str) -> List[Any]:
        """Get all commands in a group"""
        command_names = self.command_groups.get(group_name, [])
        return [self.commands[name] for name in command_names if name in self.commands]
    
    def list_commands(self) -> Dict[str, List[str]]:
        """List all commands organized by group"""
        return self.command_groups.copy()
    
    def add_commands_to_group(self, cli_group: click.Group, group_name: str):
        """Add all commands from a group to a Click group"""
        commands = self.get_commands_by_group(group_name)
        for command in commands:
            if isinstance(command, click.Command):
                cli_group.add_command(command)


def create_command_registry() -> CommandRegistry:
    """Create and populate command registry"""
    registry = CommandRegistry()
    
    # Core information commands
    registry.register_command_group(
        'info',
        'blncs.cli.commands',
        ['info', 'balance', 'system_info', 'network_test', 'lightning_ping']
    )
    
    # Channel management commands
    registry.register_command_group(
        'channels',
        'blncs.cli.commands',
        ['channels', 'analyze_channels', 'channel_summary', 'connectivity_check']
    )
    
    # Configuration commands
    registry.register_command_group(
        'config',
        'blncs.cli.commands',
        ['config_management', 'config_get', 'config_set', 'config_list', 'env_template']
    )
    
    # Financial analysis commands
    registry.register_command_group(
        'finance',
        'blncs.cli.commands',
        ['liquidity', 'earnings', 'top_channels', 'fee_analysis', 'fee_estimate', 'payment_debug']
    )
    
    # System management commands
    registry.register_command_group(
        'system',
        'blncs.cli.commands',
        ['health_check', 'backup_data', 'dashboard', 'system_overview']
    )
    
    # Database commands
    registry.register_command_group(
        'database',
        'blncs.cli.commands',
        ['db_status', 'db_optimize', 'db_cleanup', 'db_maintenance', 'db_vacuum']
    )
    
    # Fee automation commands
    registry.register_command_group(
        'fee_automation',
        'blncs.cli.commands',
        [
            'fee_automation_status', 'fee_automation_start', 'fee_automation_stop',
            'fee_automation_history', 'fee_automation_test'
        ]
    )
    
    # Rebalancer commands
    registry.register_command_group(
        'rebalancer',
        'blncs.cli.commands',
        [
            'rebalancer_status', 'rebalancer_start', 'rebalancer_stop',
            'rebalancer_history', 'rebalancer_analyze', 'rebalancer_add_target',
            'rebalancer_remove_target', 'rebalance_suggestions'
        ]
    )
    
    # Monitoring commands
    registry.register_command_group(
        'monitoring',
        'blncs.cli.commands',
        [
            'monitoring_status', 'monitoring_start', 'monitoring_stop',
            'monitoring_alerts', 'monitoring_history', 'monitoring_ack',
            'monitoring_resolve', 'monitoring_metrics'
        ]
    )
    
    # Security commands
    registry.register_command_group(
        'security',
        'blncs.cli.commands',
        [
            'security_status', 'security_start', 'security_stop',
            'security_findings', 'security_resolve', 'security_false_positive',
            'security_scan', 'security_harden'
        ]
    )
    
    # Connection commands
    registry.register_command_group(
        'connection',
        'blncs.cli.commands',
        [
            'quick_connect', 'connection_scan', 'connection_reconnect',
            'connection_setup', 'connection_history', 'connection_status'
        ]
    )
    
    # QR code commands
    registry.register_command_group(
        'qr',
        'blncs.cli.commands',
        ['qr_create', 'qr_generate', 'qr_read', 'qr_scan', 'qr_list', 'qr_cleanup']
    )
    
    # Node discovery commands
    registry.register_command_group(
        'discovery',
        'blncs.cli.commands',
        ['node_discover', 'node_recommend', 'node_cached', 'node_scan_local', 'node_info']
    )
    
    # Update commands
    registry.register_command_group(
        'update',
        'blncs.cli.commands',
        [
            'update_check', 'update_install', 'update_config',
            'update_history', 'update_status', 'update_cleanup'
        ]
    )
    
    # Backup commands
    registry.register_command_group(
        'backup',
        'blncs.cli.commands',
        [
            'backup_create', 'backup_list', 'backup_restore',
            'backup_verify', 'backup_status', 'backup_auto',
            'backup_encrypt', 'backup_cleanup'
        ]
    )
    
    return registry


# Global registry instance
_command_registry: CommandRegistry = None


def get_command_registry() -> CommandRegistry:
    """Get global command registry instance"""
    global _command_registry
    if _command_registry is None:
        _command_registry = create_command_registry()
    return _command_registry


def get_command(name: str) -> Any:
    """Convenience function to get command by name"""
    registry = get_command_registry()
    return registry.get_command(name)


def list_available_commands() -> Dict[str, List[str]]:
    """List all available commands by group"""
    registry = get_command_registry()
    return registry.list_commands()


__all__ = [
    'CommandRegistry',
    'create_command_registry',
    'get_command_registry',
    'get_command',
    'list_available_commands'
]