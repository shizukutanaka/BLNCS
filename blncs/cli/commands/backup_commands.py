"""
Enhanced Backup CLI Commands
Comprehensive backup system with encryption support.
"""

import click
import getpass
from datetime import datetime
from typing import Dict, Any

from ...core.backup_enhanced import get_enhanced_backup, BackupType
from ...core.exceptions import format_error_for_cli


@click.command('backup-create')
@click.option('--type', 'backup_type', default='incremental', 
              type=click.Choice(['full', 'incremental', 'differential']),
              help='Type of backup to create')
@click.option('--encrypt', is_flag=True, help='Create encrypted backup')
@click.option('--password', help='Encryption password (will prompt if not provided)')
def backup_create(backup_type: str, encrypt: bool, password: str) -> None:
    """Create a new backup"""
    try:
        backup_manager = get_enhanced_backup()
        
        # Handle encryption setup
        if encrypt:
            if not password:
                password = getpass.getpass("Enter encryption password: ")
                confirm_password = getpass.getpass("Confirm encryption password: ")
                if password != confirm_password:
                    click.echo("Passwords do not match!", err=True)
                    return
            
            # Set encryption key
            if not backup_manager.set_encryption_key(password):
                click.echo("Failed to set encryption key", err=True)
                return
            
            # Enable encryption for this backup
            backup_manager.encryption_enabled = True
        
        click.echo(f"Creating {backup_type} backup...")
        
        backup_info = backup_manager.create_backup(
            backup_type=BackupType(backup_type),
            auto=False
        )
        
        click.echo(f"Backup created successfully!")
        click.echo(f"Backup ID: {backup_info.backup_id}")
        click.echo(f"Files: {backup_info.file_count}")
        click.echo(f"Size: {backup_info.size_bytes:,} bytes")
        click.echo(f"Encrypted: {'Yes' if backup_info.encrypted else 'No'}")
        click.echo(f"Compressed: {'Yes' if backup_info.compressed else 'No'}")
        
    except Exception as e:
        click.echo(format_error_for_cli(e))


@click.command('backup-list')
@click.option('--limit', default=10, help='Number of backups to show')
def backup_list(limit: int) -> None:
    """List available backups"""
    try:
        backup_manager = get_enhanced_backup()
        
        if not backup_manager.backup_history:
            click.echo("No backups found")
            return
        
        click.echo("Available Backups:")
        click.echo("=" * 80)
        click.echo(f"{'ID':<25} {'Type':<12} {'Date':<20} {'Size':<10} {'Files':<6} {'Enc':<3} {'Comp':<4}")
        click.echo("-" * 80)
        
        for backup in backup_manager.backup_history[-limit:]:
            size_mb = backup.size_bytes / (1024 * 1024)
            encrypted = "Yes" if backup.encrypted else "No"
            compressed = "Yes" if backup.compressed else "No"
            
            click.echo(f"{backup.backup_id:<25} {backup.backup_type.value:<12} "
                      f"{backup.timestamp.strftime('%Y-%m-%d %H:%M:%S'):<20} "
                      f"{size_mb:<10.1f} {backup.file_count:<6} {encrypted:<3} {compressed:<4}")
        
    except Exception as e:
        click.echo(format_error_for_cli(e))


@click.command('backup-restore')
@click.argument('backup_id')
@click.option('--restore-path', default='.', help='Path to restore files to')
@click.option('--password', help='Decryption password (will prompt if needed)')
def backup_restore(backup_id: str, restore_path: str, password: str) -> None:
    """Restore from a backup"""
    try:
        backup_manager = get_enhanced_backup()
        
        # Find backup info
        backup_info = next((b for b in backup_manager.backup_history if b.backup_id.startswith(backup_id)), None)
        if not backup_info:
            click.echo(f"Backup not found: {backup_id}")
            return
        
        # Handle encrypted backups
        if backup_info.encrypted:
            if not password:
                password = getpass.getpass("Enter decryption password: ")
            
            if not backup_manager.load_encryption_key(password):
                click.echo("Failed to load encryption key", err=True)
                return
        
        click.echo(f"Restoring backup {backup_info.backup_id}...")
        click.echo(f"Restore path: {restore_path}")
        
        success = backup_manager.restore_backup(backup_info.backup_id, restore_path)
        
        if success:
            click.echo("Backup restored successfully!")
        else:
            click.echo("Backup restoration failed", err=True)
        
    except Exception as e:
        click.echo(format_error_for_cli(e))


@click.command('backup-verify')
@click.argument('backup_id')
def backup_verify(backup_id: str) -> None:
    """Verify backup integrity"""
    try:
        backup_manager = get_enhanced_backup()
        
        # Find backup info
        backup_info = next((b for b in backup_manager.backup_history if b.backup_id.startswith(backup_id)), None)
        if not backup_info:
            click.echo(f"Backup not found: {backup_id}")
            return
        
        click.echo(f"Verifying backup {backup_info.backup_id}...")
        
        if backup_manager.verify_backup(backup_info.backup_id):
            click.echo("Backup verification successful")
        else:
            click.echo("Backup verification failed", err=True)
        
    except Exception as e:
        click.echo(format_error_for_cli(e))


@click.command('backup-status')
def backup_status() -> None:
    """Show backup system status"""
    try:
        backup_manager = get_enhanced_backup()
        status = backup_manager.get_backup_status()
        
        click.echo("Backup System Status")
        click.echo("=" * 30)
        click.echo(f"Enabled: {'Yes' if status['enabled'] else 'No'}")
        click.echo(f"Directory: {status['backup_directory']}")
        click.echo(f"Total Backups: {status['total_backups']}")
        
        if status['last_backup']:
            last_backup = datetime.fromisoformat(status['last_backup'])
            click.echo(f"Last Backup: {last_backup.strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            click.echo("Last Backup: Never")
        
        if status['last_full_backup']:
            last_full = datetime.fromisoformat(status['last_full_backup'])
            click.echo(f"Last Full Backup: {last_full.strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            click.echo("Last Full Backup: Never")
        
        click.echo(f"Auto Backup: {'Active' if status['auto_backup_active'] else 'Inactive'}")
        click.echo(f"Compression: {'Enabled' if status['compression_enabled'] else 'Disabled'}")
        click.echo(f"Encryption: {'Enabled' if status['encryption_enabled'] else 'Disabled'}")
        
        if status['encryption_enabled']:
            click.echo(f"Encryption Available: {'Yes' if status['encryption_available'] else 'No'}")
            click.echo(f"Encryption Key Set: {'Yes' if status['encryption_key_set'] else 'No'}")
            click.echo(f"Encryption Method: {status['encryption_method'] or 'None'}")
        
        if status['next_backup_due']:
            click.echo(f"Next Backup: {status['next_backup_due']}")
        
    except Exception as e:
        click.echo(format_error_for_cli(e))


@click.command('backup-auto')
@click.option('--start', is_flag=True, help='Start automatic backups')
@click.option('--stop', is_flag=True, help='Stop automatic backups')
@click.option('--status', is_flag=True, help='Show auto-backup status')
def backup_auto(start: bool, stop: bool, status: bool) -> None:
    """Control automatic backup system"""
    try:
        backup_manager = get_enhanced_backup()
        
        if start:
            backup_manager.start_auto_backup()
            click.echo("Automatic backup started")
        elif stop:
            backup_manager.stop_auto_backup()
            click.echo("Automatic backup stopped")
        elif status:
            backup_status = backup_manager.get_backup_status()
            is_active = backup_status['auto_backup_active']
            click.echo(f"Automatic backup: {'Active' if is_active else 'Inactive'}")
            if backup_status['next_backup_due']:
                click.echo(f"Next backup due: {backup_status['next_backup_due']}")
        else:
            click.echo("Use --start, --stop, or --status")
        
    except Exception as e:
        click.echo(format_error_for_cli(e))


@click.command('backup-encrypt')
@click.option('--enable', is_flag=True, help='Enable backup encryption')
@click.option('--disable', is_flag=True, help='Disable backup encryption')
@click.option('--set-password', is_flag=True, help='Set encryption password')
@click.option('--password', help='Encryption password (will prompt if not provided)')
def backup_encrypt(enable: bool, disable: bool, set_password: bool, password: str) -> None:
    """Manage backup encryption settings"""
    try:
        backup_manager = get_enhanced_backup()
        
        if not backup_manager.encryption_available:
            click.echo("Encryption not available - cryptography library not installed", err=True)
            return
        
        if enable:
            backup_manager.encryption_enabled = True
            click.echo("Backup encryption enabled")
            click.echo("Use 'blncs backup-encrypt --set-password' to set encryption key")
        elif disable:
            backup_manager.encryption_enabled = False
            click.echo("Backup encryption disabled")
        elif set_password:
            if not password:
                password = getpass.getpass("Enter new encryption password: ")
                confirm_password = getpass.getpass("Confirm encryption password: ")
                if password != confirm_password:
                    click.echo("Passwords do not match!", err=True)
                    return
            
            if backup_manager.set_encryption_key(password):
                click.echo("Encryption password set successfully")
            else:
                click.echo("Failed to set encryption password", err=True)
        else:
            # Show current encryption status
            status = backup_manager.get_backup_status()
            click.echo("Encryption Status")
            click.echo("=" * 20)
            click.echo(f"Available: {'Yes' if status['encryption_available'] else 'No'}")
            click.echo(f"Enabled: {'Yes' if status['encryption_enabled'] else 'No'}")
            click.echo(f"Key Set: {'Yes' if status['encryption_key_set'] else 'No'}")
            click.echo(f"Method: {status['encryption_method'] or 'None'}")
        
    except Exception as e:
        click.echo(format_error_for_cli(e))


@click.command('backup-cleanup')
@click.option('--keep', default=10, help='Number of backups to keep')
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
def backup_cleanup(keep: int, confirm: bool) -> None:
    """Clean up old backups"""
    try:
        backup_manager = get_enhanced_backup()
        
        if len(backup_manager.backup_history) <= keep:
            click.echo(f"Only {len(backup_manager.backup_history)} backups found, no cleanup needed")
            return
        
        to_remove = len(backup_manager.backup_history) - keep
        
        if not confirm:
            click.echo(f"This will remove {to_remove} old backup(s), keeping {keep} most recent.")
            if not click.confirm('Continue?'):
                click.echo("Cleanup cancelled")
                return
        
        # Perform cleanup manually by updating max_backups temporarily
        original_max = backup_manager.max_backups
        backup_manager.max_backups = keep
        backup_manager._cleanup_old_backups()
        backup_manager.max_backups = original_max
        
        click.echo(f"Cleanup completed. Removed {to_remove} old backup(s)")
        
    except Exception as e:
        click.echo(format_error_for_cli(e))


# Export all commands
__all__ = [
    'backup_create',
    'backup_list', 
    'backup_restore',
    'backup_verify',
    'backup_status',
    'backup_auto',
    'backup_encrypt',
    'backup_cleanup'
]