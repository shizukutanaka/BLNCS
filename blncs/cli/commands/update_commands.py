"""
Auto-Update CLI Commands
Manage automatic updates and system maintenance.
"""

import click
from datetime import datetime
from typing import Dict, Any

from ...core.auto_updater import get_auto_updater
from ...core.exceptions import format_error_for_cli
from ...core.config_manager import get_config_manager


@click.command()
@click.option('--force', is_flag=True, help='Force check even if recently checked')
def update_check(force: bool) -> None:
    """Check for available updates"""
    try:
        updater = get_auto_updater()
        
        click.echo("Checking for updates...")
        
        update_info = updater.check_for_updates(force=force)
        
        if update_info:
            click.echo(f"\nUpdate Available!")
            click.echo("=" * 30)
            click.echo(f"Current Version: {update_info.current_version}")
            click.echo(f"Latest Version: {update_info.latest_version}")
            click.echo(f"Download Size: {update_info.size_mb:.1f} MB")
            
            if update_info.is_critical:
                click.echo("Priority: CRITICAL - Immediate update recommended")
            else:
                click.echo("Priority: Normal")
            
            if update_info.changelog:
                click.echo(f"\nChangelog:")
                click.echo(f"  {update_info.changelog}")
            
            click.echo(f"\nTo install this update, run:")
            click.echo(f"  blncs update-install")
            
        else:
            current_version = updater.current_version
            click.echo(f"No updates available.")
            click.echo(f"Current version {current_version} is up to date.")
            
    except Exception as e:
        click.echo(f"Error checking for updates: {format_error_for_cli(e)}", err=True)


@click.command()
@click.option('--auto-backup/--no-backup', default=True, help='Create backup before updating')
@click.option('--confirm', is_flag=True, help='Skip confirmation prompts')
def update_install(auto_backup: bool, confirm: bool) -> None:
    """Install available updates"""
    try:
        updater = get_auto_updater()
        
        # Check for updates first
        update_info = updater.check_for_updates()
        
        if not update_info:
            click.echo("No updates available.")
            return
        
        # Show update information
        click.echo("Update Information:")
        click.echo("=" * 30)
        click.echo(f"Current Version: {update_info.current_version}")
        click.echo(f"New Version: {update_info.latest_version}")
        click.echo(f"Download Size: {update_info.size_mb:.1f} MB")
        
        if update_info.changelog:
            click.echo(f"Changes: {update_info.changelog}")
        
        # Confirm update
        if not confirm:
            if not click.confirm('\nProceed with update?'):
                click.echo("Update cancelled.")
                return
        
        # Create backup if requested
        backup_path = None
        if auto_backup:
            click.echo("\nCreating backup...")
            backup_path = updater.backup_current_installation()
            if backup_path:
                click.echo(f"Backup created: {backup_path}")
            else:
                click.echo("Warning: Backup creation failed!")
                if not confirm and not click.confirm('Continue without backup?'):
                    click.echo("Update cancelled.")
                    return
        
        # Download update
        click.echo("Downloading update...")
        update_path = updater.download_update(update_info)
        
        if not update_path:
            click.echo("Download failed!", err=True)
            return
        
        click.echo("Download completed.")
        
        # Apply update
        click.echo("Installing update...")
        result = updater.apply_update(update_path, backup_path)
        
        if result.success:
            click.echo("Update installed successfully!")
            click.echo(f"New version: {result.version}")
            
            if result.requires_restart:
                click.echo("\nImportant: Restart BLNCS to complete the update.")
                click.echo("Run: systemctl restart blncs  # or restart manually")
            
            # Cleanup old backups
            updater.cleanup_old_backups()
            
        else:
            click.echo(f"Update installation failed: {result.error}", err=True)
            
            if backup_path:
                click.echo(f"\nBackup available at: {backup_path}")
                if click.confirm('Restore from backup?'):
                    if updater.rollback_update(backup_path):
                        click.echo("Restored from backup successfully.")
                    else:
                        click.echo("Backup restoration failed!", err=True)
            
    except Exception as e:
        click.echo(f"Error during update: {format_error_for_cli(e)}", err=True)


@click.command()
@click.option('--enable/--disable', default=None, help='Enable or disable auto-updates')
@click.option('--interval', type=int, help='Check interval in hours')
def update_config(enable: bool, interval: int) -> None:
    """Configure automatic update settings"""
    try:
        config_manager = get_config_manager()
        updater = get_auto_updater()
        
        changes_made = False
        
        # Enable/disable auto-updates
        if enable is not None:
            config_manager.set('system.auto_update_enabled', enable)
            status = "enabled" if enable else "disabled"
            click.echo(f"Automatic updates {status}")
            changes_made = True
        
        # Set check interval
        if interval:
            config_manager.set('system.update_check_interval', interval * 3600)  # Convert to seconds
            click.echo(f"Update check interval set to {interval} hours")
            changes_made = True
        
        if not changes_made:
            # Show current settings
            auto_enabled = config_manager.get('system.auto_update_enabled', False)
            check_interval = config_manager.get('system.update_check_interval', 3600) // 3600
            
            click.echo("Current Update Configuration:")
            click.echo("=" * 35)
            click.echo(f"Automatic Updates: {'Enabled' if auto_enabled else 'Disabled'}")
            click.echo(f"Check Interval: {check_interval} hours")
            
            system_info = updater.get_system_info()
            click.echo(f"Current Version: {system_info['current_version']}")
            
            if system_info['last_check_time'] > 0:
                last_check = datetime.fromtimestamp(system_info['last_check_time'])
                click.echo(f"Last Check: {last_check.strftime('%Y-%m-%d %H:%M:%S')}")
            else:
                click.echo("Last Check: Never")
            
            click.echo(f"\nTo enable auto-updates: blncs update-config --enable")
            click.echo(f"To disable auto-updates: blncs update-config --disable")
            
    except Exception as e:
        click.echo(f"Error configuring updates: {format_error_for_cli(e)}", err=True)


@click.command()
@click.option('--limit', default=10, help='Number of entries to show')
def update_history(limit: int) -> None:
    """Show update history"""
    try:
        updater = get_auto_updater()
        
        history = updater.get_update_history(limit=limit)
        
        if not history:
            click.echo("No update history found.")
            return
        
        click.echo(f"Update History (last {len(history)} entries):")
        click.echo("=" * 50)
        
        for entry in history:
            timestamp = datetime.fromtimestamp(entry['timestamp'])
            status = "SUCCESS" if entry['success'] else "FAILED"
            update_type = entry['type'].replace('auto_', '').title()
            
            click.echo(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} - {update_type}")
            click.echo(f"  Version: {entry['version']}")
            click.echo(f"  Status: {status}")
            click.echo(f"  Details: {entry['message']}")
            click.echo()
            
    except Exception as e:
        click.echo(f"Error retrieving update history: {format_error_for_cli(e)}", err=True)


@click.command()
def update_status() -> None:
    """Show current update status and system information"""
    try:
        updater = get_auto_updater()
        config_manager = get_config_manager()
        
        click.echo("Update System Status:")
        click.echo("=" * 30)
        
        system_info = updater.get_system_info()
        
        click.echo(f"Current Version: {system_info['current_version']}")
        click.echo(f"Auto-Update: {'Enabled' if system_info['auto_update_enabled'] else 'Disabled'}")
        
        if system_info['last_check_time'] > 0:
            last_check = datetime.fromtimestamp(system_info['last_check_time'])
            click.echo(f"Last Check: {last_check.strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            click.echo("Last Check: Never")
        
        # Check for updates
        update_info = updater.check_for_updates()
        if update_info:
            click.echo(f"Update Available: Yes ({update_info.latest_version})")
            if update_info.is_critical:
                click.echo("Priority: CRITICAL")
        else:
            click.echo("Update Available: No")
        
        click.echo(f"Install Directory: {system_info['install_directory']}")
        
        # Show backup information
        if updater.backup_dir.exists():
            backups = [d for d in updater.backup_dir.iterdir() if d.is_dir()]
            click.echo(f"Available Backups: {len(backups)}")
        
        click.echo()
        
        # Show available commands
        click.echo("Available Commands:")
        click.echo("  blncs update-check     - Check for updates")
        click.echo("  blncs update-install   - Install available updates")
        click.echo("  blncs update-config    - Configure auto-update settings")
        click.echo("  blncs update-history   - View update history")
        
    except Exception as e:
        click.echo(f"Error getting update status: {format_error_for_cli(e)}", err=True)


@click.command()
@click.option('--keep', default=5, help='Number of backups to keep')
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
def update_cleanup(keep: int, confirm: bool) -> None:
    """Clean up old update backups"""
    try:
        updater = get_auto_updater()
        
        if not updater.backup_dir.exists():
            click.echo("No backup directory found.")
            return
        
        backups = [d for d in updater.backup_dir.iterdir() if d.is_dir()]
        
        if len(backups) <= keep:
            click.echo(f"Only {len(backups)} backups found, no cleanup needed.")
            return
        
        to_remove = len(backups) - keep
        
        if not confirm:
            click.echo(f"This will remove {to_remove} old backup(s), keeping {keep} most recent.")
            if not click.confirm('Continue?'):
                click.echo("Cleanup cancelled.")
                return
        
        updater.cleanup_old_backups(keep_count=keep)
        click.echo(f"Cleanup completed. Removed {to_remove} old backup(s).")
        
    except Exception as e:
        click.echo(f"Error during cleanup: {format_error_for_cli(e)}", err=True)