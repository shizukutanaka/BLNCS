#!/usr/bin/env python3
"""
BLNCS Backup CLI Commands
Command-line interface for comprehensive backup and recovery operations.
"""

import click
import json
import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any

from blncs.backup import (
    get_backup_manager, get_recovery_engine, get_backup_scheduler,
    BackupManager, RecoveryEngine, BackupScheduler
)
from blncs.backup.backup_validator import BackupValidator, ValidationLevel
from blncs.backup.storage_backend import get_storage_manager, StorageManager, StorageType, StorageConfig

@click.group()
def backup():
    """Backup and recovery management commands"""
    pass

@backup.group()
def create():
    """Create backup operations"""
    pass

@create.command()
@click.option('--name', '-n', help='Backup name')
@click.option('--type', '-t', 'backup_type', 
              type=click.Choice(['full', 'incremental', 'differential']), 
              default='incremental', help='Backup type')
@click.option('--items', '-i', multiple=True, help='Backup items to include (can be used multiple times)')
@click.option('--all-items', is_flag=True, help='Include all configured backup items')
@click.option('--encrypt/--no-encrypt', default=True, help='Enable/disable encryption')
@click.option('--compress/--no-compress', default=True, help='Enable/disable compression')
def backup_now(name: Optional[str], backup_type: str, items: tuple, all_items: bool, 
               encrypt: bool, compress: bool):
    """Create a backup immediately"""
    try:
        backup_manager = get_backup_manager()
        
        # Get backup items
        if all_items:
            backup_items = backup_manager.list_backup_items()
        elif items:
            all_items_list = backup_manager.list_backup_items()
            item_names = {item['name']: item for item in all_items_list}
            backup_items = []
            for item_name in items:
                if item_name in item_names:
                    backup_items.append(item_names[item_name])
                else:
                    click.echo(f"❌ Backup item not found: {item_name}", err=True)
                    return
        else:
            click.echo("❌ No backup items specified. Use --items or --all-items", err=True)
            return
        
        if not backup_items:
            click.echo("❌ No backup items available", err=True)
            return
        
        click.echo(f"🔄 Creating {backup_type} backup...")
        click.echo(f"   Items: {', '.join(item['name'] for item in backup_items)}")
        click.echo(f"   Encryption: {'Enabled' if encrypt else 'Disabled'}")
        click.echo(f"   Compression: {'Enabled' if compress else 'Disabled'}")
        
        # Override encryption/compression if specified
        for item in backup_items:
            if 'encryption' not in item:
                item['encryption'] = encrypt
            if 'compression' not in item:
                item['compression'] = compress
        
        # Create backup
        result = backup_manager.create_backup(
            backup_items=backup_items,
            backup_type=backup_type,
            backup_name=name
        )
        
        if result.success:
            click.echo("✅ Backup completed successfully!")
            click.echo(f"   Backup ID: {result.backup_id}")
            click.echo(f"   Files backed up: {result.files_backed_up}")
            click.echo(f"   Total size: {result.total_size / (1024*1024):.1f} MB")
            click.echo(f"   Duration: {result.backup_time:.1f} seconds")
            
            if result.warnings:
                click.echo("⚠️  Warnings:")
                for warning in result.warnings:
                    click.echo(f"   - {warning}")
        else:
            click.echo("❌ Backup failed!")
            click.echo(f"   Files failed: {result.files_failed}")
            if result.errors:
                click.echo("   Errors:")
                for error in result.errors:
                    click.echo(f"   - {error}")
                    
    except Exception as e:
        click.echo(f"❌ Error creating backup: {e}", err=True)

@backup.group()
def list():
    """List backup-related information"""
    pass

@list.command('backups')
@click.option('--limit', '-l', default=20, help='Maximum number of backups to show')
@click.option('--status', type=click.Choice(['all', 'completed', 'failed', 'in_progress']), 
              default='all', help='Filter by status')
def list_backups(limit: int, status: str):
    """List available backups"""
    try:
        backup_manager = get_backup_manager()
        backups = backup_manager.list_backups(limit=limit)
        
        if status != 'all':
            backups = [b for b in backups if b['status'] == status]
        
        if not backups:
            click.echo("No backups found")
            return
        
        click.echo("📦 Available Backups:")
        click.echo("-" * 80)
        
        for backup in backups:
            status_emoji = {
                'completed': '✅',
                'failed': '❌', 
                'in_progress': '🔄'
            }.get(backup['status'], '❓')
            
            click.echo(f"{status_emoji} {backup['backup_name'] or backup['backup_id'][:8]}")
            click.echo(f"   ID: {backup['backup_id']}")
            click.echo(f"   Type: {backup['backup_type'].title()}")
            click.echo(f"   Time: {backup['backup_time']}")
            click.echo(f"   Size: {backup['total_size'] / (1024*1024):.1f} MB")
            click.echo(f"   Files: {backup['file_count']}")
            click.echo(f"   Status: {backup['status'].title()}")
            click.echo()
            
    except Exception as e:
        click.echo(f"❌ Error listing backups: {e}", err=True)

@list.command('items')
def list_items():
    """List configured backup items"""
    try:
        backup_manager = get_backup_manager()
        items = backup_manager.list_backup_items()
        
        if not items:
            click.echo("No backup items configured")
            return
        
        click.echo("📁 Backup Items:")
        click.echo("-" * 60)
        
        for item in items:
            status_emoji = '✅' if item.get('enabled', True) else '⏸️'
            click.echo(f"{status_emoji} {item['name']}")
            click.echo(f"   Path: {item['source_path']}")
            click.echo(f"   Type: {item['backup_type']}")
            click.echo(f"   Priority: {item['priority']}")
            click.echo(f"   Encryption: {'Yes' if item.get('encryption', True) else 'No'}")
            click.echo(f"   Compression: {'Yes' if item.get('compression', True) else 'No'}")
            click.echo()
            
    except Exception as e:
        click.echo(f"❌ Error listing backup items: {e}", err=True)

@backup.group()
def recover():
    """Recovery operations"""
    pass

@recover.command('backup')
@click.argument('backup_id')
@click.option('--target', '-t', help='Target directory for recovery')
@click.option('--items', '-i', multiple=True, help='Specific items to recover')
@click.option('--overwrite', is_flag=True, help='Overwrite existing files')
def recover_backup(backup_id: str, target: Optional[str], items: tuple, overwrite: bool):
    """Recover files from a backup"""
    try:
        recovery_engine = get_recovery_engine()
        
        # List available backups to validate ID
        available_backups = recovery_engine.list_available_backups()
        backup_found = any(b['backup_id'] == backup_id for b in available_backups)
        
        if not backup_found:
            click.echo(f"❌ Backup not found: {backup_id}", err=True)
            return
        
        # Get backup contents
        click.echo(f"🔍 Analyzing backup {backup_id}...")
        contents = recovery_engine.get_backup_contents(backup_id)
        
        if not contents:
            click.echo("❌ Could not read backup contents", err=True)
            return
        
        click.echo(f"   Found {len(contents)} files/directories")
        
        # Prepare recovery items
        recovery_items = []
        if items:
            # Recover specific items
            for item_path in items:
                found = False
                for content_item in contents:
                    if content_item['path'] == item_path:
                        from blncs.backup.recovery_engine import RecoveryItem
                        recovery_items.append(RecoveryItem(
                            backup_id=backup_id,
                            original_path=item_path,
                            target_path=str(Path(target or '.') / item_path),
                            overwrite_existing=overwrite
                        ))
                        found = True
                        break
                if not found:
                    click.echo(f"⚠️  Item not found in backup: {item_path}")
        else:
            # Recover all items
            from blncs.backup.recovery_engine import RecoveryItem
            for content_item in contents:
                recovery_items.append(RecoveryItem(
                    backup_id=backup_id,
                    original_path=content_item['path'],
                    target_path=str(Path(target or '.') / content_item['path']),
                    overwrite_existing=overwrite
                ))
        
        if not recovery_items:
            click.echo("❌ No items to recover", err=True)
            return
        
        click.echo(f"🔄 Recovering {len(recovery_items)} items...")
        
        # Execute recovery
        result = recovery_engine.execute_recovery(
            backup_id=backup_id,
            recovery_items=recovery_items,
            target_directory=target
        )
        
        if result.success:
            click.echo("✅ Recovery completed successfully!")
            click.echo(f"   Items recovered: {result.items_recovered}")
            click.echo(f"   Total size: {result.total_size / (1024*1024):.1f} MB")
            click.echo(f"   Duration: {result.recovery_time:.1f} seconds")
            
            if result.warnings:
                click.echo("⚠️  Warnings:")
                for warning in result.warnings:
                    click.echo(f"   - {warning}")
        else:
            click.echo("❌ Recovery failed!")
            click.echo(f"   Items failed: {result.items_failed}")
            if result.errors:
                click.echo("   Errors:")
                for error in result.errors:
                    click.echo(f"   - {error}")
                    
    except Exception as e:
        click.echo(f"❌ Error during recovery: {e}", err=True)

@recover.command('list')
@click.argument('backup_id')
def list_backup_contents(backup_id: str):
    """List contents of a backup"""
    try:
        recovery_engine = get_recovery_engine()
        contents = recovery_engine.get_backup_contents(backup_id)
        
        if not contents:
            click.echo(f"❌ Could not read backup contents for {backup_id}", err=True)
            return
        
        click.echo(f"📁 Backup Contents ({backup_id}):")
        click.echo("-" * 80)
        
        total_size = 0
        for item in contents:
            click.echo(f"   {item['path']}")
            click.echo(f"      Size: {item['size'] / 1024:.1f} KB")
            click.echo(f"      Modified: {item['modified']}")
            total_size += item['size']
        
        click.echo("-" * 80)
        click.echo(f"Total: {len(contents)} items, {total_size / (1024*1024):.1f} MB")
        
    except Exception as e:
        click.echo(f"❌ Error listing backup contents: {e}", err=True)

@backup.group()
def schedule():
    """Backup scheduling operations"""
    pass

@schedule.command('create')
@click.option('--name', '-n', required=True, help='Schedule name')
@click.option('--items', '-i', multiple=True, required=True, help='Backup items to include')
@click.option('--type', 'schedule_type', required=True,
              type=click.Choice(['hourly', 'daily', 'weekly', 'monthly']),
              help='Schedule frequency')
@click.option('--hour', type=int, help='Hour (0-23) for daily/weekly/monthly schedules')
@click.option('--minute', type=int, default=0, help='Minute (0-59)')
@click.option('--day-of-week', type=int, help='Day of week (0-6, Monday=0) for weekly')
@click.option('--day', type=int, help='Day of month (1-31) for monthly')
@click.option('--backup-type', default='incremental', 
              type=click.Choice(['full', 'incremental', 'differential']),
              help='Type of backup to create')
@click.option('--retention', default=30, help='Retention period in days')
def create_schedule(name: str, items: tuple, schedule_type: str, hour: Optional[int], 
                   minute: int, day_of_week: Optional[int], day: Optional[int],
                   backup_type: str, retention: int):
    """Create a backup schedule"""
    try:
        scheduler = get_backup_scheduler()
        
        # Validate backup items
        backup_manager = get_backup_manager()
        all_items = backup_manager.list_backup_items()
        item_names = {item['name'] for item in all_items}
        
        invalid_items = set(items) - item_names
        if invalid_items:
            click.echo(f"❌ Invalid backup items: {', '.join(invalid_items)}", err=True)
            return
        
        # Build schedule configuration
        schedule_config = {'minute': minute}
        
        if schedule_type in ['daily', 'weekly', 'monthly']:
            if hour is None:
                click.echo("❌ --hour is required for daily/weekly/monthly schedules", err=True)
                return
            schedule_config['hour'] = hour
        
        if schedule_type == 'weekly':
            if day_of_week is None:
                click.echo("❌ --day-of-week is required for weekly schedules", err=True)
                return
            schedule_config['day_of_week'] = day_of_week
        
        if schedule_type == 'monthly':
            if day is None:
                click.echo("❌ --day is required for monthly schedules", err=True)
                return
            schedule_config['day'] = day
        
        from blncs.backup.backup_scheduler import ScheduleType
        
        # Create schedule
        schedule_id = scheduler.create_schedule(
            name=name,
            backup_items=list(items),
            schedule_type=ScheduleType(schedule_type),
            schedule_config=schedule_config,
            backup_type=backup_type,
            retention_days=retention
        )
        
        click.echo("✅ Schedule created successfully!")
        click.echo(f"   Schedule ID: {schedule_id}")
        click.echo(f"   Name: {name}")
        click.echo(f"   Type: {schedule_type}")
        click.echo(f"   Items: {', '.join(items)}")
        click.echo(f"   Backup Type: {backup_type}")
        click.echo(f"   Retention: {retention} days")
        
    except Exception as e:
        click.echo(f"❌ Error creating schedule: {e}", err=True)

@schedule.command('list')
def list_schedules():
    """List backup schedules"""
    try:
        scheduler = get_backup_scheduler()
        schedules = scheduler.list_schedules()
        
        if not schedules:
            click.echo("No backup schedules configured")
            return
        
        click.echo("📅 Backup Schedules:")
        click.echo("-" * 80)
        
        for schedule in schedules:
            status_emoji = {
                'active': '✅',
                'paused': '⏸️',
                'disabled': '❌',
                'error': '🚨'
            }.get(schedule['status'], '❓')
            
            click.echo(f"{status_emoji} {schedule['name']}")
            click.echo(f"   ID: {schedule['schedule_id']}")
            click.echo(f"   Type: {schedule['schedule_type'].title()}")
            click.echo(f"   Items: {', '.join(schedule['backup_items'])}")
            click.echo(f"   Next run: {schedule['next_run'] or 'Not scheduled'}")
            click.echo(f"   Success rate: {schedule['success_rate']}")
            click.echo(f"   Runs: {schedule['run_count']} (✅{schedule['success_count']} ❌{schedule['failure_count']})")
            click.echo()
            
    except Exception as e:
        click.echo(f"❌ Error listing schedules: {e}", err=True)

@schedule.command('start')
def start_scheduler():
    """Start the backup scheduler"""
    try:
        scheduler = get_backup_scheduler()
        scheduler.start_scheduler()
        click.echo("✅ Backup scheduler started")
        
    except Exception as e:
        click.echo(f"❌ Error starting scheduler: {e}", err=True)

@schedule.command('stop')
def stop_scheduler():
    """Stop the backup scheduler"""
    try:
        scheduler = get_backup_scheduler()
        scheduler.stop_scheduler()
        click.echo("✅ Backup scheduler stopped")
        
    except Exception as e:
        click.echo(f"❌ Error stopping scheduler: {e}", err=True)

@backup.group()
def validate():
    """Backup validation operations"""
    pass

@validate.command('backup')
@click.argument('backup_id')
@click.option('--level', '-l', 
              type=click.Choice(['basic', 'standard', 'thorough', 'deep']),
              default='standard', help='Validation level')
def validate_backup_cmd(backup_id: str, level: str):
    """Validate a backup"""
    try:
        validator = BackupValidator()
        
        level_map = {
            'basic': ValidationLevel.BASIC,
            'standard': ValidationLevel.STANDARD,
            'thorough': ValidationLevel.THOROUGH,
            'deep': ValidationLevel.DEEP
        }
        
        validation_level = level_map[level]
        
        click.echo(f"🔍 Validating backup {backup_id} ({level} level)...")
        
        result = validator.validate_backup(backup_id, validation_level)
        
        status_emoji = {
            'valid': '✅',
            'warning': '⚠️',
            'invalid': '❌',
            'error': '🚨',
            'corrupted': '☠️'
        }.get(result.overall_status.value, '❓')
        
        click.echo(f"{status_emoji} Validation result: {result.overall_status.value.upper()}")
        click.echo(f"   Files: {result.valid_files} valid, {result.invalid_files} invalid")
        click.echo(f"   Total size: {result.total_size / (1024*1024):.1f} MB")
        click.echo(f"   Duration: {result.validation_duration:.1f} seconds")
        
        if result.metadata_valid:
            click.echo("   ✅ Metadata valid")
        else:
            click.echo("   ❌ Metadata invalid")
        
        if result.checksum_valid:
            click.echo("   ✅ Checksum valid")
        else:
            click.echo("   ❌ Checksum invalid")
        
        if result.structure_valid:
            click.echo("   ✅ Structure valid")
        else:
            click.echo("   ❌ Structure invalid")
        
        if result.restoration_test_passed is not None:
            if result.restoration_test_passed:
                click.echo("   ✅ Restoration test passed")
            else:
                click.echo("   ❌ Restoration test failed")
        
        if result.issues:
            click.echo("\n🔍 Issues found:")
            for issue in result.issues:
                severity_emoji = {
                    'valid': '✅',
                    'warning': '⚠️',
                    'invalid': '❌',
                    'error': '🚨',
                    'corrupted': '☠️'
                }.get(issue.severity.value, '❓')
                
                click.echo(f"   {severity_emoji} [{issue.category}] {issue.description}")
                if issue.file_path:
                    click.echo(f"      File: {issue.file_path}")
                if issue.recommendation:
                    click.echo(f"      Recommendation: {issue.recommendation}")
        
    except Exception as e:
        click.echo(f"❌ Error validating backup: {e}", err=True)

@backup.group()
def storage():
    """Storage backend operations"""
    pass

@storage.command('list')
def list_storage_backends():
    """List storage backends"""
    try:
        storage_manager = get_storage_manager()
        backends = storage_manager.list_backends()
        
        if not backends:
            click.echo("No storage backends configured")
            return
        
        click.echo("💾 Storage Backends:")
        click.echo("-" * 60)
        
        for backend in backends:
            status_emoji = {
                'available': '✅',
                'unavailable': '❌',
                'error': '🚨',
                'testing': '🔍'
            }.get(backend['status'], '❓')
            
            click.echo(f"{status_emoji} {backend['name']} ({backend['storage_type'].upper()})")
            click.echo(f"   Priority: {backend['priority']}")
            click.echo(f"   Status: {backend['status'].title()}")
            
            stats = backend['statistics']
            click.echo(f"   Operations: ⬆️{stats['uploads']} ⬇️{stats['downloads']} ❌{stats['errors']}")
            click.echo(f"   Data: {stats['total_uploaded']/(1024*1024):.1f}MB up, {stats['total_downloaded']/(1024*1024):.1f}MB down")
            click.echo()
            
    except Exception as e:
        click.echo(f"❌ Error listing storage backends: {e}", err=True)

@storage.command('add')
@click.option('--name', '-n', required=True, help='Backend name')
@click.option('--type', '-t', 'storage_type', required=True,
              type=click.Choice(['local', 's3', 'sftp']),
              help='Storage backend type')
@click.option('--config', '-c', help='Configuration JSON string or file path')
def add_storage_backend(name: str, storage_type: str, config: str):
    """Add a storage backend"""
    try:
        storage_manager = get_storage_manager()
        
        # Parse configuration
        if config:
            if Path(config).exists():
                with open(config, 'r') as f:
                    config_dict = json.load(f)
            else:
                config_dict = json.loads(config)
        else:
            # Interactive configuration
            config_dict = {}
            
            if storage_type == 'local':
                config_dict['path'] = click.prompt("Storage path", 
                    default=str(Path.home() / '.blncs' / 'backups'))
                    
            elif storage_type == 's3':
                config_dict['bucket'] = click.prompt("S3 bucket name")
                config_dict['access_key_id'] = click.prompt("Access key ID")
                config_dict['secret_access_key'] = click.prompt("Secret access key", hide_input=True)
                config_dict['region'] = click.prompt("AWS region", default='us-east-1')
                
            elif storage_type == 'sftp':
                config_dict['host'] = click.prompt("SFTP host")
                config_dict['username'] = click.prompt("Username")
                config_dict['password'] = click.prompt("Password (leave blank for key auth)", 
                    default="", hide_input=True)
                if not config_dict['password']:
                    config_dict['key_file'] = click.prompt("Private key file path")
                config_dict['remote_path'] = click.prompt("Remote path", default='/backups')
        
        # Create storage configuration
        from blncs.backup.storage_backend import StorageConfig, StorageType
        backend_id = f"{storage_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        storage_config = StorageConfig(
            backend_id=backend_id,
            name=name,
            storage_type=StorageType(storage_type),
            config=config_dict
        )
        
        # Register backend
        if storage_manager.register_backend(storage_config):
            click.echo("✅ Storage backend added successfully!")
            click.echo(f"   Name: {name}")
            click.echo(f"   Type: {storage_type.upper()}")
            click.echo(f"   ID: {backend_id}")
        else:
            click.echo("❌ Failed to add storage backend", err=True)
            
    except Exception as e:
        click.echo(f"❌ Error adding storage backend: {e}", err=True)

@backup.command('status')
def backup_status():
    """Show backup system status"""
    try:
        # Backup Manager
        backup_manager = get_backup_manager()
        backup_stats = backup_manager.get_statistics()
        
        # Scheduler
        scheduler = get_backup_scheduler()
        scheduler_stats = scheduler.get_statistics()
        
        # Storage
        storage_manager = get_storage_manager()
        storage_stats = storage_manager.get_statistics()
        
        click.echo("📊 BLNCS Backup System Status")
        click.echo("=" * 50)
        
        click.echo("\n💾 Backup Manager:")
        click.echo(f"   Total backups: {backup_stats['total_backups']}")
        click.echo(f"   Successful: {backup_stats['successful_backups']}")
        click.echo(f"   Failed: {backup_stats['failed_backups']}")
        click.echo(f"   Success rate: {backup_stats['success_rate']}")
        click.echo(f"   Total data: {backup_stats['total_data_backed_up_gb']}")
        
        click.echo("\n📅 Scheduler:")
        click.echo(f"   Status: {'🟢 Running' if scheduler_stats['scheduler_running'] else '🔴 Stopped'}")
        click.echo(f"   Total schedules: {scheduler_stats['total_schedules']}")
        click.echo(f"   Active schedules: {scheduler_stats['active_schedules']}")
        click.echo(f"   Executions: {scheduler_stats['total_executions']}")
        click.echo(f"   Success rate: {scheduler_stats['success_rate']}")
        
        click.echo("\n💾 Storage:")
        click.echo(f"   Total backends: {storage_stats['total_backends']}")
        click.echo(f"   Enabled: {storage_stats['enabled_backends']}")
        click.echo(f"   Uploads: {storage_stats['total_uploads']}")
        click.echo(f"   Downloads: {storage_stats['total_downloads']}")
        click.echo(f"   Data uploaded: {storage_stats['total_uploaded_bytes']/(1024*1024*1024):.1f} GB")
        click.echo(f"   Data downloaded: {storage_stats['total_downloaded_bytes']/(1024*1024*1024):.1f} GB")
        
    except Exception as e:
        click.echo(f"❌ Error getting system status: {e}", err=True)

@backup.command('history')
@click.option('--limit', '-l', default=10, help='Number of recent operations to show')
def backup_history(limit: int):
    """Show recent backup and recovery history"""
    try:
        backup_manager = get_backup_manager()
        recovery_engine = get_recovery_engine()
        
        # Get recent backups
        recent_backups = backup_manager.list_backups(limit=limit//2)
        
        # Get recent recoveries  
        recent_recoveries = recovery_engine.get_recovery_history(limit=limit//2)
        
        click.echo("📜 Recent Backup Operations")
        click.echo("=" * 50)
        
        if recent_backups:
            click.echo("\n💾 Recent Backups:")
            for backup in recent_backups:
                status_emoji = {
                    'completed': '✅',
                    'failed': '❌',
                    'in_progress': '🔄'
                }.get(backup['status'], '❓')
                
                click.echo(f"   {status_emoji} {backup['backup_time']} - {backup.get('backup_name', backup['backup_id'][:8])}")
                click.echo(f"      Size: {backup['total_size']/(1024*1024):.1f} MB, Files: {backup['file_count']}")
        
        if recent_recoveries:
            click.echo("\n🔄 Recent Recoveries:")
            for recovery in recent_recoveries:
                status_emoji = '✅' if recovery['success'] else '❌'
                click.echo(f"   {status_emoji} {recovery['recovery_time']} - {recovery['backup_id'][:8]}")
                click.echo(f"      Recovered: {recovery['items_recovered']} items, {recovery['recovery_rate']}")
        
        if not recent_backups and not recent_recoveries:
            click.echo("No recent operations found")
            
    except Exception as e:
        click.echo(f"❌ Error getting backup history: {e}", err=True)

# Legacy commands for backwards compatibility
@click.command()
@click.option('--output', '-o', help='Output backup file path')
@click.option('--compress/--no-compress', default=True, help='Compress backup')
@click.option('--include-logs/--no-logs', default=False, help='Include log files')
@click.option('--include-cache/--no-cache', default=False, help='Include cache data')
@click.pass_context
def create_backup(ctx: click.Context, output: Optional[str], compress: bool, 
                 include_logs: bool, include_cache: bool) -> None:
    """Legacy: Create a simple backup of BLNCS data"""
    click.echo("⚠️  This is a legacy backup command. Use 'blncs backup create now' for full backup system.")
    # Implementation kept for backwards compatibility but simplified

@click.command()
@click.option('--backup-file', '-f', required=True, type=click.Path(exists=True), help='Backup file to restore')
@click.option('--restore-config/--no-config', default=True, help='Restore configuration')
@click.option('--restore-files/--no-files', default=True, help='Restore data files')
@click.option('--force/--no-force', default=False, help='Force restore (overwrite existing)')
@click.pass_context
def restore_backup(ctx: click.Context, backup_file: str, restore_config: bool, 
                  restore_files: bool, force: bool) -> None:
    """Legacy: Restore BLNCS data from backup"""
    click.echo("⚠️  This is a legacy restore command. Use 'blncs backup recover backup' for full recovery system.")
    # Implementation kept for backwards compatibility but simplified

@click.command()
@click.option('--backup-dir', help='Directory to scan for backups')
@click.pass_context
def list_backups_legacy(ctx: click.Context, backup_dir: Optional[str]) -> None:
    """Legacy: List available backups"""
    click.echo("⚠️  This is a legacy list command. Use 'blncs backup list backups' for full backup system.")
    # Implementation kept for backwards compatibility but simplified

# Register commands with main CLI
def register_backup_commands(main_cli):
    """Register backup commands with main CLI"""
    main_cli.add_command(backup)