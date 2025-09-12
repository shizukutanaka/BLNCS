#!/usr/bin/env python3
"""
BLNCS Migration CLI Commands
Command-line interface for migration operations and upgrade management.
"""

import click
import json
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
import logging
import sys
import os

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))

from blncs.migration import VersionManager, ConfigMigrator, DataMigrator, BackupMigrator
from blncs.core.config_manager import ConfigManager
from blncs.utils.setup_helper import print_status, print_error, print_success, print_warning

logger = logging.getLogger(__name__)

@click.group(name='migration')
@click.pass_context
def migration_commands(ctx):
    """Migration and upgrade management commands"""
    pass

@migration_commands.command()
@click.option('--check-only', is_flag=True, help='Only check for upgrades, do not perform')
@click.option('--force', is_flag=True, help='Force migration even if not required')
@click.option('--backup-first', is_flag=True, default=True, help='Create backup before migration')
@click.pass_context
def upgrade(ctx, check_only, force, backup_first):
    """Check for and perform system upgrades"""
    print_status("Checking system version and upgrade requirements...")
    
    try:
        version_manager = VersionManager()
        config_migrator = ConfigMigrator()
        data_migrator = DataMigrator()
        backup_migrator = BackupMigrator()
        
        # Check if upgrade is needed
        upgrade_needed, current_version, upgrade_path = version_manager.check_upgrade_needed()
        
        if not upgrade_needed and not force:
            if current_version:
                print_success(f"System is up to date (version {current_version})")
            else:
                print_success("No version detected - performing fresh installation")
            return
        
        if check_only:
            if upgrade_needed:
                print_status(f"Upgrade available: {current_version} -> {version_manager.current_version}")
                print_status(f"Upgrade path: {' -> '.join(upgrade_path)}")
                
                # Show breaking changes
                breaking_changes = version_manager.get_breaking_changes(
                    current_version, version_manager.current_version
                )
                
                if breaking_changes:
                    print_warning("Breaking changes detected:")
                    for change in breaking_changes:
                        print(f"  • {change['description']}")
                        print(f"    Action: {change['action_required']}")
                        
            else:
                print_success("No upgrade needed")
            return
        
        # Validate upgrade requirements
        requirements = version_manager.validate_upgrade_requirements()
        
        if not all(requirements.values()):
            print_error("Upgrade requirements not met:")
            for requirement, passed in requirements.items():
                if not passed:
                    print_error(f"  ❌ {requirement}")
            return
        
        # Show upgrade plan
        print_status(f"Upgrading from {current_version} to {version_manager.current_version}")
        print_status(f"Upgrade steps: {len(upgrade_path)}")
        
        if not click.confirm("Proceed with upgrade?"):
            print_status("Upgrade cancelled")
            return
        
        # Create backup if requested
        if backup_first:
            print_status("Creating configuration backup...")
            backup_result = _create_migration_backup()
            if not backup_result['success']:
                print_error("Failed to create backup - aborting upgrade")
                return
        
        # Perform migration steps
        migration_results = []
        
        for step in upgrade_path:
            print_status(f"Executing migration step: {step}")
            
            if "1_0_to_1_1" in step:
                # Config migration
                result = config_migrator.migrate_1_0_to_1_1()
                migration_results.append(("Config 1.0->1.1", result))
                
                # Data migration
                result = data_migrator.migrate_backup_metadata_1_0_to_1_1()
                migration_results.append(("Data 1.0->1.1", result))
                
            elif "1_1_to_1_2" in step:
                # Config migration
                result = config_migrator.migrate_1_1_to_1_2()
                migration_results.append(("Config 1.1->1.2", result))
                
                # Data migration
                result = data_migrator.migrate_backup_metadata_1_1_to_1_2()
                migration_results.append(("Data 1.1->1.2", result))
                
                # Backup format migration
                result = backup_migrator.migrate_backup_format_1_1_to_1_2()
                migration_results.append(("Backups 1.1->1.2", result))
                
            elif "1_2_to_2_0" in step:
                # Config migration  
                result = config_migrator.migrate_1_2_to_2_0()
                migration_results.append(("Config 1.2->2.0", result))
                
                # Data migration
                result = data_migrator.migrate_backup_metadata_1_2_to_2_0()
                migration_results.append(("Data 1.2->2.0", result))
                
                # Backup format migration
                result = backup_migrator.migrate_backup_format_1_2_to_2_0()
                migration_results.append(("Backups 1.2->2.0", result))
        
        # Check migration results
        failed_migrations = [name for name, result in migration_results if not result.get('success', False)]
        
        if failed_migrations:
            print_error(f"Migration failed at: {', '.join(failed_migrations)}")
            print_status("Check migration logs for details")
            return
        
        # Save new version info
        version_manager.save_version_info(
            version_manager.current_version,
            {
                'timestamp': datetime.now().isoformat(),
                'type': 'upgrade',
                'previous_version': str(current_version) if current_version else None,
                'migration_applied': True
            }
        )
        
        # Show migration summary
        print_success(f"Successfully upgraded to version {version_manager.current_version}")
        _show_migration_summary(migration_results)
        
    except Exception as e:
        print_error(f"Upgrade failed: {str(e)}")
        logger.error(f"Upgrade error: {e}", exc_info=True)

@migration_commands.command()
@click.option('--backup-ids', help='Comma-separated backup IDs to migrate')
@click.option('--target-version', help='Target version for migration')
@click.option('--estimate-only', is_flag=True, help='Only estimate migration time')
@click.pass_context
def migrate_backups(ctx, backup_ids, target_version, estimate_only):
    """Migrate backup files between format versions"""
    print_status("Analyzing backup migration requirements...")
    
    try:
        backup_migrator = BackupMigrator()
        
        # Parse backup IDs
        backup_id_list = None
        if backup_ids:
            backup_id_list = [bid.strip() for bid in backup_ids.split(',')]
        
        # Find backup files to migrate
        backup_files = []
        if backup_id_list:
            for backup_id in backup_id_list:
                files = list(Path(os.path.expanduser("~/.blncs/backups")).glob(f"{backup_id}*"))
                backup_files.extend(files)
        else:
            backup_files = list(Path(os.path.expanduser("~/.blncs/backups")).glob("*.tar.*"))
        
        if not backup_files:
            print_warning("No backup files found to migrate")
            return
        
        print_status(f"Found {len(backup_files)} backup files")
        
        # Estimate migration time
        if estimate_only:
            estimation = backup_migrator.estimate_migration_time(backup_files)
            
            print_status("Migration time estimation:")
            print(f"  Total size: {estimation['total_size_mb']:.1f} MB")
            print(f"  File count: {estimation['file_count']}")
            print(f"  Estimated time: {estimation['estimated_minutes']:.1f} minutes")
            print(f"  Processing rate: {estimation['processing_rate_mbps']} MB/s")
            return
        
        # Determine target version
        if not target_version:
            version_manager = VersionManager()
            target_version = str(version_manager.current_version)
        
        print_status(f"Migrating backups to version {target_version}")
        
        if not click.confirm(f"Migrate {len(backup_files)} backup files?"):
            print_status("Migration cancelled")
            return
        
        # Perform migration based on target version
        migration_result = None
        
        if target_version.startswith("1.1"):
            migration_result = backup_migrator.migrate_backup_format_1_0_to_1_1(backup_id_list)
        elif target_version.startswith("1.2"):
            migration_result = backup_migrator.migrate_backup_format_1_1_to_1_2(backup_id_list)
        elif target_version.startswith("2.0"):
            migration_result = backup_migrator.migrate_backup_format_1_2_to_2_0(backup_id_list)
        else:
            print_error(f"Unsupported target version: {target_version}")
            return
        
        # Show results
        if migration_result['success']:
            print_success(f"Successfully migrated {len(migration_result['migrated_backups'])} backups")
            
            if migration_result.get('total_size_migrated'):
                size_mb = migration_result['total_size_migrated'] / (1024 * 1024)
                print_status(f"Total migrated size: {size_mb:.1f} MB")
            
            if migration_result.get('compression_improvement'):
                improvement = migration_result['compression_improvement'] * 100
                print_status(f"Average compression improvement: {improvement:.1f}%")
            
            if migration_result.get('deduplication_savings'):
                savings_mb = migration_result['deduplication_savings'] / (1024 * 1024)
                print_status(f"Deduplication savings: {savings_mb:.1f} MB")
        else:
            print_error("Backup migration failed")
            for error in migration_result.get('errors', []):
                print_error(f"  {error}")
        
    except Exception as e:
        print_error(f"Backup migration failed: {str(e)}")
        logger.error(f"Backup migration error: {e}", exc_info=True)

@migration_commands.command()
@click.option('--config-file', help='Specific configuration file to validate')
@click.option('--fix-issues', is_flag=True, help='Attempt to fix validation issues')
@click.pass_context
def validate_config(ctx, config_file, fix_issues):
    """Validate configuration file format and structure"""
    print_status("Validating configuration...")
    
    try:
        config_migrator = ConfigMigrator()
        
        if config_file:
            config_path = Path(config_file)
            if not config_path.exists():
                print_error(f"Configuration file not found: {config_file}")
                return
                
            validation = config_migrator.validate_configuration(config_path)
            _show_validation_results(config_path, validation, fix_issues)
        else:
            # Validate all configuration files
            config_dir = Path(os.path.expanduser("~/.blncs"))
            config_files = list(config_dir.glob("*.json"))
            
            if not config_files:
                print_warning("No configuration files found")
                return
            
            all_valid = True
            for config_path in config_files:
                validation = config_migrator.validate_configuration(config_path)
                _show_validation_results(config_path, validation, fix_issues)
                if not validation['valid']:
                    all_valid = False
            
            if all_valid:
                print_success("All configuration files are valid")
            else:
                print_warning("Some configuration files have validation issues")
        
    except Exception as e:
        print_error(f"Configuration validation failed: {str(e)}")
        logger.error(f"Config validation error: {e}", exc_info=True)

@migration_commands.command()
@click.option('--backup-id', help='Verify specific backup by ID')
@click.option('--repair', is_flag=True, help='Attempt to repair integrity issues')
@click.pass_context
def verify_integrity(ctx, backup_id, repair):
    """Verify data integrity of backups and metadata"""
    print_status("Verifying data integrity...")
    
    try:
        data_migrator = DataMigrator()
        
        result = data_migrator.verify_data_integrity(backup_id)
        
        if result['success']:
            print_success(f"Verified {result['verified_backups']} backups")
            
            if result['integrity_errors']:
                print_warning(f"Found {len(result['integrity_errors'])} integrity issues:")
                for error in result['integrity_errors']:
                    print_error(f"  {error}")
            
            if result['warnings']:
                print_warning("Warnings:")
                for warning in result['warnings']:
                    print_warning(f"  {warning}")
            
            if not result['integrity_errors'] and not result['warnings']:
                print_success("No integrity issues found")
                
        else:
            print_error("Integrity verification failed")
            for error in result.get('integrity_errors', []):
                print_error(f"  {error}")
        
    except Exception as e:
        print_error(f"Integrity verification failed: {str(e)}")
        logger.error(f"Integrity verification error: {e}", exc_info=True)

@migration_commands.command()
@click.option('--older-than-days', default=30, help='Clean files older than N days')
@click.option('--dry-run', is_flag=True, help='Show what would be cleaned without doing it')
@click.pass_context
def cleanup(ctx, older_than_days, dry_run):
    """Clean up old migration files and temporary data"""
    print_status(f"Cleaning up files older than {older_than_days} days...")
    
    try:
        if dry_run:
            print_status("DRY RUN - no files will be deleted")
        
        data_migrator = DataMigrator()
        
        if not dry_run:
            result = data_migrator.cleanup_old_data(older_than_days)
            
            if result['success']:
                print_success(f"Cleaned up {result['cleaned_files']} files")
                size_mb = result['freed_bytes'] / (1024 * 1024)
                print_status(f"Freed {size_mb:.1f} MB of disk space")
            else:
                print_error("Cleanup failed")
                for error in result.get('errors', []):
                    print_error(f"  {error}")
        else:
            # Show what would be cleaned
            migration_log_dir = Path(os.path.expanduser("~/.blncs/data/migration_logs"))
            if migration_log_dir.exists():
                old_files = []
                cutoff_timestamp = datetime.now().timestamp() - (older_than_days * 24 * 3600)
                
                for file_path in migration_log_dir.glob("*"):
                    if file_path.stat().st_mtime < cutoff_timestamp:
                        old_files.append(file_path)
                
                if old_files:
                    print_status(f"Would clean {len(old_files)} files:")
                    for file_path in old_files:
                        size = file_path.stat().st_size / 1024
                        print(f"  {file_path.name} ({size:.1f} KB)")
                else:
                    print_status("No old files found to clean")
        
    except Exception as e:
        print_error(f"Cleanup failed: {str(e)}")
        logger.error(f"Cleanup error: {e}", exc_info=True)

@migration_commands.command()
@click.pass_context
def status(ctx):
    """Show migration and version status"""
    print_status("System Migration Status")
    print("=" * 50)
    
    try:
        version_manager = VersionManager()
        
        # Current version
        current_version = version_manager.detect_installed_version()
        target_version = version_manager.current_version
        
        print(f"Current version: {current_version or 'Unknown'}")
        print(f"Target version:  {target_version}")
        
        # Check upgrade status
        upgrade_needed, _, upgrade_path = version_manager.check_upgrade_needed()
        
        if upgrade_needed:
            print_warning("⚠️  Upgrade available")
            if upgrade_path:
                print(f"Upgrade path: {' → '.join(upgrade_path)}")
        else:
            print_success("✅ System up to date")
        
        # Version file info
        if version_manager.version_file.exists():
            with open(version_manager.version_file, 'r') as f:
                version_info = json.load(f)
            
            print("\nVersion Information:")
            print(f"  Installed at: {version_info.get('installed_at', 'Unknown')}")
            print(f"  Installation type: {version_info.get('installation_type', 'Unknown')}")
            print(f"  Previous version: {version_info.get('previous_version', 'None')}")
            print(f"  Migration applied: {version_info.get('migration_applied', False)}")
        
        # Configuration status
        config_dir = Path(os.path.expanduser("~/.blncs"))
        config_files = list(config_dir.glob("*.json"))
        
        print(f"\nConfiguration files: {len(config_files)}")
        for config_file in config_files:
            print(f"  📄 {config_file.name}")
        
        # Backup status
        backup_dir = Path(os.path.expanduser("~/.blncs/backups"))
        if backup_dir.exists():
            backup_files = list(backup_dir.glob("*.tar.*"))
            print(f"\nBackup files: {len(backup_files)}")
            
            # Group by version
            version_counts = {}
            for backup_file in backup_files:
                if "_v2.0." in backup_file.name:
                    version_counts["2.0"] = version_counts.get("2.0", 0) + 1
                elif "_v1.2." in backup_file.name:
                    version_counts["1.2"] = version_counts.get("1.2", 0) + 1
                elif "_v1.1." in backup_file.name:
                    version_counts["1.1"] = version_counts.get("1.1", 0) + 1
                else:
                    version_counts["1.0"] = version_counts.get("1.0", 0) + 1
            
            for version, count in sorted(version_counts.items()):
                print(f"  v{version}: {count} backups")
        
    except Exception as e:
        print_error(f"Status check failed: {str(e)}")
        logger.error(f"Status error: {e}", exc_info=True)

def _create_migration_backup() -> Dict[str, Any]:
    """Create backup of configuration before migration"""
    try:
        config_dir = Path(os.path.expanduser("~/.blncs"))
        backup_dir = config_dir / "migration_backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_subdir = backup_dir / f"pre_migration_{timestamp}"
        backup_subdir.mkdir()
        
        # Copy all configuration files
        copied_files = 0
        for config_file in config_dir.glob("*.json"):
            if config_file.is_file():
                import shutil
                shutil.copy2(config_file, backup_subdir)
                copied_files += 1
        
        return {
            "success": True,
            "backup_dir": str(backup_subdir),
            "files_copied": copied_files
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

def _show_migration_summary(migration_results):
    """Show summary of migration results"""
    print("\nMigration Summary:")
    print("-" * 30)
    
    for name, result in migration_results:
        status = "✅" if result.get('success', False) else "❌"
        print(f"{status} {name}")
        
        if result.get('migrated_backups'):
            print(f"    Migrated items: {result['migrated_backups']}")
        
        if result.get('changes'):
            print(f"    Changes: {len(result['changes'])}")
        
        if result.get('errors'):
            print(f"    Errors: {len(result['errors'])}")
        
        if result.get('warnings'):
            print(f"    Warnings: {len(result['warnings'])}")

def _show_validation_results(config_path: Path, validation: Dict, fix_issues: bool):
    """Show configuration validation results"""
    status_icon = "✅" if validation['valid'] else "❌"
    print(f"{status_icon} {config_path.name} (version: {validation.get('version', 'unknown')})")
    
    if validation['errors']:
        print("  Errors:")
        for error in validation['errors']:
            print(f"    ❌ {error}")
    
    if validation['warnings']:
        print("  Warnings:")
        for warning in validation['warnings']:
            print(f"    ⚠️  {warning}")
    
    if not validation['valid'] and fix_issues:
        print("  🔧 Attempting to fix issues...")
        # In a real implementation, would attempt fixes
        print("  ℹ️  Manual review required for complex issues")

if __name__ == '__main__':
    migration_commands()