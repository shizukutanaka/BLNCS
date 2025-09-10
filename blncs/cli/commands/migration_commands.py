"""
Migration management commands for BLNCS CLI.
"""

import asyncio
import click
from pathlib import Path
from typing import Optional
from datetime import datetime

from ...core.database_migrations import (
    MigrationManager,
    MigrationStatus,
    MigrationType,
    create_migration_template
)
from ...core.config import get_database_url


@click.group()
def migrate():
    """Database migration management commands."""
    pass


@migrate.command()
@click.option('--database-url', '-d', help='Database URL (defaults to config)')
@click.option('--migration-path', '-p', default='migrations', help='Path to migration files')
def status(database_url: Optional[str], migration_path: str):
    """Show current migration status."""
    
    async def _status():
        db_url = database_url or get_database_url()
        manager = MigrationManager(db_url, Path(migration_path))
        
        try:
            await manager.initialize()
            status_info = await manager.get_status()
            
            click.echo("Migration Status:")
            click.echo(f"  Total migrations: {status_info['total_migrations']}")
            click.echo(f"  Completed: {status_info['completed_migrations']}")
            click.echo(f"  Pending: {status_info['pending_migrations']}")
            
            if status_info['last_completed']:
                click.echo(f"  Last completed: {status_info['last_completed']}")
            
            if status_info['next_pending']:
                click.echo(f"  Next pending: {status_info['next_pending']}")
            
            if status_info['pending_migrations'] > 0:
                click.echo(f"\n⚠️  {status_info['pending_migrations']} migration(s) need to be applied")
                click.echo("Run 'blncs migrate up' to apply pending migrations")
            else:
                click.echo("\n✅ Database is up to date")
                
        finally:
            await manager.close()
    
    asyncio.run(_status())


@migrate.command()
@click.option('--database-url', '-d', help='Database URL (defaults to config)')
@click.option('--migration-path', '-p', default='migrations', help='Path to migration files')
@click.option('--target', '-t', help='Target migration version (latest if not specified)')
@click.option('--dry-run', '--dry', is_flag=True, help='Show what would be executed without running')
def up(database_url: Optional[str], migration_path: str, target: Optional[str], dry_run: bool):
    """Apply pending migrations."""
    
    async def _migrate_up():
        db_url = database_url or get_database_url()
        manager = MigrationManager(db_url, Path(migration_path))
        
        try:
            await manager.initialize()
            
            if dry_run:
                click.echo("DRY RUN - The following migrations would be executed:")
            
            results = await manager.migrate(target_version=target, dry_run=dry_run)
            
            if not results:
                click.echo("No pending migrations to apply")
                return
            
            for result in results:
                status_emoji = {
                    MigrationStatus.COMPLETED: "✅",
                    MigrationStatus.FAILED: "❌",
                    MigrationStatus.RUNNING: "⏳"
                }.get(result.status, "❓")
                
                click.echo(f"{status_emoji} {result.version}")
                
                if result.error_message:
                    click.echo(f"   Error: {result.error_message}")
                elif result.rows_affected is not None:
                    click.echo(f"   Rows affected: {result.rows_affected}")
                
                if result.duration_seconds:
                    click.echo(f"   Duration: {result.duration_seconds:.2f}s")
            
            failed_count = sum(1 for r in results if r.status == MigrationStatus.FAILED)
            if failed_count > 0:
                click.echo(f"\n❌ {failed_count} migration(s) failed")
                exit(1)
            else:
                click.echo(f"\n✅ Successfully applied {len(results)} migration(s)")
                
        finally:
            await manager.close()
    
    asyncio.run(_migrate_up())


@migrate.command()
@click.option('--database-url', '-d', help='Database URL (defaults to config)')
@click.option('--migration-path', '-p', default='migrations', help='Path to migration files')
@click.argument('target_version')
def down(database_url: Optional[str], migration_path: str, target_version: str):
    """Rollback migrations to target version."""
    
    async def _migrate_down():
        db_url = database_url or get_database_url()
        manager = MigrationManager(db_url, Path(migration_path))
        
        try:
            await manager.initialize()
            
            click.confirm(
                f"⚠️  This will rollback migrations to version {target_version}. "
                f"This operation may result in data loss. Continue?",
                abort=True
            )
            
            results = await manager.rollback(target_version)
            
            if not results:
                click.echo("No migrations to rollback")
                return
            
            for result in results:
                status_emoji = {
                    MigrationStatus.ROLLED_BACK: "↩️",
                    MigrationStatus.FAILED: "❌",
                }.get(result.status, "❓")
                
                click.echo(f"{status_emoji} {result.version}")
                
                if result.error_message:
                    click.echo(f"   Error: {result.error_message}")
                elif result.rows_affected is not None:
                    click.echo(f"   Rows affected: {result.rows_affected}")
                
                if result.duration_seconds:
                    click.echo(f"   Duration: {result.duration_seconds:.2f}s")
            
            failed_count = sum(1 for r in results if r.status == MigrationStatus.FAILED)
            if failed_count > 0:
                click.echo(f"\n❌ {failed_count} rollback(s) failed")
                exit(1)
            else:
                click.echo(f"\n✅ Successfully rolled back {len(results)} migration(s)")
                
        finally:
            await manager.close()
    
    asyncio.run(_migrate_down())


@migrate.command()
@click.option('--database-url', '-d', help='Database URL (defaults to config)')
@click.option('--migration-path', '-p', default='migrations', help='Path to migration files')
@click.option('--limit', '-l', default=20, help='Maximum number of entries to show')
def history(database_url: Optional[str], migration_path: str, limit: int):
    """Show migration history."""
    
    async def _history():
        db_url = database_url or get_database_url()
        manager = MigrationManager(db_url, Path(migration_path))
        
        try:
            await manager.initialize()
            history_entries = await manager.history.get_migration_history(limit)
            
            if not history_entries:
                click.echo("No migration history found")
                return
            
            click.echo("Migration History:")
            click.echo("-" * 80)
            
            for entry in history_entries:
                status_emoji = {
                    'completed': '✅',
                    'failed': '❌',
                    'rolled_back': '↩️',
                    'running': '⏳'
                }.get(entry['status'], '❓')
                
                started_at = entry['started_at'].strftime('%Y-%m-%d %H:%M:%S')
                duration = f" ({entry['duration_seconds']:.1f}s)" if entry.get('duration_seconds') else ""
                
                click.echo(f"{status_emoji} {entry['version']} - {entry['name']}")
                click.echo(f"    {started_at}{duration}")
                
                if entry.get('error_message'):
                    click.echo(f"    Error: {entry['error_message']}")
                
                click.echo()
                
        finally:
            await manager.close()
    
    asyncio.run(_history())


@migrate.command()
@click.argument('name')
@click.option('--migration-path', '-p', default='migrations', help='Path to migration files')
@click.option('--type', '-t', 'migration_type', 
              type=click.Choice(['schema', 'data', 'index', 'constraint', 'function', 'trigger']),
              default='schema', help='Type of migration')
@click.option('--author', '-a', default='blncs', help='Author name')
def create(name: str, migration_path: str, migration_type: str, author: str):
    """Create a new migration template."""
    
    async def _create():
        # Generate version based on timestamp
        version = datetime.now().strftime('%Y%m%d%H%M%S')
        
        file_path = await create_migration_template(
            Path(migration_path),
            version,
            name,
            MigrationType(migration_type),
            author
        )
        
        click.echo(f"✅ Created new migration: {file_path}")
        click.echo(f"   Version: {version}")
        click.echo(f"   Name: {name}")
        click.echo(f"   Type: {migration_type}")
        click.echo("\nEdit the file to add your migration SQL, then run 'blncs migrate up' to apply.")
    
    asyncio.run(_create())


@migrate.command()
@click.option('--database-url', '-d', help='Database URL (defaults to config)')
@click.option('--migration-path', '-p', default='migrations', help='Path to migration files')
@click.argument('version')
def validate(database_url: Optional[str], migration_path: str, version: str):
    """Validate a migration without executing it."""
    
    async def _validate():
        db_url = database_url or get_database_url()
        manager = MigrationManager(db_url, Path(migration_path))
        
        try:
            await manager.initialize()
            migrations = await manager.discover_migrations()
            
            if version not in migrations:
                click.echo(f"❌ Migration {version} not found")
                exit(1)
            
            migration = migrations[version]
            
            click.echo(f"Migration {version} validation:")
            click.echo(f"  Name: {migration.metadata.name}")
            click.echo(f"  Type: {migration.metadata.migration_type.value}")
            click.echo(f"  Author: {migration.metadata.author}")
            click.echo(f"  Rollback supported: {migration.metadata.rollback_supported}")
            click.echo(f"  Dependencies: {', '.join(migration.metadata.dependencies) or 'None'}")
            click.echo(f"  Checksum: {migration.metadata.checksum}")
            
            # Check dependencies
            completed_versions = await manager.history.get_completed_migrations()
            missing_deps = [dep for dep in migration.metadata.dependencies 
                          if dep not in completed_versions]
            
            if missing_deps:
                click.echo(f"⚠️  Missing dependencies: {', '.join(missing_deps)}")
            else:
                click.echo("✅ All dependencies satisfied")
            
            # Check if already applied
            status = await manager.history.get_migration_status(version)
            if status:
                click.echo(f"ℹ️  Current status: {status.value}")
            else:
                click.echo("✅ Ready to apply")
                
        finally:
            await manager.close()
    
    asyncio.run(_validate())


@migrate.command()
@click.option('--database-url', '-d', help='Database URL (defaults to config)')
def init(database_url: Optional[str]):
    """Initialize migration system (create migration history table)."""
    
    async def _init():
        db_url = database_url or get_database_url()
        manager = MigrationManager(db_url, Path('migrations'))
        
        try:
            await manager.initialize()
            click.echo("✅ Migration system initialized successfully")
            click.echo(f"   Database: {db_url}")
            click.echo("   Migration history table created")
                
        finally:
            await manager.close()
    
    asyncio.run(_init())