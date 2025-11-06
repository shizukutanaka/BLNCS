#!/usr/bin/env python3
"""
BLNCS Database Migration System

Lightweight database schema migration and version management.
"""

import asyncio
import json
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
import logging

from ..core.exceptions import ValidationError, DatabaseError
from ..core.unified_database import UnifiedDatabase

logger = logging.getLogger(__name__)


@dataclass
class Migration:
    """Database migration definition"""
    version: str
    name: str
    up_sql: str
    down_sql: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    checksum: Optional[str] = None
    applied_at: Optional[datetime] = None
    applied_by: Optional[str] = None


@dataclass
class MigrationResult:
    """Migration operation result"""
    success: bool
    migration: Optional[Migration] = None
    error_message: Optional[str] = None
    execution_time: float = 0.0
    rollback_performed: bool = False


class MigrationManager:
    """Lightweight database migration manager"""

    def __init__(self, migrations_dir: str = "migrations", db_connection_string: Optional[str] = None):
        self.migrations_dir = Path(migrations_dir)
        self.migrations_dir.mkdir(exist_ok=True)
        self.db_connection_string = db_connection_string
        self.db = None
        self.migrations_table = "schema_migrations"

    async def initialize(self):
        """Initialize migration system"""
        if not self.db:
            if self.db_connection_string:
                self.db = UnifiedDatabase(connection_string=self.db_connection_string)
            else:
                self.db = UnifiedDatabase()

        await self._ensure_migrations_table()

    async def _ensure_migrations_table(self):
        """Create migrations tracking table if it doesn't exist"""
        create_table_sql = f"""
        CREATE TABLE IF NOT EXISTS {self.migrations_table} (
            version VARCHAR(50) PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            checksum VARCHAR(64) NOT NULL,
            applied_at TIMESTAMP NOT NULL,
            applied_by VARCHAR(100),
            dependencies TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """

        try:
            await self.db.execute(create_table_sql)
        except Exception as e:
            logger.error(f"Failed to create migrations table: {e}")
            raise DatabaseError(f"Migration table creation failed: {e}")

    def create_migration(self, name: str, up_sql: str, down_sql: Optional[str] = None) -> Migration:
        """Create a new migration file"""
        # Generate version (timestamp + hash)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        content_hash = hashlib.sha256((name + up_sql).encode()).hexdigest()[:8]
        version = f"{timestamp}_{content_hash}"

        migration = Migration(
            version=version,
            name=name,
            up_sql=up_sql,
            down_sql=down_sql,
            checksum=self._calculate_checksum(up_sql, down_sql)
        )

        # Write migration file
        migration_file = self.migrations_dir / f"{version}_{name}.json"
        migration_data = {
            'version': migration.version,
            'name': migration.name,
            'up_sql': migration.up_sql,
            'down_sql': migration.down_sql,
            'dependencies': migration.dependencies,
            'checksum': migration.checksum
        }

        with open(migration_file, 'w') as f:
            json.dump(migration_data, f, indent=2)

        logger.info(f"Created migration: {migration_file}")
        return migration

    def _calculate_checksum(self, up_sql: str, down_sql: Optional[str] = None) -> str:
        """Calculate migration checksum"""
        content = up_sql
        if down_sql:
            content += down_sql
        return hashlib.sha256(content.encode()).hexdigest()

    def load_migrations(self) -> List[Migration]:
        """Load all migration files"""
        migrations = []

        for migration_file in self.migrations_dir.glob("*.json"):
            try:
                with open(migration_file, 'r') as f:
                    data = json.load(f)

                migration = Migration(
                    version=data['version'],
                    name=data['name'],
                    up_sql=data['up_sql'],
                    down_sql=data.get('down_sql'),
                    dependencies=data.get('dependencies', []),
                    checksum=data.get('checksum')
                )
                migrations.append(migration)

            except Exception as e:
                logger.warning(f"Failed to load migration {migration_file}: {e}")

        # Sort by version
        migrations.sort(key=lambda m: m.version)
        return migrations

    async def get_applied_migrations(self) -> List[str]:
        """Get list of applied migration versions"""
        await self.initialize()

        try:
            result = await self.db.fetch_all(
                f"SELECT version FROM {self.migrations_table} ORDER BY version"
            )
            return [row['version'] for row in result]
        except Exception as e:
            logger.error(f"Failed to get applied migrations: {e}")
            return []

    async def migrate(self, target_version: Optional[str] = None) -> List[MigrationResult]:
        """Run migrations up to target version"""
        await self.initialize()

        migrations = self.load_migrations()
        applied_versions = await self.get_applied_migrations()

        # Filter migrations to apply
        migrations_to_apply = []
        for migration in migrations:
            if migration.version not in applied_versions:
                if target_version and migration.version > target_version:
                    break
                migrations_to_apply.append(migration)

        results = []
        for migration in migrations_to_apply:
            result = await self._apply_migration(migration)
            results.append(result)

            if not result.success:
                logger.error(f"Migration failed: {migration.name}")
                break

        return results

    async def rollback(self, target_version: Optional[str] = None) -> List[MigrationResult]:
        """Rollback migrations to target version"""
        await self.initialize()

        migrations = self.load_migrations()
        applied_versions = await self.get_applied_migrations()

        # Find migrations to rollback
        migrations_to_rollback = []
        for migration in reversed(migrations):
            if migration.version in applied_versions:
                if target_version and migration.version <= target_version:
                    break
                migrations_to_rollback.append(migration)

        results = []
        for migration in migrations_to_rollback:
            result = await self._rollback_migration(migration)
            results.append(result)

            if not result.success:
                logger.error(f"Rollback failed: {migration.name}")
                break

        return results

    async def _apply_migration(self, migration: Migration) -> MigrationResult:
        """Apply a single migration"""
        import time
        start_time = time.time()

        try:
            # Verify checksum
            if migration.checksum != self._calculate_checksum(migration.up_sql, migration.down_sql):
                return MigrationResult(
                    success=False,
                    migration=migration,
                    error_message="Checksum verification failed"
                )

            # Execute migration
            await self.db.execute(migration.up_sql)

            # Record migration
            await self._record_migration(migration)

            execution_time = time.time() - start_time
            logger.info(f"Applied migration: {migration.name} ({migration.version})")

            return MigrationResult(
                success=True,
                migration=migration,
                execution_time=execution_time
            )

        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Failed to apply migration {migration.name}: {e}")

            return MigrationResult(
                success=False,
                migration=migration,
                error_message=str(e),
                execution_time=execution_time
            )

    async def _rollback_migration(self, migration: Migration) -> MigrationResult:
        """Rollback a single migration"""
        import time
        start_time = time.time()

        try:
            if not migration.down_sql:
                return MigrationResult(
                    success=False,
                    migration=migration,
                    error_message="No rollback SQL provided"
                )

            # Execute rollback
            await self.db.execute(migration.down_sql)

            # Remove migration record
            await self._remove_migration_record(migration)

            execution_time = time.time() - start_time
            logger.info(f"Rolled back migration: {migration.name} ({migration.version})")

            return MigrationResult(
                success=True,
                migration=migration,
                execution_time=execution_time,
                rollback_performed=True
            )

        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Failed to rollback migration {migration.name}: {e}")

            return MigrationResult(
                success=False,
                migration=migration,
                error_message=str(e),
                execution_time=execution_time,
                rollback_performed=True
            )

    async def _record_migration(self, migration: Migration):
        """Record applied migration"""
        insert_sql = f"""
        INSERT INTO {self.migrations_table}
        (version, name, checksum, applied_at, applied_by, dependencies)
        VALUES (?, ?, ?, ?, ?, ?)
        """

        await self.db.execute(insert_sql, (
            migration.version,
            migration.name,
            migration.checksum,
            datetime.now(timezone.utc),
            "system",  # Could be enhanced to track user
            json.dumps(migration.dependencies)
        ))

    async def _remove_migration_record(self, migration: Migration):
        """Remove migration record"""
        delete_sql = f"DELETE FROM {self.migrations_table} WHERE version = ?"
        await self.db.execute(delete_sql, (migration.version,))

    def get_migration_status(self) -> Dict[str, Any]:
        """Get current migration status"""
        migrations = self.load_migrations()

        status = {
            'total_migrations': len(migrations),
            'applied_count': 0,
            'pending_count': 0,
            'migrations': []
        }

        # This would need async context in real usage
        # For now, return basic info
        for migration in migrations:
            migration_info = {
                'version': migration.version,
                'name': migration.name,
                'applied': False,  # Would check database
                'checksum': migration.checksum
            }
            status['migrations'].append(migration_info)

        return status

    def generate_migration_template(self, name: str) -> str:
        """Generate a migration template"""
        return f'''-- Migration: {name}
-- Generated: {datetime.now(timezone.utc).isoformat()}

-- Up migration (apply changes)
-- Write your UP migration SQL here

-- Down migration (rollback changes)
-- Write your DOWN migration SQL here
'''


# Migration templates for common operations
MIGRATION_TEMPLATES = {
    'create_table': '''-- Create new table: {table_name}
CREATE TABLE {table_name} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Down migration
DROP TABLE IF EXISTS {table_name};
''',

    'add_column': '''-- Add column: {column_name} to table: {table_name}
ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type};

-- Down migration
ALTER TABLE {table_name} DROP COLUMN IF EXISTS {column_name};
''',

    'create_index': '''-- Create index: {index_name} on table: {table_name}
CREATE INDEX {index_name} ON {table_name} ({columns});

-- Down migration
DROP INDEX IF EXISTS {index_name};
''',

    'add_foreign_key': '''-- Add foreign key: {fk_name}
ALTER TABLE {table_name} ADD CONSTRAINT {fk_name}
FOREIGN KEY ({column}) REFERENCES {ref_table} ({ref_column});

-- Down migration
ALTER TABLE {table_name} DROP CONSTRAINT IF EXISTS {fk_name};
'''
}


class MigrationCLI:
    """CLI interface for migration management"""

    def __init__(self):
        self.manager = MigrationManager()

    def create_migration_cmd(self, name: str, template: Optional[str] = None):
        """Create a new migration"""
        if template and template in MIGRATION_TEMPLATES:
            sql_content = MIGRATION_TEMPLATES[template]
        else:
            sql_content = self.manager.generate_migration_template(name)

        migration = self.manager.create_migration(name, sql_content)
        print(f"Created migration: {migration.version}_{migration.name}")

    def status_cmd(self):
        """Show migration status"""
        status = self.manager.get_migration_status()
        print(f"Total migrations: {status['total_migrations']}")
        print(f"Applied: {status['applied_count']}")
        print(f"Pending: {status['pending_count']}")

        for migration in status['migrations']:
            status_icon = "✓" if migration['applied'] else "○"
            print(f"  {status_icon} {migration['version']}: {migration['name']}")

    async def migrate_cmd(self, target_version: Optional[str] = None):
        """Run migrations"""
        print("Running migrations...")
        results = await self.manager.migrate(target_version)

        for result in results:
            if result.success:
                print(f"✓ Applied: {result.migration.name}")
            else:
                print(f"✗ Failed: {result.migration.name} - {result.error_message}")
                break

    async def rollback_cmd(self, target_version: Optional[str] = None):
        """Rollback migrations"""
        print("Rolling back migrations...")
        results = await self.manager.rollback(target_version)

        for result in results:
            if result.success:
                print(f"✓ Rolled back: {result.migration.name}")
            else:
                print(f"✗ Rollback failed: {result.migration.name} - {result.error_message}")
                break


# Global migration manager
_migration_manager = None

def get_migration_manager() -> MigrationManager:
    """Get global migration manager instance"""
    global _migration_manager
    if _migration_manager is None:
        _migration_manager = MigrationManager()
    return _migration_manager
