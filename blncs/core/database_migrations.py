"""
PostgreSQL Migration Framework for BLNCS
Provides enterprise-grade database migration and schema management.
"""

import asyncio
import logging
import json
import hashlib
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum
import traceback

import asyncpg
from asyncpg import Connection, Pool

from .structured_logging import StructuredLogger, LogLevel
from .telemetry import TracingMixin


class MigrationStatus(Enum):
    """Migration execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class MigrationType(Enum):
    """Types of database migrations."""
    SCHEMA = "schema"
    DATA = "data"
    INDEX = "index"
    CONSTRAINT = "constraint"
    FUNCTION = "function"
    TRIGGER = "trigger"


@dataclass
class MigrationMetadata:
    """Metadata for a database migration."""
    version: str
    name: str
    description: str
    migration_type: MigrationType
    author: str
    created_at: datetime
    checksum: str
    dependencies: List[str]
    rollback_supported: bool = True
    estimated_duration: Optional[int] = None  # seconds
    tags: List[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []


@dataclass
class MigrationResult:
    """Result of migration execution."""
    version: str
    status: MigrationStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    error_message: Optional[str] = None
    rows_affected: Optional[int] = None
    rollback_available: bool = True


class Migration:
    """Base class for database migrations."""
    
    def __init__(self, metadata: MigrationMetadata):
        self.metadata = metadata
        self.logger = StructuredLogger(f"migration.{metadata.version}")
    
    async def validate_preconditions(self, connection: Connection) -> bool:
        """Validate that preconditions for migration are met."""
        return True
    
    async def up(self, connection: Connection) -> int:
        """Execute the migration. Return number of rows affected."""
        raise NotImplementedError("Subclasses must implement up()")
    
    async def down(self, connection: Connection) -> int:
        """Rollback the migration. Return number of rows affected."""
        if not self.metadata.rollback_supported:
            raise NotImplementedError("This migration does not support rollback")
        raise NotImplementedError("Subclasses must implement down() if rollback_supported=True")
    
    def calculate_checksum(self) -> str:
        """Calculate checksum for migration integrity verification."""
        content = f"{self.metadata.version}{self.metadata.name}{self.metadata.description}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


class SQLMigration(Migration):
    """SQL-based migration."""
    
    def __init__(self, metadata: MigrationMetadata, up_sql: str, down_sql: Optional[str] = None):
        super().__init__(metadata)
        self.up_sql = up_sql
        self.down_sql = down_sql
        if down_sql is None:
            self.metadata.rollback_supported = False
    
    async def up(self, connection: Connection) -> int:
        """Execute the up SQL migration."""
        try:
            result = await connection.execute(self.up_sql)
            return self._parse_affected_rows(result)
        except Exception as e:
            self.logger.error("SQL migration failed", extra={"sql": self.up_sql, "error": str(e)})
            raise
    
    async def down(self, connection: Connection) -> int:
        """Execute the down SQL migration."""
        if not self.down_sql:
            raise NotImplementedError("No rollback SQL provided")
        
        try:
            result = await connection.execute(self.down_sql)
            return self._parse_affected_rows(result)
        except Exception as e:
            self.logger.error("SQL rollback failed", extra={"sql": self.down_sql, "error": str(e)})
            raise
    
    def _parse_affected_rows(self, result: str) -> int:
        """Parse affected rows from SQL result."""
        if isinstance(result, str) and result.startswith(('INSERT', 'UPDATE', 'DELETE')):
            parts = result.split()
            if len(parts) >= 2:
                try:
                    return int(parts[1])
                except ValueError:
                    pass
        return 0
    
    def calculate_checksum(self) -> str:
        """Calculate checksum including SQL content."""
        base_content = f"{self.metadata.version}{self.metadata.name}{self.up_sql}"
        if self.down_sql:
            base_content += self.down_sql
        return hashlib.sha256(base_content.encode()).hexdigest()[:16]


class MigrationLoader:
    """Loads migrations from various sources."""
    
    def __init__(self, migration_path: Path):
        self.migration_path = Path(migration_path)
        self.logger = StructuredLogger("migration.loader")
    
    async def load_migrations(self) -> Dict[str, Migration]:
        """Load all migrations from the migration directory."""
        migrations = {}
        
        if not self.migration_path.exists():
            self.logger.warning("Migration directory does not exist", 
                              extra={"path": str(self.migration_path)})
            return migrations
        
        for file_path in sorted(self.migration_path.glob("*.sql")):
            try:
                migration = await self._load_sql_migration(file_path)
                migrations[migration.metadata.version] = migration
            except Exception as e:
                self.logger.error("Failed to load migration", 
                                extra={"file": str(file_path), "error": str(e)})
        
        self.logger.info("Loaded migrations", extra={"count": len(migrations)})
        return migrations
    
    async def _load_sql_migration(self, file_path: Path) -> SQLMigration:
        """Load a SQL migration from file."""
        content = file_path.read_text(encoding='utf-8')
        
        # Parse migration header
        lines = content.split('\n')
        metadata_lines = []
        sql_lines = []
        in_metadata = False
        
        for line in lines:
            if line.strip() == '-- MIGRATION_START':
                in_metadata = True
                continue
            elif line.strip() == '-- MIGRATION_END':
                in_metadata = False
                continue
            elif in_metadata:
                metadata_lines.append(line)
            else:
                sql_lines.append(line)
        
        # Parse metadata
        metadata_dict = {}
        for line in metadata_lines:
            if line.startswith('-- '):
                parts = line[3:].split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip().lower()
                    value = parts[1].strip()
                    metadata_dict[key] = value
        
        # Create metadata object
        version = metadata_dict.get('version', file_path.stem)
        name = metadata_dict.get('name', file_path.stem)
        description = metadata_dict.get('description', '')
        migration_type = MigrationType(metadata_dict.get('type', 'schema'))
        author = metadata_dict.get('author', 'unknown')
        dependencies = metadata_dict.get('dependencies', '').split(',') if metadata_dict.get('dependencies') else []
        dependencies = [dep.strip() for dep in dependencies if dep.strip()]
        
        metadata = MigrationMetadata(
            version=version,
            name=name,
            description=description,
            migration_type=migration_type,
            author=author,
            created_at=datetime.now(timezone.utc),
            checksum='',  # Will be calculated
            dependencies=dependencies
        )
        
        # Split up and down SQL
        sql_content = '\n'.join(sql_lines)
        up_sql = sql_content
        down_sql = None
        
        if '-- ROLLBACK' in sql_content:
            parts = sql_content.split('-- ROLLBACK', 1)
            up_sql = parts[0].strip()
            down_sql = parts[1].strip() if len(parts) > 1 else None
        
        migration = SQLMigration(metadata, up_sql, down_sql)
        metadata.checksum = migration.calculate_checksum()
        
        return migration


class MigrationHistory:
    """Manages migration execution history."""
    
    HISTORY_TABLE = 'blncs_migration_history'
    
    def __init__(self, pool: Pool):
        self.pool = pool
        self.logger = StructuredLogger("migration.history")
    
    async def initialize_history_table(self):
        """Create the migration history table if it doesn't exist."""
        async with self.pool.acquire() as conn:
            await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.HISTORY_TABLE} (
                    version VARCHAR(255) PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    description TEXT,
                    migration_type VARCHAR(50) NOT NULL,
                    status VARCHAR(50) NOT NULL,
                    checksum VARCHAR(32) NOT NULL,
                    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
                    completed_at TIMESTAMP WITH TIME ZONE,
                    duration_seconds REAL,
                    rows_affected INTEGER,
                    error_message TEXT,
                    author VARCHAR(255),
                    metadata JSONB,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                );
                
                CREATE INDEX IF NOT EXISTS idx_migration_history_status 
                ON {self.HISTORY_TABLE} (status);
                
                CREATE INDEX IF NOT EXISTS idx_migration_history_completed_at 
                ON {self.HISTORY_TABLE} (completed_at);
            """)
    
    async def record_migration_start(self, migration: Migration) -> MigrationResult:
        """Record the start of a migration."""
        result = MigrationResult(
            version=migration.metadata.version,
            status=MigrationStatus.RUNNING,
            started_at=datetime.now(timezone.utc)
        )
        
        async with self.pool.acquire() as conn:
            await conn.execute(f"""
                INSERT INTO {self.HISTORY_TABLE} 
                (version, name, description, migration_type, status, checksum, 
                 started_at, author, metadata)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (version) DO UPDATE SET
                    status = EXCLUDED.status,
                    started_at = EXCLUDED.started_at,
                    completed_at = NULL,
                    error_message = NULL
            """, 
                migration.metadata.version,
                migration.metadata.name,
                migration.metadata.description,
                migration.metadata.migration_type.value,
                result.status.value,
                migration.metadata.checksum,
                result.started_at,
                migration.metadata.author,
                json.dumps(asdict(migration.metadata), default=str)
            )
        
        return result
    
    async def record_migration_completion(self, result: MigrationResult):
        """Record the completion of a migration."""
        result.completed_at = datetime.now(timezone.utc)
        if result.started_at:
            result.duration_seconds = (result.completed_at - result.started_at).total_seconds()
        
        async with self.pool.acquire() as conn:
            await conn.execute(f"""
                UPDATE {self.HISTORY_TABLE} 
                SET status = $1, completed_at = $2, duration_seconds = $3, 
                    rows_affected = $4, error_message = $5
                WHERE version = $6
            """,
                result.status.value,
                result.completed_at,
                result.duration_seconds,
                result.rows_affected,
                result.error_message,
                result.version
            )
    
    async def get_migration_status(self, version: str) -> Optional[MigrationStatus]:
        """Get the current status of a migration."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(f"""
                SELECT status FROM {self.HISTORY_TABLE} WHERE version = $1
            """, version)
            
            if row:
                return MigrationStatus(row['status'])
            return None
    
    async def get_completed_migrations(self) -> List[str]:
        """Get list of successfully completed migration versions."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(f"""
                SELECT version FROM {self.HISTORY_TABLE} 
                WHERE status = $1 
                ORDER BY completed_at
            """, MigrationStatus.COMPLETED.value)
            
            return [row['version'] for row in rows]
    
    async def get_migration_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get migration history."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(f"""
                SELECT * FROM {self.HISTORY_TABLE} 
                ORDER BY started_at DESC 
                LIMIT $1
            """, limit)
            
            return [dict(row) for row in rows]


class MigrationManager(TracingMixin):
    """Main migration management system."""
    
    def __init__(self, database_url: str, migration_path: Path):
        self.database_url = database_url
        self.migration_path = Path(migration_path)
        self.pool: Optional[Pool] = None
        self.loader = MigrationLoader(self.migration_path)
        self.logger = StructuredLogger("migration.manager")
        self.history: Optional[MigrationHistory] = None
    
    async def initialize(self):
        """Initialize the migration manager."""
        with self.trace_operation("migration_manager_initialize"):
            self.pool = await asyncpg.create_pool(self.database_url)
            self.history = MigrationHistory(self.pool)
            await self.history.initialize_history_table()
            
            self.logger.info("Migration manager initialized", 
                           extra={"migration_path": str(self.migration_path)})
    
    async def close(self):
        """Close the migration manager."""
        if self.pool:
            await self.pool.close()
            self.logger.info("Migration manager closed")
    
    async def discover_migrations(self) -> Dict[str, Migration]:
        """Discover all available migrations."""
        with self.trace_operation("discover_migrations"):
            return await self.loader.load_migrations()
    
    async def get_pending_migrations(self) -> List[Migration]:
        """Get list of pending migrations in dependency order."""
        with self.trace_operation("get_pending_migrations"):
            all_migrations = await self.discover_migrations()
            completed_versions = await self.history.get_completed_migrations()
            
            # Filter pending migrations
            pending = {v: m for v, m in all_migrations.items() if v not in completed_versions}
            
            # Sort by dependency order
            return self._sort_migrations_by_dependencies(pending)
    
    def _sort_migrations_by_dependencies(self, migrations: Dict[str, Migration]) -> List[Migration]:
        """Sort migrations by their dependencies."""
        sorted_migrations = []
        remaining = migrations.copy()
        
        while remaining:
            # Find migrations with no pending dependencies
            ready = []
            for version, migration in remaining.items():
                dependencies_met = all(
                    dep in [m.metadata.version for m in sorted_migrations] or dep not in migrations
                    for dep in migration.metadata.dependencies
                )
                if dependencies_met:
                    ready.append((version, migration))
            
            if not ready:
                # Circular dependency or missing dependency
                remaining_versions = list(remaining.keys())
                raise ValueError(f"Circular dependency detected in migrations: {remaining_versions}")
            
            # Add ready migrations and remove from remaining
            for version, migration in ready:
                sorted_migrations.append(migration)
                del remaining[version]
        
        return sorted_migrations
    
    async def migrate(self, target_version: Optional[str] = None, dry_run: bool = False) -> List[MigrationResult]:
        """Execute pending migrations up to target version."""
        with self.trace_operation("migrate"):
            pending_migrations = await self.get_pending_migrations()
            
            if target_version:
                # Filter to target version
                target_index = None
                for i, migration in enumerate(pending_migrations):
                    if migration.metadata.version == target_version:
                        target_index = i
                        break
                
                if target_index is None:
                    raise ValueError(f"Target version {target_version} not found in pending migrations")
                
                pending_migrations = pending_migrations[:target_index + 1]
            
            results = []
            for migration in pending_migrations:
                if dry_run:
                    self.logger.info("DRY RUN: Would execute migration", 
                                   extra={"version": migration.metadata.version})
                    result = MigrationResult(
                        version=migration.metadata.version,
                        status=MigrationStatus.COMPLETED,
                        started_at=datetime.now(timezone.utc)
                    )
                    results.append(result)
                else:
                    result = await self._execute_migration(migration)
                    results.append(result)
                    
                    if result.status == MigrationStatus.FAILED:
                        self.logger.error("Migration failed, stopping execution", 
                                        extra={"version": migration.metadata.version})
                        break
            
            return results
    
    async def _execute_migration(self, migration: Migration) -> MigrationResult:
        """Execute a single migration."""
        with self.trace_operation("execute_migration", {"version": migration.metadata.version}):
            result = await self.history.record_migration_start(migration)
            
            try:
                async with self.pool.acquire() as conn:
                    async with conn.transaction():
                        # Validate preconditions
                        if not await migration.validate_preconditions(conn):
                            raise Exception("Migration preconditions not met")
                        
                        # Execute migration
                        rows_affected = await migration.up(conn)
                        result.rows_affected = rows_affected
                        result.status = MigrationStatus.COMPLETED
                        
                        self.logger.info("Migration completed successfully", 
                                       extra={
                                           "version": migration.metadata.version,
                                           "rows_affected": rows_affected
                                       })
                
            except Exception as e:
                result.status = MigrationStatus.FAILED
                result.error_message = str(e)
                
                self.logger.error("Migration failed", 
                                extra={
                                    "version": migration.metadata.version,
                                    "error": str(e),
                                    "traceback": traceback.format_exc()
                                })
            
            finally:
                await self.history.record_migration_completion(result)
            
            return result
    
    async def rollback(self, target_version: str) -> List[MigrationResult]:
        """Rollback migrations to target version."""
        with self.trace_operation("rollback"):
            completed_versions = await self.history.get_completed_migrations()
            all_migrations = await self.discover_migrations()
            
            # Find migrations to rollback (in reverse order)
            rollback_versions = []
            found_target = False
            
            for version in reversed(completed_versions):
                if version == target_version:
                    found_target = True
                    break
                rollback_versions.append(version)
            
            if not found_target and target_version not in completed_versions:
                raise ValueError(f"Target version {target_version} not found in completed migrations")
            
            results = []
            for version in rollback_versions:
                migration = all_migrations.get(version)
                if not migration:
                    self.logger.error("Migration not found for rollback", extra={"version": version})
                    continue
                
                if not migration.metadata.rollback_supported:
                    raise Exception(f"Migration {version} does not support rollback")
                
                result = await self._rollback_migration(migration)
                results.append(result)
                
                if result.status == MigrationStatus.FAILED:
                    self.logger.error("Rollback failed, stopping execution", 
                                    extra={"version": version})
                    break
            
            return results
    
    async def _rollback_migration(self, migration: Migration) -> MigrationResult:
        """Rollback a single migration."""
        with self.trace_operation("rollback_migration", {"version": migration.metadata.version}):
            result = MigrationResult(
                version=migration.metadata.version,
                status=MigrationStatus.RUNNING,
                started_at=datetime.now(timezone.utc)
            )
            
            try:
                async with self.pool.acquire() as conn:
                    async with conn.transaction():
                        rows_affected = await migration.down(conn)
                        result.rows_affected = rows_affected
                        result.status = MigrationStatus.ROLLED_BACK
                        
                        # Update history
                        await conn.execute(f"""
                            UPDATE {self.history.HISTORY_TABLE} 
                            SET status = $1 
                            WHERE version = $2
                        """, result.status.value, migration.metadata.version)
                        
                        self.logger.info("Migration rolled back successfully", 
                                       extra={
                                           "version": migration.metadata.version,
                                           "rows_affected": rows_affected
                                       })
                
            except Exception as e:
                result.status = MigrationStatus.FAILED
                result.error_message = str(e)
                
                self.logger.error("Rollback failed", 
                                extra={
                                    "version": migration.metadata.version,
                                    "error": str(e),
                                    "traceback": traceback.format_exc()
                                })
            
            finally:
                result.completed_at = datetime.now(timezone.utc)
                if result.started_at:
                    result.duration_seconds = (result.completed_at - result.started_at).total_seconds()
            
            return result
    
    async def get_status(self) -> Dict[str, Any]:
        """Get current migration status."""
        with self.trace_operation("get_migration_status"):
            all_migrations = await self.discover_migrations()
            completed_versions = await self.history.get_completed_migrations()
            pending_migrations = await self.get_pending_migrations()
            
            return {
                "total_migrations": len(all_migrations),
                "completed_migrations": len(completed_versions),
                "pending_migrations": len(pending_migrations),
                "last_completed": completed_versions[-1] if completed_versions else None,
                "next_pending": pending_migrations[0].metadata.version if pending_migrations else None
            }


# CLI Integration Functions
async def create_migration_template(
    migration_path: Path, 
    version: str, 
    name: str, 
    migration_type: MigrationType = MigrationType.SCHEMA,
    author: str = "blncs"
) -> Path:
    """Create a new migration template file."""
    migration_path.mkdir(parents=True, exist_ok=True)
    
    filename = f"{version}_{name.replace(' ', '_').lower()}.sql"
    file_path = migration_path / filename
    
    template = f"""-- MIGRATION_START
-- Version: {version}
-- Name: {name}
-- Description: TODO: Add description
-- Type: {migration_type.value}
-- Author: {author}
-- Dependencies: 
-- MIGRATION_END

-- Add your migration SQL here


-- ROLLBACK
-- Add rollback SQL here (optional)

"""
    
    file_path.write_text(template)
    return file_path