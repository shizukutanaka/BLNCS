# BLRCS Database Module
# Lightweight and efficient database operations
import asyncio
import json
import sqlite3
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
from contextlib import asynccontextmanager
import aiosqlite
from blrcs.errors import DatabaseError, ErrorHandler, resilient, error_boundary, ErrorSeverity
from blrcs.pool import DatabasePool

class Database:
    """Lightweight async database handler using SQLite."""
    
    def __init__(self, db_path: Path, use_pool: bool = True):
        self.db_path = db_path
        self.connection: Optional[aiosqlite.Connection] = None
        self.pool: Optional[DatabasePool] = None
        self.use_pool = use_pool
        self.error_handler = ErrorHandler()
        self._ensure_directory()
    
    def _ensure_directory(self):
        """Ensure database directory exists"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
    
    @error_boundary(severity=ErrorSeverity.HIGH)
    async def connect(self):
        """Establish database connection"""
        if self.use_pool:
            if self.pool:
                return
            
            try:
                self.pool = DatabasePool(
                    str(self.db_path),
                    min_size=2,
                    max_size=10,
                    max_age=3600,
                    max_idle=600
                )
                await self.pool.initialize()
                
                # Initialize schema using pool
                async with self.pool.connection() as conn:
                    await self._init_schema_with_connection(conn)
            except Exception as e:
                self.error_handler.handle_error(e, "database_pool_connect")
                raise DatabaseError(f"Failed to initialize database pool: {str(e)}")
        else:
            if self.connection:
                return
            
            try:
                self.connection = await aiosqlite.connect(
                    str(self.db_path),
                    isolation_level=None
                )
                
                # Enhanced database optimizations
                await self.connection.execute("PRAGMA journal_mode=WAL")
                await self.connection.execute("PRAGMA synchronous=NORMAL")
                await self.connection.execute("PRAGMA cache_size=20000")  # Increased cache
                await self.connection.execute("PRAGMA temp_store=MEMORY")
                await self.connection.execute("PRAGMA mmap_size=268435456")  # 256MB
                await self.connection.execute("PRAGMA page_size=4096")
                await self.connection.execute("PRAGMA optimize")
                await self.connection.execute("PRAGMA vacuum_auto=1")
                await self.connection.execute("PRAGMA wal_autocheckpoint=1000")
                await self.connection.execute("PRAGMA busy_timeout=30000")  # 30 second timeout
                
                # Initialize schema
                await self._init_schema_with_connection(self.connection)
            except Exception as e:
                self.error_handler.handle_error(e, "database_connect")
                raise DatabaseError(f"Failed to connect to database: {str(e)}")
    
    async def disconnect(self):
        """Close database connection"""
        if self.connection:
            await self.connection.close()
            self.connection = None
    
    async def _init_schema_with_connection(self, conn: aiosqlite.Connection):
        """Initialize database schema"""
        schema = """
        CREATE TABLE IF NOT EXISTS data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL UNIQUE,
            value TEXT NOT NULL,
            type TEXT DEFAULT 'json',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            level TEXT NOT NULL,
            message TEXT NOT NULL,
            context TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS cache (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            expires_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        -- Optimized compound indexes for better query performance
        CREATE INDEX IF NOT EXISTS idx_data_key_type ON data(key, type);
        CREATE INDEX IF NOT EXISTS idx_data_created_key ON data(created_at DESC, key);
        CREATE INDEX IF NOT EXISTS idx_data_updated_key ON data(updated_at DESC, key);
        CREATE INDEX IF NOT EXISTS idx_logs_level_created ON logs(level, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_logs_created_level ON logs(created_at DESC, level);
        CREATE INDEX IF NOT EXISTS idx_cache_expires_key ON cache(expires_at, key);
        CREATE INDEX IF NOT EXISTS idx_cache_created_expires ON cache(created_at DESC, expires_at);
        
        -- Partial indexes for active records
        CREATE INDEX IF NOT EXISTS idx_cache_active ON cache(key) WHERE expires_at > datetime('now');
        CREATE INDEX IF NOT EXISTS idx_data_recent ON data(key, updated_at) WHERE updated_at > datetime('now', '-1 day');
        """
        
        await conn.executescript(schema)
    
    @resilient(default=None, retries=3, exceptions=(DatabaseError, aiosqlite.Error))
    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Get value by key"""
        if not self.connection:
            raise DatabaseError("Database not connected")
        
        try:
            cursor = await self.connection.execute(
                "SELECT value, type FROM data WHERE key = ?",
                (key,)
            )
            row = await cursor.fetchone()
            await cursor.close()
            if row:
                value, value_type = row
                if value_type == 'json':
                    return json.loads(value)
                return {"value": value, "type": value_type}
            return None
        except json.JSONDecodeError as e:
            self.error_handler.handle_error(e, f"get_key_{key}")
            raise DatabaseError(f"Failed to decode JSON for key {key}")
        except Exception as e:
            self.error_handler.handle_error(e, f"get_key_{key}")
            raise DatabaseError(f"Failed to get key {key}: {str(e)}")
    
    async def set(self, key: str, value: Any, value_type: str = 'json') -> bool:
        """Set or update value"""
        try:
            if value_type == 'json':
                value = json.dumps(value)
            
            await self.connection.execute("""
                INSERT INTO data (key, value, type)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    type = excluded.type,
                    updated_at = CURRENT_TIMESTAMP
            """, (key, value, value_type))
            
            return True
        except Exception as e:
            await self.log_error(f"Failed to set key {key}: {e}")
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete value by key"""
        try:
            cursor = await self.connection.execute(
                "DELETE FROM data WHERE key = ?",
                (key,)
            )
            return cursor.rowcount > 0
        except Exception as e:
            await self.log_error(f"Failed to delete key {key}: {e}")
            return False
    
    async def list_keys(self, pattern: str = '%', limit: int = 1000) -> List[str]:
        """List keys matching pattern with limit for performance"""
        async with self.connection.execute(
            "SELECT key FROM data WHERE key LIKE ? ORDER BY key LIMIT ?",
            (pattern, limit)
        ) as cursor:
            rows = await cursor.fetchall()
            return [row[0] for row in rows]
    
    async def log(self, level: str, message: str, context: Optional[Dict] = None):
        """Add log entry"""
        context_str = json.dumps(context) if context else None
        await self.connection.execute(
            "INSERT INTO logs (level, message, context) VALUES (?, ?, ?)",
            (level.upper(), message, context_str)
        )
    
    async def log_error(self, message: str, context: Optional[Dict] = None):
        """Log error message"""
        await self.log("ERROR", message, context)
    
    async def get_logs(self, limit: int = 100, level: Optional[str] = None) -> List[Dict]:
        """Get recent logs"""
        query = "SELECT * FROM logs"
        params = []
        
        if level:
            query += " WHERE level = ?"
            params.append(level.upper())
        
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        
        async with self.connection.execute(query, params) as cursor:
            rows = await cursor.fetchall()
            columns = [d[0] for d in cursor.description]
            return [dict(zip(columns, row)) for row in rows]
    
    async def store_result(self, result: Dict[str, Any]):
        """Store processing result"""
        key = f"result_{datetime.utcnow().isoformat()}"
        await self.set(key, result)
    
    async def health_check(self) -> bool:
        """Check database health"""
        try:
            async with self.connection.execute("SELECT 1") as cursor:
                await cursor.fetchone()
            return True
        except Exception as e:
            logger = get_logger(__name__)
            logger.warning(f"Database connection test failed: {e}")
            return False
    
    async def get_stats(self) -> Dict[str, int]:
        """Get database statistics"""
        stats = {}
        
        tables = ['data', 'logs', 'cache']
        for table in tables:
            async with self.connection.execute(f"SELECT COUNT(*) FROM {table}") as cursor:
                row = await cursor.fetchone()
                stats[f"{table}_count"] = row[0] if row else 0
        
        return stats
