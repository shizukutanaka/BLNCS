"""
Asynchronous database manager for BLNCS
High-performance async database operations with connection pooling and optimization.
"""

import asyncio
try:
    import aiosqlite
    AIOSQLITE_AVAILABLE = True
except ImportError:
    AIOSQLITE_AVAILABLE = False
    aiosqlite = None
import json
import time
from typing import Dict, List, Any, Optional, Union, AsyncIterator
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from contextlib import asynccontextmanager
from pathlib import Path
import logging

from .logger import get_logger
from .error_handler import get_error_handler, ErrorContext
from .exceptions import DatabaseError


@dataclass
class DatabaseConfig:
    """Database configuration settings"""
    database_path: str = "blncs.db"
    max_connections: int = 20
    connection_timeout: float = 30.0
    query_timeout: float = 10.0
    backup_interval: int = 3600  # 1 hour
    enable_wal: bool = True
    enable_foreign_keys: bool = True
    cache_size: int = -64000  # 64MB
    journal_mode: str = "WAL"
    synchronous: str = "NORMAL"
    temp_store: str = "MEMORY"


@dataclass
class QueryResult:
    """Result of database query execution"""
    rows: List[Dict[str, Any]] = field(default_factory=list)
    rowcount: int = 0
    execution_time: float = 0.0
    query_hash: str = ""
    cached: bool = False


@dataclass
class ConnectionStats:
    """Connection pool statistics"""
    total_connections: int = 0
    active_connections: int = 0
    available_connections: int = 0
    total_queries: int = 0
    failed_queries: int = 0
    avg_query_time: float = 0.0
    cache_hits: int = 0
    cache_misses: int = 0


class AsyncConnectionPool:
    """High-performance async connection pool"""
    
    def __init__(self, config: DatabaseConfig):
        self.config = config
        self.logger = get_logger(__name__)
        self.error_handler = get_error_handler()
        
        # Check if aiosqlite is available
        if not AIOSQLITE_AVAILABLE:
            self.logger.warning("aiosqlite not available - async database features disabled")
            self._disabled = True
            return
        else:
            self._disabled = False
        
        # Connection pool
        self._connections: asyncio.Queue = asyncio.Queue(maxsize=config.max_connections)
        self._connection_count = 0
        self._stats = ConnectionStats()
        
        # Query cache
        self._query_cache: Dict[str, tuple] = {}  # hash -> (result, timestamp)
        self._cache_ttl = 300  # 5 minutes
        
        # Connection semaphore
        self._semaphore = asyncio.Semaphore(config.max_connections)
        
        # Performance tracking
        self._query_times: List[float] = []
        self._lock = asyncio.Lock()
    
    async def initialize(self):
        """Initialize connection pool"""
        if self._disabled:
            self.logger.info("Async database disabled - using fallback mode")
            return
            
        try:
            # Create initial connections
            initial_connections = min(5, self.config.max_connections)
            for _ in range(initial_connections):
                conn = await self._create_connection()
                await self._connections.put(conn)
                self._connection_count += 1
            
            self.logger.info(f"Database connection pool initialized with {initial_connections} connections")
        
        except Exception as e:
            self.error_handler.handle_error(
                e,
                ErrorContext(
                    component="async_database",
                    operation="initialize_pool",
                    severity="critical"
                )
            )
            raise DatabaseError(f"Failed to initialize connection pool: {e}")
    
    async def _create_connection(self):
        """Create optimized database connection"""
        if self._disabled or aiosqlite is None:
            raise DatabaseError("aiosqlite not available")
            
        try:
            conn = await aiosqlite.connect(
                self.config.database_path,
                timeout=self.config.connection_timeout
            )
            
            # Optimize connection settings
            await conn.execute(f"PRAGMA journal_mode = {self.config.journal_mode}")
            await conn.execute(f"PRAGMA synchronous = {self.config.synchronous}")
            await conn.execute(f"PRAGMA cache_size = {self.config.cache_size}")
            await conn.execute(f"PRAGMA temp_store = {self.config.temp_store}")
            
            if self.config.enable_foreign_keys:
                await conn.execute("PRAGMA foreign_keys = ON")
            
            if self.config.enable_wal:
                await conn.execute("PRAGMA wal_autocheckpoint = 1000")
            
            await conn.commit()
            return conn
            
        except Exception as e:
            raise DatabaseError(f"Failed to create database connection: {e}")
    
    @asynccontextmanager
    async def get_connection(self):
        """Get connection from pool with automatic return"""
        async with self._semaphore:
            try:
                # Try to get existing connection
                conn = await asyncio.wait_for(
                    self._connections.get(),
                    timeout=1.0
                )
            except asyncio.TimeoutError:
                # Create new connection if pool is empty
                if self._connection_count < self.config.max_connections:
                    conn = await self._create_connection()
                    self._connection_count += 1
                else:
                    # Wait longer for available connection
                    conn = await asyncio.wait_for(
                        self._connections.get(),
                        timeout=self.config.connection_timeout
                    )
            
            try:
                # Check if connection is still valid
                await conn.execute("SELECT 1")
                
                async with self._lock:
                    self._stats.active_connections += 1
                
                yield conn
                
            except Exception as e:
                # Connection is broken, create new one
                try:
                    await conn.close()
                except:
                    pass
                
                conn = await self._create_connection()
                yield conn
            
            finally:
                async with self._lock:
                    self._stats.active_connections -= 1
                
                # Return connection to pool
                try:
                    await self._connections.put(conn)
                except asyncio.QueueFull:
                    # Pool is full, close this connection
                    await conn.close()
                    self._connection_count -= 1
    
    def _hash_query(self, query: str, params: tuple = ()) -> str:
        """Generate hash for query caching"""
        import hashlib
        content = f"{query}:{params}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def _get_cached_result(self, query_hash: str) -> Optional[QueryResult]:
        """Get cached query result if valid"""
        if query_hash in self._query_cache:
            result, timestamp = self._query_cache[query_hash]
            if time.time() - timestamp < self._cache_ttl:
                self._stats.cache_hits += 1
                result.cached = True
                return result
            else:
                # Expired, remove from cache
                del self._query_cache[query_hash]
        
        self._stats.cache_misses += 1
        return None
    
    def _cache_result(self, query_hash: str, result: QueryResult):
        """Cache query result"""
        self._query_cache[query_hash] = (result, time.time())
        
        # Limit cache size
        if len(self._query_cache) > 1000:
            # Remove oldest entries
            oldest_entries = sorted(
                self._query_cache.items(),
                key=lambda x: x[1][1]
            )[:100]
            
            for key, _ in oldest_entries:
                del self._query_cache[key]
    
    async def execute_query(
        self,
        query: str,
        params: tuple = (),
        fetch_results: bool = True,
        use_cache: bool = True
    ) -> QueryResult:
        """Execute database query with caching and performance tracking"""
        query_hash = self._hash_query(query, params)
        
        # Check cache for SELECT queries
        if fetch_results and use_cache and query.strip().upper().startswith('SELECT'):
            cached_result = self._get_cached_result(query_hash)
            if cached_result:
                return cached_result
        
        start_time = time.time()
        
        async with self.get_connection() as conn:
            try:
                cursor = await conn.execute(query, params)
                
                result = QueryResult()
                result.query_hash = query_hash
                
                if fetch_results:
                    rows = await cursor.fetchall()
                    # Convert rows to dictionaries
                    if rows:
                        columns = [desc[0] for desc in cursor.description]
                        result.rows = [
                            dict(zip(columns, row)) for row in rows
                        ]
                
                result.rowcount = cursor.rowcount
                result.execution_time = time.time() - start_time
                
                await conn.commit()
                
                # Update statistics
                async with self._lock:
                    self._stats.total_queries += 1
                    self._query_times.append(result.execution_time)
                    
                    # Keep only recent query times for average calculation
                    if len(self._query_times) > 1000:
                        self._query_times = self._query_times[-500:]
                    
                    self._stats.avg_query_time = sum(self._query_times) / len(self._query_times)
                
                # Cache SELECT results
                if fetch_results and use_cache and query.strip().upper().startswith('SELECT'):
                    self._cache_result(query_hash, result)
                
                return result
                
            except Exception as e:
                async with self._lock:
                    self._stats.failed_queries += 1
                
                raise DatabaseError(f"Query execution failed: {e}")
    
    async def execute_batch(
        self,
        queries: List[tuple]  # [(query, params), ...]
    ) -> List[QueryResult]:
        """Execute multiple queries in a transaction"""
        results = []
        
        async with self.get_connection() as conn:
            try:
                await conn.execute("BEGIN TRANSACTION")
                
                for query, params in queries:
                    start_time = time.time()
                    cursor = await conn.execute(query, params)
                    
                    result = QueryResult()
                    result.rowcount = cursor.rowcount
                    result.execution_time = time.time() - start_time
                    results.append(result)
                
                await conn.commit()
                
                async with self._lock:
                    self._stats.total_queries += len(queries)
                
                return results
                
            except Exception as e:
                await conn.rollback()
                async with self._lock:
                    self._stats.failed_queries += len(queries)
                raise DatabaseError(f"Batch execution failed: {e}")
    
    async def close_all(self):
        """Close all connections in pool"""
        connections_closed = 0
        
        while not self._connections.empty():
            try:
                conn = await self._connections.get()
                await conn.close()
                connections_closed += 1
            except Exception as e:
                self.logger.warning(f"Error closing connection: {e}")
        
        self.logger.info(f"Closed {connections_closed} database connections")
    
    def get_stats(self) -> ConnectionStats:
        """Get connection pool statistics"""
        self._stats.total_connections = self._connection_count
        self._stats.available_connections = self._connections.qsize()
        return self._stats


class AsyncDatabaseManager:
    """High-level async database manager"""
    
    def __init__(self, config: Optional[DatabaseConfig] = None):
        self.config = config or DatabaseConfig()
        self.logger = get_logger(__name__)
        self.error_handler = get_error_handler()
        self.pool: Optional[AsyncConnectionPool] = None
        
        # Schema management
        self._schema_version = "1.0.0"
        self._initialized = False
    
    async def initialize(self):
        """Initialize database manager"""
        if self._initialized:
            return
        
        try:
            # Ensure database directory exists
            db_path = Path(self.config.database_path)
            db_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Initialize connection pool
            self.pool = AsyncConnectionPool(self.config)
            await self.pool.initialize()
            
            # Setup database schema
            await self._setup_schema()
            
            self._initialized = True
            self.logger.info("Async database manager initialized successfully")
            
        except Exception as e:
            self.error_handler.handle_error(
                e,
                ErrorContext(
                    component="async_database",
                    operation="initialize",
                    severity="critical"
                )
            )
            raise DatabaseError(f"Failed to initialize database manager: {e}")
    
    async def _setup_schema(self):
        """Setup database schema"""
        schema_queries = [
            # Transactions table
            """
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                amount INTEGER DEFAULT 0,
                fee INTEGER DEFAULT 0,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                payment_hash TEXT,
                invoice TEXT,
                status TEXT DEFAULT 'pending',
                metadata TEXT DEFAULT '{}',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """,
            
            # Channels table
            """
            CREATE TABLE IF NOT EXISTS channels (
                id TEXT PRIMARY KEY,
                remote_pubkey TEXT NOT NULL,
                capacity INTEGER NOT NULL,
                local_balance INTEGER DEFAULT 0,
                remote_balance INTEGER DEFAULT 0,
                active BOOLEAN DEFAULT TRUE,
                private BOOLEAN DEFAULT FALSE,
                fee_base_msat INTEGER DEFAULT 1000,
                fee_rate_ppm INTEGER DEFAULT 1000,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """,
            
            # Performance metrics table
            """
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                metric_name TEXT NOT NULL,
                metric_value REAL NOT NULL,
                metric_type TEXT DEFAULT 'gauge',
                labels TEXT DEFAULT '{}',
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """,
            
            # Error logs table
            """
            CREATE TABLE IF NOT EXISTS error_logs (
                id TEXT PRIMARY KEY,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                component TEXT NOT NULL,
                operation TEXT NOT NULL,
                error_message TEXT NOT NULL,
                stack_trace TEXT,
                metadata TEXT DEFAULT '{}',
                correlation_id TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """,
            
            # Configuration table
            """
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                type TEXT DEFAULT 'string',
                description TEXT,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """,
            
            # Indexes for performance
            "CREATE INDEX IF NOT EXISTS idx_transactions_timestamp ON transactions(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status)",
            "CREATE INDEX IF NOT EXISTS idx_metrics_name_timestamp ON metrics(metric_name, timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_error_logs_timestamp ON error_logs(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_channels_updated ON channels(updated_at)",
        ]
        
        for query in schema_queries:
            await self.pool.execute_query(query, fetch_results=False)
    
    async def execute(
        self,
        query: str,
        params: tuple = (),
        fetch_results: bool = True,
        use_cache: bool = True
    ) -> QueryResult:
        """Execute single database query"""
        if not self._initialized:
            await self.initialize()
        
        return await self.pool.execute_query(query, params, fetch_results, use_cache)
    
    async def execute_batch(self, queries: List[tuple]) -> List[QueryResult]:
        """Execute multiple queries in transaction"""
        if not self._initialized:
            await self.initialize()
        
        return await self.pool.execute_batch(queries)
    
    async def fetch_one(self, query: str, params: tuple = ()) -> Optional[Dict[str, Any]]:
        """Fetch single row"""
        result = await self.execute(query, params)
        return result.rows[0] if result.rows else None
    
    async def fetch_all(self, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
        """Fetch all rows"""
        result = await self.execute(query, params)
        return result.rows
    
    async def insert(self, table: str, data: Dict[str, Any]) -> int:
        """Insert data and return row ID"""
        columns = list(data.keys())
        placeholders = ', '.join('?' * len(columns))
        query = f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})"
        
        result = await self.execute(query, tuple(data.values()), fetch_results=False)
        return result.rowcount
    
    async def update(
        self,
        table: str,
        data: Dict[str, Any],
        where_clause: str,
        where_params: tuple = ()
    ) -> int:
        """Update data and return affected rows"""
        set_clause = ', '.join(f"{col} = ?" for col in data.keys())
        query = f"UPDATE {table} SET {set_clause} WHERE {where_clause}"
        
        params = tuple(data.values()) + where_params
        result = await self.execute(query, params, fetch_results=False)
        return result.rowcount
    
    async def delete(self, table: str, where_clause: str, where_params: tuple = ()) -> int:
        """Delete data and return affected rows"""
        query = f"DELETE FROM {table} WHERE {where_clause}"
        result = await self.execute(query, where_params, fetch_results=False)
        return result.rowcount
    
    async def stream_results(
        self,
        query: str,
        params: tuple = (),
        batch_size: int = 1000
    ) -> AsyncIterator[List[Dict[str, Any]]]:
        """Stream large result sets in batches"""
        offset = 0
        
        while True:
            batch_query = f"{query} LIMIT {batch_size} OFFSET {offset}"
            result = await self.execute(batch_query, params)
            
            if not result.rows:
                break
            
            yield result.rows
            
            if len(result.rows) < batch_size:
                break
            
            offset += batch_size
    
    async def backup_database(self, backup_path: Optional[str] = None) -> str:
        """Create database backup"""
        if backup_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"{self.config.database_path}.backup_{timestamp}"
        
        try:
            # Use VACUUM INTO for efficient backup
            await self.execute(f"VACUUM INTO '{backup_path}'", fetch_results=False)
            self.logger.info(f"Database backup created: {backup_path}")
            return backup_path
            
        except Exception as e:
            raise DatabaseError(f"Backup failed: {e}")
    
    async def optimize_database(self):
        """Optimize database performance"""
        try:
            # Analyze query planner statistics
            await self.execute("ANALYZE", fetch_results=False)
            
            # Rebuild indexes
            await self.execute("REINDEX", fetch_results=False)
            
            # Update statistics
            await self.execute("PRAGMA optimize", fetch_results=False)
            
            self.logger.info("Database optimization completed")
            
        except Exception as e:
            self.logger.warning(f"Database optimization failed: {e}")
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        stats = {
            "connection_pool": self.pool.get_stats().__dict__ if self.pool else {},
            "database_size": 0,
            "table_counts": {}
        }
        
        try:
            # Database size
            db_path = Path(self.config.database_path)
            if db_path.exists():
                stats["database_size"] = db_path.stat().st_size
            
            # Table counts
            tables = ["transactions", "channels", "metrics", "error_logs", "config"]
            for table in tables:
                try:
                    result = await self.fetch_one(f"SELECT COUNT(*) as count FROM {table}")
                    stats["table_counts"][table] = result["count"] if result else 0
                except:
                    stats["table_counts"][table] = 0
        
        except Exception as e:
            self.logger.warning(f"Failed to get database statistics: {e}")
        
        return stats
    
    async def close(self):
        """Close database manager and all connections"""
        if self.pool:
            await self.pool.close_all()
        self._initialized = False
        self.logger.info("Database manager closed")


# Global database manager instance
_global_db_manager: Optional[AsyncDatabaseManager] = None


async def get_async_db_manager():
    """Get global async database manager instance"""
    global _global_db_manager
    
    if not AIOSQLITE_AVAILABLE:
        # Return a mock for systems without aiosqlite
        if _global_db_manager is None:
            _global_db_manager = MockAsyncDatabaseManager()
        return _global_db_manager
    
    if _global_db_manager is None:
        _global_db_manager = AsyncDatabaseManager()
        await _global_db_manager.initialize()
    return _global_db_manager


class MockAsyncDatabaseManager:
    """Mock async database manager for systems without aiosqlite"""
    
    def __init__(self):
        from .logger import get_logger
        self.logger = get_logger(__name__)
        self.logger.warning("Using mock async database manager - aiosqlite not available")
    
    async def initialize(self):
        pass
    
    async def execute(self, query: str, params: tuple = (), **kwargs):
        return QueryResult(rows=[], rowcount=0, execution_time=0.0)
    
    async def fetch_one(self, query: str, params: tuple = ()):
        return None
    
    async def fetch_all(self, query: str, params: tuple = ()):
        return []
    
    async def close(self):
        pass


async def execute_query(query: str, params: tuple = (), **kwargs) -> QueryResult:
    """Convenience function for query execution"""
    db = await get_async_db_manager()
    return await db.execute(query, params, **kwargs)


async def fetch_one(query: str, params: tuple = ()) -> Optional[Dict[str, Any]]:
    """Convenience function to fetch single row"""
    db = await get_async_db_manager()
    return await db.fetch_one(query, params)


async def fetch_all(query: str, params: tuple = ()) -> List[Dict[str, Any]]:
    """Convenience function to fetch all rows"""
    db = await get_async_db_manager()
    return await db.fetch_all(query, params)


__all__ = [
    'AsyncDatabaseManager',
    'AsyncConnectionPool',
    'DatabaseConfig',
    'QueryResult',
    'ConnectionStats',
    'get_async_db_manager',
    'execute_query',
    'fetch_one',
    'fetch_all'
]