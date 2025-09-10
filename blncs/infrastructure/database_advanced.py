"""
Advanced PostgreSQL Database Architecture
High-performance database layer with connection pooling, read replicas, and query optimization.
"""

import asyncio
import asyncpg
import json
import time
import logging
from typing import Dict, List, Optional, Any, Union, Tuple, AsyncGenerator
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from contextlib import asynccontextmanager
import threading
from concurrent.futures import ThreadPoolExecutor
import weakref

from ..core.structured_logging import StructuredLogger
from ..infrastructure.resilience import resilient, CircuitBreakerError


class DatabaseRole(Enum):
    """Database connection role."""
    PRIMARY = "primary"
    REPLICA = "replica"
    ANALYTICS = "analytics"


class IsolationLevel(Enum):
    """Transaction isolation levels."""
    READ_UNCOMMITTED = "read_uncommitted"
    READ_COMMITTED = "read_committed"  
    REPEATABLE_READ = "repeatable_read"
    SERIALIZABLE = "serializable"


@dataclass
class DatabaseConfig:
    """Database connection configuration."""
    host: str
    port: int = 5432
    database: str = "blncs"
    username: str = "blncs"
    password: str = ""
    ssl_mode: str = "prefer"
    role: DatabaseRole = DatabaseRole.PRIMARY
    
    # Connection pool settings
    min_connections: int = 10
    max_connections: int = 100
    connection_timeout: float = 60.0
    command_timeout: float = 60.0
    server_settings: Dict[str, str] = field(default_factory=dict)
    
    # Performance settings
    statement_cache_size: int = 1024
    max_cached_statement_lifetime: int = 300
    max_cacheable_statement_size: int = 15 * 1024  # 15KB
    
    def to_dsn(self) -> str:
        """Convert to PostgreSQL DSN."""
        dsn_parts = [
            f"postgresql://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"
        ]
        
        params = []
        if self.ssl_mode != "prefer":
            params.append(f"sslmode={self.ssl_mode}")
            
        if params:
            dsn_parts.append("?" + "&".join(params))
            
        return "".join(dsn_parts)


@dataclass
class QueryMetrics:
    """Query execution metrics."""
    query_hash: str
    query: str
    execution_time: float
    rows_affected: int
    connection_id: str
    timestamp: datetime
    isolation_level: Optional[str] = None
    parameters_count: int = 0


class DatabaseMetrics:
    """Database metrics collector."""
    
    def __init__(self):
        self.query_metrics: List[QueryMetrics] = []
        self.connection_metrics: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()
        self.slow_query_threshold = 1.0  # seconds
        
    def record_query(self, metrics: QueryMetrics):
        """Record query execution metrics."""
        with self.lock:
            self.query_metrics.append(metrics)
            
            # Keep only recent metrics (last 1000 queries)
            if len(self.query_metrics) > 1000:
                self.query_metrics = self.query_metrics[-1000:]
                
    def record_connection_metrics(self, connection_id: str, metrics: Dict[str, Any]):
        """Record connection metrics."""
        with self.lock:
            self.connection_metrics[connection_id] = {
                **metrics,
                'last_updated': datetime.now(timezone.utc)
            }
            
    def get_slow_queries(self, threshold: float = None) -> List[QueryMetrics]:
        """Get slow queries above threshold."""
        threshold = threshold or self.slow_query_threshold
        with self.lock:
            return [q for q in self.query_metrics if q.execution_time > threshold]
            
    def get_query_stats(self) -> Dict[str, Any]:
        """Get query statistics."""
        with self.lock:
            if not self.query_metrics:
                return {}
                
            execution_times = [q.execution_time for q in self.query_metrics]
            return {
                'total_queries': len(self.query_metrics),
                'avg_execution_time': sum(execution_times) / len(execution_times),
                'max_execution_time': max(execution_times),
                'min_execution_time': min(execution_times),
                'slow_queries': len([q for q in self.query_metrics 
                                   if q.execution_time > self.slow_query_threshold])
            }


class DatabaseConnection:
    """Wrapper for asyncpg connection with metrics and monitoring."""
    
    def __init__(self, connection: asyncpg.Connection, config: DatabaseConfig, 
                 metrics: DatabaseMetrics):
        self.connection = connection
        self.config = config
        self.metrics = metrics
        self.logger = StructuredLogger("database.connection")
        self.connection_id = f"{id(connection)}"
        self.created_at = datetime.now(timezone.utc)
        self.last_used_at = self.created_at
        self.query_count = 0
        
    async def execute(self, query: str, *args, timeout: float = None) -> str:
        """Execute a query with metrics collection."""
        start_time = time.time()
        query_hash = str(hash(query))
        
        try:
            result = await self.connection.execute(
                query, *args, timeout=timeout or self.config.command_timeout
            )
            
            execution_time = time.time() - start_time
            self.last_used_at = datetime.now(timezone.utc)
            self.query_count += 1
            
            # Extract rows affected from result
            rows_affected = 0
            if isinstance(result, str) and result.startswith(('INSERT', 'UPDATE', 'DELETE')):
                parts = result.split()
                if len(parts) >= 2:
                    try:
                        rows_affected = int(parts[1])
                    except ValueError:
                        pass
                        
            # Record metrics
            self.metrics.record_query(QueryMetrics(
                query_hash=query_hash,
                query=query[:200] + "..." if len(query) > 200 else query,
                execution_time=execution_time,
                rows_affected=rows_affected,
                connection_id=self.connection_id,
                timestamp=datetime.now(timezone.utc),
                parameters_count=len(args)
            ))
            
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error("Query execution failed", extra={
                'query_hash': query_hash,
                'execution_time': execution_time,
                'error': str(e),
                'connection_id': self.connection_id
            })
            raise
            
    async def fetch(self, query: str, *args, timeout: float = None) -> List[asyncpg.Record]:
        """Fetch query results with metrics."""
        start_time = time.time()
        query_hash = str(hash(query))
        
        try:
            result = await self.connection.fetch(
                query, *args, timeout=timeout or self.config.command_timeout
            )
            
            execution_time = time.time() - start_time
            self.last_used_at = datetime.now(timezone.utc)
            self.query_count += 1
            
            self.metrics.record_query(QueryMetrics(
                query_hash=query_hash,
                query=query[:200] + "..." if len(query) > 200 else query,
                execution_time=execution_time,
                rows_affected=len(result),
                connection_id=self.connection_id,
                timestamp=datetime.now(timezone.utc),
                parameters_count=len(args)
            ))
            
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error("Query fetch failed", extra={
                'query_hash': query_hash,
                'execution_time': execution_time,
                'error': str(e)
            })
            raise
            
    async def fetchrow(self, query: str, *args, timeout: float = None) -> Optional[asyncpg.Record]:
        """Fetch single row with metrics."""
        start_time = time.time()
        query_hash = str(hash(query))
        
        try:
            result = await self.connection.fetchrow(
                query, *args, timeout=timeout or self.config.command_timeout
            )
            
            execution_time = time.time() - start_time
            self.last_used_at = datetime.now(timezone.utc)
            self.query_count += 1
            
            self.metrics.record_query(QueryMetrics(
                query_hash=query_hash,
                query=query[:200] + "..." if len(query) > 200 else query,
                execution_time=execution_time,
                rows_affected=1 if result else 0,
                connection_id=self.connection_id,
                timestamp=datetime.now(timezone.utc),
                parameters_count=len(args)
            ))
            
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error("Query fetchrow failed", extra={
                'query_hash': query_hash,
                'execution_time': execution_time,
                'error': str(e)
            })
            raise
            
    async def executemany(self, command: str, args: List[Tuple], timeout: float = None) -> None:
        """Execute many commands with metrics."""
        start_time = time.time()
        query_hash = str(hash(command))
        
        try:
            await self.connection.executemany(
                command, args, timeout=timeout or self.config.command_timeout
            )
            
            execution_time = time.time() - start_time
            self.last_used_at = datetime.now(timezone.utc)
            self.query_count += 1
            
            self.metrics.record_query(QueryMetrics(
                query_hash=query_hash,
                query=command[:200] + "..." if len(command) > 200 else command,
                execution_time=execution_time,
                rows_affected=len(args),
                connection_id=self.connection_id,
                timestamp=datetime.now(timezone.utc),
                parameters_count=len(args[0]) if args else 0
            ))
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error("Query executemany failed", extra={
                'query_hash': query_hash,
                'execution_time': execution_time,
                'error': str(e)
            })
            raise
            
    def transaction(self, *, isolation: IsolationLevel = IsolationLevel.READ_COMMITTED,
                   readonly: bool = False, deferrable: bool = False):
        """Create a transaction with specified isolation level."""
        isolation_map = {
            IsolationLevel.READ_UNCOMMITTED: 'read_uncommitted',
            IsolationLevel.READ_COMMITTED: 'read_committed',
            IsolationLevel.REPEATABLE_READ: 'repeatable_read',
            IsolationLevel.SERIALIZABLE: 'serializable'
        }
        
        return self.connection.transaction(
            isolation=isolation_map[isolation],
            readonly=readonly,
            deferrable=deferrable
        )
        
    async def close(self):
        """Close the connection."""
        try:
            await self.connection.close()
        except Exception as e:
            self.logger.warning("Error closing connection", extra={'error': str(e)})


class DatabasePool:
    """Advanced database connection pool with load balancing and failover."""
    
    def __init__(self, configs: List[DatabaseConfig]):
        self.configs = {config.role: config for config in configs}
        self.pools: Dict[DatabaseRole, asyncpg.Pool] = {}
        self.metrics = DatabaseMetrics()
        self.logger = StructuredLogger("database.pool")
        self._initialized = False
        
    async def initialize(self):
        """Initialize connection pools for all database roles."""
        for role, config in self.configs.items():
            try:
                # Custom connection factory to wrap connections
                async def connection_factory():
                    conn = await asyncpg.connect(
                        host=config.host,
                        port=config.port,
                        user=config.username,
                        password=config.password,
                        database=config.database,
                        ssl=config.ssl_mode,
                        timeout=config.connection_timeout,
                        command_timeout=config.command_timeout,
                        server_settings=config.server_settings,
                        statement_cache_size=config.statement_cache_size,
                        max_cached_statement_lifetime=config.max_cached_statement_lifetime,
                        max_cacheable_statement_size=config.max_cacheable_statement_size
                    )
                    return DatabaseConnection(conn, config, self.metrics)
                
                pool = await asyncpg.create_pool(
                    host=config.host,
                    port=config.port,
                    user=config.username,
                    password=config.password,
                    database=config.database,
                    ssl=config.ssl_mode,
                    min_size=config.min_connections,
                    max_size=config.max_connections,
                    timeout=config.connection_timeout,
                    command_timeout=config.command_timeout,
                    server_settings=config.server_settings,
                    statement_cache_size=config.statement_cache_size,
                    max_cached_statement_lifetime=config.max_cached_statement_lifetime,
                    max_cacheable_statement_size=config.max_cacheable_statement_size
                )
                
                self.pools[role] = pool
                
                self.logger.info("Initialized database pool", extra={
                    'role': role.value,
                    'host': config.host,
                    'min_connections': config.min_connections,
                    'max_connections': config.max_connections
                })
                
            except Exception as e:
                self.logger.error("Failed to initialize database pool", extra={
                    'role': role.value,
                    'error': str(e)
                })
                raise
                
        self._initialized = True
        
    async def close(self):
        """Close all connection pools."""
        for role, pool in self.pools.items():
            try:
                await pool.close()
                self.logger.info("Closed database pool", extra={'role': role.value})
            except Exception as e:
                self.logger.error("Error closing pool", extra={
                    'role': role.value,
                    'error': str(e)
                })
                
        self.pools.clear()
        self._initialized = False
        
    @asynccontextmanager
    async def acquire(self, role: DatabaseRole = DatabaseRole.PRIMARY):
        """Acquire a connection from the pool."""
        if not self._initialized:
            raise RuntimeError("Database pool not initialized")
            
        if role not in self.pools:
            # Fallback to primary if role not available
            role = DatabaseRole.PRIMARY
            
        pool = self.pools[role]
        
        async with pool.acquire() as raw_connection:
            connection = DatabaseConnection(raw_connection, self.configs[role], self.metrics)
            try:
                yield connection
            finally:
                # Update connection metrics
                self.metrics.record_connection_metrics(connection.connection_id, {
                    'role': role.value,
                    'query_count': connection.query_count,
                    'created_at': connection.created_at,
                    'last_used_at': connection.last_used_at
                })
                
    @resilient(
        circuit_breaker_name="database_execute",
        retry_name="database_retry",
        circuit_breaker={"failure_threshold": 5, "recovery_timeout": 60},
        retry={"max_attempts": 3, "base_delay": 0.5}
    )
    async def execute(self, query: str, *args, role: DatabaseRole = DatabaseRole.PRIMARY) -> str:
        """Execute a query with automatic retry and circuit breaking."""
        async with self.acquire(role) as connection:
            return await connection.execute(query, *args)
            
    @resilient(
        circuit_breaker_name="database_fetch",
        retry_name="database_retry"
    )
    async def fetch(self, query: str, *args, 
                   role: DatabaseRole = DatabaseRole.REPLICA) -> List[asyncpg.Record]:
        """Fetch query results with automatic retry."""
        async with self.acquire(role) as connection:
            return await connection.fetch(query, *args)
            
    @resilient(
        circuit_breaker_name="database_fetchrow", 
        retry_name="database_retry"
    )
    async def fetchrow(self, query: str, *args,
                      role: DatabaseRole = DatabaseRole.REPLICA) -> Optional[asyncpg.Record]:
        """Fetch single row with automatic retry."""
        async with self.acquire(role) as connection:
            return await connection.fetchrow(query, *args)
            
    async def batch_execute(self, queries: List[Tuple[str, Tuple]], 
                           role: DatabaseRole = DatabaseRole.PRIMARY) -> List[Any]:
        """Execute multiple queries in a single transaction."""
        results = []
        
        async with self.acquire(role) as connection:
            async with connection.transaction():
                for query, args in queries:
                    result = await connection.execute(query, *args)
                    results.append(result)
                    
        return results
        
    async def bulk_insert(self, table: str, columns: List[str], 
                         data: List[List[Any]], role: DatabaseRole = DatabaseRole.PRIMARY,
                         batch_size: int = 1000) -> int:
        """Efficient bulk insert using COPY."""
        total_inserted = 0
        
        async with self.acquire(role) as connection:
            # Process in batches
            for i in range(0, len(data), batch_size):
                batch = data[i:i + batch_size]
                
                # Use COPY for efficient bulk insert
                copy_query = f"COPY {table}({', '.join(columns)}) FROM STDIN"
                
                async with connection.connection.copy(copy_query) as copy:
                    for row in batch:
                        await copy.write_row(row)
                        
                total_inserted += len(batch)
                
        return total_inserted
        
    async def analyze_performance(self) -> Dict[str, Any]:
        """Analyze database performance metrics."""
        query_stats = self.metrics.get_query_stats()
        slow_queries = self.metrics.get_slow_queries()
        
        # Get connection pool stats
        pool_stats = {}
        for role, pool in self.pools.items():
            pool_stats[role.value] = {
                'size': pool.get_size(),
                'min_size': pool.get_min_size(),
                'max_size': pool.get_max_size(),
                'idle_size': pool.get_idle_size()
            }
            
        return {
            'query_statistics': query_stats,
            'slow_queries': [
                {
                    'query': q.query,
                    'execution_time': q.execution_time,
                    'timestamp': q.timestamp.isoformat()
                } for q in slow_queries[:10]  # Top 10 slow queries
            ],
            'pool_statistics': pool_stats,
            'connection_metrics': dict(self.metrics.connection_metrics)
        }


class DatabaseManager:
    """High-level database manager with advanced features."""
    
    def __init__(self):
        self.pool: Optional[DatabasePool] = None
        self.logger = StructuredLogger("database.manager")
        
    async def initialize(self, configs: List[DatabaseConfig]):
        """Initialize database manager with multiple database configurations."""
        self.pool = DatabasePool(configs)
        await self.pool.initialize()
        
        self.logger.info("Database manager initialized", extra={
            'database_roles': [config.role.value for config in configs]
        })
        
    async def close(self):
        """Close database manager."""
        if self.pool:
            await self.pool.close()
            self.pool = None
            self.logger.info("Database manager closed")
            
    def get_pool(self) -> DatabasePool:
        """Get database pool instance."""
        if not self.pool:
            raise RuntimeError("Database manager not initialized")
        return self.pool
        
    async def health_check(self) -> Dict[str, Any]:
        """Perform comprehensive database health check."""
        if not self.pool:
            return {"status": "not_initialized"}
            
        health_status = {
            "status": "healthy",
            "checks": {},
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        # Test each database role
        for role in self.pool.pools.keys():
            try:
                async with self.pool.acquire(role) as connection:
                    start_time = time.time()
                    await connection.fetchrow("SELECT 1")
                    response_time = time.time() - start_time
                    
                    health_status["checks"][role.value] = {
                        "status": "healthy",
                        "response_time_ms": response_time * 1000
                    }
                    
            except Exception as e:
                health_status["checks"][role.value] = {
                    "status": "unhealthy",
                    "error": str(e)
                }
                health_status["status"] = "degraded"
                
        return health_status


# Global database manager instance
_database_manager: Optional[DatabaseManager] = None


async def get_database_manager() -> DatabaseManager:
    """Get global database manager instance."""
    global _database_manager
    if _database_manager is None:
        _database_manager = DatabaseManager()
    return _database_manager


async def initialize_database(configs: List[DatabaseConfig]):
    """Initialize global database manager."""
    manager = await get_database_manager()
    await manager.initialize(configs)