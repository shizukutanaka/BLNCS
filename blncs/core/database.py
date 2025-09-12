"""
Unified Database System for BLNCS
Combines all database functionality into a single, optimized module.
"""

import sqlite3
import threading
import time
import json
from typing import Dict, List, Any, Optional, Union, Tuple, Callable
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime, timedelta
import hashlib

# Optional async support
HAS_AIOSQLITE = False
try:
    import asyncio
    import aiosqlite
    from contextlib import asynccontextmanager
    HAS_AIOSQLITE = True
except ImportError:
    pass  # Graceful degradation to sync-only

from .logger import get_logger
from .config_manager import get_config_manager

logger = get_logger(__name__)

@dataclass
class QueryStats:
    """Query statistics for optimization."""
    query_hash: str
    query: str
    execution_count: int = 0
    total_time_ms: float = 0
    avg_time_ms: float = 0
    last_executed: datetime = field(default_factory=datetime.now)

class DatabaseManager:
    """Unified database manager with connection pooling and optimization."""
    
    def __init__(self, db_path: str = "blncs.db", pool_size: int = 10):
        """Initialize database manager."""
        self.db_path = db_path
        self.pool_size = pool_size
        self.connections = []
        self.available_connections = []
        self.lock = threading.RLock()
        self.query_stats: Dict[str, QueryStats] = {}
        self.logger = get_logger(__name__)
        
        # Performance optimizations
        self._query_cache = {}
        self._cache_ttl = {}
        self._cache_lock = threading.RLock()
        
        # Migration tracking
        self.migrations_table = "schema_migrations"
        
        # Initialize connection pool
        self._init_pool()
        
        # Create tables if needed
        self._init_database()
    
    def _init_pool(self):
        """Initialize connection pool with performance optimizations."""
        for _ in range(self.pool_size):
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            # Performance optimizations
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL") 
            conn.execute("PRAGMA cache_size=20000")  # Increased cache
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA mmap_size=268435456")  # 256MB memory map
            conn.execute("PRAGMA optimize")  # Auto-optimize on startup
            self.connections.append(conn)
            self.available_connections.append(conn)
    
    def _init_database(self):
        """Initialize database schema."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Migrations table
            cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.migrations_table} (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Key-value store
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS kv_store (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Transactions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT NOT NULL,
                    data TEXT,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP
                )
            """)
            
            # Performance metrics
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric_name TEXT NOT NULL,
                    metric_value REAL,
                    tags TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_kv_key ON kv_store(key)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_transactions_created ON transactions(created_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_metrics_name ON metrics(metric_name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp)")
            
            conn.commit()
    
    @contextmanager
    def get_connection(self):
        """Get a connection from the pool."""
        conn = None
        try:
            with self.lock:
                if self.available_connections:
                    conn = self.available_connections.pop()
                else:
                    # All connections in use, create temporary one
                    conn = sqlite3.connect(self.db_path, check_same_thread=False)
                    conn.row_factory = sqlite3.Row
            
            yield conn
            
        finally:
            if conn:
                with self.lock:
                    if conn in self.connections:
                        self.available_connections.append(conn)
                    else:
                        conn.close()  # Close temporary connection
    
    def execute(self, query: str, params: Optional[Tuple] = None) -> List[sqlite3.Row]:
        """Execute a query and return results."""
        start_time = time.time()
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            if query.strip().upper().startswith(('INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER')):
                conn.commit()
                result = []
            else:
                result = cursor.fetchall()
        
        # Track query statistics
        self._track_query_stats(query, time.time() - start_time)
        
        return result
    
    def execute_many(self, query: str, params_list: List[Tuple]) -> int:
        """Execute multiple queries efficiently."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany(query, params_list)
            conn.commit()
            return cursor.rowcount
    
    def _track_query_stats(self, query: str, execution_time: float):
        """Track query execution statistics."""
        query_hash = hashlib.md5(query.encode()).hexdigest()
        
        if query_hash not in self.query_stats:
            self.query_stats[query_hash] = QueryStats(
                query_hash=query_hash,
                query=query[:100]  # Store first 100 chars
            )
        
        stats = self.query_stats[query_hash]
        stats.execution_count += 1
        stats.total_time_ms += execution_time * 1000
        stats.avg_time_ms = stats.total_time_ms / stats.execution_count
        stats.last_executed = datetime.now()
    
    # Key-Value Operations
    def get(self, key: str) -> Optional[Any]:
        """Get value from key-value store with caching."""
        # Check cache first
        with self._cache_lock:
            if key in self._query_cache:
                # Check TTL
                if time.time() < self._cache_ttl.get(key, 0):
                    return self._query_cache[key]
                else:
                    # Expired, remove from cache
                    self._query_cache.pop(key, None)
                    self._cache_ttl.pop(key, None)
        
        result = self.execute(
            "SELECT value FROM kv_store WHERE key = ?",
            (key,)
        )
        
        value = None
        if result:
            try:
                value = json.loads(result[0]['value'])
            except json.JSONDecodeError:
                value = result[0]['value']
        
        # Cache the result for 60 seconds
        if value is not None:
            with self._cache_lock:
                self._query_cache[key] = value
                self._cache_ttl[key] = time.time() + 60
        
        return value
    
    def set(self, key: str, value: Any) -> bool:
        """Set value in key-value store and update cache."""
        value_str = json.dumps(value) if not isinstance(value, str) else value
        
        self.execute("""
            INSERT OR REPLACE INTO kv_store (key, value, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
        """, (key, value_str))
        
        # Update cache
        with self._cache_lock:
            self._query_cache[key] = value
            self._cache_ttl[key] = time.time() + 60
        
        return True
    
    def delete(self, key: str) -> bool:
        """Delete key from key-value store and cache."""
        self.execute("DELETE FROM kv_store WHERE key = ?", (key,))
        
        # Remove from cache
        with self._cache_lock:
            self._query_cache.pop(key, None)
            self._cache_ttl.pop(key, None)
        
        return True
    
    def get_all(self, prefix: str = "") -> Dict[str, Any]:
        """Get all key-value pairs with optional prefix."""
        if prefix:
            result = self.execute(
                "SELECT key, value FROM kv_store WHERE key LIKE ?",
                (f"{prefix}%",)
            )
        else:
            result = self.execute("SELECT key, value FROM kv_store")
        
        data = {}
        for row in result:
            try:
                data[row['key']] = json.loads(row['value'])
            except json.JSONDecodeError:
                data[row['key']] = row['value']
        return data
    
    # Transaction Operations
    def record_transaction(self, tx_type: str, data: Dict[str, Any]) -> int:
        """Record a transaction."""
        result = self.execute(
            "INSERT INTO transactions (type, data) VALUES (?, ?)",
            (tx_type, json.dumps(data))
        )
        return self.execute("SELECT last_insert_rowid()")[0][0]
    
    def update_transaction_status(self, tx_id: int, status: str):
        """Update transaction status."""
        self.execute(
            "UPDATE transactions SET status = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?",
            (status, tx_id)
        )
    
    def get_recent_transactions(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent transactions."""
        result = self.execute(
            "SELECT * FROM transactions ORDER BY created_at DESC LIMIT ?",
            (limit,)
        )
        return [dict(row) for row in result]
    
    # Metrics Operations
    def record_metric(self, name: str, value: float, tags: Optional[Dict[str, str]] = None):
        """Record a metric."""
        tags_str = json.dumps(tags) if tags else None
        self.execute(
            "INSERT INTO metrics (metric_name, metric_value, tags) VALUES (?, ?, ?)",
            (name, value, tags_str)
        )
    
    def get_metrics(self, name: str, hours: int = 24) -> List[Dict[str, Any]]:
        """Get metrics for the specified time period."""
        cutoff = datetime.now() - timedelta(hours=hours)
        result = self.execute(
            "SELECT * FROM metrics WHERE metric_name = ? AND timestamp > ? ORDER BY timestamp",
            (name, cutoff)
        )
        return [dict(row) for row in result]
    
    # Migration Operations
    def run_migrations(self, migrations: List[Tuple[int, str, str]]):
        """Run database migrations.
        
        Args:
            migrations: List of (version, name, sql) tuples
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Get current version
            cursor.execute(f"SELECT MAX(version) FROM {self.migrations_table}")
            current_version = cursor.fetchone()[0] or 0
            
            for version, name, sql in migrations:
                if version > current_version:
                    self.logger.info(f"Running migration {version}: {name}")
                    cursor.executescript(sql)
                    cursor.execute(
                        f"INSERT INTO {self.migrations_table} (version, name) VALUES (?, ?)",
                        (version, name)
                    )
            
            conn.commit()
    
    # Optimization Operations
    def optimize(self):
        """Optimize database performance."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Vacuum and analyze
            cursor.execute("VACUUM")
            cursor.execute("ANALYZE")
            
            # Clean old metrics (keep 30 days)
            cutoff = datetime.now() - timedelta(days=30)
            cursor.execute("DELETE FROM metrics WHERE timestamp < ?", (cutoff,))
            
            # Clean old completed transactions (keep 90 days)
            cutoff = datetime.now() - timedelta(days=90)
            cursor.execute(
                "DELETE FROM transactions WHERE status = 'completed' AND completed_at < ?",
                (cutoff,)
            )
            
            conn.commit()
            self.logger.info("Database optimization completed")
    
    def get_slow_queries(self, threshold_ms: float = 100) -> List[QueryStats]:
        """Get queries slower than threshold."""
        slow_queries = [
            stats for stats in self.query_stats.values()
            if stats.avg_time_ms > threshold_ms
        ]
        return sorted(slow_queries, key=lambda x: x.avg_time_ms, reverse=True)
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Table sizes
            tables = ['kv_store', 'transactions', 'metrics']
            table_stats = {}
            for table in tables:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                table_stats[table] = cursor.fetchone()[0]
            
            # Database file size
            db_size = Path(self.db_path).stat().st_size if Path(self.db_path).exists() else 0
            
            return {
                "database_size_mb": db_size / (1024 * 1024),
                "connection_pool_size": self.pool_size,
                "available_connections": len(self.available_connections),
                "table_row_counts": table_stats,
                "slow_queries": len(self.get_slow_queries()),
                "total_queries_tracked": len(self.query_stats)
            }
    
    def close(self):
        """Close all database connections."""
        with self.lock:
            for conn in self.connections:
                conn.close()
            self.connections.clear()
            self.available_connections.clear()

# Global database manager instance
_db_manager: Optional[DatabaseManager] = None

def get_database(db_path: str = "blncs.db") -> DatabaseManager:
    """Get or create global database manager instance."""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager(db_path)
    return _db_manager
