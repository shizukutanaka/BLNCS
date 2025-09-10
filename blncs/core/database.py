"""
Optimized database operations for BLNCS
Provides connection pooling, query caching, and transaction management.
"""

import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from queue import Queue, Empty
import json

from .logger import get_logger
from .config_manager import get_config_manager
from .fast_cache import get_cache
from .metrics import get_metrics_collector, increment_counter, set_gauge


class DatabasePool:
    """SQLite connection pool with optimizations"""
    
    def __init__(self, db_path: str, max_connections: int = 20):
        self.logger = get_logger(__name__)
        self.db_path = db_path
        self.max_connections = max_connections
        self._connections = Queue(maxsize=max_connections)
        self._lock = threading.Lock()
        self._created_connections = 0
        
        # Ensure database directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database schema
        self._initialize_db()
    
    def _initialize_db(self):
        """Initialize database with optimized schema"""
        conn = self._create_connection()
        try:
            cursor = conn.cursor()
            
            # Enable WAL mode for better concurrency
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA cache_size=10000")
            cursor.execute("PRAGMA temp_store=MEMORY")
            
            # Create tables with proper indexes
            cursor.executescript("""
                -- Metrics table for time-series data
                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric_name TEXT NOT NULL,
                    value REAL NOT NULL,
                    labels TEXT,
                    timestamp INTEGER NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_metrics_name_time 
                    ON metrics(metric_name, timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_metrics_timestamp 
                    ON metrics(timestamp DESC);
                
                -- Events table for system events
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    details TEXT,
                    timestamp INTEGER NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_events_type_time 
                    ON events(event_type, timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_events_severity 
                    ON events(severity, timestamp DESC);
                
                -- Channel states for Lightning channels
                CREATE TABLE IF NOT EXISTS channel_states (
                    channel_id TEXT PRIMARY KEY,
                    peer_id TEXT NOT NULL,
                    capacity INTEGER NOT NULL,
                    local_balance INTEGER NOT NULL,
                    remote_balance INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    last_update INTEGER NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_channels_peer 
                    ON channel_states(peer_id);
                CREATE INDEX IF NOT EXISTS idx_channels_state 
                    ON channel_states(state);
                
                -- Payment history
                CREATE TABLE IF NOT EXISTS payments (
                    payment_hash TEXT PRIMARY KEY,
                    payment_preimage TEXT,
                    amount INTEGER NOT NULL,
                    fee INTEGER,
                    status TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_payments_status 
                    ON payments(status, timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_payments_direction 
                    ON payments(direction, timestamp DESC);
                
                -- Key-value store for configuration and state
                CREATE TABLE IF NOT EXISTS kv_store (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    expires_at INTEGER,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_kv_expires 
                    ON kv_store(expires_at) WHERE expires_at IS NOT NULL;
                
                -- Discovered Lightning Network nodes
                CREATE TABLE IF NOT EXISTS discovered_nodes (
                    pubkey TEXT PRIMARY KEY,
                    alias TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    channel_count INTEGER DEFAULT 0,
                    capacity_btc REAL DEFAULT 0.0,
                    connectivity_score REAL DEFAULT 0.0,
                    discovery_method TEXT DEFAULT 'unknown',
                    last_seen INTEGER NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_discovered_nodes_last_seen 
                    ON discovered_nodes(last_seen DESC);
                CREATE INDEX IF NOT EXISTS idx_discovered_nodes_score 
                    ON discovered_nodes(connectivity_score DESC);
            """)
            
            conn.commit()
        finally:
            self._connections.put(conn)
    
    def _create_connection(self) -> sqlite3.Connection:
        """Create a new database connection"""
        conn = sqlite3.connect(
            self.db_path,
            timeout=30.0,
            isolation_level=None,  # Autocommit mode
            check_same_thread=False
        )
        conn.row_factory = sqlite3.Row
        return conn
    
    @contextmanager
    def get_connection(self):
        """Get a connection from the pool"""
        conn = None
        try:
            # Try to get existing connection
            try:
                conn = self._connections.get(block=False)
            except Empty:
                # Create new connection if under limit
                with self._lock:
                    if self._created_connections < self.max_connections:
                        conn = self._create_connection()
                        self._created_connections += 1
                    else:
                        # Wait for available connection
                        conn = self._connections.get(block=True, timeout=10.0)
            
            yield conn
        finally:
            if conn:
                self._connections.put(conn)
    
    def close_all(self):
        """Close all connections in the pool"""
        while not self._connections.empty():
            try:
                conn = self._connections.get_nowait()
                conn.close()
            except Empty:
                break


class DatabaseManager:
    """Optimized database manager with caching and batch operations"""
    
    def __init__(self, db_path: Optional[str] = None):
        self.logger = get_logger(__name__)
        self.config_manager = get_config_manager()
        self.cache = get_cache()
        
        # Database path
        if db_path is None:
            db_path = self.config_manager.get('database.path', 'data/blncs.db')
        
        self.db_path = db_path
        self.pool = DatabasePool(db_path)
        
        # Batch operation queue
        self._batch_queue = []
        self._batch_lock = threading.Lock()
        self._batch_thread = None
        self._stop_batch = threading.Event()
        
        # Start batch processor
        self._start_batch_processor()
    
    def _start_batch_processor(self):
        """Start background batch processor"""
        if not self._batch_thread or not self._batch_thread.is_alive():
            self._stop_batch.clear()
            self._batch_thread = threading.Thread(
                target=self._batch_processor,
                daemon=True,
                name="DatabaseBatch"
            )
            self._batch_thread.start()
    
    def _batch_processor(self):
        """Process batched database operations"""
        while not self._stop_batch.is_set():
            try:
                time.sleep(1)  # Process batch every second
                
                with self._batch_lock:
                    if not self._batch_queue:
                        continue
                    
                    batch = self._batch_queue[:100]  # Process up to 100 items
                    self._batch_queue = self._batch_queue[100:]
                
                # Execute batch operations
                with self.pool.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("BEGIN TRANSACTION")
                    
                    try:
                        for operation in batch:
                            cursor.execute(operation['query'], operation['params'])
                        cursor.execute("COMMIT")
                    except Exception as e:
                        cursor.execute("ROLLBACK")
                        self.logger.error(f"Batch operation failed: {e}")
                        
            except Exception as e:
                self.logger.error(f"Batch processor error: {e}")
    
    def stop(self):
        """Stop the database manager"""
        self._stop_batch.set()
        if self._batch_thread:
            self._batch_thread.join(timeout=2.0)
        self.pool.close_all()
    
    # Metrics operations
    def record_metric(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Record a metric value"""
        timestamp = int(time.time())
        labels_json = json.dumps(labels) if labels else None
        
        with self._batch_lock:
            self._batch_queue.append({
                'query': "INSERT INTO metrics (metric_name, value, labels, timestamp) VALUES (?, ?, ?, ?)",
                'params': (name, value, labels_json, timestamp)
            })
    
    def get_metrics(self, name: str, start_time: Optional[int] = None, 
                   end_time: Optional[int] = None, limit: int = 1000) -> List[Dict]:
        """Get metrics within time range"""
        # Try cache first
        cache_key = f"metrics:{name}:{start_time}:{end_time}:{limit}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        
        query = "SELECT * FROM metrics WHERE metric_name = ?"
        params = [name]
        
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        with self.pool.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            results = [dict(row) for row in cursor.fetchall()]
        
        # Cache for 60 seconds
        self.cache.set(cache_key, results, ttl=60)
        return results
    
    # Event operations
    def record_event(self, event_type: str, severity: str, message: str, 
                    details: Optional[Dict] = None):
        """Record a system event"""
        timestamp = int(time.time())
        details_json = json.dumps(details) if details else None
        
        with self._batch_lock:
            self._batch_queue.append({
                'query': "INSERT INTO events (event_type, severity, message, details, timestamp) VALUES (?, ?, ?, ?, ?)",
                'params': (event_type, severity, message, details_json, timestamp)
            })
    
    def get_recent_events(self, event_type: Optional[str] = None, 
                         severity: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """Get recent events"""
        query = "SELECT * FROM events WHERE 1=1"
        params = []
        
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        with self.pool.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    # Channel operations
    def update_channel_state(self, channel_id: str, peer_id: str, capacity: int,
                            local_balance: int, remote_balance: int, state: str):
        """Update channel state"""
        timestamp = int(time.time())
        
        with self.pool.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO channel_states 
                (channel_id, peer_id, capacity, local_balance, remote_balance, state, last_update, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (channel_id, peer_id, capacity, local_balance, remote_balance, state, timestamp))
    
    def get_channel_states(self, state: Optional[str] = None) -> List[Dict]:
        """Get channel states"""
        query = "SELECT * FROM channel_states"
        params = []
        
        if state:
            query += " WHERE state = ?"
            params.append(state)
        
        query += " ORDER BY last_update DESC"
        
        with self.pool.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    # Key-value operations
    def set_kv(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set key-value pair with optional TTL"""
        value_json = json.dumps(value)
        expires_at = int(time.time()) + ttl if ttl else None
        
        with self.pool.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO kv_store (key, value, expires_at, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            """, (key, value_json, expires_at))
    
    def get_kv(self, key: str) -> Optional[Any]:
        """Get key-value pair"""
        with self.pool.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT value FROM kv_store 
                WHERE key = ? AND (expires_at IS NULL OR expires_at > ?)
            """, (key, int(time.time())))
            
            row = cursor.fetchone()
            if row:
                return json.loads(row['value'])
            return None
    
    def delete_kv(self, key: str):
        """Delete key-value pair"""
        with self.pool.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM kv_store WHERE key = ?", (key,))
    
    # Cleanup operations
    def cleanup_old_data(self, days: int = 30):
        """Clean up old data"""
        cutoff_time = int(time.time()) - (days * 86400)
        
        with self.pool.get_connection() as conn:
            cursor = conn.cursor()
            
            # Clean old metrics
            cursor.execute("DELETE FROM metrics WHERE timestamp < ?", (cutoff_time,))
            metrics_deleted = cursor.rowcount
            
            # Clean old events
            cursor.execute("DELETE FROM events WHERE timestamp < ?", (cutoff_time,))
            events_deleted = cursor.rowcount
            
            # Clean expired KV pairs
            cursor.execute("DELETE FROM kv_store WHERE expires_at IS NOT NULL AND expires_at < ?", 
                         (int(time.time()),))
            kv_deleted = cursor.rowcount
            
            # Vacuum to reclaim space
            cursor.execute("VACUUM")
            
            self.logger.info(f"Cleanup: {metrics_deleted} metrics, {events_deleted} events, {kv_deleted} KV pairs")
            
            return {
                'metrics_deleted': metrics_deleted,
                'events_deleted': events_deleted,
                'kv_deleted': kv_deleted
            }
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        with self.pool.get_connection() as conn:
            cursor = conn.cursor()
            
            # Get table sizes
            cursor.execute("""
                SELECT 
                    'metrics' as table_name,
                    COUNT(*) as row_count,
                    MIN(timestamp) as oldest_timestamp,
                    MAX(timestamp) as newest_timestamp
                FROM metrics
                UNION ALL
                SELECT 
                    'events' as table_name,
                    COUNT(*) as row_count,
                    MIN(timestamp) as oldest_timestamp,
                    MAX(timestamp) as newest_timestamp
                FROM events
                UNION ALL
                SELECT 
                    'channel_states' as table_name,
                    COUNT(*) as row_count,
                    MIN(last_update) as oldest_timestamp,
                    MAX(last_update) as newest_timestamp
                FROM channel_states
                UNION ALL
                SELECT 
                    'payments' as table_name,
                    COUNT(*) as row_count,
                    MIN(timestamp) as oldest_timestamp,
                    MAX(timestamp) as newest_timestamp
                FROM payments
            """)
            
            stats = {}
            for row in cursor.fetchall():
                stats[row['table_name']] = {
                    'row_count': row['row_count'],
                    'oldest_timestamp': row['oldest_timestamp'],
                    'newest_timestamp': row['newest_timestamp']
                }
            
            # Get database file size
            db_file = Path(self.db_path)
            if db_file.exists():
                stats['file_size_mb'] = round(db_file.stat().st_size / (1024 * 1024), 2)
            
            # Get batch queue size
            with self._batch_lock:
                stats['batch_queue_size'] = len(self._batch_queue)
            
            return stats
    
    def optimize_database(self) -> Dict[str, Any]:
        """Advanced database optimization operations"""
        start_time = time.time()
        self.logger.info("Starting advanced database optimization")
        
        optimization_results = {}
        
        with self.pool.get_connection() as conn:
            cursor = conn.cursor()
            
            try:
                # 1. Analyze and optimize query performance
                self.logger.info("Analyzing query performance...")
                cursor.execute("ANALYZE")
                optimization_results['analyze_completed'] = True
                
                # 2. Rebuild indexes for better performance
                self.logger.info("Rebuilding indexes...")
                cursor.execute("REINDEX")
                optimization_results['reindex_completed'] = True
                
                # 3. Update database statistics
                cursor.execute("PRAGMA optimize")
                optimization_results['optimize_completed'] = True
                
                # 4. Check for and fix database integrity
                self.logger.info("Checking database integrity...")
                cursor.execute("PRAGMA integrity_check")
                integrity_result = cursor.fetchone()
                optimization_results['integrity_check'] = integrity_result[0] if integrity_result else 'unknown'
                
                # 5. Optimize cache and memory settings
                cursor.execute("PRAGMA cache_size=20000")  # Increase cache size
                cursor.execute("PRAGMA mmap_size=268435456")  # 256MB memory mapping
                optimization_results['memory_optimized'] = True
                
                # 6. Get performance metrics before/after
                optimization_results['optimization_duration'] = time.time() - start_time
                
                self.logger.info(f"Database optimization completed in {optimization_results['optimization_duration']:.2f}s")
                
                # Update metrics
                increment_counter('database_optimizations_total')
                set_gauge('database_optimization_duration_seconds', optimization_results['optimization_duration'])
                
                return optimization_results
                
            except Exception as e:
                self.logger.error(f"Database optimization failed: {e}")
                optimization_results['error'] = str(e)
                return optimization_results
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get database performance metrics"""
        with self.pool.get_connection() as conn:
            cursor = conn.cursor()
            
            # Connection pool metrics
            pool_metrics = {
                'active_connections': self.pool._created_connections,
                'max_connections': self.pool.max_connections,
                'pool_utilization': self.pool._created_connections / self.pool.max_connections
            }
            
            # Query performance metrics
            try:
                # Get cache hit ratio
                cursor.execute("PRAGMA cache_size")
                cache_size = cursor.fetchone()[0]
                
                cursor.execute("PRAGMA page_count")
                page_count = cursor.fetchone()[0]
                
                cursor.execute("PRAGMA page_size")
                page_size = cursor.fetchone()[0]
                
                query_metrics = {
                    'cache_size': cache_size,
                    'page_count': page_count,
                    'page_size': page_size,
                    'database_size_mb': (page_count * page_size) / (1024 * 1024)
                }
                
                # Batch processing metrics
                with self._batch_lock:
                    batch_metrics = {
                        'batch_queue_size': len(self._batch_queue),
                        'batch_size': self.batch_size,
                        'batch_timeout': self.batch_timeout
                    }
                
                return {
                    'connection_pool': pool_metrics,
                    'query_performance': query_metrics,
                    'batch_processing': batch_metrics
                }
                
            except Exception as e:
                self.logger.error(f"Failed to get performance metrics: {e}")
                return {'error': str(e)}
    
    def auto_maintenance(self) -> Dict[str, Any]:
        """Perform automatic database maintenance"""
        self.logger.info("Starting automatic database maintenance")
        maintenance_results = {}
        
        try:
            # 1. Clean old data
            cleanup_results = self.cleanup_old_data()
            maintenance_results['cleanup'] = cleanup_results
            
            # 2. Optimize database if needed
            stats = self.get_database_stats()
            total_records = sum(table.get('row_count', 0) for table in stats.values() if isinstance(table, dict))
            
            # Optimize if we have a significant amount of data
            if total_records > 10000:
                opt_results = self.optimize_database()
                maintenance_results['optimization'] = opt_results
            
            # 3. Update performance metrics
            perf_metrics = self.get_performance_metrics()
            maintenance_results['performance_metrics'] = perf_metrics
            
            # 4. Log maintenance completion
            self.logger.info("Automatic database maintenance completed successfully")
            maintenance_results['success'] = True
            
            # Update metrics
            increment_counter('database_maintenance_total')
            
            return maintenance_results
            
        except Exception as e:
            self.logger.error(f"Database maintenance failed: {e}")
            maintenance_results['error'] = str(e)
            maintenance_results['success'] = False
            return maintenance_results


# Global database manager instance
_db_manager = None

def get_database_manager() -> DatabaseManager:
    """Get global database manager instance"""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
    return _db_manager

def stop_database_manager():
    """Stop the global database manager"""
    global _db_manager
    if _db_manager:
        _db_manager.stop()
        _db_manager = None