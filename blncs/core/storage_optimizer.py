"""
Storage Access Optimization System
Optimized database and file I/O operations with caching, batching, and async support.
"""

import sqlite3
import json
import asyncio
import threading
from typing import Dict, Any, List, Optional, Union, Callable
from datetime import datetime, timedelta
from collections import defaultdict, deque
from contextlib import contextmanager
from pathlib import Path
import time

from .logger import get_logger
from .config_manager import get_config_manager
from .fast_cache import get_fast_cache


class BatchedOperations:
    """Batched database operations for better performance"""
    
    def __init__(self, db_path: str, batch_size: int = 100, flush_interval: float = 1.0):
        self.db_path = db_path
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        
        self.pending_inserts = defaultdict(list)
        self.pending_updates = defaultdict(list)
        self.pending_deletes = defaultdict(list)
        
        self._lock = threading.RLock()
        self._last_flush = time.time()
        self._auto_flush_thread = None
        self._stop_flush = threading.Event()
        
        self.logger = get_logger(__name__)
        self._start_auto_flush()
    
    def _start_auto_flush(self):
        """Start auto-flush thread"""
        self._stop_flush.clear()
        self._auto_flush_thread = threading.Thread(target=self._auto_flush_loop, daemon=True)
        self._auto_flush_thread.start()
    
    def _auto_flush_loop(self):
        """Auto-flush loop"""
        while not self._stop_flush.is_set():
            try:
                if time.time() - self._last_flush >= self.flush_interval:
                    self.flush_all()
                self._stop_flush.wait(self.flush_interval / 2)
            except Exception as e:
                self.logger.error(f"Auto-flush error: {e}")
    
    def queue_insert(self, table: str, data: Dict[str, Any]):
        """Queue insert operation"""
        with self._lock:
            self.pending_inserts[table].append(data)
            if len(self.pending_inserts[table]) >= self.batch_size:
                self._flush_table_inserts(table)
    
    def queue_update(self, table: str, data: Dict[str, Any], where_clause: str):
        """Queue update operation"""
        with self._lock:
            self.pending_updates[table].append((data, where_clause))
            if len(self.pending_updates[table]) >= self.batch_size:
                self._flush_table_updates(table)
    
    def queue_delete(self, table: str, where_clause: str):
        """Queue delete operation"""
        with self._lock:
            self.pending_deletes[table].append(where_clause)
            if len(self.pending_deletes[table]) >= self.batch_size:
                self._flush_table_deletes(table)
    
    def flush_all(self):
        """Flush all pending operations"""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    # Flush inserts
                    for table in list(self.pending_inserts.keys()):
                        self._flush_table_inserts(table, conn)
                    
                    # Flush updates
                    for table in list(self.pending_updates.keys()):
                        self._flush_table_updates(table, conn)
                    
                    # Flush deletes
                    for table in list(self.pending_deletes.keys()):
                        self._flush_table_deletes(table, conn)
                    
                    self._last_flush = time.time()
                    
            except Exception as e:
                self.logger.error(f"Batch flush error: {e}")
    
    def _flush_table_inserts(self, table: str, conn: Optional[sqlite3.Connection] = None):
        """Flush inserts for a specific table"""
        if not self.pending_inserts[table]:
            return
        
        records = self.pending_inserts[table].copy()
        self.pending_inserts[table].clear()
        
        if not records:
            return
        
        try:
            should_close = conn is None
            if should_close:
                conn = sqlite3.connect(self.db_path)
            
            # Build INSERT query
            columns = list(records[0].keys())
            placeholders = ', '.join(['?' for _ in columns])
            query = f"INSERT OR IGNORE INTO {table} ({', '.join(columns)}) VALUES ({placeholders})"
            
            # Execute batch insert
            values = [[record[col] for col in columns] for record in records]
            conn.executemany(query, values)
            
            if should_close:
                conn.commit()
                conn.close()
                
        except Exception as e:
            self.logger.error(f"Batch insert error for {table}: {e}")
            # Re-queue failed operations
            self.pending_inserts[table].extend(records)
    
    def _flush_table_updates(self, table: str, conn: Optional[sqlite3.Connection] = None):
        """Flush updates for a specific table"""
        if not self.pending_updates[table]:
            return
        
        updates = self.pending_updates[table].copy()
        self.pending_updates[table].clear()
        
        try:
            should_close = conn is None
            if should_close:
                conn = sqlite3.connect(self.db_path)
            
            for data, where_clause in updates:
                set_clause = ', '.join([f"{k} = ?" for k in data.keys()])
                query = f"UPDATE {table} SET {set_clause} WHERE {where_clause}"
                conn.execute(query, list(data.values()))
            
            if should_close:
                conn.commit()
                conn.close()
                
        except Exception as e:
            self.logger.error(f"Batch update error for {table}: {e}")
            self.pending_updates[table].extend(updates)
    
    def _flush_table_deletes(self, table: str, conn: Optional[sqlite3.Connection] = None):
        """Flush deletes for a specific table"""
        if not self.pending_deletes[table]:
            return
        
        deletes = self.pending_deletes[table].copy()
        self.pending_deletes[table].clear()
        
        try:
            should_close = conn is None
            if should_close:
                conn = sqlite3.connect(self.db_path)
            
            for where_clause in deletes:
                query = f"DELETE FROM {table} WHERE {where_clause}"
                conn.execute(query)
            
            if should_close:
                conn.commit()
                conn.close()
                
        except Exception as e:
            self.logger.error(f"Batch delete error for {table}: {e}")
            self.pending_deletes[table].extend(deletes)
    
    def stop(self):
        """Stop batched operations and flush remaining"""
        self._stop_flush.set()
        if self._auto_flush_thread:
            self._auto_flush_thread.join(timeout=5)
        self.flush_all()


class OptimizedStorage:
    """Optimized storage access with caching and batching"""
    
    def __init__(self, db_path: Optional[str] = None):
        self.logger = get_logger(__name__)
        self.config_manager = get_config_manager()
        self.cache = get_fast_cache()
        
        # Database configuration
        self.db_path = db_path or self.config_manager.get('storage.db_path', 'blncs.db')
        self.cache_ttl = self.config_manager.get('storage.cache_ttl', 300)
        self.batch_enabled = self.config_manager.get('storage.batch_enabled', True)
        
        # Connection pool
        self.connection_pool = []
        self.pool_size = self.config_manager.get('storage.pool_size', 5)
        self._pool_lock = threading.RLock()
        
        # Batching
        self.batcher = BatchedOperations(
            self.db_path,
            batch_size=self.config_manager.get('storage.batch_size', 100),
            flush_interval=self.config_manager.get('storage.flush_interval', 1.0)
        ) if self.batch_enabled else None
        
        # Performance tracking
        self.query_times = deque(maxlen=1000)
        self.cache_stats = {'hits': 0, 'misses': 0}
        
        self._init_database()
    
    def _init_database(self):
        """Initialize database and create tables"""
        try:
            with self.get_connection() as conn:
                # Create basic tables if they don't exist
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        category TEXT,
                        name TEXT,
                        value REAL,
                        metadata TEXT
                    )
                ''')
                
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS performance_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        operation TEXT,
                        duration_ms REAL,
                        success BOOLEAN,
                        error_message TEXT,
                        context TEXT
                    )
                ''')
                
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS cache_stats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        cache_name TEXT,
                        hits INTEGER,
                        misses INTEGER,
                        hit_rate REAL,
                        size INTEGER
                    )
                ''')
                
                # Create indexes for better query performance
                conn.execute('CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_metrics_category ON metrics(category)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_performance_timestamp ON performance_logs(timestamp)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_performance_operation ON performance_logs(operation)')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Database initialization error: {e}")
    
    @contextmanager
    def get_connection(self):
        """Get database connection from pool or create new"""
        conn = None
        try:
            with self._pool_lock:
                if self.connection_pool:
                    conn = self.connection_pool.pop()
                else:
                    conn = sqlite3.connect(self.db_path, timeout=30.0)
                    conn.row_factory = sqlite3.Row
                    # Enable WAL mode for better concurrency
                    conn.execute('PRAGMA journal_mode=WAL')
                    conn.execute('PRAGMA synchronous=NORMAL')
                    conn.execute('PRAGMA cache_size=10000')
                    conn.execute('PRAGMA temp_store=MEMORY')
            
            yield conn
            
        finally:
            if conn:
                try:
                    with self._pool_lock:
                        if len(self.connection_pool) < self.pool_size:
                            self.connection_pool.append(conn)
                        else:
                            conn.close()
                except:
                    pass
    
    def execute_query(self, query: str, params: tuple = (), cache_key: Optional[str] = None, 
                     cache_ttl: Optional[int] = None) -> List[Dict[str, Any]]:
        """Execute query with caching support"""
        start_time = time.time()
        
        # Check cache first
        if cache_key:
            cached_result = self.cache.get(cache_key)
            if cached_result is not None:
                self.cache_stats['hits'] += 1
                return cached_result
            self.cache_stats['misses'] += 1
        
        try:
            with self.get_connection() as conn:
                cursor = conn.execute(query, params)
                rows = cursor.fetchall()
                result = [dict(row) for row in rows]
                
                # Cache the result if requested
                if cache_key and result:
                    ttl = cache_ttl or self.cache_ttl
                    self.cache.set(cache_key, result, ttl)
                
                # Track query performance
                duration_ms = (time.time() - start_time) * 1000
                self.query_times.append(duration_ms)
                
                return result
                
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            self.logger.error(f"Query error: {e}, Duration: {duration_ms:.2f}ms")
            raise
    
    def insert_record(self, table: str, data: Dict[str, Any], batch: bool = None) -> bool:
        """Insert record with optional batching"""
        if batch is None:
            batch = self.batch_enabled
        
        try:
            if batch and self.batcher:
                self.batcher.queue_insert(table, data)
                return True
            else:
                # Direct insert
                columns = list(data.keys())
                placeholders = ', '.join(['?' for _ in columns])
                query = f"INSERT OR IGNORE INTO {table} ({', '.join(columns)}) VALUES ({placeholders})"
                values = [data[col] for col in columns]
                
                with self.get_connection() as conn:
                    conn.execute(query, values)
                    conn.commit()
                    return True
                    
        except Exception as e:
            self.logger.error(f"Insert error for {table}: {e}")
            return False
    
    def update_record(self, table: str, data: Dict[str, Any], where_clause: str, 
                     params: tuple = (), batch: bool = None) -> bool:
        """Update record with optional batching"""
        if batch is None:
            batch = self.batch_enabled
        
        try:
            if batch and self.batcher:
                # For batching, we need to embed the where parameters into the where_clause
                # This is a simplified approach - in practice, you might need more sophisticated batching
                self.batcher.queue_update(table, data, where_clause)
                return True
            else:
                # Direct update
                set_clause = ', '.join([f"{k} = ?" for k in data.keys()])
                query = f"UPDATE {table} SET {set_clause} WHERE {where_clause}"
                all_params = list(data.values()) + list(params)
                
                with self.get_connection() as conn:
                    conn.execute(query, all_params)
                    conn.commit()
                    return True
                    
        except Exception as e:
            self.logger.error(f"Update error for {table}: {e}")
            return False
    
    def store_metric(self, category: str, name: str, value: float, metadata: Dict[str, Any] = None):
        """Store performance metric"""
        data = {
            'category': category,
            'name': name,
            'value': value,
            'metadata': json.dumps(metadata) if metadata else None
        }
        return self.insert_record('metrics', data)
    
    def store_performance_log(self, operation: str, duration_ms: float, success: bool = True, 
                            error_message: str = None, context: Dict[str, Any] = None):
        """Store performance log entry"""
        data = {
            'operation': operation,
            'duration_ms': duration_ms,
            'success': success,
            'error_message': error_message,
            'context': json.dumps(context) if context else None
        }
        return self.insert_record('performance_logs', data)
    
    def get_recent_metrics(self, category: str = None, hours: int = 24, 
                          cache_key: str = None) -> List[Dict[str, Any]]:
        """Get recent metrics with caching"""
        where_clause = "WHERE timestamp >= datetime('now', '-{} hours')".format(hours)
        if category:
            where_clause += f" AND category = '{category}'"
        
        query = f"SELECT * FROM metrics {where_clause} ORDER BY timestamp DESC LIMIT 1000"
        
        if not cache_key and category:
            cache_key = f"metrics_{category}_{hours}h"
        
        return self.execute_query(query, cache_key=cache_key, cache_ttl=60)
    
    def get_performance_stats(self, operation: str = None, hours: int = 24) -> Dict[str, Any]:
        """Get performance statistics"""
        where_clause = "WHERE timestamp >= datetime('now', '-{} hours')".format(hours)
        if operation:
            where_clause += f" AND operation = '{operation}'"
        
        query = f"""
            SELECT 
                COUNT(*) as total_operations,
                AVG(duration_ms) as avg_duration_ms,
                MIN(duration_ms) as min_duration_ms,
                MAX(duration_ms) as max_duration_ms,
                SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful_operations,
                SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed_operations
            FROM performance_logs {where_clause}
        """
        
        results = self.execute_query(query, cache_key=f"perf_stats_{operation or 'all'}_{hours}h", cache_ttl=60)
        
        if results:
            stats = results[0]
            stats['success_rate'] = stats['successful_operations'] / stats['total_operations'] if stats['total_operations'] > 0 else 0
            return stats
        
        return {}
    
    def optimize_database(self) -> Dict[str, Any]:
        """Perform database optimization"""
        results = {}
        
        try:
            with self.get_connection() as conn:
                # Analyze tables for query optimization
                conn.execute('ANALYZE')
                
                # Vacuum database to reclaim space
                conn.execute('VACUUM')
                
                # Update database statistics
                conn.execute('PRAGMA optimize')
                
                # Get database info
                size_result = conn.execute("SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()").fetchone()
                results['database_size_bytes'] = size_result[0] if size_result else 0
                
                # Clean old records (older than 30 days)
                cutoff_date = datetime.now() - timedelta(days=30)
                
                old_metrics = conn.execute("DELETE FROM metrics WHERE timestamp < ?", (cutoff_date,)).rowcount
                old_logs = conn.execute("DELETE FROM performance_logs WHERE timestamp < ?", (cutoff_date,)).rowcount
                old_cache_stats = conn.execute("DELETE FROM cache_stats WHERE timestamp < ?", (cutoff_date,)).rowcount
                
                conn.commit()
                
                results.update({
                    'optimization_completed': True,
                    'old_metrics_removed': old_metrics,
                    'old_logs_removed': old_logs,
                    'old_cache_stats_removed': old_cache_stats
                })
                
        except Exception as e:
            self.logger.error(f"Database optimization error: {e}")
            results['error'] = str(e)
        
        return results
    
    def get_storage_stats(self) -> Dict[str, Any]:
        """Get storage performance statistics"""
        avg_query_time = sum(self.query_times) / len(self.query_times) if self.query_times else 0
        
        cache_total = self.cache_stats['hits'] + self.cache_stats['misses']
        cache_hit_rate = self.cache_stats['hits'] / cache_total if cache_total > 0 else 0
        
        return {
            'database_path': self.db_path,
            'connection_pool_size': len(self.connection_pool),
            'max_pool_size': self.pool_size,
            'batch_enabled': self.batch_enabled,
            'avg_query_time_ms': avg_query_time,
            'recent_queries': len(self.query_times),
            'cache_hit_rate': cache_hit_rate,
            'cache_hits': self.cache_stats['hits'],
            'cache_misses': self.cache_stats['misses']
        }
    
    def close(self):
        """Close all connections and stop batching"""
        if self.batcher:
            self.batcher.stop()
        
        with self._pool_lock:
            for conn in self.connection_pool:
                try:
                    conn.close()
                except:
                    pass
            self.connection_pool.clear()


# Global storage instance
_optimized_storage = None

def get_optimized_storage(db_path: Optional[str] = None) -> OptimizedStorage:
    """Get or create global optimized storage instance"""
    global _optimized_storage
    if _optimized_storage is None:
        _optimized_storage = OptimizedStorage(db_path)
    return _optimized_storage