"""
Simple Storage Optimizer
Follows Pike: do one thing well - optimize storage access.
"""

import json
import threading
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from collections import deque
import time

from .logger import get_logger
from .config_manager import get_config_manager
from .cache_unified import get_cache
from .database import get_database


class SimpleBatcher:
    """Simple batch operations using unified database"""
    
    def __init__(self, batch_size: int = 100, flush_interval: float = 1.0):
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.pending_operations = deque(maxlen=1000)
        self._lock = threading.RLock()
        self._last_flush = time.time()
        self._auto_flush_thread = None
        self._stop_flush = threading.Event()
        self.logger = get_logger(__name__)
        self.db = get_database()
        self._start_auto_flush()
    
    def _start_auto_flush(self):
        self._stop_flush.clear()
        self._auto_flush_thread = threading.Thread(target=self._auto_flush_loop, daemon=True)
        self._auto_flush_thread.start()
    
    def _auto_flush_loop(self):
        while not self._stop_flush.is_set():
            try:
                if time.time() - self._last_flush >= self.flush_interval:
                    self.flush_all()
                self._stop_flush.wait(self.flush_interval / 2)
            except Exception as e:
                self.logger.error(f"Auto-flush error: {e}")
    
    def queue_operation(self, query: str, params: tuple = ()):
        """Queue database operation"""
        with self._lock:
            self.pending_operations.append((query, params))
            if len(self.pending_operations) >= self.batch_size:
                self.flush_all()
    
    def flush_all(self):
        """Flush all pending operations"""
        with self._lock:
            if not self.pending_operations:
                return
            
            operations = list(self.pending_operations)
            self.pending_operations.clear()
            
            try:
                for query, params in operations:
                    self.db.execute(query, params)
                self._last_flush = time.time()
            except Exception as e:
                self.logger.error(f"Batch flush error: {e}")
                self.pending_operations.extendleft(reversed(operations))
    
    def stop(self):
        self._stop_flush.set()
        if self._auto_flush_thread:
            self._auto_flush_thread.join(timeout=5)
        self.flush_all()


class SimpleStorageOptimizer:
    """Simple storage optimizer using unified database"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config_manager = get_config_manager()
        self.cache = get_cache()
        self.db = get_database()
        
        self.cache_ttl = self.config_manager.get('storage.cache_ttl', 300)
        self.batch_enabled = self.config_manager.get('storage.batch_enabled', True)
        
        # Batching
        self.batcher = SimpleBatcher(
            batch_size=self.config_manager.get('storage.batch_size', 100),
            flush_interval=self.config_manager.get('storage.flush_interval', 1.0)
        ) if self.batch_enabled else None
        
        # Performance tracking
        self.query_times = deque(maxlen=1000)
        self.cache_stats = {'hits': 0, 'misses': 0}
    
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
            result = self.db.execute(query, params)
            result_dicts = [dict(row) for row in result]
            
            # Cache the result if requested
            if cache_key and result_dicts:
                ttl = cache_ttl or self.cache_ttl
                self.cache.set(cache_key, result_dicts, ttl)
            
            # Track query performance
            duration_ms = (time.time() - start_time) * 1000
            self.query_times.append(duration_ms)
            
            return result_dicts
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            self.logger.error(f"Query error: {e}, Duration: {duration_ms:.2f}ms")
            raise
    
    def insert_record(self, table: str, data: Dict[str, Any], batch: bool = None) -> bool:
        """Insert record with optional batching"""
        if batch is None:
            batch = self.batch_enabled
        
        try:
            columns = list(data.keys())
            placeholders = ', '.join(['?' for _ in columns])
            query = f"INSERT OR IGNORE INTO {table} ({', '.join(columns)}) VALUES ({placeholders})"
            values = tuple(data[col] for col in columns)
            
            if batch and self.batcher:
                self.batcher.queue_operation(query, values)
            else:
                self.db.execute(query, values)
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
            set_clause = ', '.join([f"{k} = ?" for k in data.keys()])
            query = f"UPDATE {table} SET {set_clause} WHERE {where_clause}"
            all_params = tuple(list(data.values()) + list(params))
            
            if batch and self.batcher:
                self.batcher.queue_operation(query, all_params)
            else:
                self.db.execute(query, all_params)
            return True
                    
        except Exception as e:
            self.logger.error(f"Update error for {table}: {e}")
            return False
    
    def store_metric(self, category: str, name: str, value: float, metadata: Dict[str, Any] = None):
        """Store performance metric using unified database"""
        self.db.record_metric(f"{category}_{name}", value, metadata)
    
    def store_performance_log(self, operation: str, duration_ms: float, success: bool = True, 
                            error_message: str = None, context: Dict[str, Any] = None):
        """Store performance log entry"""
        tags = {'success': str(success)}
        if error_message:
            tags['error'] = error_message
        if context:
            tags.update({k: str(v) for k, v in context.items()})
        
        self.db.record_metric(f"performance_{operation}", duration_ms, tags)
    
    def get_recent_metrics(self, category: str = None, hours: int = 24, 
                          cache_key: str = None) -> List[Dict[str, Any]]:
        """Get recent metrics with caching"""
        if cache_key:
            cached_result = self.cache.get(cache_key)
            if cached_result is not None:
                self.cache_stats['hits'] += 1
                return cached_result
            self.cache_stats['misses'] += 1
        
        if category:
            result = self.db.get_metrics(f"{category}_", hours)
        else:
            result = self.db.get_metrics("performance_", hours)
        
        if cache_key:
            self.cache.set(cache_key, result, 60)
        
        return result
    
    def get_performance_stats(self, operation: str = None, hours: int = 24) -> Dict[str, Any]:
        """Get performance statistics"""
        metric_name = f"performance_{operation}" if operation else "performance_"
        metrics = self.db.get_metrics(metric_name, hours)
        
        if not metrics:
            return {}
        
        values = [m['metric_value'] for m in metrics if m.get('metric_value') is not None]
        
        if not values:
            return {}
        
        return {
            'total_operations': len(values),
            'avg_duration_ms': sum(values) / len(values),
            'min_duration_ms': min(values),
            'max_duration_ms': max(values),
            'successful_operations': len([m for m in metrics if m.get('tags', {}).get('success') == 'True']),
            'failed_operations': len([m for m in metrics if m.get('tags', {}).get('success') == 'False'])
        }
    
    def optimize_database(self) -> Dict[str, Any]:
        """Perform database optimization using unified database"""
        try:
            self.db.optimize()
            stats = self.db.get_database_stats()
            return {
                'optimization_completed': True,
                'database_stats': stats
            }
        except Exception as e:
            self.logger.error(f"Database optimization error: {e}")
            return {'error': str(e)}
    
    def get_storage_stats(self) -> Dict[str, Any]:
        """Get storage performance statistics"""
        avg_query_time = sum(self.query_times) / len(self.query_times) if self.query_times else 0
        
        cache_total = self.cache_stats['hits'] + self.cache_stats['misses']
        cache_hit_rate = self.cache_stats['hits'] / cache_total if cache_total > 0 else 0
        
        db_stats = self.db.get_database_stats()
        
        return {
            'batch_enabled': self.batch_enabled,
            'avg_query_time_ms': avg_query_time,
            'recent_queries': len(self.query_times),
            'cache_hit_rate': cache_hit_rate,
            'cache_hits': self.cache_stats['hits'],
            'cache_misses': self.cache_stats['misses'],
            **db_stats
        }
    
    def close(self):
        """Stop batching operations"""
        if self.batcher:
            self.batcher.stop()


# Global storage instance
_storage_optimizer = None

def get_storage_optimizer() -> SimpleStorageOptimizer:
    """Get or create global storage optimizer instance"""
    global _storage_optimizer
    if _storage_optimizer is None:
        _storage_optimizer = SimpleStorageOptimizer()
    return _storage_optimizer