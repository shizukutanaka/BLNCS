"""
Database Optimization and Caching System
Advanced database performance optimization with intelligent caching.
"""

import sqlite3
import threading
import time
from typing import Dict, List, Any, Optional, Tuple, Union, Callable
from dataclasses import dataclass, field
from collections import defaultdict, OrderedDict
from datetime import datetime, timedelta
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path

from .logger import get_logger
from .config_manager import get_config_manager
from .metrics import get_metrics_collector, increment_counter, set_gauge, record_histogram


@dataclass
class QueryProfile:
    """Query performance profile"""
    query_hash: str
    query_template: str
    execution_count: int = 0
    total_time: float = 0.0
    min_time: float = float('inf')
    max_time: float = 0.0
    avg_time: float = 0.0
    last_executed: Optional[datetime] = None
    cache_hits: int = 0
    cache_misses: int = 0
    
    def add_execution(self, execution_time: float, from_cache: bool = False):
        """Add execution metrics"""
        self.execution_count += 1
        self.last_executed = datetime.now()
        
        if from_cache:
            self.cache_hits += 1
        else:
            self.cache_misses += 1
            self.total_time += execution_time
            self.min_time = min(self.min_time, execution_time)
            self.max_time = max(self.max_time, execution_time)
            self.avg_time = self.total_time / (self.execution_count - self.cache_hits)
    
    @property
    def cache_hit_rate(self) -> float:
        """Calculate cache hit rate"""
        if self.execution_count == 0:
            return 0.0
        return (self.cache_hits / self.execution_count) * 100


@dataclass
class CacheEntry:
    """Cache entry with metadata"""
    data: Any
    created_at: datetime
    accessed_at: datetime
    access_count: int = 1
    size_bytes: int = 0
    
    def __post_init__(self):
        if isinstance(self.data, (str, bytes)):
            self.size_bytes = len(self.data)
        else:
            # Estimate size for complex objects
            self.size_bytes = len(str(self.data))
    
    def touch(self):
        """Update access information"""
        self.accessed_at = datetime.now()
        self.access_count += 1


class IntelligentQueryCache:
    """Advanced query cache with multiple eviction strategies"""
    
    def __init__(self, max_size_mb: int = 100, default_ttl_seconds: int = 3600):
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.default_ttl_seconds = default_ttl_seconds
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.lock = threading.RLock()
        self.logger = get_logger(__name__)
        
        # Statistics
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self.total_size_bytes = 0
    
    def _generate_cache_key(self, query: str, params: Tuple = None) -> str:
        """Generate cache key for query and parameters"""
        key_data = f"{query}:{params}" if params else query
        return hashlib.sha256(key_data.encode()).hexdigest()
    
    def get(self, query: str, params: Tuple = None) -> Optional[Any]:
        """Get cached query result"""
        cache_key = self._generate_cache_key(query, params)
        
        with self.lock:
            entry = self.cache.get(cache_key)
            
            if entry is None:
                self.misses += 1
                return None
            
            # Check TTL
            if (datetime.now() - entry.created_at).total_seconds() > self.default_ttl_seconds:
                self._remove_entry(cache_key)
                self.misses += 1
                return None
            
            # Update access info and move to end (LRU)
            entry.touch()
            self.cache.move_to_end(cache_key)
            self.hits += 1
            
            return entry.data
    
    def set(self, query: str, data: Any, params: Tuple = None, ttl_seconds: int = None) -> bool:
        """Cache query result"""
        cache_key = self._generate_cache_key(query, params)
        ttl = ttl_seconds or self.default_ttl_seconds
        
        with self.lock:
            # Create new entry
            entry = CacheEntry(
                data=data,
                created_at=datetime.now(),
                accessed_at=datetime.now()
            )
            
            # Check if we need to evict entries
            if self.total_size_bytes + entry.size_bytes > self.max_size_bytes:
                self._evict_entries(entry.size_bytes)
            
            # Add entry
            if cache_key in self.cache:
                old_entry = self.cache[cache_key]
                self.total_size_bytes -= old_entry.size_bytes
            
            self.cache[cache_key] = entry
            self.total_size_bytes += entry.size_bytes
            
            return True
    
    def _remove_entry(self, cache_key: str):
        """Remove cache entry"""
        if cache_key in self.cache:
            entry = self.cache.pop(cache_key)
            self.total_size_bytes -= entry.size_bytes
            self.evictions += 1
    
    def _evict_entries(self, needed_bytes: int):
        """Evict entries to make space"""
        bytes_to_free = needed_bytes
        
        # Use LRU eviction strategy
        keys_to_remove = []
        
        for cache_key, entry in self.cache.items():
            keys_to_remove.append(cache_key)
            bytes_to_free -= entry.size_bytes
            
            if bytes_to_free <= 0:
                break
        
        for cache_key in keys_to_remove:
            self._remove_entry(cache_key)
        
        self.logger.debug(f"Evicted {len(keys_to_remove)} cache entries")
    
    def clear(self):
        """Clear all cache entries"""
        with self.lock:
            self.cache.clear()
            self.total_size_bytes = 0
            self.hits = 0
            self.misses = 0
            self.evictions = 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.lock:
            total_requests = self.hits + self.misses
            hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0
            
            return {
                'entries': len(self.cache),
                'size_mb': round(self.total_size_bytes / (1024 * 1024), 2),
                'max_size_mb': self.max_size_bytes / (1024 * 1024),
                'hits': self.hits,
                'misses': self.misses,
                'hit_rate': round(hit_rate, 2),
                'evictions': self.evictions,
                'ttl_seconds': self.default_ttl_seconds
            }


class DatabaseOptimizer:
    """Comprehensive database optimization system"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.logger = get_logger(__name__)
        self.config_manager = get_config_manager()
        self.metrics = get_metrics_collector()
        
        # Query profiling
        self.query_profiles: Dict[str, QueryProfile] = {}
        self.profile_lock = threading.RLock()
        
        # Caching
        cache_size_mb = self.config_manager.get('database.cache_size_mb', 100)
        cache_ttl = self.config_manager.get('database.cache_ttl_seconds', 3600)
        self.query_cache = IntelligentQueryCache(cache_size_mb, cache_ttl)
        
        # Connection pooling
        self.connection_pool: List[sqlite3.Connection] = []
        self.pool_lock = threading.RLock()
        self.max_connections = self.config_manager.get('database.max_connections', 10)
        
        # Optimization settings
        self.enable_query_profiling = self.config_manager.get('database.enable_profiling', True)
        self.enable_caching = self.config_manager.get('database.enable_caching', True)
        self.auto_optimize = self.config_manager.get('database.auto_optimize', True)
        
        # Background optimization
        self.optimization_thread: Optional[threading.Thread] = None
        self.optimization_active = False
        
        self._initialize_database()
        self.logger.info(f"Database optimizer initialized for {db_path}")
    
    def _initialize_database(self):
        """Initialize database with optimal settings"""
        conn = self._get_connection()
        try:
            # Apply SQLite optimizations
            optimizations = [
                "PRAGMA journal_mode = WAL",
                "PRAGMA synchronous = NORMAL",
                "PRAGMA cache_size = -64000",  # 64MB cache
                "PRAGMA temp_store = MEMORY",
                "PRAGMA mmap_size = 268435456",  # 256MB memory map
                "PRAGMA optimize",
            ]
            
            for pragma in optimizations:
                try:
                    conn.execute(pragma)
                    self.logger.debug(f"Applied optimization: {pragma}")
                except sqlite3.Error as e:
                    self.logger.warning(f"Failed to apply {pragma}: {e}")
            
            conn.commit()
            
        finally:
            self._return_connection(conn)
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection from pool"""
        with self.pool_lock:
            if self.connection_pool:
                return self.connection_pool.pop()
            
            # Create new connection
            conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            return conn
    
    def _return_connection(self, conn: sqlite3.Connection):
        """Return connection to pool"""
        with self.pool_lock:
            if len(self.connection_pool) < self.max_connections:
                self.connection_pool.append(conn)
            else:
                conn.close()
    
    @contextmanager
    def get_db_connection(self):
        """Context manager for database connections"""
        conn = self._get_connection()
        try:
            yield conn
        finally:
            self._return_connection(conn)
    
    def _normalize_query(self, query: str) -> str:
        """Normalize query for profiling (replace parameters with placeholders)"""
        # Simple normalization - replace numeric literals and strings
        import re
        normalized = re.sub(r'\b\d+\b', '?', query)
        normalized = re.sub(r"'[^']*'", '?', normalized)
        normalized = re.sub(r'"[^"]*"', '?', normalized)
        return normalized.strip()
    
    def _get_query_hash(self, query: str) -> str:
        """Get hash for query profiling"""
        normalized = self._normalize_query(query)
        return hashlib.md5(normalized.encode()).hexdigest()
    
    def execute_query(self, query: str, params: Tuple = None, 
                     cache_result: bool = True, fetch_all: bool = True) -> Optional[List[sqlite3.Row]]:
        """Execute query with optimization"""
        start_time = time.time()
        from_cache = False
        
        # Try cache first
        if self.enable_caching and cache_result:
            cached_result = self.query_cache.get(query, params)
            if cached_result is not None:
                from_cache = True
                result = cached_result
            else:
                result = self._execute_query_direct(query, params, fetch_all)
                if result is not None:
                    self.query_cache.set(query, result, params)
        else:
            result = self._execute_query_direct(query, params, fetch_all)
        
        # Record metrics
        execution_time = time.time() - start_time
        
        if self.enable_query_profiling:
            self._record_query_profile(query, execution_time, from_cache)
        
        # Record metrics
        record_histogram('database_query_duration_seconds', execution_time)
        increment_counter('database_queries_total', {'cached': str(from_cache)})
        
        return result
    
    def _execute_query_direct(self, query: str, params: Tuple = None, 
                            fetch_all: bool = True) -> Optional[List[sqlite3.Row]]:
        """Execute query directly against database"""
        with self.get_db_connection() as conn:
            try:
                cursor = conn.cursor()
                
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                
                if query.strip().upper().startswith('SELECT'):
                    if fetch_all:
                        return cursor.fetchall()
                    else:
                        return cursor.fetchone()
                else:
                    conn.commit()
                    return None
                    
            except sqlite3.Error as e:
                self.logger.error(f"Database query failed: {e}")
                self.logger.error(f"Query: {query}")
                self.logger.error(f"Params: {params}")
                raise
    
    def _record_query_profile(self, query: str, execution_time: float, from_cache: bool):
        """Record query execution profile"""
        query_hash = self._get_query_hash(query)
        normalized_query = self._normalize_query(query)
        
        with self.profile_lock:
            if query_hash not in self.query_profiles:
                self.query_profiles[query_hash] = QueryProfile(
                    query_hash=query_hash,
                    query_template=normalized_query
                )
            
            profile = self.query_profiles[query_hash]
            profile.add_execution(execution_time, from_cache)
    
    def analyze_slow_queries(self, min_avg_time: float = 0.1, limit: int = 10) -> List[QueryProfile]:
        """Analyze slow queries"""
        with self.profile_lock:
            slow_queries = [
                profile for profile in self.query_profiles.values()
                if profile.avg_time >= min_avg_time and profile.execution_count >= 5
            ]
            
            # Sort by average execution time
            slow_queries.sort(key=lambda p: p.avg_time, reverse=True)
            
            return slow_queries[:limit]
    
    def get_query_stats(self) -> Dict[str, Any]:
        """Get comprehensive query statistics"""
        with self.profile_lock:
            total_queries = sum(p.execution_count for p in self.query_profiles.values())
            total_time = sum(p.total_time for p in self.query_profiles.values())
            avg_query_time = total_time / total_queries if total_queries > 0 else 0
            
            # Cache statistics
            cache_stats = self.query_cache.get_stats()
            
            # Top queries by frequency
            frequent_queries = sorted(
                self.query_profiles.values(),
                key=lambda p: p.execution_count,
                reverse=True
            )[:10]
            
            # Slow queries
            slow_queries = self.analyze_slow_queries(limit=5)
            
            return {
                'total_unique_queries': len(self.query_profiles),
                'total_executions': total_queries,
                'total_execution_time': round(total_time, 3),
                'average_query_time': round(avg_query_time, 3),
                'cache_stats': cache_stats,
                'most_frequent_queries': [
                    {
                        'query_template': q.query_template,
                        'execution_count': q.execution_count,
                        'avg_time': round(q.avg_time, 3),
                        'cache_hit_rate': round(q.cache_hit_rate, 1)
                    }
                    for q in frequent_queries
                ],
                'slowest_queries': [
                    {
                        'query_template': q.query_template,
                        'avg_time': round(q.avg_time, 3),
                        'execution_count': q.execution_count,
                        'max_time': round(q.max_time, 3)
                    }
                    for q in slow_queries
                ]
            }
    
    def optimize_database(self) -> Dict[str, Any]:
        """Perform database optimization"""
        optimization_results = {
            'timestamp': datetime.now().isoformat(),
            'operations_performed': [],
            'errors': []
        }
        
        with self.get_db_connection() as conn:
            try:
                # Analyze database
                self.logger.info("Starting database optimization")
                
                # VACUUM to defragment
                try:
                    conn.execute("VACUUM")
                    optimization_results['operations_performed'].append('VACUUM completed')
                    self.logger.info("Database VACUUM completed")
                except sqlite3.Error as e:
                    error_msg = f"VACUUM failed: {e}"
                    optimization_results['errors'].append(error_msg)
                    self.logger.error(error_msg)
                
                # ANALYZE to update statistics
                try:
                    conn.execute("ANALYZE")
                    optimization_results['operations_performed'].append('ANALYZE completed')
                    self.logger.info("Database ANALYZE completed")
                except sqlite3.Error as e:
                    error_msg = f"ANALYZE failed: {e}"
                    optimization_results['errors'].append(error_msg)
                    self.logger.error(error_msg)
                
                # Optimize queries
                try:
                    conn.execute("PRAGMA optimize")
                    optimization_results['operations_performed'].append('PRAGMA optimize completed')
                    self.logger.info("Database PRAGMA optimize completed")
                except sqlite3.Error as e:
                    error_msg = f"PRAGMA optimize failed: {e}"
                    optimization_results['errors'].append(error_msg)
                    self.logger.error(error_msg)
                
                # Check and create missing indexes
                missing_indexes = self._identify_missing_indexes(conn)
                for index_sql in missing_indexes:
                    try:
                        conn.execute(index_sql)
                        optimization_results['operations_performed'].append(f'Created index: {index_sql}')
                        self.logger.info(f"Created index: {index_sql}")
                    except sqlite3.Error as e:
                        error_msg = f"Failed to create index {index_sql}: {e}"
                        optimization_results['errors'].append(error_msg)
                        self.logger.error(error_msg)
                
                conn.commit()
                
            except Exception as e:
                error_msg = f"Database optimization error: {e}"
                optimization_results['errors'].append(error_msg)
                self.logger.error(error_msg)
        
        return optimization_results
    
    def _identify_missing_indexes(self, conn: sqlite3.Connection) -> List[str]:
        """Identify potentially beneficial indexes"""
        suggested_indexes = []
        
        try:
            # Get table information
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            # Common patterns for indexes
            common_index_patterns = [
                ("events", ["timestamp"]),
                ("events", ["event_type"]),
                ("events", ["severity"]),
                ("metrics", ["timestamp"]),
                ("metrics", ["metric_name"]),
                ("discovered_nodes", ["pubkey"]),
                ("discovered_nodes", ["last_seen"]),
            ]
            
            # Check existing indexes
            cursor.execute("SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index'")
            existing_indexes = {(row[1], row[0]): row[2] for row in cursor.fetchall() if row[2]}
            
            for table, columns in common_index_patterns:
                if table in tables:
                    index_name = f"idx_{table}_{'_'.join(columns)}"
                    if (table, index_name) not in existing_indexes:
                        # Check if columns exist
                        cursor.execute(f"PRAGMA table_info({table})")
                        table_columns = [col[1] for col in cursor.fetchall()]
                        
                        if all(col in table_columns for col in columns):
                            index_sql = f"CREATE INDEX IF NOT EXISTS {index_name} ON {table} ({', '.join(columns)})"
                            suggested_indexes.append(index_sql)
            
        except sqlite3.Error as e:
            self.logger.error(f"Error identifying missing indexes: {e}")
        
        return suggested_indexes
    
    def get_database_health(self) -> Dict[str, Any]:
        """Get database health metrics"""
        with self.get_db_connection() as conn:
            cursor = conn.cursor()
            
            try:
                # Database size
                cursor.execute("SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()")
                db_size = cursor.fetchone()[0]
                
                # Free pages
                cursor.execute("PRAGMA freelist_count")
                free_pages = cursor.fetchone()[0]
                
                # Page size
                cursor.execute("PRAGMA page_size")
                page_size = cursor.fetchone()[0]
                
                # WAL mode info
                cursor.execute("PRAGMA journal_mode")
                journal_mode = cursor.fetchone()[0]
                
                # Cache size
                cursor.execute("PRAGMA cache_size")
                cache_size = cursor.fetchone()[0]
                
                # Table count
                cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
                table_count = cursor.fetchone()[0]
                
                # Index count
                cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='index'")
                index_count = cursor.fetchone()[0]
                
                return {
                    'database_size_mb': round(db_size / (1024 * 1024), 2),
                    'free_pages': free_pages,
                    'page_size': page_size,
                    'journal_mode': journal_mode,
                    'cache_size': cache_size,
                    'table_count': table_count,
                    'index_count': index_count,
                    'fragmentation_ratio': round((free_pages * page_size) / db_size * 100, 2) if db_size > 0 else 0,
                    'connection_pool_size': len(self.connection_pool),
                    'max_connections': self.max_connections
                }
                
            except sqlite3.Error as e:
                self.logger.error(f"Error getting database health: {e}")
                return {'error': str(e)}
    
    def start_background_optimization(self, interval_hours: int = 24):
        """Start background database optimization"""
        if self.optimization_active:
            return
        
        self.optimization_active = True
        self.optimization_thread = threading.Thread(
            target=self._optimization_loop,
            args=(interval_hours,),
            daemon=True
        )
        self.optimization_thread.start()
        self.logger.info(f"Background optimization started (interval: {interval_hours}h)")
    
    def stop_background_optimization(self):
        """Stop background optimization"""
        self.optimization_active = False
        if self.optimization_thread:
            self.optimization_thread.join(timeout=5)
        self.logger.info("Background optimization stopped")
    
    def _optimization_loop(self, interval_hours: int):
        """Background optimization loop"""
        while self.optimization_active:
            try:
                # Perform optimization
                if self.auto_optimize:
                    self.optimize_database()
                
                # Clear old query profiles (keep last 24 hours)
                self._cleanup_old_profiles()
                
                # Sleep until next optimization
                time.sleep(interval_hours * 3600)
                
            except Exception as e:
                self.logger.error(f"Error in optimization loop: {e}")
                time.sleep(3600)  # Wait 1 hour on error
    
    def _cleanup_old_profiles(self):
        """Clean up old query profiles"""
        cutoff_time = datetime.now() - timedelta(hours=24)
        
        with self.profile_lock:
            profiles_to_remove = []
            for query_hash, profile in self.query_profiles.items():
                if profile.last_executed and profile.last_executed < cutoff_time:
                    profiles_to_remove.append(query_hash)
            
            for query_hash in profiles_to_remove:
                del self.query_profiles[query_hash]
            
            if profiles_to_remove:
                self.logger.debug(f"Cleaned up {len(profiles_to_remove)} old query profiles")
    
    def clear_cache(self):
        """Clear query cache"""
        self.query_cache.clear()
        self.logger.info("Query cache cleared")
    
    def get_optimization_report(self) -> Dict[str, Any]:
        """Generate comprehensive optimization report"""
        return {
            'timestamp': datetime.now().isoformat(),
            'database_health': self.get_database_health(),
            'query_statistics': self.get_query_stats(),
            'cache_performance': self.query_cache.get_stats(),
            'optimization_settings': {
                'query_profiling_enabled': self.enable_query_profiling,
                'caching_enabled': self.enable_caching,
                'auto_optimize_enabled': self.auto_optimize,
                'background_optimization_active': self.optimization_active,
                'max_connections': self.max_connections
            },
            'recommendations': self._generate_optimization_recommendations()
        }
    
    def _generate_optimization_recommendations(self) -> List[str]:
        """Generate optimization recommendations"""
        recommendations = []
        
        # Check database health
        health = self.get_database_health()
        
        if health.get('fragmentation_ratio', 0) > 10:
            recommendations.append("Database fragmentation is high. Consider running VACUUM.")
        
        # Check cache performance
        cache_stats = self.query_cache.get_stats()
        if cache_stats.get('hit_rate', 0) < 50:
            recommendations.append("Low cache hit rate. Consider increasing cache size or TTL.")
        
        # Check query performance
        slow_queries = self.analyze_slow_queries(min_avg_time=0.5, limit=5)
        if slow_queries:
            recommendations.append(f"Found {len(slow_queries)} slow queries. Consider optimization or indexing.")
        
        # Check connection pool
        if health.get('connection_pool_size', 0) < 2:
            recommendations.append("Connection pool is small. Consider increasing max_connections.")
        
        if not recommendations:
            recommendations.append("Database performance is optimal.")
        
        return recommendations


# Global instance
_database_optimizer = None

def get_database_optimizer(db_path: str = None) -> DatabaseOptimizer:
    """Get global database optimizer"""
    global _database_optimizer
    if _database_optimizer is None:
        if db_path is None:
            db_path = "blncs.db"  # Default database path
        _database_optimizer = DatabaseOptimizer(db_path)
    return _database_optimizer