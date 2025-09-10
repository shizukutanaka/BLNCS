"""
Database Query Optimizer for BLNCS
Eliminates N+1 patterns and optimizes database operations.
"""

import time
import threading
from typing import Dict, List, Any, Optional, Set, Callable, Tuple, Union
from dataclasses import dataclass, field
from contextlib import contextmanager
from collections import defaultdict, OrderedDict

from .logger import get_logger
from .unified_cache import get_cache_manager, CacheType


@dataclass
class QueryMetrics:
    """Query execution metrics"""
    query_hash: str
    query: str
    execution_count: int = 0
    total_time: float = 0.0
    avg_time: float = 0.0
    last_executed: Optional[float] = None
    parameters: List[Any] = field(default_factory=list)


class QueryBatch:
    """Batches multiple queries for execution"""
    
    def __init__(self, batch_id: str):
        self.batch_id = batch_id
        self.queries: List[Tuple[str, List[Any]]] = []
        self.results: Dict[str, Any] = {}
        self.executed = False
        self.created_at = time.time()


class DatabaseQueryOptimizer:
    """Optimizes database queries to eliminate N+1 patterns"""
    
    def __init__(self, database_manager):
        self.database_manager = database_manager
        self.logger = get_logger(__name__)
        self.cache_manager = get_cache_manager()
        
        # Query tracking and metrics
        self._query_metrics: Dict[str, QueryMetrics] = {}
        self._metrics_lock = threading.RLock()
        
        # Query batching
        self._batch_queries: Dict[str, QueryBatch] = {}
        self._batch_lock = threading.RLock()
        self._batch_timeout = 0.1  # 100ms batch window
        
        # Query result caching
        self._query_cache_ttl = 300  # 5 minutes default
        
        # N+1 detection
        self._query_patterns: Dict[str, int] = defaultdict(int)
        self._pattern_lock = threading.RLock()
    
    def _hash_query(self, query: str, parameters: List[Any] = None) -> str:
        """Generate hash for query caching"""
        import hashlib
        content = query
        if parameters:
            content += str(sorted(parameters) if isinstance(parameters, (list, tuple)) else str(parameters))
        return hashlib.md5(content.encode()).hexdigest()
    
    def _record_query_metrics(self, query: str, execution_time: float, parameters: List[Any] = None):
        """Record query execution metrics"""
        query_hash = self._hash_query(query, parameters)
        
        with self._metrics_lock:
            if query_hash not in self._query_metrics:
                self._query_metrics[query_hash] = QueryMetrics(
                    query_hash=query_hash,
                    query=query,
                    parameters=parameters or []
                )
            
            metrics = self._query_metrics[query_hash]
            metrics.execution_count += 1
            metrics.total_time += execution_time
            metrics.avg_time = metrics.total_time / metrics.execution_count
            metrics.last_executed = time.time()
    
    def _detect_n_plus_one(self, query: str) -> bool:
        """Detect potential N+1 query patterns"""
        # Extract query pattern (remove specific values)
        import re
        pattern = re.sub(r'\b\d+\b', '?', query)  # Replace numbers with ?
        pattern = re.sub(r"'[^']*'", '?', pattern)  # Replace string literals with ?
        
        with self._pattern_lock:
            self._query_patterns[pattern] += 1
            count = self._query_patterns[pattern]
            
            # If same pattern executed many times in short period, it's likely N+1
            if count > 10:  # Threshold for N+1 detection
                self.logger.warning(f"Potential N+1 pattern detected: {pattern} (count: {count})")
                return True
        
        return False
    
    def execute_query(self, query: str, parameters: List[Any] = None, cache_ttl: Optional[int] = None) -> Any:
        """Execute query with optimization and caching"""
        query_hash = self._hash_query(query, parameters)
        
        # Check cache first
        cache_key = f"query_{query_hash}"
        cached_result = self.cache_manager.get(CacheType.CALCULATIONS, cache_key)
        if cached_result is not None:
            self.logger.debug(f"Query cache hit: {query_hash[:8]}")
            return cached_result
        
        # Detect N+1 patterns
        self._detect_n_plus_one(query)
        
        # Execute query and measure time
        start_time = time.time()
        try:
            with self.database_manager.get_connection() as conn:
                cursor = conn.cursor()
                if parameters:
                    cursor.execute(query, parameters)
                else:
                    cursor.execute(query)
                
                # Fetch results based on query type
                if query.strip().upper().startswith('SELECT'):
                    result = cursor.fetchall()
                else:
                    result = cursor.rowcount
                
                execution_time = time.time() - start_time
                
                # Record metrics
                self._record_query_metrics(query, execution_time, parameters)
                
                # Cache result
                ttl = cache_ttl or self._query_cache_ttl
                self.cache_manager.set(CacheType.CALCULATIONS, cache_key, result, ttl)
                
                return result
                
        except Exception as e:
            execution_time = time.time() - start_time
            self._record_query_metrics(query, execution_time, parameters)
            raise
    
    def batch_execute(self, queries: List[Tuple[str, List[Any]]], batch_id: Optional[str] = None) -> Dict[str, Any]:
        """Execute multiple queries in a batch"""
        if not queries:
            return {}
        
        batch_id = batch_id or f"batch_{int(time.time() * 1000)}"
        
        # Check if any results are cached
        results = {}
        uncached_queries = []
        
        for query, params in queries:
            query_hash = self._hash_query(query, params)
            cache_key = f"query_{query_hash}"
            cached_result = self.cache_manager.get(CacheType.CALCULATIONS, cache_key)
            
            if cached_result is not None:
                results[query_hash] = cached_result
            else:
                uncached_queries.append((query, params))
        
        # Execute uncached queries
        if uncached_queries:
            start_time = time.time()
            
            try:
                with self.database_manager.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    for query, params in uncached_queries:
                        query_hash = self._hash_query(query, params)
                        
                        if params:
                            cursor.execute(query, params)
                        else:
                            cursor.execute(query)
                        
                        if query.strip().upper().startswith('SELECT'):
                            result = cursor.fetchall()
                        else:
                            result = cursor.rowcount
                        
                        results[query_hash] = result
                        
                        # Cache result
                        cache_key = f"query_{query_hash}"
                        self.cache_manager.set(CacheType.CALCULATIONS, cache_key, result, self._query_cache_ttl)
                
                batch_time = time.time() - start_time
                self.logger.debug(f"Batch executed {len(uncached_queries)} queries in {batch_time:.3f}s")
                
            except Exception as e:
                self.logger.error(f"Batch execution failed: {e}")
                raise
        
        return results
    
    def get_related_records(self, table: str, foreign_keys: List[Any], 
                          fields: str = "*", key_field: str = "id") -> Dict[Any, Any]:
        """Fetch related records efficiently (eliminates N+1)"""
        if not foreign_keys:
            return {}
        
        # Remove duplicates while preserving order
        unique_keys = list(OrderedDict.fromkeys(foreign_keys))
        
        # Build IN query
        placeholders = ','.join(['?' for _ in unique_keys])
        query = f"SELECT {fields} FROM {table} WHERE {key_field} IN ({placeholders})"
        
        # Execute query
        result = self.execute_query(query, unique_keys)
        
        # Index results by key for fast lookup
        indexed_results = {}
        for row in result:
            # Assume first column is the key field
            key_value = row[0] if isinstance(row, (list, tuple)) else getattr(row, key_field)
            indexed_results[key_value] = row
        
        return indexed_results
    
    def bulk_insert(self, table: str, records: List[Dict[str, Any]]) -> int:
        """Perform bulk insert operation"""
        if not records:
            return 0
        
        # Get field names from first record
        fields = list(records[0].keys())
        field_names = ','.join(fields)
        placeholders = ','.join(['?' for _ in fields])
        
        query = f"INSERT INTO {table} ({field_names}) VALUES ({placeholders})"
        
        # Prepare parameter list
        parameters = []
        for record in records:
            parameters.append([record.get(field) for field in fields])
        
        start_time = time.time()
        
        try:
            with self.database_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.executemany(query, parameters)
                conn.commit()
                
                execution_time = time.time() - start_time
                self._record_query_metrics(query, execution_time)
                
                self.logger.info(f"Bulk inserted {len(records)} records in {execution_time:.3f}s")
                return cursor.rowcount
                
        except Exception as e:
            self.logger.error(f"Bulk insert failed: {e}")
            raise
    
    def bulk_update(self, table: str, records: List[Dict[str, Any]], key_field: str = "id") -> int:
        """Perform bulk update operation"""
        if not records:
            return 0
        
        # Group updates by fields being updated
        update_groups = defaultdict(list)
        for record in records:
            fields_to_update = set(record.keys()) - {key_field}
            fields_key = tuple(sorted(fields_to_update))
            update_groups[fields_key].append(record)
        
        total_updated = 0
        
        for fields_tuple, group_records in update_groups.items():
            if not fields_tuple:
                continue
            
            # Build update query
            set_clause = ','.join([f"{field} = ?" for field in fields_tuple])
            query = f"UPDATE {table} SET {set_clause} WHERE {key_field} = ?"
            
            # Prepare parameters
            parameters = []
            for record in group_records:
                params = [record.get(field) for field in fields_tuple]
                params.append(record[key_field])
                parameters.append(params)
            
            start_time = time.time()
            
            try:
                with self.database_manager.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.executemany(query, parameters)
                    conn.commit()
                    
                    execution_time = time.time() - start_time
                    self._record_query_metrics(query, execution_time)
                    
                    total_updated += cursor.rowcount
                    
            except Exception as e:
                self.logger.error(f"Bulk update failed for fields {fields_tuple}: {e}")
                raise
        
        self.logger.info(f"Bulk updated {total_updated} records")
        return total_updated
    
    def get_query_stats(self) -> Dict[str, Any]:
        """Get query execution statistics"""
        with self._metrics_lock:
            total_queries = sum(m.execution_count for m in self._query_metrics.values())
            total_time = sum(m.total_time for m in self._query_metrics.values())
            avg_time = total_time / total_queries if total_queries > 0 else 0
            
            # Find slowest queries
            slowest_queries = sorted(
                self._query_metrics.values(),
                key=lambda m: m.avg_time,
                reverse=True
            )[:10]
            
            # Find most frequent queries
            most_frequent = sorted(
                self._query_metrics.values(),
                key=lambda m: m.execution_count,
                reverse=True
            )[:10]
            
            return {
                'total_queries': total_queries,
                'total_execution_time': f"{total_time:.3f}s",
                'average_query_time': f"{avg_time:.3f}s",
                'unique_queries': len(self._query_metrics),
                'slowest_queries': [
                    {
                        'query': q.query[:100] + "..." if len(q.query) > 100 else q.query,
                        'avg_time': f"{q.avg_time:.3f}s",
                        'execution_count': q.execution_count
                    }
                    for q in slowest_queries
                ],
                'most_frequent_queries': [
                    {
                        'query': q.query[:100] + "..." if len(q.query) > 100 else q.query,
                        'execution_count': q.execution_count,
                        'avg_time': f"{q.avg_time:.3f}s"
                    }
                    for q in most_frequent
                ]
            }
    
    def clear_cache(self) -> None:
        """Clear query result cache"""
        self.cache_manager.clear_cache_type(CacheType.CALCULATIONS)
        self.logger.info("Query result cache cleared")
    
    def reset_metrics(self) -> None:
        """Reset query metrics"""
        with self._metrics_lock:
            self._query_metrics.clear()
        
        with self._pattern_lock:
            self._query_patterns.clear()
        
        self.logger.info("Query metrics reset")


# Global query optimizer instance
_query_optimizer: Optional[DatabaseQueryOptimizer] = None
_optimizer_lock = threading.Lock()


def get_query_optimizer(database_manager=None) -> DatabaseQueryOptimizer:
    """Get global query optimizer instance"""
    global _query_optimizer
    if _query_optimizer is None:
        with _optimizer_lock:
            if _query_optimizer is None:
                if database_manager is None:
                    from .database import get_database_manager
                    database_manager = get_database_manager()
                _query_optimizer = DatabaseQueryOptimizer(database_manager)
    return _query_optimizer


# Convenience functions
def execute_optimized_query(query: str, parameters: List[Any] = None, cache_ttl: Optional[int] = None) -> Any:
    """Execute query with optimization"""
    optimizer = get_query_optimizer()
    return optimizer.execute_query(query, parameters, cache_ttl)


def batch_execute_queries(queries: List[Tuple[str, List[Any]]], batch_id: Optional[str] = None) -> Dict[str, Any]:
    """Execute multiple queries in a batch"""
    optimizer = get_query_optimizer()
    return optimizer.batch_execute(queries, batch_id)


def get_related_records(table: str, foreign_keys: List[Any], 
                       fields: str = "*", key_field: str = "id") -> Dict[Any, Any]:
    """Fetch related records efficiently"""
    optimizer = get_query_optimizer()
    return optimizer.get_related_records(table, foreign_keys, fields, key_field)