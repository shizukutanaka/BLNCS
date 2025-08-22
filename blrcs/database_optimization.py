# BLRCS Database Optimization System
# Advanced database performance optimization with query analysis and index management

import sqlite3
import time
import logging
import json
import threading
import hashlib
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, field
from pathlib import Path
from collections import defaultdict, deque
import re
import statistics
from contextlib import contextmanager
import os

logger = logging.getLogger(__name__)

@dataclass
class QueryMetrics:
    """Query performance metrics"""
    query_hash: str
    query: str
    execution_time: float
    rows_affected: int
    timestamp: float
    database_file: str
    frequency: int = 1

@dataclass
class IndexRecommendation:
    """Database index recommendation"""
    table: str
    columns: List[str]
    index_type: str  # btree, hash, unique
    reason: str
    estimated_improvement: float
    priority: str  # high, medium, low

@dataclass
class TableStatistics:
    """Table statistics and analysis"""
    name: str
    row_count: int
    size_bytes: int
    column_count: int
    index_count: int
    last_analyzed: float
    growth_rate: float = 0.0

class QueryAnalyzer:
    """SQL query analysis and optimization recommendations"""
    
    def __init__(self):
        self.query_patterns = {
            'select_no_where': r'SELECT.*FROM\s+(\w+)(?!.*WHERE)',
            'select_no_index': r'SELECT.*FROM\s+(\w+).*WHERE\s+(\w+)\s*=',
            'select_multiple_tables': r'SELECT.*FROM\s+(\w+).*JOIN\s+(\w+)',
            'insert_bulk': r'INSERT\s+INTO\s+(\w+)',
            'update_no_where': r'UPDATE\s+(\w+)(?!.*WHERE)',
            'delete_no_where': r'DELETE\s+FROM\s+(\w+)(?!.*WHERE)'
        }
        
    def analyze_query(self, query: str) -> Dict[str, Any]:
        """Analyze individual query for optimization opportunities"""
        query_clean = re.sub(r'\s+', ' ', query.strip().upper())
        
        analysis = {
            "query_type": self._identify_query_type(query_clean),
            "complexity_score": self._calculate_complexity(query_clean),
            "tables_accessed": self._extract_tables(query_clean),
            "potential_issues": [],
            "optimization_suggestions": []
        }
        
        # Check for common performance issues
        for pattern_name, pattern in self.query_patterns.items():
            if re.search(pattern, query_clean, re.IGNORECASE):
                analysis["potential_issues"].append(pattern_name)
                analysis["optimization_suggestions"].extend(
                    self._get_suggestions_for_pattern(pattern_name)
                )
        
        return analysis
    
    def _identify_query_type(self, query: str) -> str:
        """Identify the type of SQL query"""
        query = query.strip().upper()
        if query.startswith('SELECT'):
            return 'SELECT'
        elif query.startswith('INSERT'):
            return 'INSERT'
        elif query.startswith('UPDATE'):
            return 'UPDATE'
        elif query.startswith('DELETE'):
            return 'DELETE'
        elif query.startswith('CREATE'):
            return 'CREATE'
        else:
            return 'OTHER'
    
    def _calculate_complexity(self, query: str) -> int:
        """Calculate query complexity score"""
        score = 0
        
        # Count joins
        score += len(re.findall(r'\bJOIN\b', query, re.IGNORECASE)) * 3
        
        # Count subqueries
        score += len(re.findall(r'\(.*SELECT.*\)', query, re.IGNORECASE)) * 5
        
        # Count aggregate functions
        score += len(re.findall(r'\b(COUNT|SUM|AVG|MIN|MAX)\s*\(', query, re.IGNORECASE)) * 2
        
        # Count conditions
        score += len(re.findall(r'\bWHERE\b', query, re.IGNORECASE))
        score += len(re.findall(r'\bAND\b|\bOR\b', query, re.IGNORECASE))
        
        # Count sorting/grouping
        score += len(re.findall(r'\bORDER BY\b|\bGROUP BY\b', query, re.IGNORECASE)) * 2
        
        return score
    
    def _extract_tables(self, query: str) -> List[str]:
        """Extract table names from query"""
        tables = []
        
        # FROM clause
        from_matches = re.findall(r'\bFROM\s+(\w+)', query, re.IGNORECASE)
        tables.extend(from_matches)
        
        # JOIN clauses
        join_matches = re.findall(r'\bJOIN\s+(\w+)', query, re.IGNORECASE)
        tables.extend(join_matches)
        
        # INSERT/UPDATE/DELETE
        insert_matches = re.findall(r'\bINSERT\s+INTO\s+(\w+)', query, re.IGNORECASE)
        tables.extend(insert_matches)
        
        update_matches = re.findall(r'\bUPDATE\s+(\w+)', query, re.IGNORECASE)
        tables.extend(update_matches)
        
        delete_matches = re.findall(r'\bDELETE\s+FROM\s+(\w+)', query, re.IGNORECASE)
        tables.extend(delete_matches)
        
        return list(set(tables))
    
    def _get_suggestions_for_pattern(self, pattern_name: str) -> List[str]:
        """Get optimization suggestions for detected patterns"""
        suggestions = {
            'select_no_where': [
                "Consider adding WHERE clause to limit result set",
                "Use LIMIT to restrict number of rows returned"
            ],
            'select_no_index': [
                "Consider creating index on WHERE clause columns",
                "Analyze query execution plan for optimization"
            ],
            'select_multiple_tables': [
                "Ensure JOIN conditions use indexed columns",
                "Consider query restructuring for better performance"
            ],
            'insert_bulk': [
                "Consider using bulk INSERT for multiple rows",
                "Use transactions for better performance"
            ],
            'update_no_where': [
                "WARNING: UPDATE without WHERE affects all rows",
                "Add WHERE clause to limit scope"
            ],
            'delete_no_where': [
                "WARNING: DELETE without WHERE removes all rows",
                "Add WHERE clause to limit scope"
            ]
        }
        
        return suggestions.get(pattern_name, [])

class DatabaseOptimizer:
    """Database optimization engine"""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or "blrcs.db"
        self.query_analyzer = QueryAnalyzer()
        self.metrics: deque = deque(maxlen=1000)
        self.query_cache: Dict[str, QueryMetrics] = {}
        self.table_stats: Dict[str, TableStatistics] = {}
        self._lock = threading.Lock()
        
    @contextmanager
    def get_connection(self):
        """Get database connection with optimizations"""
        conn = sqlite3.connect(self.db_path)
        
        # Apply performance optimizations
        conn.execute("PRAGMA journal_mode = WAL")  # Write-Ahead Logging
        conn.execute("PRAGMA synchronous = NORMAL")  # Balanced durability/performance
        conn.execute("PRAGMA cache_size = 10000")  # 10MB cache
        conn.execute("PRAGMA temp_store = MEMORY")  # Store temp tables in memory
        
        try:
            yield conn
        finally:
            conn.close()
    
    def execute_with_metrics(self, query: str, parameters: tuple = None) -> Tuple[Any, QueryMetrics]:
        """Execute query with performance metrics collection"""
        start_time = time.time()
        query_hash = hashlib.sha256(query.encode()).hexdigest()[:16]
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            if parameters:
                result = cursor.execute(query, parameters)
            else:
                result = cursor.execute(query)
            
            # Get result data
            if query.strip().upper().startswith('SELECT'):
                data = result.fetchall()
                rows_affected = len(data)
            else:
                data = result
                rows_affected = cursor.rowcount
                conn.commit()
        
        execution_time = time.time() - start_time
        
        # Create metrics
        metrics = QueryMetrics(
            query_hash=query_hash,
            query=query,
            execution_time=execution_time,
            rows_affected=rows_affected,
            timestamp=time.time(),
            database_file=self.db_path
        )
        
        # Update metrics tracking
        with self._lock:
            if query_hash in self.query_cache:
                self.query_cache[query_hash].frequency += 1
                # Update average execution time
                old_metrics = self.query_cache[query_hash]
                old_metrics.execution_time = (
                    (old_metrics.execution_time * (old_metrics.frequency - 1) + execution_time) / 
                    old_metrics.frequency
                )
            else:
                self.query_cache[query_hash] = metrics
            
            self.metrics.append(metrics)
        
        return data, metrics
    
    def analyze_database_performance(self) -> Dict[str, Any]:
        """Comprehensive database performance analysis"""
        logger.info("🔍 Analyzing database performance")
        
        with self.get_connection() as conn:
            # Update table statistics
            self._update_table_statistics(conn)
            
            # Analyze query patterns
            query_analysis = self._analyze_query_patterns()
            
            # Generate index recommendations
            index_recommendations = self._generate_index_recommendations(conn)
            
            # Analyze database structure
            structure_analysis = self._analyze_database_structure(conn)
            
            # Calculate performance score
            performance_score = self._calculate_performance_score()
        
        return {
            "performance_score": performance_score,
            "table_statistics": {name: {
                "row_count": stats.row_count,
                "size_mb": round(stats.size_bytes / 1024 / 1024, 2),
                "index_count": stats.index_count,
                "growth_rate": stats.growth_rate
            } for name, stats in self.table_stats.items()},
            "query_analysis": query_analysis,
            "index_recommendations": [
                {
                    "table": rec.table,
                    "columns": rec.columns,
                    "type": rec.index_type,
                    "reason": rec.reason,
                    "priority": rec.priority,
                    "estimated_improvement": f"{rec.estimated_improvement:.1f}%"
                }
                for rec in index_recommendations
            ],
            "structure_analysis": structure_analysis,
            "optimization_summary": self._generate_optimization_summary(
                query_analysis, index_recommendations, structure_analysis
            )
        }
    
    def _update_table_statistics(self, conn: sqlite3.Connection):
        """Update table statistics"""
        # Get all tables
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        for table in tables:
            try:
                # Count rows
                cursor = conn.execute(f"SELECT COUNT(*) FROM {table}")
                row_count = cursor.fetchone()[0]
                
                # Get table info
                cursor = conn.execute(f"PRAGMA table_info({table})")
                columns = cursor.fetchall()
                
                # Get index info
                cursor = conn.execute(f"PRAGMA index_list({table})")
                indexes = cursor.fetchall()
                
                # Calculate estimated size (rough approximation)
                size_bytes = row_count * len(columns) * 50  # Rough estimate
                
                # Update statistics
                self.table_stats[table] = TableStatistics(
                    name=table,
                    row_count=row_count,
                    size_bytes=size_bytes,
                    column_count=len(columns),
                    index_count=len(indexes),
                    last_analyzed=time.time()
                )
                
            except Exception as e:
                logger.warning(f"Failed to analyze table {table}: {e}")
    
    def _analyze_query_patterns(self) -> Dict[str, Any]:
        """Analyze query patterns from metrics"""
        if not self.metrics:
            return {"message": "No query metrics available"}
        
        # Group queries by type
        query_types = defaultdict(list)
        for metric in self.metrics:
            analysis = self.query_analyzer.analyze_query(metric.query)
            query_types[analysis["query_type"]].append(metric)
        
        # Calculate statistics
        type_stats = {}
        for query_type, metrics_list in query_types.items():
            execution_times = [m.execution_time for m in metrics_list]
            type_stats[query_type] = {
                "count": len(metrics_list),
                "avg_execution_time": statistics.mean(execution_times),
                "max_execution_time": max(execution_times),
                "total_time": sum(execution_times)
            }
        
        # Find slow queries
        slow_queries = [
            {
                "query": m.query[:100] + "..." if len(m.query) > 100 else m.query,
                "execution_time": m.execution_time,
                "frequency": self.query_cache.get(m.query_hash, m).frequency
            }
            for m in sorted(self.metrics, key=lambda x: x.execution_time, reverse=True)[:5]
        ]
        
        return {
            "total_queries": len(self.metrics),
            "query_type_breakdown": type_stats,
            "slow_queries": slow_queries,
            "average_execution_time": statistics.mean([m.execution_time for m in self.metrics]),
            "performance_trends": self._calculate_performance_trends()
        }
    
    def _generate_index_recommendations(self, conn: sqlite3.Connection) -> List[IndexRecommendation]:
        """Generate index recommendations based on query patterns"""
        recommendations = []
        
        # Analyze frequent WHERE clauses
        where_columns = defaultdict(int)
        for metric in self.metrics:
            # Extract WHERE column patterns
            where_matches = re.findall(r'WHERE\s+(\w+)\s*=', metric.query, re.IGNORECASE)
            for column in where_matches:
                where_columns[column] += self.query_cache.get(metric.query_hash, metric).frequency
        
        # Recommend indexes for frequently queried columns
        for column, frequency in where_columns.items():
            if frequency >= 5:  # Threshold for recommendation
                # Try to determine table (simplified approach)
                table = self._guess_table_for_column(conn, column)
                if table:
                    recommendations.append(IndexRecommendation(
                        table=table,
                        columns=[column],
                        index_type="btree",
                        reason=f"Frequently used in WHERE clause ({frequency} times)",
                        estimated_improvement=min(frequency * 2, 50),  # Rough estimate
                        priority="high" if frequency > 20 else "medium"
                    ))
        
        # Analyze JOIN patterns
        join_patterns = self._analyze_join_patterns()
        for pattern in join_patterns:
            recommendations.append(IndexRecommendation(
                table=pattern["table"],
                columns=pattern["columns"],
                index_type="btree",
                reason="Frequently used in JOIN operations",
                estimated_improvement=20,
                priority="medium"
            ))
        
        return recommendations[:10]  # Limit to top 10 recommendations
    
    def _guess_table_for_column(self, conn: sqlite3.Connection, column: str) -> Optional[str]:
        """Try to guess which table a column belongs to"""
        # Get all tables and their columns
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        for table in tables:
            try:
                cursor = conn.execute(f"PRAGMA table_info({table})")
                columns = [col[1] for col in cursor.fetchall()]
                if column in columns:
                    return table
            except:
                continue
        
        return None
    
    def _analyze_join_patterns(self) -> List[Dict[str, Any]]:
        """Analyze JOIN patterns for index recommendations"""
        join_patterns = []
        
        for metric in self.metrics:
            # Look for JOIN patterns
            join_matches = re.findall(
                r'JOIN\s+(\w+)\s+.*?ON\s+(\w+)\.(\w+)\s*=\s*(\w+)\.(\w+)',
                metric.query,
                re.IGNORECASE
            )
            
            for match in join_matches:
                table, table1, col1, table2, col2 = match
                join_patterns.append({
                    "table": table,
                    "columns": [col1, col2],
                    "frequency": self.query_cache.get(metric.query_hash, metric).frequency
                })
        
        # Group and count
        pattern_counts = defaultdict(int)
        for pattern in join_patterns:
            key = f"{pattern['table']}:{','.join(pattern['columns'])}"
            pattern_counts[key] += pattern['frequency']
        
        # Convert back to list format
        result = []
        for key, count in pattern_counts.items():
            if count >= 3:  # Threshold
                table, columns_str = key.split(':', 1)
                result.append({
                    "table": table,
                    "columns": columns_str.split(','),
                    "frequency": count
                })
        
        return result
    
    def _analyze_database_structure(self, conn: sqlite3.Connection) -> Dict[str, Any]:
        """Analyze database structure for optimization opportunities"""
        
        # Check for tables without primary keys
        tables_without_pk = []
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        for table in tables:
            try:
                cursor = conn.execute(f"PRAGMA table_info({table})")
                columns = cursor.fetchall()
                has_pk = any(col[5] for col in columns)  # col[5] is pk flag
                if not has_pk:
                    tables_without_pk.append(table)
            except:
                continue
        
        # Check for unused indexes
        unused_indexes = self._find_unused_indexes(conn)
        
        # Check for large tables without indexes
        large_unindexed_tables = []
        for table, stats in self.table_stats.items():
            if stats.row_count > 1000 and stats.index_count == 0:
                large_unindexed_tables.append(table)
        
        return {
            "total_tables": len(tables),
            "tables_without_primary_key": tables_without_pk,
            "unused_indexes": unused_indexes,
            "large_unindexed_tables": large_unindexed_tables,
            "database_size_mb": sum(stats.size_bytes for stats in self.table_stats.values()) / 1024 / 1024
        }
    
    def _find_unused_indexes(self, conn: sqlite3.Connection) -> List[str]:
        """Find potentially unused indexes"""
        unused = []
        
        try:
            # Get all indexes
            cursor = conn.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='index' AND name NOT LIKE 'sqlite_%'
            """)
            indexes = [row[0] for row in cursor.fetchall()]
            
            # For SQLite, we can't easily detect unused indexes without query logs
            # This is a simplified approach based on naming patterns
            for index in indexes:
                if '_auto_' in index or index.startswith('idx_temp_'):
                    unused.append(index)
        
        except Exception as e:
            logger.warning(f"Failed to analyze indexes: {e}")
        
        return unused
    
    def _calculate_performance_trends(self) -> Dict[str, Any]:
        """Calculate performance trends over time"""
        if len(self.metrics) < 10:
            return {"message": "Insufficient data for trend analysis"}
        
        # Group metrics by time buckets (last hour, last day, etc.)
        recent_metrics = [m for m in self.metrics if time.time() - m.timestamp < 3600]  # Last hour
        older_metrics = [m for m in self.metrics if time.time() - m.timestamp >= 3600]
        
        if not recent_metrics or not older_metrics:
            return {"message": "Insufficient historical data"}
        
        recent_avg = statistics.mean([m.execution_time for m in recent_metrics])
        older_avg = statistics.mean([m.execution_time for m in older_metrics])
        
        trend = ((recent_avg - older_avg) / older_avg) * 100 if older_avg > 0 else 0
        
        return {
            "recent_average_ms": round(recent_avg * 1000, 2),
            "historical_average_ms": round(older_avg * 1000, 2),
            "trend_percentage": round(trend, 2),
            "trend_direction": "improving" if trend < 0 else "degrading" if trend > 5 else "stable"
        }
    
    def _calculate_performance_score(self) -> float:
        """Calculate overall database performance score"""
        score = 100.0
        
        if not self.metrics:
            return 50.0  # Neutral score if no data
        
        # Penalize slow queries
        avg_execution_time = statistics.mean([m.execution_time for m in self.metrics])
        if avg_execution_time > 1.0:  # > 1 second
            score -= 30
        elif avg_execution_time > 0.5:  # > 500ms
            score -= 15
        elif avg_execution_time > 0.1:  # > 100ms
            score -= 5
        
        # Penalize tables without indexes
        large_unindexed = sum(1 for stats in self.table_stats.values() 
                             if stats.row_count > 1000 and stats.index_count == 0)
        score -= large_unindexed * 10
        
        # Penalize frequent slow queries
        slow_query_ratio = len([m for m in self.metrics if m.execution_time > 0.5]) / len(self.metrics)
        score -= slow_query_ratio * 20
        
        return max(0.0, min(100.0, score))
    
    def _generate_optimization_summary(self, query_analysis: Dict, 
                                     index_recommendations: List[IndexRecommendation],
                                     structure_analysis: Dict) -> List[str]:
        """Generate optimization summary and recommendations"""
        summary = []
        
        # Performance issues
        if query_analysis.get("average_execution_time", 0) > 0.5:
            summary.append("High average query execution time detected - consider query optimization")
        
        # Index recommendations
        high_priority_indexes = [r for r in index_recommendations if r.priority == "high"]
        if high_priority_indexes:
            summary.append(f"{len(high_priority_indexes)} high-priority index recommendations available")
        
        # Structure issues
        tables_without_pk = structure_analysis.get("tables_without_primary_key", [])
        if tables_without_pk:
            summary.append(f"{len(tables_without_pk)} tables missing primary keys")
        
        large_unindexed = structure_analysis.get("large_unindexed_tables", [])
        if large_unindexed:
            summary.append(f"{len(large_unindexed)} large tables without indexes")
        
        # Performance trends
        if "performance_trends" in query_analysis:
            trends = query_analysis["performance_trends"]
            if isinstance(trends, dict) and trends.get("trend_direction") == "degrading":
                summary.append("Performance trend is degrading - investigate recent changes")
        
        return summary or ["Database performance appears optimal"]

# Global optimizer instance
db_optimizer = DatabaseOptimizer()

def optimize_database() -> Dict[str, Any]:
    """Optimize database performance"""
    return db_optimizer.analyze_database_performance()

def execute_optimized_query(query: str, parameters: tuple = None) -> Tuple[Any, Dict[str, Any]]:
    """Execute query with optimization metrics"""
    result, metrics = db_optimizer.execute_with_metrics(query, parameters)
    return result, {
        "execution_time_ms": round(metrics.execution_time * 1000, 2),
        "rows_affected": metrics.rows_affected,
        "query_hash": metrics.query_hash
    }