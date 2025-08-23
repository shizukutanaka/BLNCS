"""
Database Abstraction Layer
Enterprise-grade database management with multiple backend support
"""

import sqlite3
import time
import json
import threading
import queue
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from contextlib import contextmanager
import hashlib
from pathlib import Path


class DatabaseEngine(Enum):
    """Supported database engines"""
    SQLITE = "sqlite"
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    MONGODB = "mongodb"
    REDIS = "redis"


class IsolationLevel(Enum):
    """Transaction isolation levels"""
    READ_UNCOMMITTED = "READ UNCOMMITTED"
    READ_COMMITTED = "READ COMMITTED"
    REPEATABLE_READ = "REPEATABLE READ"
    SERIALIZABLE = "SERIALIZABLE"


@dataclass
class QueryResult:
    """Database query result"""
    rows: List[Dict[str, Any]]
    affected_rows: int = 0
    last_insert_id: Optional[int] = None
    execution_time: float = 0
    success: bool = True
    error: Optional[str] = None


@dataclass
class TransactionContext:
    """Transaction context"""
    id: str
    start_time: float = field(default_factory=time.time)
    isolation_level: IsolationLevel = IsolationLevel.READ_COMMITTED
    savepoints: List[str] = field(default_factory=list)
    committed: bool = False
    rolled_back: bool = False


class ConnectionPool:
    """Database connection pool"""
    
    def __init__(self, create_connection, max_size: int = 20, 
                 min_size: int = 5, timeout: int = 30):
        self.create_connection = create_connection
        self.max_size = max_size
        self.min_size = min_size
        self.timeout = timeout
        self.pool = queue.Queue(maxsize=max_size)
        self.active_connections = 0
        self.lock = threading.Lock()
        
        # Pre-create minimum connections
        for _ in range(min_size):
            conn = self.create_connection()
            self.pool.put(conn)
            self.active_connections += 1
            
    def get_connection(self):
        """Get connection from pool"""
        try:
            # Try to get from pool
            conn = self.pool.get_nowait()
            
            # Validate connection
            if self._validate_connection(conn):
                return conn
            else:
                # Connection is dead, create new one
                with self.lock:
                    self.active_connections -= 1
                return self._create_new_connection()
                
        except queue.Empty:
            # Pool is empty, create new connection if under limit
            with self.lock:
                if self.active_connections < self.max_size:
                    return self._create_new_connection()
                    
            # Wait for available connection
            try:
                conn = self.pool.get(timeout=self.timeout)
                if self._validate_connection(conn):
                    return conn
                else:
                    with self.lock:
                        self.active_connections -= 1
                    return self._create_new_connection()
            except queue.Empty:
                raise TimeoutError("Connection pool timeout")
                
    def return_connection(self, conn):
        """Return connection to pool"""
        if self._validate_connection(conn):
            try:
                self.pool.put_nowait(conn)
            except queue.Full:
                # Pool is full, close connection
                self._close_connection(conn)
                with self.lock:
                    self.active_connections -= 1
        else:
            # Connection is dead, don't return to pool
            with self.lock:
                self.active_connections -= 1
                
    def _create_new_connection(self):
        """Create new connection"""
        conn = self.create_connection()
        with self.lock:
            self.active_connections += 1
        return conn
        
    def _validate_connection(self, conn) -> bool:
        """Validate connection is alive"""
        try:
            # Simple validation - override in subclasses
            if hasattr(conn, 'execute'):
                conn.execute("SELECT 1")
            return True
        except Exception:
            return False
            
    def _close_connection(self, conn):
        """Close connection"""
        try:
            conn.close()
        except Exception:
            pass
            
    def close_all(self):
        """Close all connections"""
        while not self.pool.empty():
            try:
                conn = self.pool.get_nowait()
                self._close_connection(conn)
            except queue.Empty:
                break
                
        with self.lock:
            self.active_connections = 0


class QueryBuilder:
    """SQL query builder"""
    
    def __init__(self):
        self.reset()
        
    def reset(self):
        """Reset query builder"""
        self._select_fields = []
        self._from_table = None
        self._joins = []
        self._where_conditions = []
        self._group_by_fields = []
        self._having_conditions = []
        self._order_by_fields = []
        self._limit_value = None
        self._offset_value = None
        return self
        
    def select(self, *fields):
        """Add SELECT fields"""
        self._select_fields.extend(fields)
        return self
        
    def from_table(self, table: str):
        """Set FROM table"""
        self._from_table = table
        return self
        
    def join(self, table: str, condition: str, join_type: str = "INNER"):
        """Add JOIN"""
        self._joins.append((join_type, table, condition))
        return self
        
    def where(self, condition: str, *params):
        """Add WHERE condition"""
        self._where_conditions.append((condition, params))
        return self
        
    def group_by(self, *fields):
        """Add GROUP BY"""
        self._group_by_fields.extend(fields)
        return self
        
    def having(self, condition: str):
        """Add HAVING condition"""
        self._having_conditions.append(condition)
        return self
        
    def order_by(self, field: str, direction: str = "ASC"):
        """Add ORDER BY"""
        self._order_by_fields.append(f"{field} {direction}")
        return self
        
    def limit(self, value: int):
        """Set LIMIT"""
        self._limit_value = value
        return self
        
    def offset(self, value: int):
        """Set OFFSET"""
        self._offset_value = value
        return self
        
    def build(self) -> Tuple[str, List[Any]]:
        """Build SQL query"""
        parts = []
        params = []
        
        # SELECT
        if self._select_fields:
            fields = ", ".join(self._select_fields)
            parts.append(f"SELECT {fields}")
        else:
            parts.append("SELECT *")
            
        # FROM
        if self._from_table:
            parts.append(f"FROM {self._from_table}")
            
        # JOIN
        for join_type, table, condition in self._joins:
            parts.append(f"{join_type} JOIN {table} ON {condition}")
            
        # WHERE
        if self._where_conditions:
            conditions = []
            for condition, condition_params in self._where_conditions:
                conditions.append(condition)
                params.extend(condition_params)
            parts.append(f"WHERE {' AND '.join(conditions)}")
            
        # GROUP BY
        if self._group_by_fields:
            fields = ", ".join(self._group_by_fields)
            parts.append(f"GROUP BY {fields}")
            
        # HAVING
        if self._having_conditions:
            conditions = " AND ".join(self._having_conditions)
            parts.append(f"HAVING {conditions}")
            
        # ORDER BY
        if self._order_by_fields:
            fields = ", ".join(self._order_by_fields)
            parts.append(f"ORDER BY {fields}")
            
        # LIMIT
        if self._limit_value is not None:
            parts.append(f"LIMIT {self._limit_value}")
            
        # OFFSET
        if self._offset_value is not None:
            parts.append(f"OFFSET {self._offset_value}")
            
        query = " ".join(parts)
        return query, params


class DatabaseMigration:
    """Database migration system"""
    
    def __init__(self, db):
        self.db = db
        self.migrations_table = "schema_migrations"
        self._ensure_migrations_table()
        
    def _ensure_migrations_table(self):
        """Ensure migrations table exists"""
        self.db.execute(f"""
            CREATE TABLE IF NOT EXISTS {self.migrations_table} (
                version VARCHAR(255) PRIMARY KEY,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
    def get_applied_migrations(self) -> List[str]:
        """Get list of applied migrations"""
        result = self.db.query(
            f"SELECT version FROM {self.migrations_table} ORDER BY version"
        )
        return [row['version'] for row in result.rows]
        
    def apply_migration(self, version: str, up_sql: str):
        """Apply migration"""
        try:
            # Start transaction
            with self.db.transaction():
                # Execute migration
                for statement in up_sql.split(';'):
                    if statement.strip():
                        self.db.execute(statement)
                        
                # Record migration
                self.db.execute(
                    f"INSERT INTO {self.migrations_table} (version) VALUES (?)",
                    version
                )
                
            return True
        except Exception as e:
            raise Exception(f"Migration {version} failed: {str(e)}")
            
    def rollback_migration(self, version: str, down_sql: str):
        """Rollback migration"""
        try:
            # Start transaction
            with self.db.transaction():
                # Execute rollback
                for statement in down_sql.split(';'):
                    if statement.strip():
                        self.db.execute(statement)
                        
                # Remove migration record
                self.db.execute(
                    f"DELETE FROM {self.migrations_table} WHERE version = ?",
                    version
                )
                
            return True
        except Exception as e:
            raise Exception(f"Rollback {version} failed: {str(e)}")


class Database:
    """Main database interface"""
    
    def __init__(self, engine: DatabaseEngine = DatabaseEngine.SQLITE,
                 connection_string: str = "blrcs.db",
                 pool_size: int = 20):
        self.engine = engine
        self.connection_string = connection_string
        self.pool = None
        self.transactions = {}
        self.lock = threading.Lock()
        
        # Initialize connection pool
        self._init_pool(pool_size)
        
        # Initialize migration system
        self.migrations = DatabaseMigration(self)
        
    def _init_pool(self, pool_size: int):
        """Initialize connection pool"""
        if self.engine == DatabaseEngine.SQLITE:
            def create_connection():
                conn = sqlite3.connect(
                    self.connection_string,
                    check_same_thread=False,
                    isolation_level=None
                )
                conn.row_factory = sqlite3.Row
                return conn
                
            self.pool = ConnectionPool(create_connection, max_size=pool_size)
            
        # Add other database engines as needed
        
    def execute(self, query: str, *params) -> QueryResult:
        """Execute query"""
        start_time = time.time()
        conn = self.pool.get_connection()
        
        try:
            cursor = conn.cursor()
            
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
                
            # Get results
            if query.strip().upper().startswith("SELECT"):
                rows = [dict(row) for row in cursor.fetchall()]
            else:
                rows = []
                
            affected_rows = cursor.rowcount
            last_insert_id = cursor.lastrowid
            
            conn.commit()
            
            result = QueryResult(
                rows=rows,
                affected_rows=affected_rows,
                last_insert_id=last_insert_id,
                execution_time=time.time() - start_time,
                success=True
            )
            
        except Exception as e:
            conn.rollback()
            result = QueryResult(
                rows=[],
                success=False,
                error=str(e),
                execution_time=time.time() - start_time
            )
            
        finally:
            self.pool.return_connection(conn)
            
        return result
        
    def query(self, query: str, *params) -> QueryResult:
        """Execute SELECT query"""
        return self.execute(query, *params)
        
    def insert(self, table: str, data: Dict[str, Any]) -> QueryResult:
        """Insert data"""
        fields = list(data.keys())
        values = list(data.values())
        placeholders = ", ".join(["?" for _ in fields])
        
        query = f"INSERT INTO {table} ({', '.join(fields)}) VALUES ({placeholders})"
        return self.execute(query, *values)
        
    def update(self, table: str, data: Dict[str, Any], 
              where: Dict[str, Any]) -> QueryResult:
        """Update data"""
        # Build SET clause
        set_fields = []
        set_values = []
        for field, value in data.items():
            set_fields.append(f"{field} = ?")
            set_values.append(value)
            
        # Build WHERE clause
        where_fields = []
        where_values = []
        for field, value in where.items():
            where_fields.append(f"{field} = ?")
            where_values.append(value)
            
        query = f"UPDATE {table} SET {', '.join(set_fields)} WHERE {' AND '.join(where_fields)}"
        return self.execute(query, *(set_values + where_values))
        
    def delete(self, table: str, where: Dict[str, Any]) -> QueryResult:
        """Delete data"""
        where_fields = []
        where_values = []
        for field, value in where.items():
            where_fields.append(f"{field} = ?")
            where_values.append(value)
            
        query = f"DELETE FROM {table} WHERE {' AND '.join(where_fields)}"
        return self.execute(query, *where_values)
        
    @contextmanager
    def transaction(self, isolation_level: IsolationLevel = IsolationLevel.READ_COMMITTED):
        """Transaction context manager"""
        transaction_id = hashlib.md5(
            f"{threading.get_ident()}{time.time()}".encode()
        ).hexdigest()
        
        transaction = TransactionContext(
            id=transaction_id,
            isolation_level=isolation_level
        )
        
        conn = self.pool.get_connection()
        
        try:
            # Start transaction
            if self.engine == DatabaseEngine.SQLITE:
                conn.execute(f"BEGIN {isolation_level.value}")
                
            self.transactions[transaction_id] = transaction
            
            yield transaction
            
            # Commit transaction
            conn.commit()
            transaction.committed = True
            
        except Exception as e:
            # Rollback transaction
            conn.rollback()
            transaction.rolled_back = True
            raise e
            
        finally:
            # Clean up
            del self.transactions[transaction_id]
            self.pool.return_connection(conn)
            
    def create_savepoint(self, name: str):
        """Create savepoint in current transaction"""
        self.execute(f"SAVEPOINT {name}")
        
    def rollback_to_savepoint(self, name: str):
        """Rollback to savepoint"""
        self.execute(f"ROLLBACK TO SAVEPOINT {name}")
        
    def release_savepoint(self, name: str):
        """Release savepoint"""
        self.execute(f"RELEASE SAVEPOINT {name}")
        
    def backup(self, backup_path: str):
        """Backup database"""
        if self.engine == DatabaseEngine.SQLITE:
            import shutil
            shutil.copy2(self.connection_string, backup_path)
            return True
        # Add other database backup methods
        return False
        
    def restore(self, backup_path: str):
        """Restore database from backup"""
        if self.engine == DatabaseEngine.SQLITE:
            import shutil
            shutil.copy2(backup_path, self.connection_string)
            return True
        # Add other database restore methods
        return False
        
    def optimize(self):
        """Optimize database"""
        if self.engine == DatabaseEngine.SQLITE:
            self.execute("VACUUM")
            self.execute("ANALYZE")
        # Add other database optimization methods
        
    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        stats = {
            "engine": self.engine.value,
            "pool_size": self.pool.max_size if self.pool else 0,
            "active_connections": self.pool.active_connections if self.pool else 0,
            "active_transactions": len(self.transactions)
        }
        
        if self.engine == DatabaseEngine.SQLITE:
            # Get SQLite specific stats
            result = self.query("SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()")
            if result.rows:
                stats["database_size"] = result.rows[0]["size"]
                
        return stats
        
    def close(self):
        """Close database connections"""
        if self.pool:
            self.pool.close_all()


# Global database instance
_database = None


def get_database() -> Database:
    """Get global database instance"""
    global _database
    if _database is None:
        _database = Database()
    return _database


def init_database(engine: DatabaseEngine = DatabaseEngine.SQLITE,
                 connection_string: str = "blrcs.db",
                 pool_size: int = 20) -> Database:
    """Initialize database"""
    global _database
    _database = Database(engine, connection_string, pool_size)
    return _database