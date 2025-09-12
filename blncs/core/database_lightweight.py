"""
Lightweight Database System for BLNCS
Simple SQLite wrapper focusing on performance and reliability.
"""

import sqlite3
import threading
import time
from typing import Dict, List, Any, Optional, Union, Tuple
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime
import json

from .logger import get_logger

logger = get_logger(__name__)

class LightweightDatabase:
    """Lightweight database manager with connection pooling."""
    
    def __init__(self, db_path: str = "blncs.db", pool_size: int = 5):
        """Initialize lightweight database manager."""
        self.db_path = Path(db_path)
        self.pool_size = pool_size
        self.connections = []
        self.lock = threading.Lock()
        self.logger = get_logger(__name__)
        
        # Simple prepared statement cache
        self._prepared_statements = {}
        
        # Initialize database
        self._init_database()
        self._create_connection_pool()
    
    def _init_database(self):
        """Initialize database with basic optimizations."""
        self.db_path.parent.mkdir(exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA temp_store=memory")
            conn.execute("PRAGMA mmap_size=268435456")  # 256MB
            conn.commit()
            
    def _create_connection_pool(self):
        """Create connection pool."""
        for _ in range(self.pool_size):
            conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=30.0
            )
            conn.row_factory = sqlite3.Row
            self.connections.append(conn)
    
    @contextmanager
    def get_connection(self):
        """Get a connection from pool."""
        with self.lock:
            if self.connections:
                conn = self.connections.pop()
            else:
                conn = sqlite3.connect(
                    self.db_path,
                    check_same_thread=False,
                    timeout=30.0
                )
                conn.row_factory = sqlite3.Row
        
        try:
            yield conn
        finally:
            with self.lock:
                if len(self.connections) < self.pool_size:
                    self.connections.append(conn)
                else:
                    conn.close()
    
    def execute(self, query: str, params: Tuple = ()) -> int:
        """Execute a query and return affected row count."""
        with self.get_connection() as conn:
            cursor = conn.execute(query, params)
            conn.commit()
            return cursor.rowcount
    
    def fetch_one(self, query: str, params: Tuple = ()) -> Optional[Dict]:
        """Fetch one row as dictionary."""
        with self.get_connection() as conn:
            cursor = conn.execute(query, params)
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def fetch_all(self, query: str, params: Tuple = ()) -> List[Dict]:
        """Fetch all rows as list of dictionaries."""
        with self.get_connection() as conn:
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    
    def fetch_value(self, query: str, params: Tuple = ()) -> Any:
        """Fetch single value."""
        row = self.fetch_one(query, params)
        return list(row.values())[0] if row else None
    
    def insert(self, table: str, data: Dict[str, Any]) -> int:
        """Insert data into table and return row ID."""
        columns = list(data.keys())
        placeholders = ','.join('?' * len(columns))
        query = f"INSERT INTO {table} ({','.join(columns)}) VALUES ({placeholders})"
        
        with self.get_connection() as conn:
            cursor = conn.execute(query, list(data.values()))
            conn.commit()
            return cursor.lastrowid
    
    def update(self, table: str, data: Dict[str, Any], where: str, params: Tuple = ()) -> int:
        """Update table data."""
        set_clause = ','.join(f"{col} = ?" for col in data.keys())
        query = f"UPDATE {table} SET {set_clause} WHERE {where}"
        
        with self.get_connection() as conn:
            cursor = conn.execute(query, list(data.values()) + list(params))
            conn.commit()
            return cursor.rowcount
    
    def delete(self, table: str, where: str, params: Tuple = ()) -> int:
        """Delete from table."""
        query = f"DELETE FROM {table} WHERE {where}"
        return self.execute(query, params)
    
    def ensure_table(self, table_name: str, schema: str):
        """Ensure table exists with given schema."""
        query = f"CREATE TABLE IF NOT EXISTS {table_name} ({schema})"
        self.execute(query)
    
    def get_table_info(self, table_name: str) -> List[Dict]:
        """Get table structure information."""
        return self.fetch_all(f"PRAGMA table_info({table_name})")
    
    def vacuum(self):
        """Optimize database."""
        with self.get_connection() as conn:
            conn.execute("VACUUM")
            conn.commit()
    
    def close(self):
        """Close all connections."""
        with self.lock:
            for conn in self.connections:
                conn.close()
            self.connections.clear()

# Create singleton instance
_db_instance = None
_db_lock = threading.Lock()

def get_database(db_path: str = "blncs.db") -> LightweightDatabase:
    """Get or create database instance."""
    global _db_instance
    if _db_instance is None:
        with _db_lock:
            if _db_instance is None:
                _db_instance = LightweightDatabase(db_path)
    return _db_instance

# For backward compatibility
DatabaseManager = LightweightDatabase

__all__ = ['LightweightDatabase', 'DatabaseManager', 'get_database']