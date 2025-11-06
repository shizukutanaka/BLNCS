#!/usr/bin/env python3
"""
Unified Database System for BLNCS
統一されたデータベースシステム
"""

import os
import sqlite3
import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from datetime import datetime
import json
import logging

# Try to import SQLAlchemy for ORM support
try:
    from sqlalchemy import create_engine, text, MetaData, Table, Column, Integer, String, DateTime, Float, Boolean, JSON
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import sessionmaker, Session
    from sqlalchemy.pool import QueuePool
    HAS_SQLALCHEMY = True
    Base = declarative_base()
except ImportError:
    HAS_SQLALCHEMY = False
    Base = None

logger = logging.getLogger(__name__)


class UnifiedDatabase:
    """
    Unified database interface supporting SQLite and PostgreSQL
    Provides both sync and async operations with fallback to sqlite3
    """

    def __init__(
        self,
        database_url: Optional[str] = None,
        pool_size: int = 5,
        max_overflow: int = 10,
        echo: bool = False,
        auto_create: bool = True
    ):
        self.database_url = database_url or os.getenv('BLNCS_DATABASE_URL', 'sqlite:///./blncs.db')
        self.pool_size = pool_size
        self.max_overflow = max_overflow
        self.echo = echo
        self.auto_create = auto_create

        # Parse database type
        self.db_type = self._parse_db_type(self.database_url)

        # Initialize database connection
        if HAS_SQLALCHEMY and self.db_type != 'sqlite_native':
            self._init_sqlalchemy()
        else:
            self._init_sqlite()

        # Create tables if needed
        if self.auto_create:
            self.create_tables()

    def _parse_db_type(self, url: str) -> str:
        """Parse database type from URL"""
        if url.startswith('sqlite:///'):
            return 'sqlite'
        elif url.startswith('postgresql://'):
            return 'postgresql'
        elif url.startswith('mysql://'):
            return 'mysql'
        elif url.endswith('.db'):
            return 'sqlite_native'
        else:
            return 'sqlite_native'

    def _init_sqlalchemy(self):
        """Initialize SQLAlchemy connection"""
        try:
            self.engine = create_engine(
                self.database_url,
                pool_size=self.pool_size,
                max_overflow=self.max_overflow,
                echo=self.echo,
                poolclass=QueuePool if self.db_type != 'sqlite' else None
            )
            self.SessionLocal = sessionmaker(bind=self.engine)
            self.metadata = MetaData()
            self.using_sqlalchemy = True
            logger.info(f"Initialized SQLAlchemy with {self.db_type}")
        except Exception as e:
            logger.warning(f"Failed to initialize SQLAlchemy: {e}, falling back to sqlite3")
            self._init_sqlite()

    def _init_sqlite(self):
        """Initialize native SQLite connection"""
        # Extract path from URL if needed
        if self.database_url.startswith('sqlite:///'):
            db_path = self.database_url.replace('sqlite:///', '')
        else:
            db_path = self.database_url

        # Ensure directory exists
        db_file = Path(db_path)
        db_file.parent.mkdir(parents=True, exist_ok=True)

        self.db_path = str(db_file)
        self.using_sqlalchemy = False
        logger.info(f"Initialized native SQLite at {self.db_path}")

    def _get_connection(self) -> Union[Any, sqlite3.Connection]:
        """Get database connection"""
        if self.using_sqlalchemy:
            return self.SessionLocal()
        else:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            return conn

    def create_tables(self):
        """Create required database tables"""
        if self.using_sqlalchemy:
            self._create_tables_sqlalchemy()
        else:
            self._create_tables_sqlite()

    def _create_tables_sqlalchemy(self):
        """Create tables using SQLAlchemy"""
        # Define tables
        channels_table = Table(
            'channels',
            self.metadata,
            Column('id', Integer, primary_key=True),
            Column('channel_id', String(64), unique=True, index=True),
            Column('peer_id', String(66), index=True),
            Column('capacity', Integer),
            Column('local_balance', Integer),
            Column('remote_balance', Integer),
            Column('status', String(20)),
            Column('created_at', DateTime, default=datetime.utcnow),
            Column('updated_at', DateTime, default=datetime.utcnow, onupdate=datetime.utcnow),
            Column('metadata', JSON)
        )

        transactions_table = Table(
            'transactions',
            self.metadata,
            Column('id', Integer, primary_key=True),
            Column('payment_hash', String(64), unique=True, index=True),
            Column('payment_request', String(1024)),
            Column('amount', Integer),
            Column('fee', Integer),
            Column('status', String(20)),
            Column('type', String(20)),  # incoming/outgoing
            Column('created_at', DateTime, default=datetime.utcnow),
            Column('settled_at', DateTime),
            Column('metadata', JSON)
        )

        invoices_table = Table(
            'invoices',
            self.metadata,
            Column('id', Integer, primary_key=True),
            Column('payment_hash', String(64), unique=True, index=True),
            Column('payment_request', String(1024)),
            Column('amount', Integer),
            Column('description', String(1024)),
            Column('status', String(20)),
            Column('created_at', DateTime, default=datetime.utcnow),
            Column('expires_at', DateTime),
            Column('settled_at', DateTime),
            Column('metadata', JSON)
        )

        metrics_table = Table(
            'metrics',
            self.metadata,
            Column('id', Integer, primary_key=True),
            Column('metric_name', String(100), index=True),
            Column('value', Float),
            Column('tags', JSON),
            Column('timestamp', DateTime, default=datetime.utcnow, index=True)
        )

        # Create all tables
        self.metadata.create_all(self.engine)
        logger.info("Created database tables using SQLAlchemy")

    def _create_tables_sqlite(self):
        """Create tables using native SQLite"""
        queries = [
            """
            CREATE TABLE IF NOT EXISTS channels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_id TEXT UNIQUE NOT NULL,
                peer_id TEXT NOT NULL,
                capacity INTEGER,
                local_balance INTEGER,
                remote_balance INTEGER,
                status TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                metadata TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payment_hash TEXT UNIQUE NOT NULL,
                payment_request TEXT,
                amount INTEGER,
                fee INTEGER,
                status TEXT,
                type TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                settled_at TIMESTAMP,
                metadata TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS invoices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payment_hash TEXT UNIQUE NOT NULL,
                payment_request TEXT,
                amount INTEGER,
                description TEXT,
                status TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                settled_at TIMESTAMP,
                metadata TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                metric_name TEXT,
                value REAL,
                tags TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            # Create indexes
            "CREATE INDEX IF NOT EXISTS idx_channels_peer ON channels(peer_id)",
            "CREATE INDEX IF NOT EXISTS idx_transactions_hash ON transactions(payment_hash)",
            "CREATE INDEX IF NOT EXISTS idx_invoices_hash ON invoices(payment_hash)",
            "CREATE INDEX IF NOT EXISTS idx_metrics_name ON metrics(metric_name)",
            "CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp)"
        ]

        conn = self._get_connection()
        try:
            for query in queries:
                conn.execute(query)
            conn.commit()
            logger.info("Created database tables using SQLite")
        finally:
            conn.close()

    def execute(self, query: str, params: Optional[Union[Dict, Tuple]] = None) -> Any:
        """Execute a query with parameters"""
        if self.using_sqlalchemy:
            return self._execute_sqlalchemy(query, params)
        else:
            return self._execute_sqlite(query, params)

    def _execute_sqlalchemy(self, query: str, params: Optional[Union[Dict, Tuple]] = None):
        """Execute query using SQLAlchemy"""
        session = self._get_connection()
        try:
            result = session.execute(text(query), params or {})
            session.commit()
            return result.fetchall()
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    def _execute_sqlite(self, query: str, params: Optional[Union[Dict, Tuple]] = None):
        """Execute query using native SQLite"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)

            # Check if it's a SELECT query
            if query.strip().upper().startswith('SELECT'):
                result = cursor.fetchall()
            else:
                conn.commit()
                result = cursor.lastrowid

            return result
        finally:
            conn.close()

    def fetch_one(self, query: str, params: Optional[Union[Dict, Tuple]] = None) -> Optional[Dict]:
        """Fetch single row as dictionary"""
        if self.using_sqlalchemy:
            session = self._get_connection()
            try:
                result = session.execute(text(query), params or {})
                row = result.fetchone()
                return dict(row) if row else None
            finally:
                session.close()
        else:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                row = cursor.fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    def fetch_all(self, query: str, params: Optional[Union[Dict, Tuple]] = None) -> List[Dict]:
        """Fetch all rows as list of dictionaries"""
        if self.using_sqlalchemy:
            session = self._get_connection()
            try:
                result = session.execute(text(query), params or {})
                return [dict(row) for row in result.fetchall()]
            finally:
                session.close()
        else:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                return [dict(row) for row in cursor.fetchall()]
            finally:
                conn.close()

    def insert(self, table: str, data: Dict[str, Any]) -> int:
        """Insert data into table"""
        columns = ', '.join(data.keys())
        placeholders = ', '.join([':' + k for k in data.keys()])
        query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
        return self.execute(query, data)

    def update(self, table: str, data: Dict[str, Any], where: Dict[str, Any]) -> int:
        """Update data in table"""
        set_clause = ', '.join([f"{k} = :{k}" for k in data.keys()])
        where_clause = ' AND '.join([f"{k} = :where_{k}" for k in where.keys()])

        # Prepare parameters
        params = data.copy()
        for k, v in where.items():
            params[f'where_{k}'] = v

        query = f"UPDATE {table} SET {set_clause} WHERE {where_clause}"
        return self.execute(query, params)

    def delete(self, table: str, where: Dict[str, Any]) -> int:
        """Delete data from table"""
        where_clause = ' AND '.join([f"{k} = :{k}" for k in where.keys()])
        query = f"DELETE FROM {table} WHERE {where_clause}"
        return self.execute(query, where)

    async def execute_async(self, query: str, params: Optional[Union[Dict, Tuple]] = None):
        """Execute query asynchronously"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.execute, query, params)

    async def fetch_one_async(self, query: str, params: Optional[Union[Dict, Tuple]] = None):
        """Fetch single row asynchronously"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.fetch_one, query, params)

    async def fetch_all_async(self, query: str, params: Optional[Union[Dict, Tuple]] = None):
        """Fetch all rows asynchronously"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.fetch_all, query, params)

    def save_transaction(self, transaction_data: Dict[str, Any]) -> int:
        """Save Lightning transaction"""
        return self.insert('transactions', transaction_data)

    def save_channel(self, channel_data: Dict[str, Any]) -> int:
        """Save Lightning channel"""
        return self.insert('channels', channel_data)

    def save_invoice(self, invoice_data: Dict[str, Any]) -> int:
        """Save Lightning invoice"""
        return self.insert('invoices', invoice_data)

    def get_transactions(self, limit: int = 100) -> List[Dict]:
        """Get recent transactions"""
        query = "SELECT * FROM transactions ORDER BY created_at DESC LIMIT :limit"
        return self.fetch_all(query, {'limit': limit})

    def get_channels(self) -> List[Dict]:
        """Get all channels"""
        return self.fetch_all("SELECT * FROM channels")

    def get_invoices(self, limit: int = 100) -> List[Dict]:
        """Get recent invoices"""
        query = "SELECT * FROM invoices ORDER BY created_at DESC LIMIT :limit"
        return self.fetch_all(query, {'limit': limit})

    def close(self):
        """Close database connection"""
        if self.using_sqlalchemy and hasattr(self, 'engine'):
            self.engine.dispose()
            logger.info("Closed SQLAlchemy connection pool")


# Singleton instance
_database_instance: Optional[UnifiedDatabase] = None

def get_database(database_url: Optional[str] = None) -> UnifiedDatabase:
    """Get or create database singleton"""
    global _database_instance
    if _database_instance is None:
        _database_instance = UnifiedDatabase(database_url)
    return _database_instance

def reset_database():
    """Reset database singleton (mainly for testing)"""
    global _database_instance
    if _database_instance:
        _database_instance.close()
    _database_instance = None

__all__ = ['UnifiedDatabase', 'get_database', 'reset_database']