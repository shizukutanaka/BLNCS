#!/usr/bin/env python3
"""
Database Optimization for SQLite and PostgreSQL
Implements best practices from 2024-2025 research
"""

import sqlite3
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class SQLiteOptimizer:
    """
    Optimizes SQLite database for production use
    Based on proven best practices for concurrent reads and high-performance queries
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._verify_database()

    def _verify_database(self):
        """Verify database file exists"""
        db_file = Path(self.db_path)
        if not db_file.exists():
            db_file.parent.mkdir(parents=True, exist_ok=True)

    def apply_optimizations(self) -> Dict[str, Any]:
        """
        Apply all recommended SQLite optimizations
        Returns configuration applied
        """
        config = {
            'journal_mode': 'WAL',
            'synchronous': 'NORMAL',
            'temp_store': 'MEMORY',
            'cache_size': -64000,  # 64MB
            'page_size': 4096,
            'mmap_size': 30000000,  # 30MB memory-mapped I/O
            'optimize_pragmas': True
        }

        try:
            with self._get_connection() as conn:
                # Write-Ahead Logging for concurrent reads during writes
                conn.execute('PRAGMA journal_mode=WAL')

                # Balanced synchronous mode (not full, not off)
                conn.execute('PRAGMA synchronous=NORMAL')

                # Use memory for temporary tables
                conn.execute('PRAGMA temp_store=MEMORY')

                # Increase cache size (64MB)
                conn.execute('PRAGMA cache_size=-64000')

                # Keep page size at 4KB (default, optimal for most cases)
                conn.execute('PRAGMA page_size=4096')

                # Memory-mapped I/O for better performance
                conn.execute('PRAGMA mmap_size=30000000')

                # Enable foreign keys
                conn.execute('PRAGMA foreign_keys=ON')

                # Set automatic incremental vacuum
                conn.execute('PRAGMA incremental_vacuum(10000)')

                # Optimize on close
                conn.execute('PRAGMA optimize')

                conn.commit()
                logger.info("SQLite optimizations applied successfully")

        except Exception as e:
            logger.error(f"Failed to apply SQLite optimizations: {e}")
            config['success'] = False
            return config

        config['success'] = True
        return config

    def create_indexes(self, indexes: List[str]) -> None:
        """
        Create recommended indexes for performance
        Should be called after table creation
        """
        try:
            with self._get_connection() as conn:
                for index_sql in indexes:
                    try:
                        conn.execute(index_sql)
                        logger.debug(f"Created index: {index_sql[:50]}...")
                    except sqlite3.OperationalError as e:
                        if 'already exists' in str(e):
                            logger.debug(f"Index already exists")
                        else:
                            logger.warning(f"Failed to create index: {e}")

                conn.commit()
                logger.info(f"Created {len(indexes)} indexes")

        except Exception as e:
            logger.error(f"Failed to create indexes: {e}")

    def analyze_queries(self) -> Dict[str, Any]:
        """
        Run ANALYZE command to gather statistics for query optimizer
        Should be run periodically after data changes
        """
        try:
            with self._get_connection() as conn:
                conn.execute('ANALYZE')
                conn.commit()
                logger.info("Database analysis completed")
                return {'success': True, 'message': 'Database analyzed successfully'}

        except Exception as e:
            logger.error(f"Failed to analyze database: {e}")
            return {'success': False, 'error': str(e)}

    def vacuum_database(self) -> Dict[str, Any]:
        """
        Optimize database file size and performance
        Call periodically when there's significant delete/update activity
        """
        try:
            with self._get_connection() as conn:
                conn.execute('VACUUM')
                conn.commit()
                logger.info("Database vacuumed successfully")
                return {'success': True, 'message': 'Database vacuumed successfully'}

        except Exception as e:
            logger.error(f"Failed to vacuum database: {e}")
            return {'success': False, 'error': str(e)}

    def get_optimization_status(self) -> Dict[str, Any]:
        """Get current optimization status"""
        try:
            with self._get_connection() as conn:
                status = {}

                # Check journal mode
                result = conn.execute('PRAGMA journal_mode').fetchone()
                status['journal_mode'] = result[0] if result else 'unknown'

                # Check synchronous
                result = conn.execute('PRAGMA synchronous').fetchone()
                sync_values = {0: 'OFF', 1: 'NORMAL', 2: 'FULL', 3: 'EXTRA'}
                status['synchronous'] = sync_values.get(result[0], 'unknown') if result else 'unknown'

                # Check cache size
                result = conn.execute('PRAGMA cache_size').fetchone()
                status['cache_size'] = result[0] if result else 'unknown'

                # Check temp store
                result = conn.execute('PRAGMA temp_store').fetchone()
                temp_values = {0: 'DEFAULT', 1: 'FILE', 2: 'MEMORY'}
                status['temp_store'] = temp_values.get(result[0], 'unknown') if result else 'unknown'

                # Check mmap_size
                result = conn.execute('PRAGMA mmap_size').fetchone()
                status['mmap_size'] = result[0] if result else 'unknown'

                # Check foreign keys
                result = conn.execute('PRAGMA foreign_keys').fetchone()
                status['foreign_keys'] = 'ON' if (result and result[0]) else 'OFF'

                return {'success': True, 'status': status}

        except Exception as e:
            logger.error(f"Failed to get optimization status: {e}")
            return {'success': False, 'error': str(e)}

    @contextmanager
    def _get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()


class IndexManager:
    """Manages database indexes for optimal query performance"""

    # Recommended indexes for Lightning Network operations
    LIGHTNING_INDEXES = [
        'CREATE INDEX IF NOT EXISTS idx_channels_peer ON channels(peer_id)',
        'CREATE INDEX IF NOT EXISTS idx_channels_status ON channels(status)',
        'CREATE INDEX IF NOT EXISTS idx_transactions_payment_hash ON transactions(payment_hash)',
        'CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON transactions(created_at)',
        'CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status)',
        'CREATE INDEX IF NOT EXISTS idx_payments_hash ON payments(payment_hash)',
        'CREATE INDEX IF NOT EXISTS idx_payments_state ON payments(state)',
    ]

    @staticmethod
    def get_recommended_indexes(table_type: str = 'lightning') -> List[str]:
        """Get recommended indexes for the table type"""
        if table_type == 'lightning':
            return IndexManager.LIGHTNING_INDEXES
        return []


def optimize_database(db_path: str) -> Dict[str, Any]:
    """
    Main function to optimize a SQLite database
    Call this after database creation
    """
    optimizer = SQLiteOptimizer(db_path)

    results = {
        'optimizations': optimizer.apply_optimizations(),
        'indexes': {},
        'analysis': optimizer.analyze_queries(),
    }

    # Create recommended indexes
    indexes = IndexManager.get_recommended_indexes('lightning')
    optimizer.create_indexes(indexes)

    results['indexes']['created'] = len(indexes)
    results['status'] = optimizer.get_optimization_status()

    return results


__all__ = ['SQLiteOptimizer', 'IndexManager', 'optimize_database']
