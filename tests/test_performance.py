"""
Performance and Integration Tests for BLNCS
"""

import unittest
import time
import threading
from concurrent.futures import ThreadPoolExecutor
import tempfile
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


class TestPerformance(unittest.TestCase):
    """Test performance optimizations"""

    def test_connection_pool(self):
        """Test optimized connection pool"""
        from blncs.core.optimized_pool import OptimizedConnectionPool

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            pool = OptimizedConnectionPool(db_path, min_size=2, max_size=5)

            # Test concurrent access
            def worker():
                with pool.acquire() as conn:
                    conn.execute("SELECT 1")
                    time.sleep(0.01)

            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(worker) for _ in range(20)]
                for future in futures:
                    future.result()

            # Check statistics
            stats = pool.get_stats()
            self.assertGreater(stats['total_requests'], 0)
            self.assertGreaterEqual(stats['cache_hit_rate'], 0)

            pool.close_all()

    def test_transaction_manager(self):
        """Test transaction support"""
        from blncs.core.transaction import TransactionManager
        import sqlite3

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            conn = sqlite3.connect(db_path)
            conn.execute("CREATE TABLE test (id INTEGER, value TEXT)")

            manager = TransactionManager()

            # Test successful transaction
            with manager.transaction(conn):
                conn.execute("INSERT INTO test VALUES (1, 'test1')")
                conn.execute("INSERT INTO test VALUES (2, 'test2')")

            result = conn.execute("SELECT COUNT(*) FROM test").fetchone()
            self.assertEqual(result[0], 2)

            # Test rollback on error
            try:
                with manager.transaction(conn):
                    conn.execute("INSERT INTO test VALUES (3, 'test3')")
                    raise ValueError("Test error")
            except ValueError:
                pass

            result = conn.execute("SELECT COUNT(*) FROM test").fetchone()
            self.assertEqual(result[0], 2)  # Should still be 2

            # Check statistics
            stats = manager.get_stats()
            self.assertEqual(stats['committed'], 1)
            self.assertEqual(stats['rolled_back'], 1)

            conn.close()

    def test_rate_limiter(self):
        """Test rate limiting"""
        from blncs.core.rate_limit import RateLimiter, RateLimitConfig

        config = RateLimitConfig(
            requests_per_second=5,
            requests_per_minute=100,
            burst_size=10
        )
        limiter = RateLimiter(config)

        # Test burst capacity
        allowed = 0
        for _ in range(15):
            if limiter.check_rate_limit():
                allowed += 1

        self.assertLessEqual(allowed, config.burst_size)

        # Test per-client limiting
        client_allowed = 0
        for _ in range(10):
            if limiter.check_rate_limit('client1'):
                client_allowed += 1

        self.assertGreater(client_allowed, 0)

        # Check statistics
        stats = limiter.get_stats()
        self.assertIn('total_allowed', stats)
        self.assertIn('total_blocked', stats)

    def test_cache_performance(self):
        """Test cache performance with concurrent access"""
        from blncs.core.simple_cache import SimpleCache

        cache = SimpleCache(max_size=100)

        # Test concurrent reads/writes
        def cache_worker(worker_id):
            for i in range(10):
                cache.set(f"key_{worker_id}_{i}", f"value_{worker_id}_{i}")
                value = cache.get(f"key_{worker_id}_{i}")
                self.assertIsNotNone(value)

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(cache_worker, i) for i in range(5)]
            for future in futures:
                future.result()

        # Check cache size
        self.assertLessEqual(cache.size(), 100)

    def test_batch_operations(self):
        """Test batch database operations"""
        from blncs.core.transaction import batch_execute
        import sqlite3

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            conn = sqlite3.connect(db_path)
            conn.execute("CREATE TABLE batch_test (id INTEGER, value TEXT)")

            # Prepare batch operations
            operations = [
                ("INSERT INTO batch_test VALUES (?, ?)", (i, f"value_{i}"))
                for i in range(100)
            ]

            # Execute in batches
            batch_execute(conn, operations, batch_size=20)

            # Verify results
            result = conn.execute("SELECT COUNT(*) FROM batch_test").fetchone()
            self.assertEqual(result[0], 100)

            conn.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)