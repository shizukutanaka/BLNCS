#!/usr/bin/env python3
"""
Unified Comprehensive Test Suite for BLNCS
軽量で実用的なテストスイート
"""

import unittest
import sys
import os
import time
import json
import tempfile
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import modules with fallback support
try:
    from blncs.core.unified_config import UnifiedConfig, get_config
    from blncs.core.unified_logging import get_logger
    from blncs.lightning.simple_client import SimpleLightningClient
    from blncs.core.unified_database import UnifiedDatabase
    from blncs.core.simple_cache import SimpleCache
    from blncs.core.performance_optimizer import PerformanceOptimizer
    from blncs.core.simple_error_handler import SimpleErrorHandler
    IMPORTS_OK = True
except ImportError as e:
    print(f"⚠️  Import warning: {e}")
    IMPORTS_OK = False


class TestCoreComponents(unittest.TestCase):
    """Core component tests"""

    def setUp(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.temp_dir, "test_config.json")
        self.db_path = os.path.join(self.temp_dir, "test.db")

    def tearDown(self):
        """Cleanup test environment"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    @unittest.skipUnless(IMPORTS_OK, "Core imports not available")
    def test_config_system(self):
        """Test configuration management"""
        # Create config instance
        config = UnifiedConfig(self.config_path)
        self.assertIsNotNone(config)

        # Test default values
        self.assertEqual(config.get('lightning.host'), 'localhost')
        self.assertEqual(config.get('lightning.port'), 10009)
        self.assertEqual(config.get('api.host'), '127.0.0.1')
        self.assertEqual(config.get('api.port'), 8080)

        # Test set and get
        config.set('test.value', 42)
        self.assertEqual(config.get('test.value'), 42)

        # Test save and reload
        config.save()
        self.assertTrue(os.path.exists(self.config_path))

        # Create new instance and verify persistence
        config2 = UnifiedConfig(self.config_path)
        self.assertEqual(config2.get('test.value'), 42)

    @unittest.skipUnless(IMPORTS_OK, "Core imports not available")
    def test_lightning_client(self):
        """Test Lightning client"""
        client = SimpleLightningClient()
        self.assertIsNotNone(client)

        # Test connection (will use mock mode)
        connected = client.connect()
        self.assertTrue(connected)

        # Test basic operations
        info = client.get_info()
        self.assertIn('connected', info)
        self.assertEqual(info['connected'], True)

        # Test balance
        balance = client.get_balance()
        self.assertIn('total_balance', balance)

        # Test invoice creation
        invoice = client.create_invoice(1000, "test invoice")
        self.assertIn('payment_request', invoice)
        self.assertIn('amount', invoice)
        self.assertEqual(invoice['amount'], 1000)

        # Test invoice decoding
        decoded = client.decode_invoice(invoice['payment_request'])
        self.assertIn('amount', decoded)

        # Test cleanup
        client.disconnect()
        self.assertFalse(client.connected)

    @unittest.skipUnless(IMPORTS_OK, "Core imports not available")
    def test_database(self):
        """Test database operations"""
        db = UnifiedDatabase(self.db_path)
        self.assertIsNotNone(db)

        # Database is initialized automatically

        # Test transaction operations
        tx_id = db.save_transaction({
            'payment_hash': 'test_hash_123',
            'amount': 1000,
            'status': 'pending',
            'timestamp': time.time()
        })
        self.assertIsNotNone(tx_id)

        # Test retrieval
        tx = db.get_transaction('payment_hash', 'test_hash_123')
        self.assertIsNotNone(tx)
        self.assertEqual(tx['amount'], 1000)

        # Test update
        updated = db.update_transaction('test_hash_123', {'status': 'completed'})
        self.assertTrue(updated)

        # Verify update
        tx = db.get_transaction('payment_hash', 'test_hash_123')
        self.assertEqual(tx['status'], 'completed')

        # Test stats
        stats = db.get_stats()
        self.assertIn('total_transactions', stats)
        self.assertGreaterEqual(stats['total_transactions'], 1)

        # Cleanup
        db.close()

    @unittest.skipUnless(IMPORTS_OK, "Core imports not available")
    def test_cache(self):
        """Test cache operations"""
        cache = SimpleCache(max_size=10)
        self.assertIsNotNone(cache)

        # Test set and get
        cache.set('key1', 'value1')
        self.assertEqual(cache.get('key1'), 'value1')

        # Test TTL
        cache.set('key2', 'value2', ttl=1)
        self.assertEqual(cache.get('key2'), 'value2')

        # Wait for expiration
        time.sleep(1.5)
        self.assertIsNone(cache.get('key2'))

        # Test max size (LRU eviction)
        for i in range(15):
            cache.set(f'key_{i}', f'value_{i}')

        # First keys should be evicted
        self.assertIsNone(cache.get('key_0'))
        self.assertIsNotNone(cache.get('key_14'))

        # Test clear
        cache.clear()
        self.assertIsNone(cache.get('key_14'))

    @unittest.skipUnless(IMPORTS_OK, "Core imports not available")
    def test_error_handler(self):
        """Test error handling"""
        handler = SimpleErrorHandler()
        self.assertIsNotNone(handler)

        # Test error handling
        @handler.handle_errors()
        def risky_function():
            raise ValueError("Test error")

        result = risky_function()
        self.assertIn('error', result)
        self.assertIn('Test error', result['error'])

        # Test with default value
        @handler.handle_errors(default_return={'success': False})
        def another_risky():
            raise RuntimeError("Another error")

        result = another_risky()
        self.assertEqual(result, {'success': False})

    @unittest.skipUnless(IMPORTS_OK, "Core imports not available")
    def test_security(self):
        """Test security features"""
        # Import simple_security module components
        try:
            from blncs.core.simple_security import SimpleRateLimit, ValidationResult

            # Test rate limiting
            rate_limiter = SimpleRateLimit()
            self.assertIsNotNone(rate_limiter)

            # Test rate limit checks
            for i in range(5):
                allowed = rate_limiter.is_allowed('test_client')
                self.assertTrue(allowed)

            # Test validation result
            result = ValidationResult(valid=True, message="OK", sanitized_value="test")
            self.assertTrue(result.valid)
            self.assertEqual(result.message, "OK")

        except ImportError:
            self.skipTest("Security module not available")


class TestPerformance(unittest.TestCase):
    """Performance and optimization tests"""

    @unittest.skipUnless(IMPORTS_OK, "Core imports not available")
    def test_performance_optimizer(self):
        """Test performance optimization"""
        optimizer = PerformanceOptimizer()
        self.assertIsNotNone(optimizer)

        # Test system optimization
        result = optimizer.optimize_system()
        self.assertIsInstance(result, dict)

        # Test memory optimization
        mem_result = optimizer.optimize_memory()
        self.assertIsInstance(mem_result, dict)

        # Test CPU optimization
        cpu_result = optimizer.optimize_cpu()
        self.assertIsInstance(cpu_result, dict)

    @unittest.skipUnless(IMPORTS_OK, "Core imports not available")
    def test_cache_performance(self):
        """Test cache performance"""
        cache = SimpleCache(max_size=100)

        start = time.time()

        # Write performance
        for i in range(1000):
            cache.set(f'key_{i}', f'value_{i}')

        write_time = time.time() - start
        self.assertLess(write_time, 0.5)  # Should complete in <500ms

        # Read performance
        start = time.time()
        for i in range(1000):
            cache.get(f'key_{i % 100}')  # Only last 100 are in cache

        read_time = time.time() - start
        self.assertLess(read_time, 0.1)  # Should complete in <100ms


class TestIntegration(unittest.TestCase):
    """Integration tests"""

    def setUp(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Cleanup test environment"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    @unittest.skipUnless(IMPORTS_OK, "Core imports not available")
    def test_full_system_integration(self):
        """Test full system integration"""
        # Setup components
        config_path = os.path.join(self.temp_dir, "config.json")
        db_path = os.path.join(self.temp_dir, "test.db")

        config = UnifiedConfig(config_path)
        config.set('database.path', db_path)
        config.save()

        lightning = SimpleLightningClient()
        lightning.connect()

        database = UnifiedDatabase(db_path)

        cache = SimpleCache()

        # Simulate transaction flow
        # 1. Create invoice
        invoice = lightning.create_invoice(5000, "Integration test")
        self.assertIsNotNone(invoice)

        # 2. Cache invoice
        cache.set(f"invoice_{invoice['payment_request'][:10]}", invoice)

        # 3. Save to database
        tx_id = database.save_transaction({
            'payment_hash': invoice['payment_request'][:10],
            'amount': invoice['amount'],
            'status': 'pending',
            'timestamp': invoice['created_at']
        })
        self.assertIsNotNone(tx_id)

        # 4. Retrieve from cache
        cached = cache.get(f"invoice_{invoice['payment_request'][:10]}")
        self.assertIsNotNone(cached)
        self.assertEqual(cached['amount'], 5000)

        # 5. Update status
        database.update_transaction(
            invoice['payment_request'][:10],
            {'status': 'completed'}
        )

        # 6. Verify
        tx = database.get_transaction('payment_hash', invoice['payment_request'][:10])
        self.assertEqual(tx['status'], 'completed')

        # Cleanup
        lightning.disconnect()
        database.close()


def run_tests(verbose=False):
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestCoreComponents))
    suite.addTests(loader.loadTestsFromTestCase(TestPerformance))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2 if verbose else 1)
    result = runner.run(suite)

    # Return success status
    return result.wasSuccessful()


if __name__ == '__main__':
    # Check for verbose flag
    verbose = '--verbose' in sys.argv or '-v' in sys.argv

    # Run tests
    success = run_tests(verbose)

    # Exit with appropriate code
    sys.exit(0 if success else 1)