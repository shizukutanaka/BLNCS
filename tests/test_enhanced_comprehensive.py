"""
Enhanced Comprehensive Test Suite for BLNCS
Advanced testing covering all implemented components with full automation.
"""

import pytest
import unittest
import asyncio
from unittest.mock import Mock, patch, MagicMock, AsyncMock
import tempfile
import json
import sqlite3
import threading
import time
import os
import sys
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Dict, Any, Optional, List, Callable
import concurrent.futures

# Add BLNCS to path for testing
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import test fixtures
from test_comprehensive import TestFixtures, BLNCSTestSuite


class TestAdvancedDatabaseOperations(unittest.TestCase):
    """Test advanced database operations and performance"""
    
    def setUp(self):
        """Setup advanced database test environment"""
        self.db_path = TestFixtures.create_temp_db()
        
        try:
            from blncs.core.database import DatabaseManager
            self.db = DatabaseManager(self.db_path, pool_size=5)
        except ImportError:
            self.skipTest("Database module not available")
    
    def tearDown(self):
        """Cleanup test database"""
        if hasattr(self, 'db'):
            self.db.close()
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)
    
    def test_concurrent_operations(self):
        """Test concurrent database operations"""
        def worker(worker_id, results):
            try:
                # Perform multiple operations
                self.db.set(f'worker_{worker_id}_key', f'value_{worker_id}')
                self.db.record_metric(f'worker_{worker_id}_metric', worker_id * 10.5)
                tx_id = self.db.record_transaction('worker_tx', {'worker_id': worker_id})
                
                # Read operations
                value = self.db.get(f'worker_{worker_id}_key')
                metrics = self.db.get_metrics(f'worker_{worker_id}_metric', hours=1)
                
                results[worker_id] = {
                    'value': value,
                    'metrics_count': len(metrics),
                    'tx_id': tx_id,
                    'success': True
                }
            except Exception as e:
                results[worker_id] = {'success': False, 'error': str(e)}
        
        # Run concurrent workers
        results = {}
        threads = []
        num_workers = 20
        
        for i in range(num_workers):
            t = threading.Thread(target=worker, args=(i, results))
            threads.append(t)
            t.start()
        
        # Wait for completion
        for t in threads:
            t.join()
        
        # Verify results
        self.assertEqual(len(results), num_workers)
        for worker_id, result in results.items():
            self.assertTrue(result['success'], f"Worker {worker_id} failed: {result.get('error', 'Unknown error')}")
            self.assertEqual(result['value'], f'value_{worker_id}')
            self.assertEqual(result['metrics_count'], 1)
    
    def test_performance_benchmarks(self):
        """Test database performance benchmarks"""
        # Benchmark key-value operations
        start_time = time.time()
        num_operations = 1000
        
        for i in range(num_operations):
            self.db.set(f'perf_key_{i}', f'perf_value_{i}')
        
        write_time = time.time() - start_time
        
        # Benchmark read operations
        start_time = time.time()
        for i in range(num_operations):
            value = self.db.get(f'perf_key_{i}')
            self.assertEqual(value, f'perf_value_{i}')
        
        read_time = time.time() - start_time
        
        # Performance assertions (should be reasonably fast)
        write_ops_per_sec = num_operations / write_time
        read_ops_per_sec = num_operations / read_time
        
        self.assertGreater(write_ops_per_sec, 100, "Write performance too slow")
        self.assertGreater(read_ops_per_sec, 500, "Read performance too slow")
        
        print(f"\nDatabase Performance:")
        print(f"  Write: {write_ops_per_sec:.1f} ops/sec")
        print(f"  Read:  {read_ops_per_sec:.1f} ops/sec")
    
    def test_large_dataset_operations(self):
        """Test operations with large datasets"""
        # Insert large amount of data
        batch_size = 100
        total_records = 1000
        
        # Batch insert metrics
        for batch in range(0, total_records, batch_size):
            params_list = []
            for i in range(batch, min(batch + batch_size, total_records)):
                params_list.append(('large_dataset_test', i * 0.1, json.dumps({'batch': batch, 'index': i})))
            
            # Use executemany for better performance
            query = "INSERT INTO metrics (metric_name, metric_value, tags) VALUES (?, ?, ?)"
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.executemany(query, params_list)
                conn.commit()
        
        # Query large dataset
        metrics = self.db.get_metrics('large_dataset_test', hours=24)
        self.assertEqual(len(metrics), total_records)
        
        # Test database stats with large dataset
        stats = self.db.get_database_stats()
        self.assertGreaterEqual(stats['table_row_counts']['metrics'], total_records)
    
    def test_query_optimization(self):
        """Test query optimization and statistics"""
        # Generate queries that will be tracked
        test_queries = [
            "SELECT * FROM metrics WHERE metric_name = 'test1'",
            "SELECT COUNT(*) FROM transactions",
            "SELECT * FROM kv_store WHERE key LIKE 'test_%'"
        ]
        
        for query in test_queries:
            for _ in range(10):  # Execute each query multiple times
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(query)
        
        # Check query statistics
        slow_queries = self.db.get_slow_queries(threshold_ms=0.1)
        self.assertGreater(len(slow_queries), 0, "Should have tracked some queries")
        
        # Verify statistics tracking
        for stats in slow_queries:
            self.assertGreater(stats.execution_count, 0)
            self.assertGreater(stats.avg_time_ms, 0)


class TestEnhancedLightningClient(unittest.TestCase):
    """Test enhanced Lightning client functionality"""
    
    def setUp(self):
        """Setup enhanced client tests"""
        try:
            from blncs.lightning.client import EnhancedClient, SimpleClient, LightningError
            self.SimpleClient = SimpleClient
            self.EnhancedClient = EnhancedClient
            self.LightningError = LightningError
        except ImportError:
            self.skipTest("Lightning client module not available")
    
    @patch('blncs.lightning.client.requests')
    def test_enhanced_client_features(self, mock_requests):
        """Test enhanced client specific features"""
        # Setup mock
        mock_session = Mock()
        mock_responses = {
            'getinfo': TestFixtures.create_mock_lightning_response('getinfo'),
            'balance/channels': {'balance': '500000', 'pending_open_balance': '0'},
            'graph/info': {'num_nodes': 15000, 'num_channels': 40000},
            'channels/pending': {'pending_open_channels': []},
            'payments': {'payments': []},
            'invoices': {'invoices': []}
        }
        
        def mock_get(url, **kwargs):
            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            
            # Determine response based on URL
            if 'getinfo' in url:
                mock_response.json.return_value = mock_responses['getinfo']
            elif 'balance/channels' in url:
                mock_response.json.return_value = mock_responses['balance/channels']
            elif 'graph/info' in url:
                mock_response.json.return_value = mock_responses['graph/info']
            elif 'channels/pending' in url:
                mock_response.json.return_value = mock_responses['channels/pending']
            elif 'payments' in url:
                mock_response.json.return_value = mock_responses['payments']
            elif 'invoices' in url:
                mock_response.json.return_value = mock_responses['invoices']
            else:
                mock_response.json.return_value = {}
            
            return mock_response
        
        mock_session.get.side_effect = mock_get
        mock_requests.Session.return_value = mock_session
        
        # Test enhanced client
        client = self.EnhancedClient()
        client._session = mock_session
        client.connected = True
        
        # Test caching functionality
        info1 = client.get_info_cached()
        info2 = client.get_info_cached()
        self.assertEqual(info1, info2)
        self.assertEqual(mock_session.get.call_count, 1)  # Should only call once due to caching
        
        # Test enhanced methods
        channel_balance = client.get_channel_balance()
        self.assertIn('balance', channel_balance)
        
        network_info = client.get_network_info()
        self.assertIn('num_nodes', network_info)
        
        pending_channels = client.get_pending_channels()
        self.assertIn('pending_open_channels', pending_channels)
    
    def test_client_error_handling(self):
        """Test client error handling and resilience"""
        client = self.SimpleClient()
        
        # Test various error conditions
        with self.assertRaises(self.LightningError):
            client.get_info()  # Not connected
        
        with self.assertRaises(self.LightningError):
            client.create_invoice(1000)  # Not connected
        
        # Test invalid parameters
        client.connected = True
        with patch.object(client, '_get_session') as mock_session:
            mock_response = Mock()
            mock_response.raise_for_status.side_effect = Exception("HTTP 500")
            mock_session.return_value.post.return_value = mock_response
            
            with self.assertRaises(self.LightningError):
                client.create_invoice(1000)
    
    @patch('blncs.lightning.client.requests')
    def test_client_timeout_handling(self, mock_requests):
        """Test client timeout handling"""
        import requests
        
        mock_session = Mock()
        mock_session.get.side_effect = requests.exceptions.Timeout("Request timed out")
        mock_requests.Session.return_value = mock_session
        
        client = self.SimpleClient()
        client._session = mock_session
        client.connected = True
        
        with self.assertRaises(self.LightningError):
            client.get_info()


class TestConfigurationSystem(unittest.TestCase):
    """Test advanced configuration management"""
    
    def setUp(self):
        """Setup configuration tests"""
        try:
            from blncs.core.config_enhanced import EnhancedConfigManager
            self.EnhancedConfigManager = EnhancedConfigManager
            self.temp_dir = Path(tempfile.mkdtemp())
        except ImportError:
            self.skipTest("Configuration module not available")
    
    def tearDown(self):
        """Cleanup configuration tests"""
        import shutil
        if hasattr(self, 'temp_dir'):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_hierarchical_configuration(self):
        """Test hierarchical configuration loading"""
        config = self.EnhancedConfigManager("TestApp")
        config.user_config_dir = self.temp_dir
        
        # Create multiple config files with different priorities
        base_config = {
            'app': {'name': 'BaseApp', 'version': '1.0.0'},
            'lightning': {'host': 'localhost', 'port': 8080}
        }
        
        user_config = {
            'lightning': {'port': 9735},  # Override port
            'ui': {'theme': 'dark'}       # Add new setting
        }
        
        local_config = {
            'lightning': {'host': '192.168.1.100'},  # Override host
            'debug': True                              # Add debug flag
        }
        
        # Write config files
        base_file = self.temp_dir / "base.json"
        user_file = self.temp_dir / "user.json"
        local_file = self.temp_dir / "local.json"
        
        for file, data in [(base_file, base_config), (user_file, user_config), (local_file, local_config)]:
            with open(file, 'w') as f:
                json.dump(data, f)
        
        # Add sources with different priorities
        config.add_config_source(str(base_file), priority=1)   # Lowest priority
        config.add_config_source(str(user_file), priority=10)  # Medium priority
        config.add_config_source(str(local_file), priority=20) # Highest priority
        
        # Load configuration
        config.load_config()
        
        # Test hierarchical override behavior
        self.assertEqual(config.get('app.name'), 'BaseApp')           # From base
        self.assertEqual(config.get('lightning.port'), 9735)          # From user (overrides base)
        self.assertEqual(config.get('lightning.host'), '192.168.1.100') # From local (overrides user)
        self.assertEqual(config.get('ui.theme'), 'dark')              # From user
        self.assertTrue(config.get('debug'))                          # From local
    
    def test_configuration_validation_comprehensive(self):
        """Test comprehensive configuration validation"""
        config = self.EnhancedConfigManager("TestApp")
        
        # Test all validation rules
        test_cases = [
            # Valid cases
            ('lightning.network', 'testnet', True),
            ('lightning.port', 9735, True),
            ('ui.theme', 'dark', True),
            ('app.log_level', 'DEBUG', True),
            
            # Invalid cases
            ('lightning.network', 'invalid_network', False),
            ('lightning.port', 99999, False),  # Out of range
            ('ui.theme', 'invalid_theme', False),
            ('app.log_level', 'INVALID_LEVEL', False),
        ]
        
        for key, value, expected_valid in test_cases:
            result = config.set(key, value)
            self.assertEqual(result, expected_valid, 
                           f"Validation failed for {key}={value}, expected {expected_valid}")
    
    def test_configuration_watchers_advanced(self):
        """Test advanced configuration watcher functionality"""
        config = self.EnhancedConfigManager("TestApp")
        
        # Track multiple changes
        changes = {'theme': [], 'language': [], 'debug': []}
        
        def theme_watcher(key, old, new):
            changes['theme'].append((old, new))
        
        def language_watcher(key, old, new):
            changes['language'].append((old, new))
        
        def debug_watcher(key, old, new):
            changes['debug'].append((old, new))
        
        # Register watchers
        config.watch('ui.theme', theme_watcher)
        config.watch('ui.language', language_watcher)
        config.watch('app.debug', debug_watcher)
        
        # Make changes
        config.set('ui.theme', 'dark')
        config.set('ui.theme', 'bitcoin')
        config.set('ui.language', 'ja')
        config.set('app.debug', True)
        
        # Verify watchers were called correctly
        self.assertEqual(len(changes['theme']), 2)
        self.assertEqual(changes['theme'][0], ('light', 'dark'))
        self.assertEqual(changes['theme'][1], ('dark', 'bitcoin'))
        
        self.assertEqual(len(changes['language']), 1)
        self.assertEqual(changes['language'][0], ('en', 'ja'))
        
        self.assertEqual(len(changes['debug']), 1)
        self.assertEqual(changes['debug'][0], (False, True))
    
    def test_configuration_encryption_advanced(self):
        """Test advanced configuration encryption"""
        config = self.EnhancedConfigManager("TestApp")
        config.enable_encryption("super_secure_password_123")
        
        # Test encryption of sensitive data
        sensitive_data = {
            'macaroon_path': '/path/to/admin.macaroon',
            'tls_cert_path': '/path/to/tls.cert',
            'wallet_password': 'my_wallet_password'
        }
        
        # Encrypt and save
        for key, value in sensitive_data.items():
            config.set(key, value)
        
        encrypted_file = self.temp_dir / "encrypted.json.enc"
        config.save_config(str(encrypted_file))
        
        # Verify file is encrypted (not readable as plain JSON)
        with open(encrypted_file, 'r') as f:
            content = f.read()
            with self.assertRaises(json.JSONDecodeError):
                json.loads(content)
        
        # Load encrypted config
        new_config = self.EnhancedConfigManager("TestApp") 
        new_config.enable_encryption("super_secure_password_123")
        new_config.add_config_source(str(encrypted_file), encrypted=True)
        new_config.load_config()
        
        # Verify encrypted data is correctly decrypted
        for key, expected_value in sensitive_data.items():
            actual_value = new_config.get(key)
            self.assertEqual(actual_value, expected_value)


class TestSystemIntegration(unittest.TestCase):
    """Test complete system integration"""
    
    def setUp(self):
        """Setup system integration tests"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.db_path = self.temp_dir / "integration_test.db"
        self.config_path = self.temp_dir / "integration_config.json"
    
    def tearDown(self):
        """Cleanup integration tests"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('blncs.lightning.client.requests')
    def test_full_system_workflow(self, mock_requests):
        """Test complete system workflow from startup to operation"""
        # Mock Lightning responses
        mock_session = Mock()
        
        def mock_request(method, url, **kwargs):
            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            
            if 'getinfo' in url:
                mock_response.json.return_value = TestFixtures.create_mock_lightning_response('getinfo')
            elif 'balance' in url:
                mock_response.json.return_value = TestFixtures.create_mock_lightning_response('balance')
            elif 'channels' in url and method == 'GET':
                mock_response.json.return_value = TestFixtures.create_mock_lightning_response('channels')
            elif 'invoices' in url and method == 'POST':
                mock_response.json.return_value = TestFixtures.create_mock_lightning_response('invoice')
            else:
                mock_response.json.return_value = {}
            
            return mock_response
        
        mock_session.get.side_effect = lambda url, **kwargs: mock_request('GET', url, **kwargs)
        mock_session.post.side_effect = lambda url, **kwargs: mock_request('POST', url, **kwargs)
        mock_requests.Session.return_value = mock_session
        
        try:
            # 1. Initialize configuration
            from blncs.core.config_enhanced import EnhancedConfigManager
            config = EnhancedConfigManager("IntegrationTest")
            config.user_config_dir = self.temp_dir
            
            # Set test configuration
            config.set('lightning.host', 'localhost')
            config.set('lightning.port', 8080)
            config.set('database.path', str(self.db_path))
            config.save_config(str(self.config_path))
            
            # 2. Initialize database
            from blncs.core.database import DatabaseManager
            db = DatabaseManager(str(self.db_path))
            
            # 3. Initialize Lightning client
            from blncs.lightning.client import EnhancedClient
            client = EnhancedClient()
            client._session = mock_session
            client.connected = True
            
            # 4. Perform typical operations
            # Get node info and store in database
            node_info = client.get_info()
            db.set('node.info', node_info)
            db.record_metric('node.active_channels', node_info['num_active_channels'])
            
            # Get balance and store
            balance = client.get_balance()
            db.set('wallet.balance', balance)
            db.record_metric('wallet.confirmed_balance', int(balance['confirmed_balance']))
            
            # Create invoice
            invoice = client.create_invoice(10000, "Integration test invoice")
            invoice_id = db.record_transaction('invoice_created', {
                'payment_request': invoice['payment_request'],
                'amount': 10000
            })
            
            # 5. Verify all operations
            # Check database storage
            stored_info = db.get('node.info')
            self.assertEqual(stored_info['alias'], 'TestNode')
            
            stored_balance = db.get('wallet.balance')
            self.assertEqual(stored_balance['confirmed_balance'], '1000000')
            
            # Check metrics
            channel_metrics = db.get_metrics('node.active_channels', hours=1)
            self.assertEqual(len(channel_metrics), 1)
            
            balance_metrics = db.get_metrics('wallet.confirmed_balance', hours=1)
            self.assertEqual(len(balance_metrics), 1)
            
            # Check transaction record
            transactions = db.get_recent_transactions(limit=10)
            self.assertEqual(len(transactions), 1)
            self.assertEqual(transactions[0]['type'], 'invoice_created')
            
            # 6. Test configuration persistence
            config.reload()
            self.assertEqual(config.get('lightning.host'), 'localhost')
            self.assertEqual(config.get('lightning.port'), 8080)
            
            # Cleanup
            db.close()
            
        except ImportError as e:
            self.skipTest(f"Required modules not available: {e}")
    
    def test_error_recovery_workflow(self):
        """Test system behavior under error conditions"""
        try:
            from blncs.core.database import DatabaseManager
            from blncs.lightning.client import SimpleClient, LightningError
            
            # Test database recovery
            db = DatabaseManager(str(self.db_path))
            
            # Simulate database corruption by manually corrupting the file
            db.close()
            with open(self.db_path, 'wb') as f:
                f.write(b'corrupted data')
            
            # Attempt to reconnect - should handle gracefully
            with self.assertRaises(Exception):  # Should fail due to corruption
                corrupted_db = DatabaseManager(str(self.db_path))
            
            # Test Lightning client error recovery
            client = SimpleClient()
            
            # Test multiple connection failures
            for _ in range(3):
                result = client.connect()  # Will fail - no real server
                self.assertFalse(result)
                self.assertFalse(client.connected)
            
            # Test graceful error handling
            with self.assertRaises(LightningError):
                client.get_info()  # Should raise proper error
            
        except ImportError:
            self.skipTest("Required modules not available")


class PerformanceBenchmarks(unittest.TestCase):
    """Performance benchmarking for BLNCS components"""
    
    def setUp(self):
        """Setup performance test environment"""
        self.results = {}
        self.temp_dir = Path(tempfile.mkdtemp())
    
    def tearDown(self):
        """Cleanup and report performance results"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        
        if self.results:
            print(f"\n{'='*50}")
            print("PERFORMANCE BENCHMARK RESULTS")
            print(f"{'='*50}")
            for test_name, metrics in self.results.items():
                print(f"{test_name}:")
                for metric, value in metrics.items():
                    print(f"  {metric}: {value}")
            print(f"{'='*50}")
    
    def test_database_performance_benchmark(self):
        """Comprehensive database performance benchmark"""
        try:
            from blncs.core.database import DatabaseManager
            
            db_path = self.temp_dir / "perf_test.db"
            db = DatabaseManager(str(db_path), pool_size=10)
            
            # Benchmark different operation types
            benchmarks = {}
            
            # 1. Key-Value Operations
            start = time.time()
            for i in range(1000):
                db.set(f'perf_kv_{i}', f'value_{i}')
            benchmarks['kv_write_1k_ops_per_sec'] = 1000 / (time.time() - start)
            
            start = time.time()
            for i in range(1000):
                db.get(f'perf_kv_{i}')
            benchmarks['kv_read_1k_ops_per_sec'] = 1000 / (time.time() - start)
            
            # 2. Metrics Operations
            start = time.time()
            for i in range(1000):
                db.record_metric('perf_metric', i * 0.1)
            benchmarks['metrics_write_1k_ops_per_sec'] = 1000 / (time.time() - start)
            
            # 3. Transaction Operations
            start = time.time()
            for i in range(500):
                db.record_transaction('perf_tx', {'data': f'tx_{i}'})
            benchmarks['tx_write_500_ops_per_sec'] = 500 / (time.time() - start)
            
            # 4. Concurrent Operations
            def concurrent_worker(results, worker_id):
                start = time.time()
                for i in range(100):
                    db.set(f'concurrent_{worker_id}_{i}', f'value_{i}')
                    db.record_metric(f'concurrent_metric_{worker_id}', i)
                results[worker_id] = 200 / (time.time() - start)
            
            concurrent_results = {}
            threads = []
            for i in range(10):  # 10 concurrent workers
                t = threading.Thread(target=concurrent_worker, args=(concurrent_results, i))
                threads.append(t)
                t.start()
            
            start = time.time()
            for t in threads:
                t.join()
            total_time = time.time() - start
            
            total_ops = sum(concurrent_results.values())
            benchmarks['concurrent_10_workers_ops_per_sec'] = total_ops
            
            self.results['Database Performance'] = benchmarks
            db.close()
            
        except ImportError:
            self.skipTest("Database module not available")
    
    def test_configuration_performance_benchmark(self):
        """Configuration system performance benchmark"""
        try:
            from blncs.core.config_enhanced import EnhancedConfigManager
            
            config = EnhancedConfigManager("PerfTest")
            config.user_config_dir = self.temp_dir
            
            benchmarks = {}
            
            # 1. Configuration Loading
            # Create large config file
            large_config = {}
            for i in range(1000):
                large_config[f'section_{i}'] = {
                    f'key_{j}': f'value_{i}_{j}' for j in range(10)
                }
            
            config_file = self.temp_dir / "large_config.json"
            with open(config_file, 'w') as f:
                json.dump(large_config, f)
            
            start = time.time()
            config.add_config_source(str(config_file))
            config.load_config()
            benchmarks['large_config_load_time_sec'] = time.time() - start
            
            # 2. Configuration Access
            start = time.time()
            for i in range(1000):
                config.get(f'section_{i}.key_5')
            benchmarks['config_access_1k_ops_per_sec'] = 1000 / (time.time() - start)
            
            # 3. Configuration Validation
            start = time.time()
            for i in range(100):
                config.set('ui.theme', 'light')
                config.set('ui.theme', 'dark')
            benchmarks['validation_200_ops_per_sec'] = 200 / (time.time() - start)
            
            self.results['Configuration Performance'] = benchmarks
            
        except ImportError:
            self.skipTest("Configuration module not available")


class EnhancedBLNCSTestSuite(BLNCSTestSuite):
    """Enhanced test suite with advanced features"""
    
    def __init__(self):
        super().__init__()
        self.performance_results = {}
        self.coverage_data = {}
    
    def run_all_tests(self):
        """Run all tests including performance benchmarks"""
        print("Starting Enhanced BLNCS Test Suite...")
        
        # Run standard tests
        standard_report = super().run_all_tests()
        
        # Run performance benchmarks
        performance_report = self.run_performance_tests()
        
        # Combine reports
        enhanced_report = {
            **standard_report,
            'performance_benchmarks': performance_report,
            'enhanced_features': {
                'concurrent_testing': True,
                'performance_benchmarking': True,
                'integration_testing': True,
                'error_recovery_testing': True
            }
        }
        
        return enhanced_report
    
    def run_performance_tests(self):
        """Run performance benchmark tests"""
        print("\nRunning performance benchmarks...")
        
        benchmark_classes = [
            PerformanceBenchmarks
        ]
        
        performance_results = {}
        
        for test_class in benchmark_classes:
            suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
            runner = unittest.TextTestRunner(verbosity=1, stream=open(os.devnull, 'w'))
            result = runner.run(suite)
            
            performance_results[test_class.__name__] = {
                'tests_run': result.testsRun,
                'success': result.testsRun - len(result.failures) - len(result.errors) > 0
            }
        
        return performance_results
    
    def generate_comprehensive_report(self, report):
        """Generate comprehensive test report"""
        timestamp = datetime.now().isoformat()
        
        comprehensive_report = {
            **report,
            'metadata': {
                'generated_at': timestamp,
                'test_suite_version': '2.0.0',
                'python_version': sys.version,
                'platform': sys.platform
            },
            'recommendations': self.generate_recommendations(report)
        }
        
        return comprehensive_report
    
    def generate_recommendations(self, report):
        """Generate recommendations based on test results"""
        recommendations = []
        
        summary = report['summary']
        
        if summary['success_rate'] < 95:
            recommendations.append({
                'type': 'quality',
                'message': 'Test success rate below 95%. Review failing tests and improve code quality.'
            })
        
        if summary['duration_seconds'] > 60:
            recommendations.append({
                'type': 'performance',
                'message': 'Test suite takes over 60 seconds. Consider optimizing slow tests.'
            })
        
        # Performance recommendations
        if 'performance_benchmarks' in report:
            for test_class, results in report['performance_benchmarks'].items():
                if not results['success']:
                    recommendations.append({
                        'type': 'performance',
                        'message': f'Performance benchmarks failed in {test_class}. Check system resources.'
                    })
        
        return recommendations


def main():
    """Enhanced test runner with comprehensive reporting"""
    print("BLNCS Enhanced Comprehensive Test Suite")
    print("="*50)
    
    # Create enhanced test suite
    suite = EnhancedBLNCSTestSuite()
    
    # Run all tests
    report = suite.run_all_tests()
    
    # Generate comprehensive report
    comprehensive_report = suite.generate_comprehensive_report(report)
    
    # Print summary
    suite.print_summary(report)
    
    # Print recommendations
    if comprehensive_report['recommendations']:
        print("\nRECOMMENDATIONS:")
        print("-" * 30)
        for rec in comprehensive_report['recommendations']:
            print(f"[{rec['type'].upper()}] {rec['message']}")
    
    # Save comprehensive report
    report_file = Path(__file__).parent / f"enhanced_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    suite.save_report(comprehensive_report, str(report_file))
    print(f"\nComprehensive report saved to: {report_file}")
    
    # Return appropriate exit code
    if report['summary']['failures'] > 0 or report['summary']['errors'] > 0:
        return 1
    return 0


if __name__ == "__main__":
    exit(main())