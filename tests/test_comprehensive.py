#!/usr/bin/env python3
"""
Comprehensive Test Suite for BLNCS
High-quality tests covering all major components with proper type checking.
"""

import unittest
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any, Optional

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from blncs.core.exceptions import BLNCSError, LightningError, ConnectionError
from blncs.core.config import Config, get_config
from blncs.core.logger import setup_logger, get_logger
from blncs.core.health import HealthChecker
from blncs.core.cache import SimpleCache
from blncs.lightning.client import LightningClient


class TestExceptionsComprehensive(unittest.TestCase):
    """Comprehensive exception testing"""
    
    def test_blncs_error_creation(self) -> None:
        """Test BLNCSError creation with all parameters"""
        error = BLNCSError(
            message="Test error",
            recoverable=True,
            error_code="TEST_001",
            context="test_context",
            details={"key": "value"}
        )
        
        self.assertEqual(error.message, "Test error")
        self.assertTrue(error.recoverable)
        self.assertEqual(error.error_code, "TEST_001")
        self.assertIn("key", error.details)
        self.assertIsNotNone(error.timestamp)
    
    def test_blncs_error_to_dict(self) -> None:
        """Test BLNCSError dictionary conversion"""
        error = BLNCSError("Test", recoverable=False)
        error_dict = error.to_dict()
        
        required_keys = ["error", "error_code", "message", "severity", "recoverable", "timestamp", "details"]
        for key in required_keys:
            self.assertIn(key, error_dict)
        
        self.assertEqual(error_dict["severity"], "error")
        self.assertFalse(error_dict["recoverable"])
    
    def test_recovery_suggestions(self) -> None:
        """Test recovery suggestions functionality"""
        error = BLNCSError("Connection failed", recoverable=True)
        suggestions = error.get_recovery_suggestions()
        
        self.assertIsInstance(suggestions, list)
        self.assertTrue(len(suggestions) > 0)
        
        # Non-recoverable error should return empty list
        fatal_error = BLNCSError("Fatal error", recoverable=False)
        self.assertEqual(len(fatal_error.get_recovery_suggestions()), 0)
    
    def test_lightning_error_specifics(self) -> None:
        """Test Lightning-specific error features"""
        ln_error = LightningError("Payment failed", operation="send_payment")
        
        self.assertEqual(ln_error.operation, "send_payment")
        self.assertTrue(ln_error.recoverable)  # Default for Lightning errors
        
        suggestions = ln_error.get_recovery_suggestions()
        self.assertTrue(any("Lightning" in s for s in suggestions))
    
    def test_connection_error_details(self) -> None:
        """Test connection error with host/port details"""
        conn_error = ConnectionError(
            "Connection refused", 
            host="localhost", 
            port=8080
        )
        
        self.assertEqual(conn_error.host, "localhost")
        self.assertEqual(conn_error.port, 8080)
        
        suggestions = conn_error.get_recovery_suggestions()
        self.assertTrue(any("localhost:8080" in s for s in suggestions))


class TestConfigComprehensive(unittest.TestCase):
    """Comprehensive configuration testing"""
    
    def setUp(self) -> None:
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = Path(self.temp_dir) / "test_config.yaml"
    
    def test_config_creation_with_defaults(self) -> None:
        """Test configuration creation with default values"""
        config = Config(str(self.config_path))
        
        self.assertIsInstance(config.data, dict)
        self.assertIn('lightning', config.data)
        self.assertIn('system', config.data)
        
        # Check default values
        ln_config = config.data['lightning']
        self.assertEqual(ln_config['host'], 'localhost')
        self.assertEqual(ln_config['network'], 'testnet')
    
    def test_config_get_with_dotted_keys(self) -> None:
        """Test configuration retrieval with dotted notation"""
        config = Config(str(self.config_path))
        
        # Test existing key
        host = config.get('lightning.host')
        self.assertEqual(host, 'localhost')
        
        # Test nested key
        log_level = config.get('system.log_level')
        self.assertIsInstance(log_level, str)
        
        # Test non-existent key with default
        missing = config.get('non.existent.key', 'default_value')
        self.assertEqual(missing, 'default_value')
    
    def test_config_set_and_persist(self) -> None:
        """Test configuration setting and persistence"""
        config = Config(str(self.config_path))
        
        # Set a value
        config.set('test.nested.value', 'test_data')
        value = config.get('test.nested.value')
        self.assertEqual(value, 'test_data')
        
        # Test persistence
        config.save()
        self.assertTrue(self.config_path.exists())
        
        # Load new config instance and verify persistence
        new_config = Config(str(self.config_path))
        persisted_value = new_config.get('test.nested.value')
        self.assertEqual(persisted_value, 'test_data')
    
    def test_config_section_access(self) -> None:
        """Test section-based configuration access"""
        config = Config(str(self.config_path))
        
        lightning_section = config.get_section('lightning')
        self.assertIsInstance(lightning_section, dict)
        self.assertIn('host', lightning_section)
        self.assertIn('port', lightning_section)
        
        # Non-existent section should return empty dict
        empty_section = config.get_section('nonexistent')
        self.assertEqual(empty_section, {})
    
    def test_config_env_template_generation(self) -> None:
        """Test environment variable template generation"""
        config = Config(str(self.config_path))
        template = config.get_env_template()
        
        self.assertIsInstance(template, str)
        self.assertIn('LN_HOST', template)
        self.assertIn('LOG_LEVEL', template)
        self.assertIn('#', template)  # Should contain commented examples


class TestLightningClientComprehensive(unittest.TestCase):
    """Comprehensive Lightning client testing"""
    
    def setUp(self) -> None:
        """Set up test environment"""
        self.mock_config = {
            'lightning': {
                'host': 'test.host',
                'port': 9999,
                'network': 'testnet',
                'timeout': 10,
                'connect_timeout': 5
            }
        }
    
    def test_client_initialization(self) -> None:
        """Test Lightning client initialization"""
        client = LightningClient(self.mock_config)
        
        self.assertEqual(client.host, 'test.host')
        self.assertEqual(client.port, 9999)
        self.assertEqual(client.network, 'testnet')
        self.assertFalse(client.connected)
        self.assertIsNotNone(client.session)
    
    @patch('blncs.lightning.client.requests.Session')
    def test_client_connection_success(self, mock_session_class: Mock) -> None:
        """Test successful Lightning client connection"""
        # Mock successful response
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'alias': 'TestNode',
            'identity_pubkey': '03' + '0' * 64,
            'synced_to_chain': True,
            'version': '0.17.0'
        }
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session
        
        client = LightningClient(self.mock_config)
        result = client.connect()
        
        self.assertTrue(result)
        self.assertTrue(client.connected)
        self.assertEqual(client.connection_failures, 0)
    
    @patch('blncs.lightning.client.requests.Session')
    def test_client_connection_failure(self, mock_session_class: Mock) -> None:
        """Test Lightning client connection failure"""
        # Mock failed connection
        mock_session = Mock()
        mock_session.get.side_effect = Exception("Connection refused")
        mock_session_class.return_value = mock_session
        
        client = LightningClient(self.mock_config)
        
        with self.assertRaises(ConnectionError):
            client.connect()
        
        self.assertFalse(client.connected)
        self.assertEqual(client.connection_failures, 1)
    
    def test_client_fallback_behavior(self) -> None:
        """Test client fallback behavior when real connection fails"""
        client = LightningClient(self.mock_config)
        
        # get_info should return fallback data when connection fails
        info = client.get_info()
        self.assertIsInstance(info, dict)
        self.assertIn('alias', info)
        self.assertIn('network', info)
        
        # get_balance should return zero balances
        balance = client.get_balance()
        self.assertIsInstance(balance, dict)
        self.assertEqual(balance['total'], 0)
        
        # list_channels should return empty list
        channels = client.list_channels()
        self.assertIsInstance(channels, list)
        self.assertEqual(len(channels), 0)


class TestHealthCheckerComprehensive(unittest.TestCase):
    """Comprehensive health checker testing"""
    
    def setUp(self) -> None:
        """Set up test environment"""
        self.health_checker = HealthChecker()
    
    def test_health_checker_initialization(self) -> None:
        """Test health checker initialization"""
        self.assertIsNotNone(self.health_checker.logger)
        self.assertIsNotNone(self.health_checker.config)
    
    @patch('blncs.core.health.PSUTIL_AVAILABLE', False)
    def test_system_resources_without_psutil(self) -> None:
        """Test system resources check without psutil"""
        result = self.health_checker.check_system_resources()
        
        self.assertIsInstance(result, dict)
        self.assertIn('error', result)
        self.assertEqual(result['status'], 'warning')
    
    @patch('blncs.core.health.psutil')
    @patch('blncs.core.health.PSUTIL_AVAILABLE', True)
    def test_system_resources_with_psutil(self, mock_psutil: Mock) -> None:
        """Test system resources check with psutil available"""
        # Mock psutil responses
        mock_psutil.cpu_percent.return_value = 25.5
        
        mock_memory = Mock()
        mock_memory.percent = 45.0
        mock_memory.available = 2 * 1024 * 1024 * 1024  # 2GB
        mock_psutil.virtual_memory.return_value = mock_memory
        
        mock_disk = Mock()
        mock_disk.used = 50 * 1024**3  # 50GB
        mock_disk.total = 100 * 1024**3  # 100GB
        mock_disk.free = 50 * 1024**3  # 50GB
        mock_psutil.disk_usage.return_value = mock_disk
        
        result = self.health_checker.check_system_resources()
        
        self.assertIsInstance(result, dict)
        self.assertIn('cpu', result)
        self.assertIn('memory', result)
        self.assertIn('disk', result)
        
        self.assertEqual(result['cpu']['status'], 'healthy')
        self.assertEqual(result['memory']['status'], 'healthy')
        self.assertEqual(result['disk']['status'], 'healthy')
    
    @patch('socket.socket')
    def test_network_connectivity_check(self, mock_socket_class: Mock) -> None:
        """Test network connectivity checking"""
        # Mock successful network operations
        mock_socket = Mock()
        mock_socket.connect_ex.return_value = 0  # Success
        mock_socket_class.return_value = mock_socket
        
        with patch('socket.gethostbyname', return_value='8.8.8.8'):
            result = self.health_checker.check_network_connectivity()
        
        self.assertIsInstance(result, dict)
        self.assertTrue(result.get('internet_available', False))
        self.assertTrue(result.get('lightning_port_open', False))
        self.assertEqual(result.get('status'), 'healthy')
    
    def test_quick_status_format(self) -> None:
        """Test quick status return format"""
        result = self.health_checker.get_quick_status()
        
        self.assertIsInstance(result, dict)
        self.assertIn('timestamp', result)
        self.assertIn('lightning_node', result)
        self.assertIn('status', result)


class TestCacheComprehensive(unittest.TestCase):
    """Comprehensive cache testing"""
    
    def setUp(self) -> None:
        """Set up test environment"""
        self.cache = SimpleCache()
    
    def test_cache_basic_operations(self) -> None:
        """Test basic cache operations"""
        # Set and get
        self.cache.set('test_key', 'test_value', 60)
        value = self.cache.get('test_key')
        self.assertEqual(value, 'test_value')
        
        # Non-existent key
        missing = self.cache.get('missing_key')
        self.assertIsNone(missing)
    
    def test_cache_expiration(self) -> None:
        """Test cache expiration functionality"""
        import time
        
        # Set short-lived cache entry
        self.cache.set('expire_test', 'value', 0.1)  # 0.1 seconds
        
        # Should exist immediately
        value = self.cache.get('expire_test')
        self.assertEqual(value, 'value')
        
        # Should expire after delay
        time.sleep(0.2)
        expired_value = self.cache.get('expire_test')
        self.assertIsNone(expired_value)
    
    def test_cache_deletion(self) -> None:
        """Test cache deletion"""
        self.cache.set('delete_test', 'value', 60)
        self.assertIsNotNone(self.cache.get('delete_test'))
        
        self.cache.delete('delete_test')
        self.assertIsNone(self.cache.get('delete_test'))
    
    def test_cache_cleanup(self) -> None:
        """Test cache cleanup of expired entries"""
        import time
        
        # Add expired and valid entries
        self.cache.set('expired1', 'value1', 0.1)
        self.cache.set('expired2', 'value2', 0.1)
        self.cache.set('valid', 'valid_value', 60)
        
        time.sleep(0.2)
        
        # Clean up expired entries
        self.cache.cleanup_expired()
        
        # Valid entry should remain, expired should be gone
        self.assertEqual(self.cache.get('valid'), 'valid_value')
        self.assertIsNone(self.cache.get('expired1'))
        self.assertIsNone(self.cache.get('expired2'))


def run_comprehensive_tests() -> bool:
    """Run all comprehensive tests"""
    print("Running BLNCS Comprehensive Test Suite...")
    print("=" * 50)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test cases
    test_cases = [
        TestExceptionsComprehensive,
        TestConfigComprehensive,
        TestLightningClientComprehensive,
        TestHealthCheckerComprehensive,
        TestCacheComprehensive,
    ]
    
    for test_case in test_cases:
        tests = loader.loadTestsFromTestCase(test_case)
        suite.addTests(tests)
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(
        verbosity=2,
        failfast=False,
        stream=sys.stdout
    )
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 50)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped) if hasattr(result, 'skipped') else 0}")
    
    success = result.wasSuccessful()
    if success:
        print("🎉 All comprehensive tests passed!")
    else:
        print("❌ Some comprehensive tests failed!")
        
        if result.failures:
            print("\nFailures:")
            for test, traceback in result.failures:
                print(f"- {test}: {traceback.split('AssertionError:')[-1].strip()}")
        
        if result.errors:
            print("\nErrors:")
            for test, traceback in result.errors:
                print(f"- {test}: {traceback.split('Exception:')[-1].strip()}")
    
    return success


if __name__ == '__main__':
    success = run_comprehensive_tests()
    sys.exit(0 if success else 1)