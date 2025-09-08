#!/usr/bin/env python3
"""
Basic tests for BLNCS functionality
Simple tests to verify core components work.
"""

import unittest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from blncs.core.exceptions import BLNCSError, LightningError, ConnectionError
from blncs.core.config_manager import get_config_manager
from blncs.core.logger import setup_logger
from blncs.core.setup import validate_setup, create_default_config
from blncs.core.history import TransactionHistory, record_transaction
from blncs.core.health import get_health_checker
from blncs.lightning.client import LightningClient


class TestExceptions(unittest.TestCase):
    """Test exception classes"""
    
    def test_blncs_error(self):
        """Test basic BLNCS error"""
        error = BLNCSError("Test error", recoverable=False)
        self.assertEqual(error.message, "Test error")
        self.assertFalse(error.recoverable)
        
        error_dict = error.to_dict()
        self.assertEqual(error_dict["error"], "BLNCSError")
        self.assertEqual(error_dict["message"], "Test error")
        self.assertEqual(error_dict["severity"], "error")
    
    def test_lightning_error(self):
        """Test Lightning error"""
        error = LightningError("Lightning test error")
        self.assertEqual(error.message, "Lightning test error")
        self.assertTrue(error.recoverable)  # Default is recoverable
    
    def test_connection_error(self):
        """Test connection error"""
        error = ConnectionError("Connection failed")
        self.assertEqual(error.message, "Connection failed")


class TestConfig(unittest.TestCase):
    """Test configuration management"""
    
    def test_default_config(self):
        """Test default configuration"""
        config = get_config_manager()
        self.assertIsNotNone(config.data)
        
        # Check default values
        self.assertIn('lightning', config.data)
        self.assertIn('system', config.data)
        
        lightning_config = config.data['lightning']
        self.assertEqual(lightning_config['host'], 'localhost')
        self.assertEqual(lightning_config['port'], 8080)
        self.assertEqual(lightning_config['network'], 'testnet')
    
    def test_config_get(self):
        """Test config value retrieval"""
        config = get_config_manager()
        
        # Test nested key access
        host = config.get('lightning.host')
        self.assertEqual(host, 'localhost')
        
        # Test default value
        missing = config.get('missing.key', 'default')
        self.assertEqual(missing, 'default')
    
    def test_config_set(self):
        """Test config value setting"""
        config = get_config_manager()
        config.set('test.key', 'test_value')
        
        value = config.get('test.key')
        self.assertEqual(value, 'test_value')


class TestLogger(unittest.TestCase):
    """Test logging functionality"""
    
    def test_setup_logger(self):
        """Test logger setup"""
        logger = setup_logger("test_logger", "INFO")
        self.assertIsNotNone(logger)
        self.assertEqual(logger.name, "test_logger")


class TestLightningClient(unittest.TestCase):
    """Test Lightning Network client"""
    
    def test_client_creation(self):
        """Test client can be created"""
        client = LightningClient()
        self.assertIsNotNone(client)
        self.assertEqual(client.host, 'localhost')
        self.assertEqual(client.port, 8080)  # REST API port from config
        self.assertEqual(client.network, 'testnet')
    
    def test_client_with_config(self):
        """Test client with custom config"""
        config = {
            'lightning': {
                'host': 'custom.host',
                'port': 9999,
                'network': 'mainnet'
            }
        }
        client = LightningClient(config)
        self.assertEqual(client.host, 'custom.host')
        self.assertEqual(client.port, 9999)
        self.assertEqual(client.network, 'mainnet')
    
    def test_get_info_fallback(self):
        """Test get_info returns fallback data when no real node"""
        client = LightningClient()
        info = client.get_info()
        
        # Should return mock data when no real connection
        self.assertIn('alias', info)
        self.assertIn('identity_pubkey', info)
        self.assertIn('network', info)
        self.assertEqual(info['network'], 'testnet')
    
    def test_get_balance_fallback(self):
        """Test get_balance returns fallback data when no real node"""
        client = LightningClient()
        balance = client.get_balance()
        
        # Should return zero balances when no real connection
        self.assertIn('total', balance)
        self.assertIn('confirmed', balance)
        self.assertIn('channel_local', balance)
        self.assertEqual(balance['total'], 0)
    
    def test_list_channels_fallback(self):
        """Test list_channels returns empty list when no real node"""
        client = LightningClient()
        channels = client.list_channels()
        
        # Should return empty list when no real connection
        self.assertIsInstance(channels, list)
        self.assertEqual(len(channels), 0)


class TestSetup(unittest.TestCase):
    """Test setup functionality"""
    
    def test_validate_setup(self):
        """Test setup validation"""
        result = validate_setup()
        self.assertIsInstance(result, dict)
        self.assertIn('config_valid', result)
    
    def test_create_default_config(self):
        """Test default config creation"""
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "test_config.yaml"
            result = create_default_config(str(config_path))
            self.assertTrue(result.exists())


class TestHistory(unittest.TestCase):
    """Test transaction history"""
    
    def test_history_creation(self):
        """Test history can be created"""
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            history_file = Path(tmpdir) / "test_history.json"
            history = TransactionHistory(str(history_file))
            self.assertIsNotNone(history)
    
    def test_record_transaction(self):
        """Test transaction recording"""
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            history_file = Path(tmpdir) / "test_history.json"
            history = TransactionHistory(str(history_file))
            
            history.add_transaction("test_tx", {"amount": 1000, "memo": "test"})
            
            recent = history.get_recent_transactions(1)
            self.assertEqual(len(recent), 1)
            self.assertEqual(recent[0]['type'], 'test_tx')
            self.assertEqual(recent[0]['data']['amount'], 1000)
    
    def test_transaction_statistics(self):
        """Test transaction statistics"""
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            history_file = Path(tmpdir) / "test_history.json"
            history = TransactionHistory(str(history_file))
            
            # Add some test transactions
            history.add_transaction("payment", {"amount": 1000})
            history.add_transaction("invoice", {"amount": 500})
            history.add_transaction("payment", {"amount": 2000})
            
            stats = history.get_statistics()
            # Allow for possible existing transactions
            self.assertGreaterEqual(stats['total_transactions'], 3)
            self.assertGreaterEqual(stats['types']['payment'], 2)
            self.assertGreaterEqual(stats['types']['invoice'], 1)


class TestHealth(unittest.TestCase):
    """Test health check functionality"""
    
    def test_health_checker_creation(self):
        """Test health checker can be created"""
        checker = get_health_checker()
        self.assertIsNotNone(checker)
    
    def test_quick_health_check(self):
        """Test quick health check"""
        checker = get_health_checker()
        result = checker.get_quick_status()
        self.assertIsInstance(result, dict)
        self.assertIn('status', result)
        self.assertIn('timestamp', result)


class TestCLIIntegration(unittest.TestCase):
    """Test CLI integration"""
    
    def test_cli_import(self):
        """Test that CLI module can be imported"""
        try:
            from blncs_cli import main
            self.assertIsNotNone(main)
        except ImportError as e:
            self.fail(f"Failed to import CLI: {e}")


def run_tests():
    """Run all tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test cases
    test_cases = [
        TestExceptions,
        TestConfig,
        TestLogger,
        TestLightningClient,
        TestSetup,
        TestHistory,
        TestHealth,
        TestCLIIntegration
    ]
    
    for test_case in test_cases:
        tests = loader.loadTestsFromTestCase(test_case)
        suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Return True if all tests passed
    return result.wasSuccessful()


if __name__ == '__main__':
    print("Running BLNCS Basic Tests...")
    success = run_tests()
    
    if success:
        print("\n✅ All tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed!")
        sys.exit(1)