#!/usr/bin/env python3
"""
Integration Tests for BLNCS
Tests that verify component integration and end-to-end workflows.
"""

import unittest
import sys
import tempfile
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from blncs.lightning.client import LightningClient
from blncs.core.config_manager import get_config_manager
from blncs.core.health import get_health_checker
from blncs.core.monitor import get_monitor


class TestSystemIntegration(unittest.TestCase):
    """Test system-wide integration"""
    
    def setUp(self):
        """Set up test environment"""
        self.client = LightningClient()
        self.config = get_config_manager()
        self.health_checker = get_health_checker()
        self.monitor = get_monitor()
    
    def test_client_config_integration(self):
        """Test Lightning client uses configuration properly"""
        # Test default configuration
        self.assertEqual(self.client.host, 'localhost')
        self.assertEqual(self.client.port, 8080)
        self.assertEqual(self.client.network, 'testnet')
        
        # Test custom configuration
        custom_config = {
            'lightning': {
                'host': 'test.example.com',
                'port': 9999,
                'network': 'mainnet'
            }
        }
        custom_client = LightningClient(custom_config)
        self.assertEqual(custom_client.host, 'test.example.com')
        self.assertEqual(custom_client.port, 9999)
        self.assertEqual(custom_client.network, 'mainnet')
    
    def test_health_monitoring_integration(self):
        """Test health monitoring works with all components"""
        # Quick status check
        status = self.health_checker.get_quick_status()
        self.assertIsInstance(status, dict)
        self.assertIn('status', status)
        self.assertIn('timestamp', status)
        
        # Status should be valid string
        self.assertIn(status['status'], ['healthy', 'warning', 'error', 'unknown'])
    
    def test_monitoring_system_integration(self):
        """Test monitoring system integration"""
        # Monitor should be creatable
        self.assertIsNotNone(self.monitor)
        
        # Should have basic monitoring capabilities
        # Note: We don't test actual monitoring to avoid side effects
    
    def test_client_fallback_behavior(self):
        """Test client fallback when no real node available"""
        # When no real Lightning node is available, should return fallback data
        info = self.client.get_info()
        self.assertIn('alias', info)
        self.assertIn('network', info)
        self.assertEqual(info['network'], 'testnet')
        
        balance = self.client.get_balance()
        self.assertIn('total', balance)
        self.assertIsInstance(balance['total'], int)
        
        channels = self.client.list_channels()
        self.assertIsInstance(channels, list)


class TestConfigurationIntegration(unittest.TestCase):
    """Test configuration system integration"""
    
    def test_config_persistence(self):
        """Test configuration changes persist"""
        config = get_config_manager()
        
        # Set a test value
        original_value = config.get('test.integration', 'default')
        config.set('test.integration', 'test_value')
        
        # Verify it's set
        self.assertEqual(config.get('test.integration'), 'test_value')
        
        # Get a new config instance
        new_config = get_config_manager()
        self.assertEqual(new_config.get('test.integration'), 'test_value')
        
        # Clean up
        config.set('test.integration', original_value)
    
    def test_config_validation_integration(self):
        """Test config validation works with real config"""
        from blncs.core.validator import get_validator
        
        validator = get_validator()
        
        # Should be able to validate default config
        result = validator.validate_config("config/config.yaml")
        self.assertIsNotNone(result)
        self.assertTrue(hasattr(result, 'is_valid'))


class TestWorkflowIntegration(unittest.TestCase):
    """Test common workflow integration"""
    
    def test_status_check_workflow(self):
        """Test complete status check workflow"""
        # This simulates what happens when user runs 'status' command
        client = LightningClient()
        health_checker = get_health_checker()
        
        # Get node info (with fallback)
        node_info = client.get_info()
        self.assertIsInstance(node_info, dict)
        
        # Get balance (with fallback)  
        balance = client.get_balance()
        self.assertIsInstance(balance, dict)
        
        # Get health status
        health_status = health_checker.get_quick_status()
        self.assertIsInstance(health_status, dict)
        
        # All should complete without errors
        self.assertTrue(True)  # If we get here, workflow completed
    
    def test_info_display_workflow(self):
        """Test node info display workflow"""
        client = LightningClient()
        
        info = client.get_info()
        
        # Should have all expected fields for display
        expected_fields = ['alias', 'identity_pubkey', 'network', 'version']
        for field in expected_fields:
            self.assertIn(field, info)
            self.assertIsNotNone(info[field])
    
    def test_balance_display_workflow(self):
        """Test balance display workflow"""
        client = LightningClient()
        
        balance = client.get_balance()
        
        # Should have all expected balance fields
        expected_fields = ['total', 'confirmed', 'channel_local']
        for field in expected_fields:
            self.assertIn(field, balance)
            self.assertIsInstance(balance[field], int)


def run_integration_tests():
    """Run all integration tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestSystemIntegration,
        TestConfigurationIntegration,
        TestWorkflowIntegration
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    print("Running BLNCS Integration Tests...")
    success = run_integration_tests()
    
    if success:
        print("\n✅ All integration tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some integration tests failed!")
        sys.exit(1)