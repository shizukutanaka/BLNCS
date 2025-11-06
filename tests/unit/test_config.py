#!/usr/bin/env python3
"""
Unit tests for BLNCS configuration system
Tests configuration loading, caching, and validation
"""

import unittest
import tempfile
import json
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

from blncs.core.config import ConfigManager, get_config, reset_config


class TestConfigManager(unittest.TestCase):
    """Test ConfigManager functionality"""

    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = Path(self.temp_dir) / "test_config.json"

        # Create test config
        self.test_config = {
            "version": "2.0.0",
            "environment": "test",
            "lightning": {
                "network": "testnet",
                "host": "localhost",
                "port": 10009,
                "mock_mode": True
            },
            "database": {
                "url": "sqlite:///test.db"
            },
            "api": {
                "port": 3000,
                "enabled": True
            }
        }

        with open(self.config_path, 'w') as f:
            json.dump(self.test_config, f, indent=2)

    def tearDown(self):
        """Clean up test environment"""
        reset_config()
        # Clean up temp files
        if self.config_path.exists():
            self.config_path.unlink()
        if Path(self.temp_dir).exists():
            import shutil
            shutil.rmtree(self.temp_dir)

    def test_config_loading(self):
        """Test basic configuration loading"""
        config = ConfigManager(config_path=str(self.config_path))

        self.assertEqual(config.environment, "test")
        self.assertEqual(config.lightning.network, "testnet")
        self.assertEqual(config.api.port, 3000)
        self.assertTrue(config.api.enabled)

    def test_config_get_method(self):
        """Test configuration get method"""
        config = ConfigManager(config_path=str(self.config_path))

        # Test existing values
        self.assertEqual(config.get("lightning.network"), "testnet")
        self.assertEqual(config.get("api.port"), 3000)
        self.assertTrue(config.get("api.enabled"))

        # Test nested access
        self.assertEqual(config.get("lightning.host"), "localhost")
        self.assertEqual(config.get("database.url"), "sqlite:///test.db")

        # Test default values
        self.assertEqual(config.get("nonexistent.key", "default"), "default")
        self.assertIsNone(config.get("nonexistent.key"))

    def test_config_set_method(self):
        """Test configuration set method"""
        config = ConfigManager(config_path=str(self.config_path))

        # Set a new value
        config.set("api.port", 8080)
        self.assertEqual(config.get("api.port"), 8080)

        # Set nested value
        config.set("lightning.host", "test.example.com")
        self.assertEqual(config.get("lightning.host"), "test.example.com")

    def test_config_caching(self):
        """Test configuration caching functionality"""
        config = ConfigManager(config_path=str(self.config_path))

        # First access should create cache
        value1 = config.get("lightning.network")
        self.assertIsNotNone(config._config_cache)
        self.assertIsNotNone(config._cache_hash)

        # Second access should use cache
        value2 = config.get("lightning.network")
        self.assertEqual(value1, value2)

        # Cache should be valid
        self.assertTrue(config._is_cache_valid())

    def test_config_cache_invalidation(self):
        """Test cache invalidation on configuration changes"""
        config = ConfigManager(config_path=str(self.config_path))

        # Access to create cache
        config.get("lightning.network")
        self.assertIsNotNone(config._config_cache)

        # Setting value should invalidate cache
        config.set("lightning.network", "mainnet")
        self.assertIsNone(config._config_cache)

        # Next access should recreate cache
        value = config.get("lightning.network")
        self.assertEqual(value, "mainnet")
        self.assertIsNotNone(config._config_cache)

    def test_config_validation(self):
        """Test configuration validation"""
        config = ConfigManager(config_path=str(self.config_path))

        # Valid configuration should not raise
        try:
            config._validate_config()
        except Exception as e:
            self.fail(f"Valid configuration raised exception: {e}")

        # Test invalid network
        config.lightning.network = "invalid"
        with self.assertRaises(Exception):
            config._validate_config()

    def test_config_to_dict(self):
        """Test configuration serialization to dict"""
        config = ConfigManager(config_path=str(self.config_path))
        config_dict = config.to_dict()

        self.assertIsInstance(config_dict, dict)
        self.assertIn('version', config_dict)
        self.assertIn('environment', config_dict)
        self.assertIn('lightning', config_dict)
        self.assertIn('api', config_dict)

        # Check specific values
        self.assertEqual(config_dict['environment'], 'test')
        self.assertEqual(config_dict['lightning']['network'], 'testnet')

    def test_config_backup_restore(self):
        """Test configuration backup and restore"""
        config = ConfigManager(config_path=str(self.config_path))

        # Modify config
        config.set("api.port", 9999)

        # Create backup
        backup_path = config.create_backup()
        self.assertTrue(Path(backup_path).exists())

        # Modify config again
        config.set("api.port", 8888)
        self.assertEqual(config.get("api.port"), 8888)

        # Restore from backup
        config.restore_from_backup(backup_path)
        self.assertEqual(config.get("api.port"), 9999)

        # Clean up
        Path(backup_path).unlink()

    def test_config_environment_variables(self):
        """Test environment variable overrides"""
        with patch.dict(os.environ, {'BLNCS_API_PORT': '9000', 'BLNCS_LIGHTNING_NETWORK': 'mainnet'}):
            config = ConfigManager(config_path=str(self.config_path))

            # Should use environment overrides
            self.assertEqual(config.api.port, 9000)
            self.assertEqual(config.lightning.network, 'mainnet')

    def test_config_file_watching(self):
        """Test configuration file watching (basic test)"""
        config = ConfigManager(
            config_path=str(self.config_path),
            enable_file_watching=False  # Disable for test
        )

        # Should not have watchers when disabled
        self.assertEqual(len(config._file_watchers), 0)

    def test_get_config_singleton(self):
        """Test get_config singleton behavior"""
        # Reset any existing config
        reset_config()

        config1 = get_config()
        config2 = get_config()

        # Should be the same instance
        self.assertIs(config1, config2)


class TestConfigValidation(unittest.TestCase):
    """Test configuration validation"""

    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = Path(self.temp_dir) / "test_config.json"

    def tearDown(self):
        """Clean up test environment"""
        reset_config()
        if self.config_path.exists():
            self.config_path.unlink()
        if Path(self.temp_dir).exists():
            import shutil
            shutil.rmtree(self.temp_dir)

    def test_config_integrity_check(self):
        """Test configuration integrity validation"""
        # Create valid config
        config_data = {
            "version": "2.0.0",
            "environment": "test",
            "lightning": {"network": "testnet", "host": "localhost", "port": 10009},
            "api": {"enabled": True, "port": 3000}
        }

        with open(self.config_path, 'w') as f:
            json.dump(config_data, f)

        config = ConfigManager(config_path=str(self.config_path))
        result = config.validate_configuration_integrity()

        self.assertTrue(result['valid'])
        self.assertTrue(result['checks']['parseable'])
        self.assertTrue(result['checks']['has_version'])

    def test_invalid_config_file(self):
        """Test handling of invalid config file"""
        # Create invalid JSON
        with open(self.config_path, 'w') as f:
            f.write("invalid json content {")

        config = ConfigManager(config_path=str(self.config_path))
        result = config.validate_configuration_integrity()

        self.assertFalse(result['valid'])
        self.assertFalse(result['checks']['parseable'])


if __name__ == '__main__':
    unittest.main()
