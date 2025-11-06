#!/usr/bin/env python3
"""
BLNCS Test Runner
Simplified test execution with comprehensive coverage and reporting.
"""

import sys
import os
import time
import argparse
import json
import tempfile
import traceback
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

# Ensure project root is in path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

# Test environment setup
os.environ['BLNCS_TEST_MODE'] = '1'
os.environ['BLNCS_LOG_LEVEL'] = 'ERROR'
os.environ['PYTHONPATH'] = str(PROJECT_ROOT)

def test_config():
    """Test configuration system"""
    print("Testing Configuration...")
    from blncs.core.config import UnifiedConfig

    config = UnifiedConfig()

    # Test defaults
    assert config.get('database.path') == 'blncs.db', "Default database path"
    assert config.get('api.port') == 8080, "Default API port"

    # Test set/get
    config.set('test.key', 'test_value')
    assert config.get('test.key') == 'test_value', "Set and get value"

    # Test validation
    result = config.validate()
    assert result['valid'] is True, "Valid configuration"

    print("✓ Configuration tests passed")
    return True


def test_database():
    """Test database system"""
    print("Testing Database...")
    from blncs.core.database import UnifiedDatabase

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = UnifiedDatabase(str(db_path))

        # Test table creation
        tables = db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
        table_names = [t['name'] for t in tables]
        assert 'channels' in table_names, "Channels table exists"
        assert 'transactions' in table_names, "Transactions table exists"

        # Test insert
        db.insert('nodes', {
            'id': 'test_node',
            'alias': 'Test Node'
        })

        # Test fetch
        node = db.fetchone("SELECT * FROM nodes WHERE id = ?", ('test_node',))
        assert node is not None, "Node inserted"
        assert node['alias'] == 'Test Node', "Node data correct"

        # Test settings
        db.save_setting('test_key', 'test_value')
        value = db.get_setting('test_key')
        assert value == 'test_value', "Settings work"

        db.close()

    print("✓ Database tests passed")
    return True


def test_cache():
    """Test caching system"""
    print("Testing Cache...")
    from blncs.core.cache import UnifiedCache

    cache = UnifiedCache(max_size=10)

    # Test set/get
    cache.set('key1', 'value1')
    assert cache.get('key1') == 'value1', "Cache set/get"

    # Test default value
    assert cache.get('nonexistent', 'default') == 'default', "Default value"

    # Test delete
    cache.set('key2', 'value2')
    cache.delete('key2')
    assert cache.get('key2') is None, "Delete works"

    # Test exists
    cache.set('key3', 'value3')
    assert cache.exists('key3') is True, "Exists check"
    assert cache.exists('nonexistent') is False, "Not exists check"

    # Test stats
    stats = cache.get_stats()
    assert 'hits' in stats, "Stats available"

    cache.stop()

    print("✓ Cache tests passed")
    return True


def test_logger():
    """Test logging system"""
    print("Testing Logger...")
    from blncs.core.logger import get_logger, LogManager

    # Test logger creation
    logger = get_logger('test')
    assert logger is not None, "Logger created"

    # Test log manager
    manager = LogManager()
    test_logger = manager.get_logger('test2')
    assert test_logger.name == 'test2', "Named logger"

    # Test log stats
    stats = manager.get_log_stats()
    assert 'config' in stats, "Log stats available"

    print("✓ Logger tests passed")
    return True


def test_lightning_client():
    """Test Lightning client"""
    print("Testing Lightning Client...")
    try:
        # Import without grpc dependency for testing
        import sys
        sys.modules['grpc'] = None  # Mock grpc module

        from blncs.lightning.simple_client import PracticalLightningClient

        # Test client creation with forced mock mode
        client = PracticalLightningClient()
        client.client_type = 'mock'  # Force mock mode for testing
        assert client is not None, "Lightning client created"

        # Test mock functionality (should work without actual Lightning node)
        info = client.get_info()
        assert 'alias' in info, "Node info contains alias"
        assert 'identity_pubkey' in info, "Node info contains pubkey"

        balance = client.get_balance()
        assert 'channel_balance' in balance, "Balance info contains channel balance"

        channels = client.list_channels()
        assert isinstance(channels, list), "Channels list returned"

        invoice = client.create_invoice(1000, "Test invoice")
        assert 'payment_request' in invoice, "Invoice created"

        client.disconnect()

        print("✓ Lightning Client tests passed")
        return True

    except Exception as e:
        print(f"✗ Lightning Client test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_api_endpoints():
    """Test API endpoint definitions"""
    print("Testing API Endpoints...")

    # Just check that the API module can be imported
    try:
        from blncs.api.unified_api_server import UnifiedAPIServer
        api = UnifiedAPIServer()
        assert api is not None, "API instance created"
        print("✓ API tests passed")
        return True
    except Exception as e:
        print(f"✗ API test failed: {e}")
        return False


def test_cli_commands():
    """Test CLI command definitions"""
    print("Testing CLI Commands...")

    try:
        from blncs.cli.main import cli
        assert cli is not None, "CLI created"
        print("✓ CLI tests passed")
        return True
    except Exception as e:
        print(f"✗ CLI test failed: {e}")
        return False


def main():
    """Run all tests"""
    print("\n" + "="*50)
    print("BLNCS Test Suite")
    print("="*50 + "\n")

    tests = [
        test_config,
        test_database,
        test_cache,
        test_logger,
        test_lightning_client,
        test_api_endpoints,
        test_cli_commands
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"✗ {test.__name__} failed with exception:")
            traceback.print_exc()
            failed += 1
        print()

    print("="*50)
    print(f"Results: {passed} passed, {failed} failed")
    print("="*50)

    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())