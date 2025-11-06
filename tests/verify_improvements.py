#!/usr/bin/env python3
"""
BLNCS Improvements Verification
Test all the practical improvements implemented
"""

import sys
import time
import os
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))


def test_timing(description, test_func):
    """Time a test function"""
    print(f"\n🔧 {description}")
    start = time.perf_counter()
    try:
        result = test_func()
        elapsed = time.perf_counter() - start
        if result:
            print(f"✅ Success ({elapsed:.3f}s)")
            return True, elapsed
        else:
            print(f"❌ Failed ({elapsed:.3f}s)")
            return False, elapsed
    except Exception as e:
        elapsed = time.perf_counter() - start
        print(f"💥 Error ({elapsed:.3f}s): {e}")
        return False, elapsed


def test_config_system():
    """Test unified config"""
    from blncs.core.unified_config import get_config
    config = get_config()

    # Test basic functionality
    config.set('test.key', 'test_value')
    assert config.get('test.key') == 'test_value'

    # Test dot notation
    assert config.get('lightning.host') == 'localhost'
    return True


def test_lightning_client():
    """Test Lightning client with mock support"""
    from blncs.lightning.simple_client import SimpleLightningClient

    client = SimpleLightningClient()
    connected = client.connect()  # Should work in mock mode
    assert connected is True

    info = client.get_info()
    assert 'connected' in info
    assert info['connected'] is True

    # Test basic operations
    balance = client.get_balance()
    assert 'total_balance' in balance

    invoice = client.create_invoice(1000, "test")
    assert 'payment_request' in invoice

    client.disconnect()
    return True


def test_cache_system():
    """Test simple cache with TTL"""
    from blncs.core.simple_cache import SimpleCache

    cache = SimpleCache(max_size=10)

    # Basic operations
    cache.set('key1', 'value1')
    assert cache.get('key1') == 'value1'

    # TTL support
    cache.set('key2', 'value2', ttl=0.1)
    assert cache.get('key2') == 'value2'

    time.sleep(0.2)
    assert cache.get('key2') is None  # Should be expired

    # LRU eviction
    for i in range(15):
        cache.set(f'key_{i}', f'value_{i}')

    assert cache.get('key_0') is None  # Should be evicted
    assert cache.get('key_14') == 'value_14'  # Should exist

    return True


def test_database_system():
    """Test unified database"""
    from blncs.core.unified_database import UnifiedDatabase
    import tempfile

    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
        db_path = tmp.name

    try:
        db = UnifiedDatabase(db_path)

        # Test basic query
        result = db.execute("SELECT 1 as test")
        assert result is not None

        # Test connection pool (should work)
        with db.get_connection() as conn:
            cursor = conn.execute("SELECT 1")
            assert cursor.fetchone()[0] == 1

        db.close()
        return True
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


def test_error_handling():
    """Test error handler with decorator"""
    from blncs.core.simple_error_handler import SimpleErrorHandler

    handler = SimpleErrorHandler()

    @handler.handle_errors()
    def failing_function():
        raise ValueError("Test error")

    result = failing_function()
    assert 'error' in result
    assert 'Test error' in result['error']

    return True


def test_performance_optimizer():
    """Test performance optimizer"""
    from blncs.core.performance_optimizer import PerformanceOptimizer

    optimizer = PerformanceOptimizer()

    # Test system optimization
    result = optimizer.optimize_system()
    assert 'memory' in result
    assert 'cpu' in result

    # Test memory optimization
    mem_result = optimizer.optimize_memory()
    assert 'memory_before_mb' in mem_result

    return True


def test_backup_system():
    """Test backup manager"""
    from blncs.utils.backup_manager import BackupManager
    import tempfile
    import sqlite3

    with tempfile.TemporaryDirectory() as temp_dir:
        backup_manager = BackupManager(temp_dir)

        # Create test database
        test_db = Path(temp_dir) / "test.db"
        conn = sqlite3.connect(str(test_db))
        conn.execute("CREATE TABLE test (id INTEGER)")
        conn.close()

        # Test backup
        backup_path = backup_manager.backup_database(str(test_db))
        assert Path(backup_path).exists()

        # Test list backups
        backups = backup_manager.list_backups()
        assert len(backups) > 0

        return True


def test_metrics_system():
    """Test metrics collection"""
    from blncs.utils.simple_metrics import get_metrics, timing

    metrics = get_metrics()

    # Test counter
    metrics.counter_inc('test.counter', 5)

    # Test gauge
    metrics.gauge_set('test.gauge', 42.0)

    # Test timer
    metrics.timer_record('test.timer', 0.1)

    # Test timing decorator
    @timing('test.decorated')
    def test_function():
        time.sleep(0.01)
        return True

    assert test_function() is True

    # Get stats
    stats = metrics.get_stats()
    assert 'counters' in stats
    assert 'test.counter' in stats['counters']
    assert stats['counters']['test.counter'] == 5

    return True


def test_api_system():
    """Test API creation"""
    from blncs.api.unified_rest_api import create_app
    from blncs.core.unified_config import get_config

    config = get_config()
    app = create_app(config)

    # Test that app was created
    assert app is not None
    assert hasattr(app, 'route')

    return True


def test_fast_launcher():
    """Test fast launcher startup"""
    import subprocess

    # Test system check
    result = subprocess.run([
        sys.executable, 'blncs_fast.py', 'check'
    ], capture_output=True, text=True, timeout=10)

    return result.returncode == 0


def main():
    """Run all improvement tests"""
    print("🚀 BLNCS Improvements Verification")
    print("=" * 50)

    tests = [
        ("Unified Configuration System", test_config_system),
        ("Lightning Client (Mock Mode)", test_lightning_client),
        ("Cache System with TTL", test_cache_system),
        ("Database with Connection Pool", test_database_system),
        ("Error Handling Decorator", test_error_handling),
        ("Performance Optimizer", test_performance_optimizer),
        ("Backup Manager", test_backup_system),
        ("Metrics Collection", test_metrics_system),
        ("API System", test_api_system),
        ("Fast Launcher", test_fast_launcher),
    ]

    passed = 0
    total_time = 0

    for desc, test_func in tests:
        success, elapsed = test_timing(desc, test_func)
        if success:
            passed += 1
        total_time += elapsed

    print("\n" + "=" * 50)
    print(f"📊 Results: {passed}/{len(tests)} tests passed")
    print(f"⏱️  Total time: {total_time:.3f}s")
    print(f"⚡ Average per test: {total_time/len(tests):.3f}s")

    if passed == len(tests):
        print("🎉 All improvements working correctly!")
        return 0
    else:
        print(f"⚠️  {len(tests) - passed} tests failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())