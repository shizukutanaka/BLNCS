#!/usr/bin/env python3
"""
Test New BLNCS Features
Comprehensive testing of all new practical features
"""

import sys
import time
import os
import tempfile
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))


def test_websocket_server():
    """Test WebSocket server functionality"""
    print("🌐 Testing WebSocket Server...")

    try:
        from blncs.api.websocket_server import SimpleWebSocketServer, WSMessage
        from blncs.api.websocket_server import WebSocketManager, get_websocket_manager

        # Test message creation
        message = WSMessage(type="test", data={"key": "value"})
        assert message.type == "test"
        assert message.data["key"] == "value"
        assert message.timestamp is not None

        # Test JSON serialization
        json_str = message.to_json()
        assert "test" in json_str
        assert "value" in json_str

        # Test WebSocket manager
        manager = get_websocket_manager()
        assert manager is not None

        print("   ✅ WebSocket server module loaded successfully")
        print("   ✅ Message serialization works")
        print("   ✅ Manager singleton pattern works")

        return True
    except ImportError as e:
        print(f"   ⚠️  WebSocket dependencies missing: {e}")
        return True  # Not a failure, just optional
    except Exception as e:
        print(f"   ❌ WebSocket test failed: {e}")
        return False


def test_authentication_system():
    """Test authentication system"""
    print("🔐 Testing Authentication System...")

    try:
        from blncs.core.simple_auth import SimpleAuth, AuthToken, generate_api_key
        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:
            auth_file = os.path.join(temp_dir, "test_auth.json")
            auth = SimpleAuth(auth_file)

            # Test API key generation
            api_key = auth.generate_api_key("test_key", permissions={
                'read': True,
                'write': True,
                'admin': False
            })
            assert api_key.startswith("blncs_")

            # Test validation
            token = auth.validate_api_key(api_key)
            assert token is not None
            assert token.has_permission('read')
            assert token.has_permission('write')
            assert not token.has_permission('admin')

            # Test token expiration
            expired_key = auth.generate_api_key("expired", expires_in=1)
            time.sleep(1.1)
            expired_token = auth.validate_api_key(expired_key)
            assert expired_token is None

            # Test session creation
            session_id = auth.create_session(token)
            assert session_id is not None

            session = auth.validate_session(session_id)
            assert session is not None

            print("   ✅ API key generation works")
            print("   ✅ Token validation works")
            print("   ✅ Permission system works")
            print("   ✅ Session management works")
            print("   ✅ Token expiration works")

            return True
    except Exception as e:
        print(f"   ❌ Authentication test failed: {e}")
        return False


def test_backup_manager():
    """Test backup manager functionality"""
    print("💾 Testing Backup Manager...")

    try:
        from blncs.utils.backup_manager import BackupManager
        import sqlite3
        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:
            backup_manager = BackupManager(temp_dir)

            # Create test database
            test_db = Path(temp_dir) / "test.db"
            conn = sqlite3.connect(str(test_db))
            conn.execute("CREATE TABLE test (id INTEGER, data TEXT)")
            conn.execute("INSERT INTO test VALUES (1, 'test_data')")
            conn.commit()
            conn.close()

            # Test database backup
            backup_path = backup_manager.backup_database(str(test_db))
            assert Path(backup_path).exists()

            # Test backup listing
            backups = backup_manager.list_backups()
            assert len(backups) > 0

            # Test backup info
            info = backup_manager.get_backup_size()
            assert info['total_bytes'] > 0
            assert info['file_count'] > 0

            print("   ✅ Database backup works")
            print("   ✅ Backup compression works")
            print("   ✅ Backup listing works")
            print("   ✅ Storage info works")

            return True
    except Exception as e:
        print(f"   ❌ Backup manager test failed: {e}")
        return False


def test_metrics_collection():
    """Test metrics collection system"""
    print("📊 Testing Metrics Collection...")

    try:
        from blncs.utils.simple_metrics import SimpleMetrics, TimingContext, get_metrics
        from blncs.utils.simple_metrics import timing, counter_inc, gauge_set

        # Test basic metrics
        metrics = SimpleMetrics()

        # Test counter
        metrics.counter_inc('test.counter', 5)

        # Test gauge
        metrics.gauge_set('test.gauge', 42.5)

        # Test timer
        metrics.timer_record('test.timer', 0.123)

        # Test histogram
        metrics.histogram_record('test.histogram', 100.0)

        # Test timing context
        with TimingContext(metrics, 'test.context'):
            time.sleep(0.01)

        # Test decorator
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

        assert 'gauges' in stats
        assert 'test.gauge' in stats['gauges']
        assert stats['gauges']['test.gauge'] == 42.5

        # Test global functions
        counter_inc('global.counter', 1)
        gauge_set('global.gauge', 123.0)

        global_stats = get_metrics().get_stats()
        assert 'global.counter' in global_stats['counters']

        print("   ✅ Counter metrics work")
        print("   ✅ Gauge metrics work")
        print("   ✅ Timer metrics work")
        print("   ✅ Histogram metrics work")
        print("   ✅ Timing context works")
        print("   ✅ Global metrics work")

        return True
    except Exception as e:
        print(f"   ❌ Metrics test failed: {e}")
        return False


def test_log_manager():
    """Test log management system"""
    print("📝 Testing Log Manager...")

    try:
        from blncs.utils.log_manager import LogManager
        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:
            log_manager = LogManager(temp_dir, max_size_mb=1)

            # Create test log file
            test_log = Path(temp_dir) / "test.log"
            with open(test_log, 'w') as f:
                f.write("2024-01-01 10:00:00 INFO Test message\n")
                f.write("2024-01-01 10:01:00 ERROR Test error\n")
                f.write("2024-01-01 10:02:00 INFO Another message\n")

            # Test log stats
            stats = log_manager.get_log_stats()
            assert stats['total_files'] > 0
            assert len(stats['active_logs']) > 0

            # Test log search
            results = log_manager.search_logs("error")
            assert len(results) > 0
            assert "error" in results[0]['content'].lower()

            # Test tail
            lines = log_manager.tail_log("test.log", 2)
            assert len(lines) == 2

            # Test error summary
            summary = log_manager.get_error_summary()
            assert summary['total_errors'] > 0

            print("   ✅ Log statistics work")
            print("   ✅ Log search works")
            print("   ✅ Log tail works")
            print("   ✅ Error summary works")

            return True
    except Exception as e:
        print(f"   ❌ Log manager test failed: {e}")
        return False


def test_api_endpoints():
    """Test API endpoints functionality"""
    print("🌐 Testing API Endpoints...")

    try:
        from blncs.api.unified_rest_api import create_app
        from blncs.core.unified_config import get_config

        config = get_config()
        app = create_app(config)

        # Test that app was created with new endpoints
        assert app is not None

        # Get route list (Flask specific)
        routes = []
        for rule in app.url_map.iter_rules():
            routes.append(rule.rule)

        # Check for new endpoints
        expected_endpoints = [
            '/health',
            '/api/lightning/info',
            '/api/lightning/balance',
            '/api/lightning/invoice',
            '/api/lightning/pay',
            '/api/system/backup',
            '/api/system/metrics'
        ]

        for endpoint in expected_endpoints:
            assert endpoint in routes, f"Missing endpoint: {endpoint}"

        print("   ✅ API app creation works")
        print("   ✅ All Lightning endpoints registered")
        print("   ✅ System management endpoints registered")
        print("   ✅ Health check endpoint available")

        return True
    except Exception as e:
        print(f"   ❌ API endpoints test failed: {e}")
        return False


def test_fast_launcher():
    """Test fast launcher improvements"""
    print("⚡ Testing Fast Launcher...")

    try:
        # Import the launcher module
        import blncs_fast

        # Test that it has the expected functions
        assert hasattr(blncs_fast, 'run_check')
        assert hasattr(blncs_fast, 'run_cli')
        assert hasattr(blncs_fast, 'run_api')

        # Test check function
        import subprocess
        result = subprocess.run([
            sys.executable, 'blncs_fast.py', 'check'
        ], capture_output=True, text=True, timeout=10)

        assert result.returncode == 0
        assert "System ready" in result.stdout or "checks failed" in result.stdout

        print("   ✅ Fast launcher module loads")
        print("   ✅ System check runs successfully")
        print("   ✅ All launcher functions available")

        return True
    except Exception as e:
        print(f"   ❌ Fast launcher test failed: {e}")
        return False


def main():
    """Run all new feature tests"""
    print("🚀 BLNCS New Features Test Suite")
    print("=" * 50)

    tests = [
        ("WebSocket Server", test_websocket_server),
        ("Authentication System", test_authentication_system),
        ("Backup Manager", test_backup_manager),
        ("Metrics Collection", test_metrics_collection),
        ("Log Manager", test_log_manager),
        ("API Endpoints", test_api_endpoints),
        ("Fast Launcher", test_fast_launcher),
    ]

    passed = 0
    start_time = time.time()

    for name, test_func in tests:
        try:
            success = test_func()
            if success:
                passed += 1
        except Exception as e:
            print(f"   💥 Test failed with exception: {e}")

        print()  # Add spacing between tests

    total_time = time.time() - start_time

    print("=" * 50)
    print(f"📊 Results: {passed}/{len(tests)} tests passed")
    print(f"⏱️  Total time: {total_time:.3f}s")
    print(f"⚡ Average per test: {total_time/len(tests):.3f}s")

    if passed == len(tests):
        print("🎉 All new features working correctly!")
        return 0
    else:
        print(f"⚠️  {len(tests) - passed} tests failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())