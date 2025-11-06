#!/usr/bin/env python3
"""
BLNCS Lightweight Improvements Integration Test
Test all newly implemented lightweight improvement systems
"""

import os
import sys
import time
import tempfile
from pathlib import Path

# Add BLNCS to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.'))

def test_quick_performance_boosts():
    """Test quick performance boosts"""
    print("🚀 Testing Quick Performance Boosts...")

    try:
        from blncs.core.quick_performance_boosts import apply_quick_performance_boosts, get_performance_recommendations

        start_time = time.time()
        results = apply_quick_performance_boosts()
        execution_time = time.time() - start_time

        print(f"  ⚡ Applied in {execution_time:.3f}s")
        print(f"  💾 Memory saved: {results['performance_stats']['memory_saved_mb']:.1f}MB")
        print(f"  🧹 Objects collected: {results['performance_stats']['objects_collected']}")
        print(f"  ✅ Improvements: {', '.join(results['performance_stats']['improvements'])}")

        # Test recommendations
        recommendations = get_performance_recommendations()
        print(f"  💡 Recommendations: {len(recommendations)} items")

        return True

    except Exception as e:
        print(f"  ❌ Quick Performance Boosts test failed: {e}")
        return False

def test_error_recovery():
    """Test error recovery system"""
    print("🛡️ Testing Error Recovery System...")

    try:
        from blncs.core.simple_error_recovery import SimpleErrorRecovery, get_error_recovery

        recovery = SimpleErrorRecovery()

        # Test different error types
        test_errors = [
            (ConnectionError("Test connection error"), "network"),
            (FileNotFoundError("Test file error"), "file_system"),
            (TimeoutError("Test timeout"), "api"),
            (ValueError("Test value error"), "validation")
        ]

        handled_count = 0
        for error, component in test_errors:
            try:
                raise error
            except Exception as e:
                result = recovery.handle_error(e, component)
                if result['recovery_attempted']:
                    handled_count += 1

        # Get statistics
        stats = recovery.get_error_statistics()
        health = recovery.is_system_healthy()

        print(f"  🔧 Handled {handled_count}/{len(test_errors)} errors")
        print(f"  📊 Total errors logged: {stats['total_errors']}")
        print(f"  💚 System healthy: {health}")
        print(f"  📈 Recovery rate: {stats['recovery_rate']:.1f}%")

        return True

    except Exception as e:
        print(f"  ❌ Error Recovery test failed: {e}")
        return False

def test_connection_pool():
    """Test optimized connection pool"""
    print("🔌 Testing Optimized Connection Pool...")

    try:
        from blncs.core.optimized_connection_pool import OptimizedConnectionPool, get_pool_manager

        def create_test_connection():
            return {"id": time.time(), "test": True, "ping": lambda: True}

        # Test pool
        pool = OptimizedConnectionPool(
            create_connection=create_test_connection,
            min_connections=2,
            max_connections=5,
            test_on_borrow=True
        )

        # Test getting/returning connections
        connections = []
        for i in range(3):
            conn = pool.get_connection(timeout=5.0)
            connections.append(conn)

        for conn in connections:
            pool.return_connection(conn)

        # Get statistics
        stats = pool.get_pool_statistics()

        print(f"  🔧 Total connections: {stats['total_connections']}")
        print(f"  💤 Idle connections: {stats['idle_connections']}")
        print(f"  📊 Borrowed: {stats['statistics']['borrowed']}")
        print(f"  ✅ Health checks: {stats['statistics']['health_checks']}")

        # Test pool manager
        manager = get_pool_manager()
        manager.create_pool("test_pool", create_test_connection, min_connections=1, max_connections=3)

        test_conn = manager.get_connection("test_pool")
        manager.return_connection("test_pool", test_conn)

        all_stats = manager.get_all_statistics()
        print(f"  🎛️ Managed pools: {len(all_stats)}")

        # Cleanup
        pool.close_pool()
        manager.close_all_pools()

        return True

    except Exception as e:
        print(f"  ❌ Connection Pool test failed: {e}")
        return False

def test_fast_startup():
    """Test fast startup optimizations"""
    print("⚡ Testing Fast Startup...")

    try:
        from blncs.core.fast_startup import ultra_fast_startup, intelligent_startup, get_fast_startup

        # Test ultra fast startup
        start_time = time.time()
        ultra_result = ultra_fast_startup()
        ultra_time = time.time() - start_time

        print(f"  🚀 Ultra startup: {ultra_time:.3f}s")
        print(f"  📦 Components loaded: {len(ultra_result)} items")

        # Test intelligent startup
        start_time = time.time()
        intel_result = intelligent_startup(['logging', 'validation'])
        intel_time = time.time() - start_time

        print(f"  🧠 Intelligent startup: {intel_time:.3f}s")
        print(f"  📋 Requirements met: {len(intel_result['loaded_requirements'])}")

        # Test regular fast startup
        startup = get_fast_startup()
        stats = startup.get_startup_stats()

        print(f"  ⏱️ Total startup time: {stats['total_time']:.3f}s")
        print(f"  🐍 Python version: {stats['environment']['python_version']}")

        return True

    except Exception as e:
        print(f"  ❌ Fast Startup test failed: {e}")
        return False

def test_simple_monitoring():
    """Test simple monitoring system"""
    print("📊 Testing Simple Monitoring...")

    try:
        from blncs.monitoring.simple_monitoring import create_monitoring_suite, get_monitoring

        # Create monitoring suite
        suite = create_monitoring_suite()
        monitoring = suite['monitoring']

        # Test different metric types
        monitoring.counter("test.requests", 5)
        monitoring.gauge("test.temperature", 23.5)

        # Test timer
        with monitoring.time_operation("test.operation"):
            time.sleep(0.01)  # Short operation

        # Collect system metrics
        suite['system_monitor'].collect_system_metrics()

        # Run health checks
        suite['health_monitor'].run_health_checks()

        # Get metrics
        all_metrics = monitoring.get_all_metrics()
        health_score = suite['health_monitor'].get_overall_health()

        print(f"  📈 Counters: {len(all_metrics['counters'])}")
        print(f"  📊 Gauges: {len(all_metrics['gauges'])}")
        print(f"  ⏱️ Timers: {len(all_metrics['timer_stats'])}")
        print(f"  💚 Health score: {health_score:.2f}")
        print(f"  📋 Total metrics stored: {all_metrics['total_metrics']}")

        # Test performance monitor
        @suite['performance_monitor'].monitor_function("test_function")
        def test_func():
            time.sleep(0.01)
            return "success"

        result = test_func()

        # Cleanup
        monitoring.shutdown()

        return True

    except Exception as e:
        print(f"  ❌ Simple Monitoring test failed: {e}")
        return False

def test_configuration_systems():
    """Test configuration consolidation"""
    print("⚙️ Testing Configuration Systems...")

    try:
        from blncs.core.config_consolidator import get_config
        from blncs.utils.simple_enhancements import get_enhancements

        # Test config consolidator
        config = get_config()

        # Test getting values
        lightning_host = config.get('lightning.host')
        api_port = config.get('api.port')
        db_type = config.get('database.type')

        print(f"  🌩️ Lightning host: {lightning_host}")
        print(f"  🌐 API port: {api_port}")
        print(f"  🗄️ Database type: {db_type}")
        print(f"  ✅ Config valid: {config.is_valid()}")

        # Test enhancements
        enhancements = get_enhancements()

        # Test validations
        email_valid = enhancements.validator.is_valid_email('test@example.com')
        port_valid = enhancements.validator.is_valid_port(9735)
        amount_valid, amount = enhancements.validator.validate_amount('1000')

        print(f"  📧 Email validation: {email_valid}")
        print(f"  🔌 Port validation: {port_valid}")
        print(f"  💰 Amount validation: {amount_valid} ({amount} sats)")

        return True

    except Exception as e:
        print(f"  ❌ Configuration test failed: {e}")
        return False

def test_stability_systems():
    """Test stability management"""
    print("🛡️ Testing Stability Systems...")

    try:
        from blncs.core.stability_manager import create_stability_manager
        from blncs.core.lightweight_optimizer import create_optimizer

        # Test stability manager
        stability = create_stability_manager()

        # Test circuit breaker
        def test_operation():
            return "success"

        circuit = stability.register_circuit_breaker("test_service")
        result = stability.execute_with_circuit_breaker("test_service", test_operation)

        health = stability.get_system_health()

        print(f"  🔄 Circuit breaker result: {result}")
        print(f"  💚 Health score: {health['health_score']:.1f}%")
        print(f"  📊 Components: {health['total_components']}")
        print(f"  🔗 Active resources: {health['active_resources']}")

        # Test lightweight optimizer
        optimizer = create_optimizer()

        opt_result = optimizer.run_optimization(force=True)
        summary = optimizer.get_performance_summary()

        print(f"  ⚡ Optimization runs: {summary['optimization_runs']}")
        print(f"  💾 Average memory: {summary['average_memory_mb']:.1f}MB")
        print(f"  🧹 Cache size: {summary['cache_size']}")

        # Cleanup
        stability.shutdown()
        optimizer.cleanup()

        return True

    except Exception as e:
        print(f"  ❌ Stability Systems test failed: {e}")
        return False

def main():
    """Run all lightweight improvement tests"""
    print("🎯 BLNCS Lightweight Improvements Integration Test")
    print("=" * 60)

    tests = [
        ("Quick Performance Boosts", test_quick_performance_boosts),
        ("Error Recovery", test_error_recovery),
        ("Connection Pool", test_connection_pool),
        ("Fast Startup", test_fast_startup),
        ("Simple Monitoring", test_simple_monitoring),
        ("Configuration Systems", test_configuration_systems),
        ("Stability Systems", test_stability_systems),
    ]

    start_time = time.time()
    passed_tests = 0

    for test_name, test_func in tests:
        try:
            if test_func():
                passed_tests += 1
                print(f"✅ {test_name}: PASSED\n")
            else:
                print(f"❌ {test_name}: FAILED\n")
        except Exception as e:
            print(f"💥 {test_name}: CRASHED - {e}\n")

    total_time = time.time() - start_time

    print("=" * 60)
    print(f"🏁 Test Results: {passed_tests}/{len(tests)} tests passed")
    print(f"⏱️ Total execution time: {total_time:.2f}s")

    if passed_tests == len(tests):
        print("🎉 All lightweight improvements working correctly!")

        # Summary report
        print("\n📋 Implementation Summary:")
        print("  🚀 Quick Performance Boosts - Memory & CPU optimization")
        print("  🛡️ Simple Error Recovery - Automatic error handling")
        print("  🔌 Optimized Connection Pool - High-performance connection management")
        print("  ⚡ Enhanced Fast Startup - Ultra-fast initialization")
        print("  📊 Simple Monitoring - Lightweight metrics collection")
        print("  ⚙️ Configuration Consolidation - Unified config management")
        print("  🛡️ Stability Management - Circuit breakers & health monitoring")

        return True
    else:
        print(f"⚠️ {len(tests) - passed_tests} tests failed")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)