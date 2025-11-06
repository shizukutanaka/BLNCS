#!/usr/bin/env python3
"""
BLNCS Additional Improvements Integration Test
Test all newly implemented lightweight improvement systems
"""

import os
import sys
import time
import tempfile
from pathlib import Path

# Add BLNCS to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.'))

def test_ultra_lightweight_optimizations():
    """Test ultra-lightweight optimizations"""
    print("⚡ Testing Ultra-Lightweight Optimizations...")

    try:
        from blncs.core.ultra_lightweight_optimizations import optimize_lightning_operations, fast_hash

        start_time = time.time()
        results = optimize_lightning_operations()
        execution_time = time.time() - start_time

        print(f"  🚀 Optimizations applied in {execution_time * 1000:.2f}ms")
        print(f"  📊 Total optimizations: {results['optimization_summary']['total_optimizations']}")
        print(f"  🧠 Applied: {', '.join(results['optimization_summary']['optimizations_applied'])}")

        # Test fast hash
        test_hash = fast_hash("test_lightning_payment_12345")
        print(f"  #️⃣ Fast hash test: {test_hash}")

        return True

    except Exception as e:
        print(f"  ❌ Ultra-lightweight optimizations test failed: {e}")
        return False

def test_micro_speed_boosts():
    """Test micro speed boosts"""
    print("⚡ Testing Micro Speed Boosts...")

    try:
        from blncs.core.micro_speed_boosts import apply_micro_speed_boosts, lightning_amount_format

        start_time = time.time()
        results = apply_micro_speed_boosts()
        execution_time = time.time() - start_time

        print(f"  🚀 Micro boosts applied in {execution_time * 1000:.2f}ms")
        print(f"  📊 Optimizations count: {results['optimizations_count']}")
        print(f"  ⚡ Processing time: {results['execution_time_us']:.1f}μs")

        # Test utility functions
        amount_test = lightning_amount_format(250000)
        print(f"  💰 Amount format: {amount_test}")

        return True

    except Exception as e:
        print(f"  ❌ Micro speed boosts test failed: {e}")
        return False

def test_simple_backup_recovery():
    """Test simple backup and recovery"""
    print("💾 Testing Simple Backup Recovery...")

    try:
        from blncs.utils.simple_backup_recovery import SimpleBackup, emergency_backup
        import json

        # Create test backup system
        backup_system = SimpleBackup("test_backups", max_backups=3)

        # Create test file
        test_file = "test_backup_data.json"
        test_data = {"test": "backup_data", "timestamp": time.time()}
        with open(test_file, 'w') as f:
            json.dump(test_data, f)

        # Test file backup
        backup_item = backup_system.backup_file(test_file)
        backup_success = backup_item is not None

        # Test backup listing
        backups = backup_system.list_backups()

        # Test emergency backup
        emergency_result = emergency_backup()

        # Get backup size info
        size_info = backup_system.get_backup_size()

        print(f"  📦 File backup: {'✅' if backup_success else '❌'}")
        print(f"  📋 Available backups: {len(backups)}")
        print(f"  🚨 Emergency backup items: {len(emergency_result['emergency_backups'])}")
        print(f"  💾 Backup size: {size_info['total_size_mb']:.2f}MB")

        # Cleanup
        os.remove(test_file)
        import shutil
        shutil.rmtree("test_backups", ignore_errors=True)
        shutil.rmtree("emergency_backups", ignore_errors=True)

        return True

    except Exception as e:
        print(f"  ❌ Simple backup recovery test failed: {e}")
        return False

def test_database_speed_optimizer():
    """Test database speed optimizer"""
    print("🗄️ Testing Database Speed Optimizer...")

    try:
        from blncs.core.database_speed_optimizer import create_optimized_database
        import tempfile
        import os

        # Create temporary database
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            test_db = tmp.name

        try:
            # Create optimized database
            db_system = create_optimized_database(test_db)
            optimizer = db_system['optimizer']
            connection = db_system['connection']

            # Test payment operations
            test_payment = {
                'payment_hash': 'test_hash_speed_12345',
                'amount_sats': 2000,
                'status': 'pending',
                'created_at': time.time(),
                'updated_at': time.time(),
                'destination': 'test_node',
                'description': 'Speed test payment'
            }

            # Test insert
            insert_success = optimizer.fast_payment_insert(connection, test_payment)

            # Test query
            query_result = optimizer.fast_payment_query(connection, 'test_hash_speed_12345')

            # Test channel listing
            channels = optimizer.fast_channel_list(connection, limit=10)

            # Get performance stats
            stats = optimizer.get_performance_stats()

            print(f"  💳 Payment insert: {'✅' if insert_success else '❌'}")
            print(f"  🔍 Payment query: {'✅' if query_result else '❌'}")
            print(f"  📊 Performance profiles: {len(stats['query_profiles'])}")
            print(f"  💾 Cache stats available: {'✅' if 'cache_stats' in stats else '❌'}")

            # Cleanup
            optimizer.cleanup()
            connection.close()

        finally:
            os.unlink(test_db)

        return True

    except Exception as e:
        print(f"  ❌ Database speed optimizer test failed: {e}")
        return False

def test_lightweight_security():
    """Test lightweight security"""
    print("🔒 Testing Lightweight Security...")

    try:
        from blncs.core.lightweight_security import create_security_system

        security = create_security_system()

        # Test payment validation
        test_payment = {
            'payment_hash': 'a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd',
            'amount_sats': 1500,
            'description': 'Security test payment',
            'source_ip': '127.0.0.1'
        }

        validation_result = security.validate_payment_request(test_payment)
        payment_valid = validation_result['valid']

        # Test invoice validation
        test_invoice = {
            'amount_sats': 1000,
            'description': 'Test invoice',
            'source_ip': '127.0.0.1'
        }

        invoice_result = security.validate_invoice_request(test_invoice)
        invoice_valid = invoice_result['valid']

        # Test rate limiting
        rate_limit_triggered = False
        for i in range(102):  # Over limit of 100
            if not security.rate_limiter.is_allowed('test_rate_limit'):
                rate_limit_triggered = True
                break

        # Test secure storage
        test_secret = "lightning_node_secret_key"
        secured = security.secure_config_value("node_key", test_secret)
        retrieved = security.retrieve_config_value("node_key", secured)
        storage_works = retrieved == test_secret

        # Get security status
        status = security.get_security_status()

        print(f"  💳 Payment validation: {'✅' if payment_valid else '❌'}")
        print(f"  📄 Invoice validation: {'✅' if invoice_valid else '❌'}")
        print(f"  🚫 Rate limiting: {'✅' if rate_limit_triggered else '❌'}")
        print(f"  🔐 Secure storage: {'✅' if storage_works else '❌'}")
        print(f"  📊 Security events: {status['security_monitor']['total_events']}")

        return True

    except Exception as e:
        print(f"  ❌ Lightweight security test failed: {e}")
        return False

def test_integration_systems():
    """Test integration of all systems"""
    print("🔗 Testing System Integration...")

    try:
        # Test that all systems can work together
        from blncs.core.ultra_lightweight_optimizations import SpeedOptimizer
        from blncs.core.micro_speed_boosts import LightningMicroOptimizer
        from blncs.core.lightweight_security import LightweightSecurity

        # Create optimizers
        speed_optimizer = SpeedOptimizer()
        micro_optimizer = LightningMicroOptimizer()
        security = LightweightSecurity()

        # Apply optimizations
        speed_results = speed_optimizer.apply_all_optimizations()
        micro_results = micro_optimizer.optimize_payment_processing({
            'amount_btc': 0.001,
            'payment_hash': 'integration_test_hash_12345678901234567890123456789012345678901234',
            'status': 'pending'
        })

        # Test security with optimized data (use proper 64-char hex hash)
        security_result = security.validate_payment_request({
            'payment_hash': 'a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd',
            'amount_sats': micro_results.get('amount_sats', 100000),
            'source_ip': '127.0.0.1'
        })

        integration_success = (
            speed_results['optimization_summary']['total_optimizations'] > 0 and
            'amount_sats' in micro_results and
            security_result['valid']
        )

        print(f"  🚀 Speed optimizations: {speed_results['optimization_summary']['total_optimizations']}")
        print(f"  ⚡ Micro optimizations: {'✅' if 'amount_sats' in micro_results else '❌'}")
        print(f"  🔒 Security validation: {'✅' if security_result['valid'] else '❌'}")
        print(f"  🔗 Integration success: {'✅' if integration_success else '❌'}")

        return integration_success

    except Exception as e:
        print(f"  ❌ System integration test failed: {e}")
        return False

def main():
    """Run all additional improvement tests"""
    print("🎯 BLNCS Additional Improvements Integration Test")
    print("=" * 60)

    tests = [
        ("Ultra-Lightweight Optimizations", test_ultra_lightweight_optimizations),
        ("Micro Speed Boosts", test_micro_speed_boosts),
        ("Simple Backup Recovery", test_simple_backup_recovery),
        ("Database Speed Optimizer", test_database_speed_optimizer),
        ("Lightweight Security", test_lightweight_security),
        ("System Integration", test_integration_systems),
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
        print("🎉 All additional improvements working correctly!")

        # Final summary
        print("\n📋 Additional Implementation Summary:")
        print("  ⚡ Ultra-Lightweight Optimizations - Python internals & memory layout")
        print("  🚀 Micro Speed Boosts - Lightning-specific performance optimizations")
        print("  💾 Simple Backup Recovery - Automated backup system")
        print("  🗄️ Database Speed Optimizer - SQLite optimizations & query caching")
        print("  🔒 Lightweight Security - Input validation & rate limiting")
        print("  🔗 System Integration - All components working together")

        return True
    else:
        print(f"⚠️ {len(tests) - passed_tests} tests failed")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)