#!/usr/bin/env python3
"""
Verify BLNCS Consolidation
Test script to verify all consolidated modules work correctly
"""

import sys
import os
import traceback
from pathlib import Path

# Add project to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_import_modules():
    """Test that all consolidated modules can be imported"""
    print("Testing module imports...")
    test_results = []

    modules_to_test = [
        ('blncs.core.unified_logging', 'Unified Logging'),
        ('blncs.core.lightweight_metrics', 'Lightweight Metrics'),
        ('blncs.core.performance_optimizations', 'Performance Optimizations'),
        ('blncs.core.enhanced_core', 'Enhanced Core'),
        ('blncs.core.metrics', 'Metrics (Redirected)'),
        ('blncs.core.logger', 'Logger (Redirected)'),
        ('blncs.core.micro_speed_boosts', 'Micro Speed Boosts (Redirected)'),
        ('blncs.core.ultra_lightweight_optimizations', 'Ultra Lightweight (Redirected)')
    ]

    for module_name, description in modules_to_test:
        try:
            __import__(module_name)
            test_results.append((module_name, description, "PASS"))
            print(f"  ✓ {description}: PASS")
        except ImportError as e:
            test_results.append((module_name, description, f"FAIL: {e}"))
            print(f"  ✗ {description}: FAIL - {e}")
        except Exception as e:
            test_results.append((module_name, description, f"ERROR: {e}"))
            print(f"  ✗ {description}: ERROR - {e}")

    return test_results


def test_core_functionality():
    """Test core functionality"""
    print("\nTesting core functionality...")

    try:
        # Test logging
        print("  Testing logging system...")
        from blncs.core.unified_logging import get_logger
        logger = get_logger("test")
        logger.info("Test log message")
        print("    ✓ Logging works")

        # Test metrics
        print("  Testing metrics system...")
        from blncs.core.lightweight_metrics import get_metrics_collector, record_metric
        metrics = get_metrics_collector()
        record_metric("test.metric", 1.0)
        print("    ✓ Metrics works")

        # Test performance optimizations
        print("  Testing performance optimizations...")
        from blncs.core.performance_optimizations import get_optimizer
        optimizer = get_optimizer()
        print("    ✓ Performance optimizer works")

        # Test enhanced core
        print("  Testing enhanced core system...")
        from blncs.core.enhanced_core import SystemConfig, get_core
        config = SystemConfig()
        core = get_core()
        status = core.get_status()
        print(f"    ✓ Enhanced core works - Status: {status['health']['status']}")

        return True

    except Exception as e:
        print(f"  ✗ Core functionality test failed: {e}")
        traceback.print_exc()
        return False


def test_file_structure():
    """Test that file structure is clean"""
    print("\nChecking file structure...")

    # Check for removed files
    removed_files = [
        'blncs_fast.py',
        'blncs_simple.py',
        'blncs_unified.py',
        'blncs_simple_test.py',
        'Dockerfile.simple',
        'Dockerfile_simple',
        'deploy_simple.sh',
        'run_tests_fixed.py'
    ]

    for file_name in removed_files:
        if os.path.exists(file_name):
            print(f"  ✗ Duplicate file still exists: {file_name}")
        else:
            print(f"  ✓ Removed duplicate: {file_name}")

    # Check that main entry point exists
    if os.path.exists('blncs_main.py'):
        print(f"  ✓ Main entry point exists: blncs_main.py")
    else:
        print(f"  ✗ Main entry point missing: blncs_main.py")

    # Check that tests are in tests/ directory
    test_files_in_root = [f for f in os.listdir('.') if f.startswith('test_') and f.endswith('.py')]
    if test_files_in_root:
        print(f"  ✗ Test files still in root: {test_files_in_root}")
    else:
        print(f"  ✓ No test files in root directory")

    # Check tests directory exists
    if os.path.exists('tests') and os.path.isdir('tests'):
        test_count = len([f for f in os.listdir('tests') if f.endswith('.py')])
        print(f"  ✓ Tests directory exists with {test_count} test files")
    else:
        print(f"  ✗ Tests directory missing")


def main():
    """Main verification function"""
    print("=" * 60)
    print("BLNCS Consolidation Verification")
    print("=" * 60)

    # Test imports
    import_results = test_import_modules()

    # Test core functionality
    core_works = test_core_functionality()

    # Test file structure
    test_file_structure()

    # Summary
    print("\n" + "=" * 60)
    print("VERIFICATION SUMMARY")
    print("=" * 60)

    import_failures = [r for r in import_results if not r[2] == "PASS"]

    if not import_failures and core_works:
        print("✓ All tests passed! Consolidation successful.")
        return 0
    else:
        if import_failures:
            print(f"✗ {len(import_failures)} import failures detected")
            for module, desc, status in import_failures:
                print(f"  - {desc}: {status}")
        if not core_works:
            print("✗ Core functionality tests failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())