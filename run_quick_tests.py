#!/usr/bin/env python3
"""
Quick validation tests for BLNCS system
Fast tests to verify core functionality without long-running operations.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

def test_imports():
    """Test that all core modules can be imported"""
    print("Testing module imports...")
    
    try:
        from blncs.core.exceptions import BLNCSError, format_error_for_cli
        from blncs.core.config import get_config
        from blncs.core.logger import get_logger
        from blncs.core.validation import get_validator
        from blncs.core.monitor import get_monitor
        from blncs.core.security import get_security_manager
        from blncs.core.fee_optimizer import get_fee_optimizer
        from blncs.core.channel_manager import get_channel_manager
        from blncs.core.connection_pool import ConnectionPool
        from blncs.cli.main import main
        print("✅ All core modules imported successfully")
        return True
    except Exception as e:
        print(f"❌ Import failed: {e}")
        return False

def test_configuration():
    """Test configuration system"""
    print("Testing configuration system...")
    
    try:
        from blncs.core.config import get_config
        config = get_config()
        
        # Test basic config operations
        test_value = config.get('system.name', 'default')
        config.set('test.value', 'test_data')
        retrieved_value = config.get('test.value')
        
        assert retrieved_value == 'test_data', "Config set/get failed"
        print("✅ Configuration system works")
        return True
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False

def test_exception_handling():
    """Test exception handling system"""
    print("Testing exception handling...")
    
    try:
        from blncs.core.exceptions import BLNCSError, format_error_for_cli
        
        # Create test error
        error = BLNCSError("Test error", recoverable=True)
        error_dict = error.to_dict()
        formatted = format_error_for_cli(error)
        
        assert error_dict['message'] == "Test error"
        assert error_dict['recoverable'] == True
        assert "Test error" in formatted
        
        print("✅ Exception handling works")
        return True
    except Exception as e:
        print(f"❌ Exception handling test failed: {e}")
        return False

def test_validator():
    """Test validator system"""
    print("Testing validator system...")
    
    try:
        from blncs.core.validation import get_validator
        validator = get_validator()
        
        # Test basic validation (with default config path)
        result = validator.validate_config("config/config.yaml")
        # Check if result has expected attributes
        assert hasattr(result, 'is_valid'), "Result should have is_valid attribute"
        assert hasattr(result, 'errors'), "Result should have errors attribute"
        
        print("✅ Validator system works")
        return True
    except Exception as e:
        print(f"❌ Validator test failed: {e}")
        return False

def test_monitors():
    """Test monitoring systems"""
    print("Testing monitoring systems...")
    
    try:
        from blncs.core.monitor import get_monitor
        monitor = get_monitor()
        
        # Test monitor creation and basic operations
        assert monitor is not None, "Monitor should be created"
        
        print("✅ Monitoring systems work")
        return True
    except Exception as e:
        print(f"❌ Monitoring test failed: {e}")
        return False

def main():
    """Run all quick tests"""
    print("🚀 Running BLNCS Quick Tests")
    print("=" * 50)
    
    tests = [
        test_imports,
        test_configuration,
        test_exception_handling,
        test_validator,
        test_monitors
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} crashed: {e}")
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} passed")
    
    if passed == total:
        print("🎉 All tests passed! BLNCS system is ready.")
        return 0
    else:
        print("⚠️  Some tests failed. Check the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())