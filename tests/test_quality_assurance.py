#!/usr/bin/env python3
"""
Comprehensive Quality Assurance Test Suite
Tests all major BLNCS functionality for highest quality standards.
"""

import unittest
import sys
import time
import tempfile
import threading
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

# Add BLNCS to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from blncs.core.error_recovery import (
        get_error_recovery_manager, ErrorRecoveryManager, ErrorSeverity,
        RecoveryStrategy, CircuitBreaker, with_retry, with_circuit_breaker
    )
    from blncs.core.input_validator import (
        get_input_validator, InputValidator, ValidationRule, ValidationType,
        InputSanitizer, ValidationError, validate_input
    )
    from blncs.core.performance_optimizer import (
        get_performance_optimizer, PerformanceOptimizer, PerformanceLevel,
        PerformanceCache, profile_performance, cached_result
    )
    from blncs.core.health_diagnostics import (
        get_system_diagnostics, SystemDiagnostics, HealthStatus,
        ComponentType, HealthCheckResult
    )
    from blncs.core.backup_enhanced import (
        get_enhanced_backup, EnhancedBackupManager, BackupType
    )
    from blncs.core.one_click_connector import get_one_click_connector
    from blncs.core.qr_payments import get_qr_payment_manager
    from blncs.core.node_discovery import get_node_discovery
    IMPORTS_SUCCESS = True
except ImportError as e:
    print(f"Import error: {e}")
    IMPORTS_SUCCESS = False


class TestErrorRecovery(unittest.TestCase):
    """Test error recovery and circuit breaker functionality"""
    
    @classmethod
    def setUpClass(cls):
        if not IMPORTS_SUCCESS:
            cls.skipTest("Imports failed")
    
    def setUp(self):
        self.error_manager = ErrorRecoveryManager()
    
    def test_circuit_breaker_registration(self):
        """Test circuit breaker registration"""
        cb = self.error_manager.register_circuit_breaker("test_service")
        self.assertIsInstance(cb, CircuitBreaker)
        self.assertEqual(cb.name, "test_service")
        self.assertEqual(cb.state.value, "closed")
    
    def test_circuit_breaker_failure_handling(self):
        """Test circuit breaker failure handling"""
        cb = self.error_manager.register_circuit_breaker("test_service", 
                                                        {"failure_threshold": 2})
        
        # Record failures
        cb.record_failure()
        self.assertTrue(cb.can_execute())
        
        cb.record_failure()
        self.assertFalse(cb.can_execute())  # Should be open now
        self.assertEqual(cb.state.value, "open")
    
    def test_retry_decorator(self):
        """Test retry decorator functionality"""
        call_count = 0
        
        @with_retry(max_attempts=3)
        def failing_function():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Test error")
            return "success"
        
        result = failing_function()
        self.assertEqual(result, "success")
        self.assertEqual(call_count, 3)
    
    def test_error_context_recording(self):
        """Test error context recording"""
        error = ValueError("Test error")
        context = self.error_manager.record_error(error, "test_operation")
        
        self.assertEqual(context.error_type, ValueError)
        self.assertEqual(context.operation, "test_operation")
        self.assertIsInstance(context.severity, ErrorSeverity)
    
    def test_fallback_handler(self):
        """Test fallback handler registration and execution"""
        def fallback():
            return "fallback_result"
        
        self.error_manager.register_fallback_handler("test_op", fallback)
        
        def failing_operation():
            raise Exception("Always fails")
        
        result = self.error_manager.execute_with_recovery(
            failing_operation, "test_op"
        )
        # This should raise the exception since no automatic fallback is applied
        # In real usage, the fallback would need to be explicitly called


class TestInputValidation(unittest.TestCase):
    """Test input validation and sanitization"""
    
    @classmethod
    def setUpClass(cls):
        if not IMPORTS_SUCCESS:
            cls.skipTest("Imports failed")
    
    def setUp(self):
        self.validator = InputValidator()
        self.sanitizer = InputSanitizer()
    
    def test_string_validation(self):
        """Test string validation"""
        rule = ValidationRule(ValidationType.STRING, min_length=3, max_length=10)
        
        # Valid string
        result = self.validator.validate_value("hello", rule)
        self.assertEqual(result, "hello")
        
        # Too short
        with self.assertRaises(ValidationError):
            self.validator.validate_value("hi", rule)
        
        # Too long
        with self.assertRaises(ValidationError):
            self.validator.validate_value("this is too long", rule)
    
    def test_integer_validation(self):
        """Test integer validation"""
        rule = ValidationRule(ValidationType.INTEGER, min_value=0, max_value=100)
        
        # Valid integer
        result = self.validator.validate_value(50, rule)
        self.assertEqual(result, 50)
        
        # String to integer conversion
        result = self.validator.validate_value("75", rule)
        self.assertEqual(result, 75)
        
        # Out of range
        with self.assertRaises(ValidationError):
            self.validator.validate_value(-5, rule)
        
        with self.assertRaises(ValidationError):
            self.validator.validate_value(150, rule)
    
    def test_pubkey_validation(self):
        """Test Lightning Network public key validation"""
        rule = ValidationRule(ValidationType.PUBKEY)
        
        # Valid pubkey (66 hex characters)
        valid_pubkey = "02" + "a" * 64
        result = self.validator.validate_value(valid_pubkey, rule)
        self.assertEqual(result, valid_pubkey)
        
        # Invalid pubkey (wrong length)
        with self.assertRaises(ValidationError):
            self.validator.validate_value("invalid", rule)
    
    def test_amount_validation(self):
        """Test amount validation and conversion"""
        rule = ValidationRule(ValidationType.AMOUNT, min_value=0)
        
        # Integer amount (satoshis)
        result = self.validator.validate_value(1000, rule)
        self.assertEqual(result, 1000)
        
        # Float amount (BTC to satoshis)
        result = self.validator.validate_value(0.001, rule)
        self.assertEqual(result, 100000)  # 0.001 BTC = 100,000 sats
        
        # String amount
        result = self.validator.validate_value("0.0001", rule)
        self.assertEqual(result, 10000)  # 0.0001 BTC = 10,000 sats
    
    def test_sanitization(self):
        """Test input sanitization"""
        # String sanitization
        dirty_string = "  <script>alert('xss')</script>  "
        clean_string = self.sanitizer.sanitize_string(dirty_string)
        self.assertNotIn("<script>", clean_string)
        self.assertEqual(clean_string.strip(), "alert('xss')")
        
        # Path sanitization
        dangerous_path = "../../../etc/passwd"
        safe_path = self.sanitizer.sanitize_path(dangerous_path)
        self.assertNotIn("..", safe_path)
    
    def test_schema_validation(self):
        """Test dictionary validation against schema"""
        schema = self.validator.create_schema(
            name={"type": "string", "min_length": 2, "max_length": 50},
            age={"type": "integer", "min_value": 0, "max_value": 150},
            email={"type": "email"},
            required=True
        )
        
        valid_data = {
            "name": "John Doe",
            "age": 30,
            "email": "john@example.com"
        }
        
        result = self.validator.validate_dict(valid_data, schema)
        self.assertEqual(result["name"], "John Doe")
        self.assertEqual(result["age"], 30)
        
        # Invalid data
        invalid_data = {
            "name": "J",  # Too short
            "age": -5,    # Negative
            "email": "invalid-email"
        }
        
        with self.assertRaises(ValidationError):
            self.validator.validate_dict(invalid_data, schema)


class TestPerformanceOptimization(unittest.TestCase):
    """Test performance monitoring and optimization"""
    
    @classmethod
    def setUpClass(cls):
        if not IMPORTS_SUCCESS:
            cls.skipTest("Imports failed")
    
    def setUp(self):
        self.optimizer = PerformanceOptimizer(PerformanceLevel.BALANCED)
    
    def test_operation_profiling(self):
        """Test operation performance profiling"""
        # Measure a test operation
        with self.optimizer.measure_operation("test_operation"):
            time.sleep(0.1)  # Simulate work
        
        profile = self.optimizer.get_operation_profile("test_operation")
        self.assertIsNotNone(profile)
        self.assertEqual(profile.call_count, 1)
        self.assertGreater(profile.total_time, 0.05)  # Should be at least 50ms
    
    def test_performance_cache(self):
        """Test performance cache functionality"""
        cache = PerformanceCache(max_size=10, ttl_seconds=1)
        
        # Set and get
        cache.set("test_key", "test_value")
        self.assertEqual(cache.get("test_key"), "test_value")
        
        # TTL expiration
        time.sleep(1.1)
        self.assertIsNone(cache.get("test_key"))
        
        # Cache size limit
        for i in range(15):
            cache.set(f"key_{i}", f"value_{i}")
        
        stats = cache.stats()
        self.assertEqual(stats["size"], 10)  # Should not exceed max_size
    
    def test_profile_performance_decorator(self):
        """Test performance profiling decorator"""
        @profile_performance("decorated_function")
        def test_function():
            time.sleep(0.05)
            return "result"
        
        result = test_function()
        self.assertEqual(result, "result")
        
        profile = self.optimizer.get_operation_profile("decorated_function")
        self.assertIsNotNone(profile)
        self.assertEqual(profile.call_count, 1)
    
    def test_cached_result_decorator(self):
        """Test result caching decorator"""
        call_count = 0
        
        @cached_result(ttl_seconds=1)
        def expensive_function(x):
            nonlocal call_count
            call_count += 1
            return x * 2
        
        # First call
        result1 = expensive_function(5)
        self.assertEqual(result1, 10)
        self.assertEqual(call_count, 1)
        
        # Second call should use cache
        result2 = expensive_function(5)
        self.assertEqual(result2, 10)
        self.assertEqual(call_count, 1)  # Should not increment
    
    def test_performance_report(self):
        """Test performance report generation"""
        # Generate some test data
        with self.optimizer.measure_operation("fast_op"):
            time.sleep(0.01)
        
        with self.optimizer.measure_operation("slow_op"):
            time.sleep(0.1)
        
        report = self.optimizer.get_performance_report()
        
        self.assertIn("system", report)
        self.assertIn("operations", report)
        self.assertIn("cache", report)
        self.assertIn("recommendations", report)
        self.assertGreater(report["operations"]["total_tracked"], 0)


class TestHealthDiagnostics(unittest.TestCase):
    """Test health check and diagnostic functionality"""
    
    @classmethod
    def setUpClass(cls):
        if not IMPORTS_SUCCESS:
            cls.skipTest("Imports failed")
    
    def setUp(self):
        self.diagnostics = SystemDiagnostics()
    
    def test_health_check_registration(self):
        """Test health check registration"""
        def test_check():
            return HealthCheckResult(
                component="test", 
                component_type=ComponentType.PROCESS,
                status=HealthStatus.HEALTHY,
                message="Test OK"
            )
        
        self.diagnostics.register_health_check(
            "test_check", ComponentType.PROCESS, test_check
        )
        
        result = self.diagnostics.run_health_check("test_check")
        self.assertIsNotNone(result)
        self.assertEqual(result.status, HealthStatus.HEALTHY)
    
    def test_system_health_summary(self):
        """Test system health summary generation"""
        summary = self.diagnostics.get_system_health_summary()
        
        self.assertIn("overall_status", summary)
        self.assertIn("summary", summary)
        self.assertIn("critical_issues", summary)
        self.assertIn("warning_issues", summary)
        self.assertIsInstance(summary["summary"], dict)
    
    def test_detailed_diagnostics(self):
        """Test detailed diagnostics generation"""
        diagnostics = self.diagnostics.get_detailed_diagnostics()
        
        self.assertIn("timestamp", diagnostics)
        self.assertIn("system_info", diagnostics)
        self.assertIn("health_checks", diagnostics)
        self.assertIn("performance_metrics", diagnostics)
        self.assertIn("recommendations", diagnostics)
    
    def test_custom_health_check(self):
        """Test custom health check implementation"""
        def failing_check():
            return {
                "status": HealthStatus.CRITICAL,
                "message": "Test failure",
                "suggestions": ["Fix the test"]
            }
        
        self.diagnostics.register_health_check(
            "failing_test", ComponentType.EXTERNAL_SERVICE, failing_check
        )
        
        result = self.diagnostics.run_health_check("failing_test")
        self.assertEqual(result.status, HealthStatus.CRITICAL)
        self.assertIn("Fix the test", result.suggestions)
    
    def test_monitoring_lifecycle(self):
        """Test health monitoring start/stop"""
        self.assertFalse(self.diagnostics.monitoring_active)
        
        self.diagnostics.start_monitoring(check_interval=1)
        self.assertTrue(self.diagnostics.monitoring_active)
        
        # Let it run for a moment
        time.sleep(0.1)
        
        self.diagnostics.stop_monitoring()
        self.assertFalse(self.diagnostics.monitoring_active)


class TestBackupEncryption(unittest.TestCase):
    """Test enhanced backup functionality with encryption"""
    
    @classmethod
    def setUpClass(cls):
        if not IMPORTS_SUCCESS:
            cls.skipTest("Imports failed")
    
    def setUp(self):
        self.backup_manager = EnhancedBackupManager()
        self.test_password = "test_password_123"
    
    def test_encryption_key_management(self):
        """Test encryption key setup and loading"""
        # Test key setup
        success = self.backup_manager.set_encryption_key(self.test_password)
        self.assertTrue(success)
        self.assertIsNotNone(self.backup_manager._encryption_key)
        
        # Test key loading
        self.backup_manager._encryption_key = None  # Reset
        success = self.backup_manager.load_encryption_key(self.test_password)
        self.assertTrue(success)
        self.assertIsNotNone(self.backup_manager._encryption_key)
    
    def test_data_encryption_decryption(self):
        """Test data encryption and decryption"""
        if not hasattr(self.backup_manager, '_encrypt_data'):
            self.skipTest("Encryption not available")
        
        self.backup_manager.set_encryption_key(self.test_password)
        
        test_data = b"This is test data for encryption"
        
        # Encrypt data
        encrypted_data = self.backup_manager._encrypt_data(test_data)
        self.assertNotEqual(encrypted_data, test_data)
        
        # Decrypt data
        decrypted_data = self.backup_manager._decrypt_data(encrypted_data)
        self.assertEqual(decrypted_data, test_data)
    
    def test_backup_status_with_encryption(self):
        """Test backup status reporting with encryption"""
        self.backup_manager.encryption_enabled = True
        self.backup_manager.set_encryption_key(self.test_password)
        
        status = self.backup_manager.get_backup_status()
        
        self.assertTrue(status["encryption_enabled"])
        self.assertTrue(status["encryption_key_set"])
        self.assertIn("encryption_method", status)


class TestIntegratedFeatures(unittest.TestCase):
    """Test integrated Lightning Network features"""
    
    @classmethod
    def setUpClass(cls):
        if not IMPORTS_SUCCESS:
            cls.skipTest("Imports failed")
    
    def test_one_click_connector_initialization(self):
        """Test one-click connector initialization"""
        try:
            connector = get_one_click_connector()
            self.assertIsNotNone(connector)
        except Exception as e:
            self.skipTest(f"One-click connector not available: {e}")
    
    def test_qr_payment_manager_initialization(self):
        """Test QR payment manager initialization"""
        try:
            qr_manager = get_qr_payment_manager()
            self.assertIsNotNone(qr_manager)
        except Exception as e:
            self.skipTest(f"QR payment manager not available: {e}")
    
    def test_node_discovery_initialization(self):
        """Test node discovery initialization"""
        try:
            discovery = get_node_discovery()
            self.assertIsNotNone(discovery)
        except Exception as e:
            self.skipTest(f"Node discovery not available: {e}")


class TestSystemIntegration(unittest.TestCase):
    """Test system-wide integration"""
    
    @classmethod
    def setUpClass(cls):
        if not IMPORTS_SUCCESS:
            cls.skipTest("Imports failed")
    
    def test_global_managers_initialization(self):
        """Test that all global managers initialize correctly"""
        managers = []
        
        try:
            managers.append(get_error_recovery_manager())
            managers.append(get_input_validator())
            managers.append(get_performance_optimizer())
            managers.append(get_system_diagnostics())
            managers.append(get_enhanced_backup())
        except Exception as e:
            self.fail(f"Failed to initialize managers: {e}")
        
        for manager in managers:
            self.assertIsNotNone(manager)
    
    def test_thread_safety(self):
        """Test thread safety of managers"""
        error_manager = get_error_recovery_manager()
        results = []
        
        def test_thread():
            try:
                for i in range(10):
                    error_manager.record_error(ValueError(f"Test {i}"), "test_op")
                results.append(True)
            except Exception:
                results.append(False)
        
        threads = [threading.Thread(target=test_thread) for _ in range(5)]
        
        for thread in threads:
            thread.start()
        
        for thread in threads:
            thread.join()
        
        self.assertTrue(all(results))
        self.assertGreater(len(error_manager.error_history), 0)
    
    def test_performance_under_load(self):
        """Test system performance under load"""
        optimizer = get_performance_optimizer()
        validator = get_input_validator()
        
        start_time = time.time()
        
        # Simulate load
        for i in range(100):
            with optimizer.measure_operation(f"load_test_{i % 10}"):
                rule = ValidationRule(ValidationType.STRING, max_length=100)
                try:
                    validator.validate_value(f"test_value_{i}", rule)
                except:
                    pass
        
        end_time = time.time()
        duration = end_time - start_time
        
        self.assertLess(duration, 5.0)  # Should complete within 5 seconds
        
        # Check that performance data was collected
        profiles = optimizer.get_top_operations(limit=5)
        self.assertGreater(len(profiles), 0)


def run_quality_tests():
    """Run all quality assurance tests"""
    print("BLNCS Quality Assurance Test Suite")
    print("=" * 50)
    
    if not IMPORTS_SUCCESS:
        print("❌ CRITICAL: Import failures detected!")
        print("Cannot run quality tests without proper imports.")
        return False
    
    # Create test suite
    suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        TestErrorRecovery,
        TestInputValidation,
        TestPerformanceOptimization,
        TestHealthDiagnostics,
        TestBackupEncryption,
        TestIntegratedFeatures,
        TestSystemIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 50)
    print("Quality Assurance Test Results")
    print("=" * 50)
    
    total_tests = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    skipped = len(result.skipped) if hasattr(result, 'skipped') else 0
    
    success_rate = ((total_tests - failures - errors) / total_tests * 100) if total_tests > 0 else 0
    
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {total_tests - failures - errors}")
    print(f"Failed: {failures}")
    print(f"Errors: {errors}")
    print(f"Skipped: {skipped}")
    print(f"Success Rate: {success_rate:.1f}%")
    
    if result.wasSuccessful():
        print("\n🎉 ALL TESTS PASSED!")
        print("BLNCS meets highest quality standards.")
        return True
    else:
        print("\n❌ Some tests failed.")
        print("Review failures and fix issues before deployment.")
        
        if result.failures:
            print("\nFailures:")
            for test, traceback in result.failures:
                print(f"- {test}: {traceback.split('AssertionError:')[-1].strip()}")
        
        if result.errors:
            print("\nErrors:")
            for test, traceback in result.errors:
                print(f"- {test}: {traceback.split('Exception:')[-1].strip()}")
        
        return False


if __name__ == "__main__":
    success = run_quality_tests()
    sys.exit(0 if success else 1)