"""
Production-Grade Comprehensive Test Suite
Enterprise-level testing framework for BLNCS
"""

import unittest
import asyncio
import json
import time
import tempfile
import shutil
import threading
from datetime import datetime, timedelta
from pathlib import Path
import sys
import os
import sqlite3
from unittest.mock import Mock, patch, MagicMock
from dataclasses import dataclass
from typing import Dict, List, Any, Optional

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from blncs.core.production_security import SecurityManager, PasswordValidator, EncryptionManager
    from blncs.core.production_performance import ProductionPerformanceManager
    from blncs.core.production_stability import ProductionStabilityManager, CircuitBreaker, CircuitBreakerConfig
    from blncs.monitoring.production_monitoring import ProductionMonitoringSystem
    from blncs.api.production_api import ProductionAPI, APIResponse, APIError
    IMPORTS_OK = True
except ImportError as e:
    print(f"⚠️  Import warning: {e}")
    IMPORTS_OK = False


@dataclass
class TestResult:
    """Test result structure"""
    test_name: str
    success: bool
    duration_ms: float
    error_message: Optional[str] = None
    details: Dict[str, Any] = None


class PerformanceTestCase(unittest.TestCase):
    """Base class for performance testing"""

    def assertResponseTime(self, func, max_time_ms: float, *args, **kwargs):
        """Assert that function executes within specified time"""
        start_time = time.time()
        result = func(*args, **kwargs)
        duration_ms = (time.time() - start_time) * 1000

        self.assertLessEqual(
            duration_ms, max_time_ms,
            f"Function took {duration_ms:.2f}ms, expected <= {max_time_ms}ms"
        )
        return result

    def assertThroughput(self, func, min_ops_per_second: float, duration_seconds: int = 1):
        """Assert minimum throughput for a function"""
        start_time = time.time()
        operations = 0

        while time.time() - start_time < duration_seconds:
            func()
            operations += 1

        actual_throughput = operations / duration_seconds
        self.assertGreaterEqual(
            actual_throughput, min_ops_per_second,
            f"Throughput {actual_throughput:.2f} ops/sec, expected >= {min_ops_per_second} ops/sec"
        )


class SecurityTestCase(unittest.TestCase):
    """Security testing suite"""

    def setUp(self):
        """Setup security test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.security_manager = SecurityManager()

    def tearDown(self):
        """Cleanup security test environment"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    @unittest.skipUnless(IMPORTS_OK, "Security imports not available")
    def test_password_validation(self):
        """Test password validation functionality"""
        validator = PasswordValidator(self.security_manager.policy)

        # Test strong password
        strong_password = "StrongP@ssw0rd123!"
        is_valid, errors = validator.validate(strong_password)
        self.assertTrue(is_valid, f"Strong password should be valid: {errors}")

        # Test weak passwords
        weak_passwords = [
            "password",  # Too common
            "123456",    # Too simple
            "short",     # Too short
            "nouppercase123!",  # No uppercase
            "NOLOWERCASE123!",  # No lowercase
            "NoNumbers!",       # No numbers
            "NoSymbols123"      # No symbols
        ]

        for weak_password in weak_passwords:
            is_valid, errors = validator.validate(weak_password)
            self.assertFalse(is_valid, f"Weak password should be invalid: {weak_password}")

    @unittest.skipUnless(IMPORTS_OK, "Security imports not available")
    def test_encryption_decryption(self):
        """Test data encryption and decryption"""
        # Create encryption manager with test key
        test_key_file = os.path.join(self.temp_dir, "test_encryption.key")
        with patch.dict(os.environ, {'BLNCS_ENCRYPTION_KEY_FILE': test_key_file}):
            encryption = EncryptionManager()

            # Test string encryption
            original_data = "Sensitive information that needs protection"
            encrypted_data = encryption.encrypt(original_data)
            decrypted_data = encryption.decrypt(encrypted_data)

            self.assertEqual(original_data, decrypted_data)
            self.assertNotEqual(original_data, encrypted_data)

            # Test dictionary encryption
            original_dict = {
                "username": "testuser",
                "email": "test@example.com",
                "sensitive_data": "secret_information"
            }

            encrypted_dict = encryption.encrypt_dict(original_dict)
            decrypted_dict = encryption.decrypt_dict(encrypted_dict)

            self.assertEqual(original_dict, decrypted_dict)

    @unittest.skipUnless(IMPORTS_OK, "Security imports not available")
    def test_session_management(self):
        """Test secure session management"""
        user_id = "test_user"
        source_ip = "192.168.1.100"

        # Create session
        session_data = self.security_manager.create_secure_session(user_id, source_ip)

        self.assertIsNotNone(session_data)
        self.assertEqual(session_data['user_id'], user_id)
        self.assertEqual(session_data['source_ip'], source_ip)

        # Validate session
        session_id = session_data['session_id']
        is_valid = self.security_manager.validate_session(session_id, source_ip)
        self.assertTrue(is_valid)

        # Test invalid IP
        is_valid_wrong_ip = self.security_manager.validate_session(session_id, "192.168.1.200")
        self.assertFalse(is_valid_wrong_ip)

    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        identifier = "test_user"
        action = "login"
        max_attempts = 3
        window_minutes = 1

        # First attempts should succeed
        for i in range(max_attempts):
            allowed = self.security_manager.check_rate_limit(
                identifier, action, max_attempts, window_minutes
            )
            self.assertTrue(allowed, f"Attempt {i+1} should be allowed")

        # Subsequent attempt should be blocked
        blocked = self.security_manager.check_rate_limit(
            identifier, action, max_attempts, window_minutes
        )
        self.assertFalse(blocked, "Rate limit should be exceeded")


class PerformanceTestSuite(PerformanceTestCase):
    """Performance testing suite"""

    def setUp(self):
        """Setup performance test environment"""
        self.performance_manager = ProductionPerformanceManager() if IMPORTS_OK else None

    @unittest.skipUnless(IMPORTS_OK, "Performance imports not available")
    def test_memory_optimization_performance(self):
        """Test memory optimization performance"""
        def optimize_memory():
            return self.performance_manager.memory_optimizer.optimize_memory()

        # Memory optimization should complete within 5 seconds
        result = self.assertResponseTime(optimize_memory, 5000)
        self.assertTrue(result.applied)
        self.assertGreaterEqual(result.improvement_percent, 0)

    @unittest.skipUnless(IMPORTS_OK, "Performance imports not available")
    def test_cpu_optimization_performance(self):
        """Test CPU optimization performance"""
        def optimize_cpu():
            return self.performance_manager.cpu_optimizer.optimize_cpu()

        # CPU optimization should complete within 2 seconds
        result = self.assertResponseTime(optimize_cpu, 2000)
        self.assertTrue(result.applied)

    @unittest.skipUnless(IMPORTS_OK, "Performance imports not available")
    def test_monitoring_overhead(self):
        """Test performance monitoring overhead"""
        def collect_metrics():
            return self.performance_manager.monitor.collect_metrics()

        # Metrics collection should be very fast (< 100ms)
        metrics = self.assertResponseTime(collect_metrics, 100)
        self.assertIsNotNone(metrics)

        # Should handle high frequency collection
        self.assertThroughput(collect_metrics, 10)  # At least 10 collections per second


class StabilityTestSuite(unittest.TestCase):
    """Stability and resilience testing suite"""

    def setUp(self):
        """Setup stability test environment"""
        self.stability_manager = ProductionStabilityManager() if IMPORTS_OK else None

    @unittest.skipUnless(IMPORTS_OK, "Stability imports not available")
    def test_circuit_breaker_functionality(self):
        """Test circuit breaker pattern"""
        config = CircuitBreakerConfig(
            failure_threshold=3,
            timeout_seconds=1,
            success_threshold=2
        )
        circuit_breaker = CircuitBreaker("test_service", config)

        # Mock function that fails
        call_count = 0
        def failing_function():
            nonlocal call_count
            call_count += 1
            if call_count <= 3:
                raise Exception("Service unavailable")
            return "success"

        # Test initial failures
        for i in range(3):
            with self.assertRaises(Exception):
                circuit_breaker.call(failing_function)

        # Circuit breaker should now be OPEN
        from blncs.core.production_stability import CircuitBreakerState, CircuitBreakerOpenError
        self.assertEqual(circuit_breaker.state, CircuitBreakerState.OPEN)

        # Should reject calls when OPEN
        with self.assertRaises(CircuitBreakerOpenError):
            circuit_breaker.call(failing_function)

        # Wait for timeout
        time.sleep(1.1)

        # Should transition to HALF_OPEN and eventually CLOSED
        result = circuit_breaker.call(failing_function)
        self.assertEqual(result, "success")

    @unittest.skipUnless(IMPORTS_OK, "Stability imports not available")
    def test_error_recovery_system(self):
        """Test automatic error recovery"""
        recovery_manager = self.stability_manager.error_recovery

        # Register a mock recovery strategy
        recovery_called = False
        def mock_recovery(error, context):
            nonlocal recovery_called
            recovery_called = True
            return True

        recovery_manager.register_recovery_strategy("ValueError", mock_recovery)

        # Test error handling with recovery
        test_error = ValueError("Test error")
        success = recovery_manager.handle_error(test_error, {"component": "test"})

        self.assertTrue(success)
        self.assertTrue(recovery_called)

    @unittest.skipUnless(IMPORTS_OK, "Stability imports not available")
    def test_health_monitoring(self):
        """Test health monitoring system"""
        health_monitor = self.stability_manager.health_monitor

        # Register a test health check
        check_called = False
        def test_health_check():
            nonlocal check_called
            check_called = True
            return {"status": "healthy"}

        from blncs.core.production_stability import HealthCheck
        health_check = HealthCheck(
            name="test_check",
            check_function=test_health_check,
            interval_seconds=1,
            timeout_seconds=5
        )

        health_monitor.register_health_check(health_check)

        # Run health checks manually
        health_monitor._run_health_checks()

        # Verify check was called
        self.assertTrue(check_called)

        # Verify health status
        status = health_monitor.get_health_status()
        self.assertIn("test_check", status["health_checks"])


class APITestSuite(unittest.TestCase):
    """API functionality testing suite"""

    def setUp(self):
        """Setup API test environment"""
        if IMPORTS_OK:
            self.app_config = {
                'SECRET_KEY': 'test-secret-key',
                'TESTING': True,
                'DEBUG': True
            }
            self.api = ProductionAPI(self.app_config)
            self.client = self.api.app.test_client()

    @unittest.skipUnless(IMPORTS_OK, "API imports not available")
    def test_health_endpoint(self):
        """Test health check endpoint"""
        response = self.client.get('/health')

        self.assertEqual(response.status_code, 200)

        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertIn('data', data)
        self.assertEqual(data['data']['status'], 'healthy')

    @unittest.skipUnless(IMPORTS_OK, "API imports not available")
    def test_authentication_required(self):
        """Test that protected endpoints require authentication"""
        # Try to access protected endpoint without auth
        response = self.client.get('/api/v1/system/metrics')

        self.assertEqual(response.status_code, 401)

        data = json.loads(response.data)
        self.assertFalse(data['success'])
        self.assertEqual(data['error_code'], 'AUTHENTICATION_FAILED')

    @unittest.skipUnless(IMPORTS_OK, "API imports not available")
    def test_login_functionality(self):
        """Test login endpoint"""
        # Valid credentials
        login_data = {
            'username': 'admin',
            'password': 'secure_password'
        }

        response = self.client.post(
            '/api/v1/auth/login',
            json=login_data,
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)

        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertIn('token', data['data'])

    @unittest.skipUnless(IMPORTS_OK, "API imports not available")
    def test_input_validation(self):
        """Test API input validation"""
        # Invalid JSON data for invoice creation
        invalid_data = {
            'amount': -100,  # Invalid negative amount
            'memo': 'x' * 2000  # Too long memo
        }

        # First login to get token
        login_response = self.client.post(
            '/api/v1/auth/login',
            json={'username': 'admin', 'password': 'secure_password'},
            content_type='application/json'
        )

        token = json.loads(login_response.data)['data']['token']

        # Try to create invoice with invalid data
        response = self.client.post(
            '/api/v1/lightning/invoices',
            json=invalid_data,
            headers={'Authorization': f'Bearer {token}'},
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)

        data = json.loads(response.data)
        self.assertFalse(data['success'])
        self.assertEqual(data['error_code'], 'VALIDATION_ERROR')

    @unittest.skipUnless(IMPORTS_OK, "API imports not available")
    def test_rate_limiting(self):
        """Test API rate limiting"""
        # Make multiple rapid requests to rate-limited endpoint
        for i in range(6):  # Exceed the 5 per minute limit
            response = self.client.post(
                '/api/v1/auth/login',
                json={'username': 'admin', 'password': 'wrong_password'},
                content_type='application/json'
            )

            if i >= 5:  # Should be rate limited
                self.assertEqual(response.status_code, 429)


class IntegrationTestSuite(unittest.TestCase):
    """Integration testing suite"""

    def setUp(self):
        """Setup integration test environment"""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Cleanup integration test environment"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    @unittest.skipUnless(IMPORTS_OK, "Integration imports not available")
    def test_full_system_integration(self):
        """Test full system integration"""
        # Initialize all managers
        security_manager = SecurityManager()
        performance_manager = ProductionPerformanceManager()
        stability_manager = ProductionStabilityManager()
        monitoring_system = ProductionMonitoringSystem()

        # Start monitoring systems
        monitoring_system.start_monitoring()
        stability_manager.start_monitoring()

        try:
            # Test security integration
            session = security_manager.create_secure_session("test_user", "127.0.0.1")
            self.assertIsNotNone(session)

            # Test performance optimization
            optimization_results = performance_manager.optimize_all()
            self.assertGreater(len(optimization_results), 0)

            # Test stability monitoring
            stability_report = stability_manager.get_stability_report()
            self.assertIn("system_state", stability_report)

            # Test monitoring data collection
            monitoring_status = monitoring_system.get_monitoring_status()
            self.assertTrue(monitoring_status["monitoring_active"])

        finally:
            # Clean up
            monitoring_system.stop_monitoring()
            stability_manager.stop_monitoring()

    def test_database_integration(self):
        """Test database integration"""
        # Create test database
        db_path = os.path.join(self.temp_dir, "test.db")

        # Test database operations
        with sqlite3.connect(db_path) as conn:
            # Create test table
            conn.execute("""
                CREATE TABLE test_payments (
                    id INTEGER PRIMARY KEY,
                    amount INTEGER,
                    memo TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Insert test data
            conn.execute(
                "INSERT INTO test_payments (amount, memo) VALUES (?, ?)",
                (1000, "Test payment")
            )

            # Query test data
            cursor = conn.execute("SELECT * FROM test_payments")
            rows = cursor.fetchall()

            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0][1], 1000)  # amount
            self.assertEqual(rows[0][2], "Test payment")  # memo


class LoadTestSuite(PerformanceTestCase):
    """Load testing suite"""

    @unittest.skipUnless(IMPORTS_OK, "Load test imports not available")
    def test_concurrent_api_requests(self):
        """Test concurrent API request handling"""
        if not IMPORTS_OK:
            self.skipTest("API imports not available")

        app_config = {
            'SECRET_KEY': 'test-secret-key',
            'TESTING': True
        }
        api = ProductionAPI(app_config)
        client = api.app.test_client()

        # Function to make health check requests
        def make_request():
            response = client.get('/health')
            return response.status_code == 200

        # Test concurrent requests
        import concurrent.futures

        success_count = 0
        total_requests = 50

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(total_requests)]

            for future in concurrent.futures.as_completed(futures):
                if future.result():
                    success_count += 1

        # Should handle at least 90% of concurrent requests successfully
        success_rate = success_count / total_requests
        self.assertGreaterEqual(success_rate, 0.9)

    def test_memory_usage_under_load(self):
        """Test memory usage under load"""
        import psutil
        import gc

        process = psutil.Process()
        initial_memory = process.memory_info().rss

        # Simulate load by creating and processing data
        for i in range(1000):
            # Create some data structures
            data = [f"test_data_{j}" for j in range(100)]
            result = sum(len(item) for item in data)

            # Periodic cleanup
            if i % 100 == 0:
                gc.collect()

        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory

        # Memory increase should be reasonable (< 50MB)
        self.assertLess(memory_increase, 50 * 1024 * 1024)


class ProductionTestRunner:
    """Production test runner with comprehensive reporting"""

    def __init__(self):
        self.test_results = []
        self.start_time = None
        self.end_time = None

    def run_all_tests(self):
        """Run all test suites"""
        self.start_time = datetime.now()

        test_suites = [
            ('Security Tests', SecurityTestCase),
            ('Performance Tests', PerformanceTestSuite),
            ('Stability Tests', StabilityTestSuite),
            ('API Tests', APITestSuite),
            ('Integration Tests', IntegrationTestSuite),
            ('Load Tests', LoadTestSuite)
        ]

        for suite_name, test_class in test_suites:
            print(f"\n{'='*50}")
            print(f"Running {suite_name}")
            print(f"{'='*50}")

            suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
            runner = unittest.TextTestRunner(verbosity=2)
            result = runner.run(suite)

            self.test_results.append({
                'suite_name': suite_name,
                'tests_run': result.testsRun,
                'failures': len(result.failures),
                'errors': len(result.errors),
                'skipped': len(result.skipped),
                'success_rate': (result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun if result.testsRun > 0 else 0
            })

        self.end_time = datetime.now()
        self.generate_report()

    def generate_report(self):
        """Generate comprehensive test report"""
        duration = self.end_time - self.start_time

        print(f"\n{'='*60}")
        print("PRODUCTION TEST SUITE SUMMARY")
        print(f"{'='*60}")
        print(f"Total Duration: {duration}")
        print(f"Test Suites: {len(self.test_results)}")

        total_tests = sum(r['tests_run'] for r in self.test_results)
        total_failures = sum(r['failures'] for r in self.test_results)
        total_errors = sum(r['errors'] for r in self.test_results)
        total_skipped = sum(r['skipped'] for r in self.test_results)

        overall_success_rate = (total_tests - total_failures - total_errors) / total_tests if total_tests > 0 else 0

        print(f"\nOverall Results:")
        print(f"  Total Tests: {total_tests}")
        print(f"  Passed: {total_tests - total_failures - total_errors}")
        print(f"  Failed: {total_failures}")
        print(f"  Errors: {total_errors}")
        print(f"  Skipped: {total_skipped}")
        print(f"  Success Rate: {overall_success_rate:.1%}")

        print(f"\nDetailed Results:")
        for result in self.test_results:
            print(f"  {result['suite_name']}: "
                  f"{result['tests_run']} tests, "
                  f"{result['success_rate']:.1%} success rate")

        # Generate JSON report
        report_data = {
            'summary': {
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat(),
                'duration_seconds': duration.total_seconds(),
                'total_tests': total_tests,
                'total_failures': total_failures,
                'total_errors': total_errors,
                'total_skipped': total_skipped,
                'overall_success_rate': overall_success_rate
            },
            'suites': self.test_results
        }

        # Save report
        report_path = f"test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)

        print(f"\nDetailed report saved to: {report_path}")

        # Determine overall result
        if total_failures == 0 and total_errors == 0:
            print("\n🎉 ALL TESTS PASSED!")
            return True
        else:
            print("\n❌ Some tests failed. Review the results above.")
            return False


if __name__ == '__main__':
    # Run production test suite
    runner = ProductionTestRunner()
    success = runner.run_all_tests()

    # Exit with appropriate code
    sys.exit(0 if success else 1)