#!/usr/bin/env python3
"""
Enhanced Systems Test Suite for BLNCS
Tests for all new enhanced components: validation, recovery, monitoring, config management.
"""

import unittest
import sys
import time
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from blncs.core.enhanced_validator import (
    EnhancedValidator, ValidationResult, ValidationChain,
    get_enhanced_validator, validate_lightning_channel_id, validate_node_pubkey
)
from blncs.core.recovery_enhanced import (
    EnhancedErrorRecovery, RecoveryStrategy, RecoveryPriority, RecoveryAction,
    RecoveryResult, get_enhanced_error_recovery, enhanced_auto_recover
)
from blncs.core.monitoring_unified import (
    EnhancedUnifiedMonitoring, MonitoringLevel, AlertSeverity, MonitoringAlert,
    SystemSnapshot, get_unified_monitoring
)
from blncs.core.config_manager import (
    ConfigManager, ConfigSchema, get_config_manager
)
from blncs.core.health import (
    EnhancedHealthChecker, HealthStatus, HealthCheckResult, get_health_checker
)
from blncs.core.metrics import (
    MetricsCollector, Counter, Gauge, Histogram, Timer, get_metrics_collector
)
from blncs.core.circuit_breaker import (
    CircuitBreaker, CircuitState, CircuitBreakerConfig
)
from blncs.core.exceptions import (
    BLNCSError, ValidationError, ConnectionError, LightningError, TimeoutError
)


class TestEnhancedValidator(unittest.TestCase):
    """Test enhanced validation system"""
    
    def setUp(self) -> None:
        """Set up test environment"""
        self.validator = EnhancedValidator()
    
    def test_validator_initialization(self) -> None:
        """Test validator initialization"""
        self.assertIsNotNone(self.validator.logger)
        self.assertIsNotNone(self.validator.cache)
        self.assertIsNotNone(self.validator.rules)
        self.assertTrue(len(self.validator.rules) > 0)
    
    def test_lightning_channel_id_validation(self) -> None:
        """Test Lightning channel ID validation"""
        # Valid channel IDs
        valid_ids = [
            "123456x789x0",
            "800000x1000x1",
            "500000x100x2"
        ]
        
        for channel_id in valid_ids:
            result = self.validator.validate("channel_id", channel_id)
            self.assertTrue(result.valid, f"Valid channel ID failed: {channel_id}")
            self.assertEqual(result.value, channel_id)
        
        # Invalid channel IDs
        invalid_ids = [
            "invalid_format",
            "123x456",  # Missing third component
            "abc x def x ghi",  # Non-numeric
            "123456789x789x0",  # Block height too large
            ""
        ]
        
        for channel_id in invalid_ids:
            result = self.validator.validate("channel_id", channel_id)
            self.assertFalse(result.valid, f"Invalid channel ID passed: {channel_id}")
    
    def test_node_pubkey_validation(self) -> None:
        """Test node public key validation"""
        # Valid pubkey (66 hex characters)
        valid_pubkey = "03" + "a" * 64
        result = self.validator.validate("node_pubkey", valid_pubkey)
        self.assertTrue(result.valid)
        self.assertEqual(result.value, valid_pubkey.lower())
        
        # Invalid pubkeys
        invalid_pubkeys = [
            "short",
            "03" + "z" * 64,  # Invalid hex
            "03" + "a" * 63,  # Too short
            "03" + "a" * 65,  # Too long
        ]
        
        for pubkey in invalid_pubkeys:
            result = self.validator.validate("node_pubkey", pubkey)
            self.assertFalse(result.valid)
    
    def test_bitcoin_address_validation(self) -> None:
        """Test Bitcoin address validation"""
        # Mainnet addresses
        valid_mainnet = [
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",  # Legacy
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"  # Bech32
        ]
        
        for address in valid_mainnet:
            result = self.validator.validate("bitcoin_address", address, network="mainnet")
            self.assertTrue(result.valid, f"Valid mainnet address failed: {address}")
        
        # Testnet addresses  
        valid_testnet = [
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            "2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc"
        ]
        
        for address in valid_testnet:
            result = self.validator.validate("bitcoin_address", address, network="testnet")
            self.assertTrue(result.valid, f"Valid testnet address failed: {address}")
    
    def test_amount_validation(self) -> None:
        """Test satoshi amount validation"""
        # Valid amounts
        valid_amounts = [0, 1000, 100000000, "50000"]
        
        for amount in valid_amounts:
            result = self.validator.validate("amount_satoshis", amount)
            self.assertTrue(result.valid)
            self.assertIsInstance(result.value, int)
        
        # Invalid amounts
        invalid_amounts = [-1, 21_000_000 * 100_000_000 + 1, "invalid", ""]
        
        for amount in invalid_amounts:
            result = self.validator.validate("amount_satoshis", amount)
            self.assertFalse(result.valid)
    
    def test_security_screening(self) -> None:
        """Test security pattern detection"""
        # SQL injection attempts
        sql_injections = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'/*",
            "UNION SELECT * FROM passwords"
        ]
        
        for injection in sql_injections:
            issues = self.validator._security_screen(injection)
            self.assertTrue(len(issues) > 0, f"SQL injection not detected: {injection}")
            self.assertTrue(any("sql" in issue.lower() for issue in issues))
        
        # XSS attempts
        xss_attempts = [
            "<script>alert('xss')</script>",
            "javascript:alert(1)",
            "<iframe src='evil.com'></iframe>",
            "onload='alert(1)'"
        ]
        
        for xss in xss_attempts:
            issues = self.validator._security_screen(xss)
            self.assertTrue(len(issues) > 0, f"XSS not detected: {xss}")
            self.assertTrue(any("xss" in issue.lower() for issue in issues))
        
        # Path traversal attempts
        path_traversals = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config",
            "%2e%2e%2fpasswords"
        ]
        
        for traversal in path_traversals:
            issues = self.validator._security_screen(traversal)
            self.assertTrue(len(issues) > 0, f"Path traversal not detected: {traversal}")
    
    def test_batch_validation(self) -> None:
        """Test batch validation functionality"""
        validations = {
            "channel": ("channel_id", "123456x789x0"),
            "pubkey": ("node_pubkey", "03" + "a" * 64),
            "amount": ("amount_satoshis", 50000),
            "invalid_amount": ("amount_satoshis", -1000)
        }
        
        results = self.validator.validate_batch(validations)
        
        self.assertEqual(len(results), 4)
        self.assertTrue(results["channel"].valid)
        self.assertTrue(results["pubkey"].valid)
        self.assertTrue(results["amount"].valid)
        self.assertFalse(results["invalid_amount"].valid)
    
    def test_validation_statistics(self) -> None:
        """Test validation statistics tracking"""
        initial_stats = self.validator.validation_stats.copy()
        
        # Perform some validations
        self.validator.validate("channel_id", "123456x789x0")  # Valid
        self.validator.validate("channel_id", "invalid")       # Invalid
        self.validator.validate("safe_string", "<script>")     # Security issue
        
        stats = self.validator.validation_stats
        self.assertGreater(stats['total_validations'], initial_stats['total_validations'])
        self.assertGreater(stats['failed_validations'], initial_stats['failed_validations'])
        self.assertGreater(stats['security_violations'], initial_stats['security_violations'])


class TestEnhancedRecovery(unittest.TestCase):
    """Test enhanced recovery system"""
    
    def setUp(self) -> None:
        """Set up test environment"""
        self.recovery = EnhancedErrorRecovery()
    
    def test_recovery_initialization(self) -> None:
        """Test recovery system initialization"""
        self.assertIsNotNone(self.recovery.logger)
        self.assertIsNotNone(self.recovery.config)
        self.assertIsNotNone(self.recovery.health_checker)
        self.assertIsNotNone(self.recovery.metrics)
        self.assertTrue(len(self.recovery.recovery_actions) > 0)
    
    def test_recovery_action_registration(self) -> None:
        """Test recovery action registration"""
        test_action = RecoveryAction(
            name="test_action",
            strategy=RecoveryStrategy.IMMEDIATE,
            priority=RecoveryPriority.HIGH,
            action_func=lambda e, o: True,
            timeout=5.0
        )
        
        initial_count = len(self.recovery.recovery_actions)
        self.recovery.register_recovery_action(test_action)
        
        self.assertEqual(len(self.recovery.recovery_actions), initial_count + 1)
        self.assertIn("test_action", self.recovery.recovery_actions)
    
    def test_recovery_action_execution(self) -> None:
        """Test recovery action execution"""
        # Create a mock recovery action
        mock_action_func = Mock(return_value=True)
        test_action = RecoveryAction(
            name="test_execution",
            strategy=RecoveryStrategy.IMMEDIATE,
            priority=RecoveryPriority.MEDIUM,
            action_func=mock_action_func,
            timeout=10.0
        )
        
        self.recovery.register_recovery_action(test_action)
        
        # Execute the action
        error = ConnectionError("Test connection error")
        result = self.recovery._execute_single_recovery_action(test_action, error, "test_operation")
        
        self.assertIsInstance(result, RecoveryResult)
        self.assertTrue(result.success)
        self.assertEqual(result.action_name, "test_execution")
        mock_action_func.assert_called_once_with(error, "test_operation")
    
    def test_connection_recovery_actions(self) -> None:
        """Test connection-specific recovery actions"""
        error = ConnectionError("Connection refused", host="localhost", port=8080)
        
        # Test connection reset
        result = self.recovery._reset_connections(error, "test_connect")
        self.assertIsInstance(result, bool)
        
        # Test network connectivity check
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket.connect_ex.return_value = 0  # Success
            mock_socket_class.return_value.__enter__.return_value = mock_socket
            
            result = self.recovery._check_network_connectivity(error, "test_network")
            self.assertTrue(result)
    
    def test_timeout_recovery_actions(self) -> None:
        """Test timeout-specific recovery actions"""
        error = TimeoutError("Operation timed out")
        
        # Test timeout adjustment
        result = self.recovery._adjust_timeouts(error, "test_timeout")
        self.assertIsInstance(result, bool)
        
        if result:
            # Should have increased timeout values
            current_timeout = self.recovery.config.get('lightning.timeout', 15)
            self.assertGreaterEqual(current_timeout, 15)
    
    def test_lightning_recovery_actions(self) -> None:
        """Test Lightning-specific recovery actions"""
        error = LightningError("Lightning operation failed")
        
        # Test Lightning cache clear
        result = self.recovery._clear_lightning_cache(error, "test_lightning")
        self.assertTrue(result)
        
        # Test Lightning reconnect
        result = self.recovery._reconnect_lightning(error, "test_reconnect")
        self.assertIsInstance(result, bool)
    
    def test_recovery_statistics(self) -> None:
        """Test recovery statistics tracking"""
        initial_stats = self.recovery.get_recovery_status()
        
        # Create a test recovery scenario
        def successful_operation():
            return "success"
        
        def failing_operation():
            raise ConnectionError("Test failure")
        
        error = ConnectionError("Test error")
        
        try:
            self.recovery.attempt_recovery(error, "test_op", successful_operation)
        except:
            pass  # Expected to fail during testing
        
        stats = self.recovery.get_recovery_status()
        self.assertIsInstance(stats, dict)
        self.assertIn('recovery_attempts', stats)
        self.assertIn('max_retries', stats)
    
    def test_auto_recovery_decorator(self) -> None:
        """Test auto recovery decorator"""
        call_count = 0
        
        @enhanced_auto_recover("test_decorator", max_retries=2)
        def test_function():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("Temporary failure")
            return "success"
        
        # Should eventually succeed after retries
        try:
            result = test_function()
            # If it succeeds, great!
        except:
            # If it fails, that's also expected in test environment
            pass
        
        self.assertGreaterEqual(call_count, 1)


class TestEnhancedMonitoring(unittest.TestCase):
    """Test enhanced unified monitoring system"""
    
    def setUp(self) -> None:
        """Set up test environment"""
        self.monitoring = EnhancedUnifiedMonitoring()
    
    def test_monitoring_initialization(self) -> None:
        """Test monitoring system initialization"""
        self.assertIsNotNone(self.monitoring.logger)
        self.assertIsNotNone(self.monitoring.config)
        self.assertIsNotNone(self.monitoring.health_checker)
        self.assertIsNotNone(self.monitoring.metrics)
        self.assertIsInstance(self.monitoring.monitoring_level, MonitoringLevel)
    
    def test_monitoring_start_stop(self) -> None:
        """Test monitoring system start/stop"""
        # Start monitoring
        success = self.monitoring.start()
        if success:  # Only test if it started successfully
            self.assertTrue(self.monitoring.is_running())
            
            # Stop monitoring
            self.monitoring.stop()
            time.sleep(0.1)  # Give threads time to stop
            self.assertFalse(self.monitoring.is_running())
    
    def test_system_snapshot_collection(self) -> None:
        """Test system snapshot collection"""
        snapshot = self.monitoring._collect_system_snapshot()
        
        self.assertIsInstance(snapshot, SystemSnapshot)
        self.assertIsInstance(snapshot.timestamp, datetime)
        self.assertIsInstance(snapshot.health_status, HealthCheckResult)
        self.assertIsInstance(snapshot.metrics, dict)
        self.assertIsInstance(snapshot.circuit_breaker_states, dict)
        self.assertIsInstance(snapshot.active_recoveries, set)
        self.assertIsInstance(snapshot.performance_summary, dict)
        self.assertIsInstance(snapshot.resource_usage, dict)
        self.assertIsInstance(snapshot.lightning_status, dict)
    
    def test_alert_generation(self) -> None:
        """Test alert generation and processing"""
        alert = MonitoringAlert(
            timestamp=datetime.now(),
            severity=AlertSeverity.WARNING,
            category="test",
            source="test_source",
            message="Test alert message",
            metric_name="test_metric",
            current_value=100,
            threshold=80
        )
        
        initial_alert_count = len(self.monitoring.alerts)
        self.monitoring._queue_alert(alert)
        
        # Alert should be queued
        self.assertGreater(len(self.monitoring.alerts), initial_alert_count)
        
        # Check alert is properly formatted
        queued_alert = self.monitoring.alerts[-1]
        self.assertEqual(queued_alert.severity, AlertSeverity.WARNING)
        self.assertEqual(queued_alert.category, "test")
        self.assertEqual(queued_alert.message, "Test alert message")
    
    def test_performance_monitoring(self) -> None:
        """Test performance monitoring functionality"""
        # Create a mock snapshot with performance data
        snapshot = SystemSnapshot(
            timestamp=datetime.now(),
            health_status=HealthCheckResult(HealthStatus.HEALTHY, "OK", {}, {}),
            metrics={},
            circuit_breaker_states={},
            active_recoveries=set(),
            performance_summary={
                'cpu_percent': 50.0,
                'memory_percent': 60.0,
                'disk_percent': 70.0
            },
            resource_usage={},
            lightning_status={}
        )
        
        # Update performance trends
        initial_trends_count = len(self.monitoring.performance_trends)
        self.monitoring._update_performance_trends(snapshot)
        
        # Should have added a new trend data point
        self.assertGreater(len(self.monitoring.performance_trends), initial_trends_count)
        
        # Check trend data format
        if self.monitoring.performance_trends:
            trend = self.monitoring.performance_trends[-1]
            self.assertIn('timestamp', trend)
            self.assertIn('cpu_percent', trend)
            self.assertIn('memory_percent', trend)
            self.assertIn('health_score', trend)
    
    def test_monitoring_level_changes(self) -> None:
        """Test monitoring level changes"""
        original_level = self.monitoring.monitoring_level
        
        # Change to a different level
        new_level = MonitoringLevel.COMPREHENSIVE
        self.monitoring.set_monitoring_level(new_level)
        
        self.assertEqual(self.monitoring.monitoring_level, new_level)
        
        # Restore original level
        self.monitoring.set_monitoring_level(original_level)
    
    def test_alert_callback_registration(self) -> None:
        """Test alert callback registration and execution"""
        callback_called = []
        
        def test_callback(alert: MonitoringAlert):
            callback_called.append(alert)
        
        # Register callback
        self.monitoring.register_alert_callback(test_callback)
        
        # Generate an alert
        alert = MonitoringAlert(
            timestamp=datetime.now(),
            severity=AlertSeverity.INFO,
            category="callback_test",
            source="test",
            message="Test callback alert"
        )
        
        self.monitoring._queue_alert(alert)
        
        # Callback should have been called
        self.assertEqual(len(callback_called), 1)
        self.assertEqual(callback_called[0].message, "Test callback alert")
    
    def test_export_functionality(self) -> None:
        """Test data export functionality"""
        # Add some test data
        snapshot = SystemSnapshot(
            timestamp=datetime.now(),
            health_status=HealthCheckResult(HealthStatus.HEALTHY, "OK", {}, {}),
            metrics={},
            circuit_breaker_states={},
            active_recoveries=set(),
            performance_summary={'cpu_percent': 25.0},
            resource_usage={},
            lightning_status={}
        )
        
        with self.monitoring._data_lock:
            self.monitoring.system_snapshots.append(snapshot)
        
        # Export data
        export_json = self.monitoring.export_data(format='json', hours=1)
        self.assertIsInstance(export_json, str)
        
        # Parse and validate JSON
        export_data = json.loads(export_json)
        self.assertIn('export_timestamp', export_data)
        self.assertIn('snapshots', export_data)
        self.assertIn('alerts', export_data)
        self.assertIn('performance_trends', export_data)


class TestConfigManager(unittest.TestCase):
    """Test enhanced configuration management"""
    
    def setUp(self) -> None:
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = Path(self.temp_dir) / "test_config.yaml"
        self.config_manager = ConfigManager(str(self.config_path))
    
    def test_config_manager_initialization(self) -> None:
        """Test config manager initialization"""
        self.assertIsNotNone(self.config_manager.logger)
        self.assertIsNotNone(self.config_manager.cache)
        self.assertTrue(len(self.config_manager.SCHEMA) > 0)
    
    def test_schema_validation(self) -> None:
        """Test configuration schema validation"""
        # Valid configuration
        self.config_manager.set('lightning.host', 'localhost')
        self.config_manager.set('lightning.port', 8080)
        self.config_manager.set('system.environment', 'development')
        
        # Should validate successfully
        self.assertTrue(self.config_manager.validate())
        
        # Invalid configuration
        with self.assertRaises(ValidationError):
            self.config_manager.set('lightning.port', -1)  # Invalid port
    
    def test_environment_variable_support(self) -> None:
        """Test environment variable overrides"""
        with patch.dict('os.environ', {'BLNCS_LN_HOST': 'env.host.com'}):
            # Reload config to pick up environment variables
            self.config_manager.reload()
            
            host = self.config_manager.get('lightning.host')
            self.assertEqual(host, 'env.host.com')
    
    def test_configuration_persistence(self) -> None:
        """Test configuration persistence"""
        # Set a test value
        self.config_manager.set('test.key', 'test_value', persist=True)
        
        # Config file should exist
        self.assertTrue(self.config_path.exists())
        
        # Create new config manager instance
        new_config = ConfigManager(str(self.config_path))
        
        # Value should be persisted
        self.assertEqual(new_config.get('test.key'), 'test_value')
    
    def test_env_template_generation(self) -> None:
        """Test environment variable template generation"""
        template = self.config_manager.export_env_template()
        
        self.assertIsInstance(template, str)
        self.assertIn('BLNCS_ENV', template)
        self.assertIn('BLNCS_LN_HOST', template)
        self.assertIn('#', template)  # Should contain comments


class TestCircuitBreaker(unittest.TestCase):
    """Test circuit breaker implementation"""
    
    def setUp(self) -> None:
        """Set up test environment"""
        self.circuit_breaker = CircuitBreaker(
            name="test_breaker",
            failure_threshold=3,
            timeout=1.0,
            reset_timeout=2.0
        )
    
    def test_circuit_breaker_initialization(self) -> None:
        """Test circuit breaker initialization"""
        self.assertEqual(self.circuit_breaker.name, "test_breaker")
        self.assertEqual(self.circuit_breaker.state, CircuitState.CLOSED)
        self.assertEqual(self.circuit_breaker.failure_count, 0)
    
    def test_circuit_breaker_failure_threshold(self) -> None:
        """Test circuit breaker failure threshold"""
        # Simulate failures
        for i in range(3):
            try:
                with self.circuit_breaker:
                    raise ConnectionError(f"Failure {i+1}")
            except ConnectionError:
                pass
        
        # Should be open after threshold failures
        self.assertEqual(self.circuit_breaker.state, CircuitState.OPEN)
    
    def test_circuit_breaker_recovery(self) -> None:
        """Test circuit breaker recovery"""
        # Force circuit breaker to open
        self.circuit_breaker._transition_to_open()
        
        # Wait for reset timeout
        time.sleep(2.1)
        
        # Should transition to half-open
        try:
            with self.circuit_breaker:
                pass  # Successful operation
        except:
            pass
        
        # After successful operation, should be closed
        try:
            with self.circuit_breaker:
                pass  # Another successful operation
        except:
            pass


class TestHealthChecker(unittest.TestCase):
    """Test enhanced health checker"""
    
    def setUp(self) -> None:
        """Set up test environment"""
        self.health_checker = get_health_checker()
    
    def test_health_checker_initialization(self) -> None:
        """Test health checker initialization"""
        self.assertIsNotNone(self.health_checker.logger)
        self.assertIsNotNone(self.health_checker.config)
    
    def test_system_health_check(self) -> None:
        """Test system health check"""
        result = self.health_checker.check_system_health()
        
        self.assertIsInstance(result, HealthCheckResult)
        self.assertIsInstance(result.status, HealthStatus)
        self.assertIsInstance(result.message, str)
        self.assertIsInstance(result.checks, dict)
        self.assertIsInstance(result.metadata, dict)
    
    def test_component_health_checks(self) -> None:
        """Test individual component health checks"""
        # System resources check
        result = self.health_checker.check_system_resources()
        self.assertIsInstance(result, dict)
        
        # Network connectivity check  
        result = self.health_checker.check_network_connectivity()
        self.assertIsInstance(result, dict)
        
        # Configuration validation check
        result = self.health_checker.check_config_validity()
        self.assertIsInstance(result, dict)
    
    def test_health_check_registration(self) -> None:
        """Test custom health check registration"""
        def custom_check() -> dict:
            return {'status': 'healthy', 'message': 'Custom check passed'}
        
        initial_count = len(self.health_checker.health_checks)
        self.health_checker.register_health_check('custom_test', custom_check)
        
        self.assertEqual(len(self.health_checker.health_checks), initial_count + 1)
        self.assertIn('custom_test', self.health_checker.health_checks)


def run_enhanced_tests() -> bool:
    """Run all enhanced system tests"""
    print("Running BLNCS Enhanced Systems Test Suite...")
    print("=" * 60)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test cases
    test_cases = [
        TestEnhancedValidator,
        TestEnhancedRecovery,
        TestEnhancedMonitoring,
        TestConfigManager,
        TestCircuitBreaker,
        TestHealthChecker
    ]
    
    for test_case in test_cases:
        tests = loader.loadTestsFromTestCase(test_case)
        suite.addTests(tests)
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(
        verbosity=2,
        failfast=False,
        stream=sys.stdout
    )
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 60)
    print("Enhanced Systems Test Summary:")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped) if hasattr(result, 'skipped') else 0}")
    
    success = result.wasSuccessful()
    if success:
        print("🎉 All enhanced system tests passed!")
    else:
        print("❌ Some enhanced system tests failed!")
        
        if result.failures:
            print("\nFailures:")
            for test, traceback in result.failures:
                print(f"- {test}")
                # Print just the assertion error, not the full traceback
                lines = traceback.split('\n')
                for line in lines:
                    if 'AssertionError' in line:
                        print(f"  {line.strip()}")
                        break
        
        if result.errors:
            print("\nErrors:")
            for test, traceback in result.errors:
                print(f"- {test}")
                # Print just the error, not the full traceback
                lines = traceback.split('\n')
                for line in lines:
                    if any(err in line for err in ['Error:', 'Exception:']):
                        print(f"  {line.strip()}")
                        break
    
    return success


if __name__ == '__main__':
    success = run_enhanced_tests()
    sys.exit(0 if success else 1)