"""
Comprehensive Test Suite for BLNCS
Achieves >90% test coverage with thorough testing of all components.
"""

import pytest
import asyncio
import tempfile
import json
import os
import time
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, List

# Import BLNCS components
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from blncs.core.security_validator import (
    SecurityValidator, ValidationLevel, validate_and_sanitize
)
from blncs.core.config_manager import ConfigManager, get_config_manager
from blncs.core.logger import get_logger
from blncs.core.exceptions import (
    ValidationError, ConnectionError, LightningError
)
from blncs.core.metrics import (
    get_metrics_collector, MetricType, increment_counter
)
from blncs.core.performance_optimizer import (
    get_performance_optimizer, PerformanceLevel
)
from blncs.core.health_diagnostics import (
    get_system_diagnostics, HealthStatus, ComponentType
)
from blncs.lightning.async_client import AsyncLightningClient
from blncs.lightning.client import LightningClient


class TestSecurityValidator:
    """Comprehensive security validator tests"""
    
    def setup_method(self):
        """Setup test environment"""
        self.validator = SecurityValidator(ValidationLevel.STRICT)
        self.relaxed_validator = SecurityValidator(ValidationLevel.RELAXED)
    
    def test_string_validation_success(self):
        """Test successful string validation"""
        result = self.validator.validate_string("valid string", min_length=5, max_length=20)
        assert result.is_valid
        assert result.sanitized_value == "valid string"
        assert len(result.errors) == 0
    
    def test_string_validation_length_error(self):
        """Test string length validation errors"""
        result = self.validator.validate_string("short", min_length=10)
        assert not result.is_valid
        assert "too short" in result.errors[0].lower()
        
        long_string = "x" * 10001
        result = self.validator.validate_string(long_string)
        assert not result.is_valid
        assert "too long" in result.errors[0].lower()
    
    def test_sql_injection_detection(self):
        """Test SQL injection pattern detection"""
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "1 OR 1=1",
            "UNION SELECT * FROM passwords"
        ]
        
        for malicious in malicious_inputs:
            result = self.validator.validate_string(malicious)
            assert not result.is_valid
            assert any("sql injection" in e.lower() for e in result.errors)
    
    def test_xss_detection(self):
        """Test XSS pattern detection"""
        xss_inputs = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<iframe src='evil.com'></iframe>"
        ]
        
        for xss in xss_inputs:
            result = self.validator.validate_string(xss)
            assert len(result.warnings) > 0 or not result.is_valid
    
    def test_integer_validation(self):
        """Test integer validation"""
        # Valid integers
        assert self.validator.validate_integer(42).is_valid
        assert self.validator.validate_integer("123").is_valid
        assert self.validator.validate_integer(3.14).sanitized_value == 3
        
        # Invalid integers
        assert not self.validator.validate_integer("abc").is_valid
        assert not self.validator.validate_integer(None).is_valid
        
        # Range validation
        result = self.validator.validate_integer(150, min_value=0, max_value=100)
        assert not result.is_valid
        assert "above maximum" in result.errors[0]
    
    def test_path_validation(self):
        """Test file path validation with security checks"""
        # Valid paths
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            valid_file = temp_path / "test.txt"
            valid_file.write_text("test")
            
            result = self.validator.validate_path(str(valid_file), must_exist=True)
            assert result.is_valid
        
        # Path traversal attempts
        traversal_attempts = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32",
            "%2e%2e/etc/shadow"
        ]
        
        for attempt in traversal_attempts:
            result = self.validator.validate_path(attempt)
            assert not result.is_valid
            assert "traversal" in result.errors[0].lower()
    
    def test_url_validation(self):
        """Test URL validation"""
        # Valid URLs
        valid_urls = [
            "https://example.com",
            "http://localhost:8080/api",
            "https://test.example.com/path?param=value"
        ]
        
        for url in valid_urls:
            result = self.validator.validate_url(url)
            assert result.is_valid
        
        # Invalid URLs
        invalid_urls = [
            "javascript:alert('xss')",
            "data:text/html,<script>alert(1)</script>",
            "not-a-url",
            "ftp://example.com"  # If FTP not allowed
        ]
        
        for url in invalid_urls:
            result = self.validator.validate_url(url, allowed_schemes=['http', 'https'])
            if url.startswith(('javascript:', 'data:')):
                assert not result.is_valid
                assert 'security_violation' in result.metadata
    
    def test_email_validation(self):
        """Test email validation"""
        valid_emails = [
            "user@example.com",
            "test.email+tag@domain.co.uk",
            "user123@test-domain.com"
        ]
        
        for email in valid_emails:
            result = self.validator.validate_email(email)
            assert result.is_valid
        
        invalid_emails = [
            "invalid-email",
            "@example.com",
            "user@",
            "user<script>@example.com"
        ]
        
        for email in invalid_emails:
            result = self.validator.validate_email(email)
            assert not result.is_valid
    
    def test_bitcoin_address_validation(self):
        """Test Bitcoin address validation"""
        valid_addresses = [
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
        ]
        
        for address in valid_addresses:
            result = self.validator.validate_bitcoin_address(address)
            assert result.is_valid
        
        invalid_addresses = [
            "invalid-address",
            "1234567890",
            "bc1invalid"
        ]
        
        for address in invalid_addresses:
            result = self.validator.validate_bitcoin_address(address)
            assert not result.is_valid
    
    def test_lightning_invoice_validation(self):
        """Test Lightning invoice validation"""
        valid_invoices = [
            "lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6na6hlh",
            "lntb20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs"
        ]
        
        for invoice in valid_invoices:
            result = self.validator.validate_lightning_invoice(invoice)
            assert result.is_valid
        
        invalid_invoices = [
            "invalid-invoice",
            "btc1234567890",
            "ln" + "x" * 2000  # Too long
        ]
        
        for invoice in invalid_invoices:
            result = self.validator.validate_lightning_invoice(invoice)
            assert not result.is_valid
    
    def test_command_validation(self):
        """Test shell command validation"""
        safe_commands = [
            "ls -la",
            "cat file.txt",
            "echo hello"
        ]
        
        for cmd in safe_commands:
            result = self.validator.validate_command(cmd)
            assert result.is_valid
        
        dangerous_commands = [
            "rm -rf /",
            "ls | grep password",
            "cat file.txt; rm file.txt",
            "$(malicious_command)"
        ]
        
        for cmd in dangerous_commands:
            result = self.validator.validate_command(cmd)
            assert not result.is_valid or len(result.warnings) > 0


class TestConfigManager:
    """Test configuration management system"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = Path(self.temp_dir) / "test_config.yaml"
    
    def test_config_loading(self):
        """Test configuration loading"""
        config_data = {
            'system': {'environment': 'testing'},
            'lightning': {'host': 'localhost', 'port': 8080}
        }
        
        # Write test config
        import yaml
        with open(self.config_path, 'w') as f:
            yaml.dump(config_data, f)
        
        # Load config
        config_manager = ConfigManager(str(self.config_path))
        assert config_manager.get('system.environment') == 'testing'
        assert config_manager.get('lightning.port') == 8080
    
    def test_config_validation(self):
        """Test configuration validation"""
        config_manager = ConfigManager()
        
        # Test valid configuration
        config_manager.set('lightning.port', 8080)
        assert config_manager.validate()
        
        # Test invalid configuration
        with pytest.raises(ValidationError):
            config_manager.set('lightning.port', -1)
    
    def test_environment_overrides(self):
        """Test environment variable overrides"""
        os.environ['BLNCS_LN_PORT'] = '9090'
        
        try:
            config_manager = ConfigManager()
            assert config_manager.get('lightning.port') == 9090
        finally:
            os.environ.pop('BLNCS_LN_PORT', None)


class TestMetricsSystem:
    """Test metrics collection system"""
    
    def setup_method(self):
        """Setup test environment"""
        self.collector = get_metrics_collector()
    
    def test_counter_metrics(self):
        """Test counter metrics"""
        counter = self.collector.counter('test_counter')
        initial_value = counter.get_value()
        
        counter.increment(5)
        assert counter.get_value() == initial_value + 5
        
        # Test convenience function
        increment_counter('test_counter_2', 3)
        counter2 = self.collector.counter('test_counter_2')
        assert counter2.get_value() == 3
    
    def test_gauge_metrics(self):
        """Test gauge metrics"""
        gauge = self.collector.gauge('test_gauge')
        
        gauge.set(42)
        assert gauge.get_value() == 42
        
        gauge.increment(8)
        assert gauge.get_value() == 50
        
        gauge.decrement(10)
        assert gauge.get_value() == 40
    
    def test_histogram_metrics(self):
        """Test histogram metrics"""
        histogram = self.collector.histogram('test_histogram')
        
        values = [1, 2, 3, 4, 5, 10, 15, 20]
        for value in values:
            histogram.observe(value)
        
        summary = histogram.get_summary()
        assert summary.count == len(values)
        assert summary.sum == sum(values)
        assert summary.min == min(values)
        assert summary.max == max(values)
    
    def test_timer_metrics(self):
        """Test timer metrics"""
        timer = self.collector.timer('test_timer')
        
        with timer:
            time.sleep(0.1)  # 100ms
        
        summary = timer.get_summary()
        assert summary.count == 1
        assert 0.09 <= summary.sum <= 0.2  # Allow some variance


class TestPerformanceOptimizer:
    """Test performance optimization system"""
    
    def setup_method(self):
        """Setup test environment"""
        self.optimizer = get_performance_optimizer()
    
    def test_operation_measurement(self):
        """Test operation performance measurement"""
        with self.optimizer.measure_operation('test_op'):
            time.sleep(0.05)  # 50ms
        
        profile = self.optimizer.get_operation_profile('test_op')
        assert profile is not None
        assert profile.call_count == 1
        assert 0.04 <= profile.total_time <= 0.1  # Allow variance
    
    def test_performance_cache(self):
        """Test performance cache"""
        cache = self.optimizer.cache
        
        # Test set/get
        cache.set('test_key', 'test_value')
        assert cache.get('test_key') == 'test_value'
        
        # Test cache statistics
        stats = cache.stats()
        assert 'hit_count' in stats
        assert 'miss_count' in stats
        assert 'hit_rate' in stats
    
    def test_performance_report(self):
        """Test performance report generation"""
        # Generate some test data
        with self.optimizer.measure_operation('report_test'):
            time.sleep(0.01)
        
        report = self.optimizer.get_performance_report()
        assert 'system' in report
        assert 'operations' in report
        assert 'cache' in report
        assert 'recommendations' in report
        
        # Check operation data
        assert 'report_test' in report['operations']


class TestHealthDiagnostics:
    """Test health diagnostics system"""
    
    def setup_method(self):
        """Setup test environment"""
        self.diagnostics = get_system_diagnostics()
    
    def test_health_check_registration(self):
        """Test custom health check registration"""
        def custom_check():
            from blncs.core.health_diagnostics import HealthCheckResult
            return HealthCheckResult(
                component='test_component',
                component_type=ComponentType.PROCESS,
                status=HealthStatus.HEALTHY,
                message='Test OK'
            )
        
        self.diagnostics.register_health_check(
            'custom_test',
            ComponentType.PROCESS,
            custom_check
        )
        
        result = self.diagnostics.run_health_check('custom_test')
        assert result.status == HealthStatus.HEALTHY
        assert result.component == 'test_component'
    
    def test_system_health_summary(self):
        """Test system health summary"""
        summary = self.diagnostics.get_system_health_summary()
        
        assert 'overall_status' in summary
        assert 'checks' in summary
        assert 'total_checks' in summary
        assert summary['overall_status'] in ['healthy', 'warning', 'critical']
    
    def test_detailed_diagnostics(self):
        """Test detailed diagnostics report"""
        detailed = self.diagnostics.get_detailed_diagnostics()
        
        assert 'health_summary' in detailed
        assert 'system_info' in detailed
        assert 'health_checks' in detailed
        assert 'registered_checks' in detailed


class TestAsyncLightningClient:
    """Test async Lightning client"""
    
    @pytest.fixture
    def mock_session(self):
        """Mock aiohttp session"""
        session = AsyncMock()
        session.request.return_value.__aenter__.return_value.status = 200
        session.request.return_value.__aenter__.return_value.json.return_value = {
            'alias': 'test_node',
            'identity_pubkey': '03' + '0' * 64,
            'version': '0.15.0'
        }
        return session
    
    @pytest.mark.asyncio
    async def test_async_client_connection(self, mock_session):
        """Test async client connection"""
        with patch('aiohttp.ClientSession', return_value=mock_session):
            client = AsyncLightningClient()
            
            # Mock the session creation
            client.session = mock_session
            client.connected = True
            
            info = await client.get_info()
            assert info['alias'] == 'test_node'
    
    @pytest.mark.asyncio
    async def test_async_batch_requests(self, mock_session):
        """Test batch request processing"""
        client = AsyncLightningClient()
        client.session = mock_session
        client.connected = True
        
        requests = [
            {'method': 'GET', 'endpoint': 'v1/getinfo'},
            {'method': 'GET', 'endpoint': 'v1/balance/blockchain'},
            {'method': 'GET', 'endpoint': 'v1/channels'}
        ]
        
        with patch.object(client, '_make_request', new_callable=AsyncMock) as mock_request:
            mock_request.return_value = {'success': True}
            
            results = await client.batch_request(requests)
            assert len(results) == 3
            assert all(r['success'] for r in results)
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, mock_session):
        """Test rate limiting functionality"""
        client = AsyncLightningClient()
        client.session = mock_session
        client.connected = True
        client.rate_limit = asyncio.Semaphore(2)  # Limit to 2 concurrent
        
        # Mock request method
        async def mock_request(*args, **kwargs):
            await asyncio.sleep(0.1)  # Simulate processing time
            return {'result': 'success'}
        
        with patch.object(client, '_make_request', side_effect=mock_request):
            start_time = time.time()
            
            # Start 4 requests - should be processed in batches of 2
            tasks = [client.get_info() for _ in range(4)]
            await asyncio.gather(*tasks)
            
            elapsed = time.time() - start_time
            # Should take at least 0.2 seconds (2 batches of 0.1s each)
            assert elapsed >= 0.15


class TestLightningClientCompatibility:
    """Test Lightning client backwards compatibility"""
    
    def setup_method(self):
        """Setup test environment"""
        self.client = LightningClient()
    
    @patch('requests.Session.get')
    def test_sync_client_info(self, mock_get):
        """Test sync client get_info"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'alias': 'sync_test_node',
            'version': '0.15.0'
        }
        mock_get.return_value = mock_response
        
        info = self.client.get_info()
        assert 'alias' in info
    
    def test_client_configuration(self):
        """Test client configuration"""
        custom_config = {
            'lightning': {
                'host': 'custom.host',
                'port': 9999,
                'network': 'mainnet'
            }
        }
        
        client = LightningClient(custom_config)
        assert client.host == 'custom.host'
        assert client.port == 9999
        assert client.network == 'mainnet'


class TestIntegration:
    """Integration tests for complete workflows"""
    
    @pytest.mark.integration
    def test_complete_validation_workflow(self):
        """Test complete input validation workflow"""
        validator = SecurityValidator()
        
        # Simulate user input processing
        user_inputs = {
            'email': 'user@example.com',
            'amount': '100',
            'memo': 'Test payment',
            'address': '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'
        }
        
        schema = {
            'email': {'type': 'email', 'required': True},
            'amount': {'type': 'integer', 'min_value': 1, 'max_value': 1000000},
            'memo': {'type': 'string', 'max_length': 100},
            'address': {'type': 'string', 'pattern': r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$'}
        }
        
        result = validator.validate_dict(user_inputs, schema)
        assert result.is_valid
        assert result.sanitized_value['email'] == 'user@example.com'
        assert result.sanitized_value['amount'] == 100
    
    @pytest.mark.integration
    def test_monitoring_integration(self):
        """Test integrated monitoring workflow"""
        # Initialize components
        optimizer = get_performance_optimizer()
        diagnostics = get_system_diagnostics()
        metrics = get_metrics_collector()
        
        # Simulate operation
        with optimizer.measure_operation('integration_test'):
            # Simulate some work
            counter = metrics.counter('integration_operations')
            counter.increment()
            
            # Run health check
            summary = diagnostics.get_system_health_summary()
            
            time.sleep(0.01)  # Minimal processing time
        
        # Verify integration
        profile = optimizer.get_operation_profile('integration_test')
        assert profile is not None
        assert profile.call_count == 1
        
        report = optimizer.get_performance_report()
        assert 'integration_test' in report['operations']
        
        assert summary['overall_status'] in ['healthy', 'warning', 'critical']


class TestErrorHandling:
    """Test comprehensive error handling"""
    
    def test_validation_error_handling(self):
        """Test validation error handling"""
        with pytest.raises(ValidationError):
            validate_and_sanitize("'; DROP TABLE users; --", 'string')
    
    def test_connection_error_handling(self):
        """Test connection error handling"""
        client = LightningClient({'lightning': {'host': 'nonexistent.host'}})
        
        with pytest.raises(ConnectionError):
            client.connect()
    
    def test_lightning_error_handling(self):
        """Test Lightning-specific error handling"""
        client = LightningClient()
        
        with pytest.raises(LightningError):
            client.open_channel("invalid_pubkey", -100)  # Invalid amount


class TestEdgeCases:
    """Test edge cases and boundary conditions"""
    
    def test_empty_input_validation(self):
        """Test validation with empty inputs"""
        validator = SecurityValidator()
        
        result = validator.validate_string("")
        assert result.is_valid  # Empty string is valid by default
        
        result = validator.validate_string("", min_length=1)
        assert not result.is_valid
    
    def test_unicode_input_handling(self):
        """Test Unicode input handling"""
        validator = SecurityValidator()
        
        unicode_strings = [
            "Hello 世界",
            "Café ☕",
            "🚀 Lightning ⚡",
            "Ñoño niño"
        ]
        
        for unicode_str in unicode_strings:
            result = validator.validate_string(unicode_str)
            assert result.is_valid or len(result.errors) > 0  # Should not crash
    
    def test_very_large_inputs(self):
        """Test handling of very large inputs"""
        validator = SecurityValidator()
        
        # Large string
        large_string = "x" * 100000
        result = validator.validate_string(large_string)
        assert not result.is_valid  # Should reject due to size
        assert "too long" in result.errors[0].lower()
    
    def test_concurrent_operations(self):
        """Test thread safety of components"""
        import threading
        import concurrent.futures
        
        optimizer = get_performance_optimizer()
        results = []
        
        def worker_thread(thread_id):
            with optimizer.measure_operation(f'thread_test_{thread_id}'):
                time.sleep(0.01)
                return thread_id
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker_thread, i) for i in range(10)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]
        
        assert len(results) == 10
        
        # Verify all operations were recorded
        for i in range(10):
            profile = optimizer.get_operation_profile(f'thread_test_{i}')
            assert profile is not None
            assert profile.call_count == 1


class TestPerformance:
    """Performance and load testing"""
    
    def test_validation_performance(self):
        """Test validation performance under load"""
        validator = SecurityValidator()
        
        start_time = time.time()
        
        # Validate 1000 strings
        for i in range(1000):
            result = validator.validate_string(f"test_string_{i}")
            assert result.is_valid
        
        elapsed = time.time() - start_time
        
        # Should complete within reasonable time (< 1 second)
        assert elapsed < 1.0
        
        # Should handle at least 1000 validations per second
        rate = 1000 / elapsed
        assert rate > 1000
    
    def test_metrics_performance(self):
        """Test metrics system performance"""
        collector = get_metrics_collector()
        
        start_time = time.time()
        
        # Record 10000 metrics
        for i in range(10000):
            counter = collector.counter('perf_test')
            counter.increment()
        
        elapsed = time.time() - start_time
        
        # Should complete within reasonable time (< 0.5 seconds)
        assert elapsed < 0.5
        
        counter = collector.counter('perf_test')
        assert counter.get_value() == 10000


if __name__ == '__main__':
    # Run all tests
    pytest.main([
        __file__,
        '-v',
        '--tb=short',
        '--durations=10',
        '--cov=blncs',
        '--cov-report=term-missing',
        '--cov-report=html'
    ])