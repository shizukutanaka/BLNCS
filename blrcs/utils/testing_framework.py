# BLRCS Testing Framework
# Comprehensive testing utilities following TDD principles
import asyncio
import unittest
import pytest
import time
import threading
import tempfile
import shutil
import json
import sqlite3
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable, Union
from unittest.mock import Mock, MagicMock, patch, AsyncMock
from dataclasses import dataclass, field
from contextlib import contextmanager, asynccontextmanager
from functools import wraps
import inspect
from collections import defaultdict

# Test Configuration
@dataclass
class TestConfig:
    """Test configuration and settings"""
    temp_dir: Optional[Path] = None
    test_db_path: Optional[Path] = None
    mock_external_services: bool = True
    enable_performance_tests: bool = True
    enable_integration_tests: bool = True
    test_timeout: float = 30.0
    parallel_execution: bool = True
    coverage_threshold: float = 80.0
    log_level: str = "DEBUG"
    
    def __post_init__(self):
        if self.temp_dir is None:
            self.temp_dir = Path(tempfile.mkdtemp(prefix="blrcs_test_"))
        if self.test_db_path is None:
            self.test_db_path = self.temp_dir / "test.db"

class TestResult:
    """Enhanced test result tracking"""
    
    def __init__(self):
        self.tests_run = 0
        self.failures = 0
        self.errors = 0
        self.skipped = 0
        self.duration = 0.0
        self.coverage = 0.0
        self.performance_metrics: Dict[str, float] = {}
        self.detailed_results: List[Dict[str, Any]] = []
    
    def add_result(self, test_name: str, status: str, duration: float, 
                   error: str = None, performance_data: Dict = None):
        """Add individual test result"""
        self.tests_run += 1
        
        if status == "PASS":
            pass
        elif status == "FAIL":
            self.failures += 1
        elif status == "ERROR":
            self.errors += 1
        elif status == "SKIP":
            self.skipped += 1
        
        result = {
            'test_name': test_name,
            'status': status,
            'duration': duration,
            'error': error,
            'performance_data': performance_data or {}
        }
        self.detailed_results.append(result)
        
        if performance_data:
            self.performance_metrics.update(performance_data)
    
    def get_success_rate(self) -> float:
        """Get test success rate"""
        if self.tests_run == 0:
            return 0.0
        return (self.tests_run - self.failures - self.errors) / self.tests_run * 100
    
    def get_summary(self) -> Dict[str, Any]:
        """Get test summary"""
        return {
            'tests_run': self.tests_run,
            'passed': self.tests_run - self.failures - self.errors - self.skipped,
            'failures': self.failures,
            'errors': self.errors,
            'skipped': self.skipped,
            'success_rate': self.get_success_rate(),
            'duration': self.duration,
            'coverage': self.coverage,
            'performance_metrics': self.performance_metrics
        }

class MockService:
    """Base class for service mocks"""
    
    def __init__(self):
        self.call_history: List[Dict[str, Any]] = []
        self.responses: Dict[str, Any] = {}
        self.side_effects: Dict[str, Callable] = {}
    
    def set_response(self, method: str, response: Any):
        """Set mock response for method"""
        self.responses[method] = response
    
    def set_side_effect(self, method: str, effect: Callable):
        """Set side effect for method"""
        self.side_effects[method] = effect
    
    def get_call_count(self, method: str) -> int:
        """Get call count for method"""
        return sum(1 for call in self.call_history if call['method'] == method)
    
    def get_last_call(self, method: str) -> Optional[Dict[str, Any]]:
        """Get last call for method"""
        calls = [call for call in self.call_history if call['method'] == method]
        return calls[-1] if calls else None

class DatabaseMock(MockService):
    """Database mock for testing"""
    
    def __init__(self):
        super().__init__()
        self.data: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.schemas: Dict[str, List[str]] = {}
    
    def create_table(self, table_name: str, schema: List[str]):
        """Create mock table"""
        self.schemas[table_name] = schema
        self.data[table_name] = []
    
    def insert(self, table_name: str, data: Dict[str, Any]) -> int:
        """Mock insert"""
        if table_name not in self.data:
            self.data[table_name] = []
        
        # Add auto-increment ID if not present
        if 'id' not in data:
            data['id'] = len(self.data[table_name]) + 1
        
        self.data[table_name].append(data.copy())
        self.call_history.append({
            'method': 'insert',
            'table': table_name,
            'data': data,
            'timestamp': time.time()
        })
        return data['id']
    
    def select(self, table_name: str, where: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Mock select"""
        if table_name not in self.data:
            return []
        
        results = self.data[table_name]
        
        if where:
            filtered_results = []
            for row in results:
                match = True
                for key, value in where.items():
                    if row.get(key) != value:
                        match = False
                        break
                if match:
                    filtered_results.append(row)
            results = filtered_results
        
        self.call_history.append({
            'method': 'select',
            'table': table_name,
            'where': where,
            'results_count': len(results),
            'timestamp': time.time()
        })
        
        return [row.copy() for row in results]
    
    def update(self, table_name: str, data: Dict[str, Any], where: Dict[str, Any]) -> int:
        """Mock update"""
        if table_name not in self.data:
            return 0
        
        updated_count = 0
        for row in self.data[table_name]:
            match = True
            for key, value in where.items():
                if row.get(key) != value:
                    match = False
                    break
            
            if match:
                row.update(data)
                updated_count += 1
        
        self.call_history.append({
            'method': 'update',
            'table': table_name,
            'data': data,
            'where': where,
            'updated_count': updated_count,
            'timestamp': time.time()
        })
        
        return updated_count
    
    def delete(self, table_name: str, where: Dict[str, Any]) -> int:
        """Mock delete"""
        if table_name not in self.data:
            return 0
        
        original_count = len(self.data[table_name])
        self.data[table_name] = [
            row for row in self.data[table_name]
            if not all(row.get(key) == value for key, value in where.items())
        ]
        deleted_count = original_count - len(self.data[table_name])
        
        self.call_history.append({
            'method': 'delete',
            'table': table_name,
            'where': where,
            'deleted_count': deleted_count,
            'timestamp': time.time()
        })
        
        return deleted_count
    
    def clear_table(self, table_name: str):
        """Clear table data"""
        if table_name in self.data:
            self.data[table_name].clear()
    
    def clear_all(self):
        """Clear all data"""
        self.data.clear()
        self.call_history.clear()

class PerformanceMonitor:
    """Performance monitoring for tests"""
    
    def __init__(self):
        self.metrics: Dict[str, List[float]] = defaultdict(list)
        self.thresholds: Dict[str, float] = {}
    
    def set_threshold(self, metric_name: str, threshold: float):
        """Set performance threshold"""
        self.thresholds[metric_name] = threshold
    
    @contextmanager
    def measure(self, metric_name: str):
        """Measure execution time"""
        start_time = time.perf_counter()
        try:
            yield
        finally:
            duration = time.perf_counter() - start_time
            self.metrics[metric_name].append(duration)
    
    def get_average(self, metric_name: str) -> float:
        """Get average time for metric"""
        if metric_name not in self.metrics or not self.metrics[metric_name]:
            return 0.0
        return sum(self.metrics[metric_name]) / len(self.metrics[metric_name])
    
    def get_max(self, metric_name: str) -> float:
        """Get maximum time for metric"""
        if metric_name not in self.metrics or not self.metrics[metric_name]:
            return 0.0
        return max(self.metrics[metric_name])
    
    def check_threshold(self, metric_name: str) -> bool:
        """Check if metric exceeds threshold"""
        if metric_name not in self.thresholds:
            return True
        
        avg_time = self.get_average(metric_name)
        return avg_time <= self.thresholds[metric_name]
    
    def get_report(self) -> Dict[str, Any]:
        """Get performance report"""
        report = {}
        for metric_name, times in self.metrics.items():
            if times:
                report[metric_name] = {
                    'count': len(times),
                    'average': sum(times) / len(times),
                    'min': min(times),
                    'max': max(times),
                    'threshold': self.thresholds.get(metric_name),
                    'within_threshold': self.check_threshold(metric_name)
                }
        return report

class TestFixture:
    """Base test fixture class"""
    
    def __init__(self, config: TestConfig):
        self.config = config
        self.db_mock = DatabaseMock()
        self.performance_monitor = PerformanceMonitor()
        self.temp_files: List[Path] = []
        self.cleanup_callbacks: List[Callable] = []
    
    def setup(self):
        """Setup test fixture"""
        # Create temp directory
        self.config.temp_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup test database
        if self.config.test_db_path:
            self.setup_test_database()
        
        # Setup performance thresholds
        self.setup_performance_thresholds()
    
    def teardown(self):
        """Teardown test fixture"""
        # Run cleanup callbacks
        for callback in self.cleanup_callbacks:
            try:
                callback()
            except Exception:
                pass
        
        # Clean up temp files
        for temp_file in self.temp_files:
            try:
                if temp_file.exists():
                    if temp_file.is_file():
                        temp_file.unlink()
                    else:
                        shutil.rmtree(temp_file)
            except Exception:
                pass
        
        # Clean up temp directory
        if self.config.temp_dir and self.config.temp_dir.exists():
            try:
                shutil.rmtree(self.config.temp_dir)
            except Exception:
                pass
    
    def setup_test_database(self):
        """Setup test database"""
        # Create test database with minimal schema
        conn = sqlite3.connect(self.config.test_db_path)
        cursor = conn.cursor()
        
        # Basic tables for testing
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS test_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL,
                value TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS test_cache (
                key TEXT PRIMARY KEY,
                value TEXT,
                expires_at TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def setup_performance_thresholds(self):
        """Setup performance thresholds"""
        self.performance_monitor.set_threshold('database_query', 0.01)  # 10ms
        self.performance_monitor.set_threshold('api_request', 0.1)      # 100ms
        self.performance_monitor.set_threshold('cache_operation', 0.001) # 1ms
        self.performance_monitor.set_threshold('file_operation', 0.01)   # 10ms
    
    def create_temp_file(self, content: str = "", suffix: str = ".tmp") -> Path:
        """Create temporary file"""
        temp_file = self.config.temp_dir / f"temp_{len(self.temp_files)}{suffix}"
        temp_file.write_text(content)
        self.temp_files.append(temp_file)
        return temp_file
    
    def create_temp_dir(self, name: str = None) -> Path:
        """Create temporary directory"""
        if name is None:
            name = f"temp_dir_{len(self.temp_files)}"
        temp_dir = self.config.temp_dir / name
        temp_dir.mkdir(parents=True, exist_ok=True)
        self.temp_files.append(temp_dir)
        return temp_dir
    
    def add_cleanup(self, callback: Callable):
        """Add cleanup callback"""
        self.cleanup_callbacks.append(callback)

class AsyncTestFixture(TestFixture):
    """Async test fixture"""
    
    def __init__(self, config: TestConfig):
        super().__init__(config)
        self.loop: Optional[asyncio.AbstractEventLoop] = None
    
    async def async_setup(self):
        """Async setup"""
        self.setup()
        self.loop = asyncio.get_event_loop()
    
    async def async_teardown(self):
        """Async teardown"""
        # Cancel any running tasks
        if self.loop:
            tasks = [task for task in asyncio.all_tasks(self.loop) 
                    if not task.done()]
            if tasks:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        
        self.teardown()

class TestRunner:
    """Enhanced test runner"""
    
    def __init__(self, config: TestConfig):
        self.config = config
        self.result = TestResult()
        self.fixtures: Dict[str, TestFixture] = {}
    
    def add_fixture(self, name: str, fixture: TestFixture):
        """Add test fixture"""
        self.fixtures[name] = fixture
    
    def run_test_function(self, test_func: Callable, *args, **kwargs) -> Dict[str, Any]:
        """Run individual test function"""
        test_name = test_func.__name__
        start_time = time.perf_counter()
        performance_data = {}
        
        try:
            # Setup fixtures
            for fixture in self.fixtures.values():
                fixture.setup()
            
            # Run test with timeout
            if asyncio.iscoroutinefunction(test_func):
                result = asyncio.run(asyncio.wait_for(
                    test_func(*args, **kwargs), 
                    timeout=self.config.test_timeout
                ))
            else:
                result = test_func(*args, **kwargs)
            
            duration = time.perf_counter() - start_time
            
            # Collect performance data
            for fixture in self.fixtures.values():
                if hasattr(fixture, 'performance_monitor'):
                    perf_report = fixture.performance_monitor.get_report()
                    performance_data.update(perf_report)
            
            self.result.add_result(test_name, "PASS", duration, 
                                 performance_data=performance_data)
            
            return {
                'status': 'PASS',
                'duration': duration,
                'result': result,
                'performance_data': performance_data
            }
            
        except AssertionError as e:
            duration = time.perf_counter() - start_time
            self.result.add_result(test_name, "FAIL", duration, str(e))
            return {
                'status': 'FAIL',
                'duration': duration,
                'error': str(e)
            }
            
        except Exception as e:
            duration = time.perf_counter() - start_time
            self.result.add_result(test_name, "ERROR", duration, str(e))
            return {
                'status': 'ERROR',
                'duration': duration,
                'error': str(e)
            }
            
        finally:
            # Teardown fixtures
            for fixture in self.fixtures.values():
                try:
                    fixture.teardown()
                except Exception:
                    pass
    
    def run_test_suite(self, test_functions: List[Callable]) -> TestResult:
        """Run test suite"""
        start_time = time.perf_counter()
        
        if self.config.parallel_execution and len(test_functions) > 1:
            # Run tests in parallel
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = [executor.submit(self.run_test_function, test_func) 
                          for test_func in test_functions]
                concurrent.futures.wait(futures)
        else:
            # Run tests sequentially
            for test_func in test_functions:
                self.run_test_function(test_func)
        
        self.result.duration = time.perf_counter() - start_time
        return self.result

# Test Decorators
def performance_test(threshold_ms: float = None):
    """Decorator for performance tests"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            result = func(*args, **kwargs)
            duration = time.perf_counter() - start_time
            
            if threshold_ms and duration > threshold_ms / 1000:
                raise AssertionError(
                    f"Performance test failed: {func.__name__} took {duration*1000:.2f}ms, "
                    f"threshold was {threshold_ms}ms"
                )
            
            return result
        return wrapper
    return decorator

def integration_test(requires_services: List[str] = None):
    """Decorator for integration tests"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Skip if integration tests disabled
            config = getattr(args[0], 'config', None)
            if config and not config.enable_integration_tests:
                pytest.skip("Integration tests disabled")
            
            # Check required services
            if requires_services:
                for service in requires_services:
                    # Add service availability checks here
                    pass
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

def mock_external_services(services: List[str]):
    """Decorator to mock external services"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            mocks = {}
            patches = []
            
            try:
                for service in services:
                    if service == 'database':
                        mock_db = DatabaseMock()
                        patch_obj = patch('blrcs.database.Database', mock_db)
                        patches.append(patch_obj)
                        mocks[service] = mock_db
                    # Add more service mocks as needed
                
                # Start all patches
                for patch_obj in patches:
                    patch_obj.start()
                
                # Add mocks to kwargs
                kwargs['mocks'] = mocks
                
                return func(*args, **kwargs)
                
            finally:
                # Stop all patches
                for patch_obj in patches:
                    patch_obj.stop()
        
        return wrapper
    return decorator

# Assertion Helpers
class BLRCSAssertions:
    """Custom assertions for BLRCS testing"""
    
    @staticmethod
    def assert_config_valid(config):
        """Assert configuration is valid"""
        assert config is not None, "Configuration cannot be None"
        
        # Check required fields
        assert hasattr(config, 'app_name'), "Configuration missing app_name"
        assert hasattr(config, 'mode'), "Configuration missing mode"
        assert config.mode in ['dev', 'test', 'prod'], f"Invalid mode: {config.mode}"
        
        # Check port ranges
        assert 1 <= config.port <= 65535, f"Invalid port: {config.port}"
        if hasattr(config, 'lnd_rest_port'):
            assert 1 <= config.lnd_rest_port <= 65535, f"Invalid LND port: {config.lnd_rest_port}"
    
    @staticmethod
    def assert_database_state(db_mock: DatabaseMock, table: str, expected_count: int):
        """Assert database state"""
        actual_count = len(db_mock.data.get(table, []))
        assert actual_count == expected_count, \
            f"Expected {expected_count} records in {table}, got {actual_count}"
    
    @staticmethod
    def assert_performance_within_threshold(monitor: PerformanceMonitor, 
                                          metric: str, threshold_ms: float):
        """Assert performance within threshold"""
        avg_time = monitor.get_average(metric)
        assert avg_time <= threshold_ms / 1000, \
            f"Performance test failed: {metric} averaged {avg_time*1000:.2f}ms, " \
            f"threshold was {threshold_ms}ms"
    
    @staticmethod
    def assert_no_sensitive_data_logged(log_messages: List[str]):
        """Assert no sensitive data in logs"""
        sensitive_patterns = [
            'password', 'secret', 'token', 'api_key', 'macaroon', 'private_key'
        ]
        
        for message in log_messages:
            for pattern in sensitive_patterns:
                assert pattern not in message.lower(), \
                    f"Sensitive data '{pattern}' found in log: {message}"

# Test Factory Functions
def create_test_config(**overrides) -> TestConfig:
    """Create test configuration with overrides"""
    config = TestConfig()
    for key, value in overrides.items():
        if hasattr(config, key):
            setattr(config, key, value)
    return config

def create_test_fixture(config: TestConfig = None) -> TestFixture:
    """Create test fixture"""
    if config is None:
        config = create_test_config()
    return TestFixture(config)

def create_async_test_fixture(config: TestConfig = None) -> AsyncTestFixture:
    """Create async test fixture"""
    if config is None:
        config = create_test_config()
    return AsyncTestFixture(config)

# Test Data Generators
class TestDataGenerator:
    """Generate test data"""
    
    @staticmethod
    def generate_config_data(**overrides) -> Dict[str, Any]:
        """Generate test configuration data"""
        data = {
            'app_name': 'BLRCS_Test',
            'mode': 'test',
            'host': '127.0.0.1',
            'port': 8081,
            'debug': True,
            'log_level': 'DEBUG'
        }
        data.update(overrides)
        return data
    
    @staticmethod
    def generate_user_data(count: int = 1) -> List[Dict[str, Any]]:
        """Generate test user data"""
        users = []
        for i in range(count):
            users.append({
                'id': i + 1,
                'username': f'testuser{i+1}',
                'email': f'testuser{i+1}@example.com',
                'created_at': time.time()
            })
        return users
    
    @staticmethod
    def generate_transaction_data(count: int = 1) -> List[Dict[str, Any]]:
        """Generate test transaction data"""
        transactions = []
        for i in range(count):
            transactions.append({
                'id': i + 1,
                'amount': 1000 + i * 100,
                'fee': 1 + i,
                'timestamp': time.time() - (count - i) * 3600
            })
        return transactions

# Export main classes and functions
__all__ = [
    'TestConfig',
    'TestResult', 
    'TestFixture',
    'AsyncTestFixture',
    'TestRunner',
    'DatabaseMock',
    'PerformanceMonitor',
    'BLRCSAssertions',
    'TestDataGenerator',
    'performance_test',
    'integration_test',
    'mock_external_services',
    'create_test_config',
    'create_test_fixture',
    'create_async_test_fixture'
]