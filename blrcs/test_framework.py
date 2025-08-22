"""
Automated Testing Framework
Comprehensive testing infrastructure for national-level quality assurance
"""

import time
import json
import unittest
import threading
import multiprocessing
import traceback
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import hashlib
import random
import string


class TestType(Enum):
    """Types of tests"""
    UNIT = "unit"
    INTEGRATION = "integration"
    SYSTEM = "system"
    PERFORMANCE = "performance"
    SECURITY = "security"
    STRESS = "stress"
    REGRESSION = "regression"
    SMOKE = "smoke"


class TestStatus(Enum):
    """Test execution status"""
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class TestCase:
    """Individual test case"""
    id: str
    name: str
    description: str
    test_type: TestType
    function: Callable
    timeout: int = 30
    retries: int = 0
    dependencies: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    priority: int = 5


@dataclass
class TestResult:
    """Test execution result"""
    test_id: str
    status: TestStatus
    execution_time: float
    message: str = ""
    error: Optional[str] = None
    assertions_passed: int = 0
    assertions_failed: int = 0
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestSuite:
    """Collection of test cases"""
    id: str
    name: str
    description: str
    test_cases: List[TestCase] = field(default_factory=list)
    setup: Optional[Callable] = None
    teardown: Optional[Callable] = None
    parallel: bool = False
    tags: List[str] = field(default_factory=list)


class TestRunner:
    """Executes test cases and suites"""
    
    def __init__(self):
        self.test_cases = {}
        self.test_suites = {}
        self.results = []
        self.current_suite = None
        self.lock = threading.Lock()
        
    def register_test(self, test_case: TestCase):
        """Register a test case"""
        self.test_cases[test_case.id] = test_case
        
    def register_suite(self, test_suite: TestSuite):
        """Register a test suite"""
        self.test_suites[test_suite.id] = test_suite
        for test_case in test_suite.test_cases:
            self.register_test(test_case)
            
    def run_test(self, test_id: str) -> TestResult:
        """Run a single test"""
        if test_id not in self.test_cases:
            return TestResult(
                test_id=test_id,
                status=TestStatus.ERROR,
                execution_time=0,
                error="Test not found"
            )
            
        test_case = self.test_cases[test_id]
        start_time = time.time()
        
        # Check dependencies
        for dep_id in test_case.dependencies:
            dep_result = self._get_latest_result(dep_id)
            if not dep_result or dep_result.status != TestStatus.PASSED:
                return TestResult(
                    test_id=test_id,
                    status=TestStatus.SKIPPED,
                    execution_time=0,
                    message=f"Dependency {dep_id} not satisfied"
                )
                
        # Run test with retries
        for attempt in range(test_case.retries + 1):
            try:
                # Execute test with timeout
                result = self._execute_with_timeout(
                    test_case.function,
                    test_case.timeout
                )
                
                if result:
                    status = TestStatus.PASSED
                    message = "Test passed"
                else:
                    status = TestStatus.FAILED
                    message = "Test failed"
                    
                execution_time = time.time() - start_time
                
                test_result = TestResult(
                    test_id=test_id,
                    status=status,
                    execution_time=execution_time,
                    message=message
                )
                
                if status == TestStatus.PASSED or attempt == test_case.retries:
                    break
                    
            except TimeoutError:
                test_result = TestResult(
                    test_id=test_id,
                    status=TestStatus.ERROR,
                    execution_time=time.time() - start_time,
                    error="Test timeout"
                )
                
            except Exception as e:
                test_result = TestResult(
                    test_id=test_id,
                    status=TestStatus.ERROR,
                    execution_time=time.time() - start_time,
                    error=str(e),
                    message=traceback.format_exc()
                )
                
        with self.lock:
            self.results.append(test_result)
            
        return test_result
        
    def run_suite(self, suite_id: str) -> List[TestResult]:
        """Run a test suite"""
        if suite_id not in self.test_suites:
            return []
            
        suite = self.test_suites[suite_id]
        self.current_suite = suite
        results = []
        
        # Run setup
        if suite.setup:
            try:
                suite.setup()
            except Exception as e:
                # Setup failed, skip all tests
                for test_case in suite.test_cases:
                    results.append(TestResult(
                        test_id=test_case.id,
                        status=TestStatus.SKIPPED,
                        execution_time=0,
                        message=f"Suite setup failed: {str(e)}"
                    ))
                return results
                
        # Run tests
        if suite.parallel:
            results = self._run_parallel(suite.test_cases)
        else:
            results = self._run_sequential(suite.test_cases)
            
        # Run teardown
        if suite.teardown:
            try:
                suite.teardown()
            except Exception as e:
                pass  # Log but don't fail tests
                
        self.current_suite = None
        return results
        
    def _run_sequential(self, test_cases: List[TestCase]) -> List[TestResult]:
        """Run tests sequentially"""
        results = []
        for test_case in test_cases:
            result = self.run_test(test_case.id)
            results.append(result)
        return results
        
    def _run_parallel(self, test_cases: List[TestCase]) -> List[TestResult]:
        """Run tests in parallel"""
        with multiprocessing.Pool() as pool:
            results = pool.map(self.run_test, [tc.id for tc in test_cases])
        return results
        
    def _execute_with_timeout(self, func: Callable, timeout: int) -> Any:
        """Execute function with timeout"""
        result = [None]
        exception = [None]
        
        def target():
            try:
                result[0] = func()
            except Exception as e:
                exception[0] = e
                
        thread = threading.Thread(target=target)
        thread.daemon = True
        thread.start()
        thread.join(timeout)
        
        if thread.is_alive():
            raise TimeoutError(f"Test exceeded timeout of {timeout} seconds")
            
        if exception[0]:
            raise exception[0]
            
        return result[0]
        
    def _get_latest_result(self, test_id: str) -> Optional[TestResult]:
        """Get latest result for a test"""
        with self.lock:
            for result in reversed(self.results):
                if result.test_id == test_id:
                    return result
        return None
        
    def get_results(self) -> List[TestResult]:
        """Get all test results"""
        with self.lock:
            return self.results.copy()
            
    def get_summary(self) -> Dict[str, Any]:
        """Get test execution summary"""
        with self.lock:
            total = len(self.results)
            passed = sum(1 for r in self.results if r.status == TestStatus.PASSED)
            failed = sum(1 for r in self.results if r.status == TestStatus.FAILED)
            skipped = sum(1 for r in self.results if r.status == TestStatus.SKIPPED)
            errors = sum(1 for r in self.results if r.status == TestStatus.ERROR)
            
            total_time = sum(r.execution_time for r in self.results)
            
            return {
                "total": total,
                "passed": passed,
                "failed": failed,
                "skipped": skipped,
                "errors": errors,
                "pass_rate": (passed / total * 100) if total > 0 else 0,
                "total_execution_time": total_time,
                "average_execution_time": total_time / total if total > 0 else 0
            }


class TestGenerator:
    """Generates test data and scenarios"""
    
    def __init__(self):
        self.generators = {}
        
    def random_string(self, length: int = 10, 
                     charset: str = string.ascii_letters + string.digits) -> str:
        """Generate random string"""
        return ''.join(random.choice(charset) for _ in range(length))
        
    def random_email(self) -> str:
        """Generate random email"""
        username = self.random_string(8)
        domain = self.random_string(6)
        return f"{username}@{domain}.com"
        
    def random_ipv4(self) -> str:
        """Generate random IPv4 address"""
        return '.'.join(str(random.randint(0, 255)) for _ in range(4))
        
    def random_ipv6(self) -> str:
        """Generate random IPv6 address"""
        return ':'.join(format(random.randint(0, 65535), 'x') for _ in range(8))
        
    def random_json(self, depth: int = 3, max_items: int = 5) -> Dict[str, Any]:
        """Generate random JSON structure"""
        if depth == 0:
            return self._random_primitive()
            
        result = {}
        for _ in range(random.randint(1, max_items)):
            key = self.random_string(6)
            if random.random() < 0.7:
                result[key] = self._random_primitive()
            else:
                result[key] = self.random_json(depth - 1, max_items)
                
        return result
        
    def _random_primitive(self) -> Any:
        """Generate random primitive value"""
        types = [
            lambda: random.randint(-1000, 1000),
            lambda: random.random() * 1000,
            lambda: self.random_string(10),
            lambda: random.choice([True, False]),
            lambda: None
        ]
        return random.choice(types)()
        
    def generate_test_data(self, schema: Dict[str, Any]) -> Any:
        """Generate test data based on schema"""
        data_type = schema.get("type", "string")
        
        if data_type == "string":
            min_length = schema.get("min_length", 0)
            max_length = schema.get("max_length", 100)
            length = random.randint(min_length, max_length)
            return self.random_string(length)
            
        elif data_type == "integer":
            min_val = schema.get("minimum", -1000000)
            max_val = schema.get("maximum", 1000000)
            return random.randint(min_val, max_val)
            
        elif data_type == "float":
            min_val = schema.get("minimum", -1000000)
            max_val = schema.get("maximum", 1000000)
            return random.uniform(min_val, max_val)
            
        elif data_type == "boolean":
            return random.choice([True, False])
            
        elif data_type == "array":
            min_items = schema.get("min_items", 0)
            max_items = schema.get("max_items", 10)
            item_schema = schema.get("items", {"type": "string"})
            count = random.randint(min_items, max_items)
            return [self.generate_test_data(item_schema) for _ in range(count)]
            
        elif data_type == "object":
            properties = schema.get("properties", {})
            result = {}
            for key, prop_schema in properties.items():
                if random.random() < 0.8:  # 80% chance to include optional fields
                    result[key] = self.generate_test_data(prop_schema)
            return result
            
        return None


class PerformanceTester:
    """Performance testing utilities"""
    
    def __init__(self):
        self.results = []
        
    def benchmark(self, func: Callable, iterations: int = 1000, 
                 warmup: int = 10) -> Dict[str, float]:
        """Benchmark a function"""
        # Warmup
        for _ in range(warmup):
            func()
            
        # Actual benchmark
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            func()
            end = time.perf_counter()
            times.append(end - start)
            
        times.sort()
        
        return {
            "min": times[0],
            "max": times[-1],
            "mean": sum(times) / len(times),
            "median": times[len(times) // 2],
            "p95": times[int(len(times) * 0.95)],
            "p99": times[int(len(times) * 0.99)],
            "iterations": iterations
        }
        
    def load_test(self, func: Callable, duration: int = 60, 
                 concurrent_users: int = 10) -> Dict[str, Any]:
        """Run load test"""
        start_time = time.time()
        end_time = start_time + duration
        
        results = {
            "requests": 0,
            "errors": 0,
            "response_times": []
        }
        lock = threading.Lock()
        
        def worker():
            while time.time() < end_time:
                request_start = time.time()
                try:
                    func()
                    response_time = time.time() - request_start
                    with lock:
                        results["requests"] += 1
                        results["response_times"].append(response_time)
                except Exception:
                    with lock:
                        results["errors"] += 1
                        
        # Start workers
        threads = []
        for _ in range(concurrent_users):
            thread = threading.Thread(target=worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)
            
        # Wait for completion
        for thread in threads:
            thread.join()
            
        # Calculate statistics
        total_time = time.time() - start_time
        response_times = results["response_times"]
        
        if response_times:
            response_times.sort()
            stats = {
                "total_requests": results["requests"],
                "total_errors": results["errors"],
                "error_rate": (results["errors"] / results["requests"] * 100) 
                             if results["requests"] > 0 else 0,
                "requests_per_second": results["requests"] / total_time,
                "min_response_time": response_times[0],
                "max_response_time": response_times[-1],
                "mean_response_time": sum(response_times) / len(response_times),
                "median_response_time": response_times[len(response_times) // 2],
                "p95_response_time": response_times[int(len(response_times) * 0.95)],
                "p99_response_time": response_times[int(len(response_times) * 0.99)],
                "concurrent_users": concurrent_users,
                "test_duration": total_time
            }
        else:
            stats = {
                "total_requests": 0,
                "total_errors": results["errors"],
                "error_rate": 100,
                "requests_per_second": 0
            }
            
        return stats


class SecurityTester:
    """Security testing utilities"""
    
    def __init__(self):
        self.vulnerabilities = []
        
    def test_sql_injection(self, func: Callable, param_name: str) -> List[Dict[str, Any]]:
        """Test for SQL injection vulnerabilities"""
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1' UNION SELECT * FROM users--",
            "admin'--",
            "' OR 1=1--"
        ]
        
        vulnerabilities = []
        
        for payload in payloads:
            try:
                result = func(**{param_name: payload})
                # Check if payload was properly escaped
                if self._contains_sql_error(result):
                    vulnerabilities.append({
                        "type": "SQL Injection",
                        "parameter": param_name,
                        "payload": payload,
                        "severity": "HIGH"
                    })
            except Exception as e:
                if self._contains_sql_error(str(e)):
                    vulnerabilities.append({
                        "type": "SQL Injection",
                        "parameter": param_name,
                        "payload": payload,
                        "severity": "HIGH",
                        "error": str(e)
                    })
                    
        return vulnerabilities
        
    def test_xss(self, func: Callable, param_name: str) -> List[Dict[str, Any]]:
        """Test for XSS vulnerabilities"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>"
        ]
        
        vulnerabilities = []
        
        for payload in payloads:
            try:
                result = func(**{param_name: payload})
                # Check if payload was properly escaped
                if payload in str(result):
                    vulnerabilities.append({
                        "type": "XSS",
                        "parameter": param_name,
                        "payload": payload,
                        "severity": "MEDIUM"
                    })
            except Exception:
                pass
                
        return vulnerabilities
        
    def _contains_sql_error(self, text: str) -> bool:
        """Check if text contains SQL error indicators"""
        sql_errors = [
            "sql syntax",
            "mysql_fetch",
            "ORA-",
            "PostgreSQL",
            "SQLite",
            "Microsoft SQL Server"
        ]
        
        text_lower = str(text).lower()
        return any(error.lower() in text_lower for error in sql_errors)


class TestingFramework:
    """Complete testing framework"""
    
    def __init__(self):
        self.runner = TestRunner()
        self.generator = TestGenerator()
        self.performance_tester = PerformanceTester()
        self.security_tester = SecurityTester()
        
    def create_test(self, name: str, test_type: TestType = TestType.UNIT):
        """Decorator to create a test"""
        def decorator(func):
            test_id = hashlib.md5(name.encode()).hexdigest()[:8]
            test_case = TestCase(
                id=test_id,
                name=name,
                description=func.__doc__ or "",
                test_type=test_type,
                function=func
            )
            self.runner.register_test(test_case)
            return func
        return decorator
        
    def create_suite(self, name: str, parallel: bool = False):
        """Create a test suite"""
        suite_id = hashlib.md5(name.encode()).hexdigest()[:8]
        suite = TestSuite(
            id=suite_id,
            name=name,
            description="",
            parallel=parallel
        )
        self.runner.register_suite(suite)
        return suite
        
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all registered tests"""
        results = []
        for test_id in self.runner.test_cases:
            result = self.runner.run_test(test_id)
            results.append(result)
            
        return self.runner.get_summary()
        
    def run_suite(self, suite_name: str) -> Dict[str, Any]:
        """Run a specific test suite"""
        suite_id = hashlib.md5(suite_name.encode()).hexdigest()[:8]
        self.runner.run_suite(suite_id)
        return self.runner.get_summary()
        
    def generate_report(self) -> str:
        """Generate test report"""
        summary = self.runner.get_summary()
        results = self.runner.get_results()
        
        report = []
        report.append("=" * 60)
        report.append("TEST EXECUTION REPORT")
        report.append("=" * 60)
        report.append(f"Total Tests: {summary['total']}")
        report.append(f"Passed: {summary['passed']}")
        report.append(f"Failed: {summary['failed']}")
        report.append(f"Skipped: {summary['skipped']}")
        report.append(f"Errors: {summary['errors']}")
        report.append(f"Pass Rate: {summary['pass_rate']:.2f}%")
        report.append(f"Total Time: {summary['total_execution_time']:.2f}s")
        report.append("")
        
        # Failed tests details
        failed_tests = [r for r in results if r.status in [TestStatus.FAILED, TestStatus.ERROR]]
        if failed_tests:
            report.append("FAILED TESTS:")
            report.append("-" * 40)
            for result in failed_tests:
                report.append(f"Test: {result.test_id}")
                report.append(f"Status: {result.status.value}")
                report.append(f"Message: {result.message}")
                if result.error:
                    report.append(f"Error: {result.error}")
                report.append("")
                
        return "\n".join(report)


# Global testing framework instance
testing = TestingFramework()


def get_testing_framework() -> TestingFramework:
    """Get the global testing framework instance"""
    return testing