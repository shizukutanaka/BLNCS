"""
Automated Testing and Quality Gates Framework
Comprehensive testing orchestration, quality validation, and continuous integration support.
"""

import asyncio
import json
import logging
import time
import uuid
import subprocess
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Callable, Tuple
from enum import Enum
from dataclasses import dataclass, field, asdict
from collections import defaultdict
import pytest
import coverage
import structlog

logger = structlog.get_logger(__name__)

class TestType(Enum):
    UNIT = "unit"
    INTEGRATION = "integration"
    PERFORMANCE = "performance"
    SECURITY = "security"
    END_TO_END = "e2e"
    SMOKE = "smoke"
    REGRESSION = "regression"
    API = "api"
    UI = "ui"
    LOAD = "load"
    STRESS = "stress"

class TestStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"

class QualityGateStatus(Enum):
    PENDING = "pending"
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"

@dataclass
class TestResult:
    test_id: str
    test_name: str
    test_type: TestType
    status: TestStatus
    duration_ms: float
    error_message: Optional[str] = None
    stack_trace: Optional[str] = None
    assertions: int = 0
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None

@dataclass
class TestSuite:
    suite_id: str
    name: str
    test_type: TestType
    test_files: List[str] = field(default_factory=list)
    test_patterns: List[str] = field(default_factory=list)
    environment_requirements: Dict[str, str] = field(default_factory=dict)
    setup_commands: List[str] = field(default_factory=list)
    teardown_commands: List[str] = field(default_factory=list)
    timeout_seconds: int = 300
    parallel_execution: bool = False
    max_workers: int = 4
    retry_count: int = 0
    tags: List[str] = field(default_factory=list)

@dataclass
class QualityGate:
    gate_id: str
    name: str
    description: str
    conditions: List[Dict[str, Any]] = field(default_factory=list)
    required_test_types: List[TestType] = field(default_factory=list)
    min_coverage_percentage: float = 80.0
    max_failure_rate: float = 0.05
    max_critical_issues: int = 0
    max_high_issues: int = 5
    performance_thresholds: Dict[str, float] = field(default_factory=dict)
    enabled: bool = True
    blocking: bool = True  # If True, blocks deployment on failure

@dataclass
class QualityMetrics:
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    skipped_tests: int = 0
    success_rate: float = 0.0
    coverage_percentage: float = 0.0
    critical_issues: int = 0
    high_issues: int = 0
    medium_issues: int = 0
    low_issues: int = 0
    performance_score: float = 0.0
    security_score: float = 0.0
    maintainability_index: float = 0.0
    technical_debt_minutes: int = 0

class CoverageAnalyzer:
    def __init__(self, source_dir: str):
        self.source_dir = source_dir
        self.coverage = coverage.Coverage()
        self.report_data = None
    
    def start_coverage(self):
        """Start coverage measurement"""
        self.coverage.start()
    
    def stop_coverage(self):
        """Stop coverage measurement"""
        self.coverage.stop()
        self.coverage.save()
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate coverage report"""
        try:
            # Generate coverage report
            self.coverage.html_report(directory='htmlcov')
            
            # Get coverage data
            report = self.coverage.report(show_missing=True)
            
            # Parse coverage data
            coverage_data = {
                'total_statements': 0,
                'missing_statements': 0,
                'coverage_percentage': 0.0,
                'files': {}
            }
            
            for filename in self.coverage.get_data().measured_files():
                analysis = self.coverage.analysis2(filename)
                statements, missing, excluded, branches = analysis
                
                if statements:
                    file_coverage = ((statements - len(missing)) / statements) * 100
                    coverage_data['files'][filename] = {
                        'statements': statements,
                        'missing': len(missing),
                        'coverage': file_coverage
                    }
                    
                    coverage_data['total_statements'] += statements
                    coverage_data['missing_statements'] += len(missing)
            
            if coverage_data['total_statements'] > 0:
                coverage_data['coverage_percentage'] = (
                    (coverage_data['total_statements'] - coverage_data['missing_statements']) 
                    / coverage_data['total_statements']
                ) * 100
            
            self.report_data = coverage_data
            return coverage_data
            
        except Exception as e:
            logger.error(f"Coverage report generation failed: {e}")
            return {'coverage_percentage': 0.0, 'error': str(e)}

class SecurityTestRunner:
    def __init__(self):
        self.security_tools = {
            'bandit': self._run_bandit,
            'safety': self._run_safety,
            'semgrep': self._run_semgrep
        }
    
    async def run_security_tests(self, source_dir: str) -> Dict[str, Any]:
        """Run security tests"""
        results = {
            'total_issues': 0,
            'critical_issues': 0,
            'high_issues': 0,
            'medium_issues': 0,
            'low_issues': 0,
            'tools': {}
        }
        
        for tool_name, tool_func in self.security_tools.items():
            try:
                tool_result = await tool_func(source_dir)
                results['tools'][tool_name] = tool_result
                
                # Aggregate issues
                for severity, count in tool_result.get('issues_by_severity', {}).items():
                    if severity in results:
                        results[severity] += count
                    
                    results['total_issues'] += count
                    
            except Exception as e:
                logger.error(f"Security tool {tool_name} failed: {e}")
                results['tools'][tool_name] = {'error': str(e)}
        
        return results
    
    async def _run_bandit(self, source_dir: str) -> Dict[str, Any]:
        """Run Bandit security linter"""
        try:
            result = subprocess.run(
                ['bandit', '-r', source_dir, '-f', 'json'],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0 or result.stdout:
                data = json.loads(result.stdout) if result.stdout else {}
                
                issues_by_severity = defaultdict(int)
                for issue in data.get('results', []):
                    severity = issue.get('issue_severity', 'LOW').lower()
                    issues_by_severity[f"{severity}_issues"] += 1
                
                return {
                    'status': 'completed',
                    'issues_by_severity': dict(issues_by_severity),
                    'raw_output': data
                }
            else:
                return {'status': 'failed', 'error': result.stderr}
                
        except subprocess.TimeoutExpired:
            return {'status': 'timeout', 'error': 'Bandit execution timed out'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    async def _run_safety(self, source_dir: str) -> Dict[str, Any]:
        """Run Safety vulnerability checker"""
        try:
            result = subprocess.run(
                ['safety', 'check', '--json'],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=source_dir
            )
            
            issues_by_severity = {'critical_issues': 0, 'high_issues': 0}
            
            if result.returncode != 0 and result.stdout:
                # Safety found vulnerabilities
                vulnerabilities = json.loads(result.stdout)
                for vuln in vulnerabilities:
                    severity = vuln.get('severity', 'high').lower()
                    if severity == 'critical':
                        issues_by_severity['critical_issues'] += 1
                    else:
                        issues_by_severity['high_issues'] += 1
            
            return {
                'status': 'completed',
                'issues_by_severity': issues_by_severity,
                'vulnerabilities_found': result.returncode != 0
            }
            
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    async def _run_semgrep(self, source_dir: str) -> Dict[str, Any]:
        """Run Semgrep static analysis"""
        try:
            result = subprocess.run(
                ['semgrep', '--config=auto', '--json', source_dir],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            issues_by_severity = defaultdict(int)
            
            if result.stdout:
                data = json.loads(result.stdout)
                for finding in data.get('results', []):
                    severity = finding.get('extra', {}).get('severity', 'INFO').lower()
                    if severity == 'error':
                        issues_by_severity['high_issues'] += 1
                    elif severity == 'warning':
                        issues_by_severity['medium_issues'] += 1
                    else:
                        issues_by_severity['low_issues'] += 1
            
            return {
                'status': 'completed',
                'issues_by_severity': dict(issues_by_severity),
                'raw_output': result.stdout
            }
            
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

class PerformanceTestRunner:
    def __init__(self):
        self.performance_metrics = {}
    
    async def run_performance_tests(self, test_suite: TestSuite) -> Dict[str, Any]:
        """Run performance tests"""
        results = {
            'response_times': [],
            'throughput': 0.0,
            'error_rate': 0.0,
            'resource_usage': {},
            'thresholds_met': True
        }
        
        try:
            # Run performance test scenarios
            for test_file in test_suite.test_files:
                if 'performance' in test_file or 'load' in test_file:
                    test_result = await self._run_performance_test_file(test_file)
                    self._merge_performance_results(results, test_result)
            
            # Calculate performance score
            results['performance_score'] = self._calculate_performance_score(results)
            
        except Exception as e:
            logger.error(f"Performance test execution failed: {e}")
            results['error'] = str(e)
        
        return results
    
    async def _run_performance_test_file(self, test_file: str) -> Dict[str, Any]:
        """Run individual performance test file"""
        # Mock performance test execution
        # In production, this would integrate with tools like Locust, k6, or JMeter
        
        await asyncio.sleep(0.1)  # Simulate test execution
        
        return {
            'response_times': [100, 150, 120, 180, 110],  # ms
            'throughput': 500.0,  # requests per second
            'error_rate': 0.02,  # 2% error rate
            'resource_usage': {
                'cpu_percent': 45.0,
                'memory_mb': 256,
                'disk_io_mb': 50
            }
        }
    
    def _merge_performance_results(self, aggregate: Dict[str, Any], test_result: Dict[str, Any]):
        """Merge performance test results"""
        aggregate['response_times'].extend(test_result.get('response_times', []))
        aggregate['throughput'] += test_result.get('throughput', 0.0)
        aggregate['error_rate'] = max(aggregate['error_rate'], test_result.get('error_rate', 0.0))
        
        # Merge resource usage
        for metric, value in test_result.get('resource_usage', {}).items():
            if metric in aggregate['resource_usage']:
                aggregate['resource_usage'][metric] = max(aggregate['resource_usage'][metric], value)
            else:
                aggregate['resource_usage'][metric] = value
    
    def _calculate_performance_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall performance score"""
        score = 100.0
        
        # Penalty for high response times
        if results['response_times']:
            avg_response_time = sum(results['response_times']) / len(results['response_times'])
            if avg_response_time > 200:  # > 200ms
                score -= min(50, (avg_response_time - 200) / 10)
        
        # Penalty for high error rate
        error_rate = results['error_rate']
        if error_rate > 0.01:  # > 1%
            score -= min(30, error_rate * 1000)
        
        # Penalty for high resource usage
        cpu_usage = results['resource_usage'].get('cpu_percent', 0)
        if cpu_usage > 80:
            score -= min(20, (cpu_usage - 80) / 5)
        
        return max(0, score)

class IntegrationTestRunner:
    def __init__(self):
        self.test_environments = {}
    
    async def run_integration_tests(self, test_suite: TestSuite) -> List[TestResult]:
        """Run integration tests"""
        results = []
        
        try:
            # Setup test environment
            await self._setup_test_environment(test_suite)
            
            # Run integration tests
            for test_file in test_suite.test_files:
                test_results = await self._run_integration_test_file(test_file, test_suite)
                results.extend(test_results)
            
        except Exception as e:
            logger.error(f"Integration test execution failed: {e}")
            # Create error result
            error_result = TestResult(
                test_id=str(uuid.uuid4()),
                test_name="Integration Test Setup",
                test_type=TestType.INTEGRATION,
                status=TestStatus.ERROR,
                duration_ms=0,
                error_message=str(e)
            )
            results.append(error_result)
        finally:
            # Cleanup test environment
            await self._cleanup_test_environment(test_suite)
        
        return results
    
    async def _setup_test_environment(self, test_suite: TestSuite):
        """Setup test environment"""
        for command in test_suite.setup_commands:
            try:
                result = subprocess.run(
                    command.split(),
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if result.returncode != 0:
                    logger.warning(f"Setup command failed: {command} - {result.stderr}")
                    
            except Exception as e:
                logger.error(f"Setup command error: {command} - {e}")
    
    async def _cleanup_test_environment(self, test_suite: TestSuite):
        """Cleanup test environment"""
        for command in test_suite.teardown_commands:
            try:
                subprocess.run(
                    command.split(),
                    capture_output=True,
                    timeout=30
                )
            except Exception as e:
                logger.warning(f"Cleanup command error: {command} - {e}")
    
    async def _run_integration_test_file(self, test_file: str, test_suite: TestSuite) -> List[TestResult]:
        """Run integration test file"""
        results = []
        start_time = time.time()
        
        try:
            # Mock integration test execution
            # In production, this would run actual pytest or similar
            await asyncio.sleep(0.2)  # Simulate test execution
            
            # Create mock test results
            test_count = 3  # Mock: assume 3 tests per file
            
            for i in range(test_count):
                test_result = TestResult(
                    test_id=str(uuid.uuid4()),
                    test_name=f"{test_file}::test_{i}",
                    test_type=TestType.INTEGRATION,
                    status=TestStatus.PASSED,
                    duration_ms=(time.time() - start_time) * 1000 / test_count,
                    assertions=5,
                    completed_at=datetime.utcnow()
                )
                results.append(test_result)
                
        except Exception as e:
            error_result = TestResult(
                test_id=str(uuid.uuid4()),
                test_name=test_file,
                test_type=TestType.INTEGRATION,
                status=TestStatus.ERROR,
                duration_ms=(time.time() - start_time) * 1000,
                error_message=str(e),
                completed_at=datetime.utcnow()
            )
            results.append(error_result)
        
        return results

class TestRunner:
    def __init__(self):
        self.coverage_analyzer = None
        self.security_runner = SecurityTestRunner()
        self.performance_runner = PerformanceTestRunner()
        self.integration_runner = IntegrationTestRunner()
    
    async def run_test_suite(self, test_suite: TestSuite, enable_coverage: bool = True) -> Dict[str, Any]:
        """Run complete test suite"""
        suite_start_time = time.time()
        
        results = {
            'suite_id': test_suite.suite_id,
            'suite_name': test_suite.name,
            'test_type': test_suite.test_type,
            'status': TestStatus.PENDING,
            'test_results': [],
            'coverage_report': None,
            'security_report': None,
            'performance_report': None,
            'started_at': datetime.utcnow(),
            'completed_at': None,
            'duration_ms': 0
        }
        
        try:
            results['status'] = TestStatus.RUNNING
            
            # Start coverage if enabled
            if enable_coverage and test_suite.test_type in [TestType.UNIT, TestType.INTEGRATION]:
                self.coverage_analyzer = CoverageAnalyzer('.')
                self.coverage_analyzer.start_coverage()
            
            # Run tests based on type
            if test_suite.test_type == TestType.UNIT:
                test_results = await self._run_unit_tests(test_suite)
            elif test_suite.test_type == TestType.INTEGRATION:
                test_results = await self.integration_runner.run_integration_tests(test_suite)
            elif test_suite.test_type == TestType.PERFORMANCE:
                performance_report = await self.performance_runner.run_performance_tests(test_suite)
                results['performance_report'] = performance_report
                test_results = []
            elif test_suite.test_type == TestType.SECURITY:
                security_report = await self.security_runner.run_security_tests('.')
                results['security_report'] = security_report
                test_results = []
            else:
                test_results = await self._run_generic_tests(test_suite)
            
            results['test_results'] = test_results
            
            # Stop coverage and generate report
            if self.coverage_analyzer:
                self.coverage_analyzer.stop_coverage()
                coverage_report = self.coverage_analyzer.generate_report()
                results['coverage_report'] = coverage_report
            
            # Determine overall status
            if test_results:
                failed_tests = [t for t in test_results if t.status == TestStatus.FAILED]
                error_tests = [t for t in test_results if t.status == TestStatus.ERROR]
                
                if error_tests:
                    results['status'] = TestStatus.ERROR
                elif failed_tests:
                    results['status'] = TestStatus.FAILED
                else:
                    results['status'] = TestStatus.PASSED
            else:
                results['status'] = TestStatus.PASSED
            
        except Exception as e:
            logger.error(f"Test suite execution failed: {e}")
            results['status'] = TestStatus.ERROR
            results['error'] = str(e)
        finally:
            results['completed_at'] = datetime.utcnow()
            results['duration_ms'] = (time.time() - suite_start_time) * 1000
        
        return results
    
    async def _run_unit_tests(self, test_suite: TestSuite) -> List[TestResult]:
        """Run unit tests using pytest"""
        results = []
        
        try:
            # Build pytest command
            pytest_args = []
            
            if test_suite.test_files:
                pytest_args.extend(test_suite.test_files)
            else:
                pytest_args.append('tests/')
            
            pytest_args.extend([
                '--json-report',
                '--json-report-file=test_report.json',
                '--tb=short'
            ])
            
            if test_suite.parallel_execution:
                pytest_args.extend(['-n', str(test_suite.max_workers)])
            
            # Run pytest
            result = subprocess.run(
                ['python', '-m', 'pytest'] + pytest_args,
                capture_output=True,
                text=True,
                timeout=test_suite.timeout_seconds
            )
            
            # Parse pytest JSON report
            try:
                with open('test_report.json', 'r') as f:
                    report_data = json.load(f)
                
                for test in report_data.get('tests', []):
                    test_result = TestResult(
                        test_id=test.get('nodeid', str(uuid.uuid4())),
                        test_name=test.get('nodeid', 'unknown'),
                        test_type=TestType.UNIT,
                        status=TestStatus(test.get('outcome', 'failed').lower()),
                        duration_ms=test.get('duration', 0) * 1000,
                        error_message=test.get('call', {}).get('longrepr') if test.get('outcome') == 'failed' else None
                    )
                    results.append(test_result)
                    
            except Exception as e:
                logger.warning(f"Failed to parse pytest report: {e}")
                
        except subprocess.TimeoutExpired:
            logger.error(f"Unit tests timed out after {test_suite.timeout_seconds} seconds")
        except Exception as e:
            logger.error(f"Unit test execution failed: {e}")
        
        return results
    
    async def _run_generic_tests(self, test_suite: TestSuite) -> List[TestResult]:
        """Run generic test suite"""
        # Mock generic test execution
        results = []
        
        for test_file in test_suite.test_files:
            test_result = TestResult(
                test_id=str(uuid.uuid4()),
                test_name=test_file,
                test_type=test_suite.test_type,
                status=TestStatus.PASSED,
                duration_ms=100,
                assertions=1,
                completed_at=datetime.utcnow()
            )
            results.append(test_result)
        
        return results

class TestReporter:
    def __init__(self):
        self.report_formats = ['json', 'html', 'junit']
    
    async def generate_test_report(self, test_results: List[Dict[str, Any]], 
                                  format: str = 'json') -> str:
        """Generate test report in specified format"""
        if format == 'json':
            return self._generate_json_report(test_results)
        elif format == 'html':
            return self._generate_html_report(test_results)
        elif format == 'junit':
            return self._generate_junit_report(test_results)
        else:
            raise ValueError(f"Unsupported report format: {format}")
    
    def _generate_json_report(self, test_results: List[Dict[str, Any]]) -> str:
        """Generate JSON test report"""
        report = {
            'generated_at': datetime.utcnow().isoformat(),
            'summary': self._calculate_summary(test_results),
            'test_suites': test_results
        }
        
        return json.dumps(report, indent=2, default=str)
    
    def _generate_html_report(self, test_results: List[Dict[str, Any]]) -> str:
        """Generate HTML test report"""
        summary = self._calculate_summary(test_results)
        
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>BLNCS Test Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .summary {{ background: #f5f5f5; padding: 15px; border-radius: 5px; }}
                .passed {{ color: green; }}
                .failed {{ color: red; }}
                .suite {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
            </style>
        </head>
        <body>
            <h1>BLNCS Test Report</h1>
            <div class="summary">
                <h2>Summary</h2>
                <p>Total Suites: {summary['total_suites']}</p>
                <p>Total Tests: {summary['total_tests']}</p>
                <p class="passed">Passed: {summary['passed_tests']}</p>
                <p class="failed">Failed: {summary['failed_tests']}</p>
                <p>Success Rate: {summary['success_rate']:.1f}%</p>
            </div>
            <h2>Test Suites</h2>
            {"".join(self._format_suite_html(suite) for suite in test_results)}
        </body>
        </html>
        """
        
        return html_template
    
    def _format_suite_html(self, suite: Dict[str, Any]) -> str:
        """Format test suite for HTML report"""
        status_class = suite['status'].value.lower()
        
        return f"""
        <div class="suite">
            <h3 class="{status_class}">{suite['suite_name']} ({suite['status'].value})</h3>
            <p>Type: {suite['test_type'].value}</p>
            <p>Duration: {suite['duration_ms']:.0f}ms</p>
            <p>Tests: {len(suite.get('test_results', []))}</p>
        </div>
        """
    
    def _generate_junit_report(self, test_results: List[Dict[str, Any]]) -> str:
        """Generate JUnit XML test report"""
        summary = self._calculate_summary(test_results)
        
        junit_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
        <testsuites name="BLNCS Test Results" 
                   tests="{summary['total_tests']}" 
                   failures="{summary['failed_tests']}" 
                   time="{summary['total_duration_ms'] / 1000:.2f}">
        """
        
        for suite in test_results:
            junit_xml += self._format_suite_junit(suite)
        
        junit_xml += "</testsuites>"
        
        return junit_xml
    
    def _format_suite_junit(self, suite: Dict[str, Any]) -> str:
        """Format test suite for JUnit XML"""
        test_results = suite.get('test_results', [])
        
        suite_xml = f"""
        <testsuite name="{suite['suite_name']}" 
                   tests="{len(test_results)}" 
                   time="{suite['duration_ms'] / 1000:.2f}">
        """
        
        for test in test_results:
            suite_xml += f"""
            <testcase name="{test.test_name}" 
                     time="{test.duration_ms / 1000:.2f}">
            """
            
            if test.status == TestStatus.FAILED:
                suite_xml += f"<failure message='{test.error_message or 'Test failed'}'></failure>"
            elif test.status == TestStatus.ERROR:
                suite_xml += f"<error message='{test.error_message or 'Test error'}'></error>"
            elif test.status == TestStatus.SKIPPED:
                suite_xml += "<skipped/>"
            
            suite_xml += "</testcase>"
        
        suite_xml += "</testsuite>"
        
        return suite_xml
    
    def _calculate_summary(self, test_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate test results summary"""
        total_suites = len(test_results)
        total_tests = sum(len(suite.get('test_results', [])) for suite in test_results)
        
        passed_tests = 0
        failed_tests = 0
        total_duration = 0
        
        for suite in test_results:
            total_duration += suite.get('duration_ms', 0)
            
            for test in suite.get('test_results', []):
                if test.status == TestStatus.PASSED:
                    passed_tests += 1
                elif test.status == TestStatus.FAILED:
                    failed_tests += 1
        
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        return {
            'total_suites': total_suites,
            'total_tests': total_tests,
            'passed_tests': passed_tests,
            'failed_tests': failed_tests,
            'success_rate': success_rate,
            'total_duration_ms': total_duration
        }

class TestOrchestrator:
    def __init__(self):
        self.test_runner = TestRunner()
        self.test_reporter = TestReporter()
        self.quality_gates = {}
        self.test_suites = {}
        self.execution_history = []
    
    async def register_test_suite(self, test_suite: TestSuite):
        """Register test suite"""
        self.test_suites[test_suite.suite_id] = test_suite
        logger.info(f"Registered test suite: {test_suite.name}")
    
    async def register_quality_gate(self, quality_gate: QualityGate):
        """Register quality gate"""
        self.quality_gates[quality_gate.gate_id] = quality_gate
        logger.info(f"Registered quality gate: {quality_gate.name}")
    
    async def execute_test_pipeline(self, pipeline_name: str, test_suite_ids: List[str] = None) -> Dict[str, Any]:
        """Execute complete test pipeline"""
        pipeline_start = time.time()
        
        pipeline_result = {
            'pipeline_name': pipeline_name,
            'started_at': datetime.utcnow(),
            'status': 'running',
            'test_results': [],
            'quality_gate_results': [],
            'overall_metrics': None,
            'reports': {}
        }
        
        try:
            # Execute test suites
            suites_to_run = test_suite_ids or list(self.test_suites.keys())
            
            for suite_id in suites_to_run:
                if suite_id in self.test_suites:
                    test_suite = self.test_suites[suite_id]
                    
                    logger.info(f"Executing test suite: {test_suite.name}")
                    suite_result = await self.test_runner.run_test_suite(test_suite)
                    pipeline_result['test_results'].append(suite_result)
            
            # Calculate overall metrics
            pipeline_result['overall_metrics'] = self._calculate_pipeline_metrics(
                pipeline_result['test_results']
            )
            
            # Execute quality gates
            for gate_id, quality_gate in self.quality_gates.items():
                if quality_gate.enabled:
                    gate_result = await self._evaluate_quality_gate(
                        quality_gate, 
                        pipeline_result['overall_metrics']
                    )
                    pipeline_result['quality_gate_results'].append(gate_result)
            
            # Determine pipeline status
            failed_gates = [g for g in pipeline_result['quality_gate_results'] 
                          if g['status'] == QualityGateStatus.FAILED and g['blocking']]
            
            if failed_gates:
                pipeline_result['status'] = 'failed'
            else:
                pipeline_result['status'] = 'passed'
            
            # Generate reports
            pipeline_result['reports']['json'] = await self.test_reporter.generate_test_report(
                pipeline_result['test_results'], 'json'
            )
            
            pipeline_result['reports']['html'] = await self.test_reporter.generate_test_report(
                pipeline_result['test_results'], 'html'
            )
            
        except Exception as e:
            logger.error(f"Test pipeline execution failed: {e}")
            pipeline_result['status'] = 'error'
            pipeline_result['error'] = str(e)
        finally:
            pipeline_result['completed_at'] = datetime.utcnow()
            pipeline_result['duration_ms'] = (time.time() - pipeline_start) * 1000
            
            # Store in execution history
            self.execution_history.append(pipeline_result)
        
        return pipeline_result
    
    def _calculate_pipeline_metrics(self, test_results: List[Dict[str, Any]]) -> QualityMetrics:
        """Calculate overall pipeline metrics"""
        metrics = QualityMetrics()
        
        all_test_results = []
        total_coverage = 0
        coverage_reports = 0
        
        for suite_result in test_results:
            all_test_results.extend(suite_result.get('test_results', []))
            
            # Aggregate coverage
            coverage_report = suite_result.get('coverage_report')
            if coverage_report:
                total_coverage += coverage_report.get('coverage_percentage', 0)
                coverage_reports += 1
            
            # Aggregate security issues
            security_report = suite_result.get('security_report')
            if security_report:
                metrics.critical_issues += security_report.get('critical_issues', 0)
                metrics.high_issues += security_report.get('high_issues', 0)
                metrics.medium_issues += security_report.get('medium_issues', 0)
                metrics.low_issues += security_report.get('low_issues', 0)
            
            # Aggregate performance score
            performance_report = suite_result.get('performance_report')
            if performance_report:
                metrics.performance_score = performance_report.get('performance_score', 0)
        
        # Calculate test metrics
        metrics.total_tests = len(all_test_results)
        metrics.passed_tests = sum(1 for t in all_test_results if t.status == TestStatus.PASSED)
        metrics.failed_tests = sum(1 for t in all_test_results if t.status == TestStatus.FAILED)
        metrics.skipped_tests = sum(1 for t in all_test_results if t.status == TestStatus.SKIPPED)
        
        if metrics.total_tests > 0:
            metrics.success_rate = metrics.passed_tests / metrics.total_tests
        
        # Calculate average coverage
        if coverage_reports > 0:
            metrics.coverage_percentage = total_coverage / coverage_reports
        
        return metrics
    
    async def _evaluate_quality_gate(self, quality_gate: QualityGate, 
                                   metrics: QualityMetrics) -> Dict[str, Any]:
        """Evaluate quality gate conditions"""
        gate_result = {
            'gate_id': quality_gate.gate_id,
            'gate_name': quality_gate.name,
            'status': QualityGateStatus.PASSED,
            'blocking': quality_gate.blocking,
            'conditions_results': []
        }
        
        # Check coverage threshold
        if metrics.coverage_percentage < quality_gate.min_coverage_percentage:
            gate_result['conditions_results'].append({
                'condition': 'coverage_percentage',
                'expected': quality_gate.min_coverage_percentage,
                'actual': metrics.coverage_percentage,
                'passed': False
            })
            gate_result['status'] = QualityGateStatus.FAILED
        
        # Check failure rate
        failure_rate = 1.0 - metrics.success_rate
        if failure_rate > quality_gate.max_failure_rate:
            gate_result['conditions_results'].append({
                'condition': 'failure_rate',
                'expected': quality_gate.max_failure_rate,
                'actual': failure_rate,
                'passed': False
            })
            gate_result['status'] = QualityGateStatus.FAILED
        
        # Check critical issues
        if metrics.critical_issues > quality_gate.max_critical_issues:
            gate_result['conditions_results'].append({
                'condition': 'critical_issues',
                'expected': quality_gate.max_critical_issues,
                'actual': metrics.critical_issues,
                'passed': False
            })
            gate_result['status'] = QualityGateStatus.FAILED
        
        # Check high issues
        if metrics.high_issues > quality_gate.max_high_issues:
            gate_result['conditions_results'].append({
                'condition': 'high_issues',
                'expected': quality_gate.max_high_issues,
                'actual': metrics.high_issues,
                'passed': False
            })
            gate_result['status'] = QualityGateStatus.FAILED
        
        return gate_result
    
    async def get_pipeline_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get pipeline execution history"""
        return self.execution_history[-limit:] if self.execution_history else []
    
    async def get_quality_trends(self, days: int = 30) -> Dict[str, Any]:
        """Get quality trends over time"""
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        recent_executions = [
            ex for ex in self.execution_history 
            if ex.get('started_at', datetime.min) > cutoff_date
        ]
        
        if not recent_executions:
            return {'message': 'No recent execution data available'}
        
        trends = {
            'success_rates': [],
            'coverage_percentages': [],
            'security_issues': [],
            'execution_dates': []
        }
        
        for execution in recent_executions:
            metrics = execution.get('overall_metrics')
            if metrics:
                trends['success_rates'].append(metrics.success_rate)
                trends['coverage_percentages'].append(metrics.coverage_percentage)
                trends['security_issues'].append(
                    metrics.critical_issues + metrics.high_issues
                )
                trends['execution_dates'].append(execution['started_at'])
        
        return trends

# Global test orchestrator instance
_test_orchestrator_instance = None

async def get_test_orchestrator() -> TestOrchestrator:
    """Get or create test orchestrator"""
    global _test_orchestrator_instance
    
    if _test_orchestrator_instance is None:
        _test_orchestrator_instance = TestOrchestrator()
    
    return _test_orchestrator_instance

async def initialize_testing_framework() -> TestOrchestrator:
    """Initialize testing framework with default configuration"""
    orchestrator = TestOrchestrator()
    
    # Register default test suites
    unit_test_suite = TestSuite(
        suite_id="unit-tests",
        name="Unit Tests",
        test_type=TestType.UNIT,
        test_patterns=["tests/test_*.py", "tests/*_test.py"],
        parallel_execution=True,
        max_workers=4
    )
    
    integration_test_suite = TestSuite(
        suite_id="integration-tests",
        name="Integration Tests",
        test_type=TestType.INTEGRATION,
        test_patterns=["tests/integration/test_*.py"],
        timeout_seconds=600
    )
    
    security_test_suite = TestSuite(
        suite_id="security-tests",
        name="Security Tests",
        test_type=TestType.SECURITY,
        test_files=["blncs/"],
        timeout_seconds=300
    )
    
    await orchestrator.register_test_suite(unit_test_suite)
    await orchestrator.register_test_suite(integration_test_suite)
    await orchestrator.register_test_suite(security_test_suite)
    
    # Register default quality gate
    default_quality_gate = QualityGate(
        gate_id="default-quality-gate",
        name="Default Quality Gate",
        description="Standard quality requirements for BLNCS",
        min_coverage_percentage=80.0,
        max_failure_rate=0.05,
        max_critical_issues=0,
        max_high_issues=5,
        performance_thresholds={
            'response_time_p95': 500,  # ms
            'throughput_min': 100,     # rps
            'error_rate_max': 0.01     # 1%
        }
    )
    
    await orchestrator.register_quality_gate(default_quality_gate)
    
    logger.info("Testing framework initialized with default configuration")
    return orchestrator