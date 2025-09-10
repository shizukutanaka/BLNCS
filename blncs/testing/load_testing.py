"""
Enterprise Load Testing and Performance Validation Infrastructure
Comprehensive load testing for Lightning Network operations and system performance.
"""

import asyncio
import logging
import json
import time
import random
from typing import Dict, List, Optional, Any, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import statistics
import aiohttp
import websockets
from pathlib import Path

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

logger = logging.getLogger(__name__)

class LoadTestType(Enum):
    """Types of load tests."""
    STRESS = "stress"
    SPIKE = "spike"
    ENDURANCE = "endurance"
    VOLUME = "volume"
    CAPACITY = "capacity"
    SCALABILITY = "scalability"

class TestScenario(Enum):
    """Test scenarios for Lightning Network operations."""
    LIGHTNING_PAYMENTS = "lightning_payments"
    CHANNEL_OPERATIONS = "channel_operations"
    API_ENDPOINTS = "api_endpoints"
    WEBSOCKET_CONNECTIONS = "websocket_connections"
    DATABASE_OPERATIONS = "database_operations"
    MULTI_TENANT_OPERATIONS = "multi_tenant_operations"
    COMPLIANCE_CHECKS = "compliance_checks"
    BACKUP_OPERATIONS = "backup_operations"

@dataclass
class LoadProfile:
    """Load test profile configuration."""
    test_type: LoadTestType
    duration_seconds: int
    initial_users: int
    max_users: int
    ramp_up_seconds: int
    ramp_down_seconds: int
    target_rps: Optional[int] = None
    think_time_ms: int = 1000
    timeout_seconds: int = 30
    
    def get_users_at_time(self, elapsed_seconds: float) -> int:
        """Calculate number of users at given time."""
        if elapsed_seconds < 0:
            return 0
        elif elapsed_seconds < self.ramp_up_seconds:
            # Ramping up
            progress = elapsed_seconds / self.ramp_up_seconds
            return int(self.initial_users + (self.max_users - self.initial_users) * progress)
        elif elapsed_seconds < (self.duration_seconds - self.ramp_down_seconds):
            # Steady state
            return self.max_users
        elif elapsed_seconds < self.duration_seconds:
            # Ramping down
            ramp_down_start = self.duration_seconds - self.ramp_down_seconds
            progress = (elapsed_seconds - ramp_down_start) / self.ramp_down_seconds
            return int(self.max_users - (self.max_users - self.initial_users) * progress)
        else:
            return 0

@dataclass
class TestResult:
    """Individual test result."""
    request_id: str
    scenario: TestScenario
    operation: str
    start_time: datetime
    end_time: datetime
    duration_ms: float
    success: bool
    status_code: Optional[int] = None
    error_message: Optional[str] = None
    response_size: int = 0
    
    @property
    def latency_ms(self) -> float:
        """Get latency in milliseconds."""
        return self.duration_ms

@dataclass
class PerformanceMetrics:
    """Aggregated performance metrics."""
    scenario: TestScenario
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_duration_seconds: float = 0.0
    min_latency_ms: float = float('inf')
    max_latency_ms: float = 0.0
    avg_latency_ms: float = 0.0
    median_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    requests_per_second: float = 0.0
    throughput_bytes_per_second: float = 0.0
    error_rate: float = 0.0
    
    def calculate_percentiles(self, latencies: List[float]) -> None:
        """Calculate latency percentiles."""
        if not latencies:
            return
        
        sorted_latencies = sorted(latencies)
        self.min_latency_ms = sorted_latencies[0]
        self.max_latency_ms = sorted_latencies[-1]
        self.avg_latency_ms = statistics.mean(latencies)
        self.median_latency_ms = statistics.median(latencies)
        
        # Calculate percentiles
        p95_index = int(len(sorted_latencies) * 0.95)
        p99_index = int(len(sorted_latencies) * 0.99)
        
        self.p95_latency_ms = sorted_latencies[min(p95_index, len(sorted_latencies) - 1)]
        self.p99_latency_ms = sorted_latencies[min(p99_index, len(sorted_latencies) - 1)]

@dataclass
class SystemMetrics:
    """System resource metrics during testing."""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    disk_io_read_mb: float
    disk_io_write_mb: float
    network_sent_mb: float
    network_recv_mb: float
    active_connections: int
    thread_count: int

class VirtualUser:
    """Virtual user for load testing."""
    
    def __init__(self, user_id: int, scenario: TestScenario, target_url: str):
        """Initialize virtual user."""
        self.user_id = user_id
        self.scenario = scenario
        self.target_url = target_url
        self.session: Optional[aiohttp.ClientSession] = None
        self.websocket: Optional[websockets.WebSocketClientProtocol] = None
        self.results: List[TestResult] = []
        self.active = True
        
    async def start(self) -> None:
        """Start virtual user session."""
        if self.scenario == TestScenario.WEBSOCKET_CONNECTIONS:
            await self._start_websocket()
        else:
            self.session = aiohttp.ClientSession()
    
    async def _start_websocket(self) -> None:
        """Start WebSocket connection."""
        try:
            ws_url = self.target_url.replace('http://', 'ws://').replace('https://', 'wss://')
            self.websocket = await websockets.connect(ws_url)
        except Exception as e:
            logger.error(f"User {self.user_id} failed to connect WebSocket: {e}")
    
    async def execute_operation(self, operation: str, **kwargs) -> TestResult:
        """Execute a test operation."""
        request_id = f"user_{self.user_id}_{int(time.time() * 1000)}"
        start_time = datetime.utcnow()
        start_perf = time.perf_counter()
        
        success = False
        status_code = None
        error_message = None
        response_size = 0
        
        try:
            if self.scenario == TestScenario.LIGHTNING_PAYMENTS:
                success, status_code, response_size = await self._test_lightning_payment(**kwargs)
            elif self.scenario == TestScenario.CHANNEL_OPERATIONS:
                success, status_code, response_size = await self._test_channel_operation(**kwargs)
            elif self.scenario == TestScenario.API_ENDPOINTS:
                success, status_code, response_size = await self._test_api_endpoint(operation, **kwargs)
            elif self.scenario == TestScenario.WEBSOCKET_CONNECTIONS:
                success, status_code, response_size = await self._test_websocket_message(**kwargs)
            elif self.scenario == TestScenario.DATABASE_OPERATIONS:
                success, status_code, response_size = await self._test_database_operation(**kwargs)
            else:
                success, status_code, response_size = await self._test_generic_operation(**kwargs)
                
        except asyncio.TimeoutError:
            error_message = "Request timeout"
        except Exception as e:
            error_message = str(e)
        
        end_time = datetime.utcnow()
        duration_ms = (time.perf_counter() - start_perf) * 1000
        
        result = TestResult(
            request_id=request_id,
            scenario=self.scenario,
            operation=operation,
            start_time=start_time,
            end_time=end_time,
            duration_ms=duration_ms,
            success=success,
            status_code=status_code,
            error_message=error_message,
            response_size=response_size
        )
        
        self.results.append(result)
        return result
    
    async def _test_lightning_payment(self, amount_sats: int = 1000, **kwargs) -> Tuple[bool, int, int]:
        """Test Lightning payment operation."""
        if not self.session:
            return False, 0, 0
        
        payload = {
            'amount_sats': amount_sats,
            'description': f'Load test payment from user {self.user_id}',
            'invoice': f'lnbc{amount_sats}u1p{int(time.time())}'
        }
        
        try:
            async with self.session.post(
                f"{self.target_url}/api/lightning/pay",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                data = await response.read()
                return response.status == 200, response.status, len(data)
        except Exception as e:
            logger.debug(f"Lightning payment test failed: {e}")
            return False, 0, 0
    
    async def _test_channel_operation(self, operation_type: str = 'info', **kwargs) -> Tuple[bool, int, int]:
        """Test channel operation."""
        if not self.session:
            return False, 0, 0
        
        endpoint = f"{self.target_url}/api/channels/{operation_type}"
        
        try:
            async with self.session.get(
                endpoint,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                data = await response.read()
                return response.status == 200, response.status, len(data)
        except Exception as e:
            logger.debug(f"Channel operation test failed: {e}")
            return False, 0, 0
    
    async def _test_api_endpoint(self, endpoint: str, method: str = 'GET', **kwargs) -> Tuple[bool, int, int]:
        """Test generic API endpoint."""
        if not self.session:
            return False, 0, 0
        
        url = f"{self.target_url}{endpoint}"
        
        try:
            async with self.session.request(
                method,
                url,
                json=kwargs.get('payload'),
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                data = await response.read()
                return response.status < 400, response.status, len(data)
        except Exception as e:
            logger.debug(f"API endpoint test failed: {e}")
            return False, 0, 0
    
    async def _test_websocket_message(self, message: str = 'ping', **kwargs) -> Tuple[bool, int, int]:
        """Test WebSocket message."""
        if not self.websocket:
            return False, 0, 0
        
        try:
            await self.websocket.send(message)
            response = await asyncio.wait_for(self.websocket.recv(), timeout=5.0)
            return True, 200, len(response)
        except Exception as e:
            logger.debug(f"WebSocket test failed: {e}")
            return False, 0, 0
    
    async def _test_database_operation(self, operation: str = 'read', **kwargs) -> Tuple[bool, int, int]:
        """Test database operation."""
        # This would test database operations through API
        return await self._test_api_endpoint(f"/api/database/{operation}", **kwargs)
    
    async def _test_generic_operation(self, **kwargs) -> Tuple[bool, int, int]:
        """Test generic operation."""
        # Simulate generic operation
        await asyncio.sleep(random.uniform(0.01, 0.1))
        return random.random() > 0.05, 200, random.randint(100, 1000)
    
    async def stop(self) -> None:
        """Stop virtual user session."""
        self.active = False
        
        if self.session:
            await self.session.close()
        
        if self.websocket:
            await self.websocket.close()

class LoadTestRunner:
    """Enterprise load test runner."""
    
    def __init__(self, target_url: str, config: Optional[Dict[str, Any]] = None):
        """Initialize load test runner."""
        self.target_url = target_url
        self.config = config or self._get_default_config()
        
        # Test state
        self.virtual_users: List[VirtualUser] = []
        self.test_results: List[TestResult] = []
        self.system_metrics: List[SystemMetrics] = []
        self.is_running = False
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        
        # Threading
        self.executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix="loadtest")
        self.metrics_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        
        # Results directory
        self.results_dir = Path(self.config.get('results_directory', 'load_test_results'))
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Load test runner initialized for target: {target_url}")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            'results_directory': 'load_test_results',
            'metrics_interval': 1.0,  # seconds
            'max_concurrent_users': 1000,
            'connection_timeout': 30,
            'request_timeout': 30,
            'default_think_time': 1000,  # milliseconds
            'save_detailed_results': True,
            'enable_system_metrics': True
        }
    
    async def run_load_test(self, scenario: TestScenario, profile: LoadProfile) -> Dict[str, Any]:
        """Run load test with specified scenario and profile."""
        if self.is_running:
            raise RuntimeError("Load test is already running")
        
        self.is_running = True
        self.start_time = datetime.utcnow()
        self.test_results.clear()
        self.system_metrics.clear()
        self.virtual_users.clear()
        
        logger.info(f"Starting load test: {scenario.value} with {profile.test_type.value} profile")
        
        try:
            # Start system metrics collection
            if self.config.get('enable_system_metrics', True) and HAS_PSUTIL:
                self._start_metrics_collection()
            
            # Run the load test
            await self._execute_load_test(scenario, profile)
            
            # Generate results
            results = self._generate_test_results(scenario, profile)
            
            # Save results
            self._save_test_results(results)
            
            return results
            
        finally:
            self.is_running = False
            self.end_time = datetime.utcnow()
            self._stop_metrics_collection()
            
            # Cleanup virtual users
            await self._cleanup_users()
    
    async def _execute_load_test(self, scenario: TestScenario, profile: LoadProfile) -> None:
        """Execute the load test."""
        start_time = time.time()
        tasks = []
        
        while time.time() - start_time < profile.duration_seconds:
            elapsed = time.time() - start_time
            target_users = profile.get_users_at_time(elapsed)
            current_users = len(self.virtual_users)
            
            # Add users if needed
            if target_users > current_users:
                for i in range(target_users - current_users):
                    user = VirtualUser(
                        user_id=len(self.virtual_users),
                        scenario=scenario,
                        target_url=self.target_url
                    )
                    self.virtual_users.append(user)
                    
                    # Start user session
                    task = asyncio.create_task(self._run_virtual_user(user, profile))
                    tasks.append(task)
            
            # Remove users if needed
            elif target_users < current_users:
                users_to_remove = current_users - target_users
                for i in range(users_to_remove):
                    if self.virtual_users:
                        user = self.virtual_users.pop()
                        user.active = False
            
            # Small delay before next check
            await asyncio.sleep(0.1)
        
        # Wait for all tasks to complete
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _run_virtual_user(self, user: VirtualUser, profile: LoadProfile) -> None:
        """Run a virtual user session."""
        await user.start()
        
        operations = self._get_scenario_operations(user.scenario)
        
        while user.active and self.is_running:
            # Select random operation
            operation = random.choice(operations)
            
            # Execute operation
            try:
                result = await asyncio.wait_for(
                    user.execute_operation(operation),
                    timeout=profile.timeout_seconds
                )
                self.test_results.append(result)
                
            except asyncio.TimeoutError:
                logger.warning(f"User {user.user_id} operation timed out")
            except Exception as e:
                logger.error(f"User {user.user_id} operation failed: {e}")
            
            # Think time
            think_time_seconds = profile.think_time_ms / 1000.0
            await asyncio.sleep(random.uniform(think_time_seconds * 0.5, think_time_seconds * 1.5))
        
        await user.stop()
    
    def _get_scenario_operations(self, scenario: TestScenario) -> List[str]:
        """Get operations for a scenario."""
        operations_map = {
            TestScenario.LIGHTNING_PAYMENTS: ['send_payment', 'receive_payment', 'check_payment'],
            TestScenario.CHANNEL_OPERATIONS: ['open_channel', 'close_channel', 'list_channels', 'channel_info'],
            TestScenario.API_ENDPOINTS: ['/api/status', '/api/info', '/api/metrics', '/api/health'],
            TestScenario.WEBSOCKET_CONNECTIONS: ['subscribe', 'unsubscribe', 'ping', 'message'],
            TestScenario.DATABASE_OPERATIONS: ['read', 'write', 'update', 'delete'],
            TestScenario.MULTI_TENANT_OPERATIONS: ['create_tenant', 'get_tenant', 'update_quota', 'check_usage'],
            TestScenario.COMPLIANCE_CHECKS: ['kyc_check', 'aml_screening', 'transaction_monitor'],
            TestScenario.BACKUP_OPERATIONS: ['create_backup', 'verify_backup', 'list_backups']
        }
        
        return operations_map.get(scenario, ['generic_operation'])
    
    async def _cleanup_users(self) -> None:
        """Cleanup all virtual users."""
        cleanup_tasks = []
        for user in self.virtual_users:
            user.active = False
            cleanup_tasks.append(asyncio.create_task(user.stop()))
        
        if cleanup_tasks:
            await asyncio.gather(*cleanup_tasks, return_exceptions=True)
    
    def _generate_test_results(self, scenario: TestScenario, profile: LoadProfile) -> Dict[str, Any]:
        """Generate test results summary."""
        if not self.test_results:
            return {
                'error': 'No test results collected',
                'scenario': scenario.value,
                'profile': profile.test_type.value
            }
        
        # Calculate metrics
        metrics = PerformanceMetrics(scenario=scenario)
        latencies = []
        total_bytes = 0
        
        for result in self.test_results:
            metrics.total_requests += 1
            
            if result.success:
                metrics.successful_requests += 1
            else:
                metrics.failed_requests += 1
            
            latencies.append(result.latency_ms)
            total_bytes += result.response_size
        
        # Calculate statistics
        metrics.calculate_percentiles(latencies)
        
        # Calculate rates
        if self.start_time and self.end_time:
            duration_seconds = (self.end_time - self.start_time).total_seconds()
            metrics.total_duration_seconds = duration_seconds
            metrics.requests_per_second = metrics.total_requests / duration_seconds
            metrics.throughput_bytes_per_second = total_bytes / duration_seconds
        
        metrics.error_rate = (metrics.failed_requests / metrics.total_requests * 100) if metrics.total_requests > 0 else 0
        
        # System metrics summary
        system_summary = self._generate_system_metrics_summary()
        
        return {
            'test_info': {
                'scenario': scenario.value,
                'profile': profile.test_type.value,
                'duration_seconds': profile.duration_seconds,
                'max_users': profile.max_users,
                'start_time': self.start_time.isoformat() if self.start_time else None,
                'end_time': self.end_time.isoformat() if self.end_time else None
            },
            'performance_metrics': {
                'total_requests': metrics.total_requests,
                'successful_requests': metrics.successful_requests,
                'failed_requests': metrics.failed_requests,
                'error_rate_percent': metrics.error_rate,
                'requests_per_second': metrics.requests_per_second,
                'throughput_mbps': metrics.throughput_bytes_per_second / (1024 * 1024),
                'latency': {
                    'min_ms': metrics.min_latency_ms,
                    'max_ms': metrics.max_latency_ms,
                    'avg_ms': metrics.avg_latency_ms,
                    'median_ms': metrics.median_latency_ms,
                    'p95_ms': metrics.p95_latency_ms,
                    'p99_ms': metrics.p99_latency_ms
                }
            },
            'system_metrics': system_summary,
            'test_passed': self._evaluate_test_success(metrics, profile)
        }
    
    def _generate_system_metrics_summary(self) -> Dict[str, Any]:
        """Generate system metrics summary."""
        if not self.system_metrics:
            return {}
        
        cpu_values = [m.cpu_percent for m in self.system_metrics]
        memory_values = [m.memory_percent for m in self.system_metrics]
        
        return {
            'cpu': {
                'min_percent': min(cpu_values),
                'max_percent': max(cpu_values),
                'avg_percent': statistics.mean(cpu_values)
            },
            'memory': {
                'min_percent': min(memory_values),
                'max_percent': max(memory_values),
                'avg_percent': statistics.mean(memory_values)
            },
            'peak_connections': max(m.active_connections for m in self.system_metrics),
            'peak_threads': max(m.thread_count for m in self.system_metrics)
        }
    
    def _evaluate_test_success(self, metrics: PerformanceMetrics, profile: LoadProfile) -> bool:
        """Evaluate if test meets success criteria."""
        # Default success criteria
        max_error_rate = self.config.get('max_error_rate', 5.0)  # 5%
        max_p99_latency = self.config.get('max_p99_latency_ms', 5000)  # 5 seconds
        
        success = True
        
        if metrics.error_rate > max_error_rate:
            logger.warning(f"Test failed: Error rate {metrics.error_rate:.2f}% exceeds threshold {max_error_rate}%")
            success = False
        
        if metrics.p99_latency_ms > max_p99_latency:
            logger.warning(f"Test failed: P99 latency {metrics.p99_latency_ms:.0f}ms exceeds threshold {max_p99_latency}ms")
            success = False
        
        if profile.target_rps and metrics.requests_per_second < profile.target_rps * 0.9:
            logger.warning(f"Test failed: RPS {metrics.requests_per_second:.1f} below target {profile.target_rps}")
            success = False
        
        return success
    
    def _save_test_results(self, results: Dict[str, Any]) -> None:
        """Save test results to file."""
        if not self.config.get('save_detailed_results', True):
            return
        
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        scenario = results['test_info']['scenario']
        profile = results['test_info']['profile']
        
        filename = f"loadtest_{scenario}_{profile}_{timestamp}.json"
        filepath = self.results_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.info(f"Test results saved to: {filepath}")
        
        # Save detailed results if configured
        if self.config.get('save_raw_results', False):
            raw_filename = f"raw_{scenario}_{profile}_{timestamp}.jsonl"
            raw_filepath = self.results_dir / raw_filename
            
            with open(raw_filepath, 'w') as f:
                for result in self.test_results:
                    f.write(json.dumps({
                        'request_id': result.request_id,
                        'operation': result.operation,
                        'latency_ms': result.latency_ms,
                        'success': result.success,
                        'status_code': result.status_code,
                        'timestamp': result.start_time.isoformat()
                    }) + '\n')
    
    def _start_metrics_collection(self) -> None:
        """Start system metrics collection."""
        if self.metrics_thread and self.metrics_thread.is_alive():
            return
        
        self.stop_event.clear()
        self.metrics_thread = threading.Thread(
            target=self._collect_metrics_loop,
            name="metrics-collector",
            daemon=True
        )
        self.metrics_thread.start()
    
    def _stop_metrics_collection(self) -> None:
        """Stop system metrics collection."""
        if not self.metrics_thread or not self.metrics_thread.is_alive():
            return
        
        self.stop_event.set()
        self.metrics_thread.join(timeout=5.0)
    
    def _collect_metrics_loop(self) -> None:
        """Metrics collection loop."""
        if not HAS_PSUTIL:
            return
        
        interval = self.config.get('metrics_interval', 1.0)
        
        # Get initial I/O counters
        disk_io_start = psutil.disk_io_counters()
        net_io_start = psutil.net_io_counters()
        
        while not self.stop_event.is_set():
            try:
                # Collect system metrics
                cpu_percent = psutil.cpu_percent(interval=None)
                memory = psutil.virtual_memory()
                disk_io = psutil.disk_io_counters()
                net_io = psutil.net_io_counters()
                process = psutil.Process()
                
                metrics = SystemMetrics(
                    timestamp=datetime.utcnow(),
                    cpu_percent=cpu_percent,
                    memory_percent=memory.percent,
                    memory_used_mb=memory.used / (1024 * 1024),
                    disk_io_read_mb=(disk_io.read_bytes - disk_io_start.read_bytes) / (1024 * 1024),
                    disk_io_write_mb=(disk_io.write_bytes - disk_io_start.write_bytes) / (1024 * 1024),
                    network_sent_mb=(net_io.bytes_sent - net_io_start.bytes_sent) / (1024 * 1024),
                    network_recv_mb=(net_io.bytes_recv - net_io_start.bytes_recv) / (1024 * 1024),
                    active_connections=len(process.connections()),
                    thread_count=process.num_threads()
                )
                
                self.system_metrics.append(metrics)
                
                # Update start counters
                disk_io_start = disk_io
                net_io_start = net_io
                
            except Exception as e:
                logger.error(f"Error collecting system metrics: {e}")
            
            # Wait for next interval
            if self.stop_event.wait(interval):
                break
    
    async def run_benchmark_suite(self) -> Dict[str, Any]:
        """Run comprehensive benchmark suite."""
        benchmark_results = {}
        
        # Define benchmark scenarios
        benchmarks = [
            (TestScenario.LIGHTNING_PAYMENTS, LoadProfile(
                test_type=LoadTestType.STRESS,
                duration_seconds=60,
                initial_users=10,
                max_users=100,
                ramp_up_seconds=10,
                ramp_down_seconds=10,
                target_rps=50
            )),
            (TestScenario.API_ENDPOINTS, LoadProfile(
                test_type=LoadTestType.CAPACITY,
                duration_seconds=60,
                initial_users=50,
                max_users=200,
                ramp_up_seconds=20,
                ramp_down_seconds=10,
                target_rps=100
            )),
            (TestScenario.WEBSOCKET_CONNECTIONS, LoadProfile(
                test_type=LoadTestType.ENDURANCE,
                duration_seconds=120,
                initial_users=25,
                max_users=50,
                ramp_up_seconds=30,
                ramp_down_seconds=30,
                think_time_ms=5000
            ))
        ]
        
        for scenario, profile in benchmarks:
            logger.info(f"Running benchmark: {scenario.value}")
            
            try:
                results = await self.run_load_test(scenario, profile)
                benchmark_results[scenario.value] = results
                
                # Small delay between tests
                await asyncio.sleep(10)
                
            except Exception as e:
                logger.error(f"Benchmark {scenario.value} failed: {e}")
                benchmark_results[scenario.value] = {'error': str(e)}
        
        # Generate summary report
        summary = self._generate_benchmark_summary(benchmark_results)
        
        # Save benchmark report
        self._save_benchmark_report(summary)
        
        return summary
    
    def _generate_benchmark_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate benchmark summary report."""
        summary = {
            'timestamp': datetime.utcnow().isoformat(),
            'target_url': self.target_url,
            'benchmarks': {},
            'overall_score': 0.0
        }
        
        scores = []
        
        for scenario, result in results.items():
            if 'error' not in result:
                perf = result.get('performance_metrics', {})
                
                # Calculate score based on multiple factors
                score = 100.0
                
                # Deduct for errors
                error_rate = perf.get('error_rate_percent', 0)
                score -= min(error_rate * 2, 50)  # Max 50 point deduction
                
                # Deduct for high latency
                p99_latency = perf.get('latency', {}).get('p99_ms', 0)
                if p99_latency > 1000:
                    score -= min((p99_latency - 1000) / 100, 30)  # Max 30 point deduction
                
                # Bonus for high throughput
                rps = perf.get('requests_per_second', 0)
                if rps > 100:
                    score += min(rps / 100, 20)  # Max 20 point bonus
                
                score = max(0, min(100, score))
                scores.append(score)
                
                summary['benchmarks'][scenario] = {
                    'score': score,
                    'passed': result.get('test_passed', False),
                    'key_metrics': {
                        'rps': perf.get('requests_per_second', 0),
                        'error_rate': error_rate,
                        'p99_latency_ms': p99_latency
                    }
                }
        
        if scores:
            summary['overall_score'] = statistics.mean(scores)
        
        return summary
    
    def _save_benchmark_report(self, summary: Dict[str, Any]) -> None:
        """Save benchmark report."""
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"benchmark_report_{timestamp}.json"
        filepath = self.results_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        
        logger.info(f"Benchmark report saved to: {filepath}")
    
    async def shutdown(self) -> None:
        """Shutdown the load test runner."""
        logger.info("Shutting down load test runner...")
        
        self.is_running = False
        self._stop_metrics_collection()
        await self._cleanup_users()
        self.executor.shutdown(wait=True, timeout=10.0)
        
        logger.info("Load test runner shutdown complete")

# Factory functions
def create_stress_test_profile(duration_minutes: int = 5, max_users: int = 100) -> LoadProfile:
    """Create stress test profile."""
    return LoadProfile(
        test_type=LoadTestType.STRESS,
        duration_seconds=duration_minutes * 60,
        initial_users=10,
        max_users=max_users,
        ramp_up_seconds=30,
        ramp_down_seconds=30,
        think_time_ms=1000
    )

def create_spike_test_profile(duration_minutes: int = 10, spike_users: int = 500) -> LoadProfile:
    """Create spike test profile."""
    return LoadProfile(
        test_type=LoadTestType.SPIKE,
        duration_seconds=duration_minutes * 60,
        initial_users=50,
        max_users=spike_users,
        ramp_up_seconds=10,  # Quick spike
        ramp_down_seconds=10,
        think_time_ms=500
    )

def create_endurance_test_profile(duration_hours: int = 2, steady_users: int = 50) -> LoadProfile:
    """Create endurance test profile."""
    return LoadProfile(
        test_type=LoadTestType.ENDURANCE,
        duration_seconds=duration_hours * 3600,
        initial_users=steady_users,
        max_users=steady_users,
        ramp_up_seconds=60,
        ramp_down_seconds=60,
        think_time_ms=2000
    )

# Global instance
_load_test_runner: Optional[LoadTestRunner] = None

def get_load_test_runner(target_url: str) -> LoadTestRunner:
    """Get or create load test runner instance."""
    global _load_test_runner
    
    if _load_test_runner is None or _load_test_runner.target_url != target_url:
        _load_test_runner = LoadTestRunner(target_url)
    
    return _load_test_runner