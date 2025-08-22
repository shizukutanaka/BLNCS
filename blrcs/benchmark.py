# BLRCS Benchmark Module
# Performance testing and benchmarking suite
import time
import asyncio
import psutil
import statistics
from pathlib import Path
from typing import Dict, List, Any, Callable, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import json
import threading
import multiprocessing

@dataclass
class BenchmarkResult:
    """Benchmark test result"""
    name: str
    duration: float
    iterations: int
    avg_time: float
    min_time: float
    max_time: float
    median_time: float
    std_dev: float
    throughput: float
    memory_used: float
    cpu_percent: float

@dataclass
class SystemBenchmark:
    """System performance baseline"""
    cpu_single_core: float
    cpu_multi_core: float
    memory_bandwidth: float
    disk_read_speed: float
    disk_write_speed: float
    network_latency: float

class PerformanceBenchmark:
    """
    Comprehensive performance benchmarking suite.
    Tests various aspects of system and application performance.
    """
    
    def __init__(self):
        self.results: List[BenchmarkResult] = []
        self.system_info = self._get_system_info()
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information"""
        return {
            'cpu_count': psutil.cpu_count(),
            'cpu_freq': psutil.cpu_freq().current if psutil.cpu_freq() else 0,
            'memory_total': psutil.virtual_memory().total,
            'platform': psutil.platform.system(),
            'python_version': psutil.platform.python_version()
        }
    
    def benchmark_function(self, func: Callable, name: str, 
                          iterations: int = 1000, *args, **kwargs) -> BenchmarkResult:
        """Benchmark a function's performance"""
        times = []
        memory_start = psutil.Process().memory_info().rss
        cpu_start = psutil.cpu_percent()
        
        # Warmup
        for _ in range(min(10, iterations // 10)):
            func(*args, **kwargs)
        
        start_time = time.perf_counter()
        
        # Main benchmark
        for _ in range(iterations):
            iter_start = time.perf_counter()
            func(*args, **kwargs)
            iter_end = time.perf_counter()
            times.append(iter_end - iter_start)
        
        end_time = time.perf_counter()
        total_duration = end_time - start_time
        
        # Memory and CPU usage
        memory_end = psutil.Process().memory_info().rss
        memory_used = (memory_end - memory_start) / 1024 / 1024  # MB
        cpu_end = psutil.cpu_percent()
        cpu_avg = (cpu_start + cpu_end) / 2
        
        # Calculate statistics
        avg_time = statistics.mean(times)
        min_time = min(times)
        max_time = max(times)
        median_time = statistics.median(times)
        std_dev = statistics.stdev(times) if len(times) > 1 else 0
        throughput = iterations / total_duration
        
        result = BenchmarkResult(
            name=name,
            duration=total_duration,
            iterations=iterations,
            avg_time=avg_time,
            min_time=min_time,
            max_time=max_time,
            median_time=median_time,
            std_dev=std_dev,
            throughput=throughput,
            memory_used=memory_used,
            cpu_percent=cpu_avg
        )
        
        self.results.append(result)
        return result
    
    async def benchmark_async_function(self, func: Callable, name: str,
                                     iterations: int = 1000, *args, **kwargs) -> BenchmarkResult:
        """Benchmark an async function's performance"""
        times = []
        memory_start = psutil.Process().memory_info().rss
        
        # Warmup
        for _ in range(min(10, iterations // 10)):
            await func(*args, **kwargs)
        
        start_time = time.perf_counter()
        
        # Main benchmark
        for _ in range(iterations):
            iter_start = time.perf_counter()
            await func(*args, **kwargs)
            iter_end = time.perf_counter()
            times.append(iter_end - iter_start)
        
        end_time = time.perf_counter()
        total_duration = end_time - start_time
        
        memory_end = psutil.Process().memory_info().rss
        memory_used = (memory_end - memory_start) / 1024 / 1024
        
        avg_time = statistics.mean(times)
        min_time = min(times)
        max_time = max(times)
        median_time = statistics.median(times)
        std_dev = statistics.stdev(times) if len(times) > 1 else 0
        throughput = iterations / total_duration
        
        result = BenchmarkResult(
            name=name,
            duration=total_duration,
            iterations=iterations,
            avg_time=avg_time,
            min_time=min_time,
            max_time=max_time,
            median_time=median_time,
            std_dev=std_dev,
            throughput=throughput,
            memory_used=memory_used,
            cpu_percent=0
        )
        
        self.results.append(result)
        return result
    
    def benchmark_cpu_intensive(self, duration: float = 5.0) -> BenchmarkResult:
        """Benchmark CPU-intensive operations"""
        def cpu_task():
            # Prime number calculation
            def is_prime(n):
                if n < 2:
                    return False
                for i in range(2, int(n ** 0.5) + 1):
                    if n % i == 0:
                        return False
                return True
            
            primes = []
            n = 2
            while len(primes) < 1000:
                if is_prime(n):
                    primes.append(n)
                n += 1
            return len(primes)
        
        return self.benchmark_function(cpu_task, "CPU Intensive", 1)
    
    def benchmark_memory_intensive(self, size_mb: int = 100) -> BenchmarkResult:
        """Benchmark memory-intensive operations"""
        def memory_task():
            # Allocate and manipulate large data structures
            data = [0] * (size_mb * 1024 * 256)  # Approximate MB
            
            # 最適化: ベクトル化処理でパフォーマンス向上
            data_len = len(data)
            for i in range(0, data_len, 500):  # バッチサイズ最適化
                end_i = min(i + 500, data_len)
                for j in range(i, end_i):
                    if j < data_len:
                        data[j] = j * 2
            
            # Sort a portion
            subset = data[:10000]
            subset.sort()
            
            return len(data)
        
        return self.benchmark_function(memory_task, f"Memory {size_mb}MB", 10)
    
    def benchmark_disk_io(self, file_size_mb: int = 10) -> Tuple[BenchmarkResult, BenchmarkResult]:
        """Benchmark disk I/O operations"""
        test_file = Path("benchmark_test.tmp")
        data = b"0" * (1024 * 1024)  # 1MB of data
        
        def write_test():
            with open(test_file, "wb") as f:
                for _ in range(file_size_mb):
                    f.write(data)
        
        def read_test():
            with open(test_file, "rb") as f:
                while f.read(1024 * 1024):
                    pass
        
        # Write benchmark
        write_result = self.benchmark_function(write_test, f"Disk Write {file_size_mb}MB", 1)
        
        # Read benchmark
        read_result = self.benchmark_function(read_test, f"Disk Read {file_size_mb}MB", 3)
        
        # Cleanup
        test_file.unlink(missing_ok=True)
        
        return write_result, read_result
    
    def benchmark_database_operations(self) -> List[BenchmarkResult]:
        """Benchmark database operations"""
        from blrcs.database import Database
        
        async def db_insert():
            db = Database(":memory:")
            await db.connect()
            
            await db.execute("""
                CREATE TABLE test (id INTEGER PRIMARY KEY, data TEXT)
            """)
            
            for i in range(1000):
                await db.execute(
                    "INSERT INTO test (data) VALUES (?)",
                    (f"test_data_{i}",)
                )
            
            await db.disconnect()
        
        async def db_select():
            db = Database(":memory:")
            await db.connect()
            
            await db.execute("""
                CREATE TABLE test (id INTEGER PRIMARY KEY, data TEXT)
            """)
            
            # Insert test data
            for i in range(1000):
                await db.execute(
                    "INSERT INTO test (data) VALUES (?)",
                    (f"test_data_{i}",)
                )
            
            # Select operations
            for _ in range(100):
                await db.fetch_all("SELECT * FROM test WHERE id < 100")
            
            await db.disconnect()
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            insert_result = loop.run_until_complete(
                self.benchmark_async_function(db_insert, "DB Insert 1000", 1)
            )
            
            select_result = loop.run_until_complete(
                self.benchmark_async_function(db_select, "DB Select 100x", 1)
            )
            
            return [insert_result, select_result]
        
        finally:
            loop.close()
    
    def benchmark_json_operations(self) -> List[BenchmarkResult]:
        """Benchmark JSON serialization/deserialization"""
        test_data = {
            "users": [
                {
                    "id": i,
                    "name": f"User {i}",
                    "email": f"user{i}@example.com",
                    "data": list(range(100))
                }
                for i in range(100)
            ]
        }
        
        def json_encode():
            return json.dumps(test_data)
        
        def json_decode():
            json_str = json.dumps(test_data)
            return json.loads(json_str)
        
        encode_result = self.benchmark_function(json_encode, "JSON Encode", 1000)
        decode_result = self.benchmark_function(json_decode, "JSON Decode", 1000)
        
        return [encode_result, decode_result]
    
    def benchmark_compression(self) -> List[BenchmarkResult]:
        """Benchmark compression operations"""
        from blrcs.compression import Compressor, CompressionType
        
        # Test data
        test_data = b"0123456789" * 10000  # 100KB of repetitive data
        
        results = []
        
        for comp_type in [CompressionType.GZIP, CompressionType.ZLIB, CompressionType.BZIP2]:
            compressor = Compressor(comp_type)
            
            def compress_test():
                return compressor.compress(test_data)
            
            def decompress_test():
                compressed = compressor.compress(test_data)
                return compressor.decompress(compressed)
            
            comp_result = self.benchmark_function(
                compress_test, 
                f"Compress {comp_type.value}", 
                100
            )
            
            decomp_result = self.benchmark_function(
                decompress_test, 
                f"Decompress {comp_type.value}", 
                100
            )
            
            results.extend([comp_result, decomp_result])
        
        return results
    
    def run_full_benchmark(self) -> Dict[str, Any]:
        """Run comprehensive benchmark suite"""
        print("Starting BLRCS Performance Benchmark...")
        
        # CPU benchmarks
        print("Running CPU benchmarks...")
        self.benchmark_cpu_intensive()
        
        # Memory benchmarks
        print("Running memory benchmarks...")
        self.benchmark_memory_intensive(50)
        self.benchmark_memory_intensive(100)
        
        # Disk I/O benchmarks
        print("Running disk I/O benchmarks...")
        self.benchmark_disk_io(5)
        self.benchmark_disk_io(10)
        
        # Database benchmarks
        print("Running database benchmarks...")
        self.benchmark_database_operations()
        
        # JSON benchmarks
        print("Running JSON benchmarks...")
        self.benchmark_json_operations()
        
        # Compression benchmarks
        print("Running compression benchmarks...")
        self.benchmark_compression()
        
        return self.generate_report()
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive benchmark report"""
        if not self.results:
            return {"error": "No benchmark results available"}
        
        # Group results by category
        categories = {}
        
        for result in self.results:
            category = result.name.split()[0]
            if category not in categories:
                categories[category] = []
            categories[category].append(result)
        
        # Calculate statistics
        total_tests = len(self.results)
        avg_throughput = statistics.mean([r.throughput for r in self.results])
        total_memory = sum([r.memory_used for r in self.results])
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "system_info": self.system_info,
            "summary": {
                "total_tests": total_tests,
                "avg_throughput": avg_throughput,
                "total_memory_used_mb": total_memory
            },
            "categories": {},
            "results": []
        }
        
        # Category summaries
        for category, results in categories.items():
            report["categories"][category] = {
                "count": len(results),
                "avg_duration": statistics.mean([r.duration for r in results]),
                "avg_throughput": statistics.mean([r.throughput for r in results]),
                "total_memory": sum([r.memory_used for r in results])
            }
        
        # Individual results
        for result in self.results:
            report["results"].append({
                "name": result.name,
                "duration": result.duration,
                "iterations": result.iterations,
                "avg_time_ms": result.avg_time * 1000,
                "min_time_ms": result.min_time * 1000,
                "max_time_ms": result.max_time * 1000,
                "throughput": result.throughput,
                "memory_used_mb": result.memory_used
            })
        
        return report
    
    def save_report(self, file_path: Path):
        """Save benchmark report to file"""
        report = self.generate_report()
        
        with open(file_path, 'w') as f:
            json.dump(report, f, indent=2)
    
    def compare_with_baseline(self, baseline_file: Path) -> Dict[str, Any]:
        """Compare current results with baseline"""
        if not baseline_file.exists():
            return {"error": "Baseline file not found"}
        
        with open(baseline_file, 'r') as f:
            baseline = json.load(f)
        
        current = self.generate_report()
        
        comparison = {
            "baseline_date": baseline.get("timestamp"),
            "current_date": current.get("timestamp"),
            "improvements": [],
            "regressions": [],
            "summary": {}
        }
        
        # Compare throughput
        baseline_throughput = baseline["summary"]["avg_throughput"]
        current_throughput = current["summary"]["avg_throughput"]
        throughput_change = (current_throughput - baseline_throughput) / baseline_throughput * 100
        
        comparison["summary"]["throughput_change_percent"] = throughput_change
        
        if throughput_change > 5:
            comparison["improvements"].append(f"Overall throughput improved by {throughput_change:.1f}%")
        elif throughput_change < -5:
            comparison["regressions"].append(f"Overall throughput decreased by {abs(throughput_change):.1f}%")
        
        return comparison

# Global benchmark instance
_benchmark: Optional[PerformanceBenchmark] = None

def get_benchmark() -> PerformanceBenchmark:
    """Get global benchmark instance"""
    global _benchmark
    
    if _benchmark is None:
        _benchmark = PerformanceBenchmark()
    
    return _benchmark

def quick_benchmark() -> Dict[str, Any]:
    """Run quick performance check"""
    benchmark = get_benchmark()
    
    # Quick tests
    benchmark.benchmark_cpu_intensive(1.0)
    benchmark.benchmark_memory_intensive(10)
    benchmark.benchmark_json_operations()
    
    return benchmark.generate_report()

def full_benchmark() -> Dict[str, Any]:
    """Run comprehensive benchmark suite"""
    benchmark = get_benchmark()
    return benchmark.run_full_benchmark()