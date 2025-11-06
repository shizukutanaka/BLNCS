#!/usr/bin/env python3
"""
性能ベンチマークと最適化ツール for BLNCS
CPU・メモリ・I/O・並行処理の評価が可能
"""

import time
import psutil
import threading
import multiprocessing
from typing import Dict, List, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
import statistics
import json
import os
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor

@dataclass
class BenchmarkResult:
    """ベンチマーク結果"""
    test_name: str
    duration: float
    cpu_usage: float
    memory_usage: float
    io_read: int
    io_write: int
    network_io: Dict[str, int]
    metrics: Dict[str, float] = field(default_factory=dict)

@dataclass
class PerformanceReport:
    """性能レポート"""
    timestamp: datetime
    overall_score: float
    benchmarks: List[BenchmarkResult] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    bottlenecks: List[str] = field(default_factory=list)

class SystemProfiler:
    """システムプロファイラ"""

    def __init__(self):
        self.process = psutil.Process()
        self.baseline_stats = None

    def get_system_stats(self) -> Dict[str, Any]:
        """システム統計取得"""
        return {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'memory_used': psutil.virtual_memory().used,
            'memory_available': psutil.virtual_memory().available,
            'disk_usage': psutil.disk_usage('/').percent,
            'network_io': dict(psutil.net_io_counters()._asdict()),
            'load_average': os.getloadavg() if hasattr(os, 'getloadavg') else [0, 0, 0],
        }

    def get_process_stats(self) -> Dict[str, Any]:
        """プロセス統計取得"""
        try:
            return {
                'process_cpu': self.process.cpu_percent(),
                'process_memory': self.process.memory_info().rss,
                'process_threads': self.process.num_threads(),
                'process_connections': len(self.process.connections()),
            }
        except:
            return {}

class CPUTester:
    """CPUベンチマークテスト"""

    def __init__(self):
        self.profiler = SystemProfiler()

    def fibonacci_recursive(self, n: int) -> int:
        """フィボナッチ再帰計算（CPU負荷テスト）"""
        if n <= 1:
            return n
        return self.fibonacci_recursive(n-1) + self.fibonacci_recursive(n-2)

    def matrix_multiplication(self, size: int) -> List[List[float]]:
        """行列乗算（CPU負荷テスト）"""
        import random
        A = [[random.random() for _ in range(size)] for _ in range(size)]
        B = [[random.random() for _ in range(size)] for _ in range(size)]
        C = [[0 for _ in range(size)] for _ in range(size)]

        for i in range(size):
            for j in range(size):
                for k in range(size):
                    C[i][j] += A[i][k] * B[k][j]
        return C

    def run_cpu_benchmark(self, duration: int = 10) -> BenchmarkResult:
        """CPUベンチマーク実行"""
        start_time = time.time()
        start_stats = self.profiler.get_system_stats()

        # CPU負荷テスト実行
        tasks = []
        with ThreadPoolExecutor(max_workers=multiprocessing.cpu_count()) as executor:
            for _ in range(multiprocessing.cpu_count()):
                tasks.append(executor.submit(self.matrix_multiplication, 100))

        # 結果待機
        for task in tasks:
            task.result()

        end_time = time.time()
        end_stats = self.profiler.get_system_stats()

        return BenchmarkResult(
            test_name='cpu_benchmark',
            duration=end_time - start_time,
            cpu_usage=(start_stats['cpu_percent'] + end_stats['cpu_percent']) / 2,
            memory_usage=end_stats['memory_used'] - start_stats['memory_used'],
            io_read=end_stats['network_io'].get('bytes_recv', 0) - start_stats['network_io'].get('bytes_recv', 0),
            io_write=end_stats['network_io'].get('bytes_sent', 0) - start_stats['network_io'].get('bytes_sent', 0),
            network_io=end_stats['network_io'],
            metrics={
                'operations_per_second': len(tasks) / (end_time - start_time),
                'cpu_efficiency': 100 - end_stats['cpu_percent']
            }
        )

class MemoryTester:
    """メモリベンチマークテスト"""

    def __init__(self):
        self.profiler = SystemProfiler()

    def memory_allocation_test(self, size_mb: int) -> List[bytes]:
        """メモリ割り当てテスト"""
        data = []
        chunk_size = 1024 * 1024  # 1MB
        num_chunks = size_mb

        for _ in range(num_chunks):
            data.append(bytes(chunk_size))
        return data

    def memory_access_test(self, data: List[bytes]) -> float:
        """メモリアクセス速度テスト"""
        start_time = time.time()
        for chunk in data:
            _ = sum(chunk)  # メモリアクセスを強制
        return time.time() - start_time

    def run_memory_benchmark(self, size_mb: int = 100) -> BenchmarkResult:
        """メモリベンチマーク実行"""
        start_time = time.time()
        start_stats = self.profiler.get_system_stats()

        # メモリテスト実行
        data = self.memory_allocation_test(size_mb)
        access_time = self.memory_access_test(data)

        # クリーンアップ
        del data

        end_time = time.time()
        end_stats = self.profiler.get_system_stats()

        return BenchmarkResult(
            test_name='memory_benchmark',
            duration=end_time - start_time,
            cpu_usage=(start_stats['cpu_percent'] + end_stats['cpu_percent']) / 2,
            memory_usage=end_stats['memory_used'] - start_stats['memory_used'],
            io_read=0,
            io_write=0,
            network_io=end_stats['network_io'],
            metrics={
                'allocation_speed': size_mb / (end_time - start_time),
                'access_time': access_time,
                'memory_efficiency': (end_stats['memory_available'] / end_stats['memory_used']) * 100
            }
        )

class IOTester:
    """I/Oベンチマークテスト"""

    def __init__(self):
        self.profiler = SystemProfiler()
        self.test_file = '/tmp/blncs_io_test.tmp'

    def file_write_test(self, size_mb: int) -> float:
        """ファイル書き込みテスト"""
        data = bytes(1024 * 1024)  # 1MBデータ
        start_time = time.time()

        with open(self.test_file, 'wb') as f:
            for _ in range(size_mb):
                f.write(data)

        write_time = time.time() - start_time

        # クリーンアップ
        os.remove(self.test_file)
        return write_time

    def file_read_test(self, size_mb: int) -> float:
        """ファイル読み込みテスト"""
        # まずデータを書き込み
        data = bytes(1024 * 1024)
        with open(self.test_file, 'wb') as f:
            for _ in range(size_mb):
                f.write(data)

        # 読み込みテスト
        start_time = time.time()

        with open(self.test_file, 'rb') as f:
            while f.read(1024 * 1024):
                pass

        read_time = time.time() - start_time

        # クリーンアップ
        os.remove(self.test_file)
        return read_time

    def run_io_benchmark(self, size_mb: int = 50) -> BenchmarkResult:
        """I/Oベンチマーク実行"""
        start_time = time.time()
        start_stats = self.profiler.get_system_stats()

        write_time = self.file_write_test(size_mb)
        read_time = self.file_read_test(size_mb)

        end_time = time.time()
        end_stats = self.profiler.get_system_stats()

        return BenchmarkResult(
            test_name='io_benchmark',
            duration=end_time - start_time,
            cpu_usage=(start_stats['cpu_percent'] + end_stats['cpu_percent']) / 2,
            memory_usage=end_stats['memory_used'] - start_stats['memory_used'],
            io_read=end_stats['network_io'].get('bytes_recv', 0) - start_stats['network_io'].get('bytes_recv', 0),
            io_write=end_stats['network_io'].get('bytes_sent', 0) - start_stats['network_io'].get('bytes_sent', 0),
            network_io=end_stats['network_io'],
            metrics={
                'write_speed': size_mb / write_time,
                'read_speed': size_mb / read_time,
                'io_efficiency': min(size_mb / write_time, size_mb / read_time)
            }
        )

class ConcurrencyTester:
    """並行処理ベンチマークテスト"""

    def __init__(self):
        self.profiler = SystemProfiler()

    def cpu_bound_task(self, duration: float) -> float:
        """CPUバウンドタスク"""
        start = time.time()
        while time.time() - start < duration:
            _ = sum(i * i for i in range(1000))
        return time.time() - start

    def io_bound_task(self, delay: float) -> float:
        """I/Oバウンドタスク"""
        time.sleep(delay)
        return delay

    def run_concurrency_benchmark(self, num_threads: int = 10, duration: float = 2.0) -> BenchmarkResult:
        """並行処理ベンチマーク実行"""
        start_time = time.time()
        start_stats = self.profiler.get_system_stats()

        tasks = []
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            for _ in range(num_threads):
                tasks.append(executor.submit(self.cpu_bound_task, duration))

        # 結果待機
        results = [task.result() for task in tasks]

        end_time = time.time()
        end_stats = self.profiler.get_system_stats()

        return BenchmarkResult(
            test_name='concurrency_benchmark',
            duration=end_time - start_time,
            cpu_usage=(start_stats['cpu_percent'] + end_stats['cpu_percent']) / 2,
            memory_usage=end_stats['memory_used'] - start_stats['memory_used'],
            io_read=end_stats['network_io'].get('bytes_recv', 0) - start_stats['network_io'].get('bytes_recv', 0),
            io_write=end_stats['network_io'].get('bytes_sent', 0) - start_stats['network_io'].get('bytes_sent', 0),
            network_io=end_stats['network_io'],
            metrics={
                'threads': num_threads,
                'avg_task_time': statistics.mean(results),
                'concurrency_efficiency': num_threads / (end_time - start_time) * statistics.mean(results)
            }
        )

class PerformanceBenchmarker:
    """総合性能ベンチマークツール"""

    def __init__(self):
        self.cpu_tester = CPUTester()
        self.memory_tester = MemoryTester()
        self.io_tester = IOTester()
        self.concurrency_tester = ConcurrencyTester()
        self.profiler = SystemProfiler()

    def run_full_benchmark(self) -> PerformanceReport:
        """全ベンチマーク実行"""
        benchmarks = []

        print("CPUベンチマーク実行中...")
        benchmarks.append(self.cpu_tester.run_cpu_benchmark())

        print("メモリベンチマーク実行中...")
        benchmarks.append(self.memory_tester.run_memory_benchmark())

        print("I/Oベンチマーク実行中...")
        benchmarks.append(self.io_tester.run_io_benchmark())

        print("並行処理ベンチマーク実行中...")
        benchmarks.append(self.concurrency_tester.run_concurrency_benchmark())

        # 全体スコア計算
        overall_score = self._calculate_overall_score(benchmarks)

        # レコメンデーション生成
        recommendations = self._generate_recommendations(benchmarks)

        # ボトルネック検知
        bottlenecks = self._identify_bottlenecks(benchmarks)

        return PerformanceReport(
            timestamp=datetime.now(),
            overall_score=overall_score,
            benchmarks=benchmarks,
            recommendations=recommendations,
            bottlenecks=bottlenecks
        )

    def _calculate_overall_score(self, benchmarks: List[BenchmarkResult]) -> float:
        """全体スコア計算"""
        scores = []
        for bench in benchmarks:
            # 各ベンチマークのスコアを計算（簡易版）
            if bench.test_name == 'cpu_benchmark':
                score = 100 - bench.cpu_usage
            elif bench.test_name == 'memory_benchmark':
                score = bench.metrics.get('memory_efficiency', 50)
            elif bench.test_name == 'io_benchmark':
                score = bench.metrics.get('io_efficiency', 50)
            else:  # concurrency
                score = bench.metrics.get('concurrency_efficiency', 50)

            scores.append(score)

        return statistics.mean(scores)

    def _generate_recommendations(self, benchmarks: List[BenchmarkResult]) -> List[str]:
        """レコメンデーション生成"""
        recommendations = []

        for bench in benchmarks:
            if bench.test_name == 'cpu_benchmark' and bench.cpu_usage > 80:
                recommendations.append("CPU使用率が高いです。プロセス数を最適化してください。")
            if bench.test_name == 'memory_benchmark' and bench.memory_usage > 1e9:  # 1GB
                recommendations.append("メモリ使用量が多いです。キャッシュサイズを調整してください。")
            if bench.test_name == 'io_benchmark' and bench.metrics.get('io_efficiency', 0) < 10:
                recommendations.append("I/O性能が低いです。ストレージの確認を推奨します。")

        return recommendations

    def _identify_bottlenecks(self, benchmarks: List[BenchmarkResult]) -> List[str]:
        """ボトルネック検知"""
        bottlenecks = []

        for bench in benchmarks:
            if bench.test_name == 'cpu_benchmark' and bench.cpu_usage > 70:
                bottlenecks.append("CPUがボトルネックになっています")
            if bench.test_name == 'memory_benchmark' and bench.memory_usage > 2e9:  # 2GB
                bottlenecks.append("メモリがボトルネックになっています")
            if bench.test_name == 'io_benchmark' and bench.metrics.get('io_efficiency', 0) < 5:
                bottlenecks.append("I/Oがボトルネックになっています")

        return bottlenecks

    def export_report(self, report: PerformanceReport, filename: str):
        """レポートをJSONでエクスポート"""
        data = {
            'timestamp': report.timestamp.isoformat(),
            'overall_score': report.overall_score,
            'benchmarks': [
                {
                    'test_name': b.test_name,
                    'duration': b.duration,
                    'cpu_usage': b.cpu_usage,
                    'memory_usage': b.memory_usage,
                    'metrics': b.metrics
                } for b in report.benchmarks
            ],
            'recommendations': report.recommendations,
            'bottlenecks': report.bottlenecks
        }

        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)

# グローバルインスタンス
performance_benchmarker = PerformanceBenchmarker()

def run_benchmark() -> PerformanceReport:
    """ベンチマークを実行"""
    return performance_benchmarker.run_full_benchmark()

def export_benchmark_report(report: PerformanceReport, filename: str = 'performance_report.json'):
    """ベンチマークレポートをエクスポート"""
    performance_benchmarker.export_report(report, filename)
