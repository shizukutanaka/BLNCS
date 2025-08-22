# BLRCS Performance Profiler Module
# Lightweight profiling following Carmack's measure-first principle
import time
import cProfile
import pstats
import io
import functools
import threading
from pathlib import Path
from typing import Optional, Dict, Any, Callable, List
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

@dataclass
class TimingResult:
    """Single timing measurement"""
    function: str
    duration: float
    calls: int
    avg_time: float
    total_time: float

class PerformanceProfiler:
    """
    Lightweight performance profiler.
    Measure, analyze, optimize.
    """
    
    def __init__(self):
        self.timings: Dict[str, List[float]] = defaultdict(list)
        self.call_counts: Dict[str, int] = defaultdict(int)
        self.enabled = True
        self.profile_dir = Path("profiles")
        self.profile_dir.mkdir(exist_ok=True)
        
        # For detailed profiling
        self.profiler: Optional[cProfile.Profile] = None
        self.is_profiling = False
    
    def measure(self, name: Optional[str] = None):
        """Decorator to measure function execution time"""
        def decorator(func):
            func_name = name or f"{func.__module__}.{func.__name__}"
            
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                if not self.enabled:
                    return func(*args, **kwargs)
                
                start = time.perf_counter()
                try:
                    result = func(*args, **kwargs)
                    return result
                finally:
                    duration = time.perf_counter() - start
                    self.timings[func_name].append(duration)
                    self.call_counts[func_name] += 1
            
            return wrapper
        return decorator
    
    def timer(self, name: str):
        """Context manager for timing code blocks"""
        class Timer:
            def __init__(self, profiler, timer_name):
                self.profiler = profiler
                self.name = timer_name
                self.start = None
            
            def __enter__(self):
                self.start = time.perf_counter()
                return self
            
            def __exit__(self, *args):
                if self.profiler.enabled and self.start:
                    duration = time.perf_counter() - self.start
                    self.profiler.timings[self.name].append(duration)
                    self.profiler.call_counts[self.name] += 1
        
        return Timer(self, name)
    
    def start_profiling(self):
        """Start detailed profiling"""
        if not self.is_profiling:
            self.profiler = cProfile.Profile()
            self.profiler.enable()
            self.is_profiling = True
    
    def stop_profiling(self) -> Optional[str]:
        """Stop detailed profiling and return stats"""
        if not self.is_profiling or not self.profiler:
            return None
        
        self.profiler.disable()
        self.is_profiling = False
        
        # Generate report
        stream = io.StringIO()
        stats = pstats.Stats(self.profiler, stream=stream)
        stats.sort_stats('cumulative')
        stats.print_stats(20)  # Top 20 functions
        
        # Save to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        profile_file = self.profile_dir / f"profile_{timestamp}.txt"
        with open(profile_file, 'w') as f:
            f.write(stream.getvalue())
        
        return stream.getvalue()
    
    def get_stats(self) -> List[TimingResult]:
        """Get timing statistics"""
        results = []
        
        for func_name, times in self.timings.items():
            if times:
                total = sum(times)
                avg = total / len(times)
                results.append(TimingResult(
                    function=func_name,
                    duration=times[-1] if times else 0,
                    calls=self.call_counts[func_name],
                    avg_time=avg,
                    total_time=total
                ))
        
        # Sort by total time
        results.sort(key=lambda x: x.total_time, reverse=True)
        return results
    
    def get_top_functions(self, n: int = 10) -> List[TimingResult]:
        """Get top N slowest functions"""
        stats = self.get_stats()
        return stats[:n]
    
    def reset(self):
        """Reset all measurements"""
        self.timings.clear()
        self.call_counts.clear()
    
    def report(self) -> str:
        """Generate performance report"""
        stats = self.get_stats()
        
        if not stats:
            return "No performance data collected"
        
        lines = ["Performance Report", "=" * 60]
        lines.append(f"{'Function':<40} {'Calls':>8} {'Avg(ms)':>10} {'Total(ms)':>12}")
        lines.append("-" * 60)
        
        for stat in stats[:20]:  # Top 20
            avg_ms = stat.avg_time * 1000
            total_ms = stat.total_time * 1000
            func_name = stat.function[:40]
            lines.append(f"{func_name:<40} {stat.calls:>8} {avg_ms:>10.2f} {total_ms:>12.2f}")
        
        return "\n".join(lines)

class SimpleProfiler:
    """
    Even simpler profiler for basic needs.
    No dependencies, just timing.
    """
    
    def __init__(self):
        self.marks: Dict[str, float] = {}
        self.durations: Dict[str, float] = {}
    
    def mark(self, name: str):
        """Mark start time"""
        self.marks[name] = time.perf_counter()
    
    def measure(self, name: str) -> float:
        """Measure time since mark"""
        if name not in self.marks:
            return 0.0
        
        duration = time.perf_counter() - self.marks[name]
        self.durations[name] = duration
        return duration
    
    def get_results(self) -> Dict[str, float]:
        """Get all measurements"""
        return self.durations.copy()

def profile_function(func):
    """Decorator to profile a single function"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        profiler = cProfile.Profile()
        profiler.enable()
        
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            profiler.disable()
            
            # Print stats
            stream = io.StringIO()
            stats = pstats.Stats(profiler, stream=stream)
            stats.sort_stats('cumulative')
            stats.print_stats(10)
            
            print(f"\nProfile for {func.__name__}:")
            print(stream.getvalue())
    
    return wrapper

# Global profiler instance
_profiler: Optional[PerformanceProfiler] = None

def get_profiler() -> PerformanceProfiler:
    """Get global profiler instance"""
    global _profiler
    if _profiler is None:
        _profiler = PerformanceProfiler()
    return _profiler

# Convenience functions
def measure(name: Optional[str] = None):
    """Decorator to measure function performance"""
    return get_profiler().measure(name)

def timer(name: str):
    """Context manager to time code blocks"""
    return get_profiler().timer(name)

def start_profiling():
    """Start detailed profiling"""
    get_profiler().start_profiling()

def stop_profiling() -> Optional[str]:
    """Stop profiling and get report"""
    return get_profiler().stop_profiling()

def get_performance_report() -> str:
    """Get performance report"""
    return get_profiler().report()

# Benchmarking utilities
def benchmark(func: Callable, *args, iterations: int = 1000, **kwargs) -> Dict[str, float]:
    """Benchmark a function"""
    times = []
    
    for _ in range(iterations):
        start = time.perf_counter()
        func(*args, **kwargs)
        times.append(time.perf_counter() - start)
    
    return {
        'min': min(times) * 1000,  # Convert to ms
        'max': max(times) * 1000,
        'avg': (sum(times) / len(times)) * 1000,
        'total': sum(times) * 1000,
        'iterations': iterations
    }

def compare_functions(funcs: Dict[str, Callable], *args, iterations: int = 1000, **kwargs):
    """Compare performance of multiple functions"""
    results = {}
    
    for name, func in funcs.items():
        results[name] = benchmark(func, *args, iterations=iterations, **kwargs)
    
    # Print comparison
    print("Performance Comparison")
    print("-" * 50)
    print(f"{'Function':<20} {'Avg(ms)':>10} {'Min(ms)':>10} {'Max(ms)':>10}")
    print("-" * 50)
    
    for name, stats in results.items():
        print(f"{name:<20} {stats['avg']:>10.3f} {stats['min']:>10.3f} {stats['max']:>10.3f}")
    
    return results