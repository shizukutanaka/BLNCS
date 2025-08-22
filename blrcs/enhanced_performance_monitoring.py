# BLRCS Enhanced Performance Monitoring System
# Advanced performance monitoring with predictive analytics and automated optimization

import asyncio
import time
import threading
import logging
import json
import psutil
import gc
import sys
import tracemalloc
from typing import Dict, List, Any, Optional, Callable, Union, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from collections import deque, defaultdict
from statistics import mean, median, stdev
from contextlib import contextmanager
import functools
import inspect
import cProfile
import pstats
import io
import os

logger = logging.getLogger(__name__)

@dataclass
class PerformanceSnapshot:
    """Performance snapshot at a point in time"""
    timestamp: float
    cpu_percent: float
    memory_mb: float
    memory_percent: float
    gc_collections: Dict[int, int]
    thread_count: int
    open_files: int
    network_connections: int
    disk_io: Dict[str, int] = field(default_factory=dict)

@dataclass
class FunctionProfile:
    """Function performance profile"""
    function_name: str
    module_name: str
    call_count: int
    total_time: float
    average_time: float
    max_time: float
    min_time: float
    memory_peak: int = 0

@dataclass
class PerformanceAlert:
    """Performance-related alert"""
    severity: str
    metric: str
    current_value: float
    threshold: float
    trend: str
    prediction: Optional[float] = None

class AdvancedProfiler:
    """Advanced function and system profiler"""
    
    def __init__(self):
        self.function_profiles: Dict[str, FunctionProfile] = {}
        self.active_profiles: Dict[str, List[float]] = defaultdict(list)
        self.profiling_enabled = False
        self._lock = threading.Lock()
    
    def enable_profiling(self):
        """Enable function profiling"""
        self.profiling_enabled = True
        logger.info("Advanced profiling enabled")
    
    def disable_profiling(self):
        """Disable function profiling"""
        self.profiling_enabled = False
        logger.info("Advanced profiling disabled")
    
    def profile_function(self, func):
        """Decorator to profile function performance"""
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not self.profiling_enabled:
                return func(*args, **kwargs)
            
            func_key = f"{func.__module__}.{func.__name__}"
            start_time = time.time()
            
            # Memory tracking
            tracemalloc.start()
            
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                execution_time = time.time() - start_time
                
                # Get memory usage
                current, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                
                # Update profile data
                with self._lock:
                    self.active_profiles[func_key].append(execution_time)
                    
                    # Keep only recent measurements
                    if len(self.active_profiles[func_key]) > 1000:
                        self.active_profiles[func_key] = self.active_profiles[func_key][-1000:]
                    
                    # Update function profile
                    if func_key in self.function_profiles:
                        profile = self.function_profiles[func_key]
                        profile.call_count += 1
                        profile.total_time += execution_time
                        profile.average_time = profile.total_time / profile.call_count
                        profile.max_time = max(profile.max_time, execution_time)
                        profile.min_time = min(profile.min_time, execution_time)
                        profile.memory_peak = max(profile.memory_peak, peak)
                    else:
                        self.function_profiles[func_key] = FunctionProfile(
                            function_name=func.__name__,
                            module_name=func.__module__,
                            call_count=1,
                            total_time=execution_time,
                            average_time=execution_time,
                            max_time=execution_time,
                            min_time=execution_time,
                            memory_peak=peak
                        )
        
        return wrapper
    
    @contextmanager
    def profile_code_block(self, block_name: str):
        """Profile a code block"""
        if not self.profiling_enabled:
            yield
            return
        
        start_time = time.time()
        tracemalloc.start()
        
        try:
            yield
        finally:
            execution_time = time.time() - start_time
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            
            with self._lock:
                self.active_profiles[block_name].append(execution_time)
                
                if block_name in self.function_profiles:
                    profile = self.function_profiles[block_name]
                    profile.call_count += 1
                    profile.total_time += execution_time
                    profile.average_time = profile.total_time / profile.call_count
                    profile.max_time = max(profile.max_time, execution_time)
                    profile.min_time = min(profile.min_time, execution_time)
                    profile.memory_peak = max(profile.memory_peak, peak)
                else:
                    self.function_profiles[block_name] = FunctionProfile(
                        function_name=block_name,
                        module_name="code_block",
                        call_count=1,
                        total_time=execution_time,
                        average_time=execution_time,
                        max_time=execution_time,
                        min_time=execution_time,
                        memory_peak=peak
                    )
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Get comprehensive performance report"""
        with self._lock:
            # Sort functions by total time
            sorted_profiles = sorted(
                self.function_profiles.values(),
                key=lambda p: p.total_time,
                reverse=True
            )
            
            top_functions = sorted_profiles[:20]  # Top 20 by total time
            
            report = {
                "total_functions_profiled": len(self.function_profiles),
                "total_calls": sum(p.call_count for p in self.function_profiles.values()),
                "total_time": sum(p.total_time for p in self.function_profiles.values()),
                "top_functions_by_total_time": [
                    {
                        "function": f"{p.module_name}.{p.function_name}",
                        "call_count": p.call_count,
                        "total_time": round(p.total_time, 4),
                        "average_time": round(p.average_time, 4),
                        "max_time": round(p.max_time, 4),
                        "memory_peak_kb": round(p.memory_peak / 1024, 2)
                    }
                    for p in top_functions
                ],
                "slowest_functions": [
                    {
                        "function": f"{p.module_name}.{p.function_name}",
                        "max_time": round(p.max_time, 4),
                        "average_time": round(p.average_time, 4),
                        "call_count": p.call_count
                    }
                    for p in sorted(self.function_profiles.values(), 
                                  key=lambda p: p.max_time, reverse=True)[:10]
                ],
                "most_called_functions": [
                    {
                        "function": f"{p.module_name}.{p.function_name}",
                        "call_count": p.call_count,
                        "total_time": round(p.total_time, 4),
                        "average_time": round(p.average_time, 4)
                    }
                    for p in sorted(self.function_profiles.values(),
                                  key=lambda p: p.call_count, reverse=True)[:10]
                ]
            }
            
            return report

class PredictiveAnalyzer:
    """Predictive performance analysis"""
    
    def __init__(self, history_size: int = 1000):
        self.history_size = history_size
        self.metrics_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=history_size))
        self.prediction_models: Dict[str, Dict[str, Any]] = {}
    
    def add_metric_point(self, metric_name: str, value: float, timestamp: float = None):
        """Add metric point for analysis"""
        timestamp = timestamp or time.time()
        self.metrics_history[metric_name].append((timestamp, value))
    
    def predict_trend(self, metric_name: str, forecast_seconds: int = 300) -> Dict[str, Any]:
        """Predict metric trend using simple linear regression"""
        history = self.metrics_history.get(metric_name)
        
        if not history or len(history) < 10:
            return {"error": "Insufficient data for prediction"}
        
        # Extract values and timestamps
        timestamps = [point[0] for point in history]
        values = [point[1] for point in history]
        
        # Simple linear regression
        n = len(values)
        sum_x = sum(range(n))
        sum_y = sum(values)
        sum_xy = sum(i * values[i] for i in range(n))
        sum_x2 = sum(i * i for i in range(n))
        
        # Calculate slope and intercept
        slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)
        intercept = (sum_y - slope * sum_x) / n
        
        # Predict future value
        future_point = n + (forecast_seconds / 60)  # Assuming 1-minute intervals
        predicted_value = slope * future_point + intercept
        
        # Calculate trend direction
        recent_avg = mean(values[-5:]) if len(values) >= 5 else mean(values)
        older_avg = mean(values[:5]) if len(values) >= 10 else mean(values)
        
        trend_direction = "increasing" if recent_avg > older_avg else "decreasing"
        trend_strength = abs((recent_avg - older_avg) / older_avg) * 100 if older_avg != 0 else 0
        
        return {
            "current_value": values[-1],
            "predicted_value": predicted_value,
            "trend_direction": trend_direction,
            "trend_strength": round(trend_strength, 2),
            "confidence": min(90, max(10, 100 - (stdev(values) / mean(values)) * 50)) if mean(values) != 0 else 50,
            "forecast_time": forecast_seconds
        }
    
    def detect_anomalies(self, metric_name: str) -> List[Dict[str, Any]]:
        """Detect anomalies in metric data"""
        history = self.metrics_history.get(metric_name)
        
        if not history or len(history) < 20:
            return []
        
        values = [point[1] for point in history]
        timestamps = [point[0] for point in history]
        
        # Calculate statistical thresholds
        mean_val = mean(values)
        std_val = stdev(values)
        
        upper_threshold = mean_val + 2 * std_val
        lower_threshold = mean_val - 2 * std_val
        
        anomalies = []
        for i, (timestamp, value) in enumerate(history):
            if value > upper_threshold or value < lower_threshold:
                anomalies.append({
                    "timestamp": timestamp,
                    "value": value,
                    "severity": "high" if abs(value - mean_val) > 3 * std_val else "medium",
                    "deviation": round(abs(value - mean_val) / std_val, 2)
                })
        
        return anomalies[-10:]  # Return last 10 anomalies

class SystemOptimizer:
    """Automated system optimization"""
    
    def __init__(self):
        self.optimization_history: List[Dict[str, Any]] = []
        self.enabled_optimizations = {
            "gc_tuning": True,
            "memory_optimization": True,
            "cpu_optimization": True,
            "io_optimization": True
        }
    
    def analyze_and_optimize(self, performance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze performance and apply optimizations"""
        optimizations_applied = []
        recommendations = []
        
        # Memory optimization
        if self.enabled_optimizations["memory_optimization"]:
            memory_opts = self._optimize_memory(performance_data)
            optimizations_applied.extend(memory_opts["applied"])
            recommendations.extend(memory_opts["recommendations"])
        
        # GC optimization
        if self.enabled_optimizations["gc_tuning"]:
            gc_opts = self._optimize_garbage_collection(performance_data)
            optimizations_applied.extend(gc_opts["applied"])
            recommendations.extend(gc_opts["recommendations"])
        
        # CPU optimization
        if self.enabled_optimizations["cpu_optimization"]:
            cpu_opts = self._optimize_cpu_usage(performance_data)
            optimizations_applied.extend(cpu_opts["applied"])
            recommendations.extend(cpu_opts["recommendations"])
        
        optimization_result = {
            "timestamp": time.time(),
            "optimizations_applied": optimizations_applied,
            "recommendations": recommendations,
            "performance_before": performance_data.get("current_metrics", {}),
            "expected_improvement": self._calculate_expected_improvement(optimizations_applied)
        }
        
        self.optimization_history.append(optimization_result)
        
        return optimization_result
    
    def _optimize_memory(self, performance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize memory usage"""
        applied = []
        recommendations = []
        
        current_memory = performance_data.get("current_metrics", {}).get("memory_percent", 0)
        
        if current_memory > 80:
            # Force garbage collection
            collected = gc.collect()
            applied.append(f"Forced garbage collection - freed {collected} objects")
            
            # Adjust GC thresholds
            gc.set_threshold(700, 10, 10)
            applied.append("Adjusted GC thresholds for high memory usage")
            
            recommendations.append("Consider implementing memory pooling for frequently allocated objects")
            recommendations.append("Review large data structures for optimization opportunities")
        
        elif current_memory > 60:
            recommendations.append("Monitor memory usage - approaching high threshold")
        
        return {"applied": applied, "recommendations": recommendations}
    
    def _optimize_garbage_collection(self, performance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize garbage collection"""
        applied = []
        recommendations = []
        
        # Get GC stats
        gc_stats = gc.get_stats()
        
        # Check if GC is running frequently
        if len(gc_stats) > 0:
            gen0_collections = gc_stats[0]["collections"]
            
            if gen0_collections > 100:  # High GC activity
                # Increase GC thresholds to reduce frequency
                current_thresholds = gc.get_threshold()
                new_thresholds = (
                    current_thresholds[0] * 2,
                    current_thresholds[1],
                    current_thresholds[2]
                )
                gc.set_threshold(*new_thresholds)
                applied.append(f"Increased GC generation 0 threshold from {current_thresholds[0]} to {new_thresholds[0]}")
                
                recommendations.append("High GC activity detected - consider object pooling")
        
        return {"applied": applied, "recommendations": recommendations}
    
    def _optimize_cpu_usage(self, performance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize CPU usage"""
        applied = []
        recommendations = []
        
        current_cpu = performance_data.get("current_metrics", {}).get("cpu_percent", 0)
        
        if current_cpu > 90:
            recommendations.append("Critical: CPU usage very high - investigate CPU-intensive operations")
            recommendations.append("Consider implementing asynchronous processing for heavy tasks")
            recommendations.append("Review algorithmic complexity of recent code changes")
        
        elif current_cpu > 70:
            recommendations.append("High CPU usage detected - monitor performance closely")
            recommendations.append("Consider load balancing or horizontal scaling")
        
        # Check thread count
        thread_count = performance_data.get("current_metrics", {}).get("thread_count", 0)
        if thread_count > 100:
            recommendations.append(f"High thread count ({thread_count}) - consider thread pooling")
        
        return {"applied": applied, "recommendations": recommendations}
    
    def _calculate_expected_improvement(self, optimizations: List[str]) -> Dict[str, float]:
        """Calculate expected performance improvement"""
        improvement = {
            "memory_improvement": 0.0,
            "cpu_improvement": 0.0,
            "response_time_improvement": 0.0
        }
        
        for opt in optimizations:
            if "garbage collection" in opt.lower():
                improvement["memory_improvement"] += 5.0
                improvement["cpu_improvement"] += 2.0
            elif "memory" in opt.lower():
                improvement["memory_improvement"] += 10.0
            elif "threshold" in opt.lower():
                improvement["response_time_improvement"] += 3.0
        
        return improvement

class EnhancedPerformanceMonitor:
    """Enhanced performance monitoring system"""
    
    def __init__(self):
        self.profiler = AdvancedProfiler()
        self.predictor = PredictiveAnalyzer()
        self.optimizer = SystemOptimizer()
        self.snapshots: deque = deque(maxlen=1000)
        self.monitoring_active = False
        self._monitoring_task = None
        
    async def start_monitoring(self, interval_seconds: int = 30):
        """Start enhanced performance monitoring"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.profiler.enable_profiling()
        
        self._monitoring_task = asyncio.create_task(
            self._monitoring_loop(interval_seconds)
        )
        
        logger.info("🔍 Enhanced performance monitoring started")
    
    async def stop_monitoring(self):
        """Stop performance monitoring"""
        self.monitoring_active = False
        self.profiler.disable_profiling()
        
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Performance monitoring stopped")
    
    async def _monitoring_loop(self, interval_seconds: int):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                # Take performance snapshot
                snapshot = self._take_performance_snapshot()
                self.snapshots.append(snapshot)
                
                # Update predictive models
                self._update_predictive_models(snapshot)
                
                # Check for optimization opportunities
                if len(self.snapshots) >= 5:  # Need some history
                    await self._check_optimization_opportunities()
                
                await asyncio.sleep(interval_seconds)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in performance monitoring loop: {e}")
                await asyncio.sleep(5)
    
    def _take_performance_snapshot(self) -> PerformanceSnapshot:
        """Take a performance snapshot"""
        process = psutil.Process()
        
        # Get GC stats
        gc_stats = {i: gc.get_count()[i] for i in range(len(gc.get_count()))}
        
        # Get disk I/O
        try:
            disk_io = process.io_counters()
            disk_io_dict = {
                "read_bytes": disk_io.read_bytes,
                "write_bytes": disk_io.write_bytes
            }
        except (psutil.AccessDenied, AttributeError):
            disk_io_dict = {}
        
        snapshot = PerformanceSnapshot(
            timestamp=time.time(),
            cpu_percent=psutil.cpu_percent(),
            memory_mb=process.memory_info().rss / 1024 / 1024,
            memory_percent=process.memory_percent(),
            gc_collections=gc_stats,
            thread_count=process.num_threads(),
            open_files=len(process.open_files()) if hasattr(process, 'open_files') else 0,
            network_connections=len(process.connections()) if hasattr(process, 'connections') else 0,
            disk_io=disk_io_dict
        )
        
        return snapshot
    
    def _update_predictive_models(self, snapshot: PerformanceSnapshot):
        """Update predictive models with new data"""
        self.predictor.add_metric_point("cpu_percent", snapshot.cpu_percent, snapshot.timestamp)
        self.predictor.add_metric_point("memory_percent", snapshot.memory_percent, snapshot.timestamp)
        self.predictor.add_metric_point("thread_count", snapshot.thread_count, snapshot.timestamp)
        
        if snapshot.disk_io:
            if "read_bytes" in snapshot.disk_io:
                self.predictor.add_metric_point("disk_read_bytes", snapshot.disk_io["read_bytes"], snapshot.timestamp)
            if "write_bytes" in snapshot.disk_io:
                self.predictor.add_metric_point("disk_write_bytes", snapshot.disk_io["write_bytes"], snapshot.timestamp)
    
    async def _check_optimization_opportunities(self):
        """Check for optimization opportunities"""
        latest_snapshot = self.snapshots[-1]
        
        performance_data = {
            "current_metrics": {
                "cpu_percent": latest_snapshot.cpu_percent,
                "memory_percent": latest_snapshot.memory_percent,
                "thread_count": latest_snapshot.thread_count
            }
        }
        
        # Run optimization analysis
        optimization_result = self.optimizer.analyze_and_optimize(performance_data)
        
        if optimization_result["optimizations_applied"]:
            logger.info(f"Applied {len(optimization_result['optimizations_applied'])} performance optimizations")
        
        if optimization_result["recommendations"]:
            logger.warning(f"Performance recommendations: {'; '.join(optimization_result['recommendations'])}")
    
    def get_comprehensive_report(self) -> Dict[str, Any]:
        """Get comprehensive performance report"""
        if not self.snapshots:
            return {"error": "No performance data available"}
        
        latest_snapshot = self.snapshots[-1]
        
        # Calculate trends
        cpu_trend = self.predictor.predict_trend("cpu_percent")
        memory_trend = self.predictor.predict_trend("memory_percent")
        
        # Detect anomalies
        cpu_anomalies = self.predictor.detect_anomalies("cpu_percent")
        memory_anomalies = self.predictor.detect_anomalies("memory_percent")
        
        # Get profiling report
        profiling_report = self.profiler.get_performance_report()
        
        # Calculate performance score
        performance_score = self._calculate_performance_score(latest_snapshot)
        
        return {
            "timestamp": latest_snapshot.timestamp,
            "performance_score": performance_score,
            "current_metrics": {
                "cpu_percent": latest_snapshot.cpu_percent,
                "memory_mb": round(latest_snapshot.memory_mb, 2),
                "memory_percent": latest_snapshot.memory_percent,
                "thread_count": latest_snapshot.thread_count,
                "open_files": latest_snapshot.open_files,
                "network_connections": latest_snapshot.network_connections
            },
            "trends": {
                "cpu_trend": cpu_trend,
                "memory_trend": memory_trend
            },
            "anomalies": {
                "cpu_anomalies": cpu_anomalies,
                "memory_anomalies": memory_anomalies
            },
            "profiling": profiling_report,
            "optimization_history": self.optimizer.optimization_history[-10:],  # Last 10
            "recommendations": self._generate_recommendations(latest_snapshot, cpu_trend, memory_trend)
        }
    
    def _calculate_performance_score(self, snapshot: PerformanceSnapshot) -> float:
        """Calculate overall performance score"""
        score = 100.0
        
        # CPU penalty
        if snapshot.cpu_percent > 90:
            score -= 30
        elif snapshot.cpu_percent > 70:
            score -= 15
        elif snapshot.cpu_percent > 50:
            score -= 5
        
        # Memory penalty
        if snapshot.memory_percent > 90:
            score -= 25
        elif snapshot.memory_percent > 70:
            score -= 10
        elif snapshot.memory_percent > 50:
            score -= 3
        
        # Thread count penalty
        if snapshot.thread_count > 100:
            score -= 15
        elif snapshot.thread_count > 50:
            score -= 5
        
        # File handle penalty
        if snapshot.open_files > 1000:
            score -= 10
        elif snapshot.open_files > 500:
            score -= 3
        
        return max(0.0, min(100.0, score))
    
    def _generate_recommendations(self, snapshot: PerformanceSnapshot, 
                                cpu_trend: Dict, memory_trend: Dict) -> List[str]:
        """Generate performance recommendations"""
        recommendations = []
        
        # CPU recommendations
        if cpu_trend.get("trend_direction") == "increasing":
            recommendations.append("CPU usage is trending upward - investigate CPU-intensive operations")
        
        if snapshot.cpu_percent > 80:
            recommendations.append("High CPU usage - consider optimizing algorithms or adding asynchronous processing")
        
        # Memory recommendations
        if memory_trend.get("trend_direction") == "increasing":
            recommendations.append("Memory usage is trending upward - check for memory leaks")
        
        if snapshot.memory_percent > 75:
            recommendations.append("High memory usage - consider implementing memory optimization strategies")
        
        # Thread recommendations
        if snapshot.thread_count > 50:
            recommendations.append(f"High thread count ({snapshot.thread_count}) - consider thread pooling")
        
        # File handle recommendations
        if snapshot.open_files > 100:
            recommendations.append(f"Many open files ({snapshot.open_files}) - ensure proper file handle cleanup")
        
        return recommendations

# Global enhanced performance monitor
enhanced_monitor = EnhancedPerformanceMonitor()

async def start_enhanced_monitoring():
    """Start enhanced performance monitoring"""
    await enhanced_monitor.start_monitoring()

async def stop_enhanced_monitoring():
    """Stop enhanced performance monitoring"""
    await enhanced_monitor.stop_monitoring()

def get_performance_report() -> Dict[str, Any]:
    """Get comprehensive performance report"""
    return enhanced_monitor.get_comprehensive_report()

def profile_function(func):
    """Decorator to profile function performance"""
    return enhanced_monitor.profiler.profile_function(func)

def profile_code_block(block_name: str):
    """Context manager to profile code block"""
    return enhanced_monitor.profiler.profile_code_block(block_name)