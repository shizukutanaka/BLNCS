# BLRCS Performance Monitoring Module
# Real-time performance tracking and optimization
import time
import psutil
import asyncio
from typing import Dict, List, Any, Optional
from collections import deque
from datetime import datetime, timedelta
import statistics

from .logger import get_logger

logger = get_logger(__name__)

class PerformanceMonitor:
    """
    Real-time performance monitoring.
    Tracks CPU, memory, disk, and application metrics.
    """
    
    def __init__(self, history_size: int = 100):
        self.history_size = history_size
        self.metrics_history = {
            "cpu": deque(maxlen=history_size),
            "memory": deque(maxlen=history_size),
            "disk": deque(maxlen=history_size),
            "network": deque(maxlen=history_size),
            "response_time": deque(maxlen=history_size),
            "request_count": deque(maxlen=history_size),
            "error_count": deque(maxlen=history_size)
        }
        
        self.current_metrics = {}
        self.alerts = []
        self.monitoring = False
        
        # Thresholds for alerts
        self.thresholds = {
            "cpu_percent": 80.0,
            "memory_percent": 85.0,
            "disk_percent": 90.0,
            "response_time_ms": 100.0,
            "error_rate": 0.05
        }
        
        # Performance counters
        self.counters = {
            "total_requests": 0,
            "total_errors": 0,
            "total_bytes_processed": 0,
            "start_time": time.time()
        }
    
    async def start_monitoring(self, interval: float = 1.0):
        """Start continuous monitoring"""
        self.monitoring = True
        asyncio.create_task(self._monitor_loop(interval))
        logger.info("Performance monitoring started")
    
    async def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        logger.info("Performance monitoring stopped")
    
    async def _monitor_loop(self, interval: float):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                # Collect metrics
                metrics = await self.collect_metrics()
                
                # Store in history
                timestamp = datetime.now()
                for key, value in metrics.items():
                    if key in self.metrics_history:
                        self.metrics_history[key].append({
                            "timestamp": timestamp,
                            "value": value
                        })
                
                # Update current metrics
                self.current_metrics = metrics
                
                # Check thresholds
                self._check_thresholds(metrics)
                
                # Wait for next interval
                await asyncio.sleep(interval)
                
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                await asyncio.sleep(interval)
    
    async def collect_metrics(self) -> Dict[str, Any]:
        """Collect system and application metrics"""
        metrics = {}
        
        try:
            # CPU metrics
            metrics["cpu_percent"] = psutil.cpu_percent(interval=0.1)
            metrics["cpu_count"] = psutil.cpu_count()
            
            # Memory metrics
            memory = psutil.virtual_memory()
            metrics["memory_percent"] = memory.percent
            metrics["memory_used_mb"] = memory.used / (1024 * 1024)
            metrics["memory_available_mb"] = memory.available / (1024 * 1024)
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            metrics["disk_percent"] = disk.percent
            metrics["disk_used_gb"] = disk.used / (1024 * 1024 * 1024)
            metrics["disk_free_gb"] = disk.free / (1024 * 1024 * 1024)
            
            # Network metrics (if available)
            try:
                net_io = psutil.net_io_counters()
                metrics["network_bytes_sent"] = net_io.bytes_sent
                metrics["network_bytes_recv"] = net_io.bytes_recv
            except:
                metrics["network_bytes_sent"] = 0
                metrics["network_bytes_recv"] = 0
            
            # Application metrics
            process = psutil.Process()
            metrics["app_cpu_percent"] = process.cpu_percent()
            metrics["app_memory_mb"] = process.memory_info().rss / (1024 * 1024)
            metrics["app_threads"] = process.num_threads()
            
            # Calculate rates
            uptime = time.time() - self.counters["start_time"]
            metrics["requests_per_second"] = self.counters["total_requests"] / uptime if uptime > 0 else 0
            metrics["error_rate"] = self.counters["total_errors"] / self.counters["total_requests"] if self.counters["total_requests"] > 0 else 0
            
        except Exception as e:
            logger.error(f"Failed to collect metrics: {e}")
        
        return metrics
    
    def _check_thresholds(self, metrics: Dict[str, Any]):
        """Check if any metrics exceed thresholds"""
        alerts = []
        
        # Check CPU
        if metrics.get("cpu_percent", 0) > self.thresholds["cpu_percent"]:
            alerts.append({
                "level": "warning",
                "metric": "cpu_percent",
                "value": metrics["cpu_percent"],
                "threshold": self.thresholds["cpu_percent"],
                "message": f"High CPU usage: {metrics['cpu_percent']:.1f}%"
            })
        
        # Check memory
        if metrics.get("memory_percent", 0) > self.thresholds["memory_percent"]:
            alerts.append({
                "level": "warning",
                "metric": "memory_percent",
                "value": metrics["memory_percent"],
                "threshold": self.thresholds["memory_percent"],
                "message": f"High memory usage: {metrics['memory_percent']:.1f}%"
            })
        
        # Check disk
        if metrics.get("disk_percent", 0) > self.thresholds["disk_percent"]:
            alerts.append({
                "level": "critical",
                "metric": "disk_percent",
                "value": metrics["disk_percent"],
                "threshold": self.thresholds["disk_percent"],
                "message": f"Low disk space: {metrics['disk_percent']:.1f}% used"
            })
        
        # Check error rate
        if metrics.get("error_rate", 0) > self.thresholds["error_rate"]:
            alerts.append({
                "level": "error",
                "metric": "error_rate",
                "value": metrics["error_rate"],
                "threshold": self.thresholds["error_rate"],
                "message": f"High error rate: {metrics['error_rate']:.2%}"
            })
        
        # Log and store alerts
        for alert in alerts:
            logger.warning(f"Performance alert: {alert['message']}")
            self.alerts.append({
                **alert,
                "timestamp": datetime.now()
            })
    
    def record_request(self, response_time: float, success: bool = True):
        """Record application request metrics"""
        self.counters["total_requests"] += 1
        if not success:
            self.counters["total_errors"] += 1
        
        # Store response time
        self.metrics_history["response_time"].append({
            "timestamp": datetime.now(),
            "value": response_time * 1000  # Convert to milliseconds
        })
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics"""
        return self.current_metrics.copy()
    
    def get_statistics(self, metric: str, duration: Optional[timedelta] = None) -> Dict[str, float]:
        """
        Calculate statistics for a metric.
        
        Args:
            metric: Metric name
            duration: Time window for statistics (None for all history)
            
        Returns:
            Dictionary with min, max, mean, median, std_dev
        """
        if metric not in self.metrics_history:
            return {}
        
        history = self.metrics_history[metric]
        if not history:
            return {}
        
        # Filter by duration if specified
        if duration:
            cutoff = datetime.now() - duration
            values = [h["value"] for h in history if h["timestamp"] > cutoff]
        else:
            values = [h["value"] for h in history]
        
        if not values:
            return {}
        
        return {
            "min": min(values),
            "max": max(values),
            "mean": statistics.mean(values),
            "median": statistics.median(values),
            "std_dev": statistics.stdev(values) if len(values) > 1 else 0
        }
    
    def get_alerts(self, level: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get performance alerts"""
        if level:
            return [a for a in self.alerts if a["level"] == level]
        return self.alerts.copy()
    
    def clear_alerts(self):
        """Clear all alerts"""
        self.alerts.clear()
    
    def set_threshold(self, metric: str, value: float):
        """Set alert threshold for a metric"""
        self.thresholds[metric] = value
    
    def get_report(self) -> Dict[str, Any]:
        """Generate performance report"""
        uptime = time.time() - self.counters["start_time"]
        
        report = {
            "uptime_seconds": uptime,
            "uptime_human": self._format_duration(uptime),
            "total_requests": self.counters["total_requests"],
            "total_errors": self.counters["total_errors"],
            "success_rate": 1 - (self.counters["total_errors"] / self.counters["total_requests"]) if self.counters["total_requests"] > 0 else 1,
            "current_metrics": self.current_metrics,
            "statistics": {},
            "alerts_count": len(self.alerts),
            "recent_alerts": self.alerts[-10:]  # Last 10 alerts
        }
        
        # Add statistics for key metrics
        for metric in ["cpu_percent", "memory_percent", "response_time"]:
            report["statistics"][metric] = self.get_statistics(metric)
        
        return report
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format"""
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        
        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        parts.append(f"{secs}s")
        
        return " ".join(parts)

class RequestTracker:
    """
    Track individual request performance.
    Useful for identifying slow operations.
    """
    
    def __init__(self, monitor: PerformanceMonitor):
        self.monitor = monitor
        self.active_requests = {}
    
    async def track_request(self, request_id: str):
        """Start tracking a request"""
        self.active_requests[request_id] = {
            "start_time": time.time(),
            "memory_start": psutil.Process().memory_info().rss
        }
    
    async def complete_request(self, request_id: str, success: bool = True):
        """Complete request tracking"""
        if request_id not in self.active_requests:
            return
        
        request_data = self.active_requests.pop(request_id)
        
        # Calculate metrics
        response_time = time.time() - request_data["start_time"]
        memory_used = psutil.Process().memory_info().rss - request_data["memory_start"]
        
        # Record in monitor
        self.monitor.record_request(response_time, success)
        
        # Log slow requests
        if response_time > 1.0:  # More than 1 second
            logger.warning(f"Slow request {request_id}: {response_time:.2f}s")
        
        return {
            "request_id": request_id,
            "response_time": response_time,
            "memory_used": memory_used,
            "success": success
        }
