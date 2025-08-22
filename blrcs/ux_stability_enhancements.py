# BLRCS UX and Stability Enhancement System
# Enhanced user experience and system stability improvements

import asyncio
import time
import logging
import json
import traceback
from typing import Any, Dict, List, Optional, Callable, Union, AsyncGenerator
from dataclasses import dataclass, field
from contextlib import asynccontextmanager
from functools import wraps
from collections import deque, defaultdict
from enum import Enum
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

class UXPriority(Enum):
    """UX Priority levels"""
    CRITICAL = "critical"
    HIGH = "high" 
    MEDIUM = "medium"
    LOW = "low"

class StabilityLevel(Enum):
    """System stability levels"""
    STABLE = "stable"
    DEGRADED = "degraded"
    UNSTABLE = "unstable"
    CRITICAL = "critical"

@dataclass
class ResponseMetrics:
    """Response time and performance metrics"""
    endpoint: str
    response_time_ms: float
    status_code: int
    payload_size_bytes: int
    timestamp: float
    user_id: Optional[str] = None
    error: Optional[str] = None

@dataclass
class UXImprovement:
    """UX improvement tracking"""
    category: str
    description: str
    priority: UXPriority
    impact_score: float
    implementation_cost: str
    status: str
    metrics_before: Dict[str, Any] = field(default_factory=dict)
    metrics_after: Dict[str, Any] = field(default_factory=dict)

class ResponseTimeOptimizer:
    """Response time optimization system"""
    
    def __init__(self, target_response_ms: float = 200):
        self.target_response_ms = target_response_ms
        self.metrics: deque = deque(maxlen=1000)
        self.slow_endpoints = defaultdict(list)
        self.optimization_rules = []
        self._lock = threading.Lock()
        
    def record_response(self, metrics: ResponseMetrics):
        """Record response metrics"""
        with self._lock:
            self.metrics.append(metrics)
            
            # Track slow endpoints
            if metrics.response_time_ms > self.target_response_ms:
                self.slow_endpoints[metrics.endpoint].append(metrics)
                
                # Keep only recent slow responses
                if len(self.slow_endpoints[metrics.endpoint]) > 50:
                    self.slow_endpoints[metrics.endpoint] = \
                        self.slow_endpoints[metrics.endpoint][-50:]
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Get performance analysis report"""
        with self._lock:
            if not self.metrics:
                return {"error": "No metrics available"}
                
            response_times = [m.response_time_ms for m in self.metrics]
            
            # Calculate percentiles
            sorted_times = sorted(response_times)
            total = len(sorted_times)
            
            percentiles = {
                "p50": sorted_times[int(total * 0.5)] if total > 0 else 0,
                "p75": sorted_times[int(total * 0.75)] if total > 0 else 0,
                "p90": sorted_times[int(total * 0.9)] if total > 0 else 0,
                "p95": sorted_times[int(total * 0.95)] if total > 0 else 0,
                "p99": sorted_times[int(total * 0.99)] if total > 0 else 0
            }
            
            # Identify problematic endpoints
            slow_endpoints = {}
            for endpoint, slow_responses in self.slow_endpoints.items():
                if len(slow_responses) >= 3:  # At least 3 slow responses
                    avg_time = sum(r.response_time_ms for r in slow_responses) / len(slow_responses)
                    slow_endpoints[endpoint] = {
                        "average_response_ms": avg_time,
                        "slow_count": len(slow_responses),
                        "improvement_needed_ms": avg_time - self.target_response_ms
                    }
            
            return {
                "target_response_ms": self.target_response_ms,
                "total_requests": len(self.metrics),
                "average_response_ms": sum(response_times) / len(response_times),
                "percentiles": percentiles,
                "slow_endpoints": slow_endpoints,
                "recommendations": self._generate_recommendations(slow_endpoints)
            }
    
    def _generate_recommendations(self, slow_endpoints: Dict) -> List[str]:
        """Generate performance improvement recommendations"""
        recommendations = []
        
        for endpoint, data in slow_endpoints.items():
            if data["average_response_ms"] > 1000:
                recommendations.append(
                    f"Critical: {endpoint} averages {data['average_response_ms']:.1f}ms - "
                    "Consider caching, database optimization, or async processing"
                )
            elif data["average_response_ms"] > 500:
                recommendations.append(
                    f"High: {endpoint} averages {data['average_response_ms']:.1f}ms - "
                    "Review query efficiency and consider response compression"
                )
            elif data["average_response_ms"] > self.target_response_ms:
                recommendations.append(
                    f"Medium: {endpoint} averages {data['average_response_ms']:.1f}ms - "
                    "Minor optimizations recommended"
                )
        
        return recommendations

class StabilityMonitor:
    """System stability monitoring and enhancement"""
    
    def __init__(self):
        self.error_counts = defaultdict(int)
        self.error_patterns = defaultdict(list)
        self.stability_level = StabilityLevel.STABLE
        self.recovery_actions = {}
        self.circuit_breakers = {}
        self._lock = threading.Lock()
    
    def record_error(self, error: Exception, context: Dict[str, Any]):
        """Record system error for stability analysis"""
        with self._lock:
            error_type = type(error).__name__
            error_msg = str(error)
            
            self.error_counts[error_type] += 1
            self.error_patterns[error_type].append({
                "message": error_msg,
                "context": context,
                "timestamp": time.time(),
                "traceback": traceback.format_exc()
            })
            
            # Keep only recent errors
            if len(self.error_patterns[error_type]) > 100:
                self.error_patterns[error_type] = \
                    self.error_patterns[error_type][-100:]
            
            # Update stability level
            self._update_stability_level()
    
    def _update_stability_level(self):
        """Update system stability level based on error patterns"""
        recent_errors = 0
        current_time = time.time()
        
        # Count errors in last 5 minutes
        for error_list in self.error_patterns.values():
            recent_errors += sum(1 for e in error_list 
                               if current_time - e["timestamp"] < 300)
        
        if recent_errors > 100:
            self.stability_level = StabilityLevel.CRITICAL
        elif recent_errors > 50:
            self.stability_level = StabilityLevel.UNSTABLE
        elif recent_errors > 20:
            self.stability_level = StabilityLevel.DEGRADED
        else:
            self.stability_level = StabilityLevel.STABLE
    
    def get_stability_report(self) -> Dict[str, Any]:
        """Get system stability report"""
        with self._lock:
            current_time = time.time()
            
            # Analyze error patterns
            error_analysis = {}
            for error_type, error_list in self.error_patterns.items():
                recent_errors = [e for e in error_list 
                               if current_time - e["timestamp"] < 3600]  # Last hour
                
                if recent_errors:
                    error_analysis[error_type] = {
                        "total_count": self.error_counts[error_type],
                        "recent_count": len(recent_errors),
                        "recent_messages": list(set(e["message"] for e in recent_errors[-10:])),
                        "severity": self._assess_error_severity(error_type, len(recent_errors))
                    }
            
            return {
                "stability_level": self.stability_level.value,
                "total_error_types": len(self.error_counts),
                "error_analysis": error_analysis,
                "recommendations": self._generate_stability_recommendations(error_analysis)
            }
    
    def _assess_error_severity(self, error_type: str, recent_count: int) -> str:
        """Assess severity of error type"""
        critical_errors = ["ConnectionError", "DatabaseError", "SecurityError"]
        high_errors = ["TimeoutError", "ValidationError", "AuthenticationError"]
        
        if error_type in critical_errors or recent_count > 20:
            return "critical"
        elif error_type in high_errors or recent_count > 10:
            return "high"
        elif recent_count > 5:
            return "medium"
        else:
            return "low"
    
    def _generate_stability_recommendations(self, error_analysis: Dict) -> List[str]:
        """Generate stability improvement recommendations"""
        recommendations = []
        
        for error_type, data in error_analysis.items():
            if data["severity"] == "critical":
                recommendations.append(
                    f"Critical: {error_type} occurred {data['recent_count']} times recently - "
                    "Immediate investigation and mitigation required"
                )
            elif data["severity"] == "high":
                recommendations.append(
                    f"High: {error_type} frequency elevated - "
                    "Review error handling and implement circuit breaker"
                )
        
        return recommendations

class UserExperienceOptimizer:
    """Comprehensive UX optimization system"""
    
    def __init__(self):
        self.response_optimizer = ResponseTimeOptimizer()
        self.stability_monitor = StabilityMonitor()
        self.ux_improvements = []
        self.user_feedback = deque(maxlen=1000)
        self.a_b_tests = {}
        
    def track_user_action(self, action: str, user_id: str, metrics: Dict[str, Any]):
        """Track user action for UX analysis"""
        self.user_feedback.append({
            "action": action,
            "user_id": user_id,
            "metrics": metrics,
            "timestamp": time.time()
        })
    
    def add_ux_improvement(self, improvement: UXImprovement):
        """Add UX improvement to tracking"""
        self.ux_improvements.append(improvement)
        logger.info(f"Added UX improvement: {improvement.description}")
    
    def get_ux_dashboard(self) -> Dict[str, Any]:
        """Get comprehensive UX dashboard data"""
        performance_report = self.response_optimizer.get_performance_report()
        stability_report = self.stability_monitor.get_stability_report()
        
        # Calculate UX score
        ux_score = self._calculate_ux_score(performance_report, stability_report)
        
        return {
            "ux_score": ux_score,
            "performance": performance_report,
            "stability": stability_report,
            "improvements": [
                {
                    "category": imp.category,
                    "description": imp.description,
                    "priority": imp.priority.value,
                    "status": imp.status,
                    "impact_score": imp.impact_score
                }
                for imp in self.ux_improvements[-20:]  # Latest 20
            ],
            "user_feedback_count": len(self.user_feedback),
            "recommendations": self._generate_comprehensive_recommendations(
                performance_report, stability_report
            )
        }
    
    def _calculate_ux_score(self, performance: Dict, stability: Dict) -> float:
        """Calculate overall UX score (0-100)"""
        base_score = 100.0
        
        # Performance impact
        if "average_response_ms" in performance:
            avg_response = performance["average_response_ms"]
            if avg_response > 1000:
                base_score -= 30
            elif avg_response > 500:
                base_score -= 20
            elif avg_response > 200:
                base_score -= 10
        
        # Stability impact
        stability_level = stability.get("stability_level", "stable")
        if stability_level == "critical":
            base_score -= 40
        elif stability_level == "unstable":
            base_score -= 25
        elif stability_level == "degraded":
            base_score -= 15
        
        # Error count impact
        error_count = len(stability.get("error_analysis", {}))
        if error_count > 10:
            base_score -= 15
        elif error_count > 5:
            base_score -= 10
        
        return max(0.0, min(100.0, base_score))
    
    def _generate_comprehensive_recommendations(self, performance: Dict, stability: Dict) -> List[str]:
        """Generate comprehensive improvement recommendations"""
        recommendations = []
        
        # Add performance recommendations
        recommendations.extend(performance.get("recommendations", []))
        
        # Add stability recommendations
        recommendations.extend(stability.get("recommendations", []))
        
        # Add UX-specific recommendations
        ux_score = self._calculate_ux_score(performance, stability)
        if ux_score < 70:
            recommendations.append(
                "UX Score below 70 - Consider implementing progressive loading, "
                "better error messages, and user feedback collection"
            )
        
        return recommendations

# Decorator for automatic response time tracking
def track_response_time(optimizer: ResponseTimeOptimizer):
    """Decorator to automatically track response times"""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            error = None
            status_code = 200
            
            try:
                result = await func(*args, **kwargs)
                return result
            except Exception as e:
                error = str(e)
                status_code = 500
                raise
            finally:
                response_time = (time.time() - start_time) * 1000
                
                # Extract endpoint name from function
                endpoint = getattr(func, '__name__', 'unknown')
                
                metrics = ResponseMetrics(
                    endpoint=endpoint,
                    response_time_ms=response_time,
                    status_code=status_code,
                    payload_size_bytes=0,  # Could be enhanced to track actual size
                    timestamp=time.time(),
                    error=error
                )
                
                optimizer.record_response(metrics)
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            error = None
            status_code = 200
            
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                error = str(e)
                status_code = 500
                raise
            finally:
                response_time = (time.time() - start_time) * 1000
                
                endpoint = getattr(func, '__name__', 'unknown')
                
                metrics = ResponseMetrics(
                    endpoint=endpoint,
                    response_time_ms=response_time,
                    status_code=status_code,
                    payload_size_bytes=0,
                    timestamp=time.time(),
                    error=error
                )
                
                optimizer.record_response(metrics)
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    return decorator

# Global UX optimizer instance
ux_optimizer = UserExperienceOptimizer()

# Convenience functions
def get_ux_dashboard():
    """Get UX dashboard data"""
    return ux_optimizer.get_ux_dashboard()

def record_user_feedback(action: str, user_id: str, metrics: Dict[str, Any]):
    """Record user feedback"""
    ux_optimizer.track_user_action(action, user_id, metrics)

def add_improvement(category: str, description: str, priority: UXPriority, 
                   impact_score: float, implementation_cost: str):
    """Add UX improvement"""
    improvement = UXImprovement(
        category=category,
        description=description,
        priority=priority,
        impact_score=impact_score,
        implementation_cost=implementation_cost,
        status="planned"
    )
    ux_optimizer.add_ux_improvement(improvement)