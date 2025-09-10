"""
Advanced Resource Optimizer and Auto-Scaling System
Intelligent resource management with predictive scaling and optimization.
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from dataclasses import dataclass, field
import structlog
import psutil
import numpy as np
from collections import deque, defaultdict
import threading
import os
import subprocess

logger = structlog.get_logger(__name__)

class ResourceType(Enum):
    CPU = "cpu"
    MEMORY = "memory" 
    DISK = "disk"
    NETWORK = "network"
    GPU = "gpu"
    DATABASE = "database"
    CACHE = "cache"

class ScalingDirection(Enum):
    UP = "up"
    DOWN = "down"
    MAINTAIN = "maintain"

class OptimizationStrategy(Enum):
    AGGRESSIVE = "aggressive"
    BALANCED = "balanced"
    CONSERVATIVE = "conservative"
    PREDICTIVE = "predictive"

@dataclass
class ResourceMetrics:
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    disk_io_read: int
    disk_io_write: int
    network_bytes_sent: int
    network_bytes_recv: int
    process_count: int
    thread_count: int
    load_average: Tuple[float, float, float]
    custom_metrics: Dict[str, float] = field(default_factory=dict)

@dataclass
class ScalingRecommendation:
    resource_type: ResourceType
    direction: ScalingDirection
    magnitude: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    reason: str
    estimated_impact: Dict[str, float]
    cost_benefit_ratio: float

class ResourceOptimizer:
    """
    Advanced resource optimizer with predictive scaling capabilities.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._default_config()
        self.metrics_history: deque = deque(maxlen=self.config['history_size'])
        self.resource_targets = self.config['resource_targets']
        self.scaling_rules = self.config['scaling_rules']
        self.optimization_strategy = OptimizationStrategy(
            self.config.get('optimization_strategy', 'balanced')
        )
        
        self.predictor = ResourcePredictor()
        self.auto_scaler = AutoScaler(self.config)
        self.process_optimizer = ProcessOptimizer()
        self.cache_optimizer = CacheOptimizer()
        
        self.running = False
        self.optimization_thread = None
        self.stats = {
            'optimizations_performed': 0,
            'resources_saved': defaultdict(float),
            'performance_improvements': defaultdict(float),
            'scaling_actions': defaultdict(int)
        }

    def _default_config(self) -> Dict[str, Any]:
        """Default configuration for resource optimization."""
        return {
            'history_size': 1000,
            'optimization_interval': 30,  # seconds
            'prediction_window': 300,  # 5 minutes
            'scaling_cooldown': 180,  # 3 minutes
            'resource_targets': {
                'cpu_utilization': {'min': 20, 'max': 70, 'optimal': 50},
                'memory_utilization': {'min': 30, 'max': 80, 'optimal': 60},
                'disk_utilization': {'min': 10, 'max': 85, 'optimal': 70},
                'network_utilization': {'min': 5, 'max': 80, 'optimal': 40}
            },
            'scaling_rules': {
                'cpu_scale_up_threshold': 75,
                'cpu_scale_down_threshold': 25,
                'memory_scale_up_threshold': 85,
                'memory_scale_down_threshold': 40,
                'sustained_duration': 120  # seconds
            },
            'optimization_strategy': 'balanced',
            'enable_predictive_scaling': True,
            'enable_process_optimization': True,
            'enable_cache_optimization': True,
            'auto_scaling_enabled': True
        }

    async def start(self):
        """Start the resource optimizer."""
        if self.running:
            return
        
        self.running = True
        logger.info("Starting Resource Optimizer")
        
        # Start optimization loop
        self.optimization_thread = threading.Thread(
            target=self._optimization_loop,
            daemon=True
        )
        self.optimization_thread.start()
        
        # Initialize components
        await self.predictor.initialize()
        await self.auto_scaler.initialize()
        
        logger.info("Resource optimizer started successfully")

    async def stop(self):
        """Stop the resource optimizer."""
        self.running = False
        
        if self.optimization_thread:
            self.optimization_thread.join(timeout=5)
        
        logger.info("Resource optimizer stopped")

    def _optimization_loop(self):
        """Main optimization loop running in separate thread."""
        while self.running:
            try:
                # Collect metrics
                metrics = self._collect_metrics()
                self.metrics_history.append(metrics)
                
                # Perform optimization
                asyncio.run(self._optimize_resources(metrics))
                
                # Wait for next cycle
                time.sleep(self.config['optimization_interval'])
                
            except Exception as e:
                logger.error(f"Error in optimization loop: {e}")
                time.sleep(10)

    def _collect_metrics(self) -> ResourceMetrics:
        """Collect comprehensive system metrics."""
        try:
            # Basic system metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            disk_io = psutil.disk_io_counters()
            network_io = psutil.net_io_counters()
            
            # Process metrics
            process_count = len(psutil.pids())
            thread_count = sum(p.num_threads() for p in psutil.process_iter(['num_threads']) if p.info['num_threads'])
            
            # Load average (Unix-like systems)
            load_avg = (0.0, 0.0, 0.0)
            if hasattr(os, 'getloadavg'):
                load_avg = os.getloadavg()
            
            # Custom application metrics
            custom_metrics = self._collect_custom_metrics()
            
            return ResourceMetrics(
                timestamp=datetime.now(),
                cpu_percent=cpu_percent,
                memory_percent=memory.percent,
                disk_percent=disk.percent,
                disk_io_read=disk_io.read_bytes if disk_io else 0,
                disk_io_write=disk_io.write_bytes if disk_io else 0,
                network_bytes_sent=network_io.bytes_sent if network_io else 0,
                network_bytes_recv=network_io.bytes_recv if network_io else 0,
                process_count=process_count,
                thread_count=thread_count,
                load_average=load_avg,
                custom_metrics=custom_metrics
            )
            
        except Exception as e:
            logger.error(f"Error collecting metrics: {e}")
            return ResourceMetrics(timestamp=datetime.now(), cpu_percent=0, memory_percent=0, 
                                 disk_percent=0, disk_io_read=0, disk_io_write=0,
                                 network_bytes_sent=0, network_bytes_recv=0,
                                 process_count=0, thread_count=0, load_average=(0, 0, 0))

    def _collect_custom_metrics(self) -> Dict[str, float]:
        """Collect custom application-specific metrics."""
        custom_metrics = {}
        
        try:
            # Lightning Network specific metrics
            custom_metrics['channel_count'] = self._get_channel_count()
            custom_metrics['active_htlcs'] = self._get_active_htlcs()
            custom_metrics['pending_payments'] = self._get_pending_payments()
            
            # Database metrics
            custom_metrics['db_connections'] = self._get_db_connections()
            custom_metrics['db_query_time'] = self._get_avg_query_time()
            
            # Cache metrics  
            custom_metrics['cache_hit_rate'] = self._get_cache_hit_rate()
            custom_metrics['cache_memory_usage'] = self._get_cache_memory_usage()
            
        except Exception as e:
            logger.warning(f"Error collecting custom metrics: {e}")
        
        return custom_metrics

    async def _optimize_resources(self, current_metrics: ResourceMetrics):
        """Perform comprehensive resource optimization."""
        try:
            # Generate optimization recommendations
            recommendations = await self._generate_recommendations(current_metrics)
            
            # Apply optimizations
            for recommendation in recommendations:
                if recommendation.confidence > 0.7:
                    await self._apply_optimization(recommendation)
            
            # Auto-scaling decisions
            if self.config['auto_scaling_enabled']:
                scaling_actions = await self.auto_scaler.evaluate_scaling(current_metrics)
                for action in scaling_actions:
                    await self._execute_scaling_action(action)
            
            # Process optimization
            if self.config['enable_process_optimization']:
                await self.process_optimizer.optimize_processes(current_metrics)
            
            # Cache optimization
            if self.config['enable_cache_optimization']:
                await self.cache_optimizer.optimize_cache(current_metrics)
            
            self.stats['optimizations_performed'] += 1
            
        except Exception as e:
            logger.error(f"Error in resource optimization: {e}")

    async def _generate_recommendations(self, metrics: ResourceMetrics) -> List[ScalingRecommendation]:
        """Generate optimization recommendations based on current metrics and predictions."""
        recommendations = []
        
        # CPU optimization
        if metrics.cpu_percent > self.resource_targets['cpu_utilization']['max']:
            recommendations.append(ScalingRecommendation(
                resource_type=ResourceType.CPU,
                direction=ScalingDirection.UP,
                magnitude=min((metrics.cpu_percent - 70) / 30, 1.0),
                confidence=0.9,
                reason=f"CPU utilization at {metrics.cpu_percent:.1f}% exceeds target",
                estimated_impact={'performance': 0.3, 'cost': 0.2},
                cost_benefit_ratio=1.5
            ))
        elif metrics.cpu_percent < self.resource_targets['cpu_utilization']['min']:
            recommendations.append(ScalingRecommendation(
                resource_type=ResourceType.CPU,
                direction=ScalingDirection.DOWN,
                magnitude=min((30 - metrics.cpu_percent) / 20, 1.0),
                confidence=0.8,
                reason=f"CPU utilization at {metrics.cpu_percent:.1f}% below minimum target",
                estimated_impact={'cost_savings': 0.2, 'performance': -0.1},
                cost_benefit_ratio=2.0
            ))
        
        # Memory optimization
        if metrics.memory_percent > self.resource_targets['memory_utilization']['max']:
            recommendations.append(ScalingRecommendation(
                resource_type=ResourceType.MEMORY,
                direction=ScalingDirection.UP,
                magnitude=min((metrics.memory_percent - 80) / 20, 1.0),
                confidence=0.95,
                reason=f"Memory utilization at {metrics.memory_percent:.1f}% exceeds target",
                estimated_impact={'stability': 0.4, 'cost': 0.3},
                cost_benefit_ratio=1.3
            ))
        
        # Predictive recommendations
        if self.config['enable_predictive_scaling']:
            predicted_recommendations = await self.predictor.predict_resource_needs(
                self.metrics_history, self.config['prediction_window']
            )
            recommendations.extend(predicted_recommendations)
        
        return recommendations

    async def _apply_optimization(self, recommendation: ScalingRecommendation):
        """Apply a specific optimization recommendation."""
        try:
            if recommendation.resource_type == ResourceType.CPU:
                await self._optimize_cpu_usage(recommendation)
            elif recommendation.resource_type == ResourceType.MEMORY:
                await self._optimize_memory_usage(recommendation)
            elif recommendation.resource_type == ResourceType.DISK:
                await self._optimize_disk_usage(recommendation)
            elif recommendation.resource_type == ResourceType.CACHE:
                await self._optimize_cache_usage(recommendation)
            
            logger.info(f"Applied optimization: {recommendation.reason}")
            
        except Exception as e:
            logger.error(f"Failed to apply optimization {recommendation.reason}: {e}")

    async def _optimize_cpu_usage(self, recommendation: ScalingRecommendation):
        """Optimize CPU usage based on recommendation."""
        if recommendation.direction == ScalingDirection.UP:
            # Increase process priorities for critical tasks
            await self.process_optimizer.boost_critical_processes()
        elif recommendation.direction == ScalingDirection.DOWN:
            # Reduce CPU usage of non-critical processes
            await self.process_optimizer.throttle_background_processes()

    async def _optimize_memory_usage(self, recommendation: ScalingRecommendation):
        """Optimize memory usage based on recommendation."""
        if recommendation.direction == ScalingDirection.UP:
            # Clear unnecessary caches
            await self.cache_optimizer.clear_old_cache_entries()
            # Trigger garbage collection
            import gc
            gc.collect()
        elif recommendation.direction == ScalingDirection.DOWN:
            # Pre-load frequently used data
            await self.cache_optimizer.preload_frequent_data()

    async def _execute_scaling_action(self, action: Dict[str, Any]):
        """Execute auto-scaling action."""
        logger.info(f"Executing scaling action: {action}")
        self.stats['scaling_actions'][action.get('type', 'unknown')] += 1

    # Metric collection helper methods
    def _get_channel_count(self) -> float:
        """Get Lightning Network channel count."""
        return 0.0  # Placeholder

    def _get_active_htlcs(self) -> float:
        """Get active HTLC count."""
        return 0.0  # Placeholder

    def _get_pending_payments(self) -> float:
        """Get pending payment count."""
        return 0.0  # Placeholder

    def _get_db_connections(self) -> float:
        """Get database connection count."""
        return 0.0  # Placeholder

    def _get_avg_query_time(self) -> float:
        """Get average database query time."""
        return 0.0  # Placeholder

    def _get_cache_hit_rate(self) -> float:
        """Get cache hit rate."""
        return 0.0  # Placeholder

    def _get_cache_memory_usage(self) -> float:
        """Get cache memory usage."""
        return 0.0  # Placeholder

class ResourcePredictor:
    """Predictive analytics for resource usage patterns."""
    
    def __init__(self):
        self.model = None
        self.feature_history = deque(maxlen=1000)
    
    async def initialize(self):
        """Initialize the prediction model."""
        logger.info("Initializing resource predictor")
    
    async def predict_resource_needs(self, 
                                   history: deque, 
                                   prediction_window: int) -> List[ScalingRecommendation]:
        """Predict future resource needs and generate recommendations."""
        if len(history) < 10:
            return []
        
        try:
            # Simple trend analysis (can be replaced with ML model)
            recent_metrics = list(history)[-10:]
            
            # CPU trend analysis
            cpu_values = [m.cpu_percent for m in recent_metrics]
            cpu_trend = np.polyfit(range(len(cpu_values)), cpu_values, 1)[0]
            
            recommendations = []
            
            # If CPU usage is trending upward significantly
            if cpu_trend > 2.0:  # 2% increase per measurement
                recommendations.append(ScalingRecommendation(
                    resource_type=ResourceType.CPU,
                    direction=ScalingDirection.UP,
                    magnitude=min(cpu_trend / 10, 1.0),
                    confidence=0.7,
                    reason=f"Predicted CPU usage increase trend: {cpu_trend:.1f}%/interval",
                    estimated_impact={'performance': 0.2, 'cost': 0.15},
                    cost_benefit_ratio=1.4
                ))
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Error in resource prediction: {e}")
            return []

class AutoScaler:
    """Automatic scaling system with intelligent decision making."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.last_scaling_time = {}
        self.scaling_history = deque(maxlen=100)
    
    async def initialize(self):
        """Initialize the auto scaler."""
        logger.info("Initializing auto scaler")
    
    async def evaluate_scaling(self, metrics: ResourceMetrics) -> List[Dict[str, Any]]:
        """Evaluate if scaling actions are needed."""
        actions = []
        current_time = datetime.now()
        cooldown = timedelta(seconds=self.config['scaling_cooldown'])
        
        # CPU scaling evaluation
        if self._should_scale_cpu(metrics) and self._scaling_allowed('cpu', current_time, cooldown):
            actions.append(self._create_scaling_action('cpu', metrics.cpu_percent))
            self.last_scaling_time['cpu'] = current_time
        
        # Memory scaling evaluation
        if self._should_scale_memory(metrics) and self._scaling_allowed('memory', current_time, cooldown):
            actions.append(self._create_scaling_action('memory', metrics.memory_percent))
            self.last_scaling_time['memory'] = current_time
        
        return actions
    
    def _should_scale_cpu(self, metrics: ResourceMetrics) -> bool:
        """Determine if CPU scaling is needed."""
        return (metrics.cpu_percent > self.config['scaling_rules']['cpu_scale_up_threshold'] or
                metrics.cpu_percent < self.config['scaling_rules']['cpu_scale_down_threshold'])
    
    def _should_scale_memory(self, metrics: ResourceMetrics) -> bool:
        """Determine if memory scaling is needed."""
        return (metrics.memory_percent > self.config['scaling_rules']['memory_scale_up_threshold'] or
                metrics.memory_percent < self.config['scaling_rules']['memory_scale_down_threshold'])
    
    def _scaling_allowed(self, resource: str, current_time: datetime, cooldown: timedelta) -> bool:
        """Check if scaling is allowed (not in cooldown period)."""
        last_time = self.last_scaling_time.get(resource)
        return last_time is None or (current_time - last_time) > cooldown
    
    def _create_scaling_action(self, resource_type: str, current_usage: float) -> Dict[str, Any]:
        """Create a scaling action dictionary."""
        return {
            'type': f'{resource_type}_scaling',
            'resource': resource_type,
            'current_usage': current_usage,
            'timestamp': datetime.now(),
            'action': 'scale_up' if current_usage > 75 else 'scale_down'
        }

class ProcessOptimizer:
    """Optimize running processes for better resource utilization."""
    
    async def optimize_processes(self, metrics: ResourceMetrics):
        """Optimize running processes based on current metrics."""
        try:
            if metrics.cpu_percent > 80:
                await self.throttle_background_processes()
            elif metrics.memory_percent > 85:
                await self.reduce_memory_usage()
                
        except Exception as e:
            logger.error(f"Error optimizing processes: {e}")
    
    async def boost_critical_processes(self):
        """Boost priority of critical processes."""
        critical_processes = ['blncs', 'lnd', 'bitcoind']
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if any(name in proc.info['name'].lower() for name in critical_processes):
                    process = psutil.Process(proc.info['pid'])
                    process.nice(-5)  # Higher priority
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    
    async def throttle_background_processes(self):
        """Throttle background and non-critical processes."""
        background_processes = ['update', 'backup', 'sync', 'index']
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if any(name in proc.info['name'].lower() for name in background_processes):
                    process = psutil.Process(proc.info['pid'])
                    process.nice(10)  # Lower priority
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    
    async def reduce_memory_usage(self):
        """Reduce memory usage of processes."""
        # Trigger garbage collection in Python processes
        import gc
        gc.collect()

class CacheOptimizer:
    """Optimize caching strategies for better performance."""
    
    async def optimize_cache(self, metrics: ResourceMetrics):
        """Optimize cache based on current metrics."""
        if metrics.memory_percent > 80:
            await self.clear_old_cache_entries()
        elif metrics.memory_percent < 50:
            await self.preload_frequent_data()
    
    async def clear_old_cache_entries(self):
        """Clear old cache entries to free memory."""
        logger.info("Clearing old cache entries to optimize memory usage")
    
    async def preload_frequent_data(self):
        """Preload frequently accessed data into cache."""
        logger.info("Preloading frequent data to optimize performance")

# Global optimizer instance
_optimizer_instance = None

def get_resource_optimizer(config: Optional[Dict[str, Any]] = None) -> ResourceOptimizer:
    """Get the global resource optimizer instance."""
    global _optimizer_instance
    if _optimizer_instance is None:
        _optimizer_instance = ResourceOptimizer(config)
    return _optimizer_instance

async def initialize_resource_optimization(config: Optional[Dict[str, Any]] = None):
    """Initialize the resource optimization system."""
    optimizer = get_resource_optimizer(config)
    await optimizer.start()
    logger.info("Resource optimization system initialized successfully")
    return optimizer