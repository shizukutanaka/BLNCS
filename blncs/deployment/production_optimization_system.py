"""
Production Deployment Optimization System for BLNCS
Auto-scaling, load balancing, and deployment orchestration
"""

import asyncio
import os
import sys
import time
import psutil
import docker
import kubernetes
from typing import Dict, Any, Optional, List, Tuple, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from collections import deque, defaultdict
import yaml
import json
import subprocess
import threading
import multiprocessing

class DeploymentEnvironment(Enum):
    """Deployment environments"""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    DISASTER_RECOVERY = "disaster_recovery"

class ScalingStrategy(Enum):
    """Auto-scaling strategies"""
    CPU_BASED = "cpu_based"
    MEMORY_BASED = "memory_based"
    REQUEST_BASED = "request_based"
    CUSTOM_METRIC = "custom_metric"
    PREDICTIVE = "predictive"

class LoadBalancingAlgorithm(Enum):
    """Load balancing algorithms"""
    ROUND_ROBIN = "round_robin"
    LEAST_CONNECTIONS = "least_connections"
    WEIGHTED = "weighted"
    IP_HASH = "ip_hash"
    RANDOM = "random"

@dataclass
class ServiceInstance:
    """Service instance information"""
    instance_id: str
    service_name: str
    host: str
    port: int
    status: str
    health_check_url: str
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    request_count: int = 0
    error_rate: float = 0.0
    response_time: float = 0.0
    weight: float = 1.0
    last_health_check: Optional[datetime] = None

@dataclass
class DeploymentConfig:
    """Deployment configuration"""
    environment: DeploymentEnvironment
    min_instances: int = 1
    max_instances: int = 10
    target_cpu_percent: float = 70.0
    target_memory_percent: float = 80.0
    scale_up_threshold: float = 0.8
    scale_down_threshold: float = 0.3
    health_check_interval: int = 30
    graceful_shutdown_timeout: int = 30
    rolling_update_batch_size: int = 2
    database_connection_pool_size: int = 20
    cache_size_mb: int = 500
    log_level: str = "INFO"

class AutoScaler:
    """Intelligent auto-scaling manager"""

    def __init__(self, config: DeploymentConfig):
        self.config = config
        self.instances: Dict[str, ServiceInstance] = {}
        self.scaling_history = deque(maxlen=100)
        self.metrics_buffer = defaultdict(lambda: deque(maxlen=60))
        self.scaling_decisions = deque(maxlen=50)
        self.lock = threading.Lock()

    def calculate_desired_instances(self, current_metrics: Dict[str, float]) -> int:
        """Calculate desired number of instances"""
        current_count = len(self.instances)

        # Store metrics
        for key, value in current_metrics.items():
            self.metrics_buffer[key].append(value)

        # Calculate average metrics
        avg_cpu = self._calculate_average('cpu')
        avg_memory = self._calculate_average('memory')
        avg_requests = self._calculate_average('requests_per_second')

        # Determine scaling need
        scale_factor = 1.0

        # CPU-based scaling
        if avg_cpu > self.config.target_cpu_percent:
            cpu_factor = avg_cpu / self.config.target_cpu_percent
            scale_factor = max(scale_factor, cpu_factor)

        # Memory-based scaling
        if avg_memory > self.config.target_memory_percent:
            memory_factor = avg_memory / self.config.target_memory_percent
            scale_factor = max(scale_factor, memory_factor)

        # Request-based scaling (assuming target of 1000 req/s per instance)
        target_rps_per_instance = 1000
        if avg_requests > 0:
            request_factor = avg_requests / (current_count * target_rps_per_instance)
            scale_factor = max(scale_factor, request_factor)

        # Apply scaling factor
        desired = int(current_count * scale_factor)

        # Apply constraints
        desired = max(self.config.min_instances, min(self.config.max_instances, desired))

        # Record decision
        self.scaling_decisions.append({
            'timestamp': datetime.now(),
            'current': current_count,
            'desired': desired,
            'metrics': {
                'cpu': avg_cpu,
                'memory': avg_memory,
                'requests': avg_requests
            }
        })

        return desired

    def _calculate_average(self, metric: str) -> float:
        """Calculate average of metric buffer"""
        if metric not in self.metrics_buffer or not self.metrics_buffer[metric]:
            return 0.0
        return sum(self.metrics_buffer[metric]) / len(self.metrics_buffer[metric])

    async def scale_up(self, count: int) -> List[ServiceInstance]:
        """Scale up by launching new instances"""
        new_instances = []

        for i in range(count):
            instance = await self._launch_instance()
            if instance:
                new_instances.append(instance)
                self.instances[instance.instance_id] = instance

        self.scaling_history.append({
            'timestamp': datetime.now(),
            'action': 'scale_up',
            'count': len(new_instances)
        })

        return new_instances

    async def scale_down(self, count: int) -> List[str]:
        """Scale down by terminating instances"""
        terminated = []

        # Select instances to terminate (prefer unhealthy or low-traffic)
        candidates = sorted(
            self.instances.values(),
            key=lambda x: (x.status != 'healthy', x.request_count)
        )

        for instance in candidates[:count]:
            if await self._terminate_instance(instance):
                terminated.append(instance.instance_id)
                del self.instances[instance.instance_id]

            if len(terminated) >= count:
                break

        self.scaling_history.append({
            'timestamp': datetime.now(),
            'action': 'scale_down',
            'count': len(terminated)
        })

        return terminated

    async def _launch_instance(self) -> Optional[ServiceInstance]:
        """Launch a new service instance"""
        # This would integrate with Docker/Kubernetes
        instance_id = f"instance_{time.time()}"

        instance = ServiceInstance(
            instance_id=instance_id,
            service_name="blncs",
            host=f"10.0.0.{len(self.instances) + 1}",
            port=8000 + len(self.instances),
            status="starting",
            health_check_url="/health"
        )

        # Simulate instance startup
        await asyncio.sleep(2)
        instance.status = "healthy"

        return instance

    async def _terminate_instance(self, instance: ServiceInstance) -> bool:
        """Gracefully terminate an instance"""
        # Send shutdown signal
        instance.status = "terminating"

        # Wait for graceful shutdown
        await asyncio.sleep(self.config.graceful_shutdown_timeout)

        return True

class LoadBalancer:
    """Intelligent load balancer"""

    def __init__(self, algorithm: LoadBalancingAlgorithm = LoadBalancingAlgorithm.LEAST_CONNECTIONS):
        self.algorithm = algorithm
        self.instances: List[ServiceInstance] = []
        self.current_index = 0
        self.connection_count = defaultdict(int)
        self.lock = threading.Lock()

    def select_instance(self, client_ip: Optional[str] = None) -> Optional[ServiceInstance]:
        """Select instance based on load balancing algorithm"""
        with self.lock:
            healthy_instances = [i for i in self.instances if i.status == 'healthy']

            if not healthy_instances:
                return None

            if self.algorithm == LoadBalancingAlgorithm.ROUND_ROBIN:
                instance = healthy_instances[self.current_index % len(healthy_instances)]
                self.current_index += 1
                return instance

            elif self.algorithm == LoadBalancingAlgorithm.LEAST_CONNECTIONS:
                return min(healthy_instances, key=lambda x: self.connection_count[x.instance_id])

            elif self.algorithm == LoadBalancingAlgorithm.WEIGHTED:
                # Select based on weight
                import random
                weights = [i.weight for i in healthy_instances]
                return random.choices(healthy_instances, weights=weights, k=1)[0]

            elif self.algorithm == LoadBalancingAlgorithm.IP_HASH:
                if client_ip:
                    hash_value = hash(client_ip)
                    return healthy_instances[hash_value % len(healthy_instances)]
                return healthy_instances[0]

            elif self.algorithm == LoadBalancingAlgorithm.RANDOM:
                import random
                return random.choice(healthy_instances)

    def update_instances(self, instances: List[ServiceInstance]):
        """Update instance list"""
        with self.lock:
            self.instances = instances

    def record_request_start(self, instance_id: str):
        """Record request start"""
        self.connection_count[instance_id] += 1

    def record_request_end(self, instance_id: str):
        """Record request end"""
        self.connection_count[instance_id] = max(0, self.connection_count[instance_id] - 1)

class HealthChecker:
    """Service health monitoring"""

    def __init__(self, check_interval: int = 30):
        self.check_interval = check_interval
        self.health_status = {}
        self.check_history = defaultdict(lambda: deque(maxlen=10))

    async def check_instance_health(self, instance: ServiceInstance) -> bool:
        """Check health of a single instance"""
        try:
            # Simulate health check (would make HTTP request in production)
            import aiohttp
            async with aiohttp.ClientSession() as session:
                url = f"http://{instance.host}:{instance.port}{instance.health_check_url}"
                async with session.get(url, timeout=5) as response:
                    healthy = response.status == 200

            # Update instance metrics
            instance.cpu_usage = psutil.cpu_percent()
            instance.memory_usage = psutil.virtual_memory().percent
            instance.last_health_check = datetime.now()

            # Record history
            self.check_history[instance.instance_id].append({
                'timestamp': datetime.now(),
                'healthy': healthy,
                'cpu': instance.cpu_usage,
                'memory': instance.memory_usage
            })

            return healthy

        except Exception:
            return False

    async def monitor_health(self, instances: List[ServiceInstance]):
        """Continuously monitor instance health"""
        while True:
            for instance in instances:
                healthy = await self.check_instance_health(instance)
                instance.status = "healthy" if healthy else "unhealthy"

            await asyncio.sleep(self.check_interval)

class ConfigurationManager:
    """Dynamic configuration management"""

    def __init__(self, environment: DeploymentEnvironment):
        self.environment = environment
        self.config_cache = {}
        self.config_version = 0
        self.lock = threading.Lock()

    def load_configuration(self, config_file: str) -> Dict[str, Any]:
        """Load configuration from file"""
        with open(config_file, 'r') as f:
            if config_file.endswith('.yaml'):
                config = yaml.safe_load(f)
            else:
                config = json.load(f)

        # Apply environment-specific overrides
        env_config = config.get('environments', {}).get(self.environment.value, {})
        base_config = config.get('base', {})

        # Merge configurations
        final_config = {**base_config, **env_config}

        # Cache configuration
        with self.lock:
            self.config_cache = final_config
            self.config_version += 1

        return final_config

    def get_config(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        with self.lock:
            return self.config_cache.get(key, default)

    def update_config(self, key: str, value: Any):
        """Update configuration dynamically"""
        with self.lock:
            self.config_cache[key] = value
            self.config_version += 1

    def generate_deployment_manifest(self, service_name: str, replicas: int) -> Dict[str, Any]:
        """Generate Kubernetes deployment manifest"""
        return {
            'apiVersion': 'apps/v1',
            'kind': 'Deployment',
            'metadata': {
                'name': service_name,
                'labels': {'app': service_name}
            },
            'spec': {
                'replicas': replicas,
                'selector': {
                    'matchLabels': {'app': service_name}
                },
                'template': {
                    'metadata': {
                        'labels': {'app': service_name}
                    },
                    'spec': {
                        'containers': [{
                            'name': service_name,
                            'image': f'{service_name}:latest',
                            'ports': [{'containerPort': 8000}],
                            'env': [
                                {'name': 'ENVIRONMENT', 'value': self.environment.value},
                                {'name': 'CONFIG_VERSION', 'value': str(self.config_version)}
                            ],
                            'resources': {
                                'requests': {
                                    'memory': '256Mi',
                                    'cpu': '250m'
                                },
                                'limits': {
                                    'memory': '512Mi',
                                    'cpu': '500m'
                                }
                            },
                            'livenessProbe': {
                                'httpGet': {
                                    'path': '/health',
                                    'port': 8000
                                },
                                'initialDelaySeconds': 30,
                                'periodSeconds': 10
                            },
                            'readinessProbe': {
                                'httpGet': {
                                    'path': '/ready',
                                    'port': 8000
                                },
                                'initialDelaySeconds': 5,
                                'periodSeconds': 5
                            }
                        }]
                    }
                }
            }
        }

class DeploymentOrchestrator:
    """Main deployment orchestration system"""

    def __init__(self, environment: DeploymentEnvironment, config_file: Optional[str] = None):
        self.environment = environment
        self.config_manager = ConfigurationManager(environment)

        if config_file:
            config_data = self.config_manager.load_configuration(config_file)
        else:
            config_data = {}

        self.config = DeploymentConfig(
            environment=environment,
            **config_data
        )

        self.auto_scaler = AutoScaler(self.config)
        self.load_balancer = LoadBalancer()
        self.health_checker = HealthChecker(self.config.health_check_interval)

        self.deployment_status = "initialized"
        self.deployment_history = deque(maxlen=100)

        # Container orchestration clients
        self.docker_client = None
        self.k8s_client = None

        self._initialize_orchestration()

    def _initialize_orchestration(self):
        """Initialize container orchestration clients"""
        try:
            # Initialize Docker client
            self.docker_client = docker.from_env()
        except Exception:
            pass

        try:
            # Initialize Kubernetes client
            kubernetes.config.load_incluster_config()
            self.k8s_client = kubernetes.client.CoreV1Api()
        except Exception:
            try:
                kubernetes.config.load_kube_config()
                self.k8s_client = kubernetes.client.CoreV1Api()
            except Exception:
                pass

    async def deploy(self, service_name: str, version: str) -> bool:
        """Deploy service"""
        try:
            self.deployment_status = "deploying"

            # Generate deployment configuration
            manifest = self.config_manager.generate_deployment_manifest(
                service_name,
                self.config.min_instances
            )

            # Deploy using appropriate orchestrator
            if self.k8s_client:
                success = await self._deploy_kubernetes(manifest)
            elif self.docker_client:
                success = await self._deploy_docker(service_name, version)
            else:
                success = await self._deploy_native(service_name, version)

            if success:
                self.deployment_status = "deployed"
                self.deployment_history.append({
                    'timestamp': datetime.now(),
                    'service': service_name,
                    'version': version,
                    'status': 'success'
                })
            else:
                self.deployment_status = "failed"

            return success

        except Exception as e:
            self.deployment_status = "error"
            print(f"Deployment error: {e}")
            return False

    async def _deploy_kubernetes(self, manifest: Dict[str, Any]) -> bool:
        """Deploy using Kubernetes"""
        try:
            apps_v1 = kubernetes.client.AppsV1Api()
            apps_v1.create_namespaced_deployment(
                namespace="default",
                body=manifest
            )
            return True
        except Exception as e:
            print(f"Kubernetes deployment error: {e}")
            return False

    async def _deploy_docker(self, service_name: str, version: str) -> bool:
        """Deploy using Docker"""
        try:
            # Pull latest image
            image = f"{service_name}:{version}"
            self.docker_client.images.pull(image)

            # Run container
            container = self.docker_client.containers.run(
                image,
                detach=True,
                ports={'8000/tcp': 8000},
                environment={
                    'ENVIRONMENT': self.environment.value
                },
                restart_policy={'Name': 'always'}
            )

            return container.status == 'running'

        except Exception as e:
            print(f"Docker deployment error: {e}")
            return False

    async def _deploy_native(self, service_name: str, version: str) -> bool:
        """Deploy using native process"""
        try:
            # Start service process
            process = subprocess.Popen(
                [sys.executable, f"{service_name}.py"],
                env={**os.environ, 'ENVIRONMENT': self.environment.value}
            )

            # Wait for startup
            await asyncio.sleep(5)

            return process.poll() is None

        except Exception as e:
            print(f"Native deployment error: {e}")
            return False

    async def rolling_update(self, service_name: str, new_version: str) -> bool:
        """Perform rolling update"""
        instances = list(self.auto_scaler.instances.values())
        batch_size = self.config.rolling_update_batch_size

        for i in range(0, len(instances), batch_size):
            batch = instances[i:i+batch_size]

            # Update batch
            for instance in batch:
                # Mark as updating
                instance.status = "updating"

                # Deploy new version
                success = await self._update_instance(instance, new_version)

                if success:
                    instance.status = "healthy"
                else:
                    instance.status = "failed"
                    return False

            # Wait for batch to stabilize
            await asyncio.sleep(30)

        return True

    async def _update_instance(self, instance: ServiceInstance, version: str) -> bool:
        """Update a single instance"""
        # Implementation would update the actual instance
        await asyncio.sleep(2)  # Simulate update
        return True

    async def auto_scale_loop(self):
        """Continuous auto-scaling loop"""
        while True:
            try:
                # Collect current metrics
                metrics = await self._collect_metrics()

                # Calculate desired instances
                desired = self.auto_scaler.calculate_desired_instances(metrics)
                current = len(self.auto_scaler.instances)

                if desired > current:
                    # Scale up
                    await self.auto_scaler.scale_up(desired - current)
                elif desired < current:
                    # Scale down
                    await self.auto_scaler.scale_down(current - desired)

                # Update load balancer
                self.load_balancer.update_instances(list(self.auto_scaler.instances.values()))

                await asyncio.sleep(30)

            except Exception as e:
                print(f"Auto-scaling error: {e}")
                await asyncio.sleep(60)

    async def _collect_metrics(self) -> Dict[str, float]:
        """Collect system metrics"""
        cpu_percent = psutil.cpu_percent(interval=1)
        memory_percent = psutil.virtual_memory().percent

        # Calculate requests per second (would get from actual metrics)
        requests_per_second = sum(
            i.request_count for i in self.auto_scaler.instances.values()
        ) / 60.0  # Assuming counts are per minute

        return {
            'cpu': cpu_percent,
            'memory': memory_percent,
            'requests_per_second': requests_per_second
        }

    def get_deployment_status(self) -> Dict[str, Any]:
        """Get comprehensive deployment status"""
        return {
            'environment': self.environment.value,
            'status': self.deployment_status,
            'instances': len(self.auto_scaler.instances),
            'healthy_instances': sum(
                1 for i in self.auto_scaler.instances.values()
                if i.status == 'healthy'
            ),
            'load_balancer': {
                'algorithm': self.load_balancer.algorithm.value,
                'total_connections': sum(self.load_balancer.connection_count.values())
            },
            'auto_scaling': {
                'min_instances': self.config.min_instances,
                'max_instances': self.config.max_instances,
                'recent_decisions': list(self.auto_scaler.scaling_decisions)[-5:]
            },
            'deployment_history': list(self.deployment_history)[-10:]
        }

    async def graceful_shutdown(self):
        """Perform graceful shutdown"""
        self.deployment_status = "shutting_down"

        # Stop accepting new requests
        # Drain existing connections
        # Save state

        # Terminate all instances
        for instance in list(self.auto_scaler.instances.values()):
            await self.auto_scaler._terminate_instance(instance)

        self.deployment_status = "shutdown"

# Singleton instance
_orchestrator = None

def get_orchestrator(environment: DeploymentEnvironment = DeploymentEnvironment.PRODUCTION) -> DeploymentOrchestrator:
    """Get or create singleton orchestrator"""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = DeploymentOrchestrator(environment)
    return _orchestrator