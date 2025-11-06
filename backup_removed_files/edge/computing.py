"""
Edge Computing Framework for BLNCS Enterprise
Provides distributed processing, low-latency responses, and intelligent data routing
"""

import time
import threading
import asyncio
from typing import Dict, List, Optional, Any, Callable, Tuple
from collections import defaultdict, deque
from datetime import datetime, timedelta
import json
import logging
import socket
import struct
import pickle
import weakref
from concurrent.futures import ThreadPoolExecutor, Future
import networkx as nx

logger = logging.getLogger(__name__)

class EdgeNode:
    """Edge computing node representation"""

    def __init__(self, node_id: str, location: Dict[str, float], capabilities: Dict[str, Any]):
        self.node_id = node_id
        self.location = location  # {'lat': float, 'lng': float}
        self.capabilities = capabilities
        self.load = 0.0  # CPU load percentage
        self.bandwidth = capabilities.get('bandwidth', 100)  # Mbps
        self.storage = capabilities.get('storage', 1000)  # GB
        self.last_heartbeat = time.time()
        self.is_active = True
        self.processing_queue = deque(maxlen=1000)
        self.executor = ThreadPoolExecutor(max_workers=capabilities.get('cpu_cores', 4))

    def calculate_distance(self, other_location: Dict[str, float]) -> float:
        """Calculate distance to another location (simplified)"""
        # In production, use proper geospatial calculations
        lat1, lng1 = self.location['lat'], self.location['lng']
        lat2, lng2 = other_location['lat'], other_location['lng']

        # Simple Euclidean distance (not geographically accurate)
        return ((lat1 - lat2) ** 2 + (lng1 - lng2) ** 2) ** 0.5

    def can_handle_request(self, request_requirements: Dict[str, Any]) -> bool:
        """Check if node can handle request requirements"""
        required_cpu = request_requirements.get('cpu', 0)
        required_memory = request_requirements.get('memory', 0)
        required_storage = request_requirements.get('storage', 0)

        return (
            self.load + required_cpu <= 100 and
            required_memory <= self.capabilities.get('memory', 8) and
            required_storage <= self.storage
        )

    def process_request(self, request_id: str, request_data: Dict[str, Any],
                       callback: Callable[[str, Any], None]) -> Future:
        """Process request asynchronously"""
        future = self.executor.submit(self._execute_request, request_id, request_data)
        future.add_done_callback(lambda f: callback(request_id, f.result()))
        return future

    def _execute_request(self, request_id: str, request_data: Dict[str, Any]) -> Any:
        """Execute request (simplified)"""
        request_type = request_data.get('type', 'generic')

        # Simulate processing time based on request complexity
        complexity = request_data.get('complexity', 1.0)
        processing_time = complexity * 0.1  # 100ms per unit complexity

        time.sleep(processing_time)

        # Return mock result
        return {
            'request_id': request_id,
            'node_id': self.node_id,
            'processing_time': processing_time,
            'result': f"Processed {request_type} request",
            'timestamp': time.time()
        }

class EdgeNetwork:
    """Edge computing network management"""

    def __init__(self):
        self.nodes = {}
        self.network_graph = nx.Graph()
        self.routing_table = {}
        self.load_balancer = EdgeLoadBalancer()
        self.data_router = IntelligentDataRouter()
        self.lock = threading.Lock()

    def register_node(self, node: EdgeNode):
        """Register edge node"""
        with self.lock:
            self.nodes[node.node_id] = node
            self.network_graph.add_node(node.node_id, data=node)
            self._update_routing_table()

        logger.info(f"Registered edge node: {node.node_id}")

    def unregister_node(self, node_id: str):
        """Unregister edge node"""
        with self.lock:
            if node_id in self.nodes:
                node = self.nodes[node_id]
                node.is_active = False
                node.executor.shutdown(wait=False)

                del self.nodes[node_id]
                self.network_graph.remove_node(node_id)
                self._update_routing_table()

        logger.info(f"Unregistered edge node: {node_id}")

    def find_optimal_node(self, request_requirements: Dict[str, Any],
                         client_location: Dict[str, float] = None) -> Optional[EdgeNode]:
        """Find optimal edge node for request"""
        candidates = []

        for node in self.nodes.values():
            if node.is_active and node.can_handle_request(request_requirements):
                # Calculate score based on distance, load, and capabilities
                distance = node.calculate_distance(client_location) if client_location else 0
                load_penalty = node.load * 0.1
                capability_score = sum(node.capabilities.values()) / len(node.capabilities)

                score = capability_score - distance * 0.01 - load_penalty
                candidates.append((node, score))

        if candidates:
            # Return node with highest score
            return max(candidates, key=lambda x: x[1])[0]

        return None

    def route_request(self, request_id: str, request_data: Dict[str, Any],
                     client_location: Dict[str, float] = None) -> Optional[str]:
        """Route request to optimal edge node"""
        optimal_node = self.find_optimal_node(request_data, client_location)

        if optimal_node:
            # Update node load
            request_cpu = request_data.get('cpu', 1.0)
            optimal_node.load = min(100.0, optimal_node.load + request_cpu)

            # Route to node
            return optimal_node.node_id
        else:
            logger.warning(f"No suitable edge node found for request {request_id}")
            return None

    def _update_routing_table(self):
        """Update network routing table"""
        self.routing_table = {}

        for node_id in self.nodes:
            # Calculate routes to all other nodes
            try:
                paths = nx.shortest_path(self.network_graph, source=node_id)
                self.routing_table[node_id] = paths
            except nx.NetworkXNoPath:
                logger.warning(f"No path found from node {node_id}")

    def get_network_status(self) -> Dict[str, Any]:
        """Get edge network status"""
        with self.lock:
            active_nodes = [node_id for node_id, node in self.nodes.items() if node.is_active]

        node_status = {}
        for node_id, node in self.nodes.items():
            node_status[node_id] = {
                'is_active': node.is_active,
                'load': node.load,
                'last_heartbeat': node.last_heartbeat,
                'location': node.location,
                'capabilities': node.capabilities
            }

        return {
            'total_nodes': len(self.nodes),
            'active_nodes': len(active_nodes),
            'network_connectivity': nx.is_connected(self.network_graph) if self.nodes else True,
            'average_load': sum(node.load for node in self.nodes.values()) / len(self.nodes) if self.nodes else 0,
            'node_details': node_status
        }

class EdgeLoadBalancer:
    """Intelligent load balancing for edge nodes"""

    def __init__(self):
        self.load_history = deque(maxlen=10000)
        self.prediction_model = None
        self.lock = threading.Lock()

    def record_load_metrics(self, node_id: str, metrics: Dict[str, float]):
        """Record load metrics for prediction"""
        with self.lock:
            self.load_history.append({
                'timestamp': time.time(),
                'node_id': node_id,
                'metrics': metrics
            })

    def predict_optimal_distribution(self, request_load: Dict[str, float]) -> Dict[str, float]:
        """Predict optimal load distribution"""
        with self.lock:
            if len(self.load_history) < 100:
                # Insufficient data, use simple round-robin
                return self._simple_distribution(request_load)

            # Use historical data for prediction
            return self._predictive_distribution(request_load)

    def _simple_distribution(self, request_load: Dict[str, float]) -> Dict[str, float]:
        """Simple load distribution"""
        total_load = sum(request_load.values())
        if total_load == 0:
            return {}

        return {node_id: load / total_load for node_id, load in request_load.items()}

    def _predictive_distribution(self, request_load: Dict[str, float]) -> Dict[str, float]:
        """Predictive load distribution based on historical data"""
        # Simplified prediction - in production, use ML models
        node_predictions = {}

        for node_id in request_load.keys():
            # Get recent metrics for node
            recent_metrics = [
                entry for entry in self.load_history
                if entry['node_id'] == node_id
            ][-10:]  # Last 10 entries

            if recent_metrics:
                avg_load = sum(entry['metrics'].get('cpu', 0) for entry in recent_metrics) / len(recent_metrics)
                # Predict future load
                predicted_load = avg_load * 1.1  # Simple prediction
                node_predictions[node_id] = predicted_load
            else:
                node_predictions[node_id] = 50.0  # Default prediction

        total_predicted = sum(node_predictions.values())
        if total_predicted == 0:
            return self._simple_distribution(request_load)

        return {
            node_id: node_predictions[node_id] / total_predicted
            for node_id in request_load.keys()
        }

class IntelligentDataRouter:
    """Intelligent data routing and caching"""

    def __init__(self):
        self.routing_policies = {}
        self.cache_locations = defaultdict(dict)
        self.data_flow_analytics = deque(maxlen=50000)
        self.lock = threading.Lock()

    def define_routing_policy(self, policy_name: str, policy_config: Dict[str, Any]):
        """Define data routing policy"""
        self.routing_policies[policy_name] = {
            'name': policy_name,
            'priority_data_types': policy_config.get('priority_data_types', []),
            'cache_strategy': policy_config.get('cache_strategy', 'lru'),
            'replication_factor': policy_config.get('replication_factor', 2),
            'latency_threshold': policy_config.get('latency_threshold', 100),  # ms
            'bandwidth_threshold': policy_config.get('bandwidth_threshold', 50)  # Mbps
        }

    def route_data(self, data: Any, source_location: Dict[str, float],
                  target_location: Dict[str, float], policy: str = 'default') -> List[str]:
        """Route data using intelligent algorithms"""
        policy_config = self.routing_policies.get(policy, {})

        # Find optimal route
        optimal_route = self._find_optimal_route(source_location, target_location, policy_config)

        # Record analytics
        with self.lock:
            self.data_flow_analytics.append({
                'timestamp': time.time(),
                'source': source_location,
                'target': target_location,
                'data_size': len(str(data)),
                'route': optimal_route,
                'policy': policy
            })

        return optimal_route

    def _find_optimal_route(self, source: Dict[str, float], target: Dict[str, float],
                           policy: Dict[str, Any]) -> List[str]:
        """Find optimal data route"""
        # Simplified routing - in production, use sophisticated algorithms
        # For now, return direct route
        return [f"route_{source['lat']}_{source['lng']}_to_{target['lat']}_{target['lng']}"]

    def cache_data(self, data_key: str, data: Any, location: Dict[str, float],
                  ttl_seconds: int = 3600):
        """Cache data at edge location"""
        with self.lock:
            cache_entry = {
                'data': data,
                'cached_at': time.time(),
                'ttl': ttl_seconds,
                'access_count': 0,
                'last_accessed': time.time()
            }

            self.cache_locations[str(location)][data_key] = cache_entry

    def get_cached_data(self, data_key: str, location: Dict[str, float]) -> Optional[Any]:
        """Get cached data from edge location"""
        location_str = str(location)

        with self.lock:
            if location_str in self.cache_locations and data_key in self.cache_locations[location_str]:
                cache_entry = self.cache_locations[location_str][data_key]

                # Check TTL
                if time.time() - cache_entry['cached_at'] > cache_entry['ttl']:
                    del self.cache_locations[location_str][data_key]
                    return None

                # Update access statistics
                cache_entry['access_count'] += 1
                cache_entry['last_accessed'] = time.time()

                return cache_entry['data']

        return None

class EdgeOrchestrator:
    """Main edge computing orchestrator"""

    def __init__(self):
        self.edge_network = EdgeNetwork()
        self.task_scheduler = EdgeTaskScheduler()
        self.data_manager = EdgeDataManager()
        self.performance_monitor = EdgePerformanceMonitor()
        self.lock = threading.Lock()

    def submit_task(self, task_id: str, task_data: Dict[str, Any],
                   requirements: Dict[str, Any], client_location: Dict[str, float] = None) -> str:
        """Submit task to edge network"""
        # Find optimal node
        optimal_node_id = self.edge_network.route_request(task_id, requirements, client_location)

        if not optimal_node_id:
            return "no_available_nodes"

        optimal_node = self.edge_network.nodes[optimal_node_id]

        # Submit task to node
        def task_callback(task_id: str, result: Any):
            self._handle_task_completion(task_id, result)

        future = optimal_node.process_request(task_id, task_data, task_callback)

        # Register task with scheduler
        self.task_scheduler.register_task(task_id, optimal_node_id, future)

        logger.info(f"Submitted task {task_id} to edge node {optimal_node_id}")
        return optimal_node_id

    def _handle_task_completion(self, task_id: str, result: Any):
        """Handle task completion"""
        # Update performance metrics
        self.performance_monitor.record_completion(task_id, result)

        # Clean up task from scheduler
        self.task_scheduler.complete_task(task_id)

        logger.info(f"Task {task_id} completed with result: {result}")

    def get_edge_status(self) -> Dict[str, Any]:
        """Get comprehensive edge computing status"""
        network_status = self.edge_network.get_network_status()
        scheduler_status = self.task_scheduler.get_status()
        performance_status = self.performance_monitor.get_metrics()

        return {
            'network': network_status,
            'scheduler': scheduler_status,
            'performance': performance_status,
            'overall_health': self._calculate_overall_health(network_status, scheduler_status, performance_status)
        }

    def _calculate_overall_health(self, network: Dict[str, Any], scheduler: Dict[str, Any],
                                 performance: Dict[str, Any]) -> str:
        """Calculate overall edge computing health"""
        # Simple health calculation
        network_health = 1.0 if network['network_connectivity'] else 0.5
        scheduler_health = 1.0 if scheduler.get('active_tasks', 0) > 0 else 0.8
        performance_health = 1.0 if performance.get('avg_response_time', 0) < 100 else 0.7

        overall_score = (network_health + scheduler_health + performance_health) / 3

        if overall_score >= 0.9:
            return 'excellent'
        elif overall_score >= 0.7:
            return 'good'
        elif overall_score >= 0.5:
            return 'fair'
        else:
            return 'poor'

class EdgeTaskScheduler:
    """Task scheduling for edge computing"""

    def __init__(self):
        self.active_tasks = {}
        self.completed_tasks = deque(maxlen=10000)
        self.task_queue = deque()
        self.lock = threading.Lock()

    def register_task(self, task_id: str, node_id: str, future: Future):
        """Register active task"""
        with self.lock:
            self.active_tasks[task_id] = {
                'node_id': node_id,
                'future': future,
                'start_time': time.time(),
                'status': 'running'
            }

    def complete_task(self, task_id: str):
        """Mark task as completed"""
        with self.lock:
            if task_id in self.active_tasks:
                task_info = self.active_tasks[task_id]
                task_info['end_time'] = time.time()
                task_info['status'] = 'completed'
                task_info['duration'] = task_info['end_time'] - task_info['start_time']

                self.completed_tasks.append(task_info)
                del self.active_tasks[task_id]

    def get_status(self) -> Dict[str, Any]:
        """Get scheduler status"""
        with self.lock:
            return {
                'active_tasks': len(self.active_tasks),
                'completed_tasks_24h': len([t for t in self.completed_tasks
                                          if time.time() - t.get('end_time', 0) < 86400]),
                'avg_task_duration': self._calculate_avg_duration()
            }

    def _calculate_avg_duration(self) -> float:
        """Calculate average task duration"""
        recent_tasks = [t for t in self.completed_tasks if 'duration' in t][-100:]
        if not recent_tasks:
            return 0.0

        return sum(t['duration'] for t in recent_tasks) / len(recent_tasks)

class EdgeDataManager:
    """Data management for edge computing"""

    def __init__(self):
        self.data_stores = defaultdict(dict)
        self.replication_status = {}
        self.data_access_patterns = deque(maxlen=10000)
        self.lock = threading.Lock()

    def store_data(self, data_key: str, data: Any, replication_factor: int = 2):
        """Store data with replication"""
        with self.lock:
            # Store in multiple locations for redundancy
            locations = list(self.data_stores.keys())[:replication_factor]

            for location in locations:
                self.data_stores[location][data_key] = {
                    'data': data,
                    'stored_at': time.time(),
                    'replication_factor': replication_factor
                }

            self.replication_status[data_key] = {
                'replication_factor': replication_factor,
                'locations': locations,
                'last_verified': time.time()
            }

    def retrieve_data(self, data_key: str) -> Optional[Any]:
        """Retrieve data from nearest location"""
        with self.lock:
            # Find available locations
            available_locations = []
            for location, store in self.data_stores.items():
                if data_key in store:
                    available_locations.append(location)

            if not available_locations:
                return None

            # Return from first available location
            location = available_locations[0]
            data_entry = self.data_stores[location][data_key]

            # Record access pattern
            self.data_access_patterns.append({
                'timestamp': time.time(),
                'data_key': data_key,
                'location': location,
                'access_type': 'read'
            })

            return data_entry['data']

class EdgePerformanceMonitor:
    """Performance monitoring for edge computing"""

    def __init__(self):
        self.performance_metrics = deque(maxlen=10000)
        self.node_metrics = defaultdict(list)
        self.lock = threading.Lock()

    def record_completion(self, task_id: str, result: Dict[str, Any]):
        """Record task completion metrics"""
        with self.lock:
            metrics = {
                'timestamp': time.time(),
                'task_id': task_id,
                'node_id': result.get('node_id', 'unknown'),
                'processing_time': result.get('processing_time', 0),
                'success': True
            }

            self.performance_metrics.append(metrics)
            self.node_metrics[result.get('node_id', 'unknown')].append(metrics)

    def get_metrics(self) -> Dict[str, Any]:
        """Get performance metrics"""
        with self.lock:
            recent_metrics = list(self.performance_metrics)[-1000:]  # Last 1000 metrics

        if not recent_metrics:
            return {'error': 'No metrics available'}

        # Calculate aggregate metrics
        total_tasks = len(recent_metrics)
        successful_tasks = sum(1 for m in recent_metrics if m.get('success', False))
        avg_processing_time = sum(m['processing_time'] for m in recent_metrics) / total_tasks

        # Node-specific metrics
        node_performance = {}
        for node_id, metrics in self.node_metrics.items():
            if metrics:
                node_performance[node_id] = {
                    'tasks_completed': len(metrics),
                    'avg_processing_time': sum(m['processing_time'] for m in metrics) / len(metrics),
                    'success_rate': sum(1 for m in metrics if m.get('success', False)) / len(metrics)
                }

        return {
            'summary': {
                'total_tasks': total_tasks,
                'success_rate': successful_tasks / total_tasks if total_tasks > 0 else 0,
                'avg_processing_time': avg_processing_time,
                'unique_nodes': len(node_performance)
            },
            'node_performance': node_performance,
            'recent_trend': self._calculate_performance_trend(recent_metrics)
        }

    def _calculate_performance_trend(self, metrics: List[Dict[str, Any]]) -> str:
        """Calculate performance trend"""
        if len(metrics) < 20:
            return 'insufficient_data'

        recent_half = metrics[-10:]
        older_half = metrics[-20:-10]

        recent_avg = sum(m['processing_time'] for m in recent_half) / len(recent_half)
        older_avg = sum(m['processing_time'] for m in older_half) / len(older_half)

        if recent_avg < older_avg * 0.9:
            return 'improving'
        elif recent_avg > older_avg * 1.1:
            return 'degrading'
        else:
            return 'stable'

# Global edge computing instances
edge_orchestrator = EdgeOrchestrator()

def init_edge_computing():
    """Initialize edge computing system"""
    logger.info("Initializing edge computing system")

    # Register sample edge nodes
    edge_nodes = [
        EdgeNode('edge_node_1', {'lat': 37.7749, 'lng': -122.4194}, {  # San Francisco
            'cpu_cores': 8,
            'memory': 16,
            'storage': 1000,
            'bandwidth': 1000
        }),
        EdgeNode('edge_node_2', {'lat': 40.7128, 'lng': -74.0060}, {  # New York
            'cpu_cores': 4,
            'memory': 8,
            'storage': 500,
            'bandwidth': 500
        }),
        EdgeNode('edge_node_3', {'lat': 51.5074, 'lng': -0.1278}, {  # London
            'cpu_cores': 6,
            'memory': 12,
            'storage': 750,
            'bandwidth': 750
        })
    ]

    for node in edge_nodes:
        edge_orchestrator.edge_network.register_node(node)

    # Define routing policies
    edge_orchestrator.edge_network.data_router.define_routing_policy('latency_sensitive', {
        'priority_data_types': ['real_time', 'streaming'],
        'cache_strategy': 'lru',
        'replication_factor': 1,
        'latency_threshold': 50,
        'bandwidth_threshold': 100
    })

    logger.info("Edge computing system initialized")

def submit_edge_task(task_id: str, task_data: Dict[str, Any], requirements: Dict[str, Any],
                    client_location: Dict[str, float] = None) -> str:
    """Submit task to edge computing network"""
    return edge_orchestrator.submit_task(task_id, task_data, requirements, client_location)

def get_edge_computing_status() -> Dict[str, Any]:
    """Get edge computing system status"""
    return edge_orchestrator.get_edge_status()
