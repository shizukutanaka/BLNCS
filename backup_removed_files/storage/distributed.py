"""
Distributed Storage Framework for BLNCS Enterprise
Provides IPFS integration, distributed file systems, and decentralized storage solutions
"""

import time
import threading
import hashlib
import json
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict, deque
from datetime import datetime, timedelta
import logging
import secrets
import base64
import asyncio
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class IPFSNode:
    """IPFS node representation and management"""

    def __init__(self, node_id: str, multiaddress: str, capabilities: Dict[str, Any]):
        self.node_id = node_id
        self.multiaddress = multiaddress
        self.capabilities = capabilities
        self.is_connected = False
        self.storage_capacity = capabilities.get('storage_gb', 1000)
        self.bandwidth_capacity = capabilities.get('bandwidth_mbps', 1000)
        self.reliability_score = 1.0
        self.last_seen = time.time()
        self.peers = set()

    def connect_to_network(self) -> bool:
        """Connect to IPFS network"""
        try:
            # Simulate IPFS node connection
            self.is_connected = True
            self.last_seen = time.time()
            logger.info(f"IPFS node {self.node_id} connected to network")
            return True
        except Exception as e:
            logger.error(f"Failed to connect IPFS node {self.node_id}: {e}")
            return False

    def disconnect_from_network(self):
        """Disconnect from IPFS network"""
        self.is_connected = False
        logger.info(f"IPFS node {self.node_id} disconnected from network")

class DistributedFileSystem:
    """Distributed file system implementation"""

    def __init__(self):
        self.files = {}
        self.file_chunks = defaultdict(list)
        self.replication_map = {}
        self.storage_nodes = {}
        self.lock = threading.Lock()

    def store_file(self, file_path: str, file_data: bytes, replication_factor: int = 3) -> str:
        """Store file in distributed file system"""
        file_hash = hashlib.sha256(file_data).hexdigest()
        file_size = len(file_data)

        # Split file into chunks
        chunk_size = 1024 * 1024  # 1MB chunks
        chunks = [file_data[i:i+chunk_size] for i in range(0, len(file_data), chunk_size)]

        with self.lock:
            self.files[file_hash] = {
                'file_path': file_path,
                'file_hash': file_hash,
                'file_size': file_size,
                'chunk_count': len(chunks),
                'stored_at': time.time(),
                'replication_factor': replication_factor
            }

            # Store chunks across nodes
            for i, chunk in enumerate(chunks):
                chunk_hash = hashlib.sha256(chunk).hexdigest()
                self.file_chunks[file_hash].append(chunk_hash)

                # Replicate chunk across multiple nodes
                available_nodes = list(self.storage_nodes.keys())
                if len(available_nodes) >= replication_factor:
                    selected_nodes = random.sample(available_nodes, replication_factor)
                else:
                    selected_nodes = available_nodes

                for node_id in selected_nodes:
                    self._store_chunk_on_node(node_id, chunk_hash, chunk)

        logger.info(f"Stored file {file_path} with hash {file_hash}")
        return file_hash

    def _store_chunk_on_node(self, node_id: str, chunk_hash: str, chunk_data: bytes):
        """Store chunk on specific node"""
        if node_id not in self.storage_nodes:
            self.storage_nodes[node_id] = {}

        self.storage_nodes[node_id][chunk_hash] = {
            'chunk_data': chunk_data,
            'stored_at': time.time(),
            'size': len(chunk_data)
        }

    def retrieve_file(self, file_hash: str) -> Optional[bytes]:
        """Retrieve file from distributed storage"""
        with self.lock:
            if file_hash not in self.files:
                return None

            file_info = self.files[file_hash]
            chunk_hashes = self.file_chunks[file_hash]

        # Retrieve all chunks
        file_chunks = []
        for chunk_hash in chunk_hashes:
            chunk_data = self._retrieve_chunk(chunk_hash)
            if chunk_data is None:
                logger.error(f"Failed to retrieve chunk {chunk_hash}")
                return None
            file_chunks.append(chunk_data)

        # Reassemble file
        return b''.join(file_chunks)

    def _retrieve_chunk(self, chunk_hash: str) -> Optional[bytes]:
        """Retrieve chunk from any available node"""
        # Find chunk in any node
        for node_id, node_storage in self.storage_nodes.items():
            if chunk_hash in node_storage:
                return node_storage[chunk_hash]['chunk_data']
        return None

    def add_storage_node(self, node_id: str, node_config: Dict[str, Any]):
        """Add storage node to distributed file system"""
        with self.lock:
            self.storage_nodes[node_id] = {
                'config': node_config,
                'available_space': node_config.get('capacity_gb', 100) * 1024 * 1024 * 1024,  # Convert to bytes
                'used_space': 0,
                'added_at': time.time()
            }

    def get_storage_status(self) -> Dict[str, Any]:
        """Get distributed storage status"""
        with self.lock:
            total_capacity = 0
            total_used = 0

            for node_id, node_info in self.storage_nodes.items():
                total_capacity += node_info['available_space']
                total_used += node_info['used_space']

            return {
                'total_nodes': len(self.storage_nodes),
                'total_capacity_bytes': total_capacity,
                'total_used_bytes': total_used,
                'utilization_percent': (total_used / total_capacity * 100) if total_capacity > 0 else 0,
                'total_files': len(self.files),
                'node_details': {
                    node_id: {
                        'capacity_gb': node['available_space'] / (1024 * 1024 * 1024),
                        'used_gb': node['used_space'] / (1024 * 1024 * 1024),
                        'utilization_percent': (node['used_space'] / node['available_space'] * 100) if node['available_space'] > 0 else 0
                    }
                    for node_id, node in self.storage_nodes.items()
                }
            }

class IPFSIntegration:
    """IPFS integration and management"""

    def __init__(self):
        self.ipfs_nodes = {}
        self.ipfs_gateway = "http://localhost:8080"  # Default IPFS gateway
        self.published_hashes = {}
        self.lock = threading.Lock()

    def add_ipfs_node(self, node: IPFSNode):
        """Add IPFS node"""
        with self.lock:
            self.ipfs_nodes[node.node_id] = node

    def publish_to_ipfs(self, data: bytes, metadata: Dict[str, Any] = None) -> str:
        """Publish data to IPFS"""
        # Generate content hash
        content_hash = hashlib.sha256(data).hexdigest()

        # Simulate IPFS publishing
        ipfs_hash = f"Qm{secrets.token_hex(44)}"  # IPFS hash format

        with self.lock:
            self.published_hashes[ipfs_hash] = {
                'content_hash': content_hash,
                'size': len(data),
                'metadata': metadata or {},
                'published_at': time.time(),
                'replication_factor': 3
            }

        logger.info(f"Published data to IPFS with hash {ipfs_hash}")
        return ipfs_hash

    def retrieve_from_ipfs(self, ipfs_hash: str) -> Optional[bytes]:
        """Retrieve data from IPFS"""
        with self.lock:
            if ipfs_hash not in self.published_hashes:
                return None

            # Simulate IPFS retrieval
            # In production, this would query actual IPFS network
            return f"Retrieved data from IPFS hash {ipfs_hash}".encode()

    def pin_content(self, ipfs_hash: str, node_id: str = None) -> bool:
        """Pin content on IPFS node"""
        with self.lock:
            if ipfs_hash not in self.published_hashes:
                return False

            # Simulate pinning
            self.published_hashes[ipfs_hash]['pinned_nodes'] = self.published_hashes[ipfs_hash].get('pinned_nodes', [])
            if node_id:
                if node_id not in self.published_hashes[ipfs_hash]['pinned_nodes']:
                    self.published_hashes[ipfs_hash]['pinned_nodes'].append(node_id)
            else:
                # Pin on all available nodes
                for node_id in self.ipfs_nodes.keys():
                    if node_id not in self.published_hashes[ipfs_hash]['pinned_nodes']:
                        self.published_hashes[ipfs_hash]['pinned_nodes'].append(node_id)

        logger.info(f"Pinned IPFS content {ipfs_hash}")
        return True

    def get_ipfs_status(self) -> Dict[str, Any]:
        """Get IPFS integration status"""
        with self.lock:
            return {
                'total_nodes': len(self.ipfs_nodes),
                'connected_nodes': len([n for n in self.ipfs_nodes.values() if n.is_connected]),
                'published_content': len(self.published_hashes),
                'node_details': {
                    node_id: {
                        'connected': node.is_connected,
                        'reliability': node.reliability_score,
                        'last_seen': node.last_seen
                    }
                    for node_id, node in self.ipfs_nodes.items()
                }
            }

class DecentralizedStorageManager:
    """Main decentralized storage management"""

    def __init__(self):
        self.distributed_fs = DistributedFileSystem()
        self.ipfs_integration = IPFSIntegration()
        self.storage_policies = {}
        self.replication_strategies = {}
        self.lock = threading.Lock()

    def define_storage_policy(self, policy_name: str, policy_config: Dict[str, Any]):
        """Define storage policy"""
        self.storage_policies[policy_name] = {
            'name': policy_name,
            'replication_factor': policy_config.get('replication_factor', 3),
            'encryption_required': policy_config.get('encryption_required', True),
            'compression_enabled': policy_config.get('compression_enabled', True),
            'access_patterns': policy_config.get('access_patterns', ['read_heavy', 'write_heavy']),
            'retention_policy': policy_config.get('retention_policy', 'permanent')
        }

    def define_replication_strategy(self, strategy_name: str, strategy_config: Dict[str, Any]):
        """Define replication strategy"""
        self.replication_strategies[strategy_name] = {
            'name': strategy_name,
            'replication_algorithm': strategy_config.get('algorithm', 'consistent_hashing'),
            'failure_detection': strategy_config.get('failure_detection', True),
            'auto_rebalancing': strategy_config.get('auto_rebalancing', True),
            'consistency_level': strategy_config.get('consistency_level', 'strong')
        }

    def store_data_securely(self, data: bytes, metadata: Dict[str, Any],
                           storage_policy: str = 'default') -> Dict[str, Any]:
        """Store data securely in distributed storage"""
        policy = self.storage_policies.get(storage_policy, {})

        # Apply encryption if required
        if policy.get('encryption_required', True):
            data = self._encrypt_data(data, metadata)

        # Apply compression if enabled
        if policy.get('compression_enabled', True):
            data = self._compress_data(data)

        # Store in distributed file system
        file_hash = self.distributed_fs.store_file(
            metadata.get('filename', 'unnamed'),
            data,
            policy.get('replication_factor', 3)
        )

        # Publish to IPFS for additional redundancy
        ipfs_hash = self.ipfs_integration.publish_to_ipfs(data, metadata)

        return {
            'file_hash': file_hash,
            'ipfs_hash': ipfs_hash,
            'storage_policy': storage_policy,
            'stored_at': time.time(),
            'data_size': len(data),
            'replication_factor': policy.get('replication_factor', 3)
        }

    def _encrypt_data(self, data: bytes, metadata: Dict[str, Any]) -> bytes:
        """Encrypt data before storage"""
        # Simplified encryption - in production, use proper encryption
        key = hashlib.sha256((metadata.get('encryption_key', 'default') + str(time.time())).encode()).digest()
        # XOR encryption for simulation
        encrypted = bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])
        return encrypted

    def _compress_data(self, data: bytes) -> bytes:
        """Compress data before storage"""
        # Simplified compression - in production, use proper compression algorithms
        # For simulation, just return original data
        return data

    def retrieve_data_securely(self, file_hash: str, decryption_key: str = None) -> Optional[bytes]:
        """Retrieve data securely from distributed storage"""
        # Retrieve from distributed file system
        data = self.distributed_fs.retrieve_file(file_hash)

        if data is None:
            return None

        # Try to decrypt if key provided
        if decryption_key:
            try:
                data = self._decrypt_data(data, decryption_key)
            except:
                pass  # Return encrypted data if decryption fails

        return data

    def _decrypt_data(self, encrypted_data: bytes, decryption_key: str) -> bytes:
        """Decrypt retrieved data"""
        # Reverse of encryption
        key = hashlib.sha256((decryption_key + str(time.time())).encode()).digest()
        return bytes([b ^ key[i % len(key)] for i, b in enumerate(encrypted_data)])

    def add_storage_node(self, node_id: str, node_type: str, node_config: Dict[str, Any]):
        """Add storage node"""
        if node_type == 'distributed_fs':
            self.distributed_fs.add_storage_node(node_id, node_config)
        elif node_type == 'ipfs':
            node = IPFSNode(node_id, node_config.get('multiaddress', ''), node_config)
            self.ipfs_integration.add_ipfs_node(node)

    def get_distributed_storage_status(self) -> Dict[str, Any]:
        """Get comprehensive distributed storage status"""
        fs_status = self.distributed_fs.get_storage_status()
        ipfs_status = self.ipfs_integration.get_ipfs_status()

        return {
            'distributed_filesystem': fs_status,
            'ipfs_integration': ipfs_status,
            'total_storage_capacity_gb': fs_status.get('total_capacity_bytes', 0) / (1024 * 1024 * 1024),
            'storage_efficiency': self._calculate_storage_efficiency(fs_status),
            'redundancy_level': self._calculate_redundancy_level()
        }

    def _calculate_storage_efficiency(self, fs_status: Dict[str, Any]) -> float:
        """Calculate storage efficiency"""
        if fs_status.get('total_capacity_bytes', 0) == 0:
            return 0.0

        return fs_status.get('utilization_percent', 0) / 100.0

    def _calculate_redundancy_level(self) -> float:
        """Calculate data redundancy level"""
        # Simplified calculation
        return 0.8  # 80% redundancy

class DataReplicationEngine:
    """Advanced data replication and consistency management"""

    def __init__(self):
        self.replication_sessions = {}
        self.consistency_models = {}
        self.replication_policies = {}
        self.lock = threading.Lock()

    def define_consistency_model(self, model_name: str, model_config: Dict[str, Any]):
        """Define consistency model"""
        self.consistency_models[model_name] = {
            'name': model_name,
            'consistency_level': model_config.get('level', 'eventual'),  # strong, eventual, weak
            'propagation_delay': model_config.get('propagation_delay', 100),  # ms
            'conflict_resolution': model_config.get('conflict_resolution', 'last_writer_wins')
        }

    def define_replication_policy(self, policy_name: str, policy_config: Dict[str, Any]):
        """Define replication policy"""
        self.replication_policies[policy_name] = {
            'name': policy_name,
            'replication_factor': policy_config.get('factor', 3),
            'synchronous_replication': policy_config.get('synchronous', False),
            'geo_distribution': policy_config.get('geo_distribution', 'regional'),
            'failure_tolerance': policy_config.get('failure_tolerance', 1)  # Number of node failures tolerated
        }

    def replicate_data(self, data_id: str, data: bytes, policy_name: str = 'default') -> bool:
        """Replicate data across distributed storage"""
        if policy_name not in self.replication_policies:
            return False

        policy = self.replication_policies[policy_name]

        try:
            # Create replication session
            session_id = f"replication_{secrets.token_hex(8)}"

            with self.lock:
                self.replication_sessions[session_id] = {
                    'session_id': session_id,
                    'data_id': data_id,
                    'policy': policy_name,
                    'replication_factor': policy['replication_factor'],
                    'status': 'replicating',
                    'created_at': time.time(),
                    'completed_nodes': 0,
                    'failed_nodes': 0
                }

            # Perform replication
            success = self._perform_replication(session_id, data, policy)

            # Update session status
            with self.lock:
                session = self.replication_sessions[session_id]
                if success:
                    session['status'] = 'completed'
                else:
                    session['status'] = 'failed'

            return success

        except Exception as e:
            logger.error(f"Data replication failed: {e}")
            return False

    def _perform_replication(self, session_id: str, data: bytes, policy: Dict[str, Any]) -> bool:
        """Perform actual data replication"""
        # Simulate replication to multiple nodes
        # In production, this would coordinate with actual storage nodes

        replication_factor = policy['replication_factor']
        simulated_nodes = [f"node_{i}" for i in range(replication_factor)]

        # Simulate replication delay
        time.sleep(0.1)

        return True

class StorageAnalytics:
    """Analytics and monitoring for distributed storage"""

    def __init__(self):
        self.access_patterns = deque(maxlen=100000)
        self.performance_metrics = deque(maxlen=50000)
        self.storage_anomalies = deque(maxlen=1000)
        self.lock = threading.Lock()

    def record_access_pattern(self, file_hash: str, access_type: str, response_time: float,
                            data_size: int, location: str = 'unknown'):
        """Record storage access pattern"""
        with self.lock:
            self.access_patterns.append({
                'timestamp': time.time(),
                'file_hash': file_hash,
                'access_type': access_type,  # read, write, delete
                'response_time': response_time,
                'data_size': data_size,
                'location': location
            })

    def record_performance_metric(self, component: str, metric_name: str, value: float):
        """Record performance metric"""
        with self.lock:
            self.performance_metrics.append({
                'timestamp': time.time(),
                'component': component,
                'metric_name': metric_name,
                'value': value
            })

    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """Detect storage anomalies"""
        with self.lock:
            recent_access = list(self.access_patterns)[-1000:]  # Last 1000 accesses

        anomalies = []

        if len(recent_access) < 100:
            return anomalies

        # Calculate baseline metrics
        response_times = [a['response_time'] for a in recent_access]
        avg_response_time = sum(response_times) / len(response_times)

        # Detect slow responses
        slow_threshold = avg_response_time * 2
        slow_accesses = [a for a in recent_access if a['response_time'] > slow_threshold]

        if slow_accesses:
            anomalies.append({
                'type': 'slow_response',
                'description': f"{len(slow_accesses)} slow responses detected",
                'severity': 'medium',
                'affected_files': list(set(a['file_hash'] for a in slow_accesses)),
                'timestamp': time.time()
            })

        # Detect unusual access patterns
        access_counts = defaultdict(int)
        for access in recent_access:
            access_counts[access['file_hash']] += 1

        # Find files with unusually high access frequency
        avg_access_count = sum(access_counts.values()) / len(access_counts)
        high_access_files = [f for f, count in access_counts.items() if count > avg_access_count * 3]

        if high_access_files:
            anomalies.append({
                'type': 'unusual_access_pattern',
                'description': f"High access frequency detected for {len(high_access_files)} files",
                'severity': 'low',
                'affected_files': high_access_files,
                'timestamp': time.time()
            })

        with self.lock:
            self.storage_anomalies.extend(anomalies)

        return anomalies

    def get_storage_analytics_report(self) -> Dict[str, Any]:
        """Get comprehensive storage analytics report"""
        with self.lock:
            recent_access = list(self.access_patterns)[-10000:]  # Last 10k accesses
            recent_metrics = list(self.performance_metrics)[-5000:]  # Last 5k metrics

        if not recent_access:
            return {'error': 'No analytics data available'}

        # Calculate access statistics
        access_by_type = defaultdict(int)
        total_response_time = 0
        total_data_transferred = 0

        for access in recent_access:
            access_by_type[access['access_type']] += 1
            total_response_time += access['response_time']
            total_data_transferred += access['data_size']

        # Calculate performance trends
        performance_by_component = defaultdict(list)
        for metric in recent_metrics:
            performance_by_component[metric['component']].append(metric['value'])

        component_performance = {}
        for component, values in performance_by_component.items():
            if values:
                component_performance[component] = {
                    'avg_value': sum(values) / len(values),
                    'min_value': min(values),
                    'max_value': max(values),
                    'sample_count': len(values)
                }

        return {
            'summary': {
                'total_accesses': len(recent_access),
                'unique_files': len(set(a['file_hash'] for a in recent_access)),
                'avg_response_time': total_response_time / len(recent_access),
                'total_data_transferred_gb': total_data_transferred / (1024 * 1024 * 1024),
                'analysis_period_hours': 24
            },
            'access_patterns': dict(access_by_type),
            'component_performance': component_performance,
            'detected_anomalies': len(self.storage_anomalies),
            'recommendations': self._generate_storage_recommendations(recent_access, component_performance)
        }

    def _generate_storage_recommendations(self, recent_access: List[Dict[str, Any]],
                                       component_performance: Dict[str, Dict[str, float]]) -> List[str]:
        """Generate storage optimization recommendations"""
        recommendations = []

        # Check for performance issues
        slow_components = [
            comp for comp, perf in component_performance.items()
            if perf.get('avg_value', 0) > 0.8  # Over 80% utilization
        ]

        if slow_components:
            recommendations.append(f"Performance issues detected in components: {', '.join(slow_components)}")

        # Check access patterns
        read_heavy_files = [a for a in recent_access if a['access_type'] == 'read']
        write_heavy_files = [a for a in recent_access if a['access_type'] == 'write']

        if len(read_heavy_files) > len(write_heavy_files) * 3:
            recommendations.append("Read-heavy workload detected - consider caching optimization")

        if not recommendations:
            recommendations.append("Storage performance is within acceptable parameters")

        return recommendations

# Global distributed storage instances
decentralized_storage = DecentralizedStorageManager()
data_replication = DataReplicationEngine()
storage_analytics = StorageAnalytics()

def init_distributed_storage():
    """Initialize distributed storage system"""
    logger.info("Initializing distributed storage system")

    # Add storage nodes
    decentralized_storage.add_storage_node('node_1', 'distributed_fs', {
        'capacity_gb': 1000,
        'location': 'us-east-1',
        'type': 'ssd'
    })

    decentralized_storage.add_storage_node('node_2', 'distributed_fs', {
        'capacity_gb': 800,
        'location': 'eu-west-1',
        'type': 'hdd'
    })

    decentralized_storage.add_storage_node('node_3', 'distributed_fs', {
        'capacity_gb': 1200,
        'location': 'ap-northeast-1',
        'type': 'ssd'
    })

    # Add IPFS nodes
    ipfs_node_1 = IPFSNode('ipfs_1', '/ip4/127.0.0.1/tcp/5001', {'storage_gb': 500})
    ipfs_node_1.connect_to_network()
    decentralized_storage.ipfs_integration.add_ipfs_node(ipfs_node_1)

    # Define storage policies
    decentralized_storage.define_storage_policy('high_availability', {
        'replication_factor': 5,
        'encryption_required': True,
        'compression_enabled': True
    })

    decentralized_storage.define_storage_policy('cost_optimized', {
        'replication_factor': 2,
        'encryption_required': False,
        'compression_enabled': True
    })

    # Define replication strategies
    data_replication.define_replication_policy('geo_redundant', {
        'factor': 3,
        'synchronous': False,
        'geo_distribution': 'global',
        'failure_tolerance': 2
    })

    # Define consistency models
    data_replication.define_consistency_model('strong_consistency', {
        'level': 'strong',
        'propagation_delay': 50,
        'conflict_resolution': 'vector_clocks'
    })

    logger.info("Distributed storage system initialized")

def store_distributed_data(data: bytes, metadata: Dict[str, Any],
                          policy: str = 'default') -> Dict[str, Any]:
    """Store data in distributed storage"""
    return decentralized_storage.store_data_securely(data, metadata, policy)

def retrieve_distributed_data(file_hash: str, decryption_key: str = None) -> Optional[bytes]:
    """Retrieve data from distributed storage"""
    return decentralized_storage.retrieve_data_securely(file_hash, decryption_key)

def get_distributed_storage_status() -> Dict[str, Any]:
    """Get distributed storage status"""
    return decentralized_storage.get_distributed_storage_status()

def replicate_data_across_nodes(data_id: str, data: bytes, policy: str = 'default') -> bool:
    """Replicate data across distributed nodes"""
    return data_replication.replicate_data(data_id, data, policy)
