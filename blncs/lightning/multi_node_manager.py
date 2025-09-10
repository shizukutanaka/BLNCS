"""
Multi-Node Lightning Network Management System
Advanced management for multiple Lightning Network nodes with intelligent routing and load balancing.
"""

import asyncio
import time
import json
from typing import Dict, List, Any, Optional, Set, Union, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timedelta
import uuid
from concurrent.futures import as_completed
import statistics

from .async_client import AsyncLightningClient
from ..core.structured_logging import get_structured_logger, LogCategory
from ..core.error_handler import get_error_handler, ErrorContext
from ..core.async_database import get_async_db_manager
from ..core.telemetry import trace_function, TracingMixin
from ..core.exceptions import LightningError, ConnectionError


class NodeStatus(Enum):
    """Lightning node status"""
    ONLINE = "online"
    OFFLINE = "offline"
    SYNCING = "syncing"
    ERROR = "error"
    MAINTENANCE = "maintenance"


class NodeRole(Enum):
    """Node roles in multi-node setup"""
    PRIMARY = "primary"         # Main routing node
    SECONDARY = "secondary"     # Backup/failover node
    LIQUIDITY = "liquidity"     # Specialized for liquidity provision
    ROUTING = "routing"         # Dedicated routing node
    WATCHTOWER = "watchtower"   # Channel monitoring
    BACKUP = "backup"           # Offline backup node


@dataclass
class NodeConfiguration:
    """Configuration for a Lightning node"""
    node_id: str
    name: str
    host: str
    port: int
    network: str = "testnet"
    role: NodeRole = NodeRole.SECONDARY
    
    # Authentication
    macaroon_path: Optional[str] = None
    cert_path: Optional[str] = None
    tls_cert_path: Optional[str] = None
    
    # Connection settings
    max_connections: int = 100
    timeout: float = 30.0
    retry_attempts: int = 3
    
    # Performance settings
    channel_capacity_sats: int = 1000000  # 1M sats default
    fee_rate_base: int = 1000  # 1 sat base fee
    fee_rate_ppm: int = 1000   # 1000 ppm (0.1%)
    
    # Monitoring
    health_check_interval: int = 60
    metrics_collection: bool = True
    
    # Metadata
    tags: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['role'] = self.role.value
        data['tags'] = list(self.tags)
        data['created_at'] = self.created_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'NodeConfiguration':
        """Create from dictionary"""
        data = data.copy()
        data['role'] = NodeRole(data['role'])
        data['tags'] = set(data.get('tags', []))
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        return cls(**data)


@dataclass
class NodeMetrics:
    """Real-time metrics for a Lightning node"""
    node_id: str
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Connection metrics
    status: NodeStatus = NodeStatus.OFFLINE
    uptime_seconds: float = 0.0
    last_seen: Optional[datetime] = None
    
    # Network metrics
    num_channels: int = 0
    num_active_channels: int = 0
    num_peers: int = 0
    total_capacity_sats: int = 0
    local_balance_sats: int = 0
    remote_balance_sats: int = 0
    
    # Transaction metrics
    total_transactions: int = 0
    successful_payments: int = 0
    failed_payments: int = 0
    total_fees_earned: int = 0
    
    # Performance metrics
    avg_response_time_ms: float = 0.0
    error_rate: float = 0.0
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    
    # Lightning-specific metrics
    routing_score: float = 0.0
    liquidity_score: float = 0.0
    availability_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['status'] = self.status.value
        data['timestamp'] = self.timestamp.isoformat()
        data['last_seen'] = self.last_seen.isoformat() if self.last_seen else None
        return data


@dataclass
class RouteCandidate:
    """Candidate route for payment routing"""
    nodes: List[str]
    total_fee: int
    total_delay: int
    success_probability: float
    route_score: float
    
    def __lt__(self, other):
        return self.route_score > other.route_score  # Higher score is better


class MultiNodeManager(TracingMixin):
    """Advanced multi-node Lightning Network management"""
    
    def __init__(self):
        super().__init__()
        self.logger = get_structured_logger(__name__)
        self.error_handler = get_error_handler()
        
        # Node management
        self.nodes: Dict[str, NodeConfiguration] = {}
        self.clients: Dict[str, AsyncLightningClient] = {}
        self.node_metrics: Dict[str, NodeMetrics] = {}
        
        # Load balancing
        self.primary_nodes: Set[str] = set()
        self.routing_nodes: Set[str] = set()
        self.liquidity_nodes: Set[str] = set()
        
        # Monitoring
        self.monitoring_tasks: Dict[str, asyncio.Task] = {}
        self.health_check_interval = 60
        
        # Database
        self.db_manager = None
        
        # Performance tracking
        self.request_distribution: Dict[str, int] = {}
        self.node_performance: Dict[str, List[float]] = {}
        
        # Event handlers
        self.event_handlers: Dict[str, List[Callable]] = {
            'node_online': [],
            'node_offline': [],
            'payment_success': [],
            'payment_failure': [],
            'channel_opened': [],
            'channel_closed': []
        }
    
    async def initialize(self):
        """Initialize multi-node manager"""
        try:
            self.db_manager = await get_async_db_manager()
            await self._create_tables()
            await self._load_saved_nodes()
            
            self.logger.info(
                "Multi-node manager initialized",
                category=LogCategory.LIGHTNING,
                data={"nodes_count": len(self.nodes)}
            )
            
        except Exception as e:
            self.error_handler.handle_error(
                e,
                ErrorContext(
                    component="multi_node_manager",
                    operation="initialize",
                    severity="critical"
                )
            )
            raise
    
    async def _create_tables(self):
        """Create database tables for multi-node management"""
        tables = [
            """
            CREATE TABLE IF NOT EXISTS lightning_nodes (
                node_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                network TEXT NOT NULL,
                role TEXT NOT NULL,
                macaroon_path TEXT,
                cert_path TEXT,
                tls_cert_path TEXT,
                config_json TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS node_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT NOT NULL,
                metrics_json TEXT NOT NULL,
                FOREIGN KEY (node_id) REFERENCES lightning_nodes (node_id) ON DELETE CASCADE
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS multi_node_routes (
                route_id TEXT PRIMARY KEY,
                source_node_id TEXT NOT NULL,
                destination_node_id TEXT NOT NULL,
                route_nodes TEXT NOT NULL,
                total_fee INTEGER NOT NULL,
                success_probability REAL NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_used DATETIME,
                success_count INTEGER DEFAULT 0,
                failure_count INTEGER DEFAULT 0
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS node_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_data TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (node_id) REFERENCES lightning_nodes (node_id) ON DELETE CASCADE
            )
            """,
            
            # Indexes
            "CREATE INDEX IF NOT EXISTS idx_node_metrics_node_id ON node_metrics(node_id)",
            "CREATE INDEX IF NOT EXISTS idx_node_metrics_timestamp ON node_metrics(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_routes_source ON multi_node_routes(source_node_id)",
            "CREATE INDEX IF NOT EXISTS idx_routes_destination ON multi_node_routes(destination_node_id)",
            "CREATE INDEX IF NOT EXISTS idx_events_node_id ON node_events(node_id)",
            "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON node_events(timestamp)"
        ]
        
        for table_sql in tables:
            await self.db_manager.execute(table_sql, fetch_results=False)
    
    async def _load_saved_nodes(self):
        """Load previously saved nodes from database"""
        try:
            rows = await self.db_manager.fetch_all("SELECT * FROM lightning_nodes")
            
            for row in rows:
                config_data = json.loads(row['config_json'])
                config = NodeConfiguration.from_dict(config_data)
                self.nodes[config.node_id] = config
                
                # Categorize nodes by role
                if config.role == NodeRole.PRIMARY:
                    self.primary_nodes.add(config.node_id)
                elif config.role == NodeRole.ROUTING:
                    self.routing_nodes.add(config.node_id)
                elif config.role == NodeRole.LIQUIDITY:
                    self.liquidity_nodes.add(config.node_id)
            
            self.logger.info(f"Loaded {len(self.nodes)} saved nodes")
            
        except Exception as e:
            self.logger.warning(f"Failed to load saved nodes: {e}")
    
    @trace_function("add_node")
    async def add_node(self, config: NodeConfiguration) -> bool:
        """Add a new Lightning node to management"""
        try:
            async with self.async_trace_operation(
                "add_lightning_node",
                attributes={
                    "node_id": config.node_id,
                    "role": config.role.value,
                    "host": config.host
                }
            ):
                # Validate node configuration
                await self._validate_node_config(config)
                
                # Test connection
                client = await self._create_client(config)
                connection_success = await self._test_connection(client)
                
                if not connection_success:
                    raise LightningError(f"Failed to connect to node {config.node_id}")
                
                # Store configuration
                self.nodes[config.node_id] = config
                self.clients[config.node_id] = client
                
                # Initialize metrics
                self.node_metrics[config.node_id] = NodeMetrics(node_id=config.node_id)
                self.node_performance[config.node_id] = []
                
                # Categorize node by role
                if config.role == NodeRole.PRIMARY:
                    self.primary_nodes.add(config.node_id)
                elif config.role == NodeRole.ROUTING:
                    self.routing_nodes.add(config.node_id)
                elif config.role == NodeRole.LIQUIDITY:
                    self.liquidity_nodes.add(config.node_id)
                
                # Save to database
                await self.db_manager.insert('lightning_nodes', {
                    'node_id': config.node_id,
                    'name': config.name,
                    'host': config.host,
                    'port': config.port,
                    'network': config.network,
                    'role': config.role.value,
                    'macaroon_path': config.macaroon_path,
                    'cert_path': config.cert_path,
                    'tls_cert_path': config.tls_cert_path,
                    'config_json': json.dumps(config.to_dict())
                })
                
                # Start monitoring
                await self._start_node_monitoring(config.node_id)
                
                # Trigger event
                await self._trigger_event('node_added', config.node_id, config.to_dict())
                
                self.logger.info(
                    "Lightning node added successfully",
                    category=LogCategory.LIGHTNING,
                    data={
                        "node_id": config.node_id,
                        "name": config.name,
                        "role": config.role.value
                    }
                )
                
                return True
                
        except Exception as e:
            self.error_handler.handle_error(
                e,
                ErrorContext(
                    component="multi_node_manager",
                    operation="add_node",
                    metadata={"node_id": config.node_id}
                )
            )
            return False
    
    async def _validate_node_config(self, config: NodeConfiguration):
        """Validate node configuration"""
        if not config.node_id:
            raise ValidationError("Node ID is required")
        
        if config.node_id in self.nodes:
            raise ValidationError(f"Node {config.node_id} already exists")
        
        if not config.host or not config.port:
            raise ValidationError("Host and port are required")
        
        if config.network not in ['mainnet', 'testnet', 'regtest']:
            raise ValidationError("Invalid network")
    
    async def _create_client(self, config: NodeConfiguration) -> AsyncLightningClient:
        """Create Lightning client for node"""
        client_config = {
            'lightning': {
                'host': config.host,
                'port': config.port,
                'network': config.network,
                'macaroon_path': config.macaroon_path,
                'cert_path': config.cert_path,
                'timeout': config.timeout,
                'max_connections': config.max_connections
            }
        }
        
        return AsyncLightningClient(client_config)
    
    async def _test_connection(self, client: AsyncLightningClient) -> bool:
        """Test connection to Lightning node"""
        try:
            async with client:
                info = await client.get_info()
                return info is not None
        except Exception:
            return False
    
    async def _start_node_monitoring(self, node_id: str):
        """Start monitoring task for node"""
        if node_id in self.monitoring_tasks:
            return  # Already monitoring
        
        task = asyncio.create_task(self._monitor_node(node_id))
        self.monitoring_tasks[node_id] = task
    
    async def _monitor_node(self, node_id: str):
        """Monitor node health and collect metrics"""
        while node_id in self.nodes:
            try:
                await self._collect_node_metrics(node_id)
                await asyncio.sleep(self.health_check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.warning(
                    f"Error monitoring node {node_id}: {e}",
                    category=LogCategory.LIGHTNING
                )
                await asyncio.sleep(self.health_check_interval)
    
    async def _collect_node_metrics(self, node_id: str):
        """Collect metrics for a specific node"""
        if node_id not in self.clients:
            return
        
        client = self.clients[node_id]
        metrics = self.node_metrics.get(node_id, NodeMetrics(node_id=node_id))
        
        try:
            start_time = time.time()
            
            # Get node info
            async with client:
                info = await client.get_info()
                balance = await client.get_balance()
                channels = await client.list_channels()
            
            response_time = (time.time() - start_time) * 1000  # ms
            
            # Update metrics
            metrics.status = NodeStatus.ONLINE
            metrics.last_seen = datetime.now()
            metrics.avg_response_time_ms = response_time
            
            if info:
                metrics.num_peers = info.get('num_peers', 0)
                
            if channels:
                metrics.num_channels = len(channels)
                metrics.num_active_channels = len([c for c in channels if c.get('active')])
                metrics.total_capacity_sats = sum(c.get('capacity', 0) for c in channels)
                metrics.local_balance_sats = sum(c.get('local_balance', 0) for c in channels)
                metrics.remote_balance_sats = sum(c.get('remote_balance', 0) for c in channels)
            
            if balance:
                metrics.local_balance_sats += balance.get('confirmed', 0)
            
            # Calculate scores
            metrics.routing_score = self._calculate_routing_score(metrics)
            metrics.liquidity_score = self._calculate_liquidity_score(metrics)
            metrics.availability_score = self._calculate_availability_score(node_id)
            
            # Store metrics
            self.node_metrics[node_id] = metrics
            
            # Record performance
            if node_id not in self.node_performance:
                self.node_performance[node_id] = []
            self.node_performance[node_id].append(response_time)
            
            # Keep only recent performance data
            if len(self.node_performance[node_id]) > 100:
                self.node_performance[node_id] = self.node_performance[node_id][-50:]
            
            # Save to database
            await self.db_manager.insert('node_metrics', {
                'node_id': node_id,
                'status': metrics.status.value,
                'metrics_json': json.dumps(metrics.to_dict())
            })
            
            # Trigger online event if status changed
            if metrics.status == NodeStatus.ONLINE:
                await self._trigger_event('node_online', node_id, metrics.to_dict())
            
        except Exception as e:
            # Mark as offline
            metrics.status = NodeStatus.OFFLINE
            metrics.error_rate = min(metrics.error_rate + 0.1, 1.0)
            self.node_metrics[node_id] = metrics
            
            await self._trigger_event('node_offline', node_id, {'error': str(e)})
            
            self.logger.warning(
                f"Failed to collect metrics for node {node_id}: {e}",
                category=LogCategory.LIGHTNING
            )
    
    def _calculate_routing_score(self, metrics: NodeMetrics) -> float:
        """Calculate routing score for node"""
        if metrics.num_channels == 0:
            return 0.0
        
        # Factors: channel count, capacity, connectivity
        channel_score = min(metrics.num_channels / 50.0, 1.0)  # Normalized to 50 channels
        capacity_score = min(metrics.total_capacity_sats / 100_000_000, 1.0)  # 1 BTC
        connectivity_score = min(metrics.num_peers / 20.0, 1.0)  # Normalized to 20 peers
        
        # Weighted average
        return (channel_score * 0.4 + capacity_score * 0.4 + connectivity_score * 0.2)
    
    def _calculate_liquidity_score(self, metrics: NodeMetrics) -> float:
        """Calculate liquidity provision score"""
        if metrics.total_capacity_sats == 0:
            return 0.0
        
        # Balance ratio - closer to 50/50 is better for routing
        local_ratio = metrics.local_balance_sats / metrics.total_capacity_sats
        balance_score = 1.0 - abs(local_ratio - 0.5) * 2  # Best at 50/50 split
        
        # Total liquidity
        liquidity_score = min(metrics.total_capacity_sats / 50_000_000, 1.0)  # 0.5 BTC
        
        return (balance_score * 0.6 + liquidity_score * 0.4)
    
    def _calculate_availability_score(self, node_id: str) -> float:
        """Calculate availability score based on uptime"""
        if node_id not in self.node_performance:
            return 0.0
        
        # Based on recent response times
        recent_times = self.node_performance[node_id][-10:]  # Last 10 measurements
        
        if not recent_times:
            return 0.0
        
        avg_time = statistics.mean(recent_times)
        
        # Score based on response time (lower is better)
        if avg_time < 100:  # <100ms
            return 1.0
        elif avg_time < 500:  # <500ms
            return 0.8
        elif avg_time < 1000:  # <1s
            return 0.6
        elif avg_time < 2000:  # <2s
            return 0.4
        else:
            return 0.2
    
    async def remove_node(self, node_id: str) -> bool:
        """Remove node from management"""
        try:
            if node_id not in self.nodes:
                return False
            
            # Stop monitoring
            if node_id in self.monitoring_tasks:
                self.monitoring_tasks[node_id].cancel()
                del self.monitoring_tasks[node_id]
            
            # Clean up
            if node_id in self.clients:
                await self.clients[node_id].close()
                del self.clients[node_id]
            
            if node_id in self.node_metrics:
                del self.node_metrics[node_id]
            
            if node_id in self.node_performance:
                del self.node_performance[node_id]
            
            # Remove from role sets
            self.primary_nodes.discard(node_id)
            self.routing_nodes.discard(node_id)
            self.liquidity_nodes.discard(node_id)
            
            # Remove configuration
            del self.nodes[node_id]
            
            # Remove from database
            await self.db_manager.delete('lightning_nodes', 'node_id = ?', (node_id,))
            
            # Trigger event
            await self._trigger_event('node_removed', node_id, {})
            
            self.logger.info(
                f"Node {node_id} removed successfully",
                category=LogCategory.LIGHTNING
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to remove node {node_id}: {e}")
            return False
    
    async def get_best_node_for_operation(
        self,
        operation: str,
        requirements: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """Get the best node for a specific operation"""
        
        requirements = requirements or {}
        online_nodes = [
            node_id for node_id, metrics in self.node_metrics.items()
            if metrics.status == NodeStatus.ONLINE
        ]
        
        if not online_nodes:
            return None
        
        if operation == "payment":
            # Prefer primary nodes, then routing nodes
            candidates = (list(self.primary_nodes) + list(self.routing_nodes))
            candidates = [n for n in candidates if n in online_nodes]
            
        elif operation == "routing":
            # Prefer routing nodes with high routing scores
            candidates = list(self.routing_nodes)
            candidates = [n for n in candidates if n in online_nodes]
            candidates.sort(key=lambda n: self.node_metrics[n].routing_score, reverse=True)
            
        elif operation == "liquidity":
            # Prefer liquidity nodes
            candidates = list(self.liquidity_nodes)
            candidates = [n for n in candidates if n in online_nodes]
            candidates.sort(key=lambda n: self.node_metrics[n].liquidity_score, reverse=True)
            
        else:
            candidates = online_nodes
        
        if not candidates:
            candidates = online_nodes
        
        # Apply load balancing
        return self._select_with_load_balancing(candidates)
    
    def _select_with_load_balancing(self, candidates: List[str]) -> str:
        """Select node with load balancing"""
        if not candidates:
            return None
        
        if len(candidates) == 1:
            return candidates[0]
        
        # Round-robin with performance weighting
        min_requests = min(self.request_distribution.get(n, 0) for n in candidates)
        least_used = [n for n in candidates if self.request_distribution.get(n, 0) == min_requests]
        
        if len(least_used) == 1:
            selected = least_used[0]
        else:
            # Among least used, select best performing
            selected = max(least_used, key=lambda n: self.node_metrics[n].availability_score)
        
        # Update request count
        self.request_distribution[selected] = self.request_distribution.get(selected, 0) + 1
        
        return selected
    
    async def execute_on_node(
        self,
        node_id: str,
        operation: str,
        *args,
        **kwargs
    ) -> Any:
        """Execute operation on specific node"""
        
        if node_id not in self.clients:
            raise LightningError(f"Node {node_id} not available")
        
        client = self.clients[node_id]
        
        try:
            async with client:
                if hasattr(client, operation):
                    method = getattr(client, operation)
                    result = await method(*args, **kwargs)
                    
                    # Update success metrics
                    metrics = self.node_metrics.get(node_id)
                    if metrics:
                        metrics.successful_payments += 1
                    
                    return result
                else:
                    raise LightningError(f"Operation {operation} not supported")
                    
        except Exception as e:
            # Update failure metrics
            metrics = self.node_metrics.get(node_id)
            if metrics:
                metrics.failed_payments += 1
                metrics.error_rate = min(metrics.error_rate + 0.01, 1.0)
            
            raise
    
    async def send_payment_multi_node(
        self,
        payment_request: str,
        preferred_nodes: Optional[List[str]] = None,
        max_attempts: int = 3
    ) -> Dict[str, Any]:
        """Send payment with multi-node failover"""
        
        # Determine candidate nodes
        if preferred_nodes:
            candidates = [n for n in preferred_nodes if n in self.nodes]
        else:
            candidates = await self._get_payment_candidates()
        
        if not candidates:
            raise LightningError("No suitable nodes available for payment")
        
        last_error = None
        
        for attempt in range(max_attempts):
            for node_id in candidates:
                try:
                    result = await self.execute_on_node(
                        node_id, 'send_payment', payment_request
                    )
                    
                    # Log successful payment
                    await self._trigger_event(
                        'payment_success',
                        node_id,
                        {'payment_request': payment_request, 'result': result}
                    )
                    
                    return {
                        'success': True,
                        'node_id': node_id,
                        'attempt': attempt + 1,
                        'result': result
                    }
                    
                except Exception as e:
                    last_error = e
                    self.logger.warning(
                        f"Payment failed on node {node_id}: {e}",
                        category=LogCategory.LIGHTNING
                    )
                    continue
            
            # Wait before retry
            if attempt < max_attempts - 1:
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
        
        # All attempts failed
        await self._trigger_event(
            'payment_failure',
            None,
            {'payment_request': payment_request, 'error': str(last_error)}
        )
        
        raise LightningError(f"Payment failed on all nodes: {last_error}")
    
    async def _get_payment_candidates(self) -> List[str]:
        """Get candidate nodes for payments"""
        online_nodes = [
            node_id for node_id, metrics in self.node_metrics.items()
            if metrics.status == NodeStatus.ONLINE
        ]
        
        # Sort by routing score and liquidity
        online_nodes.sort(
            key=lambda n: (
                self.node_metrics[n].routing_score +
                self.node_metrics[n].liquidity_score
            ),
            reverse=True
        )
        
        return online_nodes
    
    async def _trigger_event(self, event_type: str, node_id: Optional[str], data: Dict[str, Any]):
        """Trigger event handlers"""
        # Store event in database
        if node_id:
            await self.db_manager.insert('node_events', {
                'node_id': node_id,
                'event_type': event_type,
                'event_data': json.dumps(data)
            })
        
        # Call registered handlers
        handlers = self.event_handlers.get(event_type, [])
        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(node_id, data)
                else:
                    handler(node_id, data)
            except Exception as e:
                self.logger.warning(f"Event handler failed: {e}")
    
    def add_event_handler(self, event_type: str, handler: Callable):
        """Add event handler"""
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        self.event_handlers[event_type].append(handler)
    
    def get_node_summary(self) -> Dict[str, Any]:
        """Get summary of all managed nodes"""
        online_count = sum(1 for m in self.node_metrics.values() if m.status == NodeStatus.ONLINE)
        total_capacity = sum(m.total_capacity_sats for m in self.node_metrics.values())
        
        return {
            'total_nodes': len(self.nodes),
            'online_nodes': online_count,
            'offline_nodes': len(self.nodes) - online_count,
            'primary_nodes': len(self.primary_nodes),
            'routing_nodes': len(self.routing_nodes),
            'liquidity_nodes': len(self.liquidity_nodes),
            'total_capacity_sats': total_capacity,
            'average_response_time': statistics.mean([
                sum(times) / len(times) for times in self.node_performance.values()
                if times
            ]) if self.node_performance else 0
        }
    
    async def cleanup(self):
        """Cleanup resources"""
        # Cancel all monitoring tasks
        for task in self.monitoring_tasks.values():
            task.cancel()
        
        # Close all clients
        for client in self.clients.values():
            try:
                await client.close()
            except Exception:
                pass
        
        self.monitoring_tasks.clear()
        self.clients.clear()


# Global multi-node manager
_global_multi_node_manager: Optional[MultiNodeManager] = None


async def get_multi_node_manager() -> MultiNodeManager:
    """Get global multi-node manager"""
    global _global_multi_node_manager
    if _global_multi_node_manager is None:
        _global_multi_node_manager = MultiNodeManager()
        await _global_multi_node_manager.initialize()
    return _global_multi_node_manager


__all__ = [
    'NodeStatus',
    'NodeRole',
    'NodeConfiguration',
    'NodeMetrics',
    'RouteCandidate',
    'MultiNodeManager',
    'get_multi_node_manager'
]