"""
Edge Computing and CDN Integration Manager
Global content distribution, edge processing, and geo-distributed Lightning Network optimization.
"""

import asyncio
import json
import logging
import time
import uuid
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple, Callable
from enum import Enum
from dataclasses import dataclass, field, asdict
from collections import defaultdict
import aiohttp
import geoip2.database
import geoip2.errors
import structlog

logger = structlog.get_logger(__name__)

class EdgeRegion(Enum):
    US_EAST = "us-east-1"
    US_WEST = "us-west-1"
    EU_CENTRAL = "eu-central-1"
    EU_WEST = "eu-west-1"
    ASIA_PACIFIC = "ap-southeast-1"
    ASIA_NORTHEAST = "ap-northeast-1"
    SOUTH_AMERICA = "sa-east-1"
    AFRICA = "af-south-1"
    OCEANIA = "ap-southeast-2"

class ContentType(Enum):
    STATIC_WEB = "static_web"
    API_RESPONSE = "api_response"
    LIGHTNING_GRAPH = "lightning_graph"
    CHANNEL_DATA = "channel_data"
    INVOICE_QR = "invoice_qr"
    USER_CONTENT = "user_content"
    ANALYTICS_DATA = "analytics_data"

class EdgeProcessingType(Enum):
    LIGHTNING_ROUTING = "lightning_routing"
    PAYMENT_VALIDATION = "payment_validation"
    CHANNEL_OPTIMIZATION = "channel_optimization"
    FRAUD_DETECTION = "fraud_detection"
    ANALYTICS_AGGREGATION = "analytics_aggregation"
    CONTENT_OPTIMIZATION = "content_optimization"

@dataclass
class EdgeConfig:
    enable_cdn: bool = True
    enable_edge_processing: bool = True
    regions: List[EdgeRegion] = field(default_factory=lambda: list(EdgeRegion))
    geoip_database_path: str = "/usr/share/GeoIP/GeoLite2-City.mmdb"
    cdn_provider: str = "cloudflare"  # cloudflare, aws_cloudfront, azure_cdn
    cache_ttl_seconds: int = 3600
    edge_timeout_ms: int = 5000
    max_edge_requests_per_second: int = 1000
    enable_edge_analytics: bool = True
    enable_failover: bool = True
    health_check_interval: int = 30
    content_compression: bool = True
    image_optimization: bool = True
    minification: bool = True

@dataclass
class EdgeNode:
    node_id: str
    region: EdgeRegion
    endpoint_url: str
    latitude: float
    longitude: float
    capacity_rps: int = 1000
    current_load: int = 0
    healthy: bool = True
    last_health_check: datetime = field(default_factory=datetime.utcnow)
    supported_processing: List[EdgeProcessingType] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ContentItem:
    content_id: str
    content_type: ContentType
    data: bytes
    headers: Dict[str, str] = field(default_factory=dict)
    ttl_seconds: int = 3600
    regions: List[EdgeRegion] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)

class GeoRouter:
    def __init__(self, geoip_db_path: str):
        self.geoip_db_path = geoip_db_path
        self.geoip_reader = None
        self.region_mappings = {
            'US': EdgeRegion.US_EAST,
            'CA': EdgeRegion.US_EAST,
            'GB': EdgeRegion.EU_WEST,
            'DE': EdgeRegion.EU_CENTRAL,
            'FR': EdgeRegion.EU_WEST,
            'JP': EdgeRegion.ASIA_NORTHEAST,
            'SG': EdgeRegion.ASIA_PACIFIC,
            'AU': EdgeRegion.OCEANIA,
            'BR': EdgeRegion.SOUTH_AMERICA,
            'ZA': EdgeRegion.AFRICA
        }
    
    async def initialize(self):
        """Initialize GeoIP database"""
        try:
            self.geoip_reader = geoip2.database.Reader(self.geoip_db_path)
            logger.info("GeoIP database initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize GeoIP database: {e}")
    
    def get_optimal_region(self, client_ip: str) -> EdgeRegion:
        """Get optimal edge region for client IP"""
        if not self.geoip_reader:
            return EdgeRegion.US_EAST  # Default fallback
        
        try:
            response = self.geoip_reader.city(client_ip)
            country_code = response.country.iso_code
            
            # Map country to region
            region = self.region_mappings.get(country_code, EdgeRegion.US_EAST)
            
            logger.debug(f"Client IP {client_ip} mapped to region {region.value}")
            return region
            
        except geoip2.errors.AddressNotFoundError:
            logger.warning(f"IP {client_ip} not found in GeoIP database")
            return EdgeRegion.US_EAST
        except Exception as e:
            logger.error(f"GeoIP lookup error: {e}")
            return EdgeRegion.US_EAST
    
    def calculate_latency_score(self, client_lat: float, client_lon: float, 
                               edge_lat: float, edge_lon: float) -> float:
        """Calculate estimated latency score based on geographic distance"""
        import math
        
        # Haversine formula for distance calculation
        lat1, lon1, lat2, lon2 = map(math.radians, [client_lat, client_lon, edge_lat, edge_lon])
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        
        a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
        c = 2 * math.asin(math.sqrt(a))
        distance_km = 6371 * c
        
        # Rough estimation: 1ms per 100km + base latency
        estimated_latency = (distance_km / 100) + 10
        return estimated_latency

class EdgeProcessor:
    def __init__(self, edge_node: EdgeNode):
        self.edge_node = edge_node
        self.processing_queue = asyncio.Queue()
        self.worker_tasks = []
        self.running = False
    
    async def start_processing(self, worker_count: int = 4):
        """Start edge processing workers"""
        self.running = True
        
        for i in range(worker_count):
            task = asyncio.create_task(self._processing_worker(f"worker-{i}"))
            self.worker_tasks.append(task)
        
        logger.info(f"Started {worker_count} processing workers on edge node {self.edge_node.node_id}")
    
    async def _processing_worker(self, worker_id: str):
        """Process tasks from queue"""
        while self.running:
            try:
                # Get task from queue with timeout
                task = await asyncio.wait_for(self.processing_queue.get(), timeout=1.0)
                
                # Process task
                await self._process_task(task)
                
                # Mark task as done
                self.processing_queue.task_done()
                
            except asyncio.TimeoutError:
                continue  # No tasks, continue loop
            except Exception as e:
                logger.error(f"Processing worker {worker_id} error: {e}")
                await asyncio.sleep(1)
    
    async def _process_task(self, task: Dict[str, Any]):
        """Process individual task"""
        processing_type = EdgeProcessingType(task.get('type'))
        task_data = task.get('data', {})
        
        start_time = time.time()
        
        try:
            if processing_type == EdgeProcessingType.LIGHTNING_ROUTING:
                result = await self._process_lightning_routing(task_data)
            elif processing_type == EdgeProcessingType.PAYMENT_VALIDATION:
                result = await self._process_payment_validation(task_data)
            elif processing_type == EdgeProcessingType.CHANNEL_OPTIMIZATION:
                result = await self._process_channel_optimization(task_data)
            elif processing_type == EdgeProcessingType.FRAUD_DETECTION:
                result = await self._process_fraud_detection(task_data)
            elif processing_type == EdgeProcessingType.ANALYTICS_AGGREGATION:
                result = await self._process_analytics_aggregation(task_data)
            else:
                result = {"error": f"Unsupported processing type: {processing_type}"}
            
            # Update metrics
            processing_time = (time.time() - start_time) * 1000  # ms
            self._update_processing_metrics(processing_type, processing_time, True)
            
            # Store result if callback provided
            if 'callback' in task:
                await task['callback'](result)
                
        except Exception as e:
            logger.error(f"Task processing error: {e}")
            self._update_processing_metrics(processing_type, 0, False)
    
    async def _process_lightning_routing(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process Lightning Network routing optimization"""
        # Simplified routing optimization
        source = data.get('source')
        destination = data.get('destination')
        amount_sats = data.get('amount_sats')
        
        # This would integrate with Lightning Network graph analysis
        # For now, return mock optimized route
        route = {
            'path': [source, 'intermediate_node', destination],
            'total_fees': amount_sats * 0.001,  # 0.1% fee
            'estimated_time': 2000,  # 2 seconds
            'success_probability': 0.95
        }
        
        return {'optimized_route': route}
    
    async def _process_payment_validation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process payment validation"""
        payment_hash = data.get('payment_hash')
        amount = data.get('amount')
        
        # Mock validation logic
        is_valid = len(payment_hash) == 64 and amount > 0
        
        return {
            'is_valid': is_valid,
            'validation_time': time.time(),
            'risk_score': 0.1 if is_valid else 0.9
        }
    
    async def _process_channel_optimization(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process channel optimization recommendations"""
        node_id = data.get('node_id')
        channels = data.get('channels', [])
        
        # Mock channel optimization
        recommendations = []
        
        for channel in channels:
            if channel.get('local_balance', 0) < channel.get('capacity', 0) * 0.1:
                recommendations.append({
                    'channel_id': channel.get('channel_id'),
                    'action': 'rebalance_inbound',
                    'priority': 'high'
                })
        
        return {'recommendations': recommendations}
    
    async def _process_fraud_detection(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process fraud detection"""
        transaction = data.get('transaction', {})
        user_history = data.get('user_history', [])
        
        # Simple fraud detection logic
        amount = transaction.get('amount', 0)
        avg_amount = sum(t.get('amount', 0) for t in user_history) / max(len(user_history), 1)
        
        fraud_score = min(amount / (avg_amount * 10), 1.0) if avg_amount > 0 else 0.0
        
        return {
            'fraud_score': fraud_score,
            'is_suspicious': fraud_score > 0.7,
            'factors': ['unusual_amount'] if fraud_score > 0.7 else []
        }
    
    async def _process_analytics_aggregation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process analytics aggregation"""
        events = data.get('events', [])
        time_window = data.get('time_window', 3600)  # 1 hour
        
        # Aggregate events by type
        aggregated = defaultdict(int)
        for event in events:
            event_type = event.get('type', 'unknown')
            aggregated[event_type] += 1
        
        return {
            'aggregated_events': dict(aggregated),
            'total_events': len(events),
            'time_window': time_window
        }
    
    def _update_processing_metrics(self, processing_type: EdgeProcessingType, 
                                  processing_time: float, success: bool):
        """Update processing metrics"""
        if 'processing' not in self.edge_node.metrics:
            self.edge_node.metrics['processing'] = defaultdict(lambda: {
                'count': 0, 'success_count': 0, 'avg_time': 0.0
            })
        
        metrics = self.edge_node.metrics['processing'][processing_type.value]
        metrics['count'] += 1
        
        if success:
            metrics['success_count'] += 1
            # Update average processing time
            old_avg = metrics['avg_time']
            metrics['avg_time'] = (old_avg * (metrics['success_count'] - 1) + processing_time) / metrics['success_count']
    
    async def submit_task(self, processing_type: EdgeProcessingType, 
                         data: Dict[str, Any], callback: Callable = None) -> bool:
        """Submit processing task"""
        if processing_type not in self.edge_node.supported_processing:
            return False
        
        task = {
            'id': str(uuid.uuid4()),
            'type': processing_type.value,
            'data': data,
            'callback': callback,
            'submitted_at': time.time()
        }
        
        try:
            self.processing_queue.put_nowait(task)
            return True
        except asyncio.QueueFull:
            logger.warning(f"Processing queue full on edge node {self.edge_node.node_id}")
            return False
    
    async def stop_processing(self):
        """Stop edge processing"""
        self.running = False
        
        # Cancel all worker tasks
        for task in self.worker_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*self.worker_tasks, return_exceptions=True)
        
        self.worker_tasks.clear()

class EdgeCache:
    def __init__(self, edge_node: EdgeNode, max_size_mb: int = 1024):
        self.edge_node = edge_node
        self.max_size_mb = max_size_mb
        self.cache = {}
        self.cache_lock = threading.RLock()
        self.current_size = 0
    
    def get(self, key: str) -> Optional[ContentItem]:
        """Get content from edge cache"""
        with self.cache_lock:
            if key not in self.cache:
                return None
            
            item = self.cache[key]
            
            # Check TTL
            if datetime.utcnow() > item['expires_at']:
                del self.cache[key]
                self.current_size -= item['size']
                return None
            
            # Update access time
            item['last_accessed'] = datetime.utcnow()
            return item['content']
    
    def set(self, key: str, content: ContentItem) -> bool:
        """Set content in edge cache"""
        with self.cache_lock:
            content_size = len(content.data)
            
            # Check if content fits in cache
            if content_size > self.max_size_mb * 1024 * 1024:
                return False
            
            # Evict items if necessary
            while (self.current_size + content_size) > (self.max_size_mb * 1024 * 1024):
                if not self._evict_lru_item():
                    return False
            
            # Store content
            expires_at = datetime.utcnow() + timedelta(seconds=content.ttl_seconds)
            
            self.cache[key] = {
                'content': content,
                'size': content_size,
                'expires_at': expires_at,
                'last_accessed': datetime.utcnow(),
                'created_at': datetime.utcnow()
            }
            
            self.current_size += content_size
            return True
    
    def _evict_lru_item(self) -> bool:
        """Evict least recently used item"""
        if not self.cache:
            return False
        
        # Find LRU item
        lru_key = min(self.cache.keys(), 
                     key=lambda k: self.cache[k]['last_accessed'])
        
        # Remove LRU item
        item = self.cache.pop(lru_key)
        self.current_size -= item['size']
        
        return True
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.cache_lock:
            return {
                'items': len(self.cache),
                'size_mb': self.current_size / (1024 * 1024),
                'max_size_mb': self.max_size_mb,
                'utilization': self.current_size / (self.max_size_mb * 1024 * 1024)
            }

class CDNManager:
    def __init__(self, config: EdgeConfig):
        self.config = config
        self.provider = config.cdn_provider
        self.session = None
    
    async def initialize(self):
        """Initialize CDN manager"""
        self.session = aiohttp.ClientSession()
        logger.info(f"CDN manager initialized with provider: {self.provider}")
    
    async def upload_content(self, content: ContentItem, regions: List[EdgeRegion] = None) -> bool:
        """Upload content to CDN"""
        try:
            target_regions = regions or self.config.regions
            
            if self.provider == "cloudflare":
                return await self._upload_to_cloudflare(content, target_regions)
            elif self.provider == "aws_cloudfront":
                return await self._upload_to_cloudfront(content, target_regions)
            else:
                logger.warning(f"Unsupported CDN provider: {self.provider}")
                return False
                
        except Exception as e:
            logger.error(f"CDN upload error: {e}")
            return False
    
    async def _upload_to_cloudflare(self, content: ContentItem, regions: List[EdgeRegion]) -> bool:
        """Upload content to Cloudflare"""
        # Mock Cloudflare API integration
        # In production, this would use Cloudflare's API
        logger.info(f"Mock upload to Cloudflare: {content.content_id}")
        
        # Simulate upload delay
        await asyncio.sleep(0.1)
        return True
    
    async def _upload_to_cloudfront(self, content: ContentItem, regions: List[EdgeRegion]) -> bool:
        """Upload content to AWS CloudFront"""
        # Mock CloudFront API integration
        logger.info(f"Mock upload to CloudFront: {content.content_id}")
        
        await asyncio.sleep(0.1)
        return True
    
    async def invalidate_content(self, content_ids: List[str]) -> bool:
        """Invalidate content across CDN"""
        try:
            if self.provider == "cloudflare":
                return await self._invalidate_cloudflare(content_ids)
            elif self.provider == "aws_cloudfront":
                return await self._invalidate_cloudfront(content_ids)
            
            return False
            
        except Exception as e:
            logger.error(f"CDN invalidation error: {e}")
            return False
    
    async def _invalidate_cloudflare(self, content_ids: List[str]) -> bool:
        """Invalidate Cloudflare cache"""
        logger.info(f"Mock Cloudflare invalidation: {content_ids}")
        await asyncio.sleep(0.05)
        return True
    
    async def _invalidate_cloudfront(self, content_ids: List[str]) -> bool:
        """Invalidate CloudFront cache"""
        logger.info(f"Mock CloudFront invalidation: {content_ids}")
        await asyncio.sleep(0.05)
        return True
    
    async def get_analytics(self, time_range_hours: int = 24) -> Dict[str, Any]:
        """Get CDN analytics"""
        # Mock analytics data
        return {
            'requests': 10000,
            'bandwidth_gb': 50.5,
            'cache_hit_rate': 0.85,
            'top_regions': [
                {'region': 'us-east-1', 'requests': 4000},
                {'region': 'eu-west-1', 'requests': 3000},
                {'region': 'ap-southeast-1', 'requests': 2000}
            ]
        }
    
    async def close(self):
        """Close CDN manager"""
        if self.session:
            await self.session.close()

class EdgeAnalytics:
    def __init__(self):
        self.metrics = defaultdict(lambda: defaultdict(int))
        self.response_times = defaultdict(list)
        self.error_counts = defaultdict(int)
    
    def record_request(self, region: EdgeRegion, content_type: ContentType, 
                      response_time_ms: float, status_code: int):
        """Record request metrics"""
        self.metrics[region.value][content_type.value] += 1
        
        if len(self.response_times[region.value]) >= 1000:
            self.response_times[region.value].pop(0)  # Remove oldest
        
        self.response_times[region.value].append(response_time_ms)
        
        if status_code >= 400:
            self.error_counts[region.value] += 1
    
    def get_analytics_summary(self) -> Dict[str, Any]:
        """Get analytics summary"""
        summary = {
            'total_requests': sum(
                sum(content_types.values()) 
                for content_types in self.metrics.values()
            ),
            'requests_by_region': {},
            'avg_response_times': {},
            'error_rates': {}
        }
        
        for region, content_types in self.metrics.items():
            total_requests = sum(content_types.values())
            summary['requests_by_region'][region] = total_requests
            
            # Average response time
            if region in self.response_times and self.response_times[region]:
                avg_time = sum(self.response_times[region]) / len(self.response_times[region])
                summary['avg_response_times'][region] = avg_time
            
            # Error rate
            if total_requests > 0:
                error_rate = self.error_counts[region] / total_requests
                summary['error_rates'][region] = error_rate
        
        return summary

class EdgeManager:
    def __init__(self, config: EdgeConfig):
        self.config = config
        self.edge_nodes = {}
        self.geo_router = GeoRouter(config.geoip_database_path)
        self.cdn_manager = CDNManager(config) if config.enable_cdn else None
        self.edge_analytics = EdgeAnalytics() if config.enable_edge_analytics else None
        self.health_check_task = None
        self.running = False
    
    async def initialize(self):
        """Initialize edge manager"""
        try:
            # Initialize geo router
            await self.geo_router.initialize()
            
            # Initialize CDN
            if self.cdn_manager:
                await self.cdn_manager.initialize()
            
            # Initialize edge nodes
            await self._initialize_edge_nodes()
            
            # Start health monitoring
            if self.config.enable_failover:
                self.health_check_task = asyncio.create_task(self._health_check_loop())
            
            self.running = True
            logger.info("Edge manager initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize edge manager: {e}")
            raise
    
    async def _initialize_edge_nodes(self):
        """Initialize edge nodes"""
        node_configs = {
            EdgeRegion.US_EAST: {"lat": 40.7128, "lon": -74.0060, "url": "https://us-east.blncs.edge"},
            EdgeRegion.US_WEST: {"lat": 37.7749, "lon": -122.4194, "url": "https://us-west.blncs.edge"},
            EdgeRegion.EU_CENTRAL: {"lat": 52.5200, "lon": 13.4050, "url": "https://eu-central.blncs.edge"},
            EdgeRegion.EU_WEST: {"lat": 51.5074, "lon": -0.1278, "url": "https://eu-west.blncs.edge"},
            EdgeRegion.ASIA_PACIFIC: {"lat": 1.3521, "lon": 103.8198, "url": "https://ap-southeast.blncs.edge"},
            EdgeRegion.ASIA_NORTHEAST: {"lat": 35.6762, "lon": 139.6503, "url": "https://ap-northeast.blncs.edge"},
        }
        
        for region in self.config.regions:
            if region in node_configs:
                config = node_configs[region]
                node = EdgeNode(
                    node_id=f"edge-{region.value}",
                    region=region,
                    endpoint_url=config["url"],
                    latitude=config["lat"],
                    longitude=config["lon"],
                    capacity_rps=self.config.max_edge_requests_per_second,
                    supported_processing=list(EdgeProcessingType)
                )
                
                # Create edge cache
                edge_cache = EdgeCache(node)
                
                # Create edge processor
                edge_processor = EdgeProcessor(node)
                if self.config.enable_edge_processing:
                    await edge_processor.start_processing()
                
                self.edge_nodes[region] = {
                    'node': node,
                    'cache': edge_cache,
                    'processor': edge_processor
                }
                
                logger.info(f"Initialized edge node: {node.node_id}")
    
    async def get_optimal_edge_node(self, client_ip: str, 
                                   processing_type: Optional[EdgeProcessingType] = None) -> Optional[EdgeNode]:
        """Get optimal edge node for client"""
        optimal_region = self.geo_router.get_optimal_region(client_ip)
        
        # Check if optimal region is available and healthy
        if optimal_region in self.edge_nodes:
            node_info = self.edge_nodes[optimal_region]
            node = node_info['node']
            
            if node.healthy and (processing_type is None or processing_type in node.supported_processing):
                return node
        
        # Find alternative healthy node
        for region, node_info in self.edge_nodes.items():
            node = node_info['node']
            if node.healthy and (processing_type is None or processing_type in node.supported_processing):
                return node
        
        return None
    
    async def process_at_edge(self, client_ip: str, processing_type: EdgeProcessingType,
                             data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process task at optimal edge node"""
        node = await self.get_optimal_edge_node(client_ip, processing_type)
        
        if not node:
            logger.warning(f"No available edge node for processing type: {processing_type}")
            return None
        
        node_info = self.edge_nodes[node.region]
        processor = node_info['processor']
        
        # Submit task and wait for result
        result_future = asyncio.Future()
        
        async def callback(result):
            result_future.set_result(result)
        
        success = await processor.submit_task(processing_type, data, callback)
        
        if success:
            try:
                result = await asyncio.wait_for(result_future, timeout=self.config.edge_timeout_ms / 1000)
                return result
            except asyncio.TimeoutError:
                logger.warning(f"Edge processing timeout for type: {processing_type}")
                return None
        else:
            logger.warning(f"Failed to submit edge processing task: {processing_type}")
            return None
    
    async def cache_content_at_edge(self, content: ContentItem, regions: List[EdgeRegion] = None):
        """Cache content at edge nodes"""
        target_regions = regions or self.config.regions
        
        for region in target_regions:
            if region in self.edge_nodes:
                node_info = self.edge_nodes[region]
                cache = node_info['cache']
                
                cache_key = f"{content.content_type.value}:{content.content_id}"
                success = cache.set(cache_key, content)
                
                if success:
                    logger.debug(f"Content cached at edge node {region.value}: {content.content_id}")
    
    async def get_cached_content(self, client_ip: str, content_type: ContentType, 
                                content_id: str) -> Optional[ContentItem]:
        """Get cached content from optimal edge node"""
        node = await self.get_optimal_edge_node(client_ip)
        
        if not node:
            return None
        
        node_info = self.edge_nodes[node.region]
        cache = node_info['cache']
        
        cache_key = f"{content_type.value}:{content_id}"
        content = cache.get(cache_key)
        
        # Record analytics
        if self.edge_analytics:
            found = content is not None
            status_code = 200 if found else 404
            response_time = 5.0  # Mock response time
            
            self.edge_analytics.record_request(
                node.region, content_type, response_time, status_code
            )
        
        return content
    
    async def _health_check_loop(self):
        """Health check loop for edge nodes"""
        while self.running:
            try:
                for region, node_info in self.edge_nodes.items():
                    node = node_info['node']
                    
                    # Perform health check
                    healthy = await self._check_node_health(node)
                    node.healthy = healthy
                    node.last_health_check = datetime.utcnow()
                    
                    if not healthy:
                        logger.warning(f"Edge node unhealthy: {node.node_id}")
                
                await asyncio.sleep(self.config.health_check_interval)
                
            except Exception as e:
                logger.error(f"Health check error: {e}")
                await asyncio.sleep(self.config.health_check_interval)
    
    async def _check_node_health(self, node: EdgeNode) -> bool:
        """Check health of edge node"""
        try:
            # Mock health check - in production, this would ping the actual endpoint
            return True
            
        except Exception as e:
            logger.error(f"Health check failed for node {node.node_id}: {e}")
            return False
    
    async def get_edge_stats(self) -> Dict[str, Any]:
        """Get edge computing statistics"""
        stats = {
            'total_nodes': len(self.edge_nodes),
            'healthy_nodes': sum(1 for _, info in self.edge_nodes.items() if info['node'].healthy),
            'nodes': {},
            'analytics': None
        }
        
        # Get node-specific stats
        for region, node_info in self.edge_nodes.items():
            node = node_info['node']
            cache = node_info['cache']
            
            stats['nodes'][region.value] = {
                'healthy': node.healthy,
                'current_load': node.current_load,
                'capacity_rps': node.capacity_rps,
                'cache_stats': cache.get_stats(),
                'metrics': node.metrics
            }
        
        # Get analytics summary
        if self.edge_analytics:
            stats['analytics'] = self.edge_analytics.get_analytics_summary()
        
        return stats
    
    async def shutdown(self):
        """Shutdown edge manager"""
        self.running = False
        
        # Stop health check
        if self.health_check_task:
            self.health_check_task.cancel()
        
        # Stop edge processors
        for node_info in self.edge_nodes.values():
            processor = node_info['processor']
            await processor.stop_processing()
        
        # Close CDN manager
        if self.cdn_manager:
            await self.cdn_manager.close()
        
        logger.info("Edge manager shutdown completed")

# Global edge manager instance
_edge_manager_instance = None

async def get_edge_manager(config: Optional[EdgeConfig] = None) -> EdgeManager:
    """Get or create edge manager"""
    global _edge_manager_instance
    
    if _edge_manager_instance is None:
        if config is None:
            config = EdgeConfig()
        
        _edge_manager_instance = EdgeManager(config)
        await _edge_manager_instance.initialize()
    
    return _edge_manager_instance

async def initialize_edge_computing(config: EdgeConfig) -> EdgeManager:
    """Initialize edge computing with custom config"""
    manager = EdgeManager(config)
    await manager.initialize()
    return manager