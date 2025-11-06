# BLNCS Performance Guide

## Performance Optimization Overview

This guide provides comprehensive performance tuning recommendations for BLNCS deployments.

## System Requirements & Benchmarks

### Minimum System Requirements
- **CPU**: 2 cores, 2.0 GHz
- **RAM**: 2 GB available
- **Disk**: 10 GB free space
- **Network**: 10 Mbps bandwidth

### Recommended System Requirements
- **CPU**: 4+ cores, 3.0+ GHz
- **RAM**: 8+ GB available
- **Disk**: SSD with 50+ GB free space
- **Network**: 100+ Mbps bandwidth

### Performance Benchmarks

#### API Performance (REST endpoints)
- **Simple queries**: < 10ms response time
- **Complex operations**: < 100ms response time
- **Throughput**: 1000+ requests/second (optimized)
- **Concurrent users**: 100+ simultaneous connections

#### Lightning Operations
- **Payment initiation**: < 500ms
- **Channel operations**: < 2 seconds
- **Balance queries**: < 50ms
- **Route calculation**: < 200ms

## Caching Strategy

### Multi-Level Caching Architecture

#### Level 1: Memory Cache (SimpleCache)
```python
from blncs.core.simple_cache import SimpleCache

# High-frequency data (< 1MB)
cache = SimpleCache(max_size=1000, default_ttl=300) # 5 minutes
```

**Use Cases**:
- API response caching
- Configuration data
- Frequently accessed channel states

**Optimization**:
- Keep cache size under system memory limits
- Use shorter TTL for dynamic data
- Monitor hit rates (target > 80%)

#### Level 2: Database Cache
```python
# Database query result caching
cache.set(f"query_{query_hash}", result, ttl=600) # 10 minutes
```

**Use Cases**:
- Database query results
- Lightning network topology data
- Historical transaction data

#### Level 3: Distributed Cache (Future)
- Redis integration for multi-node deployments
- Consistent hashing for cache distribution
- Cache warming strategies

### Cache Performance Tuning

#### Memory Management
```python
# Optimal cache configuration
cache_config = {
 'max_size': min(10000, available_memory_mb * 10),
 'cleanup_interval': 300, # 5 minutes
 'max_memory_percent': 25 # Use max 25% of available memory
}
```

#### Cache Warming
```python
def warm_cache():
 """Pre-load frequently accessed data"""
 # Load common configurations
 config_manager.get('lightning.host')
 
 # Pre-calculate routes for common destinations
 for node in frequent_destinations:
 route_calculator.get_route(node, prefetch=True)
```

## Database Performance

### SQLite Optimization (Default)
```python
# Optimal SQLite configuration
sqlite_config = {
 'journal_mode': 'WAL', # Write-Ahead Logging
 'synchronous': 'NORMAL', # Balance safety/performance
 'cache_size': 20000, # 20MB cache
 'temp_store': 'MEMORY', # Temp tables in memory
 'mmap_size': 268435456 # 256MB memory mapping
}
```

### Query Optimization
```sql
-- Index frequently queried columns
CREATE INDEX idx_payments_timestamp ON payments(created_at);
CREATE INDEX idx_channels_status ON channels(status, node_id);

-- Avoid N+1 queries
SELECT * FROM payments p 
JOIN channels c ON p.channel_id = c.id 
WHERE p.created_at > ?;
```

## Lightning Network Optimization

### Connection Pool Management
```python
from blncs.core.connection_pool_unified import get_lightning_pool

# Optimize connection pooling
pool_config = {
 'max_connections': 10, # Max concurrent connections
 'connection_timeout': 30, # 30 second timeout
 'retry_attempts': 3, # Retry failed connections
 'health_check_interval': 60 # Check connection health every minute
}
```

### Payment Route Optimization
```python
# Route caching for common paths
class RouteOptimizer:
 def __init__(self):
 self.route_cache = SimpleCache(max_size=1000, default_ttl=300)
 
 def find_optimal_route(self, destination, amount):
 cache_key = f"route_{destination}_{amount}"
 cached_route = self.route_cache.get(cache_key)
 
 if cached_route:
 return cached_route
 
 # Calculate new route
 route = self.calculate_route(destination, amount)
 self.route_cache.set(cache_key, route)
 return route
```

## API Performance Optimization

### Request Processing Pipeline
```python
# Optimize API request handling
class OptimizedAPIHandler:
 def __init__(self):
 self.request_cache = SimpleCache(max_size=500)
 self.rate_limiter = RateLimiter(requests_per_minute=1000)
 
 async def handle_request(self, request):
 # Rate limiting
 if not self.rate_limiter.allow_request(request.client_ip):
 return error_response("Rate limit exceeded", 429)
 
 # Cache identical requests
 cache_key = self.generate_cache_key(request)
 cached_response = self.request_cache.get(cache_key)
 
 if cached_response and self.is_cacheable(request):
 return cached_response
 
 # Process request
 response = await self.process_request(request)
 
 # Cache successful responses
 if response.status_code == 200 and self.is_cacheable(request):
 self.request_cache.set(cache_key, response, ttl=60)
 
 return response
```

### Batch Operations
```python
# Batch multiple operations for efficiency
async def batch_channel_updates(channel_updates):
 """Process multiple channel updates in a single transaction"""
 async with database.transaction():
 for update in channel_updates:
 await update_channel_state(update)
 
 # Batch cache updates
 cache_keys = [f"channel_{update.channel_id}" for update in channel_updates]
 cache.delete_many(cache_keys)
```

## Memory Management

### Memory Profiling
```python
import tracemalloc

def profile_memory_usage():
 """Monitor memory usage patterns"""
 tracemalloc.start()
 
 # Run operations
 perform_operations()
 
 current, peak = tracemalloc.get_traced_memory()
 print(f"Current memory usage: {current / 1024 / 1024:.1f} MB")
 print(f"Peak memory usage: {peak / 1024 / 1024:.1f} MB")
 
 tracemalloc.stop()
```

### Memory Optimization Strategies
```python
# Use generators for large datasets
def process_large_dataset(data_source):
 """Process data without loading everything into memory"""
 for batch in data_source.get_batches(batch_size=1000):
 yield process_batch(batch)

# Implement object pooling for frequently created objects
class ObjectPool:
 def __init__(self, factory, max_size=100):
 self.factory = factory
 self.pool = []
 self.max_size = max_size
 
 def acquire(self):
 if self.pool:
 return self.pool.pop()
 return self.factory()
 
 def release(self, obj):
 if len(self.pool) < self.max_size:
 obj.reset() # Reset object state
 self.pool.append(obj)
```

## Network Performance

### Connection Management
```python
# Optimize network connections
import aiohttp
import asyncio

class HTTPClientManager:
 def __init__(self):
 # Connection pooling
 connector = aiohttp.TCPConnector(
 limit=100, # Max total connections
 limit_per_host=20, # Max per host
 keepalive_timeout=30, # Keep connections alive
 enable_cleanup_closed=True
 )
 
 # Timeout configuration
 timeout = aiohttp.ClientTimeout(
 total=30, # Total request timeout
 connect=10, # Connection timeout
 sock_read=20 # Socket read timeout
 )
 
 self.session = aiohttp.ClientSession(
 connector=connector,
 timeout=timeout
 )
```

### Compression
```python
# Enable response compression
def enable_compression(app):
 """Enable gzip compression for API responses"""
 app.config['COMPRESS_MIMETYPES'] = [
 'text/html', 'text/css', 'text/xml',
 'application/json', 'application/javascript'
 ]
 app.config['COMPRESS_LEVEL'] = 6 # Balance compression/CPU
```

## Monitoring & Metrics

### Performance Metrics Collection
```python
from blncs.core.metrics_lightweight import get_metrics_collector

def collect_performance_metrics():
 """Collect key performance indicators"""
 metrics = get_metrics_collector()
 
 # API metrics
 metrics.gauge('api_response_time', get_avg_response_time())
 metrics.counter('api_requests_total', get_request_count())
 
 # Lightning metrics
 metrics.gauge('lightning_channels_active', get_active_channel_count())
 metrics.gauge('lightning_balance_total', get_total_balance())
 
 # System metrics
 metrics.gauge('memory_usage_percent', get_memory_usage_percent())
 metrics.gauge('cpu_usage_percent', get_cpu_usage_percent())
```

### Performance Alerting
```python
class PerformanceMonitor:
 def __init__(self):
 self.thresholds = {
 'api_response_time': 1000, # 1 second
 'memory_usage_percent': 85, # 85%
 'cpu_usage_percent': 80, # 80%
 'error_rate_percent': 5 # 5%
 }
 
 def check_performance(self):
 """Check performance against thresholds"""
 metrics = self.collect_current_metrics()
 
 for metric, threshold in self.thresholds.items():
 if metrics.get(metric, 0) > threshold:
 self.trigger_alert(metric, metrics[metric], threshold)
```

## Production Optimization Checklist

### System Configuration
- [ ] Enable swap file (4GB minimum)
- [ ] Configure file descriptor limits (65536+)
- [ ] Set up log rotation
- [ ] Configure firewall rules
- [ ] Enable NTP synchronization

### Application Configuration
- [ ] Set appropriate cache sizes
- [ ] Configure connection pools
- [ ] Enable compression
- [ ] Set up health checks
- [ ] Configure monitoring

### Database Optimization
- [ ] Enable WAL mode for SQLite
- [ ] Create necessary indexes
- [ ] Set up backup schedule
- [ ] Monitor query performance
- [ ] Optimize schema for access patterns

### Security & Performance
- [ ] Enable rate limiting
- [ ] Configure SSL/TLS
- [ ] Set up API authentication
- [ ] Monitor for security events
- [ ] Regular security updates

## Troubleshooting Performance Issues

### Common Performance Problems

#### High Memory Usage
```bash
# Check memory usage
ps aux | grep python
free -h

# Analyze memory with Python
python3 -m tracemalloc
```

**Solutions**:
- Reduce cache sizes
- Implement object pooling
- Use generators for large datasets
- Check for memory leaks

#### Slow API Responses
```python
# Add timing middleware
@app.middleware('http')
async def add_process_time_header(request, call_next):
 start_time = time.time()
 response = await call_next(request)
 process_time = time.time() - start_time
 response.headers["X-Process-Time"] = str(process_time)
 return response
```

**Solutions**:
- Enable response caching
- Optimize database queries
- Use connection pooling
- Implement request batching

#### Database Bottlenecks
```sql
-- Analyze slow queries
EXPLAIN QUERY PLAN SELECT * FROM payments WHERE created_at > datetime('now', '-1 day');
```

**Solutions**:
- Add missing indexes
- Optimize query structure
- Enable query result caching
- Consider database partitioning

---

*Regular performance monitoring and optimization ensure BLNCS maintains optimal performance under varying loads.*