"""
Unified Connection Pooling System
High-performance connection pooling for Lightning Network clients and other services.
"""

import time
import threading
import asyncio
import socket
from typing import Dict, Any, Optional, List, Callable, Union, TypeVar, Generic
from dataclasses import dataclass, field
from collections import deque
from enum import Enum
import random
from contextlib import contextmanager, asynccontextmanager

from .logger import get_logger

logger = get_logger(__name__)

T = TypeVar('T')

class ConnectionState(Enum):
    """Connection state enumeration."""
    IDLE = "idle"
    ACTIVE = "active"
    FAILED = "failed"
    CLOSED = "closed"

@dataclass
class ConnectionInfo:
    """Information about a pooled connection."""
    connection: Any
    created_at: float
    last_used: float
    use_count: int = 0
    state: ConnectionState = ConnectionState.IDLE
    errors: int = 0
    
    def is_expired(self, max_age: float) -> bool:
        """Check if connection has exceeded maximum age."""
        return time.time() - self.created_at > max_age
    
    def is_idle_expired(self, idle_timeout: float) -> bool:
        """Check if connection has been idle too long."""
        return time.time() - self.last_used > idle_timeout

@dataclass
class PoolStats:
    """Connection pool statistics."""
    total_connections: int = 0
    active_connections: int = 0
    idle_connections: int = 0
    failed_connections: int = 0
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    average_response_time: float = 0.0
    pool_hits: int = 0
    pool_misses: int = 0

class ConnectionPool(Generic[T]):
    """High-performance connection pool with health monitoring."""
    
    def __init__(self, 
                 create_connection: Callable[[], T],
                 validate_connection: Optional[Callable[[T], bool]] = None,
                 close_connection: Optional[Callable[[T], None]] = None,
                 max_connections: int = 10,
                 min_connections: int = 2,
                 max_age: float = 3600,  # 1 hour
                 idle_timeout: float = 300,  # 5 minutes
                 retry_attempts: int = 3,
                 health_check_interval: float = 60):  # 1 minute
        """Initialize connection pool."""
        self.create_connection = create_connection
        self.validate_connection = validate_connection or (lambda x: True)
        self.close_connection = close_connection or (lambda x: None)
        self.max_connections = max_connections
        self.min_connections = min_connections
        self.max_age = max_age
        self.idle_timeout = idle_timeout
        self.retry_attempts = retry_attempts
        self.health_check_interval = health_check_interval
        
        # Connection storage
        self.connections: Dict[int, ConnectionInfo] = {}
        self.available_connections: deque = deque()
        self._connection_counter = 0
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Statistics
        self.stats = PoolStats()
        
        # Health monitoring
        self._health_thread: Optional[threading.Thread] = None
        self._health_running = False
        
        self.logger = get_logger(__name__)
        
        # Initialize minimum connections
        self._initialize_pool()
        
        # Start health monitoring
        self._start_health_monitoring()
    
    def _initialize_pool(self):
        """Initialize pool with minimum connections."""
        for _ in range(self.min_connections):
            try:
                conn = self._create_new_connection()
                if conn:
                    conn_id = self._get_next_id()
                    info = ConnectionInfo(
                        connection=conn,
                        created_at=time.time(),
                        last_used=time.time()
                    )
                    self.connections[conn_id] = info
                    self.available_connections.append(conn_id)
            except Exception as e:
                self.logger.error(f"Failed to initialize connection: {e}")
    
    def _get_next_id(self) -> int:
        """Get next connection ID."""
        self._connection_counter += 1
        return self._connection_counter
    
    def _create_new_connection(self) -> Optional[T]:
        """Create a new connection with retry logic."""
        for attempt in range(self.retry_attempts):
            try:
                conn = self.create_connection()
                self.logger.debug(f"Created new connection (attempt {attempt + 1})")
                return conn
            except Exception as e:
                self.logger.warning(f"Connection creation attempt {attempt + 1} failed: {e}")
                if attempt < self.retry_attempts - 1:
                    time.sleep(0.1 * (attempt + 1))  # Exponential backoff
        
        self.logger.error("Failed to create connection after all attempts")
        return None
    
    def _cleanup_connection(self, conn_id: int):
        """Clean up a failed or expired connection."""
        if conn_id in self.connections:
            info = self.connections[conn_id]
            try:
                self.close_connection(info.connection)
            except Exception as e:
                self.logger.warning(f"Error closing connection {conn_id}: {e}")
            
            del self.connections[conn_id]
            
            # Remove from available queue if present
            try:
                self.available_connections.remove(conn_id)
            except ValueError:
                pass  # Not in queue
    
    def _validate_and_refresh_connection(self, conn_id: int) -> bool:
        """Validate connection and refresh if needed."""
        if conn_id not in self.connections:
            return False
        
        info = self.connections[conn_id]
        
        # Check if connection is expired
        if info.is_expired(self.max_age):
            self.logger.debug(f"Connection {conn_id} expired, removing")
            self._cleanup_connection(conn_id)
            return False
        
        # Validate connection health
        try:
            if not self.validate_connection(info.connection):
                self.logger.debug(f"Connection {conn_id} failed validation")
                info.state = ConnectionState.FAILED
                info.errors += 1
                self._cleanup_connection(conn_id)
                return False
        except Exception as e:
            self.logger.warning(f"Connection validation error for {conn_id}: {e}")
            info.errors += 1
            if info.errors > 3:  # Too many errors, remove connection
                self._cleanup_connection(conn_id)
                return False
        
        return True
    
    @contextmanager
    def get_connection(self):
        """Get a connection from the pool (context manager)."""
        connection = None
        conn_id = None
        start_time = time.time()
        
        try:
            with self._lock:
                # Try to get an available connection
                while self.available_connections:
                    conn_id = self.available_connections.popleft()
                    
                    if self._validate_and_refresh_connection(conn_id):
                        info = self.connections[conn_id]
                        connection = info.connection
                        info.state = ConnectionState.ACTIVE
                        info.last_used = time.time()
                        info.use_count += 1
                        self.stats.pool_hits += 1
                        break
                
                # If no available connection, create a new one
                if connection is None:
                    self.stats.pool_misses += 1
                    
                    if len(self.connections) < self.max_connections:
                        new_conn = self._create_new_connection()
                        if new_conn:
                            conn_id = self._get_next_id()
                            info = ConnectionInfo(
                                connection=new_conn,
                                created_at=time.time(),
                                last_used=time.time(),
                                state=ConnectionState.ACTIVE
                            )
                            self.connections[conn_id] = info
                            connection = new_conn
                            info.use_count += 1
                    else:
                        # Wait for a connection to become available
                        # This is a simple implementation - could be improved with condition variables
                        raise RuntimeError("No connections available and max pool size reached")
            
            if connection is None:
                self.stats.failed_requests += 1
                raise RuntimeError("Unable to obtain connection from pool")
            
            self.stats.total_requests += 1
            yield connection
            self.stats.successful_requests += 1
            
        except Exception as e:
            self.stats.failed_requests += 1
            if conn_id and conn_id in self.connections:
                self.connections[conn_id].errors += 1
                if self.connections[conn_id].errors > 5:
                    with self._lock:
                        self._cleanup_connection(conn_id)
                        conn_id = None
            raise
            
        finally:
            # Return connection to pool
            if conn_id and conn_id in self.connections:
                with self._lock:
                    info = self.connections[conn_id]
                    info.state = ConnectionState.IDLE
                    self.available_connections.append(conn_id)
                    
                    # Update response time statistics
                    response_time = time.time() - start_time
                    if self.stats.average_response_time == 0:
                        self.stats.average_response_time = response_time
                    else:
                        # Exponential moving average
                        self.stats.average_response_time = 0.9 * self.stats.average_response_time + 0.1 * response_time
    
    def _start_health_monitoring(self):
        """Start background health monitoring thread."""
        if self._health_running:
            return
        
        self._health_running = True
        
        def health_monitor():
            while self._health_running:
                try:
                    self._perform_health_check()
                    time.sleep(self.health_check_interval)
                except Exception as e:
                    self.logger.error(f"Health monitor error: {e}")
                    time.sleep(10)  # Wait before retry
        
        self._health_thread = threading.Thread(target=health_monitor, daemon=True)
        self._health_thread.start()
        self.logger.debug("Started connection pool health monitoring")
    
    def _perform_health_check(self):
        """Perform health check on all connections."""
        with self._lock:
            current_time = time.time()
            expired_connections = []
            idle_expired_connections = []
            
            for conn_id, info in self.connections.items():
                # Check for expired connections
                if info.is_expired(self.max_age):
                    expired_connections.append(conn_id)
                elif info.state == ConnectionState.IDLE and info.is_idle_expired(self.idle_timeout):
                    idle_expired_connections.append(conn_id)
            
            # Remove expired connections
            for conn_id in expired_connections:
                self.logger.debug(f"Removing expired connection {conn_id}")
                self._cleanup_connection(conn_id)
            
            # Remove idle expired connections (but keep minimum)
            remaining_connections = len(self.connections)
            for conn_id in idle_expired_connections:
                if remaining_connections > self.min_connections:
                    self.logger.debug(f"Removing idle expired connection {conn_id}")
                    self._cleanup_connection(conn_id)
                    remaining_connections -= 1
            
            # Ensure we have minimum connections
            current_count = len(self.connections)
            if current_count < self.min_connections:
                needed = self.min_connections - current_count
                for _ in range(needed):
                    try:
                        conn = self._create_new_connection()
                        if conn:
                            conn_id = self._get_next_id()
                            info = ConnectionInfo(
                                connection=conn,
                                created_at=current_time,
                                last_used=current_time
                            )
                            self.connections[conn_id] = info
                            self.available_connections.append(conn_id)
                    except Exception as e:
                        self.logger.error(f"Failed to create replacement connection: {e}")
                        break
            
            # Update statistics
            self._update_stats()
    
    def _update_stats(self):
        """Update connection pool statistics."""
        active = sum(1 for info in self.connections.values() if info.state == ConnectionState.ACTIVE)
        idle = sum(1 for info in self.connections.values() if info.state == ConnectionState.IDLE)
        failed = sum(1 for info in self.connections.values() if info.state == ConnectionState.FAILED)
        
        self.stats.total_connections = len(self.connections)
        self.stats.active_connections = active
        self.stats.idle_connections = idle
        self.stats.failed_connections = failed
    
    def get_stats(self) -> Dict[str, Any]:
        """Get connection pool statistics."""
        with self._lock:
            self._update_stats()
            
            success_rate = 0.0
            if self.stats.total_requests > 0:
                success_rate = (self.stats.successful_requests / self.stats.total_requests) * 100
            
            hit_rate = 0.0
            if (self.stats.pool_hits + self.stats.pool_misses) > 0:
                hit_rate = (self.stats.pool_hits / (self.stats.pool_hits + self.stats.pool_misses)) * 100
            
            return {
                "total_connections": self.stats.total_connections,
                "active_connections": self.stats.active_connections,
                "idle_connections": self.stats.idle_connections,
                "failed_connections": self.stats.failed_connections,
                "max_connections": self.max_connections,
                "min_connections": self.min_connections,
                "total_requests": self.stats.total_requests,
                "successful_requests": self.stats.successful_requests,
                "failed_requests": self.stats.failed_requests,
                "success_rate": success_rate,
                "pool_hits": self.stats.pool_hits,
                "pool_misses": self.stats.pool_misses,
                "hit_rate": hit_rate,
                "average_response_time": self.stats.average_response_time
            }
    
    def resize_pool(self, new_max_size: int, new_min_size: Optional[int] = None):
        """Resize the connection pool."""
        with self._lock:
            if new_min_size:
                self.min_connections = new_min_size
            
            old_max = self.max_connections
            self.max_connections = new_max_size
            
            # If reducing size, remove excess connections
            if new_max_size < old_max:
                current_count = len(self.connections)
                if current_count > new_max_size:
                    excess = current_count - new_max_size
                    # Remove idle connections first
                    idle_connections = [
                        conn_id for conn_id, info in self.connections.items()
                        if info.state == ConnectionState.IDLE
                    ]
                    
                    for conn_id in idle_connections[:excess]:
                        self._cleanup_connection(conn_id)
            
            self.logger.info(f"Resized connection pool: {old_max} -> {new_max_size}")
    
    def close_all(self):
        """Close all connections and stop health monitoring."""
        self._health_running = False
        if self._health_thread:
            self._health_thread.join(timeout=5)
        
        with self._lock:
            for conn_id in list(self.connections.keys()):
                self._cleanup_connection(conn_id)
            
            self.available_connections.clear()
        
        self.logger.info("Closed all connections in pool")

class LightningConnectionPool:
    """Specialized connection pool for Lightning Network clients."""
    
    def __init__(self, client_config: Dict[str, Any], max_connections: int = 5):
        """Initialize Lightning connection pool."""
        self.client_config = client_config
        self.logger = get_logger(__name__)
        
        # Create connection pool with Lightning-specific functions
        self.pool = ConnectionPool(
            create_connection=self._create_lightning_connection,
            validate_connection=self._validate_lightning_connection,
            close_connection=self._close_lightning_connection,
            max_connections=max_connections,
            min_connections=1,
            max_age=1800,  # 30 minutes for Lightning connections
            idle_timeout=300,  # 5 minutes
            health_check_interval=30  # Check every 30 seconds
        )
    
    def _create_lightning_connection(self):
        """Create a new Lightning Network connection."""
        try:
            # This would create an actual Lightning client connection
            # For now, return a mock connection
            from ..lightning.client import LightningClient
            return LightningClient(self.client_config)
        except Exception as e:
            self.logger.error(f"Failed to create Lightning connection: {e}")
            raise
    
    def _validate_lightning_connection(self, connection) -> bool:
        """Validate Lightning Network connection."""
        try:
            # Simple ping test - could be enhanced with actual Lightning API calls
            if hasattr(connection, 'get_info'):
                info = connection.get_info()
                return info is not None
            return True
        except Exception as e:
            self.logger.warning(f"Lightning connection validation failed: {e}")
            return False
    
    def _close_lightning_connection(self, connection):
        """Close Lightning Network connection."""
        try:
            if hasattr(connection, 'close'):
                connection.close()
        except Exception as e:
            self.logger.warning(f"Error closing Lightning connection: {e}")
    
    @contextmanager
    def get_client(self):
        """Get a Lightning client from the pool."""
        with self.pool.get_connection() as conn:
            yield conn
    
    def get_stats(self) -> Dict[str, Any]:
        """Get Lightning connection pool statistics."""
        stats = self.pool.get_stats()
        stats['connection_type'] = 'lightning'
        return stats

# Global connection pools
_lightning_pools: Dict[str, LightningConnectionPool] = {}
_pool_lock = threading.Lock()

def get_lightning_pool(config: Dict[str, Any], pool_name: str = "default") -> LightningConnectionPool:
    """Get or create a Lightning connection pool."""
    global _lightning_pools
    
    with _pool_lock:
        if pool_name not in _lightning_pools:
            max_conn = config.get('max_connections', 5)
            _lightning_pools[pool_name] = LightningConnectionPool(config, max_conn)
            logger.info(f"Created Lightning connection pool '{pool_name}' with {max_conn} max connections")
        
        return _lightning_pools[pool_name]

if __name__ == "__main__":
    # Test connection pool
    import json
    
    # Mock connection function
    def create_mock_connection():
        """Mock connection creator for testing."""
        return {"id": random.randint(1000, 9999), "connected": True}
    
    def validate_mock_connection(conn):
        """Mock connection validator."""
        return conn.get("connected", False)
    
    def close_mock_connection(conn):
        """Mock connection closer."""
        conn["connected"] = False
    
    # Create test pool
    pool = ConnectionPool(
        create_connection=create_mock_connection,
        validate_connection=validate_mock_connection,
        close_connection=close_mock_connection,
        max_connections=5,
        min_connections=2
    )
    
    print("Testing connection pool...")
    
    # Test getting connections
    for i in range(10):
        try:
            with pool.get_connection() as conn:
                print(f"Got connection: {conn['id']}")
                time.sleep(0.1)  # Simulate work
        except Exception as e:
            print(f"Failed to get connection {i}: {e}")
    
    # Print statistics
    stats = pool.get_stats()
    print(f"Pool statistics: {json.dumps(stats, indent=2)}")
    
    # Clean up
    pool.close_all()
    print("Test completed")