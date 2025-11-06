"""
BLNCS Optimized Connection Pool
High-performance connection pooling for Lightning Network operations
"""

import time
import threading
import queue
import socket
import logging
from typing import Dict, Any, List, Optional, Callable, Union
from dataclasses import dataclass
from enum import Enum
from collections import deque


class ConnectionState(Enum):
    """Connection state enumeration"""
    IDLE = "idle"
    ACTIVE = "active"
    BROKEN = "broken"
    TESTING = "testing"


@dataclass
class PooledConnection:
    """Pooled connection wrapper"""
    connection: Any
    created_at: float
    last_used: float
    use_count: int
    state: ConnectionState
    pool_id: str


class ConnectionHealthChecker:
    """Check connection health"""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def is_connection_healthy(self, connection) -> bool:
        """Check if connection is healthy"""
        try:
            # Basic health check - attempt to get connection info
            if hasattr(connection, 'ping'):
                return connection.ping()
            elif hasattr(connection, 'is_connected'):
                return connection.is_connected()
            elif hasattr(connection, 'fileno'):
                # Socket-based connection
                return connection.fileno() != -1
            else:
                # Assume healthy if no check method available
                return True
        except Exception:
            return False

    def test_connection(self, connection) -> bool:
        """Test connection with timeout"""
        try:
            # Use health checker for testing
            return self.health_checker.is_connection_healthy(connection)
        except Exception:
            return False


class OptimizedConnectionPool:
    """High-performance connection pool"""

    def __init__(self, create_connection: Callable,
                 min_connections: int = 2,
                 max_connections: int = 10,
                 max_idle_time: float = 300.0,
                 test_on_borrow: bool = True,
                 test_on_return: bool = False):

        self.create_connection = create_connection
        self.min_connections = min_connections
        self.max_connections = max_connections
        self.max_idle_time = max_idle_time
        self.test_on_borrow = test_on_borrow
        self.test_on_return = test_on_return

        # Pool management
        self.idle_connections = queue.Queue()
        self.active_connections = {}
        self.total_connections = 0
        self.pool_lock = threading.RLock()

        # Statistics
        self.stats = {
            'created': 0,
            'borrowed': 0,
            'returned': 0,
            'destroyed': 0,
            'health_checks': 0,
            'health_failures': 0
        }

        # Health checker
        self.health_checker = ConnectionHealthChecker()

        # Background maintenance
        self.maintenance_thread = None
        self.shutdown_event = threading.Event()

        self.logger = logging.getLogger("BLNCS_ConnectionPool")

        # Initialize pool
        self._initialize_pool()
        self._start_maintenance()

    def _initialize_pool(self):
        """Initialize pool with minimum connections"""
        for _ in range(self.min_connections):
            conn = self._create_pooled_connection()
            if conn:
                self.idle_connections.put(conn)

    def _create_pooled_connection(self) -> Optional[PooledConnection]:
        """Create a new pooled connection"""
        try:
            connection = self.create_connection()
            pooled = PooledConnection(
                connection=connection,
                created_at=time.time(),
                last_used=time.time(),
                use_count=0,
                state=ConnectionState.IDLE,
                pool_id=f"conn_{self.stats['created']}"
            )

            with self.pool_lock:
                self.stats['created'] += 1
                self.total_connections += 1

            self.logger.debug(f"Created new connection {pooled.pool_id}")
            return pooled

        except Exception as e:
            self.logger.error(f"Failed to create connection: {e}")
            return None

    def get_connection(self, timeout: float = 10.0) -> Optional[Any]:
        """Get connection from pool"""
        deadline = time.time() + timeout

        while time.time() < deadline:
            # Try to get idle connection
            try:
                pooled_conn = self.idle_connections.get_nowait()

                # Test connection if required
                if self.test_on_borrow:
                    if not self._test_pooled_connection(pooled_conn):
                        self._destroy_connection(pooled_conn)
                        continue

                # Mark as active
                pooled_conn.state = ConnectionState.ACTIVE
                pooled_conn.last_used = time.time()
                pooled_conn.use_count += 1

                with self.pool_lock:
                    self.active_connections[id(pooled_conn.connection)] = pooled_conn
                    self.stats['borrowed'] += 1

                self.logger.debug(f"Borrowed connection {pooled_conn.pool_id}")
                return pooled_conn.connection

            except queue.Empty:
                # No idle connections, try to create new one
                if self.total_connections < self.max_connections:
                    pooled_conn = self._create_pooled_connection()
                    if pooled_conn:
                        pooled_conn.state = ConnectionState.ACTIVE
                        pooled_conn.use_count += 1

                        with self.pool_lock:
                            self.active_connections[id(pooled_conn.connection)] = pooled_conn
                            self.stats['borrowed'] += 1

                        return pooled_conn.connection

                # Wait for connection to become available
                time.sleep(0.1)

        raise TimeoutError(f"Could not get connection within {timeout} seconds")

    def return_connection(self, connection: Any):
        """Return connection to pool"""
        conn_id = id(connection)

        with self.pool_lock:
            pooled_conn = self.active_connections.pop(conn_id, None)

        if not pooled_conn:
            self.logger.warning("Attempted to return unknown connection")
            return

        # Test connection if required
        if self.test_on_return:
            if not self._test_pooled_connection(pooled_conn):
                self._destroy_connection(pooled_conn)
                return

        # Return to idle pool
        pooled_conn.state = ConnectionState.IDLE
        pooled_conn.last_used = time.time()

        try:
            self.idle_connections.put_nowait(pooled_conn)
            with self.pool_lock:
                self.stats['returned'] += 1
            self.logger.debug(f"Returned connection {pooled_conn.pool_id}")
        except queue.Full:
            # Pool full, destroy connection
            self._destroy_connection(pooled_conn)

    def _test_pooled_connection(self, pooled_conn: PooledConnection) -> bool:
        """Test if pooled connection is healthy"""
        pooled_conn.state = ConnectionState.TESTING

        with self.pool_lock:
            self.stats['health_checks'] += 1

        healthy = self.health_checker.is_connection_healthy(pooled_conn.connection)

        if not healthy:
            with self.pool_lock:
                self.stats['health_failures'] += 1

        return healthy

    def _destroy_connection(self, pooled_conn: PooledConnection):
        """Destroy a pooled connection"""
        try:
            if hasattr(pooled_conn.connection, 'close'):
                pooled_conn.connection.close()
        except Exception:
            pass

        with self.pool_lock:
            self.total_connections -= 1
            self.stats['destroyed'] += 1

        self.logger.debug(f"Destroyed connection {pooled_conn.pool_id}")

    def _start_maintenance(self):
        """Start background maintenance thread"""
        self.maintenance_thread = threading.Thread(
            target=self._maintenance_loop,
            daemon=True,
            name="ConnectionPoolMaintenance"
        )
        self.maintenance_thread.start()

    def _maintenance_loop(self):
        """Background maintenance loop"""
        while not self.shutdown_event.wait(30):  # Run every 30 seconds
            try:
                self._cleanup_idle_connections()
                self._ensure_minimum_connections()
            except Exception as e:
                self.logger.error(f"Maintenance error: {e}")

    def _cleanup_idle_connections(self):
        """Clean up idle connections that are too old"""
        current_time = time.time()
        connections_to_remove = []

        # Collect connections to check
        temp_connections = []
        while True:
            try:
                conn = self.idle_connections.get_nowait()
                temp_connections.append(conn)
            except queue.Empty:
                break

        # Check each connection
        for pooled_conn in temp_connections:
            if current_time - pooled_conn.last_used > self.max_idle_time:
                connections_to_remove.append(pooled_conn)
            elif not self._test_pooled_connection(pooled_conn):
                connections_to_remove.append(pooled_conn)
            else:
                # Connection is good, put it back
                try:
                    self.idle_connections.put_nowait(pooled_conn)
                except queue.Full:
                    connections_to_remove.append(pooled_conn)

        # Remove old/bad connections
        for pooled_conn in connections_to_remove:
            self._destroy_connection(pooled_conn)

        if connections_to_remove:
            self.logger.info(f"Cleaned up {len(connections_to_remove)} idle connections")

    def _ensure_minimum_connections(self):
        """Ensure minimum number of connections"""
        current_idle = self.idle_connections.qsize()
        if current_idle < self.min_connections:
            needed = self.min_connections - current_idle
            for _ in range(needed):
                if self.total_connections < self.max_connections:
                    conn = self._create_pooled_connection()
                    if conn:
                        try:
                            self.idle_connections.put_nowait(conn)
                        except queue.Full:
                            self._destroy_connection(conn)
                            break

    def get_pool_statistics(self) -> Dict[str, Any]:
        """Get pool statistics"""
        with self.pool_lock:
            return {
                'total_connections': self.total_connections,
                'idle_connections': self.idle_connections.qsize(),
                'active_connections': len(self.active_connections),
                'statistics': self.stats.copy(),
                'configuration': {
                    'min_connections': self.min_connections,
                    'max_connections': self.max_connections,
                    'max_idle_time': self.max_idle_time,
                    'test_on_borrow': self.test_on_borrow,
                    'test_on_return': self.test_on_return
                }
            }

    def close_pool(self):
        """Close the connection pool"""
        self.logger.info("Closing connection pool")

        # Stop maintenance
        self.shutdown_event.set()
        if self.maintenance_thread and self.maintenance_thread.is_alive():
            self.maintenance_thread.join(timeout=5)

        # Close all idle connections
        while True:
            try:
                pooled_conn = self.idle_connections.get_nowait()
                self._destroy_connection(pooled_conn)
            except queue.Empty:
                break

        # Close all active connections
        with self.pool_lock:
            for pooled_conn in list(self.active_connections.values()):
                self._destroy_connection(pooled_conn)
            self.active_connections.clear()

        self.logger.info("Connection pool closed")


class PoolManager:
    """Manage multiple connection pools"""

    def __init__(self):
        self.pools = {}
        self.lock = threading.RLock()
        self.logger = logging.getLogger("BLNCS_PoolManager")

    def create_pool(self, name: str, create_connection: Callable,
                   min_connections: int = 2, max_connections: int = 10,
                   **kwargs) -> OptimizedConnectionPool:
        """Create a named connection pool"""
        with self.lock:
            if name in self.pools:
                raise ValueError(f"Pool '{name}' already exists")

            pool = OptimizedConnectionPool(
                create_connection=create_connection,
                min_connections=min_connections,
                max_connections=max_connections,
                **kwargs
            )

            self.pools[name] = pool
            self.logger.info(f"Created connection pool '{name}'")
            return pool

    def get_pool(self, name: str) -> Optional[OptimizedConnectionPool]:
        """Get pool by name"""
        return self.pools.get(name)

    def get_connection(self, pool_name: str, timeout: float = 10.0) -> Any:
        """Get connection from named pool"""
        pool = self.get_pool(pool_name)
        if not pool:
            raise ValueError(f"Pool '{pool_name}' not found")
        return pool.get_connection(timeout)

    def return_connection(self, pool_name: str, connection: Any):
        """Return connection to named pool"""
        pool = self.get_pool(pool_name)
        if pool:
            pool.return_connection(connection)

    def get_all_statistics(self) -> Dict[str, Any]:
        """Get statistics for all pools"""
        with self.lock:
            return {
                name: pool.get_pool_statistics()
                for name, pool in self.pools.items()
            }

    def close_all_pools(self):
        """Close all connection pools"""
        with self.lock:
            for name, pool in self.pools.items():
                pool.close_pool()
            self.pools.clear()


# Global pool manager
_pool_manager = None


def get_pool_manager() -> PoolManager:
    """Get global pool manager"""
    global _pool_manager
    if _pool_manager is None:
        _pool_manager = PoolManager()
    return _pool_manager


if __name__ == "__main__":
    # Test connection pool
    def create_test_connection():
        """Create test connection"""
        return {"id": time.time(), "test": True}

    print("🔌 Testing Optimized Connection Pool...")

    # Create pool
    pool = OptimizedConnectionPool(
        create_connection=create_test_connection,
        min_connections=2,
        max_connections=5
    )

    # Test getting connections
    connections = []
    for i in range(3):
        conn = pool.get_connection()
        connections.append(conn)
        print(f"Got connection {i+1}: {conn}")

    # Return connections
    for conn in connections:
        pool.return_connection(conn)

    # Get statistics
    stats = pool.get_pool_statistics()
    print(f"Pool statistics: {stats}")

    # Close pool
    pool.close_pool()
    print("✅ Connection pool test completed")