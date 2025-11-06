#!/usr/bin/env python3
"""
BLNCS Connection Pool Optimizer

Lightweight connection pooling and optimization utilities.
"""

import asyncio
import time
import logging
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from urllib3.util import Retry
import aiohttp
import requests

from ..core.exceptions import ConnectionError, TimeoutError

logger = logging.getLogger(__name__)


@dataclass
class ConnectionMetrics:
    """Connection pool metrics"""
    total_connections: int = 0
    active_connections: int = 0
    idle_connections: int = 0
    failed_connections: int = 0
    avg_response_time: float = 0.0
    request_count: int = 0
    response_times: deque = field(default_factory=lambda: deque(maxlen=100))


class ConnectionPoolOptimizer:
    """Lightweight connection pool optimizer"""

    def __init__(self,
                 max_connections: int = 10,
                 max_connections_per_host: int = 5,
                 timeout: float = 30.0,
                 retry_attempts: int = 3):
        self.max_connections = max_connections
        self.max_connections_per_host = max_connections_per_host
        self.timeout = timeout
        self.retry_attempts = retry_attempts

        self.metrics = ConnectionMetrics()
        self._pools: Dict[str, Any] = {}
        self._lock = asyncio.Lock()

        # Setup retry strategy
        self.retry_strategy = Retry(
            total=retry_attempts,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
        )

    def create_http_session(self, base_url: str = None) -> requests.Session:
        """Create an optimized HTTP session"""
        session = requests.Session()

        # Configure connection pooling
        adapter = requests.adapters.HTTPAdapter(
            max_retries=self.retry_strategy,
            pool_connections=self.max_connections,
            pool_maxsize=self.max_connections_per_host,
            pool_block=False
        )

        session.mount('http://', adapter)
        session.mount('https://', adapter)

        # Set default headers
        session.headers.update({
            'User-Agent': 'BLNCS/2.0',
            'Connection': 'keep-alive',
        })

        # Set timeout
        session.timeout = self.timeout

        return session

    @asynccontextmanager
    async def get_http_session(self, base_url: str = None):
        """Get an HTTP session with automatic cleanup"""
        session = None
        try:
            session = self.create_http_session(base_url)
            yield session
        finally:
            if session:
                session.close()

    async def make_request(self,
                          url: str,
                          method: str = 'GET',
                          **kwargs) -> requests.Response:
        """Make an HTTP request with connection optimization"""
        start_time = time.time()

        try:
            async with self.get_http_session() as session:
                response = session.request(method, url, **kwargs)

                # Record metrics
                response_time = time.time() - start_time
                self._record_response_time(response_time)

                if response.status_code >= 400:
                    self.metrics.failed_connections += 1
                    if response.status_code == 408 or response.status_code == 504:
                        raise TimeoutError(f"Request timeout: {response.status_code}")
                    else:
                        raise ConnectionError(f"HTTP error: {response.status_code}")

                return response

        except requests.exceptions.Timeout:
            self.metrics.failed_connections += 1
            raise TimeoutError(f"Request timeout after {self.timeout}s")
        except requests.exceptions.ConnectionError as e:
            self.metrics.failed_connections += 1
            raise ConnectionError(f"Connection error: {e}")

    def _record_response_time(self, response_time: float):
        """Record response time metrics"""
        self.metrics.request_count += 1
        self.metrics.response_times.append(response_time)

        # Update average
        if self.metrics.response_times:
            self.metrics.avg_response_time = (
                sum(self.metrics.response_times) / len(self.metrics.response_times)
            )

    def get_metrics(self) -> Dict[str, Any]:
        """Get current connection metrics"""
        return {
            'total_connections': self.max_connections,
            'active_connections': getattr(self, '_active_connections', 0),
            'failed_connections': self.metrics.failed_connections,
            'avg_response_time': self.metrics.avg_response_time,
            'request_count': self.metrics.request_count,
            'success_rate': (
                (self.metrics.request_count - self.metrics.failed_connections)
                / max(self.metrics.request_count, 1) * 100
            )
        }

    def optimize_for_load(self, current_load: float) -> Dict[str, Any]:
        """Optimize pool settings based on current load"""
        optimizations = {}

        if current_load > 0.8:  # High load
            # Increase connection limits
            optimizations.update({
                'max_connections': min(self.max_connections * 2, 100),
                'max_connections_per_host': min(self.max_connections_per_host * 2, 20),
                'timeout': min(self.timeout * 1.5, 60.0)
            })
        elif current_load < 0.3:  # Low load
            # Reduce resource usage
            optimizations.update({
                'max_connections': max(self.max_connections // 2, 5),
                'max_connections_per_host': max(self.max_connections_per_host // 2, 2),
                'timeout': max(self.timeout * 0.8, 10.0)
            })

        return optimizations


class DatabaseConnectionPool:
    """Lightweight database connection pool"""

    def __init__(self,
                 connection_factory: Callable,
                 min_connections: int = 2,
                 max_connections: int = 10,
                 max_idle_time: float = 300.0):
        self.connection_factory = connection_factory
        self.min_connections = min_connections
        self.max_connections = max_connections
        self.max_idle_time = max_idle_time

        self._pool: List[Dict[str, Any]] = []
        self._active_connections: Dict[str, Any] = {}
        self._lock = asyncio.Lock()

        # Initialize minimum connections
        asyncio.create_task(self._maintain_pool())

    async def get_connection(self) -> Any:
        """Get a connection from the pool"""
        async with self._lock:
            # Try to get an idle connection
            for conn_info in self._pool:
                if not conn_info['in_use']:
                    conn_info['in_use'] = True
                    conn_info['last_used'] = time.time()
                    return conn_info['connection']

            # Create new connection if under limit
            if len(self._active_connections) < self.max_connections:
                connection = await self._create_connection()
                conn_info = {
                    'connection': connection,
                    'in_use': True,
                    'last_used': time.time(),
                    'created': time.time()
                }
                self._active_connections[id(connection)] = conn_info
                return connection

            # Pool exhausted
            raise ConnectionError("Connection pool exhausted")

    async def return_connection(self, connection: Any):
        """Return a connection to the pool"""
        async with self._lock:
            conn_id = id(connection)
            if conn_id in self._active_connections:
                conn_info = self._active_connections[conn_id]
                conn_info['in_use'] = False
                conn_info['last_used'] = time.time()

                # Move back to pool if still valid
                if time.time() - conn_info['created'] < self.max_idle_time:
                    self._pool.append(conn_info)
                    del self._active_connections[conn_id]

    async def close_all(self):
        """Close all connections"""
        async with self._lock:
            # Close active connections
            for conn_info in self._active_connections.values():
                if hasattr(conn_info['connection'], 'close'):
                    await conn_info['connection'].close()

            # Close pooled connections
            for conn_info in self._pool:
                if hasattr(conn_info['connection'], 'close'):
                    await conn_info['connection'].close()

            self._pool.clear()
            self._active_connections.clear()

    async def _create_connection(self) -> Any:
        """Create a new database connection"""
        try:
            if asyncio.iscoroutinefunction(self.connection_factory):
                return await self.connection_factory()
            else:
                return self.connection_factory()
        except Exception as e:
            raise ConnectionError(f"Failed to create connection: {e}")

    async def _maintain_pool(self):
        """Maintain minimum connections and clean up idle ones"""
        while True:
            try:
                async with self._lock:
                    # Remove expired connections
                    current_time = time.time()
                    self._pool = [
                        conn for conn in self._pool
                        if current_time - conn['last_used'] < self.max_idle_time
                    ]

                    # Ensure minimum connections
                    while len(self._pool) < self.min_connections:
                        try:
                            connection = await self._create_connection()
                            conn_info = {
                                'connection': connection,
                                'in_use': False,
                                'last_used': current_time,
                                'created': current_time
                            }
                            self._pool.append(conn_info)
                        except Exception as e:
                            logger.warning(f"Failed to create minimum connection: {e}")
                            break

                await asyncio.sleep(30)  # Check every 30 seconds

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Pool maintenance error: {e}")
                await asyncio.sleep(60)


# Global connection pool instances
_http_pool = None
_db_pool = None

def get_http_connection_pool() -> ConnectionPoolOptimizer:
    """Get global HTTP connection pool"""
    global _http_pool
    if _http_pool is None:
        _http_pool = ConnectionPoolOptimizer()
    return _http_pool

def get_database_connection_pool(connection_factory: Callable) -> DatabaseConnectionPool:
    """Get global database connection pool"""
    global _db_pool
    if _db_pool is None:
        _db_pool = DatabaseConnectionPool(connection_factory)
    return _db_pool
