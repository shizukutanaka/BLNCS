# BLRCS Connection Pool Module
# Efficient connection pooling for database and network resources
import asyncio
import time
from typing import Optional, Dict, Any, List, Generic, TypeVar
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum
import aiosqlite
from blrcs.errors import BLRCSError, ErrorSeverity

T = TypeVar('T')

class PoolState(Enum):
    """Connection pool states"""
    IDLE = "idle"
    ACTIVE = "active"
    CLOSED = "closed"

@dataclass
class PoolStats:
    """Connection pool statistics"""
    total_connections: int = 0
    active_connections: int = 0
    idle_connections: int = 0
    total_requests: int = 0
    total_failures: int = 0
    average_wait_time: float = 0.0
    peak_connections: int = 0

class ConnectionWrapper(Generic[T]):
    """Wrapper for pooled connections"""
    
    def __init__(self, connection: T, pool: 'ConnectionPool'):
        self.connection = connection
        self.pool = pool
        self.in_use = False
        self.created_at = time.time()
        self.last_used = time.time()
        self.use_count = 0
    
    def is_expired(self, max_age: float) -> bool:
        """Check if connection is expired"""
        return time.time() - self.created_at > max_age
    
    def is_idle_too_long(self, max_idle: float) -> bool:
        """Check if connection has been idle too long"""
        return not self.in_use and (time.time() - self.last_used > max_idle)

class ConnectionPool(Generic[T]):
    """
    Generic connection pool implementation.
    Following Carmack's principle: measure and optimize.
    """
    
    def __init__(self,
                 create_connection,
                 close_connection,
                 min_size: int = 5,   # Increased from 2
                 max_size: int = 20,  # Increased from 10  
                 max_age: float = 3600,
                 max_idle: float = 300,  # Reduced from 600 to 300
                 validation_interval: float = 15):  # Reduced from 30 to 15
        """
        Initialize connection pool.
        
        Args:
            create_connection: Async function to create new connection
            close_connection: Async function to close connection
            min_size: Minimum number of connections
            max_size: Maximum number of connections
            max_age: Maximum age of connection in seconds
            max_idle: Maximum idle time in seconds
            validation_interval: How often to validate connections
        """
        self.create_connection = create_connection
        self.close_connection = close_connection
        self.min_size = min_size
        self.max_size = max_size
        self.max_age = max_age
        self.max_idle = max_idle
        self.validation_interval = validation_interval
        
        self.pool: deque[ConnectionWrapper[T]] = deque()
        self.active: List[ConnectionWrapper[T]] = []
        self.state = PoolState.IDLE
        self.stats = PoolStats()
        self.lock = asyncio.Lock()
        self.semaphore = asyncio.Semaphore(max_size)
        self.wait_queue: deque[asyncio.Future] = deque()
        self._validation_task = None
    
    async def initialize(self):
        """Initialize pool with minimum connections"""
        async with self.lock:
            self.state = PoolState.ACTIVE
            
            # Create minimum connections
            for _ in range(self.min_size):
                try:
                    conn = await self.create_connection()
                    wrapper = ConnectionWrapper(conn, self)
                    self.pool.append(wrapper)
                    self.stats.total_connections += 1
                except Exception as e:
                    # Log but don't fail initialization
                    self.stats.total_failures += 1
            
            self.stats.idle_connections = len(self.pool)
            
            # Start validation task
            self._validation_task = asyncio.create_task(self._validation_loop())
    
    async def acquire(self, timeout: Optional[float] = None) -> T:
        """
        Acquire connection from pool.
        
        Args:
            timeout: Maximum time to wait for connection
            
        Returns:
            Connection object
        """
        if self.state != PoolState.ACTIVE:
            raise BLRCSError("Connection pool is not active", ErrorSeverity.HIGH)
        
        start_time = time.time()
        self.stats.total_requests += 1
        
        # Try to get existing connection
        async with self.lock:
            # Check for available connection
            while self.pool:
                wrapper = self.pool.popleft()
                
                # Validate connection
                if not wrapper.is_expired(self.max_age):
                    wrapper.in_use = True
                    wrapper.last_used = time.time()
                    wrapper.use_count += 1
                    self.active.append(wrapper)
                    self.stats.active_connections += 1
                    self.stats.idle_connections -= 1
                    
                    # Update wait time
                    wait_time = time.time() - start_time
                    self.stats.average_wait_time = (
                        (self.stats.average_wait_time * (self.stats.total_requests - 1) + wait_time) /
                        self.stats.total_requests
                    )
                    
                    return wrapper.connection
                else:
                    # Close expired connection
                    await self._close_wrapper(wrapper)
            
            # Need to create new connection
            if self.stats.total_connections < self.max_size:
                try:
                    conn = await self.create_connection()
                    wrapper = ConnectionWrapper(conn, self)
                    wrapper.in_use = True
                    wrapper.use_count = 1
                    self.active.append(wrapper)
                    self.stats.total_connections += 1
                    self.stats.active_connections += 1
                    self.stats.peak_connections = max(
                        self.stats.peak_connections,
                        self.stats.total_connections
                    )
                    
                    wait_time = time.time() - start_time
                    self.stats.average_wait_time = (
                        (self.stats.average_wait_time * (self.stats.total_requests - 1) + wait_time) /
                        self.stats.total_requests
                    )
                    
                    return wrapper.connection
                except Exception as e:
                    self.stats.total_failures += 1
                    raise BLRCSError(f"Failed to create connection: {e}", ErrorSeverity.HIGH)
        
        # Wait for available connection
        future = asyncio.Future()
        self.wait_queue.append(future)
        
        try:
            if timeout:
                conn = await asyncio.wait_for(future, timeout)
            else:
                conn = await future
            
            wait_time = time.time() - start_time
            self.stats.average_wait_time = (
                (self.stats.average_wait_time * (self.stats.total_requests - 1) + wait_time) /
                self.stats.total_requests
            )
            
            return conn
        except asyncio.TimeoutError:
            self.wait_queue.remove(future)
            self.stats.total_failures += 1
            raise BLRCSError("Timeout waiting for connection", ErrorSeverity.MEDIUM)
    
    async def release(self, connection: T):
        """
        Release connection back to pool.
        
        Args:
            connection: Connection to release
        """
        async with self.lock:
            # Find wrapper
            wrapper = None
            for w in self.active:
                if w.connection == connection:
                    wrapper = w
                    break
            
            if not wrapper:
                return  # Connection not from this pool
            
            # Remove from active
            self.active.remove(wrapper)
            wrapper.in_use = False
            wrapper.last_used = time.time()
            self.stats.active_connections -= 1
            
            # Check if someone is waiting
            if self.wait_queue:
                future = self.wait_queue.popleft()
                if not future.done():
                    wrapper.in_use = True
                    wrapper.use_count += 1
                    self.active.append(wrapper)
                    self.stats.active_connections += 1
                    future.set_result(wrapper.connection)
                    return
            
            # Return to pool
            if not wrapper.is_expired(self.max_age):
                self.pool.append(wrapper)
                self.stats.idle_connections += 1
            else:
                await self._close_wrapper(wrapper)
    
    async def _close_wrapper(self, wrapper: ConnectionWrapper[T]):
        """Close connection wrapper"""
        try:
            await self.close_connection(wrapper.connection)
        except:
            pass  # Ignore close errors
        finally:
            self.stats.total_connections -= 1
            if wrapper.in_use:
                self.stats.active_connections -= 1
            else:
                self.stats.idle_connections -= 1
    
    async def close(self):
        """Close all connections and shutdown pool"""
        async with self.lock:
            self.state = PoolState.CLOSED
            
            # Cancel validation task
            if self._validation_task:
                self._validation_task.cancel()
                try:
                    await self._validation_task
                except asyncio.CancelledError:
                    pass
            
            # Cancel waiting requests
            for future in self.wait_queue:
                if not future.done():
                    future.cancel()
            self.wait_queue.clear()
            
            # Close all connections
            all_connections = list(self.pool) + list(self.active)
            for wrapper in all_connections:
                await self._close_wrapper(wrapper)
            
            self.pool.clear()
            self.active.clear()
    
    async def _validation_loop(self):
        """Periodic validation of connections"""
        while self.state == PoolState.ACTIVE:
            try:
                await asyncio.sleep(self.validation_interval)
                await self._validate_connections()
            except asyncio.CancelledError:
                break
            except:
                pass  # Continue validation loop
    
    async def _validate_connections(self):
        """Validate and clean up connections"""
        async with self.lock:
            # Check idle connections
            to_remove = []
            for wrapper in self.pool:
                if wrapper.is_expired(self.max_age) or wrapper.is_idle_too_long(self.max_idle):
                    to_remove.append(wrapper)
            
            # Remove expired connections
            for wrapper in to_remove:
                self.pool.remove(wrapper)
                await self._close_wrapper(wrapper)
            
            # Ensure minimum connections
            while len(self.pool) + len(self.active) < self.min_size:
                try:
                    conn = await self.create_connection()
                    wrapper = ConnectionWrapper(conn, self)
                    self.pool.append(wrapper)
                    self.stats.total_connections += 1
                    self.stats.idle_connections += 1
                except:
                    break  # Stop trying if creation fails
    
    @asynccontextmanager
    async def connection(self, timeout: Optional[float] = None):
        """
        Context manager for connection.
        
        Usage:
            async with pool.connection() as conn:
                # Use connection
        """
        conn = await self.acquire(timeout)
        try:
            yield conn
        finally:
            await self.release(conn)
    
    def get_stats(self) -> PoolStats:
        """Get pool statistics"""
        return PoolStats(
            total_connections=self.stats.total_connections,
            active_connections=self.stats.active_connections,
            idle_connections=self.stats.idle_connections,
            total_requests=self.stats.total_requests,
            total_failures=self.stats.total_failures,
            average_wait_time=self.stats.average_wait_time,
            peak_connections=self.stats.peak_connections
        )

class DatabasePool(ConnectionPool[aiosqlite.Connection]):
    """
    Specialized database connection pool.
    """
    
    def __init__(self, db_path: str, **kwargs):
        self.db_path = db_path
        
        async def create():
            conn = await aiosqlite.connect(db_path)
            # Set optimizations
            await conn.execute("PRAGMA journal_mode=WAL")
            await conn.execute("PRAGMA synchronous=NORMAL")
            return conn
        
        async def close(conn):
            await conn.close()
        
        super().__init__(create, close, **kwargs)
    
    async def execute(self, query: str, params: tuple = ()):
        """Execute query using pooled connection"""
        async with self.connection() as conn:
            cursor = await conn.execute(query, params)
            await conn.commit()
            return cursor
    
    async def fetch_one(self, query: str, params: tuple = ()):
        """Fetch one row using pooled connection"""
        async with self.connection() as conn:
            cursor = await conn.execute(query, params)
            row = await cursor.fetchone()
            await cursor.close()
            return row
    
    async def fetch_all(self, query: str, params: tuple = ()):
        """Fetch all rows using pooled connection"""
        async with self.connection() as conn:
            cursor = await conn.execute(query, params)
            rows = await cursor.fetchall()
            await cursor.close()
            return rows