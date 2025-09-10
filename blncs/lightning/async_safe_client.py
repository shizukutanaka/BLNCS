#!/usr/bin/env python3
"""
Memory-safe async Lightning Network client
Prevents memory leaks in Lightning operations through systematic resource management
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, AsyncContextManager, Union
from contextlib import asynccontextmanager
import time
from dataclasses import dataclass
import weakref

from blncs.core.async_memory_manager import (
    get_async_resource_tracker,
    track_async_task, 
    lightning_operation_context,
    safe_task_cleanup,
    AsyncBoundedSemaphore
)
from blncs.core.exceptions import LightningError, ConnectionError
from blncs.lightning.client import LightningClient
from blncs.lightning.grpc_client import LNDGRPCClient

logger = logging.getLogger(__name__)

@dataclass 
class ConnectionPoolStats:
    """Statistics for connection pool"""
    active_connections: int
    idle_connections: int
    total_connections: int
    failed_connections: int
    memory_usage_mb: float

class AsyncSafeLightningClient:
    """Memory-safe async Lightning Network client with leak prevention"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._connection_pool: Dict[str, LNDGRPCClient] = {}
        self._connection_semaphore = AsyncBoundedSemaphore(10)  # Max 10 connections
        self._streaming_tasks: Dict[str, asyncio.Task] = {}
        self._resource_tracker = get_async_resource_tracker()
        self._shutdown_event = asyncio.Event()
        self._heartbeat_task: Optional[asyncio.Task] = None
        
        # Connection pool management
        self._pool_lock = asyncio.Lock()
        self._connection_timeout = 30.0
        self._max_idle_time = 300.0  # 5 minutes
        self._cleanup_interval = 60.0  # 1 minute
        
        # Start background tasks
        self._start_background_tasks()
    
    def _start_background_tasks(self):
        """Start background maintenance tasks"""
        loop = asyncio.get_running_loop()
        
        # Connection pool cleanup task
        self._cleanup_task = loop.create_task(self._connection_cleanup_loop())
        self._resource_tracker.register_task(self._cleanup_task, "connection_pool_cleanup")
        
        # Health check task
        self._heartbeat_task = loop.create_task(self._heartbeat_loop())
        self._resource_tracker.register_task(self._heartbeat_task, "client_heartbeat")
    
    async def _connection_cleanup_loop(self):
        """Background task to cleanup idle connections"""
        while not self._shutdown_event.is_set():
            try:
                await self._cleanup_idle_connections()
                await asyncio.sleep(self._cleanup_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Connection cleanup error: {e}")
                await asyncio.sleep(5.0)
    
    async def _heartbeat_loop(self):
        """Background heartbeat to maintain connections"""
        while not self._shutdown_event.is_set():
            try:
                await self._heartbeat_check()
                await asyncio.sleep(30.0)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
                await asyncio.sleep(10.0)
    
    async def _cleanup_idle_connections(self):
        """Clean up idle connections to prevent memory leaks"""
        current_time = time.time()
        to_remove = []
        
        async with self._pool_lock:
            for conn_id, client in self._connection_pool.items():
                if hasattr(client, '_last_used'):
                    idle_time = current_time - client._last_used
                    if idle_time > self._max_idle_time:
                        to_remove.append(conn_id)
                        logger.debug(f"Marking idle connection for cleanup: {conn_id}")
            
            # Remove idle connections
            for conn_id in to_remove:
                client = self._connection_pool.pop(conn_id, None)
                if client:
                    try:
                        await client.disconnect()
                    except Exception as e:
                        logger.error(f"Error disconnecting idle client {conn_id}: {e}")
        
        if to_remove:
            logger.info(f"Cleaned up {len(to_remove)} idle connections")
    
    async def _heartbeat_check(self):
        """Health check for active connections"""
        async with self._pool_lock:
            failed_connections = []
            
            for conn_id, client in self._connection_pool.items():
                try:
                    # Quick health check
                    if hasattr(client, 'get_info'):
                        await asyncio.wait_for(client.get_info(), timeout=5.0)
                        client._last_used = time.time()
                except Exception as e:
                    logger.warning(f"Connection {conn_id} failed heartbeat: {e}")
                    failed_connections.append(conn_id)
            
            # Remove failed connections
            for conn_id in failed_connections:
                self._connection_pool.pop(conn_id, None)
        
        if failed_connections:
            logger.info(f"Removed {len(failed_connections)} failed connections")
    
    @asynccontextmanager
    async def get_connection(self, node_id: str = "default") -> AsyncContextManager[LNDGRPCClient]:
        """Get connection with automatic cleanup"""
        await self._connection_semaphore.acquire(f"lightning_connection_{node_id}")
        
        client = None
        try:
            async with self._pool_lock:
                # Reuse existing connection
                if node_id in self._connection_pool:
                    client = self._connection_pool[node_id]
                    client._last_used = time.time()
                else:
                    # Create new connection
                    client = LNDGRPCClient(self.config)
                    
                    # Track connection for cleanup
                    self._resource_tracker.track_resource("connection_pool", client)
                    
                    # Connect with timeout
                    connected = await asyncio.wait_for(
                        client.connect(), 
                        timeout=self._connection_timeout
                    )
                    
                    if not connected:
                        raise ConnectionError(f"Failed to connect to Lightning node: {node_id}")
                    
                    client._last_used = time.time()
                    self._connection_pool[node_id] = client
                    
                    logger.debug(f"Created new Lightning connection: {node_id}")
            
            yield client
            
        except Exception as e:
            # Remove failed connection from pool
            async with self._pool_lock:
                if node_id in self._connection_pool and self._connection_pool[node_id] == client:
                    del self._connection_pool[node_id]
            
            if client:
                try:
                    await client.disconnect()
                except Exception:
                    pass
            
            raise LightningError(f"Lightning connection error for {node_id}: {e}")
        
        finally:
            self._connection_semaphore.release()
    
    @track_async_task("lightning_get_info")
    async def get_info(self, node_id: str = "default") -> Dict[str, Any]:
        """Get node information with memory safety"""
        async with lightning_operation_context("get_info"):
            async with self.get_connection(node_id) as client:
                return await client.get_info()
    
    @track_async_task("lightning_get_balance")
    async def get_balance(self, node_id: str = "default") -> Dict[str, Any]:
        """Get node balance with memory safety"""
        async with lightning_operation_context("get_balance"):
            async with self.get_connection(node_id) as client:
                return await client.get_balance()
    
    @track_async_task("lightning_list_channels") 
    async def list_channels(self, node_id: str = "default", active_only: bool = False) -> List[Dict[str, Any]]:
        """List channels with memory safety"""
        async with lightning_operation_context("list_channels"):
            async with self.get_connection(node_id) as client:
                return await client.list_channels(active_only=active_only)
    
    @track_async_task("lightning_send_payment")
    async def send_payment(self, payment_request: str, node_id: str = "default", timeout: float = 60.0) -> Dict[str, Any]:
        """Send payment with memory safety and timeout"""
        async with lightning_operation_context("send_payment"):
            async with self.get_connection(node_id) as client:
                try:
                    return await asyncio.wait_for(
                        client.send_payment(payment_request),
                        timeout=timeout
                    )
                except asyncio.TimeoutError:
                    raise LightningError(f"Payment timeout after {timeout}s")
    
    @track_async_task("lightning_create_invoice")
    async def create_invoice(self, amount: int, memo: str = "", node_id: str = "default") -> Dict[str, Any]:
        """Create invoice with memory safety"""
        async with lightning_operation_context("create_invoice"):
            async with self.get_connection(node_id) as client:
                return await client.create_invoice(amount, memo)
    
    async def subscribe_invoices(self, node_id: str = "default", callback: Optional[callable] = None) -> str:
        """Subscribe to invoices with automatic cleanup"""
        stream_id = f"invoice_stream_{node_id}_{int(time.time())}"
        
        async def invoice_stream_handler():
            """Handle invoice stream with proper cleanup"""
            try:
                async with self.get_connection(node_id) as client:
                    async for invoice_update in client.subscribe_invoices():
                        if callback:
                            try:
                                if asyncio.iscoroutinefunction(callback):
                                    await callback(invoice_update)
                                else:
                                    callback(invoice_update)
                            except Exception as e:
                                logger.error(f"Invoice callback error: {e}")
                        
                        # Check for shutdown
                        if self._shutdown_event.is_set():
                            break
                            
            except asyncio.CancelledError:
                logger.debug(f"Invoice stream cancelled: {stream_id}")
            except Exception as e:
                logger.error(f"Invoice stream error: {e}")
            finally:
                # Clean up stream reference
                self._streaming_tasks.pop(stream_id, None)
                logger.debug(f"Invoice stream cleanup completed: {stream_id}")
        
        # Create and track streaming task
        task = asyncio.create_task(invoice_stream_handler())
        self._streaming_tasks[stream_id] = task
        
        # Register with resource tracker
        task_id = self._resource_tracker.register_task(task, f"invoice_stream_{node_id}")
        task._blncs_task_id = task_id
        
        # Add cleanup callback
        def stream_cleanup():
            if not task.done():
                task.cancel()
        
        self._resource_tracker.add_cleanup_callback(task_id, stream_cleanup)
        
        return stream_id
    
    async def subscribe_channels(self, node_id: str = "default", callback: Optional[callable] = None) -> str:
        """Subscribe to channel updates with automatic cleanup"""
        stream_id = f"channel_stream_{node_id}_{int(time.time())}"
        
        async def channel_stream_handler():
            """Handle channel stream with proper cleanup"""
            try:
                async with self.get_connection(node_id) as client:
                    async for channel_update in client.subscribe_channel_graph():
                        if callback:
                            try:
                                if asyncio.iscoroutinefunction(callback):
                                    await callback(channel_update)
                                else:
                                    callback(channel_update)
                            except Exception as e:
                                logger.error(f"Channel callback error: {e}")
                        
                        # Check for shutdown
                        if self._shutdown_event.is_set():
                            break
                            
            except asyncio.CancelledError:
                logger.debug(f"Channel stream cancelled: {stream_id}")
            except Exception as e:
                logger.error(f"Channel stream error: {e}")
            finally:
                # Clean up stream reference
                self._streaming_tasks.pop(stream_id, None)
                logger.debug(f"Channel stream cleanup completed: {stream_id}")
        
        # Create and track streaming task
        task = asyncio.create_task(channel_stream_handler())
        self._streaming_tasks[stream_id] = task
        
        # Register with resource tracker
        task_id = self._resource_tracker.register_task(task, f"channel_stream_{node_id}")
        task._blncs_task_id = task_id
        
        # Add cleanup callback
        def stream_cleanup():
            if not task.done():
                task.cancel()
        
        self._resource_tracker.add_cleanup_callback(task_id, stream_cleanup)
        
        return stream_id
    
    async def stop_stream(self, stream_id: str):
        """Stop specific streaming task"""
        if stream_id in self._streaming_tasks:
            task = self._streaming_tasks[stream_id]
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            
            del self._streaming_tasks[stream_id]
            logger.debug(f"Stopped stream: {stream_id}")
    
    async def get_connection_stats(self) -> ConnectionPoolStats:
        """Get connection pool statistics"""
        async with self._pool_lock:
            active_count = len(self._connection_pool)
            idle_count = 0
            failed_count = 0
            
            current_time = time.time()
            for client in self._connection_pool.values():
                if hasattr(client, '_last_used'):
                    if current_time - client._last_used > 60:  # Idle for more than 1 minute
                        idle_count += 1
        
        # Get memory usage
        memory_stats = self._resource_tracker.get_memory_stats()
        
        return ConnectionPoolStats(
            active_connections=active_count - idle_count,
            idle_connections=idle_count,
            total_connections=active_count,
            failed_connections=failed_count,
            memory_usage_mb=memory_stats['memory_mb']
        )
    
    async def health_check(self) -> Dict[str, Any]:
        """Comprehensive health check"""
        stats = await self.get_connection_stats()
        memory_stats = self._resource_tracker.get_memory_stats()
        
        return {
            'status': 'healthy' if stats.total_connections > 0 else 'no_connections',
            'connection_pool': {
                'active': stats.active_connections,
                'idle': stats.idle_connections,
                'total': stats.total_connections
            },
            'streaming_tasks': len(self._streaming_tasks),
            'memory': memory_stats,
            'background_tasks': {
                'cleanup_running': not self._cleanup_task.done() if hasattr(self, '_cleanup_task') else False,
                'heartbeat_running': not self._heartbeat_task.done() if self._heartbeat_task else False
            }
        }
    
    async def shutdown(self):
        """Graceful shutdown with resource cleanup"""
        logger.info("Shutting down AsyncSafeLightningClient")
        
        # Signal shutdown
        self._shutdown_event.set()
        
        # Stop all streaming tasks
        streaming_tasks = list(self._streaming_tasks.values())
        if streaming_tasks:
            logger.info(f"Cancelling {len(streaming_tasks)} streaming tasks")
            await safe_task_cleanup(streaming_tasks, timeout=5.0)
        
        # Stop background tasks
        background_tasks = []
        if hasattr(self, '_cleanup_task') and not self._cleanup_task.done():
            background_tasks.append(self._cleanup_task)
        if self._heartbeat_task and not self._heartbeat_task.done():
            background_tasks.append(self._heartbeat_task)
        
        if background_tasks:
            logger.info(f"Stopping {len(background_tasks)} background tasks")
            await safe_task_cleanup(background_tasks, timeout=10.0)
        
        # Close all connections
        async with self._pool_lock:
            connection_tasks = []
            for node_id, client in self._connection_pool.items():
                connection_tasks.append(client.disconnect())
            
            if connection_tasks:
                logger.info(f"Disconnecting {len(connection_tasks)} connections")
                await asyncio.gather(*connection_tasks, return_exceptions=True)
            
            self._connection_pool.clear()
        
        logger.info("AsyncSafeLightningClient shutdown completed")
    
    async def __aenter__(self):
        """Async context manager entry"""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit with cleanup"""
        await self.shutdown()

# Factory function for creating memory-safe Lightning clients
async def create_safe_lightning_client(config: Optional[Dict[str, Any]] = None) -> AsyncSafeLightningClient:
    """Factory function to create memory-safe Lightning client"""
    client = AsyncSafeLightningClient(config)
    
    # Allow client to initialize background tasks
    await asyncio.sleep(0.1)
    
    return client

# Context manager for safe Lightning operations
@asynccontextmanager
async def safe_lightning_client(config: Optional[Dict[str, Any]] = None):
    """Context manager for safe Lightning client usage"""
    client = await create_safe_lightning_client(config)
    try:
        yield client
    finally:
        await client.shutdown()

# Batch operation utilities
async def batch_lightning_operations(operations: List[Dict[str, Any]], 
                                   client: AsyncSafeLightningClient,
                                   max_concurrent: int = 5) -> List[Any]:
    """Execute batch Lightning operations with memory safety"""
    semaphore = asyncio.BoundedSemaphore(max_concurrent)
    
    async def execute_operation(operation: Dict[str, Any]):
        async with semaphore:
            method_name = operation.get('method')
            args = operation.get('args', [])
            kwargs = operation.get('kwargs', {})
            
            method = getattr(client, method_name)
            return await method(*args, **kwargs)
    
    # Execute all operations concurrently
    tasks = [execute_operation(op) for op in operations]
    
    # Use resource tracker for batch operations
    tracker = get_async_resource_tracker()
    for i, task in enumerate(tasks):
        task_id = tracker.register_task(task, f"batch_operation_{i}")
        task._blncs_task_id = task_id
    
    try:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    finally:
        # Cleanup any remaining tasks
        await safe_task_cleanup([t for t in tasks if not t.done()])

# Export main classes and functions
__all__ = [
    'AsyncSafeLightningClient',
    'ConnectionPoolStats', 
    'create_safe_lightning_client',
    'safe_lightning_client',
    'batch_lightning_operations'
]