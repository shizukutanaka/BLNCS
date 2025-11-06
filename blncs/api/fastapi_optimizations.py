#!/usr/bin/env python3
"""
FastAPI Best Practices and Optimizations
Implements 2024 FastAPI patterns for production use
"""

import asyncio
import logging
from typing import Callable, Any, Optional, Type, List
from functools import wraps
from contextlib import asynccontextmanager

try:
    from fastapi import FastAPI, Depends, Request, Response
    from fastapi.dependencies.utils import get_dependant
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

logger = logging.getLogger(__name__)


class AsyncDependencyCache:
    """
    Cache for async dependencies within a request scope
    FastAPI caches sync dependencies automatically, but async ones benefit from explicit caching
    """

    def __init__(self):
        self._cache: dict = {}

    def get(self, key: str) -> Any:
        """Get cached value"""
        return self._cache.get(key)

    def set(self, key: str, value: Any) -> None:
        """Set cached value"""
        self._cache[key] = value

    def has(self, key: str) -> bool:
        """Check if key is cached"""
        return key in self._cache

    def clear(self) -> None:
        """Clear all cached values"""
        self._cache.clear()


async def async_dependency_with_cache(
    cache_key: str,
    dependency_func: Callable,
    cache: AsyncDependencyCache
) -> Any:
    """
    Execute async dependency with caching
    Prevents redundant async calls within the same request
    """
    if cache.has(cache_key):
        return cache.get(cache_key)

    result = await dependency_func()
    cache.set(cache_key, result)
    return result


def create_async_session_dependency(get_session_func: Callable):
    """
    Create a dependency for async database sessions
    Follows FastAPI best practices for resource management
    """
    async def get_session():
        async with get_session_func() as session:
            try:
                yield session
            finally:
                await session.close()
    return get_session


class ConcurrentTaskRunner:
    """
    Helper for running multiple async tasks concurrently
    Implements asyncio.gather() best practices
    """

    @staticmethod
    async def run_concurrently(*tasks, return_exceptions: bool = False) -> List[Any]:
        """
        Run multiple async tasks concurrently
        Good for parallel I/O operations (HTTP requests, database queries, etc.)
        """
        return await asyncio.gather(*tasks, return_exceptions=return_exceptions)

    @staticmethod
    async def run_with_timeout(
        coro,
        timeout_seconds: float,
        on_timeout: Optional[Callable] = None
    ) -> Any:
        """
        Run async operation with timeout
        Prevents hanging requests
        """
        try:
            return await asyncio.wait_for(coro, timeout=timeout_seconds)
        except asyncio.TimeoutError:
            logger.warning(f"Operation timed out after {timeout_seconds}s")
            if on_timeout:
                return on_timeout()
            raise


class RequestLogger:
    """
    Middleware for logging and monitoring requests
    """

    def __init__(self, app: 'FastAPI'):
        self.app = app

    async def log_request(self, request: Request, call_next) -> Response:
        """
        Log request details and execution time
        Useful for performance monitoring
        """
        import time

        method = request.method
        path = request.url.path
        start_time = time.time()

        response = await call_next(request)
        process_time = time.time() - start_time

        logger.info(
            f"{method} {path} - {response.status_code} - {process_time:.3f}s"
        )

        # Add timing header
        response.headers["X-Process-Time"] = str(process_time)
        return response


class AsyncContextManager:
    """
    Helper for managing async context (database connections, etc.)
    """

    @staticmethod
    @asynccontextmanager
    async def managed_resource(resource_factory: Callable, cleanup: Optional[Callable] = None):
        """
        Acquire and manage resource with automatic cleanup
        Ensures cleanup even if exception occurs
        """
        resource = await resource_factory() if asyncio.iscoroutinefunction(resource_factory) else resource_factory()

        try:
            yield resource
        finally:
            if cleanup:
                if asyncio.iscoroutinefunction(cleanup):
                    await cleanup(resource)
                else:
                    cleanup(resource)


class ParallelBatchProcessor:
    """
    Process items in parallel batches efficiently
    Useful for bulk operations like importing data or sending notifications
    """

    def __init__(self, batch_size: int = 10, max_concurrent: int = 5):
        self.batch_size = batch_size
        self.max_concurrent = max_concurrent

    async def process_batch(
        self,
        items: List[Any],
        processor_func: Callable
    ) -> List[Any]:
        """
        Process items in concurrent batches
        """
        results = []
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def process_with_semaphore(item):
            async with semaphore:
                return await processor_func(item)

        # Split into batches
        batches = [
            items[i:i + self.batch_size]
            for i in range(0, len(items), self.batch_size)
        ]

        for batch in batches:
            batch_tasks = [process_with_semaphore(item) for item in batch]
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            results.extend(batch_results)

        return results


class DependendencyInjectionOptimizer:
    """
    Optimizes FastAPI dependency injection
    Implements caching and efficient resolution
    """

    @staticmethod
    def cache_dependency(key: str, lifetime_seconds: Optional[int] = None):
        """
        Decorator to cache dependency results
        lifetime_seconds: if None, cache for request lifetime
        """
        def decorator(func: Callable) -> Callable:
            cached_value = None
            cached_time = None

            @wraps(func)
            async def wrapper(*args, **kwargs):
                nonlocal cached_value, cached_time
                import time

                now = time.time()

                # Check if cached and not expired
                if (cached_value is not None and
                    (lifetime_seconds is None or (now - cached_time) < lifetime_seconds)):
                    return cached_value

                # Call original function
                result = await func(*args, **kwargs) if asyncio.iscoroutinefunction(func) else func(*args, **kwargs)
                cached_value = result
                cached_time = now
                return result

            return wrapper
        return decorator


class RateLimitingHelper:
    """
    Helper for implementing rate limiting in FastAPI
    """

    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.request_times: dict = {}

    def is_allowed(self, client_id: str) -> bool:
        """Check if client is within rate limit"""
        import time

        now = time.time()
        window_start = now - self.window_seconds

        # Clean old requests
        if client_id in self.request_times:
            self.request_times[client_id] = [
                t for t in self.request_times[client_id] if t > window_start
            ]

        # Check limit
        if client_id not in self.request_times:
            self.request_times[client_id] = []

        if len(self.request_times[client_id]) >= self.max_requests:
            return False

        # Add current request
        self.request_times[client_id].append(now)
        return True


class FastAPIOptimizationConfig:
    """
    Configuration for FastAPI optimizations
    """

    def __init__(
        self,
        enable_compression: bool = True,
        compression_level: int = 6,
        enable_request_logging: bool = True,
        enable_cors: bool = True,
        cors_origins: List[str] = None,
        gzip_min_size: int = 1000
    ):
        self.enable_compression = enable_compression
        self.compression_level = compression_level
        self.enable_request_logging = enable_request_logging
        self.enable_cors = enable_cors
        self.cors_origins = cors_origins or ["*"]
        self.gzip_min_size = gzip_min_size

    def apply_to_app(self, app: 'FastAPI') -> None:
        """Apply configurations to FastAPI app"""
        if not HAS_FASTAPI:
            logger.warning("FastAPI not installed, skipping optimization")
            return

        # Add GZIP middleware for compression
        if self.enable_compression:
            try:
                from fastapi.middleware.gzip import GZIPMiddleware
                app.add_middleware(
                    GZIPMiddleware,
                    minimum_size=self.gzip_min_size
                )
                logger.info("Added GZIP compression middleware")
            except Exception as e:
                logger.warning(f"Failed to add GZIP middleware: {e}")

        # Add CORS middleware
        if self.enable_cors:
            try:
                from fastapi.middleware.cors import CORSMiddleware
                app.add_middleware(
                    CORSMiddleware,
                    allow_origins=self.cors_origins,
                    allow_credentials=True,
                    allow_methods=["*"],
                    allow_headers=["*"],
                )
                logger.info("Added CORS middleware")
            except Exception as e:
                logger.warning(f"Failed to add CORS middleware: {e}")

        # Add request logging
        if self.enable_request_logging:
            try:
                from fastapi.middleware.base import BaseHTTPMiddleware
                request_logger = RequestLogger(app)
                app.add_middleware(BaseHTTPMiddleware, dispatch=request_logger.log_request)
                logger.info("Added request logging middleware")
            except Exception as e:
                logger.warning(f"Failed to add logging middleware: {e}")


__all__ = [
    'AsyncDependencyCache',
    'async_dependency_with_cache',
    'create_async_session_dependency',
    'ConcurrentTaskRunner',
    'RequestLogger',
    'AsyncContextManager',
    'ParallelBatchProcessor',
    'DependendencyInjectionOptimizer',
    'RateLimitingHelper',
    'FastAPIOptimizationConfig',
]
