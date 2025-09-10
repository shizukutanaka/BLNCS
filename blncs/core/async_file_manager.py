"""
Asynchronous file I/O manager for BLNCS
High-performance async file operations with caching and optimization.
"""

import asyncio
import aiofiles
import aiofiles.os
import json
import time
from typing import Dict, List, Any, Optional, Union, AsyncIterator, BinaryIO, TextIO
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from pathlib import Path
import hashlib
import logging
from contextlib import asynccontextmanager

from .logger import get_logger
from .error_handler import get_error_handler, ErrorContext
from .exceptions import FileError, ValidationError


@dataclass
class FileConfig:
    """File manager configuration"""
    cache_size: int = 1000  # Max cached files
    cache_ttl: int = 300  # 5 minutes
    max_file_size: int = 100 * 1024 * 1024  # 100MB
    backup_enabled: bool = True
    backup_retention_days: int = 7
    compression_enabled: bool = True
    encryption_enabled: bool = False
    concurrent_operations: int = 10


@dataclass
class FileMetadata:
    """File metadata information"""
    path: str
    size: int
    modified_time: float
    checksum: str
    mime_type: str
    encoding: str = "utf-8"
    compressed: bool = False
    encrypted: bool = False


@dataclass
class FileOperationResult:
    """Result of file operation"""
    success: bool
    path: str
    bytes_processed: int = 0
    execution_time: float = 0.0
    cached: bool = False
    error: Optional[str] = None


class AsyncFileCache:
    """High-performance file content cache"""
    
    def __init__(self, config: FileConfig):
        self.config = config
        self.logger = get_logger(__name__)
        
        # Cache storage
        self._content_cache: Dict[str, tuple] = {}  # path -> (content, timestamp, metadata)
        self._metadata_cache: Dict[str, tuple] = {}  # path -> (metadata, timestamp)
        
        # Access tracking for LRU eviction
        self._access_times: Dict[str, float] = {}
        
        # Statistics
        self.cache_hits = 0
        self.cache_misses = 0
        self.cache_evictions = 0
        
        # Lock for thread safety
        self._lock = asyncio.Lock()
    
    def _calculate_checksum(self, content: Union[str, bytes]) -> str:
        """Calculate content checksum"""
        if isinstance(content, str):
            content = content.encode('utf-8')
        return hashlib.sha256(content).hexdigest()[:16]
    
    def _is_expired(self, timestamp: float) -> bool:
        """Check if cache entry is expired"""
        return time.time() - timestamp > self.config.cache_ttl
    
    async def _evict_expired(self):
        """Remove expired entries from cache"""
        current_time = time.time()
        
        # Remove expired content
        expired_keys = [
            key for key, (_, timestamp, _) in self._content_cache.items()
            if current_time - timestamp > self.config.cache_ttl
        ]
        
        for key in expired_keys:
            del self._content_cache[key]
            if key in self._access_times:
                del self._access_times[key]
        
        # Remove expired metadata
        expired_meta_keys = [
            key for key, (_, timestamp) in self._metadata_cache.items()
            if current_time - timestamp > self.config.cache_ttl
        ]
        
        for key in expired_meta_keys:
            del self._metadata_cache[key]
    
    async def _evict_lru(self):
        """Evict least recently used entries"""
        if len(self._content_cache) <= self.config.cache_size:
            return
        
        # Sort by access time and evict oldest
        sorted_entries = sorted(
            self._access_times.items(),
            key=lambda x: x[1]
        )
        
        to_evict = len(self._content_cache) - self.config.cache_size
        for i in range(to_evict):
            key = sorted_entries[i][0]
            if key in self._content_cache:
                del self._content_cache[key]
                del self._access_times[key]
                self.cache_evictions += 1
    
    async def get_content(self, path: str) -> Optional[tuple]:
        """Get cached file content"""
        async with self._lock:
            if path in self._content_cache:
                content, timestamp, metadata = self._content_cache[path]
                if not self._is_expired(timestamp):
                    self._access_times[path] = time.time()
                    self.cache_hits += 1
                    return content, metadata
                else:
                    # Expired, remove from cache
                    del self._content_cache[path]
                    if path in self._access_times:
                        del self._access_times[path]
            
            self.cache_misses += 1
            return None
    
    async def set_content(self, path: str, content: Union[str, bytes], metadata: FileMetadata):
        """Cache file content"""
        async with self._lock:
            await self._evict_expired()
            await self._evict_lru()
            
            timestamp = time.time()
            self._content_cache[path] = (content, timestamp, metadata)
            self._access_times[path] = timestamp
    
    async def get_metadata(self, path: str) -> Optional[FileMetadata]:
        """Get cached file metadata"""
        async with self._lock:
            if path in self._metadata_cache:
                metadata, timestamp = self._metadata_cache[path]
                if not self._is_expired(timestamp):
                    return metadata
                else:
                    del self._metadata_cache[path]
            
            return None
    
    async def set_metadata(self, path: str, metadata: FileMetadata):
        """Cache file metadata"""
        async with self._lock:
            self._metadata_cache[path] = (metadata, time.time())
    
    async def invalidate(self, path: str):
        """Invalidate cache entry"""
        async with self._lock:
            if path in self._content_cache:
                del self._content_cache[path]
            if path in self._metadata_cache:
                del self._metadata_cache[path]
            if path in self._access_times:
                del self._access_times[path]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_requests = self.cache_hits + self.cache_misses
        hit_rate = self.cache_hits / total_requests if total_requests > 0 else 0
        
        return {
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses,
            'cache_evictions': self.cache_evictions,
            'hit_rate': hit_rate,
            'cached_files': len(self._content_cache),
            'cached_metadata': len(self._metadata_cache)
        }


class AsyncFileManager:
    """High-performance async file manager"""
    
    def __init__(self, config: Optional[FileConfig] = None):
        self.config = config or FileConfig()
        self.logger = get_logger(__name__)
        self.error_handler = get_error_handler()
        
        # File cache
        self.cache = AsyncFileCache(self.config)
        
        # Concurrency control
        self.semaphore = asyncio.Semaphore(self.config.concurrent_operations)
        
        # Statistics
        self.total_operations = 0
        self.total_bytes_processed = 0
        self.total_execution_time = 0.0
    
    async def _get_file_metadata(self, path: Path) -> FileMetadata:
        """Get comprehensive file metadata"""
        try:
            # Check cache first
            cached_metadata = await self.cache.get_metadata(str(path))
            if cached_metadata:
                return cached_metadata
            
            # Get file stats
            stat = await aiofiles.os.stat(path)
            
            # Calculate checksum for small files
            checksum = ""
            if stat.st_size < 1024 * 1024:  # 1MB
                async with aiofiles.open(path, 'rb') as f:
                    content = await f.read()
                    checksum = hashlib.sha256(content).hexdigest()[:16]
            
            # Detect MIME type (simplified)
            mime_type = self._detect_mime_type(path)
            
            metadata = FileMetadata(
                path=str(path),
                size=stat.st_size,
                modified_time=stat.st_mtime,
                checksum=checksum,
                mime_type=mime_type
            )
            
            # Cache metadata
            await self.cache.set_metadata(str(path), metadata)
            
            return metadata
            
        except Exception as e:
            raise FileError(f"Failed to get file metadata for {path}: {e}")
    
    def _detect_mime_type(self, path: Path) -> str:
        """Simple MIME type detection"""
        suffix_map = {
            '.json': 'application/json',
            '.txt': 'text/plain',
            '.log': 'text/plain',
            '.csv': 'text/csv',
            '.py': 'text/x-python',
            '.js': 'text/javascript',
            '.html': 'text/html',
            '.xml': 'application/xml',
            '.zip': 'application/zip',
            '.gz': 'application/gzip',
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.pdf': 'application/pdf'
        }
        
        return suffix_map.get(path.suffix.lower(), 'application/octet-stream')
    
    async def read_text(
        self,
        path: Union[str, Path],
        encoding: str = 'utf-8',
        use_cache: bool = True
    ) -> FileOperationResult:
        """Read text file asynchronously"""
        async with self.semaphore:
            start_time = time.time()
            path = Path(path)
            
            try:
                with self.error_handler.error_context(
                    component="file_manager",
                    operation="read_text",
                    metadata={"path": str(path)}
                ):
                    # Check cache
                    if use_cache:
                        cached_data = await self.cache.get_content(str(path))
                        if cached_data:
                            content, metadata = cached_data
                            return FileOperationResult(
                                success=True,
                                path=str(path),
                                bytes_processed=len(content),
                                execution_time=time.time() - start_time,
                                cached=True
                            )
                    
                    # Validate file
                    if not path.exists():
                        raise FileError(f"File not found: {path}")
                    
                    metadata = await self._get_file_metadata(path)
                    
                    if metadata.size > self.config.max_file_size:
                        raise FileError(f"File too large: {metadata.size} bytes")
                    
                    # Read file
                    async with aiofiles.open(path, 'r', encoding=encoding) as f:
                        content = await f.read()
                    
                    # Cache content
                    if use_cache:
                        await self.cache.set_content(str(path), content, metadata)
                    
                    # Update statistics
                    self.total_operations += 1
                    self.total_bytes_processed += len(content)
                    execution_time = time.time() - start_time
                    self.total_execution_time += execution_time
                    
                    return FileOperationResult(
                        success=True,
                        path=str(path),
                        bytes_processed=len(content),
                        execution_time=execution_time
                    )
                    
            except Exception as e:
                return FileOperationResult(
                    success=False,
                    path=str(path),
                    execution_time=time.time() - start_time,
                    error=str(e)
                )
    
    async def write_text(
        self,
        path: Union[str, Path],
        content: str,
        encoding: str = 'utf-8',
        create_backup: bool = True
    ) -> FileOperationResult:
        """Write text file asynchronously"""
        async with self.semaphore:
            start_time = time.time()
            path = Path(path)
            
            try:
                with self.error_handler.error_context(
                    component="file_manager",
                    operation="write_text",
                    metadata={"path": str(path), "size": len(content)}
                ):
                    # Create directory if needed
                    path.parent.mkdir(parents=True, exist_ok=True)
                    
                    # Create backup if file exists
                    if create_backup and path.exists() and self.config.backup_enabled:
                        await self._create_backup(path)
                    
                    # Write file atomically
                    temp_path = path.with_suffix(path.suffix + '.tmp')
                    
                    async with aiofiles.open(temp_path, 'w', encoding=encoding) as f:
                        await f.write(content)
                        await f.fsync()  # Ensure data is written to disk
                    
                    # Atomic move
                    await aiofiles.os.rename(temp_path, path)
                    
                    # Invalidate cache
                    await self.cache.invalidate(str(path))
                    
                    # Update statistics
                    self.total_operations += 1
                    self.total_bytes_processed += len(content)
                    execution_time = time.time() - start_time
                    self.total_execution_time += execution_time
                    
                    return FileOperationResult(
                        success=True,
                        path=str(path),
                        bytes_processed=len(content),
                        execution_time=execution_time
                    )
                    
            except Exception as e:
                # Clean up temp file
                temp_path = path.with_suffix(path.suffix + '.tmp')
                if temp_path.exists():
                    try:
                        await aiofiles.os.remove(temp_path)
                    except:
                        pass
                
                return FileOperationResult(
                    success=False,
                    path=str(path),
                    execution_time=time.time() - start_time,
                    error=str(e)
                )
    
    async def read_json(
        self,
        path: Union[str, Path],
        use_cache: bool = True
    ) -> tuple[FileOperationResult, Optional[Any]]:
        """Read JSON file asynchronously"""
        result = await self.read_text(path, use_cache=use_cache)
        
        if not result.success:
            return result, None
        
        try:
            # Get content from cache or read result
            if result.cached:
                cached_data = await self.cache.get_content(str(path))
                content = cached_data[0] if cached_data else ""
            else:
                # Re-read the content (this is a simplified approach)
                async with aiofiles.open(path, 'r') as f:
                    content = await f.read()
            
            data = json.loads(content) if content else None
            return result, data
            
        except json.JSONDecodeError as e:
            result.success = False
            result.error = f"Invalid JSON: {e}"
            return result, None
    
    async def write_json(
        self,
        path: Union[str, Path],
        data: Any,
        indent: Optional[int] = 2,
        create_backup: bool = True
    ) -> FileOperationResult:
        """Write JSON file asynchronously"""
        try:
            content = json.dumps(data, indent=indent, ensure_ascii=False)
            return await self.write_text(path, content, create_backup=create_backup)
        except (TypeError, ValueError) as e:
            return FileOperationResult(
                success=False,
                path=str(path),
                error=f"JSON serialization error: {e}"
            )
    
    async def copy_file(
        self,
        source: Union[str, Path],
        destination: Union[str, Path]
    ) -> FileOperationResult:
        """Copy file asynchronously"""
        async with self.semaphore:
            start_time = time.time()
            source = Path(source)
            destination = Path(destination)
            
            try:
                with self.error_handler.error_context(
                    component="file_manager",
                    operation="copy_file",
                    metadata={"source": str(source), "destination": str(destination)}
                ):
                    if not source.exists():
                        raise FileError(f"Source file not found: {source}")
                    
                    # Create destination directory
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    
                    # Get source metadata
                    source_metadata = await self._get_file_metadata(source)
                    
                    # Copy file in chunks for large files
                    chunk_size = 64 * 1024  # 64KB chunks
                    bytes_copied = 0
                    
                    async with aiofiles.open(source, 'rb') as src:
                        async with aiofiles.open(destination, 'wb') as dst:
                            while True:
                                chunk = await src.read(chunk_size)
                                if not chunk:
                                    break
                                await dst.write(chunk)
                                bytes_copied += len(chunk)
                    
                    # Preserve metadata
                    await aiofiles.os.utime(destination, (source_metadata.modified_time, source_metadata.modified_time))
                    
                    # Update statistics
                    self.total_operations += 1
                    self.total_bytes_processed += bytes_copied
                    execution_time = time.time() - start_time
                    self.total_execution_time += execution_time
                    
                    return FileOperationResult(
                        success=True,
                        path=str(destination),
                        bytes_processed=bytes_copied,
                        execution_time=execution_time
                    )
                    
            except Exception as e:
                return FileOperationResult(
                    success=False,
                    path=str(destination),
                    execution_time=time.time() - start_time,
                    error=str(e)
                )
    
    async def delete_file(self, path: Union[str, Path]) -> FileOperationResult:
        """Delete file asynchronously"""
        start_time = time.time()
        path = Path(path)
        
        try:
            with self.error_handler.error_context(
                component="file_manager",
                operation="delete_file",
                metadata={"path": str(path)}
            ):
                if not path.exists():
                    return FileOperationResult(
                        success=True,  # File doesn't exist, consider it success
                        path=str(path),
                        execution_time=time.time() - start_time
                    )
                
                # Get file size before deletion
                file_size = path.stat().st_size
                
                # Delete file
                await aiofiles.os.remove(path)
                
                # Invalidate cache
                await self.cache.invalidate(str(path))
                
                # Update statistics
                self.total_operations += 1
                execution_time = time.time() - start_time
                self.total_execution_time += execution_time
                
                return FileOperationResult(
                    success=True,
                    path=str(path),
                    bytes_processed=file_size,
                    execution_time=execution_time
                )
                
        except Exception as e:
            return FileOperationResult(
                success=False,
                path=str(path),
                execution_time=time.time() - start_time,
                error=str(e)
            )
    
    async def list_files(
        self,
        directory: Union[str, Path],
        pattern: str = "*",
        recursive: bool = False
    ) -> List[FileMetadata]:
        """List files in directory asynchronously"""
        try:
            directory = Path(directory)
            
            if not directory.exists() or not directory.is_dir():
                raise FileError(f"Directory not found or not a directory: {directory}")
            
            files = []
            
            if recursive:
                pattern_path = directory.rglob(pattern)
            else:
                pattern_path = directory.glob(pattern)
            
            async for path in self._async_glob(pattern_path):
                if path.is_file():
                    try:
                        metadata = await self._get_file_metadata(path)
                        files.append(metadata)
                    except Exception as e:
                        self.logger.warning(f"Failed to get metadata for {path}: {e}")
                        continue
            
            return files
            
        except Exception as e:
            raise FileError(f"Failed to list files in {directory}: {e}")
    
    async def _async_glob(self, glob_iterator):
        """Convert sync glob iterator to async"""
        for path in glob_iterator:
            yield path
            # Allow other tasks to run
            await asyncio.sleep(0)
    
    async def _create_backup(self, path: Path):
        """Create backup of existing file"""
        if not path.exists():
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = path.parent / f".backup_{path.name}_{timestamp}"
        
        try:
            # Copy file to backup location
            await self.copy_file(path, backup_path)
            
            # Clean up old backups
            await self._cleanup_old_backups(path)
            
        except Exception as e:
            self.logger.warning(f"Failed to create backup for {path}: {e}")
    
    async def _cleanup_old_backups(self, original_path: Path):
        """Remove old backup files"""
        if not self.config.backup_enabled:
            return
        
        backup_pattern = f".backup_{original_path.name}_*"
        backups = list(original_path.parent.glob(backup_pattern))
        
        # Sort by modification time (newest first)
        backups.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        
        # Keep only recent backups
        cutoff_time = time.time() - (self.config.backup_retention_days * 24 * 3600)
        
        for backup_path in backups:
            if backup_path.stat().st_mtime < cutoff_time:
                try:
                    await aiofiles.os.remove(backup_path)
                except Exception as e:
                    self.logger.warning(f"Failed to remove old backup {backup_path}: {e}")
    
    async def stream_large_file(
        self,
        path: Union[str, Path],
        chunk_size: int = 8192
    ) -> AsyncIterator[bytes]:
        """Stream large file in chunks"""
        async with self.semaphore:
            path = Path(path)
            
            try:
                async with aiofiles.open(path, 'rb') as f:
                    while True:
                        chunk = await f.read(chunk_size)
                        if not chunk:
                            break
                        yield chunk
                        
            except Exception as e:
                raise FileError(f"Failed to stream file {path}: {e}")
    
    async def batch_operations(
        self,
        operations: List[tuple]  # [(operation, *args), ...]
    ) -> List[FileOperationResult]:
        """Execute multiple file operations in parallel"""
        tasks = []
        
        for operation_tuple in operations:
            operation = operation_tuple[0]
            args = operation_tuple[1:]
            
            if operation == 'read_text':
                task = self.read_text(*args)
            elif operation == 'write_text':
                task = self.write_text(*args)
            elif operation == 'copy_file':
                task = self.copy_file(*args)
            elif operation == 'delete_file':
                task = self.delete_file(*args)
            else:
                # Create a failed result for unknown operations
                result = FileOperationResult(
                    success=False,
                    path="unknown",
                    error=f"Unknown operation: {operation}"
                )
                tasks.append(asyncio.create_task(asyncio.sleep(0, result)))
                continue
            
            tasks.append(asyncio.create_task(task))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Convert exceptions to failed results
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                final_results.append(FileOperationResult(
                    success=False,
                    path="unknown",
                    error=str(result)
                ))
            else:
                final_results.append(result)
        
        return final_results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get file manager statistics"""
        avg_execution_time = (
            self.total_execution_time / self.total_operations
            if self.total_operations > 0 else 0
        )
        
        return {
            'total_operations': self.total_operations,
            'total_bytes_processed': self.total_bytes_processed,
            'total_execution_time': self.total_execution_time,
            'average_execution_time': avg_execution_time,
            'cache_stats': self.cache.get_stats()
        }


# Global file manager instance
_global_file_manager: Optional[AsyncFileManager] = None


def get_async_file_manager() -> AsyncFileManager:
    """Get global async file manager instance"""
    global _global_file_manager
    if _global_file_manager is None:
        _global_file_manager = AsyncFileManager()
    return _global_file_manager


async def read_text_file(path: Union[str, Path], **kwargs) -> tuple[FileOperationResult, str]:
    """Convenience function to read text file"""
    manager = get_async_file_manager()
    result = await manager.read_text(path, **kwargs)
    
    if result.success and result.cached:
        cached_data = await manager.cache.get_content(str(path))
        content = cached_data[0] if cached_data else ""
    else:
        # Re-read if not cached (simplified approach)
        async with aiofiles.open(path, 'r') as f:
            content = await f.read()
    
    return result, content


async def write_text_file(path: Union[str, Path], content: str, **kwargs) -> FileOperationResult:
    """Convenience function to write text file"""
    manager = get_async_file_manager()
    return await manager.write_text(path, content, **kwargs)


__all__ = [
    'AsyncFileManager',
    'AsyncFileCache',
    'FileConfig',
    'FileMetadata',
    'FileOperationResult',
    'get_async_file_manager',
    'read_text_file',
    'write_text_file'
]