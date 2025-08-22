# BLRCS Compression Module
# High-performance data compression using multiple algorithms
import zlib
import gzip
import bz2
import lzma
import base64
import json
from typing import Any, Optional, Union
from enum import Enum

class CompressionType(Enum):
    """Supported compression algorithms"""
    NONE = "none"
    ZLIB = "zlib"
    GZIP = "gzip"
    BZIP2 = "bzip2"
    LZMA = "lzma"
    AUTO = "auto"

class Compressor:
    """
    Data compression utility with multiple algorithm support.
    Following John Carmack's approach: measure, optimize, repeat.
    """
    
    def __init__(self, default_type: CompressionType = CompressionType.ZLIB):
        self.default_type = default_type
        self.stats = {
            "total_compressed": 0,
            "total_decompressed": 0,
            "bytes_saved": 0,
            "compression_ratio": 0.0
        }
    
    def compress(self, data: Any, compression_type: Optional[CompressionType] = None) -> bytes:
        """
        Compress data using specified algorithm.
        
        Args:
            data: Data to compress (will be JSON encoded if not bytes)
            compression_type: Algorithm to use (defaults to instance default)
            
        Returns:
            Compressed bytes
        """
        compression_type = compression_type or self.default_type
        
        # Convert to bytes if necessary
        if not isinstance(data, bytes):
            data = json.dumps(data).encode('utf-8')
        
        original_size = len(data)
        
        # Select compression algorithm
        if compression_type == CompressionType.NONE:
            compressed = data
        elif compression_type == CompressionType.ZLIB:
            compressed = zlib.compress(data, level=9)  # Maximum compression
        elif compression_type == CompressionType.GZIP:
            compressed = gzip.compress(data, compresslevel=9)  # Maximum compression
        elif compression_type == CompressionType.BZIP2:
            compressed = bz2.compress(data, compresslevel=9)  # Maximum compression
        elif compression_type == CompressionType.LZMA:
            compressed = lzma.compress(data, preset=9)  # Maximum compression
        elif compression_type == CompressionType.AUTO:
            # Try different algorithms and pick the best
            compressed = self._auto_compress(data)
        else:
            compressed = data
        
        # Update statistics
        compressed_size = len(compressed)
        self.stats["total_compressed"] += 1
        self.stats["bytes_saved"] += max(0, original_size - compressed_size)
        self.stats["compression_ratio"] = 1 - (compressed_size / original_size) if original_size > 0 else 0
        
        return compressed
    
    def decompress(self, data: bytes, compression_type: Optional[CompressionType] = None) -> bytes:
        """
        Decompress data using specified algorithm.
        
        Args:
            data: Compressed data
            compression_type: Algorithm used (auto-detect if not specified)
            
        Returns:
            Decompressed bytes
        """
        if compression_type is None:
            compression_type = self._detect_compression(data)
        
        if compression_type == CompressionType.NONE:
            decompressed = data
        elif compression_type == CompressionType.ZLIB:
            decompressed = zlib.decompress(data)
        elif compression_type == CompressionType.GZIP:
            decompressed = gzip.decompress(data)
        elif compression_type == CompressionType.BZIP2:
            decompressed = bz2.decompress(data)
        elif compression_type == CompressionType.LZMA:
            decompressed = lzma.decompress(data)
        else:
            decompressed = data
        
        self.stats["total_decompressed"] += 1
        return decompressed
    
    def _auto_compress(self, data: bytes) -> bytes:
        """
        Automatically select best compression algorithm.
        Tests multiple algorithms and returns the smallest result.
        """
        results = []
        
        # Test each algorithm with performance-optimized settings
        for comp_type in [CompressionType.ZLIB, CompressionType.GZIP, 
                         CompressionType.BZIP2, CompressionType.LZMA]:
            try:
                if comp_type == CompressionType.ZLIB:
                    compressed = zlib.compress(data, level=9)  # Maximum compression
                elif comp_type == CompressionType.GZIP:
                    compressed = gzip.compress(data, compresslevel=9)  # Maximum compression
                elif comp_type == CompressionType.BZIP2:
                    compressed = bz2.compress(data, compresslevel=9)  # Maximum compression
                elif comp_type == CompressionType.LZMA:
                    compressed = lzma.compress(data, preset=9)  # Maximum compression
                else:
                    continue
                
                results.append((len(compressed), compressed, comp_type))
            except:
                continue
        
        # Return smallest result
        if results:
            results.sort(key=lambda x: x[0])
            return results[0][1]
        
        return data
    
    def _detect_compression(self, data: bytes) -> CompressionType:
        """
        Detect compression type from data headers.
        """
        if len(data) < 2:
            return CompressionType.NONE
        
        # Check magic bytes
        if data[:2] == b'\x78\x9c' or data[:2] == b'\x78\x01':
            return CompressionType.ZLIB
        elif data[:2] == b'\x1f\x8b':
            return CompressionType.GZIP
        elif data[:3] == b'BZh':
            return CompressionType.BZIP2
        elif data[:6] == b'\xfd7zXZ\x00':
            return CompressionType.LZMA
        else:
            return CompressionType.NONE
    
    def compress_json(self, obj: Any, compression_type: Optional[CompressionType] = None) -> str:
        """
        Compress JSON object to base64 string.
        Useful for storing compressed data in text fields.
        """
        json_bytes = json.dumps(obj).encode('utf-8')
        compressed = self.compress(json_bytes, compression_type)
        return base64.b64encode(compressed).decode('ascii')
    
    def decompress_json(self, data: str, compression_type: Optional[CompressionType] = None) -> Any:
        """
        Decompress base64 string to JSON object.
        """
        compressed = base64.b64decode(data.encode('ascii'))
        decompressed = self.decompress(compressed, compression_type)
        return json.loads(decompressed.decode('utf-8'))
    
    def get_stats(self) -> dict:
        """Get compression statistics"""
        return self.stats.copy()
    
    def reset_stats(self):
        """Reset statistics"""
        self.stats = {
            "total_compressed": 0,
            "total_decompressed": 0,
            "bytes_saved": 0,
            "compression_ratio": 0.0
        }

class StreamCompressor:
    """
    Streaming compression for large files.
    Processes data in chunks to minimize memory usage.
    """
    
    def __init__(self, chunk_size: int = 65536):
        self.chunk_size = chunk_size
    
    async def compress_file(self, input_path: str, output_path: str, 
                           compression_type: CompressionType = CompressionType.GZIP):
        """Compress file using streaming"""
        import aiofiles
        
        if compression_type == CompressionType.GZIP:
            async with aiofiles.open(input_path, 'rb') as f_in:
                async with aiofiles.open(output_path, 'wb') as f_out:
                    compressor = gzip.GzipFile(fileobj=f_out, mode='wb')
                    while True:
                        chunk = await f_in.read(self.chunk_size)
                        if not chunk:
                            break
                        compressor.write(chunk)
                    compressor.close()
        else:
            # Fallback to regular compression for other types
            async with aiofiles.open(input_path, 'rb') as f:
                data = await f.read()
            
            comp = Compressor()
            compressed = comp.compress(data, compression_type)
            
            async with aiofiles.open(output_path, 'wb') as f:
                await f.write(compressed)
    
    async def decompress_file(self, input_path: str, output_path: str,
                             compression_type: Optional[CompressionType] = None):
        """Decompress file using streaming"""
        import aiofiles
        
        if compression_type == CompressionType.GZIP or compression_type is None:
            async with aiofiles.open(input_path, 'rb') as f_in:
                async with aiofiles.open(output_path, 'wb') as f_out:
                    decompressor = gzip.GzipFile(fileobj=f_in, mode='rb')
                    while True:
                        chunk = decompressor.read(self.chunk_size)
                        if not chunk:
                            break
                        await f_out.write(chunk)
                    decompressor.close()
        else:
            # Fallback to regular decompression
            async with aiofiles.open(input_path, 'rb') as f:
                data = await f.read()
            
            comp = Compressor()
            decompressed = comp.decompress(data, compression_type)
            
            async with aiofiles.open(output_path, 'wb') as f:
                await f.write(decompressed)
