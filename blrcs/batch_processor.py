# BLRCS Batch Processing Module
# High-performance batch processing with intelligent chunking and parallel execution
import asyncio
import time
import math
import statistics
from typing import Any, Dict, List, Optional, Callable, Awaitable, Union, Iterator
from dataclasses import dataclass, field
from enum import Enum
import concurrent.futures
import psutil

class BatchStrategy(Enum):
    """Batch processing strategies"""
    FIXED_SIZE = "fixed_size"
    ADAPTIVE_SIZE = "adaptive_size"
    MEMORY_BASED = "memory_based"
    TIME_BASED = "time_based"

class BatchPriority(Enum):
    """Batch priority levels"""
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3

@dataclass
class BatchResult:
    """Batch processing result"""
    batch_id: str
    total_items: int
    processed_items: int
    failed_items: int
    results: List[Any]
    errors: List[str]
    start_time: float
    end_time: float
    processing_time: float
    throughput: float  # items per second
    
@dataclass
class BatchConfig:
    """Batch processing configuration"""
    strategy: BatchStrategy = BatchStrategy.ADAPTIVE_SIZE
    initial_batch_size: int = 100
    max_batch_size: int = 1000
    min_batch_size: int = 10
    max_memory_mb: int = 100
    target_processing_time: float = 5.0  # seconds
    max_concurrent_batches: int = 4
    retry_failed_items: bool = True
    max_retries: int = 3

class BatchProcessor:
    """
    High-performance batch processor with:
    - Adaptive batch sizing based on performance
    - Memory-aware processing
    - Parallel batch execution
    - Intelligent error handling and retry
    - Performance monitoring and optimization
    """
    
    def __init__(self, config: BatchConfig = None):
        self.config = config or BatchConfig()
        
        # Performance tracking
        self.performance_history = []
        self.current_batch_size = self.config.initial_batch_size
        
        # Statistics
        self.stats = {
            "total_batches": 0,
            "total_items": 0,
            "total_processed": 0,
            "total_failed": 0,
            "avg_throughput": 0.0,
            "avg_batch_time": 0.0,
            "optimal_batch_size": self.config.initial_batch_size
        }
        
        # Concurrency control
        self.semaphore = asyncio.Semaphore(self.config.max_concurrent_batches)
        
        # Thread pool for CPU-bound operations
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=min(psutil.cpu_count(), self.config.max_concurrent_batches)
        )
    
    async def process_async(
        self,
        items: List[Any],
        processor_func: Callable[[Any], Awaitable[Any]],
        batch_id: Optional[str] = None
    ) -> BatchResult:
        """Process items asynchronously with adaptive batching"""
        batch_id = batch_id or f"batch_{int(time.time() * 1000)}"
        start_time = time.time()
        
        all_results = []
        all_errors = []
        total_processed = 0
        
        # Create batches
        batches = list(self._create_batches(items))
        
        # Process batches concurrently
        semaphore_tasks = []
        for i, batch in enumerate(batches):
            task = self._process_single_batch_async(
                batch, processor_func, f"{batch_id}_chunk_{i}"
            )
            semaphore_tasks.append(task)
        
        # Execute with concurrency control
        batch_results = await asyncio.gather(*semaphore_tasks, return_exceptions=True)
        
        # Aggregate results
        for result in batch_results:
            if isinstance(result, Exception):
                all_errors.append(str(result))
            else:
                all_results.extend(result.get("results", []))
                all_errors.extend(result.get("errors", []))
                total_processed += result.get("processed", 0)
        
        end_time = time.time()
        processing_time = end_time - start_time
        throughput = total_processed / processing_time if processing_time > 0 else 0
        
        # Update performance tracking
        self._update_performance(len(items), processing_time, throughput)
        
        # Create result
        result = BatchResult(
            batch_id=batch_id,
            total_items=len(items),
            processed_items=total_processed,
            failed_items=len(all_errors),
            results=all_results,
            errors=all_errors,
            start_time=start_time,
            end_time=end_time,
            processing_time=processing_time,
            throughput=throughput
        )
        
        return result
    
    async def process_sync(
        self,
        items: List[Any],
        processor_func: Callable[[Any], Any],
        batch_id: Optional[str] = None
    ) -> BatchResult:
        """Process items synchronously using thread pool"""
        
        async def async_wrapper(item):
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(self.thread_pool, processor_func, item)
        
        return await self.process_async(items, async_wrapper, batch_id)
    
    async def _process_single_batch_async(
        self,
        batch: List[Any],
        processor_func: Callable[[Any], Awaitable[Any]],
        batch_id: str
    ) -> Dict[str, Any]:
        """Process a single batch with concurrency control"""
        async with self.semaphore:
            start_time = time.time()
            results = []
            errors = []
            processed = 0
            
            # Check memory before processing
            memory_before = psutil.virtual_memory().percent
            
            try:
                # Process items in parallel within the batch
                tasks = [self._process_item_with_retry(item, processor_func) for item in batch]
                
                # Execute with memory monitoring
                for completed_task in asyncio.as_completed(tasks):
                    try:
                        result = await completed_task
                        results.append(result)
                        processed += 1
                        
                        # Check memory usage periodically
                        if processed % 10 == 0:
                            current_memory = psutil.virtual_memory().percent
                            if current_memory > memory_before + 20:  # 20% increase
                                # Yield control to prevent memory issues
                                await asyncio.sleep(0.01)
                    
                    except Exception as e:
                        errors.append(str(e))
            
            except Exception as e:
                errors.append(f"Batch processing error: {str(e)}")
            
            processing_time = time.time() - start_time
            
            return {
                "batch_id": batch_id,
                "results": results,
                "errors": errors,
                "processed": processed,
                "processing_time": processing_time
            }
    
    async def _process_item_with_retry(
        self,
        item: Any,
        processor_func: Callable[[Any], Awaitable[Any]]
    ) -> Any:
        """Process single item with retry logic"""
        last_error = None
        
        for attempt in range(self.config.max_retries + 1):
            try:
                return await processor_func(item)
            except Exception as e:
                last_error = e
                if attempt < self.config.max_retries:
                    # Exponential backoff
                    await asyncio.sleep(0.1 * (2 ** attempt))
                    continue
                else:
                    raise last_error
    
    def _create_batches(self, items: List[Any]) -> Iterator[List[Any]]:
        """Create batches based on current strategy"""
        if self.config.strategy == BatchStrategy.FIXED_SIZE:
            return self._create_fixed_size_batches(items)
        elif self.config.strategy == BatchStrategy.ADAPTIVE_SIZE:
            return self._create_adaptive_size_batches(items)
        elif self.config.strategy == BatchStrategy.MEMORY_BASED:
            return self._create_memory_based_batches(items)
        elif self.config.strategy == BatchStrategy.TIME_BASED:
            return self._create_time_based_batches(items)
        else:
            return self._create_fixed_size_batches(items)
    
    def _create_fixed_size_batches(self, items: List[Any]) -> Iterator[List[Any]]:
        """Create fixed-size batches"""
        batch_size = self.current_batch_size
        for i in range(0, len(items), batch_size):
            yield items[i:i + batch_size]
    
    def _create_adaptive_size_batches(self, items: List[Any]) -> Iterator[List[Any]]:
        """Create adaptive-size batches based on performance history"""
        batch_size = self._calculate_optimal_batch_size()
        for i in range(0, len(items), batch_size):
            yield items[i:i + batch_size]
    
    def _create_memory_based_batches(self, items: List[Any]) -> Iterator[List[Any]]:
        """Create batches based on available memory"""
        available_memory_mb = psutil.virtual_memory().available / (1024 * 1024)
        target_memory_mb = min(available_memory_mb * 0.1, self.config.max_memory_mb)
        
        # Estimate memory per item (simplified)
        estimated_item_size_mb = 0.001  # 1KB per item default
        max_items_for_memory = int(target_memory_mb / estimated_item_size_mb)
        
        batch_size = min(max_items_for_memory, self.config.max_batch_size)
        batch_size = max(batch_size, self.config.min_batch_size)
        
        for i in range(0, len(items), batch_size):
            yield items[i:i + batch_size]
    
    def _create_time_based_batches(self, items: List[Any]) -> Iterator[List[Any]]:
        """Create batches targeting specific processing time"""
        if not self.performance_history:
            # No history, use initial batch size
            batch_size = self.config.initial_batch_size
        else:
            # Calculate batch size for target time
            avg_time_per_item = self._calculate_avg_time_per_item()
            if avg_time_per_item > 0:
                batch_size = int(self.config.target_processing_time / avg_time_per_item)
                batch_size = max(self.config.min_batch_size, 
                               min(batch_size, self.config.max_batch_size))
            else:
                batch_size = self.config.initial_batch_size
        
        for i in range(0, len(items), batch_size):
            yield items[i:i + batch_size]
    
    def _calculate_optimal_batch_size(self) -> int:
        """Calculate optimal batch size based on performance history"""
        if len(self.performance_history) < 3:
            return self.current_batch_size
        
        # Analyze recent performance
        recent_history = self.performance_history[-10:]
        
        # Find batch size with best throughput
        best_throughput = 0
        best_batch_size = self.current_batch_size
        
        for record in recent_history:
            if record["throughput"] > best_throughput:
                best_throughput = record["throughput"]
                best_batch_size = record["batch_size"]
        
        # Adjust towards optimal size
        if best_batch_size > self.current_batch_size:
            self.current_batch_size = min(
                self.current_batch_size + 10,
                self.config.max_batch_size
            )
        elif best_batch_size < self.current_batch_size:
            self.current_batch_size = max(
                self.current_batch_size - 10,
                self.config.min_batch_size
            )
        
        return self.current_batch_size
    
    def _calculate_avg_time_per_item(self) -> float:
        """Calculate average processing time per item"""
        if not self.performance_history:
            return 0.0
        
        recent_history = self.performance_history[-5:]
        time_per_item_values = []
        
        for record in recent_history:
            if record["item_count"] > 0:
                time_per_item = record["processing_time"] / record["item_count"]
                time_per_item_values.append(time_per_item)
        
        return statistics.mean(time_per_item_values) if time_per_item_values else 0.0
    
    def _update_performance(self, item_count: int, processing_time: float, throughput: float):
        """Update performance history and statistics"""
        record = {
            "timestamp": time.time(),
            "item_count": item_count,
            "processing_time": processing_time,
            "throughput": throughput,
            "batch_size": self.current_batch_size
        }
        
        self.performance_history.append(record)
        
        # Keep only recent history
        if len(self.performance_history) > 100:
            self.performance_history = self.performance_history[-50:]
        
        # Update statistics
        self.stats["total_batches"] += 1
        self.stats["total_items"] += item_count
        self.stats["total_processed"] += item_count
        
        # Update averages
        total_batches = self.stats["total_batches"]
        self.stats["avg_throughput"] = (
            (self.stats["avg_throughput"] * (total_batches - 1) + throughput) / total_batches
        )
        self.stats["avg_batch_time"] = (
            (self.stats["avg_batch_time"] * (total_batches - 1) + processing_time) / total_batches
        )
        
        # Update optimal batch size
        if len(self.performance_history) >= 5:
            recent_throughputs = [r["throughput"] for r in self.performance_history[-5:]]
            recent_batch_sizes = [r["batch_size"] for r in self.performance_history[-5:]]
            
            if recent_throughputs:
                max_throughput_idx = recent_throughputs.index(max(recent_throughputs))
                self.stats["optimal_batch_size"] = recent_batch_sizes[max_throughput_idx]
    
    async def process_stream(
        self,
        item_stream: AsyncIterator[Any],
        processor_func: Callable[[Any], Awaitable[Any]],
        buffer_size: int = 1000
    ) -> AsyncIterator[BatchResult]:
        """Process items from async stream in batches"""
        buffer = []
        batch_counter = 0
        
        async for item in item_stream:
            buffer.append(item)
            
            if len(buffer) >= buffer_size:
                batch_id = f"stream_batch_{batch_counter}"
                result = await self.process_async(buffer.copy(), processor_func, batch_id)
                yield result
                
                buffer.clear()
                batch_counter += 1
        
        # Process remaining items
        if buffer:
            batch_id = f"stream_batch_{batch_counter}_final"
            result = await self.process_async(buffer, processor_func, batch_id)
            yield result
    
    def get_stats(self) -> Dict[str, Any]:
        """Get processing statistics"""
        stats = self.stats.copy()
        stats.update({
            "current_batch_size": self.current_batch_size,
            "performance_history_size": len(self.performance_history),
            "config": {
                "strategy": self.config.strategy.value,
                "max_batch_size": self.config.max_batch_size,
                "min_batch_size": self.config.min_batch_size,
                "max_concurrent_batches": self.config.max_concurrent_batches
            }
        })
        return stats
    
    def reset_stats(self):
        """Reset performance statistics"""
        self.performance_history.clear()
        self.current_batch_size = self.config.initial_batch_size
        self.stats = {
            "total_batches": 0,
            "total_items": 0,
            "total_processed": 0,
            "total_failed": 0,
            "avg_throughput": 0.0,
            "avg_batch_time": 0.0,
            "optimal_batch_size": self.config.initial_batch_size
        }
    
    async def shutdown(self):
        """Shutdown the batch processor"""
        self.thread_pool.shutdown(wait=True, timeout=5.0)

# Global batch processor instance
_batch_processor: Optional[BatchProcessor] = None

def get_batch_processor(config: BatchConfig = None) -> BatchProcessor:
    """Get global batch processor instance"""
    global _batch_processor
    
    if _batch_processor is None:
        _batch_processor = BatchProcessor(config)
    
    return _batch_processor

async def shutdown_batch_processor():
    """Shutdown global batch processor"""
    global _batch_processor
    
    if _batch_processor:
        await _batch_processor.shutdown()
        _batch_processor = None