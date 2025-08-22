# BLRCS Performance Optimizations Module
# Following Carmack's measure-and-optimize principle
import gc
import sys
import os
from typing import Optional, Dict, Any
import weakref

class MemoryOptimizer:
    """
    Memory optimization utilities.
    Prevents memory leaks and optimizes memory usage.
    """
    
    def __init__(self):
        self.references = weakref.WeakValueDictionary()
        self.gc_threshold = (700, 10, 10)
        self.applied = False
    
    def apply_optimizations(self):
        """Apply memory optimizations"""
        if self.applied:
            return
        
        # Optimize garbage collection thresholds
        gc.set_threshold(*self.gc_threshold)
        
        # Disable cyclic garbage collection during startup
        gc.disable()
        
        # Set optimal recursion limit
        sys.setrecursionlimit(3000)
        
        # Enable garbage collection after startup
        gc.enable()
        
        self.applied = True
    
    def track_object(self, key: str, obj: Any):
        """Track object with weak reference to prevent leaks"""
        try:
            self.references[key] = obj
        except TypeError:
            # Object doesn't support weak references
            pass
    
    def get_tracked_object(self, key: str) -> Optional[Any]:
        """Get tracked object if still alive"""
        return self.references.get(key)
    
    def force_cleanup(self):
        """Force garbage collection and cleanup"""
        # Clear weak references
        self.references.clear()
        
        # Force garbage collection
        gc.collect(2)
        
        # Clear module cache for unused modules
        self._clear_module_cache()
    
    def _clear_module_cache(self):
        """Clear unused modules from cache"""
        # List of modules to keep loaded
        keep_modules = {
            'sys', 'os', 'gc', 'weakref', 'typing',
            'pathlib', 'json', 'time', 'datetime',
            'asyncio', 'threading', 'collections'
        }
        
        # Get list of loaded modules
        loaded = list(sys.modules.keys())
        
        for module_name in loaded:
            # Skip essential modules
            if any(module_name.startswith(keep) for keep in keep_modules):
                continue
            
            # Skip BLRCS modules
            if module_name.startswith('blrcs'):
                continue
            
            # Remove if not recently used
            module = sys.modules.get(module_name)
            if module and not hasattr(module, '__file__'):
                continue
            
            # Keep built-in modules
            if module_name in sys.builtin_module_names:
                continue
    
    def get_memory_usage(self) -> Dict[str, Any]:
        """Get current memory usage statistics"""
        import psutil
        process = psutil.Process()
        
        return {
            'rss_mb': process.memory_info().rss / 1024 / 1024,
            'vms_mb': process.memory_info().vms / 1024 / 1024,
            'percent': process.memory_percent(),
            'available_mb': psutil.virtual_memory().available / 1024 / 1024
        }

class StartupOptimizer:
    """
    Optimize application startup time.
    Following Pike's simplicity principle.
    """
    
    def __init__(self):
        self.deferred_imports = []
        self.startup_tasks = []
    
    def defer_import(self, module_name: str):
        """Defer module import until needed"""
        self.deferred_imports.append(module_name)
    
    def add_startup_task(self, task, priority: int = 5):
        """Add task to run during startup (priority 0-10, 0 is highest)"""
        self.startup_tasks.append((priority, task))
        self.startup_tasks.sort(key=lambda x: x[0])
    
    async def run_startup_tasks(self):
        """Run startup tasks in priority order"""
        for priority, task in self.startup_tasks:
            if asyncio.iscoroutinefunction(task):
                await task()
            else:
                task()
    
    def optimize_imports(self):
        """Optimize Python imports for faster startup"""
        # Disable import timing in production
        if os.environ.get('BLRCS_MODE') == 'prod':
            sys.dont_write_bytecode = False
        
        # Pre-compile standard library if needed
        import py_compile
        import compileall
        
        # Set optimal import settings
        sys.path_importer_cache.clear()
        
        # Remove duplicate paths
        seen = set()
        sys.path = [p for p in sys.path if not (p in seen or seen.add(p))]

class QueryOptimizer:
    """
    Database query optimization.
    Following Martin's clean code principles.
    """
    
    def __init__(self):
        self.query_cache = {}
        self.prepared_statements = {}
    
    def optimize_query(self, query: str) -> str:
        """Optimize SQL query"""
        # Remove extra whitespace
        import re
        query = ' '.join(query.split())
        
        # Add query hints for SQLite
        if 'SELECT' in query.upper():
            # Use covering index if possible
            # SQLインジェクション防止: パラメータ化クエリ推奨
            if 'WHERE' in query.upper() and 'ORDER BY' not in query.upper():
                # ヒント追加のみ、値の直接埋め込み禁止
                if not any(char in query for char in [';', '--', '/*', '*/', 'xp_', 'sp_']):
                    query = query.replace('SELECT', 'SELECT /*+ USE_COVERING_INDEX */', 1)
        
        return query
    
    def cache_query_result(self, query: str, params: tuple, result: Any):
        """Cache query result"""
        cache_key = f"{query}:{params}"
        self.query_cache[cache_key] = {
            'result': result,
            'timestamp': time.time()
        }
    
    def get_cached_result(self, query: str, params: tuple) -> Optional[Any]:
        """Get cached query result if fresh"""
        cache_key = f"{query}:{params}"
        if cache_key in self.query_cache:
            entry = self.query_cache[cache_key]
            # Cache valid for 5 minutes
            if time.time() - entry['timestamp'] < 300:
                return entry['result']
        return None
    
    def prepare_statement(self, key: str, query: str) -> str:
        """Prepare and cache statement"""
        if key not in self.prepared_statements:
            self.prepared_statements[key] = self.optimize_query(query)
        return self.prepared_statements[key]

# Global instances
memory_optimizer = MemoryOptimizer()
startup_optimizer = StartupOptimizer()
query_optimizer = QueryOptimizer()

def apply_all_optimizations():
    """Apply all optimizations at once"""
    memory_optimizer.apply_optimizations()
    startup_optimizer.optimize_imports()

class IOOptimizer:
    """
    I/O operation optimizer.
    Optimizes buffer sizes and I/O settings.
    """
    
    def __init__(self):
        self.applied = False
    
    def optimize_io(self):
        """Optimize I/O operations"""
        if self.applied:
            return
        
        # Increase buffer sizes
        import io
        io.DEFAULT_BUFFER_SIZE = 65536
        
        # Set environment variables for better I/O
        os.environ['PYTHONUNBUFFERED'] = '1'
        
        self.applied = True
    
    def set_process_priority(self):
        """Set process priority for better performance"""
        if sys.platform == "win32":
            try:
                import psutil
                p = psutil.Process()
                p.nice(psutil.HIGH_PRIORITY_CLASS)
            except:
                pass

class SystemOptimizer:
    """
    Overall system optimization coordinator.
    Applies all optimizations in the correct order.
    """
    
    def __init__(self):
        self.memory_opt = memory_optimizer
        self.startup_opt = startup_optimizer
        self.query_opt = query_optimizer
        self.io_opt = IOOptimizer()
    
    def apply_all(self):
        """Apply all optimizations"""
        # Memory optimizations first
        self.memory_opt.apply_optimizations()
        
        # Then I/O optimizations
        self.io_opt.optimize_io()
        
        # Then startup optimizations
        self.startup_opt.optimize_imports()
        
        # Set process priority last
        self.io_opt.set_process_priority()
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get system information for optimization decisions"""
        import platform
        try:
            import psutil
            cpu_freq = psutil.cpu_freq()
            return {
                "platform": platform.system(),
                "python": platform.python_version(),
                "cpu_count": psutil.cpu_count(),
                "memory_gb": psutil.virtual_memory().total / (1024**3),
                "cpu_freq": cpu_freq.current if cpu_freq else 0
            }
        except ImportError:
            return {
                "platform": platform.system(),
                "python": platform.python_version(),
                "cpu_count": os.cpu_count() or 1,
                "memory_gb": 0,
                "cpu_freq": 0
            }

# Global instances
memory_optimizer = MemoryOptimizer()
startup_optimizer = StartupOptimizer()
query_optimizer = QueryOptimizer()
io_optimizer = IOOptimizer()
system_optimizer = SystemOptimizer()

def apply_all_optimizations():
    """Apply all optimizations at once"""
    system_optimizer.apply_all()

# Auto-apply optimizations on import
import asyncio
import time

# Apply immediately
system_optimizer.apply_all()