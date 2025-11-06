"""
Fast Startup Optimization for BLNCS
Ultra-lightweight initialization with lazy loading
"""

import time
import os
from typing import Dict, Any, Optional, Callable
import threading


class LazyLoader:
    """Lazy loading for heavy imports"""

    def __init__(self, module_name: str, attr_name: Optional[str] = None):
        self.module_name = module_name
        self.attr_name = attr_name
        self._cached = None
        self._lock = threading.Lock()

    def __call__(self, *args, **kwargs):
        if self._cached is None:
            with self._lock:
                if self._cached is None:
                    try:
                        module = __import__(self.module_name, fromlist=[self.attr_name] if self.attr_name else [])
                        self._cached = getattr(module, self.attr_name) if self.attr_name else module
                    except ImportError:
                        # Return a no-op function for optional dependencies
                        self._cached = lambda *a, **kw: None

        if callable(self._cached):
            return self._cached(*args, **kwargs)
        return self._cached


class FastStartup:
    """Ultra-fast startup manager"""

    def __init__(self):
        self.start_time = time.time()
        self.lazy_modules = {}
        self.initialized = False
        self._setup_lazy_imports()

    def _setup_lazy_imports(self):
        """Setup lazy imports for optional dependencies"""
        self.lazy_modules = {
            'psutil': LazyLoader('psutil'),
            'flask': LazyLoader('flask'),
            'websockets': LazyLoader('websockets'),
            'grpcio': LazyLoader('grpc'),
        }

    def get_module(self, name: str):
        """Get lazily loaded module"""
        return self.lazy_modules.get(name, lambda: None)

    def minimal_init(self) -> Dict[str, Any]:
        """Minimal initialization - fastest possible startup"""
        from ..core.simple_cache import get_simple_cache
        from ..lightning.simple_client import SimpleLightningClient

        # Only essential components
        components = {
            'cache': get_simple_cache(),
            'lightning': SimpleLightningClient(),
            'startup_time': time.time() - self.start_time
        }

        return components

    def fast_init(self) -> Dict[str, Any]:
        """Fast initialization with core features"""
        components = self.minimal_init()

        # Add core features
        from ..core.logger import get_logger
        from ..core.data_validator import get_validator

        components.update({
            'logger': get_logger('BLNCS'),
            'validator': get_validator(),
        })

        return components

    def full_init(self) -> Dict[str, Any]:
        """Full initialization with all features"""
        components = self.fast_init()

        # Add advanced features only if needed
        try:
            from ..core.health_monitor import get_health_monitor
            from ..core.auto_recovery import get_auto_recovery

            components.update({
                'health_monitor': get_health_monitor(),
                'auto_recovery': get_auto_recovery(),
            })
        except ImportError:
            pass

        return components

    def get_startup_stats(self) -> Dict[str, Any]:
        """Get startup performance statistics"""
        return {
            'total_time': time.time() - self.start_time,
            'initialized': self.initialized,
            'available_modules': list(self.lazy_modules.keys()),
            'environment': {
                'python_version': os.sys.version_info[:2],
                'platform': os.name,
                'fast_mode': os.environ.get('BLNCS_FAST_MODE', 'false').lower() == 'true'
            }
        }


class PerformanceOptimizer:
    """Runtime performance optimization"""

    def __init__(self):
        self.optimizations = []
        self._original_gc_thresholds = None
        self._io_buffer_adjusted = False
        self._original_io_buffer_size = None

    def optimize_imports(self):
        """Optimize import performance"""
        # Pre-compile frequently used modules
        try:
            import json
            import time
            import threading
            self.optimizations.append("imports_preloaded")
        except:
            pass

    def optimize_memory(self):
        """Optimize memory usage"""
        import gc
        # Force garbage collection
        collected = gc.collect()

        # Optimize GC thresholds for Lightning workload
        try:
            current_thresholds = gc.get_threshold()
        except Exception:
            current_thresholds = None

        if current_thresholds != (700, 10, 10):
            if current_thresholds and not self._original_gc_thresholds:
                self._original_gc_thresholds = current_thresholds
            gc.set_threshold(700, 10, 10)  # More frequent GC for small objects

        self.optimizations.append(f"memory_gc_{collected}")
        return collected

    def optimize_io(self):
        """Optimize I/O operations"""
        # Set higher buffer sizes for file operations
        import io

        # Set default buffer size (64KB instead of 8KB)
        if hasattr(io, 'DEFAULT_BUFFER_SIZE') and io.DEFAULT_BUFFER_SIZE < 65536:
            if not self._io_buffer_adjusted:
                self._original_io_buffer_size = io.DEFAULT_BUFFER_SIZE
                self._io_buffer_adjusted = True
            io.DEFAULT_BUFFER_SIZE = 65536

        self.optimizations.append("io_buffers")

    def apply_all_optimizations(self) -> Dict[str, Any]:
        """Apply all performance optimizations"""
        start_time = time.time()

        self.optimize_imports()
        collected = self.optimize_memory()
        self.optimize_io()

        return {
            'optimizations_applied': self.optimizations,
            'gc_objects_collected': collected,
            'optimization_time': time.time() - start_time
        }


# Global instances
_fast_startup = None
_optimizer = None


def get_fast_startup() -> FastStartup:
    """Get global fast startup instance"""
    global _fast_startup
    if _fast_startup is None:
        _fast_startup = FastStartup()
    return _fast_startup


def get_optimizer() -> PerformanceOptimizer:
    """Get global performance optimizer"""
    global _optimizer
    if _optimizer is None:
        _optimizer = PerformanceOptimizer()
    return _optimizer


def quick_start(mode: str = 'fast') -> Dict[str, Any]:
    """Quick start BLNCS with specified mode"""
    startup = get_fast_startup()

    if mode == 'minimal':
        return startup.minimal_init()
    elif mode == 'fast':
        return startup.fast_init()
    elif mode == 'full':
        return startup.full_init()
    else:
        raise ValueError(f"Unknown mode: {mode}. Use 'minimal', 'fast', or 'full'")


def optimize_runtime() -> Dict[str, Any]:
    """Apply runtime optimizations"""
    optimizer = get_optimizer()
    return optimizer.apply_all_optimizations()


def ultra_fast_startup() -> Dict[str, Any]:
    """Ultra-fast startup with minimal initialization"""
    start_time = time.time()

    # Apply immediate optimizations
    from .quick_performance_boosts import apply_quick_performance_boosts
    perf_results = apply_quick_performance_boosts()

    # Initialize only essential components
    startup = get_fast_startup()
    components = startup.minimal_init()

    # Add startup time
    components['ultra_startup_time'] = time.time() - start_time
    components['performance_boosts'] = perf_results

    return components


def intelligent_startup(requirements: list = None) -> Dict[str, Any]:
    """Intelligent startup that loads only required components"""
    start_time = time.time()
    requirements = requirements or []

    startup = get_fast_startup()
    components = {}

    # Always load core
    components.update(startup.minimal_init())

    # Load components based on requirements
    if 'logging' in requirements:
        from ..core.logger import get_logger
        components['logger'] = get_logger('BLNCS')

    if 'validation' in requirements:
        from ..core.data_validator import get_validator
        components['validator'] = get_validator()

    if 'health' in requirements:
        try:
            from ..core.health_monitor import get_health_monitor
            components['health_monitor'] = get_health_monitor()
        except ImportError:
            pass

    if 'recovery' in requirements:
        try:
            from ..core.simple_error_recovery import get_error_recovery
            components['error_recovery'] = get_error_recovery()
        except ImportError:
            pass

    components['intelligent_startup_time'] = time.time() - start_time
    components['loaded_requirements'] = requirements

    return components


__all__ = [
    'LazyLoader', 'FastStartup', 'PerformanceOptimizer',
    'get_fast_startup', 'get_optimizer', 'quick_start', 'optimize_runtime',
    'ultra_fast_startup', 'intelligent_startup'
]