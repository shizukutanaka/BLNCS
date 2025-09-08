"""
BLNCS - Bitcoin Lightning Network Control System

Optimized with lazy loading for faster startup and lower memory usage.
"""

from typing import Optional, Dict, Any, Union
from types import ModuleType

__version__ = "1.0.0"
__author__ = "BLNCS Team"
__description__ = "Bitcoin Lightning Network Control System"

# Lazy loading implementation for better performance
class LazyLoader:
    """Lazy module loader to reduce startup time."""
    
    def __init__(self, module_path: str) -> None:
        self.module_path = module_path
        self._module: Optional[ModuleType] = None
    
    def __getattr__(self, name: str) -> Any:
        if self._module is None:
            # Import module on first access
            parts = self.module_path.split('.')
            self._module = __import__(self.module_path, fromlist=[parts[-1]])
        return getattr(self._module, name)
    
    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        # For callable modules
        if self._module is None:
            parts = self.module_path.split('.')
            self._module = __import__(self.module_path, fromlist=[parts[-1]])
        return self._module(*args, **kwargs)


# Core module lazy loaders
_config: Optional[Any] = None
_logger: Optional[Any] = None
_metrics: Optional[Any] = None
_cache_manager: Optional[Any] = None
_lightning_client: Optional[Any] = None
_api_server: Optional[Union[Any, bool]] = None
_database_optimizer: Optional[Any] = None


def get_config() -> Any:
    """Get configuration module (lazy loaded)."""
    global _config
    if _config is None:
        from .core import config
        _config = config
    return _config


def get_logger(name: Optional[str] = None) -> Any:
    """Get logger instance (lazy loaded)."""
    global _logger
    if _logger is None:
        from .core.logger import get_logger as _get_logger
        _logger = _get_logger
    return _logger(name) if name else _logger


def get_metrics() -> Any:
    """Get metrics instance (lazy loaded)."""
    global _metrics
    if _metrics is None:
        from .core.metrics import get_metrics as _get_metrics
        _metrics = _get_metrics()
    return _metrics


def get_cache_manager() -> Any:
    """Get cache manager instance (lazy loaded)."""
    global _cache_manager
    if _cache_manager is None:
        from .core.cache import get_cache_manager as _get_cache_manager
        _cache_manager = _get_cache_manager()
    return _cache_manager


def get_lightning_client(config: Optional[Dict[str, Any]] = None) -> Any:
    """Get Lightning client class (lazy loaded)."""
    global _lightning_client
    if _lightning_client is None:
        from .lightning.client import LightningClient
        _lightning_client = LightningClient
    return _lightning_client(config) if config else _lightning_client


def get_api_server(config: Optional[Dict[str, Any]] = None) -> Any:
    """Get API server class (lazy loaded)."""
    global _api_server
    if _api_server is None:
        try:
            from .api.server import APIServer
            _api_server = APIServer
        except ImportError:
            _api_server = False
    
    if not _api_server:
        raise ImportError("API dependencies not installed. Install with: pip install fastapi uvicorn")
    
    return _api_server(config) if config else _api_server


def get_database_optimizer(config: Optional[Dict[str, Any]] = None) -> Any:
    """Get database optimizer (lazy loaded)."""
    global _database_optimizer
    if _database_optimizer is None:
        from .database.optimizer import get_database_optimizer as _get_db_opt
        _database_optimizer = _get_db_opt
    return _database_optimizer(config) if config else _database_optimizer


# Quick access functions
def load_config(config_file: Optional[str] = None) -> Any:
    """Load configuration from file."""
    config_module = get_config()
    return config_module.load_config(config_file)


def create_app(config: Optional[Dict[str, Any]] = None) -> Any:
    """Create and configure the BLNCS application."""
    if config is None:
        config = load_config()
    
    try:
        from .api.server import create_app as _create_app
        return _create_app(config)
    except ImportError as e:
        raise ImportError(f"API dependencies not installed: {e}")


def run_cli(args: Optional[list] = None) -> Any:
    """Run the BLNCS CLI."""
    from .main import main
    return main()


def health_check(config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Quick health check function."""
    if config is None:
        config = load_config()
    
    try:
        # Check Lightning connection
        client = get_lightning_client(config)
        lightning_ok = client.health_check()
        
        # Check database
        from .database.manager import DatabaseManager
        db = DatabaseManager(config)
        db_ok = db.health_check()
        
        return {
            'status': 'healthy' if (lightning_ok and db_ok) else 'degraded',
            'lightning': lightning_ok,
            'database': db_ok,
            'version': __version__
        }
    except Exception as e:
        return {
            'status': 'unhealthy',
            'error': str(e),
            'version': __version__
        }


# Minimal exports for faster import
__all__ = [
    "__version__",
    "get_config",
    "get_logger",
    "get_metrics",
    "get_cache_manager",
    "get_lightning_client",
    "get_api_server",
    "get_database_optimizer",
    "load_config",
    "create_app",
    "run_cli",
    "health_check"
]


# Optional: Auto-initialize commonly used components on first real use
def __getattr__(name: str) -> Any:
    """Module-level __getattr__ for dynamic attribute access (Python 3.7+)."""
    lazy_attrs = {
        'Config': lambda: get_config().Config,
        'LightningClient': lambda: get_lightning_client(),
        'APIServer': lambda: get_api_server(),
        'logger': lambda: get_logger('blncs'),
        'metrics': lambda: get_metrics(),
        'cache': lambda: get_cache_manager()
    }
    
    if name in lazy_attrs:
        return lazy_attrs[name]()
    
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")