# BLRCS Package Initialization
# National-level security platform with enterprise-grade capabilities

"""
BLRCS - Government-Grade Security & Monitoring Platform

Production Release v1.0.0
"""

__version__ = "1.0.0"
__author__ = "BLRCS Security Team"
__license__ = "MIT"

# Import order matters - base modules first
try:
    from .config import get_config, BLRCSConfig
    from .logger import setup_logging, get_logger
    from .database import Database
    from .cache import Cache
    from .rate_limiter import RateLimiter
    from .i18n import Translator
except ImportError as e:
    # Graceful fallback for missing core modules
    import logging
    logging.warning(f"Core module import failed: {e}")
    
    # Provide minimal fallback implementations
    def get_config():
        """Fallback config function"""
        return type('Config', (), {
            'host': '127.0.0.1',
            'port': 8080,
            'debug': True,
            'log_level': 'INFO'
        })()
    
    def get_logger(name):
        """Fallback logger function"""
        return logging.getLogger(name)

# Core system modules
try:
    from .enterprise_security import EnterpriseSecurityManager
except ImportError:
    EnterpriseSecurityManager = None

try:
    from .security_hardening import SecurityHardener, perform_full_hardening
except ImportError:
    SecurityHardener = None
    perform_full_hardening = None

try:
    from .performance_enhancements import PerformanceOptimizer, CacheManager, ConnectionPool
except ImportError:
    PerformanceOptimizer = None
    CacheManager = None
    ConnectionPool = None

try:
    from .error_handling import ErrorHandler, CircuitBreaker
except ImportError:
    ErrorHandler = None
    CircuitBreaker = None

try:
    from .production_ready import ProductionSystem, DeploymentManager
except ImportError:
    ProductionSystem = None
    DeploymentManager = None

try:
    from .improvements_500 import ImprovementSystem, get_improvement_system
except ImportError:
    ImprovementSystem = None
    get_improvement_system = None

try:
    from .monitoring_system import MonitoringSystem, get_monitoring_system
except ImportError:
    MonitoringSystem = None
    get_monitoring_system = None

try:
    from .api_system import APIServer, get_api_server
except ImportError:
    APIServer = None
    get_api_server = None

try:
    from .test_framework import TestingFramework, get_testing_framework
except ImportError:
    TestingFramework = None
    get_testing_framework = None

try:
    from .i18n_system import I18nSystem, get_i18n
except ImportError:
    I18nSystem = None
    get_i18n = None

# Module availability registry
AVAILABLE_MODULES = {
    'config': get_config is not None,
    'logger': get_logger is not None,
    'enterprise_security': EnterpriseSecurityManager is not None,
    'security_hardening': SecurityHardener is not None,
    'performance': PerformanceOptimizer is not None,
    'error_handling': ErrorHandler is not None,
    'production': ProductionSystem is not None,
    'improvements': ImprovementSystem is not None,
    'monitoring': MonitoringSystem is not None,
    'api': APIServer is not None,
    'testing': TestingFramework is not None,
    'i18n': I18nSystem is not None
}

def get_module_status():
    """Get status of all BLRCS modules"""
    return AVAILABLE_MODULES

def check_dependencies():
    """Check system dependencies and module availability"""
    missing_modules = [name for name, available in AVAILABLE_MODULES.items() if not available]
    
    status = {
        'total_modules': len(AVAILABLE_MODULES),
        'available_modules': len([m for m in AVAILABLE_MODULES.values() if m]),
        'missing_modules': missing_modules,
        'availability_percentage': (len([m for m in AVAILABLE_MODULES.values() if m]) / len(AVAILABLE_MODULES)) * 100
    }
    
    return status

# Export main classes and functions
__all__ = [
    # Core
    "get_config", "BLRCSConfig", "Database", "Cache", "setup_logging", "get_logger", 
    "RateLimiter", "Translator",
    
    # Security
    "EnterpriseSecurityManager", "SecurityHardener", "perform_full_hardening",
    
    # Performance
    "PerformanceOptimizer", "CacheManager", "ConnectionPool",
    
    # Error Handling
    "ErrorHandler", "CircuitBreaker",
    
    # Production
    "ProductionSystem", "DeploymentManager",
    
    # Improvements
    "ImprovementSystem", "get_improvement_system",
    
    # Monitoring
    "MonitoringSystem", "get_monitoring_system",
    
    # API
    "APIServer", "get_api_server",
    
    # Testing
    "TestingFramework", "get_testing_framework",
    
    # Internationalization
    "I18nSystem", "get_i18n",
    
    # Utilities
    "get_module_status", "check_dependencies", "AVAILABLE_MODULES"
]
