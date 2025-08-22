# BLRCS Package Initialization
# Ensures proper module loading and dependency resolution

"""
Bitcoin Lightning Risk Control System (BLRCS)
A comprehensive system for Bitcoin Lightning Network risk management and control.

Initial Release v0.0.1
"""

__version__ = "0.0.1"
__author__ = "BLRCS Development Team"
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

# Advanced modules with fallback handling
try:
    from .auth import AuthManager
except ImportError:
    AuthManager = None

try:
    from .secrets_manager import SecretsManager, secrets_manager
except ImportError:
    SecretsManager = None
    secrets_manager = None

try:
    from .health_check import HealthChecker
except ImportError:
    HealthChecker = None

try:
    from .lightning import LightningNode
except ImportError:
    LightningNode = None

try:
    from .comprehensive_security import ComprehensiveSecurityManager
except ImportError:
    ComprehensiveSecurityManager = None

try:
    from .enhanced_performance import EnhancedPerformanceManager
except ImportError:
    EnhancedPerformanceManager = None

try:
    from .ux_stability_enhancements import ux_optimizer, track_response_time
except ImportError:
    ux_optimizer = None
    track_response_time = None

try:
    from .code_quality_maintainability import analyze_code_quality, generate_improvement_plan
except ImportError:
    analyze_code_quality = None
    generate_improvement_plan = None

# Module availability registry
AVAILABLE_MODULES = {
    'config': get_config is not None,
    'logger': get_logger is not None,
    'auth': AuthManager is not None,
    'secrets': SecretsManager is not None,
    'health_check': HealthChecker is not None,
    'lightning': LightningNode is not None,
    'security': ComprehensiveSecurityManager is not None,
    'performance': EnhancedPerformanceManager is not None,
    'ux_optimizer': ux_optimizer is not None,
    'code_quality': analyze_code_quality is not None
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
    
    # Security & Auth
    "AuthManager", "SecretsManager", "secrets_manager", "ComprehensiveSecurityManager",
    
    # Lightning & Health
    "LightningNode", "HealthChecker",
    
    # Performance & UX
    "EnhancedPerformanceManager", "ux_optimizer", "track_response_time",
    
    # Code Quality
    "analyze_code_quality", "generate_improvement_plan",
    
    # Utilities
    "get_module_status", "check_dependencies", "AVAILABLE_MODULES"
]
