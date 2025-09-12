"""
Optional Imports Manager for BLNCS
Handles optional dependencies gracefully to keep the system lightweight.
"""

import sys
import logging
from typing import Optional, Any

logger = logging.getLogger(__name__)

class OptionalImport:
    """Context manager for optional imports"""
    
    def __init__(self, module_name: str, feature_name: str = None):
        self.module_name = module_name
        self.feature_name = feature_name or module_name
        self.module = None
        self.available = False
    
    def __enter__(self):
        try:
            self.module = __import__(self.module_name)
            # Handle nested imports like 'grpcio.grpc'
            for part in self.module_name.split('.')[1:]:
                self.module = getattr(self.module, part)
            self.available = True
            return self.module
        except ImportError as e:
            logger.debug(f"Optional dependency {self.module_name} not available: {e}")
            self.available = False
            return None
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
    
    def is_available(self) -> bool:
        """Check if the module is available without importing"""
        try:
            __import__(self.module_name)
            return True
        except ImportError:
            return False

# Common optional dependencies
class OptionalDependencies:
    """Centralized optional dependency management"""
    
    @staticmethod
    def get_grpc():
        """Get gRPC module if available"""
        with OptionalImport('grpc', 'gRPC') as grpc_module:
            return grpc_module
    
    @staticmethod
    def get_prometheus():
        """Get Prometheus client if available"""
        with OptionalImport('prometheus_client', 'Prometheus metrics') as prom_module:
            return prom_module
    
    @staticmethod
    def get_cryptography():
        """Get cryptography module if available"""
        with OptionalImport('cryptography', 'Enhanced cryptography') as crypto_module:
            return crypto_module
    
    @staticmethod
    def get_qrcode():
        """Get QR code module if available"""
        with OptionalImport('qrcode', 'QR code generation') as qr_module:
            return qr_module
    
    @staticmethod
    def get_yaml():
        """Get YAML module if available"""
        with OptionalImport('yaml', 'YAML configuration') as yaml_module:
            return yaml_module
    
    @staticmethod
    def get_validators():
        """Get validators module if available"""
        with OptionalImport('validators', 'Data validation') as validators_module:
            return validators_module
    
    @staticmethod
    def get_watchdog():
        """Get watchdog module if available"""
        with OptionalImport('watchdog', 'File watching') as watchdog_module:
            return watchdog_module

def require_module(module_name: str, feature_name: str = None) -> Any:
    """
    Require a module and raise helpful error if not available
    
    Args:
        module_name: Name of the module to import
        feature_name: Human-readable feature name
    
    Returns:
        The imported module
        
    Raises:
        ImportError: If the module is not available
    """
    feature_name = feature_name or module_name
    
    try:
        return __import__(module_name)
    except ImportError as e:
        raise ImportError(
            f"The {feature_name} feature requires the '{module_name}' package. "
            f"Install it with: pip install {module_name}"
        ) from e

def optional_feature(feature_check_func):
    """
    Decorator to make a function/method optional based on dependency availability
    
    Args:
        feature_check_func: Function that returns True if the feature is available
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            if feature_check_func():
                return func(*args, **kwargs)
            else:
                logger.warning(f"Feature {func.__name__} is not available due to missing dependencies")
                return None
        
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper
    
    return decorator

# Pre-check common dependencies
GRPC_AVAILABLE = OptionalImport('grpc').is_available()
PROMETHEUS_AVAILABLE = OptionalImport('prometheus_client').is_available()
CRYPTOGRAPHY_AVAILABLE = OptionalImport('cryptography').is_available()
QRCODE_AVAILABLE = OptionalImport('qrcode').is_available()
YAML_AVAILABLE = OptionalImport('yaml').is_available()
VALIDATORS_AVAILABLE = OptionalImport('validators').is_available()

# Convenience functions
def has_grpc() -> bool:
    """Check if gRPC is available"""
    return GRPC_AVAILABLE

def has_prometheus() -> bool:
    """Check if Prometheus client is available"""
    return PROMETHEUS_AVAILABLE

def has_cryptography() -> bool:
    """Check if cryptography is available"""
    return CRYPTOGRAPHY_AVAILABLE

def has_qrcode() -> bool:
    """Check if QR code generation is available"""
    return QRCODE_AVAILABLE

def has_yaml() -> bool:
    """Check if YAML support is available"""
    return YAML_AVAILABLE

def has_validators() -> bool:
    """Check if validators is available"""
    return VALIDATORS_AVAILABLE

def get_available_features() -> dict:
    """Get dictionary of available optional features"""
    return {
        'grpc': GRPC_AVAILABLE,
        'prometheus': PROMETHEUS_AVAILABLE,
        'cryptography': CRYPTOGRAPHY_AVAILABLE,
        'qrcode': QRCODE_AVAILABLE,
        'yaml': YAML_AVAILABLE,
        'validators': VALIDATORS_AVAILABLE,
    }

def print_feature_status():
    """Print status of optional features"""
    features = get_available_features()
    print("Optional Features Status:")
    for feature, available in features.items():
        status = "✓ Available" if available else "✗ Not Available"
        print(f"  {feature}: {status}")

__all__ = [
    'OptionalImport', 'OptionalDependencies', 'require_module', 'optional_feature',
    'has_grpc', 'has_prometheus', 'has_cryptography', 'has_qrcode', 'has_yaml', 'has_validators',
    'get_available_features', 'print_feature_status'
]