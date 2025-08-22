# BLRCS Lazy Loading Module
# Optimize imports and reduce startup time following Carmack's performance principles
import sys
import importlib
from typing import Optional, Any

class LazyLoader:
    """
    Lazy module loader to reduce startup time.
    Modules are imported only when first accessed.
    """
    
    def __init__(self, module_name: str):
        self.module_name = module_name
        self._module: Optional[Any] = None
    
    def __getattr__(self, item):
        if self._module is None:
            self._module = importlib.import_module(self.module_name)
        return getattr(self._module, item)
    
    def __dir__(self):
        if self._module is None:
            self._module = importlib.import_module(self.module_name)
        return dir(self._module)

class LazyImportManager:
    """
    Centralized lazy import management.
    Following Rob Pike's simplicity principle.
    """
    
    _instances = {}
    
    @classmethod
    def get(cls, module_name: str) -> LazyLoader:
        """Get or create lazy loader for module"""
        if module_name not in cls._instances:
            cls._instances[module_name] = LazyLoader(module_name)
        return cls._instances[module_name]
    
    @classmethod
    def preload_critical(cls):
        """Preload critical modules for performance"""
        critical = ['sys', 'os', 'pathlib', 'typing']
        for module in critical:
            if module not in sys.modules:
                importlib.import_module(module)

# Optimized imports for common heavy modules
def get_fastapi():
    """Lazy load FastAPI"""
    return LazyImportManager.get('fastapi')

def get_uvicorn():
    """Lazy load Uvicorn"""
    return LazyImportManager.get('uvicorn')

def get_tkinter():
    """Lazy load tkinter"""
    return LazyImportManager.get('tkinter')

def get_aiosqlite():
    """Lazy load aiosqlite"""
    return LazyImportManager.get('aiosqlite')

def get_psutil():
    """Lazy load psutil"""
    return LazyImportManager.get('psutil')

def get_cryptography():
    """Lazy load cryptography"""
    return LazyImportManager.get('cryptography.hazmat.primitives.ciphers.aead')