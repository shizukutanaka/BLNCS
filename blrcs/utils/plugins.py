# BLRCS Lightweight Plugin System
# Minimal plugin system following Pike's simplicity
import importlib.util
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable
import json

class LightweightPlugin:
    """Simple plugin interface"""
    
    def __init__(self):
        self.name = self.__class__.__name__
        self.enabled = True
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize plugin"""
        return True
    
    def execute(self, data: Any) -> Any:
        """Execute plugin logic"""
        return data
    
    def cleanup(self):
        """Cleanup resources"""
        pass

class SimplePluginManager:
    """
    Ultra-lightweight plugin manager.
    No abstractions, just functionality.
    """
    
    def __init__(self, plugin_dir: str = "plugins"):
        self.plugin_dir = Path(plugin_dir)
        self.plugins: Dict[str, LightweightPlugin] = {}
        self.hooks: Dict[str, List[Callable]] = {}
        
        # Ensure plugin directory exists
        self.plugin_dir.mkdir(exist_ok=True)
    
    def load_plugin(self, path: Path) -> Optional[LightweightPlugin]:
        """Load a single plugin from file"""
        if not path.exists() or not path.suffix == '.py':
            return None
        
        try:
            # Load module dynamically
            spec = importlib.util.spec_from_file_location(path.stem, path)
            if not spec or not spec.loader:
                return None
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find plugin class
            for item_name in dir(module):
                item = getattr(module, item_name)
                if (isinstance(item, type) and 
                    issubclass(item, LightweightPlugin) and 
                    item is not LightweightPlugin):
                    
                    # Create instance
                    plugin = item()
                    self.plugins[plugin.name] = plugin
                    return plugin
            
        except Exception:
            pass  # Silent fail for bad plugins
        
        return None
    
    def load_all(self):
        """Load all plugins from directory"""
        if not self.plugin_dir.exists():
            return
        
        for py_file in self.plugin_dir.glob("*.py"):
            if py_file.stem != "__init__":
                self.load_plugin(py_file)
    
    def execute_hook(self, hook_name: str, data: Any = None) -> List[Any]:
        """Execute all plugins registered for a hook"""
        results = []
        
        if hook_name in self.hooks:
            for func in self.hooks[hook_name]:
                try:
                    result = func(data)
                    results.append(result)
                except:
                    pass  # Skip failed hooks
        
        return results
    
    def register_hook(self, hook_name: str, func: Callable):
        """Register function for hook"""
        if hook_name not in self.hooks:
            self.hooks[hook_name] = []
        self.hooks[hook_name].append(func)
    
    def get_plugin(self, name: str) -> Optional[LightweightPlugin]:
        """Get plugin by name"""
        return self.plugins.get(name)
    
    def list_plugins(self) -> List[str]:
        """List loaded plugin names"""
        return list(self.plugins.keys())
    
    def unload_plugin(self, name: str):
        """Unload and cleanup plugin"""
        if name in self.plugins:
            plugin = self.plugins[name]
            plugin.cleanup()
            del self.plugins[name]
    
    def cleanup_all(self):
        """Cleanup all plugins"""
        for plugin in self.plugins.values():
            plugin.cleanup()
        self.plugins.clear()
        self.hooks.clear()

# Global plugin manager instance
_plugin_manager: Optional[SimplePluginManager] = None

def get_plugin_manager() -> SimplePluginManager:
    """Get global plugin manager"""
    global _plugin_manager
    if _plugin_manager is None:
        _plugin_manager = SimplePluginManager()
    return _plugin_manager

# Example plugin template
PLUGIN_TEMPLATE = '''
# Example BLRCS Plugin
from blrcs.plugins import LightweightPlugin

class MyPlugin(LightweightPlugin):
    """Example plugin implementation"""
    
    def initialize(self, config):
        """Initialize with config"""
        # Your initialization code here
        return True
    
    def execute(self, data):
        """Process data"""
        # Your processing logic here
        return data
    
    def cleanup(self):
        """Cleanup resources"""
        # Your cleanup code here
        pass
'''

def create_plugin_template(name: str, plugin_dir: str = "plugins"):
    """Create a plugin template file"""
    path = Path(plugin_dir) / f"{name}.py"
    if not path.exists():
        path.parent.mkdir(exist_ok=True)
        path.write_text(PLUGIN_TEMPLATE)
        return True
    return False