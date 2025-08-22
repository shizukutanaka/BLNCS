# Example Built-in Plugin for BLRCS

from blrcs.plugins import PluginInterface
from typing import Dict, Any
import hashlib

class DataHasherPlugin(PluginInterface):
    """Plugin to hash data for integrity verification"""
    
    @property
    def name(self) -> str:
        return "Data Hasher"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    @property
    def description(self) -> str:
        return "Calculates SHA256 hash of data for integrity verification"
    
    async def initialize(self, context: Dict[str, Any]) -> bool:
        """Initialize the plugin"""
        self.context = context
        self.logger = context.get("logger")
        
        if self.logger:
            self.logger.info(f"Data Hasher plugin initialized")
        
        return True
    
    async def execute(self, data: Any) -> Dict[str, Any]:
        """Calculate hash of input data"""
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        elif isinstance(data, bytes):
            data_bytes = data
        else:
            data_bytes = str(data).encode('utf-8')
        
        # Calculate SHA256 hash
        sha256 = hashlib.sha256(data_bytes).hexdigest()
        
        # Calculate SHA256 (強化セキュリティ)
        sha256_alt = hashlib.sha256(data_bytes).hexdigest()
        
        return {
            "original_size": len(data_bytes),
            "sha256": sha256,
            "sha256_alt": sha256_alt,
            "data_type": type(data).__name__
        }
    
    async def cleanup(self) -> None:
        """Cleanup plugin resources"""
        if self.logger:
            self.logger.info("Data Hasher plugin cleaned up")
