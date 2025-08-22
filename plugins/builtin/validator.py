# Data Validator Plugin

from blrcs.plugins import PluginInterface
from typing import Dict, Any
import re

class DataValidatorPlugin(PluginInterface):
    """Validate and sanitize data"""
    
    @property
    def name(self) -> str:
        return "Data Validator"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    @property
    def description(self) -> str:
        return "Validates and sanitizes input data"
    
    async def initialize(self, context: Dict[str, Any]) -> bool:
        self.rules = {
            'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
            'phone': r'^\+?1?\d{9,15}$',
            'url': r'^https?://[^\s]+$',
            'ip': r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        }
        return True
    
    async def execute(self, data: Any) -> Dict[str, Any]:
        """Validate data against common patterns"""
        if not isinstance(data, dict):
            return {"valid": False, "errors": ["Input must be a dictionary"]}
        
        results = {"valid": True, "errors": [], "validated": {}}
        
        for key, value in data.items():
            if key in self.rules:
                pattern = self.rules[key]
                if not re.match(pattern, str(value)):
                    results["valid"] = False
                    results["errors"].append(f"Invalid {key}: {value}")
                else:
                    results["validated"][key] = value
            else:
                # Sanitize unknown fields
                sanitized = str(value).strip()[:1000]  # Limit length
                results["validated"][key] = sanitized
        
        return results
    
    async def cleanup(self) -> None:
        pass
