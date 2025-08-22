# Data Transformer Plugin

from blrcs.plugins import PluginInterface
from typing import Dict, Any
import json
import csv
import io

class DataTransformerPlugin(PluginInterface):
    """Transform data between different formats"""
    
    @property
    def name(self) -> str:
        return "Data Transformer"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    @property
    def description(self) -> str:
        return "Transforms data between JSON, CSV, and other formats"
    
    async def initialize(self, context: Dict[str, Any]) -> bool:
        self.formats = ["json", "csv", "tsv", "text"]
        return True
    
    async def execute(self, data: Any) -> Dict[str, Any]:
        """Transform data to requested format"""
        if not isinstance(data, dict):
            return {"error": "Input must be a dictionary"}
        
        content = data.get("content")
        from_format = data.get("from", "json")
        to_format = data.get("to", "json")
        
        try:
            # Parse input
            if from_format == "json":
                if isinstance(content, str):
                    parsed = json.loads(content)
                else:
                    parsed = content
            elif from_format == "csv":
                reader = csv.DictReader(io.StringIO(content))
                parsed = list(reader)
            elif from_format == "tsv":
                reader = csv.DictReader(io.StringIO(content), delimiter='\t')
                parsed = list(reader)
            else:
                parsed = content
            
            # Convert to output format
            if to_format == "json":
                output = json.dumps(parsed, indent=2)
            elif to_format == "csv":
                if isinstance(parsed, list) and parsed:
                    output_io = io.StringIO()
                    writer = csv.DictWriter(output_io, fieldnames=parsed[0].keys())
                    writer.writeheader()
                    writer.writerows(parsed)
                    output = output_io.getvalue()
                else:
                    output = ""
            elif to_format == "tsv":
                if isinstance(parsed, list) and parsed:
                    output_io = io.StringIO()
                    writer = csv.DictWriter(output_io, fieldnames=parsed[0].keys(), delimiter='\t')
                    writer.writeheader()
                    writer.writerows(parsed)
                    output = output_io.getvalue()
                else:
                    output = ""
            elif to_format == "text":
                output = str(parsed)
            else:
                output = parsed
            
            return {
                "success": True,
                "output": output,
                "from_format": from_format,
                "to_format": to_format
            }
            
        except Exception as e:
            return {"error": str(e), "success": False}
    
    async def cleanup(self) -> None:
        pass
