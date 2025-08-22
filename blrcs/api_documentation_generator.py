# BLRCS API Documentation Generator
# Automatic API documentation generation with interactive examples and OpenAPI specification

import ast
import inspect
import json
import re
import time
import logging
from typing import Dict, List, Any, Optional, Union, Callable, Type, get_type_hints
from pathlib import Path
from dataclasses import dataclass, field
from collections import defaultdict
import importlib
import sys
import os

logger = logging.getLogger(__name__)

@dataclass
class APIEndpoint:
    """API endpoint documentation"""
    path: str
    method: str
    function_name: str
    description: str
    parameters: List[Dict[str, Any]]
    responses: List[Dict[str, Any]]
    examples: List[Dict[str, Any]]
    tags: List[str]
    security: List[str] = field(default_factory=list)

@dataclass
class APIParameter:
    """API parameter documentation"""
    name: str
    param_type: str  # query, path, body, header
    data_type: str
    required: bool
    description: str
    default_value: Any = None
    examples: List[Any] = field(default_factory=list)

@dataclass
class APIResponse:
    """API response documentation"""
    status_code: int
    description: str
    content_type: str
    schema: Dict[str, Any]
    examples: List[Dict[str, Any]] = field(default_factory=list)

class APIDocumentationExtractor:
    """Extract API documentation from source code"""
    
    def __init__(self, project_root: Path):
        self.project_root = Path(project_root)
        self.endpoints: List[APIEndpoint] = []
        self.schemas: Dict[str, Dict[str, Any]] = {}
        self.base_info = {
            "title": "BLRCS API",
            "version": "3.0.0",
            "description": "Bitcoin Lightning Risk Control System API",
            "contact": {"name": "BLRCS Team"},
            "license": {"name": "MIT"}
        }
    
    def extract_from_project(self) -> Dict[str, Any]:
        """Extract API documentation from entire project"""
        logger.info("🔍 Extracting API documentation from project")
        
        # Find Python files that might contain API endpoints
        api_files = self._find_api_files()
        
        for file_path in api_files:
            self._extract_from_file(file_path)
        
        # Generate comprehensive documentation
        return self._generate_documentation()
    
    def _find_api_files(self) -> List[Path]:
        """Find files that might contain API endpoints"""
        api_files = []
        
        # Look for common API file patterns
        patterns = [
            "**/app.py", "**/main.py", "**/api.py", "**/routes.py",
            "**/endpoints.py", "**/views.py", "**/handlers.py"
        ]
        
        for pattern in patterns:
            api_files.extend(self.project_root.rglob(pattern))
        
        # Also scan all Python files in blrcs directory
        blrcs_dir = self.project_root / "blrcs"
        if blrcs_dir.exists():
            api_files.extend(blrcs_dir.rglob("*.py"))
        
        # Remove duplicates and filter out __pycache__, etc.
        unique_files = []
        for file_path in api_files:
            if (str(file_path) not in [str(f) for f in unique_files] and
                '__pycache__' not in str(file_path) and
                '.pyc' not in str(file_path)):
                unique_files.append(file_path)
        
        return unique_files
    
    def _extract_from_file(self, file_path: Path):
        """Extract API documentation from a single file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Parse AST
            tree = ast.parse(content)
            
            # Look for function definitions that might be API endpoints
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    endpoint = self._extract_endpoint_from_function(node, content, file_path)
                    if endpoint:
                        self.endpoints.append(endpoint)
                        
        except Exception as e:
            logger.warning(f"Failed to extract from {file_path}: {e}")
    
    def _extract_endpoint_from_function(self, func_node: ast.FunctionDef, 
                                      content: str, file_path: Path) -> Optional[APIEndpoint]:
        """Extract endpoint information from function AST node"""
        
        # Check if function looks like an API endpoint
        if not self._is_likely_api_function(func_node):
            return None
        
        # Extract docstring
        docstring = ast.get_docstring(func_node) or ""
        
        # Parse function signature
        parameters = self._extract_parameters(func_node)
        
        # Determine HTTP method and path
        method, path = self._determine_method_and_path(func_node, docstring)
        
        if not method or not path:
            return None
        
        # Extract description
        description = self._extract_description(docstring)
        
        # Extract response information
        responses = self._extract_responses(docstring)
        
        # Extract examples
        examples = self._extract_examples(docstring)
        
        # Extract tags
        tags = self._extract_tags(func_node, file_path)
        
        return APIEndpoint(
            path=path,
            method=method,
            function_name=func_node.name,
            description=description,
            parameters=parameters,
            responses=responses,
            examples=examples,
            tags=tags
        )
    
    def _is_likely_api_function(self, func_node: ast.FunctionDef) -> bool:
        """Check if function is likely an API endpoint"""
        
        # Check for common API function indicators
        api_indicators = [
            'get', 'post', 'put', 'delete', 'patch',
            'api', 'endpoint', 'route', 'handler'
        ]
        
        func_name = func_node.name.lower()
        
        # Check function name
        if any(indicator in func_name for indicator in api_indicators):
            return True
        
        # Check decorators
        for decorator in func_node.decorator_list:
            if isinstance(decorator, ast.Name):
                if decorator.id.lower() in ['app', 'route', 'get', 'post', 'put', 'delete']:
                    return True
            elif isinstance(decorator, ast.Attribute):
                if decorator.attr.lower() in ['route', 'get', 'post', 'put', 'delete']:
                    return True
        
        # Check docstring for API keywords
        docstring = ast.get_docstring(func_node) or ""
        if any(keyword in docstring.lower() for keyword in ['api', 'endpoint', 'http', 'rest']):
            return True
        
        return False
    
    def _extract_parameters(self, func_node: ast.FunctionDef) -> List[Dict[str, Any]]:
        """Extract parameters from function signature"""
        parameters = []
        
        for arg in func_node.args.args:
            if arg.arg in ['self', 'cls']:
                continue
                
            param = {
                "name": arg.arg,
                "param_type": "query",  # Default, can be overridden
                "data_type": "string",   # Default
                "required": True,        # Default
                "description": f"Parameter {arg.arg}"
            }
            
            # Try to infer type from annotation
            if arg.annotation:
                param["data_type"] = self._ast_to_type_string(arg.annotation)
            
            parameters.append(param)
        
        return parameters
    
    def _ast_to_type_string(self, annotation) -> str:
        """Convert AST annotation to type string"""
        if isinstance(annotation, ast.Name):
            return annotation.id.lower()
        elif isinstance(annotation, ast.Constant):
            return str(type(annotation.value).__name__).lower()
        elif isinstance(annotation, ast.Attribute):
            return annotation.attr.lower()
        else:
            return "string"
    
    def _determine_method_and_path(self, func_node: ast.FunctionDef, 
                                  docstring: str) -> tuple[Optional[str], Optional[str]]:
        """Determine HTTP method and path from function"""
        
        method = None
        path = None
        
        # Check function name for method
        func_name = func_node.name.lower()
        if func_name.startswith('get_'):
            method = "GET"
            path = f"/{func_name[4:].replace('_', '/')}"
        elif func_name.startswith('post_'):
            method = "POST"
            path = f"/{func_name[5:].replace('_', '/')}"
        elif func_name.startswith('put_'):
            method = "PUT"
            path = f"/{func_name[4:].replace('_', '/')}"
        elif func_name.startswith('delete_'):
            method = "DELETE"
            path = f"/{func_name[7:].replace('_', '/')}"
        
        # Check docstring for method and path
        docstring_lower = docstring.lower()
        
        # Look for HTTP method in docstring
        if 'get' in docstring_lower and not method:
            method = "GET"
        elif 'post' in docstring_lower and not method:
            method = "POST"
        elif 'put' in docstring_lower and not method:
            method = "PUT"
        elif 'delete' in docstring_lower and not method:
            method = "DELETE"
        
        # Look for path in docstring
        path_patterns = [
            r'path[:\s]+([/\w\-_{}]+)',
            r'route[:\s]+([/\w\-_{}]+)',
            r'endpoint[:\s]+([/\w\-_{}]+)'
        ]
        
        for pattern in path_patterns:
            match = re.search(pattern, docstring_lower)
            if match and not path:
                path = match.group(1)
                break
        
        # Default path if none found
        if not path:
            path = f"/{func_node.name.replace('_', '/')}"
        
        # Default method if none found
        if not method:
            method = "GET"
        
        return method, path
    
    def _extract_description(self, docstring: str) -> str:
        """Extract description from docstring"""
        lines = docstring.split('\n')
        
        # Take first non-empty line as description
        for line in lines:
            line = line.strip()
            if line and not line.startswith('@') and not line.startswith('Args:'):
                return line
        
        return "API endpoint"
    
    def _extract_responses(self, docstring: str) -> List[Dict[str, Any]]:
        """Extract response information from docstring"""
        responses = []
        
        # Default success response
        responses.append({
            "status_code": 200,
            "description": "Successful response",
            "content_type": "application/json",
            "schema": {"type": "object"}
        })
        
        # Look for response documentation in docstring
        lines = docstring.split('\n')
        for line in lines:
            if 'return' in line.lower() or 'response' in line.lower():
                # Try to extract status codes
                status_matches = re.findall(r'\b(200|201|400|401|404|500)\b', line)
                for status in status_matches:
                    responses.append({
                        "status_code": int(status),
                        "description": f"HTTP {status} response",
                        "content_type": "application/json",
                        "schema": {"type": "object"}
                    })
        
        return responses
    
    def _extract_examples(self, docstring: str) -> List[Dict[str, Any]]:
        """Extract examples from docstring"""
        examples = []
        
        # Look for example sections in docstring
        lines = docstring.split('\n')
        in_example = False
        current_example = []
        
        for line in lines:
            line = line.strip()
            if 'example' in line.lower():
                in_example = True
                continue
            elif in_example:
                if line.startswith('```') or line.startswith('"""'):
                    if current_example:
                        examples.append({
                            "description": "Example usage",
                            "content": '\n'.join(current_example)
                        })
                        current_example = []
                    in_example = not in_example
                elif in_example:
                    current_example.append(line)
        
        return examples
    
    def _extract_tags(self, func_node: ast.FunctionDef, file_path: Path) -> List[str]:
        """Extract tags from function and file context"""
        tags = []
        
        # Add tag based on file name
        file_stem = file_path.stem
        if file_stem not in ['__init__', 'main']:
            tags.append(file_stem.replace('_', ' ').title())
        
        # Add tag based on function name
        func_name = func_node.name
        if '_' in func_name:
            prefix = func_name.split('_')[0]
            if prefix.lower() in ['get', 'post', 'put', 'delete']:
                category = func_name.split('_')[1] if len(func_name.split('_')) > 1 else 'general'
                tags.append(category.title())
        
        return tags or ["General"]
    
    def _generate_documentation(self) -> Dict[str, Any]:
        """Generate comprehensive API documentation"""
        
        # Group endpoints by tags
        endpoints_by_tag = defaultdict(list)
        for endpoint in self.endpoints:
            for tag in endpoint.tags:
                endpoints_by_tag[tag].append(endpoint)
        
        # Generate OpenAPI specification
        openapi_spec = self._generate_openapi_spec()
        
        # Generate human-readable documentation
        readable_docs = self._generate_readable_docs(endpoints_by_tag)
        
        return {
            "info": self.base_info,
            "endpoints_count": len(self.endpoints),
            "tags": list(endpoints_by_tag.keys()),
            "openapi_specification": openapi_spec,
            "readable_documentation": readable_docs,
            "endpoints_by_tag": {
                tag: [
                    {
                        "path": ep.path,
                        "method": ep.method,
                        "function": ep.function_name,
                        "description": ep.description,
                        "parameters_count": len(ep.parameters),
                        "examples_count": len(ep.examples)
                    }
                    for ep in endpoints
                ]
                for tag, endpoints in endpoints_by_tag.items()
            }
        }
    
    def _generate_openapi_spec(self) -> Dict[str, Any]:
        """Generate OpenAPI 3.0 specification"""
        
        paths = {}
        
        for endpoint in self.endpoints:
            if endpoint.path not in paths:
                paths[endpoint.path] = {}
            
            # Convert parameters
            parameters = []
            for param in endpoint.parameters:
                parameters.append({
                    "name": param["name"],
                    "in": param["param_type"],
                    "required": param["required"],
                    "description": param["description"],
                    "schema": {"type": param["data_type"]}
                })
            
            # Convert responses
            responses = {}
            for resp in endpoint.responses:
                responses[str(resp["status_code"])] = {
                    "description": resp["description"],
                    "content": {
                        resp["content_type"]: {
                            "schema": resp["schema"]
                        }
                    }
                }
            
            paths[endpoint.path][endpoint.method.lower()] = {
                "summary": endpoint.description,
                "tags": endpoint.tags,
                "parameters": parameters,
                "responses": responses
            }
        
        return {
            "openapi": "3.0.0",
            "info": self.base_info,
            "paths": paths,
            "components": {
                "schemas": self.schemas
            }
        }
    
    def _generate_readable_docs(self, endpoints_by_tag: Dict[str, List[APIEndpoint]]) -> str:
        """Generate human-readable documentation"""
        
        docs = f"# {self.base_info['title']}\n\n"
        docs += f"{self.base_info['description']}\n\n"
        docs += f"**Version:** {self.base_info['version']}\n\n"
        
        for tag, endpoints in endpoints_by_tag.items():
            docs += f"## {tag}\n\n"
            
            for endpoint in endpoints:
                docs += f"### {endpoint.method} {endpoint.path}\n\n"
                docs += f"{endpoint.description}\n\n"
                
                if endpoint.parameters:
                    docs += "**Parameters:**\n\n"
                    for param in endpoint.parameters:
                        docs += f"- `{param['name']}` ({param['data_type']}) - {param['description']}"
                        if param['required']:
                            docs += " **(required)**"
                        docs += "\n"
                    docs += "\n"
                
                if endpoint.examples:
                    docs += "**Examples:**\n\n"
                    for example in endpoint.examples:
                        docs += f"```\n{example.get('content', '')}\n```\n\n"
                
                docs += "---\n\n"
        
        return docs

class APIDocumentationGenerator:
    """Main API documentation generator"""
    
    def __init__(self, project_root: Path = None):
        self.project_root = Path(project_root or os.getcwd())
        self.extractor = APIDocumentationExtractor(self.project_root)
        self.output_dir = self.project_root / "docs" / "api"
        
    def generate_full_documentation(self) -> Dict[str, Any]:
        """Generate complete API documentation"""
        logger.info("📚 Generating comprehensive API documentation")
        
        # Extract documentation
        docs = self.extractor.extract_from_project()
        
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Save OpenAPI specification
        openapi_file = self.output_dir / "openapi.json"
        with open(openapi_file, 'w', encoding='utf-8') as f:
            json.dump(docs["openapi_specification"], f, indent=2, ensure_ascii=False)
        
        # Save readable documentation
        readme_file = self.output_dir / "README.md"
        with open(readme_file, 'w', encoding='utf-8') as f:
            f.write(docs["readable_documentation"])
        
        # Generate interactive HTML documentation
        html_file = self.output_dir / "index.html"
        self._generate_html_docs(docs, html_file)
        
        # Generate summary report
        report = {
            "generation_timestamp": time.time(),
            "project_root": str(self.project_root),
            "endpoints_found": docs["endpoints_count"],
            "tags": docs["tags"],
            "files_generated": [
                str(openapi_file),
                str(readme_file),
                str(html_file)
            ],
            "api_coverage": self._calculate_api_coverage(docs)
        }
        
        logger.info(f"✅ Generated documentation for {docs['endpoints_count']} endpoints")
        return report
    
    def _generate_html_docs(self, docs: Dict[str, Any], output_file: Path):
        """Generate interactive HTML documentation"""
        
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - API Documentation</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ border-bottom: 1px solid #eee; padding-bottom: 20px; margin-bottom: 30px; }}
        .endpoint {{ background: #f8f9fa; padding: 20px; margin: 20px 0; border-radius: 6px; border-left: 4px solid #007bff; }}
        .method {{ display: inline-block; padding: 4px 12px; border-radius: 4px; color: white; font-weight: bold; margin-right: 10px; }}
        .get {{ background: #28a745; }}
        .post {{ background: #007bff; }}
        .put {{ background: #ffc107; color: #333; }}
        .delete {{ background: #dc3545; }}
        .path {{ font-family: monospace; font-size: 16px; }}
        .parameters {{ margin: 15px 0; }}
        .parameter {{ background: white; padding: 10px; margin: 5px 0; border-radius: 4px; border: 1px solid #ddd; }}
        .tag {{ display: inline-block; background: #e9ecef; padding: 2px 8px; border-radius: 12px; margin: 2px; font-size: 12px; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat {{ background: #e3f2fd; padding: 15px; border-radius: 6px; text-align: center; flex: 1; }}
        .example {{ background: #f8f9fa; padding: 15px; border-radius: 4px; font-family: monospace; white-space: pre-wrap; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{title}</h1>
            <p>{description}</p>
            <p><strong>Version:</strong> {version}</p>
        </div>
        
        <div class="stats">
            <div class="stat">
                <h3>{endpoints_count}</h3>
                <p>Endpoints</p>
            </div>
            <div class="stat">
                <h3>{tags_count}</h3>
                <p>Categories</p>
            </div>
        </div>
        
        {endpoints_html}
    </div>
</body>
</html>
        """
        
        # Generate endpoints HTML
        endpoints_html = ""
        for tag, endpoints in docs["endpoints_by_tag"].items():
            endpoints_html += f"<h2>{tag}</h2>\n"
            
            for endpoint_info in endpoints:
                method_class = endpoint_info["method"].lower()
                endpoints_html += f"""
                <div class="endpoint">
                    <div>
                        <span class="method {method_class}">{endpoint_info["method"]}</span>
                        <span class="path">{endpoint_info["path"]}</span>
                    </div>
                    <h3>{endpoint_info["function"]}</h3>
                    <p>{endpoint_info["description"]}</p>
                    <div class="parameters">
                        <strong>Parameters:</strong> {endpoint_info["parameters_count"]}
                    </div>
                </div>
                """
        
        # Format HTML
        html_content = html_template.format(
            title=docs["info"]["title"],
            description=docs["info"]["description"],
            version=docs["info"]["version"],
            endpoints_count=docs["endpoints_count"],
            tags_count=len(docs["tags"]),
            endpoints_html=endpoints_html
        )
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _calculate_api_coverage(self, docs: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate API documentation coverage"""
        
        total_endpoints = docs["endpoints_count"]
        documented_endpoints = len([ep for ep in self.extractor.endpoints if ep.description != "API endpoint"])
        
        coverage_percentage = (documented_endpoints / total_endpoints * 100) if total_endpoints > 0 else 0
        
        return {
            "total_endpoints": total_endpoints,
            "documented_endpoints": documented_endpoints,
            "coverage_percentage": round(coverage_percentage, 2),
            "quality_score": self._calculate_quality_score(docs)
        }
    
    def _calculate_quality_score(self, docs: Dict[str, Any]) -> float:
        """Calculate documentation quality score"""
        score = 0
        total_possible = 0
        
        for endpoint in self.extractor.endpoints:
            total_possible += 5  # Max 5 points per endpoint
            
            # Points for having description
            if endpoint.description and endpoint.description != "API endpoint":
                score += 1
            
            # Points for having parameters documented
            if endpoint.parameters:
                score += 1
            
            # Points for having examples
            if endpoint.examples:
                score += 1
            
            # Points for having proper responses
            if len(endpoint.responses) > 1:  # More than just default
                score += 1
            
            # Points for having tags
            if endpoint.tags:
                score += 1
        
        return round((score / total_possible * 100) if total_possible > 0 else 0, 2)

# Global documentation generator
doc_generator = APIDocumentationGenerator()

def generate_api_documentation() -> Dict[str, Any]:
    """Generate API documentation for BLRCS"""
    return doc_generator.generate_full_documentation()

def extract_api_info() -> Dict[str, Any]:
    """Extract API information without generating files"""
    return doc_generator.extractor.extract_from_project()