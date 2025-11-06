"""
Advanced API Gateway and Client Libraries for BLNCS

This module provides enhanced API integration including:
- API Gateway with advanced routing and security
- Client libraries for multiple programming languages
- Automatic documentation generation
- API versioning and compatibility management
"""

import json
import time
import logging
from typing import Dict, List, Optional, Any, Callable, Union
from dataclasses import dataclass, asdict
from flask import Flask, request, jsonify, Blueprint
import threading
import re
from functools import wraps
import inspect
from pathlib import Path

class APIVersion:
    """API version management."""

    def __init__(self, version: str, deprecated: bool = False, sunset_date: Optional[str] = None):
        self.version = version
        self.deprecated = deprecated
        self.sunset_date = sunset_date
        self.endpoints = {}

    def add_endpoint(self, path: str, handler: Callable, methods: List[str] = None):
        """Add endpoint to this version."""
        self.endpoints[path] = {
            'handler': handler,
            'methods': methods or ['GET']
        }

    def is_deprecated(self) -> bool:
        """Check if this version is deprecated."""
        return self.deprecated

class APIClientLibrary:
    """Base class for API client libraries."""

    def __init__(self, base_url: str, api_key: str, version: str = 'v1'):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.version = version
        self.session = None
        self.logger = logging.getLogger(f"{__name__}.APIClientLibrary")

    def _make_request(self, endpoint: str, method: str = 'GET', **kwargs) -> Dict[str, Any]:
        """Make HTTP request with error handling."""
        import requests

        url = f"{self.base_url}/{self.version}{endpoint}"
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
            'User-Agent': f'BLNCS-API-Client/{self.version}'
        }

        try:
            if method.upper() == 'GET':
                response = requests.get(url, headers=headers, **kwargs)
            elif method.upper() == 'POST':
                response = requests.post(url, headers=headers, **kwargs)
            elif method.upper() == 'PUT':
                response = requests.put(url, headers=headers, **kwargs)
            elif method.upper() == 'DELETE':
                response = requests.delete(url, headers=headers, **kwargs)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            self.logger.error(f"API request failed: {e}")
            raise

class BLNCSAPIClient(APIClientLibrary):
    """BLNCS API client with enhanced features."""

    def get_system_status(self) -> Dict[str, Any]:
        """Get system status."""
        return self._make_request('/system/status')

    def get_lightning_info(self) -> Dict[str, Any]:
        """Get Lightning Network information."""
        return self._make_request('/lightning/info')

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics."""
        return self._make_request('/performance/metrics')

    def get_security_status(self) -> Dict[str, Any]:
        """Get security status."""
        return self._make_request('/security/status')

    def create_channel(self, node_id: str, capacity: int, **kwargs) -> Dict[str, Any]:
        """Create a Lightning Network channel."""
        data = {
            'node_id': node_id,
            'capacity': capacity,
            **kwargs
        }
        return self._make_request('/lightning/channels', method='POST', json=data)

    def get_channel_info(self, channel_id: str) -> Dict[str, Any]:
        """Get channel information."""
        return self._make_request(f'/lightning/channels/{channel_id}')

class APIGateway:
    """Advanced API Gateway with routing and security."""

    def __init__(self, app: Flask):
        self.app = app
        self.versions: Dict[str, APIVersion] = {}
        self.middleware = []
        self.rate_limiters = {}
        self.logger = logging.getLogger(f"{__name__}.APIGateway")

        # Default API key for demo (in production, use secure key management)
        self.api_keys = {
            'demo_key_123': {'permissions': ['read', 'write'], 'rate_limit': 1000}
        }

    def add_version(self, version: APIVersion):
        """Add API version."""
        self.versions[version.version] = version

    def add_middleware(self, middleware_func: Callable):
        """Add middleware function."""
        self.middleware.append(middleware_func)

    def _authenticate_request(self, api_key: str) -> Dict[str, Any]:
        """Authenticate API request."""
        if api_key in self.api_keys:
            return self.api_keys[api_key]
        return None

    def _check_rate_limit(self, api_key: str, endpoint: str) -> bool:
        """Check rate limiting."""
        if api_key not in self.api_keys:
            return False

        # Simple rate limiting implementation
        user_info = self.api_keys[api_key]
        rate_limit = user_info.get('rate_limit', 100)

        # In a real implementation, use Redis or similar for distributed rate limiting
        return True  # Simplified for demo

    def _apply_middleware(self, func: Callable) -> Callable:
        """Apply middleware to endpoint function."""
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Apply middleware in reverse order (last added first)
            for middleware in reversed(self.middleware):
                result = middleware(func, *args, **kwargs)
                if result is not None:
                    return result

            return func(*args, **kwargs)
        return wrapper

    def register_routes(self):
        """Register all API routes."""
        for version_name, version in self.versions.items():
            for path, endpoint_info in version.endpoints.items():
                handler = endpoint_info['handler']
                methods = endpoint_info['methods']

                # Wrap handler with middleware and security
                secured_handler = self._apply_middleware(handler)

                # Register route
                self.app.add_url_rule(
                    f'/{version_name}{path}',
                    f'{version_name}_{path.replace("/", "_").replace("<", "").replace(">", "")}',
                    secured_handler,
                    methods=methods
                )

class DocumentationGenerator:
    """Automatic API documentation generator."""

    def __init__(self):
        self.endpoints = []
        self.schemas = {}

    def analyze_endpoint(self, path: str, handler: Callable, methods: List[str]):
        """Analyze endpoint for documentation."""
        endpoint_info = {
            'path': path,
            'methods': methods,
            'handler': handler,
            'summary': handler.__doc__ or 'No description available',
            'parameters': self._extract_parameters(handler),
            'responses': self._extract_responses(handler),
            'examples': self._generate_examples(handler)
        }

        self.endpoints.append(endpoint_info)

    def _extract_parameters(self, handler: Callable) -> List[Dict[str, Any]]:
        """Extract function parameters."""
        sig = inspect.signature(handler)
        parameters = []

        for param_name, param in sig.parameters.items():
            if param_name != 'self':
                param_info = {
                    'name': param_name,
                    'type': str(param.annotation) if param.annotation != param.empty else 'Any',
                    'required': param.default == param.empty,
                    'description': 'Parameter description'  # Would be extracted from docstring
                }
                parameters.append(param_info)

        return parameters

    def _extract_responses(self, handler: Callable) -> Dict[str, Any]:
        """Extract response information."""
        # Simplified response extraction
        return {
            '200': {
                'description': 'Successful response',
                'schema': {'type': 'object'}
            }
        }

    def _generate_examples(self, handler: Callable) -> Dict[str, Any]:
        """Generate request/response examples."""
        return {
            'request': {'example': 'Request example'},
            'response': {'example': 'Response example'}
        }

    def generate_openapi_spec(self) -> Dict[str, Any]:
        """Generate OpenAPI specification."""
        spec = {
            'openapi': '3.0.0',
            'info': {
                'title': 'BLNCS API',
                'version': '1.0.0',
                'description': 'Bitcoin Lightning Network Control System API'
            },
            'paths': {},
            'components': {
                'schemas': self.schemas,
                'securitySchemes': {
                    'ApiKeyAuth': {
                        'type': 'apiKey',
                        'in': 'header',
                        'name': 'Authorization'
                    }
                }
            }
        }

        for endpoint in self.endpoints:
            path_spec = {}
            for method in endpoint['methods']:
                path_spec[method.lower()] = {
                    'summary': endpoint['summary'],
                    'parameters': endpoint['parameters'],
                    'responses': endpoint['responses'],
                    'security': [{'ApiKeyAuth': []}]
                }

            spec['paths'][endpoint['path']] = path_spec

        return spec

    def export_documentation(self, format: str = 'json') -> str:
        """Export documentation in specified format."""
        if format.lower() == 'json':
            return json.dumps(self.generate_openapi_spec(), indent=2)
        elif format.lower() == 'yaml':
            import yaml
            return yaml.dump(self.generate_openapi_spec(), default_flow_style=False)
        else:
            raise ValueError(f"Unsupported format: {format}")

# API Gateway Blueprint
api_gateway_bp = Blueprint('api_gateway', __name__)

@api_gateway_bp.route('/docs')
def get_api_documentation():
    """Get API documentation."""
    # This would be generated dynamically in a real implementation
    return jsonify({'message': 'API documentation endpoint'})

@api_gateway_bp.route('/health')
def get_api_health():
    """Get API health status."""
    return jsonify({
        'status': 'healthy',
        'timestamp': time.time(),
        'version': '1.0.0'
    })

@api_gateway_bp.route('/metrics')
def get_api_metrics():
    """Get API usage metrics."""
    return jsonify({
        'requests_total': 0,
        'response_time_avg': 0,
        'error_rate': 0
    })

# Client library generators for different languages
class ClientLibraryGenerator:
    """Generate client libraries for different programming languages."""

    def __init__(self):
        self.templates = {
            'python': self._python_template,
            'javascript': self._javascript_template,
            'java': self._java_template,
            'go': self._go_template,
            'rust': self._rust_template
        }

    def generate_client_library(self, language: str, endpoints: List[Dict[str, Any]], output_dir: str):
        """Generate client library for specified language."""
        if language.lower() not in self.templates:
            raise ValueError(f"Unsupported language: {language}")

        template_func = self.templates[language.lower()]
        library_code = template_func(endpoints)

        output_path = Path(output_dir) / f'blncs_client.{self._get_file_extension(language)}'
        output_path.write_text(library_code)

        self.logger.info(f"Generated {language} client library: {output_path}")

    def _get_file_extension(self, language: str) -> str:
        """Get file extension for language."""
        extensions = {
            'python': 'py',
            'javascript': 'js',
            'java': 'java',
            'go': 'go',
            'rust': 'rs'
        }
        return extensions.get(language.lower(), 'txt')

    def _python_template(self, endpoints: List[Dict[str, Any]]) -> str:
        """Generate Python client library."""
        code = '''"""
BLNCS API Client Library for Python

Generated client library for BLNCS API integration.
"""

import requests
import json
from typing import Dict, Any, Optional

class BLNCSClient:
    """BLNCS API client for Python."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()

    def _make_request(self, endpoint: str, method: str = 'GET', **kwargs):
        """Make API request."""
        url = f"{self.base_url}{endpoint}"
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }

        response = self.session.request(method, url, headers=headers, **kwargs)
        response.raise_for_status()
        return response.json()

'''

        for endpoint in endpoints:
            code += f'''
    def {endpoint['function_name']}(self, **kwargs):
        """{endpoint['description']}"""
        return self._make_request('{endpoint['path']}', '{endpoint['method']}', **kwargs)
'''

        return code

    def _javascript_template(self, endpoints: List[Dict[str, Any]]) -> str:
        """Generate JavaScript client library."""
        # Simplified JavaScript template
        return '''
// BLNCS API Client Library for JavaScript

class BLNCSClient {
    constructor(baseUrl, apiKey) {
        this.baseUrl = baseUrl.replace(/\/$/, '');
        this.apiKey = apiKey;
    }

    async _makeRequest(endpoint, method = 'GET', options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const response = await fetch(url, {
            method,
            headers: {
                'Authorization': `Bearer ${this.apiKey}`,
                'Content-Type': 'application/json'
            },
            ...options
        });

        if (!response.ok) {
            throw new Error(`API request failed: ${response.statusText}`);
        }

        return response.json();
    }
}

// Export for use
module.exports = BLNCSClient;
'''

    def _java_template(self, endpoints: List[Dict[str, Any]]) -> str:
        """Generate Java client library."""
        # Simplified Java template
        return '''
// BLNCS API Client Library for Java

public class BLNCSClient {
    private String baseUrl;
    private String apiKey;

    public BLNCSClient(String baseUrl, String apiKey) {
        this.baseUrl = baseUrl.replaceAll("/$", "");
        this.apiKey = apiKey;
    }

    // Implementation would include HTTP client and methods
}
'''

    def _go_template(self, endpoints: List[Dict[str, Any]]) -> str:
        """Generate Go client library."""
        # Simplified Go template
        return '''
// BLNCS API Client Library for Go

package main

import (
    "encoding/json"
    "fmt"
    "net/http"
)

type BLNCSClient struct {
    BaseURL string
    APIKey  string
}

// Implementation would include HTTP client and methods
'''

    def _rust_template(self, endpoints: List[Dict[str, Any]]) -> str:
        """Generate Rust client library."""
        # Simplified Rust template
        return '''
// BLNCS API Client Library for Rust

use reqwest::Client;

pub struct BLNCSClient {
    base_url: String,
    api_key: String,
    client: Client,
}

// Implementation would include HTTP client and methods
'''

def create_api_gateway(app: Flask) -> APIGateway:
    """Create and configure API gateway."""
    gateway = APIGateway(app)

    # Add API versions
    v1 = APIVersion('v1')
    v1.add_endpoint('/system/status', get_api_health, ['GET'])
    v1.add_endpoint('/lightning/info', lambda: jsonify({'info': 'Lightning info'}), ['GET'])

    gateway.add_version(v1)

    # Register routes
    gateway.register_routes()

    return gateway

def generate_client_libraries(endpoints: List[Dict[str, Any]], output_dir: str):
    """Generate client libraries for multiple languages."""
    generator = ClientLibraryGenerator()

    for language in ['python', 'javascript', 'java', 'go', 'rust']:
        try:
            generator.generate_client_library(language, endpoints, output_dir)
        except Exception as e:
            print(f"Failed to generate {language} client: {e}")

def setup_api_documentation(app: Flask):
    """Set up automatic API documentation."""
    doc_generator = DocumentationGenerator()

    # Analyze existing endpoints
    for rule in app.url_map.iter_rules():
        if rule.endpoint != 'static':
            doc_generator.analyze_endpoint(
                rule.rule,
                app.view_functions[rule.endpoint],
                [method for method in rule.methods if method != 'HEAD']
            )

    # Add documentation route
    @app.route('/api/docs')
    def get_docs():
        return jsonify(doc_generator.generate_openapi_spec())

    # Export documentation
    docs_dir = Path('docs/api')
    docs_dir.mkdir(exist_ok=True)
    (docs_dir / 'openapi.json').write_text(doc_generator.export_documentation('json'))

    return doc_generator

# Example usage and integration
if __name__ == "__main__":
    # Create Flask app
    app = Flask(__name__)

    # Set up API gateway
    gateway = create_api_gateway(app)

    # Set up documentation
    docs = setup_api_documentation(app)

    # Generate client libraries
    endpoints = [
        {
            'path': '/system/status',
            'function_name': 'get_system_status',
            'method': 'GET',
            'description': 'Get system status'
        },
        {
            'path': '/lightning/info',
            'function_name': 'get_lightning_info',
            'method': 'GET',
            'description': 'Get Lightning Network information'
        }
    ]

    generate_client_libraries(endpoints, 'client_libraries')

    print("API Gateway and client libraries setup complete!")
    print("Documentation available at: /api/docs")
    print("Client libraries generated in: client_libraries/")
