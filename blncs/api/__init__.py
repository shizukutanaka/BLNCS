"""
BLNCS REST API
Modern RESTful API for Lightning Network Control System with comprehensive endpoints.
"""

from .app import create_app, create_api_server
from .auth import AuthManager, api_key_required, rate_limit
from .responses import APIResponse, success_response, error_response
from .validators import validate_request, RequestValidator
from .middleware import setup_middleware, cors_middleware, logging_middleware
from .openapi import setup_docs_endpoints, get_openapi_spec
from .docs import APIDocumentationGenerator

__all__ = [
    'create_app',
    'create_api_server', 
    'AuthManager',
    'api_key_required',
    'rate_limit',
    'APIResponse',
    'success_response',
    'error_response',
    'validate_request',
    'RequestValidator',
    'setup_middleware',
    'cors_middleware',
    'logging_middleware',
    'setup_docs_endpoints',
    'get_openapi_spec',
    'APIDocumentationGenerator'
]

__version__ = '2.0.0'