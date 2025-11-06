"""
Enhanced API integration system for BLNCS
Implements API gateway, client libraries, and comprehensive documentation
based on competitor analysis and industry best practices
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any, Callable, TypeVar, Union
from dataclasses import dataclass, field
from enum import Enum
import threading
import aiohttp
import websockets
import hashlib
import hmac
from urllib.parse import urlparse, urljoin
import requests
from concurrent.futures import ThreadPoolExecutor
import inspect
import textwrap


T = TypeVar('T')


class APIProtocol(Enum):
    """API communication protocols"""
    REST = "rest"
    WEBSOCKET = "websocket"
    GRAPHQL = "graphql"
    GRPC = "grpc"


class AuthenticationMethod(Enum):
    """API authentication methods"""
    NONE = "none"
    API_KEY = "api_key"
    JWT = "jwt"
    OAUTH2 = "oauth2"
    SIGNATURE = "signature"


class APIEndpoint:
    """API endpoint configuration"""
    def __init__(
        self,
        path: str,
        method: str = "GET",
        auth_required: bool = False,
        rate_limit: Optional[int] = None,
        timeout: int = 30,
        description: str = "",
        parameters: Optional[Dict[str, Any]] = None
    ):
        self.path = path
        self.method = method.upper()
        self.auth_required = auth_required
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.description = description
        self.parameters = parameters or {}


@dataclass
class APIRequest:
    """API request structure"""
    endpoint: str
    method: str
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, Any] = field(default_factory=dict)
    data: Optional[Any] = None
    timeout: int = 30
    auth_method: AuthenticationMethod = AuthenticationMethod.NONE
    retry_count: int = 3


@dataclass
class APIResponse:
    """API response structure"""
    status_code: int
    headers: Dict[str, str]
    data: Any
    request_time: float
    success: bool
    error_message: Optional[str] = None


@dataclass
class APIMetrics:
    """API usage metrics"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    average_response_time: float = 0.0
    error_rate: float = 0.0
    rate_limit_hits: int = 0
    last_request_time: Optional[float] = None


class APIClient:
    """Enhanced API client with multiple protocol support"""

    def __init__(self, base_url: str, config: Optional[Dict[str, Any]] = None):
        """
        Initialize API client

        Args:
            base_url: Base API URL
            config: Client configuration
        """
        self.base_url = base_url.rstrip('/')
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Client configuration
        self.timeout = self.config.get('timeout', 30)
        self.retry_attempts = self.config.get('retry_attempts', 3)
        self.retry_delay = self.config.get('retry_delay', 1.0)
        self.rate_limit_delay = self.config.get('rate_limit_delay', 1.0)

        # Authentication
        self.auth_method = AuthenticationMethod(self.config.get('auth_method', 'none'))
        self.api_key = self.config.get('api_key')
        self.jwt_token = self.config.get('jwt_token')
        self.client_id = self.config.get('client_id')
        self.client_secret = self.config.get('client_secret')

        # HTTP session
        self.session: Optional[aiohttp.ClientSession] = None
        self.websocket: Optional[websockets.WebSocketServerProtocol] = None

        # Metrics
        self.metrics = APIMetrics()

        # Request history
        self.request_history: List[Tuple[APIRequest, APIResponse]] = []

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect()

    async def connect(self):
        """Establish API connection"""
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self.session = aiohttp.ClientSession(timeout=timeout)
            self.logger.info(f"API client connected to {self.base_url}")

    async def disconnect(self):
        """Close API connection"""
        if self.session:
            await self.session.close()
            self.session = None
        if self.websocket:
            await self.websocket.close()
            self.websocket = None
        self.logger.info("API client disconnected")

    def _build_url(self, endpoint: str) -> str:
        """Build full URL from endpoint"""
        if endpoint.startswith('http'):
            return endpoint
        return urljoin(self.base_url + '/', endpoint.lstrip('/'))

    def _prepare_headers(self, request: APIRequest) -> Dict[str, str]:
        """Prepare request headers with authentication"""
        headers = request.headers.copy()

        if request.auth_method == AuthenticationMethod.API_KEY and self.api_key:
            headers['X-API-Key'] = self.api_key
        elif request.auth_method == AuthenticationMethod.JWT and self.jwt_token:
            headers['Authorization'] = f'Bearer {self.jwt_token}'
        elif request.auth_method == AuthenticationMethod.OAUTH2:
            # OAuth2 implementation would go here
            pass

        # Add standard headers
        headers.setdefault('Content-Type', 'application/json')
        headers.setdefault('User-Agent', 'BLNCS-API-Client/1.0')

        return headers

    async def request(
        self,
        endpoint: str,
        method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        auth_method: AuthenticationMethod = AuthenticationMethod.NONE,
        timeout: Optional[int] = None
    ) -> APIResponse:
        """
        Make API request

        Args:
            endpoint: API endpoint
            method: HTTP method
            params: Query parameters
            data: Request data
            headers: Request headers
            auth_method: Authentication method
            timeout: Request timeout

        Returns:
            APIResponse: Response data
        """
        if not self.session:
            await self.connect()

        request = APIRequest(
            endpoint=endpoint,
            method=method,
            headers=headers or {},
            params=params or {},
            data=data,
            timeout=timeout or self.timeout,
            auth_method=auth_method
        )

        start_time = time.time()
        success = False
        error_message = None
        response_data = None
        status_code = 0
        response_headers = {}

        try:
            url = self._build_url(endpoint)
            request_headers = self._prepare_headers(request)

            # Prepare request data
            json_data = None
            if data is not None:
                if isinstance(data, dict):
                    json_data = data
                else:
                    json_data = json.loads(data) if isinstance(data, str) else data

            # Make request with retries
            for attempt in range(self.retry_attempts + 1):
                try:
                    async with self.session.request(
                        method=request.method,
                        url=url,
                        headers=request_headers,
                        params=request.params,
                        json=json_data,
                        timeout=aiohttp.ClientTimeout(total=request.timeout)
                    ) as response:
                        status_code = response.status
                        response_headers = dict(response.headers)

                        if response.status == 429:  # Rate limited
                            self.metrics.rate_limit_hits += 1
                            if attempt < self.retry_attempts:
                                await asyncio.sleep(self.rate_limit_delay * (2 ** attempt))
                                continue

                        response_data = await response.json() if response.content_type == 'application/json' else await response.text()
                        success = 200 <= response.status < 300
                        break

                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    error_message = str(e)
                    if attempt < self.retry_attempts:
                        await asyncio.sleep(self.retry_delay * (2 ** attempt))
                        continue
                    break

        except Exception as e:
            error_message = str(e)

        # Update metrics
        request_time = time.time() - start_time
        self.metrics.total_requests += 1
        self.metrics.last_request_time = time.time()

        if success:
            self.metrics.successful_requests += 1
            self.metrics.average_response_time = (
                (self.metrics.average_response_time * (self.metrics.successful_requests - 1)) +
                request_time
            ) / self.metrics.successful_requests
        else:
            self.metrics.failed_requests += 1

        self.metrics.error_rate = self.metrics.failed_requests / self.metrics.total_requests

        # Create response
        api_response = APIResponse(
            status_code=status_code,
            headers=response_headers,
            data=response_data,
            request_time=request_time,
            success=success,
            error_message=error_message
        )

        # Store in history
        self.request_history.append((request, api_response))

        # Log request
        log_level = logging.INFO if success else logging.WARNING
        self.logger.log(log_level, f"API {method} {endpoint} - {status_code} ({request_time:.3f}s)")

        return api_response

    # Convenience methods for common HTTP methods
    async def get(self, endpoint: str, **kwargs) -> APIResponse:
        return await self.request(endpoint, "GET", **kwargs)

    async def post(self, endpoint: str, **kwargs) -> APIResponse:
        return await self.request(endpoint, "POST", **kwargs)

    async def put(self, endpoint: str, **kwargs) -> APIResponse:
        return await self.request(endpoint, "PUT", **kwargs)

    async def delete(self, endpoint: str, **kwargs) -> APIResponse:
        return await self.request(endpoint, "DELETE", **kwargs)

    async def patch(self, endpoint: str, **kwargs) -> APIResponse:
        return await self.request(endpoint, "PATCH", **kwargs)

    def get_metrics(self) -> APIMetrics:
        """Get API client metrics"""
        return self.metrics

    def get_request_history(self, limit: int = 10) -> List[Tuple[APIRequest, APIResponse]]:
        """Get recent request history"""
        return self.request_history[-limit:]


class WebSocketClient:
    """WebSocket client for real-time API communication"""

    def __init__(self, ws_url: str, config: Optional[Dict[str, Any]] = None):
        """
        Initialize WebSocket client

        Args:
            ws_url: WebSocket URL
            config: Client configuration
        """
        self.ws_url = ws_url
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Connection state
        self.websocket: Optional[websockets.WebSocketServerProtocol] = None
        self.connected = False

        # Message handling
        self.message_handlers: Dict[str, Callable] = {}
        self.event_handlers: Dict[str, Callable] = {}

        # Reconnection
        self.reconnect_attempts = self.config.get('reconnect_attempts', 5)
        self.reconnect_delay = self.config.get('reconnect_delay', 1.0)

        # Authentication
        self.auth_token = self.config.get('auth_token')

    async def connect(self):
        """Connect to WebSocket"""
        try:
            # Prepare headers for authentication
            extra_headers = {}
            if self.auth_token:
                extra_headers['Authorization'] = f'Bearer {self.auth_token}'

            self.websocket = await websockets.connect(
                self.ws_url,
                extra_headers=extra_headers,
                ping_interval=30,
                ping_timeout=10
            )
            self.connected = True
            self.logger.info(f"WebSocket connected to {self.ws_url}")

            # Start message handling
            asyncio.create_task(self._handle_messages())

        except Exception as e:
            self.logger.error(f"WebSocket connection failed: {e}")
            raise

    async def disconnect(self):
        """Disconnect from WebSocket"""
        if self.websocket:
            await self.websocket.close()
            self.websocket = None
        self.connected = False
        self.logger.info("WebSocket disconnected")

    async def send(self, message: Union[str, Dict[str, Any]]):
        """Send message via WebSocket"""
        if not self.connected or not self.websocket:
            raise ConnectionError("WebSocket not connected")

        if isinstance(message, dict):
            message = json.dumps(message)

        await self.websocket.send(message)
        self.logger.debug(f"WebSocket message sent: {message[:100]}...")

    async def subscribe(self, channel: str, callback: Callable):
        """Subscribe to channel"""
        self.event_handlers[channel] = callback
        await self.send({
            'type': 'subscribe',
            'channel': channel
        })

    async def unsubscribe(self, channel: str):
        """Unsubscribe from channel"""
        if channel in self.event_handlers:
            del self.event_handlers[channel]
        await self.send({
            'type': 'unsubscribe',
            'channel': channel
        })

    async def _handle_messages(self):
        """Handle incoming WebSocket messages"""
        try:
            async for message in self.websocket:
                try:
                    data = json.loads(message) if isinstance(message, str) else message

                    # Handle different message types
                    message_type = data.get('type', 'message')
                    if message_type == 'event':
                        await self._handle_event(data)
                    elif message_type in self.message_handlers:
                        await self.message_handlers[message_type](data)
                    else:
                        self.logger.debug(f"Unhandled message type: {message_type}")

                except json.JSONDecodeError:
                    self.logger.warning(f"Invalid JSON message: {message[:100]}...")
                except Exception as e:
                    self.logger.error(f"Message handling error: {e}")

        except websockets.exceptions.ConnectionClosed:
            self.logger.warning("WebSocket connection closed")
            self.connected = False
            # Attempt reconnection
            await self._reconnect()

    async def _handle_event(self, event_data: Dict[str, Any]):
        """Handle WebSocket event"""
        channel = event_data.get('channel')
        if channel and channel in self.event_handlers:
            try:
                await self.event_handlers[channel](event_data)
            except Exception as e:
                self.logger.error(f"Event handler error for channel {channel}: {e}")

    async def _reconnect(self):
        """Attempt to reconnect WebSocket"""
        for attempt in range(self.reconnect_attempts):
            try:
                self.logger.info(f"Reconnection attempt {attempt + 1}/{self.reconnect_attempts}")
                await asyncio.sleep(self.reconnect_delay * (2 ** attempt))
                await self.connect()
                self.logger.info("WebSocket reconnected successfully")
                return
            except Exception as e:
                self.logger.warning(f"Reconnection attempt {attempt + 1} failed: {e}")

        self.logger.error("Failed to reconnect WebSocket after all attempts")


class APIGateway:
    """API Gateway for managing multiple API clients and routing"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize API Gateway

        Args:
            config: Gateway configuration
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Client registry
        self.clients: Dict[str, APIClient] = {}
        self.websocket_clients: Dict[str, WebSocketClient] = {}

        # Route registry
        self.routes: Dict[str, Dict[str, Any]] = {}

        # Load balancing
        self.load_balancers: Dict[str, List[str]] = {}

        # Rate limiting
        self.rate_limiter = self._initialize_rate_limiter()

    def register_client(self, name: str, client: APIClient):
        """Register API client"""
        self.clients[name] = client
        self.logger.info(f"API client registered: {name}")

    def register_websocket_client(self, name: str, client: WebSocketClient):
        """Register WebSocket client"""
        self.websocket_clients[name] = client
        self.logger.info(f"WebSocket client registered: {name}")

    def add_route(
        self,
        path: str,
        target_client: str,
        target_endpoint: str,
        methods: List[str] = None,
        auth_required: bool = False,
        rate_limit: Optional[int] = None
    ):
        """Add API route"""
        self.routes[path] = {
            'client': target_client,
            'endpoint': target_endpoint,
            'methods': methods or ['GET'],
            'auth_required': auth_required,
            'rate_limit': rate_limit
        }
        self.logger.info(f"API route added: {path} -> {target_client}:{target_endpoint}")

    async def route_request(
        self,
        path: str,
        method: str = "GET",
        **kwargs
    ) -> APIResponse:
        """
        Route API request

        Args:
            path: Request path
            method: HTTP method
            **kwargs: Additional request parameters

        Returns:
            APIResponse: Response data
        """
        # Find matching route
        route_config = None
        for route_path, config in self.routes.items():
            if self._match_route(path, route_path) and method in config['methods']:
                route_config = config
                break

        if not route_config:
            return APIResponse(
                status_code=404,
                headers={},
                data={'error': 'Route not found'},
                request_time=0.0,
                success=False,
                error_message='Route not found'
            )

        # Get target client
        client_name = route_config['client']
        if client_name not in self.clients:
            return APIResponse(
                status_code=500,
                headers={},
                data={'error': 'Client not available'},
                request_time=0.0,
                success=False,
                error_message='Client not available'
            )

        client = self.clients[client_name]
        target_endpoint = route_config['endpoint']

        # Apply rate limiting
        if route_config.get('rate_limit'):
            if not self._check_rate_limit(path, route_config['rate_limit']):
                return APIResponse(
                    status_code=429,
                    headers={},
                    data={'error': 'Rate limit exceeded'},
                    request_time=0.0,
                    success=False,
                    error_message='Rate limit exceeded'
                )

        # Make request
        return await client.request(target_endpoint, method, **kwargs)

    def _match_route(self, request_path: str, route_path: str) -> bool:
        """Match request path with route pattern"""
        # Simple pattern matching - could be enhanced with regex
        if route_path.endswith('*'):
            return request_path.startswith(route_path[:-1])
        return request_path == route_path

    def _initialize_rate_limiter(self) -> Dict[str, Any]:
        """Initialize rate limiter"""
        return {
            'requests': {},
            'window_start': time.time(),
            'window_size': 60  # 1 minute window
        }

    def _check_rate_limit(self, path: str, limit: int) -> bool:
        """Check if request is within rate limit"""
        current_time = time.time()

        # Reset window if needed
        if current_time - self.rate_limiter['window_start'] > self.rate_limiter['window_size']:
            self.rate_limiter['requests'] = {}
            self.rate_limiter['window_start'] = current_time

        # Check request count
        request_count = self.rate_limiter['requests'].get(path, 0)
        if request_count >= limit:
            return False

        # Increment counter
        self.rate_limiter['requests'][path] = request_count + 1
        return True

    async def broadcast_websocket(self, channel: str, message: Dict[str, Any]):
        """Broadcast message to all WebSocket clients"""
        for client in self.websocket_clients.values():
            try:
                await client.send({
                    'type': 'broadcast',
                    'channel': channel,
                    'data': message
                })
            except Exception as e:
                self.logger.error(f"WebSocket broadcast error: {e}")

    def get_metrics(self) -> Dict[str, Any]:
        """Get gateway metrics"""
        metrics = {
            'clients': len(self.clients),
            'websocket_clients': len(self.websocket_clients),
            'routes': len(self.routes),
            'rate_limit_requests': sum(self.rate_limiter['requests'].values())
        }

        # Aggregate client metrics
        client_metrics = {}
        for name, client in self.clients.items():
            client_metrics[name] = {
                'total_requests': client.metrics.total_requests,
                'success_rate': client.metrics.successful_requests / max(client.metrics.total_requests, 1),
                'average_response_time': client.metrics.average_response_time
            }

        metrics['client_metrics'] = client_metrics
        return metrics


class APIDocumentationGenerator:
    """Automatic API documentation generator"""

    def __init__(self, gateway: APIGateway):
        """
        Initialize documentation generator

        Args:
            gateway: API Gateway instance
        """
        self.gateway = gateway
        self.logger = logging.getLogger(__name__)

    def generate_openapi_spec(self) -> Dict[str, Any]:
        """Generate OpenAPI specification"""
        spec = {
            'openapi': '3.0.3',
            'info': {
                'title': 'BLNCS Lightning Network API',
                'version': '1.0.0',
                'description': 'Comprehensive API for BLNCS Lightning Network operations'
            },
            'servers': [
                {
                    'url': 'https://api.blncs.example.com',
                    'description': 'Production server'
                }
            ],
            'paths': {},
            'components': {
                'securitySchemes': {
                    'ApiKeyAuth': {
                        'type': 'apiKey',
                        'in': 'header',
                        'name': 'X-API-Key'
                    },
                    'BearerAuth': {
                        'type': 'http',
                        'scheme': 'bearer'
                    }
                }
            }
        }

        # Generate paths from routes
        for path, route_config in self.gateway.routes.items():
            spec['paths'][path] = self._generate_path_spec(path, route_config)

        return spec

    def _generate_path_spec(self, path: str, route_config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate OpenAPI path specification"""
        path_spec = {}

        for method in route_config['methods']:
            method_spec = {
                'summary': f'{method.upper()} {path}',
                'description': f'API endpoint for {path}',
                'responses': {
                    '200': {
                        'description': 'Successful response',
                        'content': {
                            'application/json': {
                                'schema': {
                                    'type': 'object'
                                }
                            }
                        }
                    },
                    '400': {
                        'description': 'Bad request',
                        'content': {
                            'application/json': {
                                'schema': {
                                    'type': 'object',
                                    'properties': {
                                        'error': {'type': 'string'}
                                    }
                                }
                            }
                        }
                    },
                    '401': {
                        'description': 'Unauthorized',
                        'content': {
                            'application/json': {
                                'schema': {
                                    'type': 'object',
                                    'properties': {
                                        'error': {'type': 'string'}
                                    }
                                }
                            }
                        }
                    },
                    '429': {
                        'description': 'Rate limit exceeded',
                        'content': {
                            'application/json': {
                                'schema': {
                                    'type': 'object',
                                    'properties': {
                                        'error': {'type': 'string'}
                                    }
                                }
                            }
                        }
                    }
                }
            }

            # Add security if required
            if route_config.get('auth_required'):
                method_spec['security'] = [
                    {'ApiKeyAuth': []},
                    {'BearerAuth': []}
                ]

            path_spec[method.lower()] = method_spec

        return path_spec

    def generate_markdown_docs(self) -> str:
        """Generate Markdown documentation"""
        docs = [
            "# BLNCS API Documentation\n",
            "## Overview\n",
            "This document provides comprehensive API documentation for BLNCS Lightning Network operations.\n",
            f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
            "## Endpoints\n"
        ]

        for path, route_config in self.gateway.routes.items():
            docs.append(f"### {path}\n")
            docs.append(f"- **Methods**: {', '.join(route_config['methods'])}\n")
            docs.append(f"- **Authentication Required**: {route_config.get('auth_required', False)}\n")
            if route_config.get('rate_limit'):
                docs.append(f"- **Rate Limit**: {route_config['rate_limit']} requests per minute\n")
            docs.append("\n")

        return ''.join(docs)

    def export_documentation(self, format_type: str = 'markdown') -> str:
        """
        Export API documentation

        Args:
            format_type: Export format ('markdown' or 'openapi')

        Returns:
            Documentation as string
        """
        if format_type == 'markdown':
            return self.generate_markdown_docs()
        elif format_type == 'openapi':
            return json.dumps(self.generate_openapi_spec(), indent=2)
        else:
            raise ValueError(f"Unsupported documentation format: {format_type}")


# Global API gateway instance
_api_gateway = None

def get_api_gateway() -> APIGateway:
    """Get the global API gateway instance"""
    global _api_gateway
    if _api_gateway is None:
        _api_gateway = APIGateway()
    return _api_gateway
