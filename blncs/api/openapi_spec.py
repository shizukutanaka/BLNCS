"""
OpenAPI Specification Generator for BLNCS
Comprehensive API documentation with automatic schema generation.
"""

from typing import Dict, Any, List, Optional, Type, Union
from dataclasses import dataclass, field
from enum import Enum
import json
import yaml
from pathlib import Path
import inspect
from pydantic import BaseModel, Field

class HTTPMethod(str, Enum):
    """HTTP methods enum for API endpoints."""
    GET = "get"
    POST = "post"
    PUT = "put"
    DELETE = "delete"
    PATCH = "patch"
    HEAD = "head"
    OPTIONS = "options"

class SecurityScheme(str, Enum):
    """API security scheme types."""
    API_KEY = "apiKey"
    HTTP = "http"
    OAUTH2 = "oauth2"
    OPENID_CONNECT = "openIdConnect"

@dataclass
class ResponseModel:
    """API response model definition."""
    description: str
    schema: Optional[Type[BaseModel]] = None
    example: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, str]] = None

@dataclass
class EndpointSpec:
    """API endpoint specification."""
    path: str
    method: HTTPMethod
    summary: str
    description: str
    tags: List[str] = field(default_factory=list)
    request_body: Optional[Type[BaseModel]] = None
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    responses: Dict[int, ResponseModel] = field(default_factory=dict)
    security: List[Dict[str, List[str]]] = field(default_factory=list)
    deprecated: bool = False

class OpenAPIGenerator:
    """Comprehensive OpenAPI specification generator."""
    
    def __init__(self, title: str = "BLNCS API", version: str = "1.0.0"):
        """Initialize OpenAPI generator."""
        self.title = title
        self.version = version
        self.endpoints: List[EndpointSpec] = []
        self.models: Dict[str, Type[BaseModel]] = {}
        self.security_schemes: Dict[str, Dict[str, Any]] = {}
        
        # Default security schemes
        self.add_security_scheme("ApiKeyAuth", {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key"
        })
        
        self.add_security_scheme("BearerAuth", {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        })
    
    def add_security_scheme(self, name: str, scheme: Dict[str, Any]) -> None:
        """Add security scheme definition."""
        self.security_schemes[name] = scheme
    
    def add_endpoint(self, endpoint: EndpointSpec) -> None:
        """Add API endpoint specification."""
        self.endpoints.append(endpoint)
        
        # Auto-register models from endpoint
        if endpoint.request_body:
            self.models[endpoint.request_body.__name__] = endpoint.request_body
            
        for response in endpoint.responses.values():
            if response.schema:
                self.models[response.schema.__name__] = response.schema
    
    def register_model(self, model: Type[BaseModel]) -> None:
        """Register Pydantic model for schema generation."""
        self.models[model.__name__] = model
    
    def _generate_schema(self, model: Type[BaseModel]) -> Dict[str, Any]:
        """Generate JSON schema from Pydantic model."""
        if hasattr(model, 'model_json_schema'):
            return model.model_json_schema()
        elif hasattr(model, 'schema'):
            return model.schema()
        else:
            # Fallback for older Pydantic versions
            return {"type": "object"}
    
    def _generate_paths(self) -> Dict[str, Dict[str, Any]]:
        """Generate OpenAPI paths specification."""
        paths = {}
        
        for endpoint in self.endpoints:
            if endpoint.path not in paths:
                paths[endpoint.path] = {}
            
            operation = {
                "summary": endpoint.summary,
                "description": endpoint.description,
                "tags": endpoint.tags,
                "responses": {}
            }
            
            # Add parameters
            if endpoint.parameters:
                operation["parameters"] = endpoint.parameters
            
            # Add request body
            if endpoint.request_body:
                operation["requestBody"] = {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": f"#/components/schemas/{endpoint.request_body.__name__}"}
                        }
                    }
                }
            
            # Add responses
            for status_code, response in endpoint.responses.items():
                response_spec = {"description": response.description}
                
                if response.schema:
                    response_spec["content"] = {
                        "application/json": {
                            "schema": {"$ref": f"#/components/schemas/{response.schema.__name__}"}
                        }
                    }
                    
                if response.example:
                    if "content" not in response_spec:
                        response_spec["content"] = {"application/json": {}}
                    response_spec["content"]["application/json"]["example"] = response.example
                    
                if response.headers:
                    response_spec["headers"] = response.headers
                    
                operation["responses"][str(status_code)] = response_spec
            
            # Add security
            if endpoint.security:
                operation["security"] = endpoint.security
            
            # Add deprecation
            if endpoint.deprecated:
                operation["deprecated"] = True
            
            paths[endpoint.path][endpoint.method.value] = operation
        
        return paths
    
    def _generate_components(self) -> Dict[str, Any]:
        """Generate OpenAPI components specification."""
        components = {
            "schemas": {},
            "securitySchemes": self.security_schemes
        }
        
        # Generate schemas for all registered models
        for name, model in self.models.items():
            components["schemas"][name] = self._generate_schema(model)
        
        return components
    
    def generate_spec(self) -> Dict[str, Any]:
        """Generate complete OpenAPI specification."""
        spec = {
            "openapi": "3.0.3",
            "info": {
                "title": self.title,
                "version": self.version,
                "description": "Comprehensive API for Bitcoin Lightning Network Control System",
                "contact": {
                    "name": "BLNCS Development Team",
                    "email": "dev@blncs.org"
                },
                "license": {
                    "name": "MIT",
                    "url": "https://opensource.org/licenses/MIT"
                }
            },
            "servers": [
                {
                    "url": "https://api.blncs.org/v1",
                    "description": "Production server"
                },
                {
                    "url": "http://localhost:8000/v1",
                    "description": "Development server"
                }
            ],
            "paths": self._generate_paths(),
            "components": self._generate_components()
        }
        
        return spec
    
    def export_json(self, file_path: Union[str, Path]) -> None:
        """Export OpenAPI specification as JSON."""
        spec = self.generate_spec()
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(spec, f, indent=2, ensure_ascii=False)
    
    def export_yaml(self, file_path: Union[str, Path]) -> None:
        """Export OpenAPI specification as YAML."""
        spec = self.generate_spec()
        with open(file_path, 'w', encoding='utf-8') as f:
            yaml.dump(spec, f, default_flow_style=False, allow_unicode=True)

# Predefined API models
class HealthCheckResponse(BaseModel):
    """Health check response model."""
    status: str = Field(..., description="Health status")
    timestamp: str = Field(..., description="Check timestamp")
    version: str = Field(..., description="API version")
    uptime_seconds: int = Field(..., description="Uptime in seconds")
    dependencies: Dict[str, str] = Field(..., description="Dependency status")

class ErrorResponse(BaseModel):
    """Standard error response model."""
    error: str = Field(..., description="Error code")
    message: str = Field(..., description="Human readable error message")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")
    timestamp: str = Field(..., description="Error timestamp")
    request_id: Optional[str] = Field(None, description="Request tracking ID")

class LightningNodeInfo(BaseModel):
    """Lightning node information model."""
    node_id: str = Field(..., description="Node public key")
    alias: str = Field(..., description="Node alias")
    color: str = Field(..., description="Node color")
    addresses: List[str] = Field(..., description="Node network addresses")
    features: Dict[str, bool] = Field(..., description="Node feature flags")
    version: str = Field(..., description="Node software version")
    block_height: int = Field(..., description="Current block height")
    synced_to_chain: bool = Field(..., description="Chain synchronization status")

class ChannelInfo(BaseModel):
    """Channel information model."""
    channel_id: str = Field(..., description="Channel ID")
    remote_pubkey: str = Field(..., description="Remote node public key")
    capacity: int = Field(..., description="Channel capacity in satoshis")
    local_balance: int = Field(..., description="Local balance in satoshis")
    remote_balance: int = Field(..., description="Remote balance in satoshis")
    active: bool = Field(..., description="Channel active status")
    private: bool = Field(..., description="Channel privacy setting")
    fee_rate: Optional[int] = Field(None, description="Fee rate in milli-satoshis")

class PaymentRequest(BaseModel):
    """Payment request model."""
    amount_sat: int = Field(..., description="Payment amount in satoshis", gt=0)
    description: str = Field(..., description="Payment description", max_length=639)
    expiry_seconds: Optional[int] = Field(3600, description="Invoice expiry in seconds")
    private_hints: bool = Field(False, description="Include private routing hints")

class PaymentResponse(BaseModel):
    """Payment response model."""
    payment_hash: str = Field(..., description="Payment hash")
    payment_request: str = Field(..., description="Encoded payment request")
    amount_sat: int = Field(..., description="Payment amount in satoshis")
    expiry_timestamp: str = Field(..., description="Payment expiry timestamp")

class SystemMetrics(BaseModel):
    """System metrics model."""
    cpu_usage_percent: float = Field(..., description="CPU usage percentage")
    memory_usage_percent: float = Field(..., description="Memory usage percentage")
    disk_usage_percent: float = Field(..., description="Disk usage percentage")
    network_connections: int = Field(..., description="Active network connections")
    lightning_channels: int = Field(..., description="Number of Lightning channels")
    total_capacity_sat: int = Field(..., description="Total channel capacity in satoshis")

def create_blncs_api_spec() -> OpenAPIGenerator:
    """Create comprehensive BLNCS API specification."""
    api = OpenAPIGenerator("BLNCS API", "1.0.0")
    
    # Register common models
    api.register_model(HealthCheckResponse)
    api.register_model(ErrorResponse)
    api.register_model(LightningNodeInfo)
    api.register_model(ChannelInfo)
    api.register_model(PaymentRequest)
    api.register_model(PaymentResponse)
    api.register_model(SystemMetrics)
    
    # Health check endpoint
    api.add_endpoint(EndpointSpec(
        path="/health",
        method=HTTPMethod.GET,
        summary="Health Check",
        description="Get system health status and basic information",
        tags=["Health"],
        responses={
            200: ResponseModel(
                description="Health check successful",
                schema=HealthCheckResponse,
                example={
                    "status": "healthy",
                    "timestamp": "2024-01-01T00:00:00Z",
                    "version": "1.0.0",
                    "uptime_seconds": 86400,
                    "dependencies": {
                        "database": "healthy",
                        "lightning": "healthy",
                        "cache": "healthy"
                    }
                }
            ),
            503: ResponseModel(
                description="Service unavailable",
                schema=ErrorResponse
            )
        }
    ))
    
    # Node information endpoint
    api.add_endpoint(EndpointSpec(
        path="/node/info",
        method=HTTPMethod.GET,
        summary="Get Node Information",
        description="Retrieve Lightning node information and status",
        tags=["Node"],
        security=[{"BearerAuth": []}],
        responses={
            200: ResponseModel(
                description="Node information retrieved successfully",
                schema=LightningNodeInfo
            ),
            401: ResponseModel(
                description="Unauthorized",
                schema=ErrorResponse
            ),
            500: ResponseModel(
                description="Internal server error",
                schema=ErrorResponse
            )
        }
    ))
    
    # List channels endpoint
    api.add_endpoint(EndpointSpec(
        path="/channels",
        method=HTTPMethod.GET,
        summary="List Channels",
        description="Get list of Lightning channels with details",
        tags=["Channels"],
        security=[{"BearerAuth": []}],
        parameters=[
            {
                "name": "active_only",
                "in": "query",
                "description": "Filter for active channels only",
                "required": False,
                "schema": {"type": "boolean", "default": False}
            },
            {
                "name": "limit",
                "in": "query",
                "description": "Maximum number of channels to return",
                "required": False,
                "schema": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100}
            }
        ],
        responses={
            200: ResponseModel(
                description="Channels retrieved successfully",
                schema=ChannelInfo
            ),
            401: ResponseModel(
                description="Unauthorized",
                schema=ErrorResponse
            ),
            500: ResponseModel(
                description="Internal server error",
                schema=ErrorResponse
            )
        }
    ))
    
    # Create payment request endpoint
    api.add_endpoint(EndpointSpec(
        path="/payments/request",
        method=HTTPMethod.POST,
        summary="Create Payment Request",
        description="Generate a new Lightning payment request (invoice)",
        tags=["Payments"],
        security=[{"BearerAuth": []}],
        request_body=PaymentRequest,
        responses={
            201: ResponseModel(
                description="Payment request created successfully",
                schema=PaymentResponse
            ),
            400: ResponseModel(
                description="Invalid request data",
                schema=ErrorResponse
            ),
            401: ResponseModel(
                description="Unauthorized",
                schema=ErrorResponse
            ),
            500: ResponseModel(
                description="Internal server error",
                schema=ErrorResponse
            )
        }
    ))
    
    # System metrics endpoint
    api.add_endpoint(EndpointSpec(
        path="/metrics",
        method=HTTPMethod.GET,
        summary="Get System Metrics",
        description="Retrieve system performance and Lightning network metrics",
        tags=["Metrics"],
        security=[{"ApiKeyAuth": []}],
        responses={
            200: ResponseModel(
                description="Metrics retrieved successfully",
                schema=SystemMetrics
            ),
            401: ResponseModel(
                description="Unauthorized",
                schema=ErrorResponse
            ),
            500: ResponseModel(
                description="Internal server error",
                schema=ErrorResponse
            )
        }
    ))
    
    return api

if __name__ == "__main__":
    # Generate and export API specification
    api = create_blncs_api_spec()
    
    # Export as JSON and YAML
    api.export_json("openapi.json")
    api.export_yaml("openapi.yaml")
    
    print("OpenAPI specification generated successfully!")
    print("Files created: openapi.json, openapi.yaml")