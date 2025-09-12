#!/usr/bin/env python3
"""
BLNCS API Response Handlers
Standardized response formatting for consistent API responses.
"""

from flask import jsonify, Response
from datetime import datetime
from typing import Any, Dict, Optional, Union
import logging

logger = logging.getLogger(__name__)

class APIResponse:
    """Standardized API response class"""
    
    def __init__(self, 
                 success: bool = True,
                 data: Any = None,
                 message: str = None,
                 error_code: str = None,
                 status_code: int = 200,
                 metadata: Dict[str, Any] = None):
        self.success = success
        self.data = data
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.metadata = metadata or {}
        self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert response to dictionary"""
        response = {
            'success': self.success,
            'timestamp': self.timestamp,
        }
        
        if self.data is not None:
            response['data'] = self.data
        
        if self.message:
            response['message'] = self.message
        
        if not self.success:
            response['error'] = {
                'message': self.message or 'An error occurred',
                'code': self.error_code,
            }
        
        if self.metadata:
            response['metadata'] = self.metadata
        
        return response
    
    def to_flask_response(self) -> Response:
        """Convert to Flask response object"""
        response = jsonify(self.to_dict())
        response.status_code = self.status_code
        
        # Add standard headers
        response.headers['Content-Type'] = 'application/json'
        response.headers['X-API-Version'] = '2.0.0'
        
        return response

def success_response(data: Any = None, 
                    message: str = None,
                    status_code: int = 200,
                    metadata: Dict[str, Any] = None) -> Response:
    """Create successful API response"""
    response = APIResponse(
        success=True,
        data=data,
        message=message,
        status_code=status_code,
        metadata=metadata
    )
    return response.to_flask_response()

def error_response(message: str = "An error occurred",
                  status_code: int = 400,
                  error_code: str = None,
                  data: Any = None,
                  metadata: Dict[str, Any] = None) -> Response:
    """Create error API response"""
    response = APIResponse(
        success=False,
        message=message,
        error_code=error_code,
        status_code=status_code,
        data=data,
        metadata=metadata
    )
    return response.to_flask_response()

def validation_error_response(errors: Dict[str, Any],
                             message: str = "Validation failed") -> Response:
    """Create validation error response"""
    return error_response(
        message=message,
        status_code=422,
        error_code="VALIDATION_ERROR",
        data={'validation_errors': errors}
    )

def not_found_response(resource: str = "Resource") -> Response:
    """Create not found response"""
    return error_response(
        message=f"{resource} not found",
        status_code=404,
        error_code="NOT_FOUND"
    )

def unauthorized_response(message: str = "Unauthorized") -> Response:
    """Create unauthorized response"""
    return error_response(
        message=message,
        status_code=401,
        error_code="UNAUTHORIZED"
    )

def forbidden_response(message: str = "Forbidden") -> Response:
    """Create forbidden response"""
    return error_response(
        message=message,
        status_code=403,
        error_code="FORBIDDEN"
    )

def server_error_response(message: str = "Internal server error") -> Response:
    """Create server error response"""
    return error_response(
        message=message,
        status_code=500,
        error_code="INTERNAL_ERROR"
    )

def rate_limit_response(limit: int, reset_time: int) -> Response:
    """Create rate limit exceeded response"""
    return error_response(
        message="Rate limit exceeded",
        status_code=429,
        error_code="RATE_LIMIT_EXCEEDED",
        metadata={
            'rate_limit': {
                'limit': limit,
                'reset_time': reset_time
            }
        }
    )

def paginated_response(data: list,
                      page: int,
                      per_page: int,
                      total: int,
                      message: str = None) -> Response:
    """Create paginated response"""
    total_pages = (total + per_page - 1) // per_page
    has_next = page < total_pages
    has_prev = page > 1
    
    metadata = {
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'total_pages': total_pages,
            'has_next': has_next,
            'has_prev': has_prev
        }
    }
    
    if has_next:
        metadata['pagination']['next_page'] = page + 1
    if has_prev:
        metadata['pagination']['prev_page'] = page - 1
    
    return success_response(
        data=data,
        message=message,
        metadata=metadata
    )

def operation_response(operation: str,
                      success: bool,
                      result: Any = None,
                      message: str = None,
                      duration: float = None) -> Response:
    """Create operation result response"""
    metadata = {'operation': operation}
    
    if duration is not None:
        metadata['duration_seconds'] = round(duration, 3)
    
    if success:
        return success_response(
            data=result,
            message=message or f"{operation.title()} completed successfully",
            metadata=metadata
        )
    else:
        return error_response(
            message=message or f"{operation.title()} failed",
            status_code=500,
            error_code="OPERATION_FAILED",
            data=result,
            metadata=metadata
        )

def async_operation_response(operation_id: str,
                            operation: str,
                            status: str = "started",
                            estimated_duration: float = None) -> Response:
    """Create asynchronous operation response"""
    data = {
        'operation_id': operation_id,
        'operation': operation,
        'status': status,
        'started_at': datetime.now().isoformat()
    }
    
    if estimated_duration:
        data['estimated_duration_seconds'] = estimated_duration
        estimated_completion = datetime.now().timestamp() + estimated_duration
        data['estimated_completion'] = datetime.fromtimestamp(estimated_completion).isoformat()
    
    return success_response(
        data=data,
        message=f"{operation.title()} started",
        status_code=202
    )

def health_check_response(healthy: bool,
                         checks: Dict[str, Any] = None,
                         version: str = None) -> Response:
    """Create health check response"""
    status_code = 200 if healthy else 503
    
    data = {
        'status': 'healthy' if healthy else 'unhealthy',
        'timestamp': datetime.now().isoformat()
    }
    
    if version:
        data['version'] = version
    
    if checks:
        data['checks'] = checks
    
    return success_response(
        data=data,
        message="Health check completed",
        status_code=status_code
    )

def metrics_response(metrics: Dict[str, Any],
                    period: str = None,
                    labels: Dict[str, str] = None) -> Response:
    """Create metrics response"""
    metadata = {}
    
    if period:
        metadata['period'] = period
    
    if labels:
        metadata['labels'] = labels
    
    return success_response(
        data=metrics,
        message="Metrics retrieved successfully",
        metadata=metadata
    )

class ResponseBuilder:
    """Builder pattern for complex responses"""
    
    def __init__(self):
        self.reset()
    
    def reset(self):
        """Reset builder state"""
        self._success = True
        self._data = None
        self._message = None
        self._error_code = None
        self._status_code = 200
        self._metadata = {}
        return self
    
    def success(self, success: bool = True):
        """Set success status"""
        self._success = success
        return self
    
    def data(self, data: Any):
        """Set response data"""
        self._data = data
        return self
    
    def message(self, message: str):
        """Set response message"""
        self._message = message
        return self
    
    def error_code(self, code: str):
        """Set error code"""
        self._error_code = code
        return self
    
    def status_code(self, code: int):
        """Set HTTP status code"""
        self._status_code = code
        return self
    
    def metadata(self, key: str, value: Any):
        """Add metadata"""
        self._metadata[key] = value
        return self
    
    def build(self) -> Response:
        """Build final response"""
        response = APIResponse(
            success=self._success,
            data=self._data,
            message=self._message,
            error_code=self._error_code,
            status_code=self._status_code,
            metadata=self._metadata
        )
        return response.to_flask_response()

# Global response builder instance
response_builder = ResponseBuilder()