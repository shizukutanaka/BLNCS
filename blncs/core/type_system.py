"""
Comprehensive Type Safety System
Enterprise-grade type system with generics, protocols, and runtime validation.
"""

from typing import (
    TypeVar, Generic, Protocol, runtime_checkable, Union, Optional, 
    Any, Dict, List, Set, Tuple, Callable, Type, get_type_hints,
    get_origin, get_args, Literal, Final, ClassVar, overload
)
from typing_extensions import ParamSpec, TypeGuard, Self
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
import inspect
import functools
import logging
from datetime import datetime, timezone
from decimal import Decimal
import uuid
import asyncio
from collections.abc import Awaitable, Coroutine

from ..core.structured_logging import StructuredLogger

# Type Variables
T = TypeVar('T')
U = TypeVar('U')
K = TypeVar('K')
V = TypeVar('V')
P = ParamSpec('P')

# Domain-specific type variables
NodeT = TypeVar('NodeT', bound='LightningNode')
ChannelT = TypeVar('ChannelT', bound='Channel')
PaymentT = TypeVar('PaymentT', bound='Payment')
InvoiceT = TypeVar('InvoiceT', bound='Invoice')

# Numeric types
Satoshis = int
Millisatoshis = int
PPM = int  # Parts per million
Percentage = float  # 0.0 to 100.0


class ValidationError(Exception):
    """Type validation error."""
    def __init__(self, message: str, field_name: str = "", expected_type: str = "", actual_value: Any = None):
        self.field_name = field_name
        self.expected_type = expected_type
        self.actual_value = actual_value
        super().__init__(message)


class TypeSafetyLevel(Enum):
    """Type safety enforcement levels."""
    STRICT = "strict"      # Full runtime validation
    LENIENT = "lenient"    # Basic validation with warnings
    DISABLED = "disabled"  # Type hints only, no runtime checks


@dataclass(frozen=True)
class TypeConstraint:
    """Type constraint specification."""
    min_value: Optional[Union[int, float, Decimal]] = None
    max_value: Optional[Union[int, float, Decimal]] = None
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    regex_pattern: Optional[str] = None
    allowed_values: Optional[Set[Any]] = None
    custom_validator: Optional[Callable[[Any], bool]] = None
    error_message: Optional[str] = None


# Lightning Network specific constraints
CONSTRAINTS = {
    'node_pubkey': TypeConstraint(
        min_length=66, max_length=66,
        regex_pattern=r'^[0-9a-fA-F]{66}$',
        error_message="Node pubkey must be 66 character hex string"
    ),
    'channel_id': TypeConstraint(
        min_length=18, max_length=20,
        regex_pattern=r'^\d+$',
        error_message="Channel ID must be numeric string"
    ),
    'payment_hash': TypeConstraint(
        min_length=64, max_length=64,
        regex_pattern=r'^[0-9a-fA-F]{64}$',
        error_message="Payment hash must be 64 character hex string"
    ),
    'satoshis': TypeConstraint(
        min_value=0, max_value=21_000_000 * 100_000_000,
        error_message="Satoshi amount must be between 0 and 2.1 quadrillion"
    ),
    'millisatoshis': TypeConstraint(
        min_value=0, max_value=21_000_000 * 100_000_000 * 1000,
        error_message="Millisatoshi amount must be between 0 and 2.1 * 10^15"
    ),
    'ppm': TypeConstraint(
        min_value=0, max_value=1_000_000,
        error_message="PPM must be between 0 and 1,000,000"
    ),
    'percentage': TypeConstraint(
        min_value=0.0, max_value=100.0,
        error_message="Percentage must be between 0.0 and 100.0"
    )
}


@runtime_checkable
class Validatable(Protocol):
    """Protocol for objects that can be validated."""
    
    def validate(self) -> bool:
        """Validate object state."""
        ...
    
    def get_validation_errors(self) -> List[str]:
        """Get validation error messages."""
        ...


@runtime_checkable
class Serializable(Protocol[T]):
    """Protocol for serializable objects."""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        ...
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> T:
        """Create from dictionary."""
        ...


@runtime_checkable
class AsyncResource(Protocol):
    """Protocol for async resources that need cleanup."""
    
    async def close(self) -> None:
        """Close/cleanup the resource."""
        ...
    
    def is_closed(self) -> bool:
        """Check if resource is closed."""
        ...


@runtime_checkable
class Repository(Protocol[T]):
    """Generic repository protocol."""
    
    async def save(self, entity: T) -> T:
        """Save entity."""
        ...
    
    async def find_by_id(self, entity_id: str) -> Optional[T]:
        """Find entity by ID."""
        ...
    
    async def find_all(self) -> List[T]:
        """Find all entities."""
        ...
    
    async def delete(self, entity_id: str) -> bool:
        """Delete entity."""
        ...


@runtime_checkable
class EventHandler(Protocol[T]):
    """Protocol for event handlers."""
    
    async def handle(self, event: T) -> None:
        """Handle event."""
        ...
    
    def can_handle(self, event_type: Type[T]) -> bool:
        """Check if can handle event type."""
        ...


class TypeValidator:
    """Runtime type validator with constraint checking."""
    
    def __init__(self, safety_level: TypeSafetyLevel = TypeSafetyLevel.STRICT):
        self.safety_level = safety_level
        self.logger = StructuredLogger("type_validator")
        self._cache: Dict[str, bool] = {}
    
    def validate_type(self, value: Any, expected_type: Type[T], 
                     constraint_name: Optional[str] = None) -> TypeGuard[T]:
        """Validate value against expected type with constraints."""
        if self.safety_level == TypeSafetyLevel.DISABLED:
            return True
            
        # Cache key for performance
        cache_key = f"{type(value).__name__}:{expected_type}:{constraint_name}"
        if cache_key in self._cache:
            return self._cache[cache_key]
            
        try:
            # Basic type checking
            if not self._check_type_compatibility(value, expected_type):
                raise ValidationError(
                    f"Type mismatch: expected {expected_type}, got {type(value)}",
                    expected_type=str(expected_type),
                    actual_value=value
                )
            
            # Constraint validation
            if constraint_name and constraint_name in CONSTRAINTS:
                constraint = CONSTRAINTS[constraint_name]
                if not self._validate_constraint(value, constraint):
                    error_msg = constraint.error_message or f"Constraint violation for {constraint_name}"
                    raise ValidationError(error_msg, field_name=constraint_name, actual_value=value)
            
            # Protocol checking
            if hasattr(expected_type, '__protocol__'):
                if not isinstance(value, expected_type):
                    raise ValidationError(
                        f"Protocol violation: {type(value)} does not implement {expected_type}"
                    )
            
            self._cache[cache_key] = True
            return True
            
        except ValidationError as e:
            if self.safety_level == TypeSafetyLevel.STRICT:
                raise
            else:
                self.logger.warning("Type validation failed", extra={
                    'error': str(e),
                    'expected_type': str(expected_type),
                    'actual_type': str(type(value))
                })
                return False
    
    def _check_type_compatibility(self, value: Any, expected_type: Type) -> bool:
        """Check if value is compatible with expected type."""
        # Handle None values
        origin = get_origin(expected_type)
        if origin is Union:
            # Handle Optional[T] and Union types
            args = get_args(expected_type)
            return any(self._check_single_type(value, arg) for arg in args)
        
        return self._check_single_type(value, expected_type)
    
    def _check_single_type(self, value: Any, expected_type: Type) -> bool:
        """Check single type compatibility."""
        if value is None:
            return expected_type is type(None)
        
        # Handle generic types
        origin = get_origin(expected_type)
        if origin:
            if origin is list and isinstance(value, list):
                args = get_args(expected_type)
                if args:
                    return all(self._check_single_type(item, args[0]) for item in value)
                return True
            elif origin is dict and isinstance(value, dict):
                args = get_args(expected_type)
                if len(args) == 2:
                    key_type, value_type = args
                    return (all(self._check_single_type(k, key_type) for k in value.keys()) and
                            all(self._check_single_type(v, value_type) for v in value.values()))
                return True
            elif origin is set and isinstance(value, set):
                args = get_args(expected_type)
                if args:
                    return all(self._check_single_type(item, args[0]) for item in value)
                return True
        
        # Basic isinstance check
        try:
            return isinstance(value, expected_type)
        except TypeError:
            # Handle cases where isinstance doesn't work (e.g., with some generics)
            return True
    
    def _validate_constraint(self, value: Any, constraint: TypeConstraint) -> bool:
        """Validate value against constraint."""
        # Numeric constraints
        if constraint.min_value is not None:
            if not isinstance(value, (int, float, Decimal)) or value < constraint.min_value:
                return False
                
        if constraint.max_value is not None:
            if not isinstance(value, (int, float, Decimal)) or value > constraint.max_value:
                return False
        
        # String/sequence length constraints
        if constraint.min_length is not None:
            if not hasattr(value, '__len__') or len(value) < constraint.min_length:
                return False
                
        if constraint.max_length is not None:
            if not hasattr(value, '__len__') or len(value) > constraint.max_length:
                return False
        
        # Regex pattern validation
        if constraint.regex_pattern is not None:
            import re
            if not isinstance(value, str) or not re.match(constraint.regex_pattern, value):
                return False
        
        # Allowed values check
        if constraint.allowed_values is not None:
            if value not in constraint.allowed_values:
                return False
        
        # Custom validator
        if constraint.custom_validator is not None:
            if not constraint.custom_validator(value):
                return False
        
        return True
    
    def validate_dict(self, data: Dict[str, Any], schema: Dict[str, Type]) -> Dict[str, Any]:
        """Validate dictionary against schema."""
        validated = {}
        
        for key, expected_type in schema.items():
            if key in data:
                value = data[key]
                if self.validate_type(value, expected_type, key):
                    validated[key] = value
            elif not self._is_optional_type(expected_type):
                raise ValidationError(f"Required field '{key}' is missing")
        
        return validated
    
    def _is_optional_type(self, type_hint: Type) -> bool:
        """Check if type hint represents an optional value."""
        origin = get_origin(type_hint)
        if origin is Union:
            args = get_args(type_hint)
            return type(None) in args
        return False


def typed(safety_level: TypeSafetyLevel = TypeSafetyLevel.STRICT):
    """Decorator for runtime type checking of functions."""
    
    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        if safety_level == TypeSafetyLevel.DISABLED:
            return func
            
        validator = TypeValidator(safety_level)
        signature = inspect.signature(func)
        type_hints = get_type_hints(func)
        
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            # Validate parameters
            bound_args = signature.bind(*args, **kwargs)
            bound_args.apply_defaults()
            
            for param_name, value in bound_args.arguments.items():
                if param_name in type_hints:
                    expected_type = type_hints[param_name]
                    constraint_name = param_name if param_name in CONSTRAINTS else None
                    validator.validate_type(value, expected_type, constraint_name)
            
            # Execute function
            result = func(*args, **kwargs)
            
            # Validate return type
            if 'return' in type_hints:
                return_type = type_hints['return']
                validator.validate_type(result, return_type)
            
            return result
        
        @functools.wraps(func)
        async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            # Validate parameters (same as sync version)
            bound_args = signature.bind(*args, **kwargs)
            bound_args.apply_defaults()
            
            for param_name, value in bound_args.arguments.items():
                if param_name in type_hints:
                    expected_type = type_hints[param_name]
                    constraint_name = param_name if param_name in CONSTRAINTS else None
                    validator.validate_type(value, expected_type, constraint_name)
            
            # Execute async function
            result = await func(*args, **kwargs)
            
            # Validate return type
            if 'return' in type_hints:
                return_type = type_hints['return']
                # Handle Awaitable return types
                origin = get_origin(return_type)
                if origin in (Awaitable, Coroutine):
                    args = get_args(return_type)
                    if args:
                        validator.validate_type(result, args[-1])  # Last arg is the result type
                else:
                    validator.validate_type(result, return_type)
            
            return result
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else wrapper
    
    return decorator


@dataclass
class TypedField(Generic[T]):
    """Typed field with runtime validation."""
    value: T
    constraint_name: Optional[str] = None
    _validator: ClassVar[TypeValidator] = TypeValidator()
    
    def __post_init__(self):
        if hasattr(self, '__orig_class__'):
            # Extract the generic type parameter
            args = get_args(self.__orig_class__)
            if args:
                expected_type = args[0]
                self._validator.validate_type(self.value, expected_type, self.constraint_name)
    
    def set(self, new_value: T) -> None:
        """Set new value with validation."""
        if hasattr(self, '__orig_class__'):
            args = get_args(self.__orig_class__)
            if args:
                expected_type = args[0]
                self._validator.validate_type(new_value, expected_type, self.constraint_name)
        
        object.__setattr__(self, 'value', new_value)
    
    def get(self) -> T:
        """Get the value."""
        return self.value


class TypedConfig(Generic[T]):
    """Configuration class with typed fields."""
    
    def __init__(self, config_dict: Dict[str, Any], schema: Dict[str, Type]):
        self._validator = TypeValidator(TypeSafetyLevel.STRICT)
        self._schema = schema
        self._config = self._validator.validate_dict(config_dict, schema)
    
    def get(self, key: str, default: T = None) -> T:
        """Get configuration value with type safety."""
        if key not in self._schema:
            raise KeyError(f"Unknown configuration key: {key}")
        
        value = self._config.get(key, default)
        expected_type = self._schema[key]
        
        if value is not None:
            self._validator.validate_type(value, expected_type, key)
        
        return value
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value with validation."""
        if key not in self._schema:
            raise KeyError(f"Unknown configuration key: {key}")
        
        expected_type = self._schema[key]
        self._validator.validate_type(value, expected_type, key)
        self._config[key] = value
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return self._config.copy()


# Specialized Lightning Network types
class NodePubKey(str):
    """Lightning node public key with validation."""
    
    def __new__(cls, value: str) -> Self:
        validator = TypeValidator()
        if not validator.validate_type(value, str, 'node_pubkey'):
            raise ValidationError("Invalid node public key format")
        return super().__new__(cls, value)


class ChannelIdStr(str):
    """Channel ID string with validation."""
    
    def __new__(cls, value: str) -> Self:
        validator = TypeValidator()
        if not validator.validate_type(value, str, 'channel_id'):
            raise ValidationError("Invalid channel ID format")
        return super().__new__(cls, value)


class PaymentHashStr(str):
    """Payment hash string with validation."""
    
    def __new__(cls, value: str) -> Self:
        validator = TypeValidator()
        if not validator.validate_type(value, str, 'payment_hash'):
            raise ValidationError("Invalid payment hash format")
        return super().__new__(cls, value)


class SatoshiAmount(int):
    """Satoshi amount with validation."""
    
    def __new__(cls, value: int) -> Self:
        validator = TypeValidator()
        if not validator.validate_type(value, int, 'satoshis'):
            raise ValidationError("Invalid satoshi amount")
        return super().__new__(cls, value)
    
    def to_btc(self) -> Decimal:
        """Convert to BTC."""
        return Decimal(self) / Decimal('100000000')
    
    def to_msat(self) -> int:
        """Convert to millisatoshis."""
        return self * 1000


class PPMRate(int):
    """Parts per million rate with validation."""
    
    def __new__(cls, value: int) -> Self:
        validator = TypeValidator()
        if not validator.validate_type(value, int, 'ppm'):
            raise ValidationError("Invalid PPM rate")
        return super().__new__(cls, value)
    
    def to_percentage(self) -> float:
        """Convert to percentage."""
        return float(self) / 10000.0


# Result types for better error handling
@dataclass(frozen=True)
class Success(Generic[T]):
    """Successful result."""
    value: T
    
    def is_success(self) -> bool:
        return True
    
    def is_error(self) -> bool:
        return False
    
    def unwrap(self) -> T:
        return self.value
    
    def unwrap_or(self, default: U) -> T:
        return self.value


@dataclass(frozen=True) 
class Error(Generic[T]):
    """Error result."""
    error: Exception
    context: Optional[Dict[str, Any]] = None
    
    def is_success(self) -> bool:
        return False
    
    def is_error(self) -> bool:
        return True
    
    def unwrap(self) -> T:
        raise self.error
    
    def unwrap_or(self, default: U) -> U:
        return default


Result = Union[Success[T], Error[T]]


def create_result(func: Callable[P, T]) -> Callable[P, Result[T]]:
    """Decorator to wrap function results in Result type."""
    
    @functools.wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> Result[T]:
        try:
            result = func(*args, **kwargs)
            return Success(result)
        except Exception as e:
            return Error(e, {'args': args, 'kwargs': kwargs})
    
    @functools.wraps(func)
    async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> Result[T]:
        try:
            result = await func(*args, **kwargs)
            return Success(result)
        except Exception as e:
            return Error(e, {'args': args, 'kwargs': kwargs})
    
    return async_wrapper if asyncio.iscoroutinefunction(func) else wrapper


# Global type validator instance
_global_validator: Optional[TypeValidator] = None


def get_type_validator() -> TypeValidator:
    """Get global type validator instance."""
    global _global_validator
    if _global_validator is None:
        _global_validator = TypeValidator(TypeSafetyLevel.STRICT)
    return _global_validator


def set_type_safety_level(level: TypeSafetyLevel) -> None:
    """Set global type safety level."""
    global _global_validator
    _global_validator = TypeValidator(level)