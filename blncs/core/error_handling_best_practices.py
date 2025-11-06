#!/usr/bin/env python3
"""
Error Handling Best Practices for BLNCS
Implements 2024 best practices for exception handling
"""

import logging
import traceback
from typing import Optional, Callable, Any, Type, TypeVar, Tuple
from contextlib import contextmanager
from functools import wraps
import sys

logger = logging.getLogger(__name__)

# Type for exceptions
T = TypeVar('T')


class BLNCsException(Exception):
    """Base exception for BLNCS"""
    def __init__(self, message: str, error_code: Optional[str] = None, details: Optional[dict] = None):
        self.message = message
        self.error_code = error_code or 'UNKNOWN_ERROR'
        self.details = details or {}
        super().__init__(self.message)

    def to_dict(self) -> dict:
        """Convert exception to dictionary for API response"""
        return {
            'error': self.error_code,
            'message': self.message,
            'details': self.details
        }


class LightningException(BLNCsException):
    """Lightning Network specific exceptions"""
    pass


class ConfigurationException(BLNCsException):
    """Configuration related exceptions"""
    pass


class DatabaseException(BLNCsException):
    """Database operation exceptions"""
    pass


class AuthenticationException(BLNCsException):
    """Authentication exceptions"""
    pass


class ValidationException(BLNCsException):
    """Input validation exceptions"""
    pass


class RateLimitException(BLNCsException):
    """Rate limiting exceptions"""
    pass


def safe_execute(
    func: Callable,
    *args,
    default: Any = None,
    on_error: Optional[Callable] = None,
    log_level: int = logging.WARNING,
    **kwargs
) -> Any:
    """
    Safely execute a function with error handling
    EAFP (Easier to Ask Forgiveness than Permission) pattern
    """
    try:
        return func(*args, **kwargs)
    except Exception as e:
        logger.log(log_level, f"Error executing {func.__name__}: {e}", exc_info=True)
        if on_error:
            return on_error(e)
        return default


def handle_exceptions(
    *exception_types: Type[Exception],
    logger_func: Optional[Callable] = None,
    reraise: bool = False,
    default: Any = None
):
    """
    Decorator for specific exception handling
    Order matters: more specific exceptions before general ones
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except exception_types as e:
                # Log the exception
                if logger_func:
                    logger_func(f"Error in {func.__name__}: {e}")
                else:
                    logger.exception(f"Error in {func.__name__}")

                # Decide whether to reraise
                if reraise:
                    raise
                return default
            except Exception as e:
                # Unexpected exception - always log
                logger.exception(f"Unexpected error in {func.__name__}: {e}")
                raise

        return wrapper
    return decorator


@contextmanager
def error_context(
    operation: str,
    exception_type: Type[BLNCsException] = BLNCsException,
    error_code: Optional[str] = None,
    reraise: bool = True
):
    """
    Context manager for error handling with context information
    Best practice: handle exceptions at the level that knows how to handle them
    """
    try:
        yield
    except BLNCsException:
        # Already properly formatted, just reraise
        raise
    except Exception as e:
        error_code_final = error_code or f"{type(e).__name__}"
        msg = f"Error during {operation}: {str(e)}"
        logger.exception(msg)

        if reraise:
            raise exception_type(
                message=msg,
                error_code=error_code_final,
                details={'operation': operation, 'original_error': str(e)}
            )


def retry_on_exception(
    max_attempts: int = 3,
    delay: float = 0.1,
    backoff_factor: float = 2.0,
    exceptions: Tuple[Type[Exception], ...] = (Exception,)
):
    """
    Decorator for retrying failed operations with exponential backoff
    Useful for network operations and transient failures
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            import time
            current_delay = delay
            last_exception = None

            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        logger.warning(
                            f"Attempt {attempt + 1}/{max_attempts} failed for {func.__name__}: {e}. "
                            f"Retrying in {current_delay}s..."
                        )
                        time.sleep(current_delay)
                        current_delay *= backoff_factor
                    else:
                        logger.error(f"All {max_attempts} attempts failed for {func.__name__}")

            raise last_exception

        return wrapper
    return decorator


class ValidationError(ValidationException):
    """Specific validation error with field information"""
    def __init__(self, field: str, message: str, value: Any = None):
        self.field = field
        self.value = value
        super().__init__(
            message=f"Validation failed for '{field}': {message}",
            error_code='VALIDATION_ERROR',
            details={'field': field, 'value': str(value)[:100]}
        )


def validate_input(
    value: Any,
    expected_type: Type,
    field_name: str = 'input',
    required: bool = True,
    min_value: Optional[Any] = None,
    max_value: Optional[Any] = None
) -> None:
    """
    Validate input parameters with clear error messages
    Fail fast: check for errors as early as possible
    """
    # Check if required
    if required and value is None:
        raise ValidationError(field_name, 'This field is required', value)

    # Check type
    if value is not None and not isinstance(value, expected_type):
        raise ValidationError(
            field_name,
            f'Expected type {expected_type.__name__}, got {type(value).__name__}',
            value
        )

    # Check min value
    if min_value is not None and value is not None and value < min_value:
        raise ValidationError(
            field_name,
            f'Value must be at least {min_value}',
            value
        )

    # Check max value
    if max_value is not None and value is not None and value > max_value:
        raise ValidationError(
            field_name,
            f'Value must be at most {max_value}',
            value
        )


@contextmanager
def ensure_cleanup(*cleanup_funcs: Callable):
    """
    Context manager that ensures cleanup functions are called
    even if an exception occurs
    """
    try:
        yield
    finally:
        for func in cleanup_funcs:
            try:
                func()
            except Exception as e:
                logger.exception(f"Error during cleanup: {e}")


class ErrorAggregator:
    """
    Collect multiple errors and report them together
    Useful for batch operations and form validation
    """
    def __init__(self):
        self.errors: list = []

    def add(self, error: str, error_code: Optional[str] = None):
        """Add an error"""
        self.errors.append({'message': error, 'code': error_code})

    def has_errors(self) -> bool:
        """Check if there are any errors"""
        return len(self.errors) > 0

    def raise_if_errors(self, exception_type: Type[BLNCsException] = BLNCsException):
        """Raise exception if there are accumulated errors"""
        if self.has_errors():
            msg = '; '.join([e['message'] for e in self.errors])
            raise exception_type(
                message=msg,
                error_code='MULTIPLE_ERRORS',
                details={'errors': self.errors}
            )

    def to_dict(self) -> dict:
        """Convert errors to dictionary"""
        return {'errors': self.errors, 'count': len(self.errors)}


__all__ = [
    'BLNCsException',
    'LightningException',
    'ConfigurationException',
    'DatabaseException',
    'AuthenticationException',
    'ValidationException',
    'RateLimitException',
    'ValidationError',
    'safe_execute',
    'handle_exceptions',
    'error_context',
    'retry_on_exception',
    'validate_input',
    'ensure_cleanup',
    'ErrorAggregator',
]
