"""
Comprehensive Security-First Input Validation System
Provides thorough input validation, sanitization, and security checks for all user inputs.
"""

import re
import os
import hashlib
import secrets
from typing import Any, Dict, List, Optional, Union, Callable, TypeVar, Type
from pathlib import Path
from dataclasses import dataclass
from enum import Enum
import ipaddress
import json
from datetime import datetime, timedelta
from functools import wraps
import logging

from .exceptions import ValidationError, SecurityError

T = TypeVar('T')

logger = logging.getLogger(__name__)


class ValidationLevel(Enum):
    """Validation strictness levels"""
    RELAXED = 1    # Basic validation only
    STANDARD = 2   # Standard validation with sanitization
    STRICT = 3     # Strict validation with security checks
    PARANOID = 4   # Maximum security validation


@dataclass
class ValidationResult:
    """Result of validation operation"""
    is_valid: bool
    sanitized_value: Any
    errors: List[str]
    warnings: List[str]
    metadata: Dict[str, Any]


class SecurityValidator:
    """
    Comprehensive security-focused input validation system
    """
    
    # Security constants
    MAX_STRING_LENGTH = 10000
    MAX_PATH_LENGTH = 4096
    MAX_URL_LENGTH = 2048
    MAX_INT_VALUE = 2**31 - 1
    MIN_INT_VALUE = -(2**31)
    
    # Dangerous patterns
    SQL_INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE)\b)",
        r"(--|#|\/\*|\*\/)",
        r"(\bOR\b\s*\d+\s*=\s*\d+)",
        r"(\bAND\b\s*\d+\s*=\s*\d+)",
        r"(\'|\"|;|\\x00|\\n|\\r|\\x1a)"
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.",
        r"\.\.\\",
        r"%2e%2e",
        r"%252e%252e"
    ]
    
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe",
        r"<embed",
        r"<object"
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        r"[;&|`$]",
        r"\$\(",
        r"\|\|",
        r"&&",
        r">",
        r"<"
    ]
    
    def __init__(self, level: ValidationLevel = ValidationLevel.STRICT):
        self.level = level
        self.logger = logger
        
    def validate_string(
        self,
        value: Any,
        min_length: int = 0,
        max_length: Optional[int] = None,
        pattern: Optional[str] = None,
        allowed_chars: Optional[str] = None,
        forbidden_patterns: Optional[List[str]] = None,
        strip_html: bool = True,
        sanitize: bool = True
    ) -> ValidationResult:
        """
        Comprehensive string validation with security checks
        """
        errors = []
        warnings = []
        
        # Type check
        if not isinstance(value, str):
            return ValidationResult(
                is_valid=False,
                sanitized_value=None,
                errors=[f"Expected string, got {type(value).__name__}"],
                warnings=[],
                metadata={}
            )
        
        # Length validation
        max_length = max_length or self.MAX_STRING_LENGTH
        if len(value) < min_length:
            errors.append(f"String too short (min: {min_length})")
        if len(value) > max_length:
            errors.append(f"String too long (max: {max_length})")
        
        # Security checks based on level
        if self.level >= ValidationLevel.STANDARD:
            # Check for SQL injection patterns
            for pattern in self.SQL_INJECTION_PATTERNS:
                if re.search(pattern, value, re.IGNORECASE):
                    errors.append("Potential SQL injection detected")
                    break
            
            # Check for XSS patterns
            if strip_html and self.level >= ValidationLevel.STRICT:
                for pattern in self.XSS_PATTERNS:
                    if re.search(pattern, value, re.IGNORECASE):
                        warnings.append("Potential XSS pattern detected")
                        break
        
        # Pattern validation
        if pattern and not re.match(pattern, value):
            errors.append(f"String does not match required pattern")
        
        # Allowed characters validation
        if allowed_chars:
            invalid_chars = set(value) - set(allowed_chars)
            if invalid_chars:
                errors.append(f"Invalid characters found: {invalid_chars}")
        
        # Forbidden patterns check
        if forbidden_patterns:
            for forbidden in forbidden_patterns:
                if re.search(forbidden, value):
                    errors.append(f"Forbidden pattern detected")
                    break
        
        # Sanitization
        sanitized = value
        if sanitize and not errors:
            # Remove null bytes
            sanitized = sanitized.replace('\x00', '')
            
            # Strip HTML if requested
            if strip_html:
                sanitized = re.sub(r'<[^>]+>', '', sanitized)
            
            # Normalize whitespace
            sanitized = ' '.join(sanitized.split())
            
            # Escape special characters for safety
            if self.level >= ValidationLevel.PARANOID:
                sanitized = sanitized.replace("'", "''")
                sanitized = sanitized.replace('"', '""')
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            sanitized_value=sanitized if not errors else None,
            errors=errors,
            warnings=warnings,
            metadata={'original_length': len(value), 'sanitized_length': len(sanitized)}
        )
    
    def validate_integer(
        self,
        value: Any,
        min_value: Optional[int] = None,
        max_value: Optional[int] = None,
        allowed_values: Optional[List[int]] = None
    ) -> ValidationResult:
        """Validate integer with bounds checking"""
        errors = []
        
        # Type conversion attempt
        try:
            if isinstance(value, str):
                # Check for hex/octal/binary attempts
                if value.startswith(('0x', '0o', '0b')):
                    errors.append("Non-decimal number format not allowed")
                    return ValidationResult(False, None, errors, [], {})
                
                int_value = int(value)
            elif isinstance(value, (int, float)):
                int_value = int(value)
            else:
                raise ValueError(f"Cannot convert {type(value).__name__} to integer")
        except (ValueError, TypeError) as e:
            errors.append(f"Invalid integer value: {e}")
            return ValidationResult(False, None, errors, [], {})
        
        # Bounds checking
        min_value = min_value if min_value is not None else self.MIN_INT_VALUE
        max_value = max_value if max_value is not None else self.MAX_INT_VALUE
        
        if int_value < min_value:
            errors.append(f"Value {int_value} below minimum {min_value}")
        if int_value > max_value:
            errors.append(f"Value {int_value} above maximum {max_value}")
        
        # Allowed values check
        if allowed_values and int_value not in allowed_values:
            errors.append(f"Value {int_value} not in allowed values")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            sanitized_value=int_value if not errors else None,
            errors=errors,
            warnings=[],
            metadata={'original_type': type(value).__name__}
        )
    
    def validate_path(
        self,
        value: str,
        must_exist: bool = False,
        must_be_file: bool = False,
        must_be_dir: bool = False,
        allowed_extensions: Optional[List[str]] = None,
        base_path: Optional[Path] = None
    ) -> ValidationResult:
        """
        Validate file path with security checks
        """
        errors = []
        warnings = []
        
        # Basic string validation first
        if not isinstance(value, str):
            errors.append(f"Path must be string, got {type(value).__name__}")
            return ValidationResult(False, None, errors, [], {})
        
        # Length check
        if len(value) > self.MAX_PATH_LENGTH:
            errors.append(f"Path too long (max: {self.MAX_PATH_LENGTH})")
        
        # Path traversal detection
        for pattern in self.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                errors.append("Path traversal attempt detected")
                return ValidationResult(False, None, errors, [], {'security_violation': 'path_traversal'})
        
        # Null byte injection check
        if '\x00' in value:
            errors.append("Null byte in path")
            return ValidationResult(False, None, errors, [], {'security_violation': 'null_byte'})
        
        # Convert to Path object
        try:
            path = Path(value)
            
            # Resolve to absolute path
            if not path.is_absolute():
                if base_path:
                    path = base_path / path
                else:
                    path = path.resolve()
            
            # Check if path escapes base directory
            if base_path:
                try:
                    path.relative_to(base_path)
                except ValueError:
                    errors.append(f"Path escapes base directory: {base_path}")
                    return ValidationResult(False, None, errors, [], {'security_violation': 'directory_escape'})
            
            # Existence checks
            if must_exist and not path.exists():
                errors.append(f"Path does not exist: {path}")
            
            if must_be_file and not path.is_file():
                errors.append(f"Path is not a file: {path}")
            
            if must_be_dir and not path.is_dir():
                errors.append(f"Path is not a directory: {path}")
            
            # Extension validation
            if allowed_extensions and path.suffix not in allowed_extensions:
                errors.append(f"File extension {path.suffix} not allowed")
            
            # Check for dangerous locations
            dangerous_paths = ['/etc', '/sys', '/proc', '/dev', 'C:\\Windows', 'C:\\System32']
            for dangerous in dangerous_paths:
                if str(path).startswith(dangerous):
                    warnings.append(f"Path in sensitive location: {dangerous}")
            
        except Exception as e:
            errors.append(f"Invalid path: {e}")
            return ValidationResult(False, None, errors, warnings, {})
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            sanitized_value=str(path) if not errors else None,
            errors=errors,
            warnings=warnings,
            metadata={'resolved_path': str(path), 'is_absolute': path.is_absolute()}
        )
    
    def validate_url(
        self,
        value: str,
        allowed_schemes: Optional[List[str]] = None,
        allowed_domains: Optional[List[str]] = None,
        require_https: bool = False
    ) -> ValidationResult:
        """Validate URL with security checks"""
        from urllib.parse import urlparse, quote
        
        errors = []
        warnings = []
        
        if not isinstance(value, str):
            errors.append(f"URL must be string, got {type(value).__name__}")
            return ValidationResult(False, None, errors, [], {})
        
        # Length check
        if len(value) > self.MAX_URL_LENGTH:
            errors.append(f"URL too long (max: {self.MAX_URL_LENGTH})")
        
        # Parse URL
        try:
            parsed = urlparse(value)
            
            # Scheme validation
            allowed_schemes = allowed_schemes or ['http', 'https']
            if parsed.scheme not in allowed_schemes:
                errors.append(f"URL scheme {parsed.scheme} not allowed")
            
            # HTTPS requirement
            if require_https and parsed.scheme != 'https':
                errors.append("HTTPS required")
            
            # Domain validation
            if allowed_domains and parsed.netloc not in allowed_domains:
                errors.append(f"Domain {parsed.netloc} not allowed")
            
            # Check for javascript: and data: URLs
            if parsed.scheme in ['javascript', 'data', 'vbscript']:
                errors.append("Potentially dangerous URL scheme")
                return ValidationResult(False, None, errors, [], {'security_violation': 'dangerous_scheme'})
            
            # Check for credential in URL
            if '@' in parsed.netloc:
                warnings.append("URL contains credentials")
            
            # Check for IP address instead of domain
            try:
                ipaddress.ip_address(parsed.hostname)
                warnings.append("URL uses IP address instead of domain")
            except (ValueError, TypeError):
                pass  # Not an IP, which is good
            
        except Exception as e:
            errors.append(f"Invalid URL: {e}")
            return ValidationResult(False, None, errors, warnings, {})
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            sanitized_value=value if not errors else None,
            errors=errors,
            warnings=warnings,
            metadata={'parsed_url': parsed._asdict()}
        )
    
    def validate_email(self, value: str) -> ValidationResult:
        """Validate email address"""
        errors = []
        
        # Basic format check
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, value):
            errors.append("Invalid email format")
        
        # Length check
        if len(value) > 254:  # RFC 5321
            errors.append("Email too long (max: 254)")
        
        # Check for dangerous characters
        if any(char in value for char in ['<', '>', '"', '\'', ';', '&']):
            errors.append("Email contains potentially dangerous characters")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            sanitized_value=value.lower() if not errors else None,
            errors=errors,
            warnings=[],
            metadata={}
        )
    
    def validate_json(self, value: str) -> ValidationResult:
        """Validate JSON string"""
        errors = []
        
        try:
            parsed = json.loads(value)
            
            # Check for excessive nesting (potential DoS)
            def check_depth(obj, current_depth=0, max_depth=10):
                if current_depth > max_depth:
                    return False
                if isinstance(obj, dict):
                    return all(check_depth(v, current_depth + 1) for v in obj.values())
                elif isinstance(obj, list):
                    return all(check_depth(v, current_depth + 1) for v in obj)
                return True
            
            if not check_depth(parsed):
                errors.append("JSON nesting too deep (potential DoS)")
            
        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON: {e}")
        except RecursionError:
            errors.append("JSON structure too complex")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            sanitized_value=parsed if not errors else None,
            errors=errors,
            warnings=[],
            metadata={}
        )
    
    def validate_command(self, value: str) -> ValidationResult:
        """Validate shell command for execution"""
        errors = []
        warnings = []
        
        # Check for command injection patterns
        for pattern in self.COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, value):
                errors.append("Potential command injection detected")
                return ValidationResult(False, None, errors, [], {'security_violation': 'command_injection'})
        
        # Check for dangerous commands
        dangerous_commands = ['rm', 'del', 'format', 'dd', 'mkfs', 'kill', 'shutdown', 'reboot']
        for cmd in dangerous_commands:
            if cmd in value.lower():
                warnings.append(f"Potentially dangerous command: {cmd}")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            sanitized_value=value if not errors else None,
            errors=errors,
            warnings=warnings,
            metadata={}
        )
    
    def validate_bitcoin_address(self, value: str) -> ValidationResult:
        """Validate Bitcoin address with checksum verification"""
        errors = []
        
        # Basic format check
        if not isinstance(value, str):
            errors.append("Address must be string")
            return ValidationResult(False, None, errors, [], {})
        
        # Length and character validation
        if value.startswith(('1', '3')):  # Legacy
            if not re.match(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$', value):
                errors.append("Invalid legacy Bitcoin address format")
        elif value.startswith(('bc1', 'tb1')):  # Bech32
            if not re.match(r'^(bc1|tb1)[a-z0-9]{39,59}$', value.lower()):
                errors.append("Invalid Bech32 Bitcoin address format")
        else:
            errors.append("Unknown Bitcoin address format")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            sanitized_value=value if not errors else None,
            errors=errors,
            warnings=[],
            metadata={'address_type': 'legacy' if value[0] in '13' else 'bech32'}
        )
    
    def validate_lightning_invoice(self, value: str) -> ValidationResult:
        """Validate Lightning Network invoice"""
        errors = []
        
        # Check prefix
        if not value.lower().startswith(('lnbc', 'lntb', 'lnbcrt')):
            errors.append("Invalid Lightning invoice prefix")
        
        # Check for valid bech32 characters
        if not re.match(r'^ln[a-z0-9]+$', value.lower()):
            errors.append("Invalid characters in Lightning invoice")
        
        # Length check (invoices can be quite long)
        if len(value) > 2000:
            errors.append("Lightning invoice too long")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            sanitized_value=value.lower() if not errors else None,
            errors=errors,
            warnings=[],
            metadata={}
        )
    
    def validate_dict(
        self,
        value: Dict[str, Any],
        schema: Dict[str, Dict[str, Any]]
    ) -> ValidationResult:
        """Validate dictionary against schema"""
        errors = []
        warnings = []
        sanitized = {}
        
        for field_name, field_schema in schema.items():
            field_value = value.get(field_name)
            
            # Check required fields
            if field_schema.get('required', False) and field_value is None:
                errors.append(f"Required field missing: {field_name}")
                continue
            
            if field_value is None:
                continue
            
            # Type validation
            expected_type = field_schema.get('type')
            if expected_type:
                if expected_type == 'string':
                    result = self.validate_string(
                        field_value,
                        min_length=field_schema.get('min_length', 0),
                        max_length=field_schema.get('max_length'),
                        pattern=field_schema.get('pattern')
                    )
                elif expected_type == 'integer':
                    result = self.validate_integer(
                        field_value,
                        min_value=field_schema.get('min_value'),
                        max_value=field_schema.get('max_value')
                    )
                elif expected_type == 'email':
                    result = self.validate_email(field_value)
                elif expected_type == 'url':
                    result = self.validate_url(field_value)
                elif expected_type == 'path':
                    result = self.validate_path(field_value)
                else:
                    result = ValidationResult(True, field_value, [], [], {})
                
                if not result.is_valid:
                    errors.extend([f"{field_name}: {e}" for e in result.errors])
                else:
                    sanitized[field_name] = result.sanitized_value
                
                warnings.extend([f"{field_name}: {w}" for w in result.warnings])
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            sanitized_value=sanitized if not errors else None,
            errors=errors,
            warnings=warnings,
            metadata={'validated_fields': len(sanitized)}
        )


def secure_input(
    validation_type: str,
    level: ValidationLevel = ValidationLevel.STRICT,
    **kwargs
) -> Callable:
    """
    Decorator for automatic input validation
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **func_kwargs):
            validator = SecurityValidator(level)
            
            # Extract the value to validate (first argument by default)
            if args:
                value = args[0]
            else:
                raise ValueError("No input to validate")
            
            # Perform validation based on type
            if validation_type == 'string':
                result = validator.validate_string(value, **kwargs)
            elif validation_type == 'integer':
                result = validator.validate_integer(value, **kwargs)
            elif validation_type == 'path':
                result = validator.validate_path(value, **kwargs)
            elif validation_type == 'url':
                result = validator.validate_url(value, **kwargs)
            elif validation_type == 'email':
                result = validator.validate_email(value)
            elif validation_type == 'json':
                result = validator.validate_json(value)
            elif validation_type == 'command':
                result = validator.validate_command(value)
            else:
                raise ValueError(f"Unknown validation type: {validation_type}")
            
            if not result.is_valid:
                raise ValidationError(f"Validation failed: {', '.join(result.errors)}")
            
            # Replace with sanitized value
            new_args = (result.sanitized_value,) + args[1:]
            
            return func(*new_args, **func_kwargs)
        return wrapper
    return decorator


# Global validator instance
_security_validator: Optional[SecurityValidator] = None

def get_security_validator(level: ValidationLevel = ValidationLevel.STRICT) -> SecurityValidator:
    """Get global security validator instance"""
    global _security_validator
    if _security_validator is None or _security_validator.level != level:
        _security_validator = SecurityValidator(level)
    return _security_validator


# Convenience functions
def validate_and_sanitize(value: Any, validation_type: str, **kwargs) -> Any:
    """Validate and sanitize input, raising exception on failure"""
    validator = get_security_validator()
    
    if validation_type == 'string':
        result = validator.validate_string(value, **kwargs)
    elif validation_type == 'integer':
        result = validator.validate_integer(value, **kwargs)
    elif validation_type == 'path':
        result = validator.validate_path(value, **kwargs)
    elif validation_type == 'url':
        result = validator.validate_url(value, **kwargs)
    elif validation_type == 'email':
        result = validator.validate_email(value)
    elif validation_type == 'bitcoin_address':
        result = validator.validate_bitcoin_address(value)
    elif validation_type == 'lightning_invoice':
        result = validator.validate_lightning_invoice(value)
    else:
        raise ValueError(f"Unknown validation type: {validation_type}")
    
    if not result.is_valid:
        raise ValidationError(f"Validation failed: {', '.join(result.errors)}")
    
    return result.sanitized_value


__all__ = [
    'SecurityValidator',
    'ValidationLevel',
    'ValidationResult',
    'secure_input',
    'get_security_validator',
    'validate_and_sanitize'
]