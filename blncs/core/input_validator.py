"""
Comprehensive Input Validation and Sanitization System
Ensures all user inputs are validated and sanitized for security and reliability.
"""

import re
import ipaddress
# Import enhanced validators with fallback support
try:
    import validators
    VALIDATORS_AVAILABLE = True
except ImportError:
    VALIDATORS_AVAILABLE = False
    validators = None

# Import our enhanced validation utilities
from ..utils.enhanced_validators import (
    get_enhanced_validator,
    validate_email as enhanced_validate_email,
    validate_url as enhanced_validate_url,
    validate_bitcoin_address,
    validate_lightning_invoice,
    sanitize_input,
    ValidationError as EnhancedValidationError
)
from typing import Any, Dict, List, Optional, Union, Callable, Set
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

from .logger import get_logger
from .exceptions import ValidationError


class ValidationType(Enum):
    """Types of validation"""
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    EMAIL = "email"
    URL = "url"
    IP_ADDRESS = "ip_address"
    PATH = "path"
    PUBKEY = "pubkey"
    AMOUNT = "amount"
    CHANNEL_ID = "channel_id"
    INVOICE = "invoice"
    PASSWORD = "password"
    JSON = "json"
    TIMESTAMP = "timestamp"


@dataclass
class ValidationRule:
    """Validation rule configuration"""
    validation_type: ValidationType
    required: bool = True
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    min_value: Optional[Union[int, float]] = None
    max_value: Optional[Union[int, float]] = None
    pattern: Optional[str] = None
    allowed_values: Optional[Set[Any]] = None
    custom_validator: Optional[Callable] = None
    sanitizer: Optional[Callable] = None
    error_message: Optional[str] = None


class InputSanitizer:
    """Input sanitization utilities"""
    
    @staticmethod
    def sanitize_string(value: str, max_length: int = None, strip_html: bool = True) -> str:
        """Sanitize string input"""
        if not isinstance(value, str):
            value = str(value)
        
        # Strip whitespace
        value = value.strip()
        
        # Remove HTML tags if requested
        if strip_html:
            value = re.sub(r'<[^>]*>', '', value)
        
        # Remove control characters
        value = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', value)
        
        # Truncate if max_length specified
        if max_length and len(value) > max_length:
            value = value[:max_length]
        
        return value
    
    @staticmethod
    def sanitize_path(value: str) -> str:
        """Sanitize file path input"""
        if not isinstance(value, str):
            value = str(value)
        
        # Remove dangerous path components
        value = value.replace('..', '')
        value = value.replace('//', '/')
        value = value.strip('/')
        
        # Remove shell metacharacters
        dangerous_chars = ['|', ';', '&', '$', '>', '<', '`', '!']
        for char in dangerous_chars:
            value = value.replace(char, '')
        
        return value
    
    @staticmethod
    def sanitize_amount(value: Union[str, int, float]) -> int:
        """Sanitize amount input (convert to satoshis)"""
        if isinstance(value, str):
            # Remove non-numeric characters except decimal point
            value = re.sub(r'[^\d.]', '', value)
            if not value:
                raise ValidationError("Invalid amount format")
            value = float(value)
        
        if isinstance(value, float):
            # Convert to satoshis
            value = int(value * 100_000_000)  # 1 BTC = 100M sats
        
        if not isinstance(value, int):
            raise ValidationError("Amount must be a number")
        
        return max(0, value)  # Ensure non-negative
    
    @staticmethod
    def sanitize_pubkey(value: str) -> str:
        """Sanitize Lightning Network public key"""
        if not isinstance(value, str):
            raise ValidationError("Public key must be a string")
        
        # Remove whitespace
        value = value.strip()
        
        # Remove common prefixes
        if value.startswith('0x'):
            value = value[2:]
        
        # Convert to lowercase for consistency
        value = value.lower()
        
        return value


class InputValidator:
    """Comprehensive input validation system"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.sanitizer = InputSanitizer()
        
        # Lightning Network specific patterns
        self.patterns = {
            'pubkey': r'^[0-9a-f]{66}$',
            'channel_id': r'^[0-9]+:[0-9]+:[0-9]+$',
            'invoice': r'^(lnbc|lntb|lnbcrt)[0-9]+[munp]?1[0-9a-z]+$',
            'bitcoin_address': r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$',
            'payment_hash': r'^[0-9a-f]{64}$',
            'preimage': r'^[0-9a-f]{64}$'
        }
        
        # Common validation rules
        self.default_rules = {
            ValidationType.STRING: ValidationRule(
                ValidationType.STRING, max_length=1000, sanitizer=self.sanitizer.sanitize_string
            ),
            ValidationType.INTEGER: ValidationRule(
                ValidationType.INTEGER, min_value=-2**63, max_value=2**63-1
            ),
            ValidationType.FLOAT: ValidationRule(
                ValidationType.FLOAT, min_value=-1e308, max_value=1e308
            ),
            ValidationType.AMOUNT: ValidationRule(
                ValidationType.AMOUNT, min_value=0, max_value=21_000_000 * 100_000_000,
                sanitizer=self.sanitizer.sanitize_amount
            ),
            ValidationType.PATH: ValidationRule(
                ValidationType.PATH, max_length=4096, sanitizer=self.sanitizer.sanitize_path
            ),
            ValidationType.PUBKEY: ValidationRule(
                ValidationType.PUBKEY, pattern=self.patterns['pubkey'],
                sanitizer=self.sanitizer.sanitize_pubkey
            ),
            ValidationType.PASSWORD: ValidationRule(
                ValidationType.PASSWORD, min_length=8, max_length=128
            )
        }
    
    def validate_value(self, value: Any, rule: ValidationRule, field_name: str = "field") -> Any:
        """Validate a single value against a rule"""
        try:
            # Handle None/empty values
            if value is None or (isinstance(value, str) and value == ""):
                if rule.required:
                    raise ValidationError(f"{field_name} is required")
                return value
            
            # Apply sanitizer first if provided
            if rule.sanitizer:
                value = rule.sanitizer(value)
            
            # Type-specific validation
            validated_value = self._validate_by_type(value, rule, field_name)
            
            # Apply custom validator if provided
            if rule.custom_validator:
                validated_value = rule.custom_validator(validated_value)
            
            return validated_value
            
        except ValidationError:
            raise
        except Exception as e:
            error_msg = rule.error_message or f"Validation failed for {field_name}: {str(e)}"
            raise ValidationError(error_msg)
    
    def _validate_by_type(self, value: Any, rule: ValidationRule, field_name: str) -> Any:
        """Validate value based on validation type"""
        validation_type = rule.validation_type
        
        if validation_type == ValidationType.STRING:
            return self._validate_string(value, rule, field_name)
        elif validation_type == ValidationType.INTEGER:
            return self._validate_integer(value, rule, field_name)
        elif validation_type == ValidationType.FLOAT:
            return self._validate_float(value, rule, field_name)
        elif validation_type == ValidationType.BOOLEAN:
            return self._validate_boolean(value, rule, field_name)
        elif validation_type == ValidationType.EMAIL:
            return self._validate_email(value, rule, field_name)
        elif validation_type == ValidationType.URL:
            return self._validate_url(value, rule, field_name)
        elif validation_type == ValidationType.IP_ADDRESS:
            return self._validate_ip_address(value, rule, field_name)
        elif validation_type == ValidationType.PATH:
            return self._validate_path(value, rule, field_name)
        elif validation_type == ValidationType.PUBKEY:
            return self._validate_pubkey(value, rule, field_name)
        elif validation_type == ValidationType.AMOUNT:
            return self._validate_amount(value, rule, field_name)
        elif validation_type == ValidationType.CHANNEL_ID:
            return self._validate_channel_id(value, rule, field_name)
        elif validation_type == ValidationType.INVOICE:
            return self._validate_invoice(value, rule, field_name)
        elif validation_type == ValidationType.PASSWORD:
            return self._validate_password(value, rule, field_name)
        elif validation_type == ValidationType.JSON:
            return self._validate_json(value, rule, field_name)
        elif validation_type == ValidationType.TIMESTAMP:
            return self._validate_timestamp(value, rule, field_name)
        else:
            raise ValidationError(f"Unknown validation type: {validation_type}")
    
    def _validate_string(self, value: Any, rule: ValidationRule, field_name: str) -> str:
        """Validate string value"""
        if not isinstance(value, str):
            value = str(value)
        
        if rule.min_length and len(value) < rule.min_length:
            raise ValidationError(f"{field_name} must be at least {rule.min_length} characters")
        
        if rule.max_length and len(value) > rule.max_length:
            raise ValidationError(f"{field_name} must not exceed {rule.max_length} characters")
        
        if rule.pattern and not re.match(rule.pattern, value):
            raise ValidationError(f"{field_name} format is invalid")
        
        if rule.allowed_values and value not in rule.allowed_values:
            raise ValidationError(f"{field_name} must be one of: {list(rule.allowed_values)}")
        
        return value
    
    def _validate_integer(self, value: Any, rule: ValidationRule, field_name: str) -> int:
        """Validate integer value"""
        try:
            if isinstance(value, str):
                value = int(value)
            elif isinstance(value, float):
                if value != int(value):
                    raise ValidationError(f"{field_name} must be a whole number")
                value = int(value)
            elif not isinstance(value, int):
                raise ValidationError(f"{field_name} must be an integer")
        except ValueError:
            raise ValidationError(f"{field_name} must be a valid integer")
        
        if rule.min_value is not None and value < rule.min_value:
            raise ValidationError(f"{field_name} must be at least {rule.min_value}")
        
        if rule.max_value is not None and value > rule.max_value:
            raise ValidationError(f"{field_name} must not exceed {rule.max_value}")
        
        if rule.allowed_values and value not in rule.allowed_values:
            raise ValidationError(f"{field_name} must be one of: {list(rule.allowed_values)}")
        
        return value
    
    def _validate_float(self, value: Any, rule: ValidationRule, field_name: str) -> float:
        """Validate float value"""
        try:
            value = float(value)
        except (ValueError, TypeError):
            raise ValidationError(f"{field_name} must be a valid number")
        
        if rule.min_value is not None and value < rule.min_value:
            raise ValidationError(f"{field_name} must be at least {rule.min_value}")
        
        if rule.max_value is not None and value > rule.max_value:
            raise ValidationError(f"{field_name} must not exceed {rule.max_value}")
        
        return value
    
    def _validate_boolean(self, value: Any, rule: ValidationRule, field_name: str) -> bool:
        """Validate boolean value"""
        if isinstance(value, bool):
            return value
        elif isinstance(value, str):
            lower_val = value.lower()
            if lower_val in ('true', '1', 'yes', 'on'):
                return True
            elif lower_val in ('false', '0', 'no', 'off'):
                return False
            else:
                raise ValidationError(f"{field_name} must be true or false")
        elif isinstance(value, (int, float)):
            return bool(value)
        else:
            raise ValidationError(f"{field_name} must be a boolean value")
    
    def _validate_email(self, value: Any, rule: ValidationRule, field_name: str) -> str:
        """Validate email address"""
        if not isinstance(value, str):
            raise ValidationError(f"{field_name} must be a string")
        
        if not validators.email(value):
            raise ValidationError(f"{field_name} must be a valid email address")
        
        return value.lower().strip()
    
    def _validate_url(self, value: Any, rule: ValidationRule, field_name: str) -> str:
        """Validate URL"""
        if not isinstance(value, str):
            raise ValidationError(f"{field_name} must be a string")
        
        if not validators.url(value):
            raise ValidationError(f"{field_name} must be a valid URL")
        
        return value.strip()
    
    def _validate_ip_address(self, value: Any, rule: ValidationRule, field_name: str) -> str:
        """Validate IP address"""
        if not isinstance(value, str):
            raise ValidationError(f"{field_name} must be a string")
        
        try:
            ipaddress.ip_address(value.strip())
        except ValueError:
            raise ValidationError(f"{field_name} must be a valid IP address")
        
        return value.strip()
    
    def _validate_path(self, value: Any, rule: ValidationRule, field_name: str) -> str:
        """Validate file path"""
        if not isinstance(value, str):
            raise ValidationError(f"{field_name} must be a string")
        
        # Check for path traversal attempts
        if '..' in value or value.startswith('/') and '../' in value:
            raise ValidationError(f"{field_name} contains invalid path components")
        
        # Check length
        if rule.max_length and len(value) > rule.max_length:
            raise ValidationError(f"{field_name} path too long")
        
        return value
    
    def _validate_pubkey(self, value: Any, rule: ValidationRule, field_name: str) -> str:
        """Validate Lightning Network public key"""
        if not isinstance(value, str):
            raise ValidationError(f"{field_name} must be a string")
        
        if not re.match(self.patterns['pubkey'], value):
            raise ValidationError(f"{field_name} must be a valid 66-character hex public key")
        
        return value
    
    def _validate_amount(self, value: Any, rule: ValidationRule, field_name: str) -> int:
        """Validate amount (in satoshis)"""
        if isinstance(value, str):
            try:
                # Handle common formats
                if '.' in value:
                    value = float(value)
                else:
                    value = int(value)
            except ValueError:
                raise ValidationError(f"{field_name} must be a valid amount")
        
        if isinstance(value, float):
            if value < 0:
                raise ValidationError(f"{field_name} must be non-negative")
            # Convert to satoshis
            value = int(value * 100_000_000)
        elif isinstance(value, int):
            if value < 0:
                raise ValidationError(f"{field_name} must be non-negative")
        else:
            raise ValidationError(f"{field_name} must be a valid amount")
        
        if rule.max_value and value > rule.max_value:
            raise ValidationError(f"{field_name} exceeds maximum allowed amount")
        
        return value
    
    def _validate_channel_id(self, value: Any, rule: ValidationRule, field_name: str) -> str:
        """Validate Lightning Network channel ID"""
        if not isinstance(value, str):
            raise ValidationError(f"{field_name} must be a string")
        
        if not re.match(self.patterns['channel_id'], value):
            raise ValidationError(f"{field_name} must be a valid channel ID (block:tx:output)")
        
        return value
    
    def _validate_invoice(self, value: Any, rule: ValidationRule, field_name: str) -> str:
        """Validate Lightning Network invoice"""
        if not isinstance(value, str):
            raise ValidationError(f"{field_name} must be a string")
        
        value = value.lower().strip()
        
        if not re.match(self.patterns['invoice'], value):
            raise ValidationError(f"{field_name} must be a valid Lightning invoice")
        
        return value
    
    def _validate_password(self, value: Any, rule: ValidationRule, field_name: str) -> str:
        """Validate password"""
        if not isinstance(value, str):
            raise ValidationError(f"{field_name} must be a string")
        
        if rule.min_length and len(value) < rule.min_length:
            raise ValidationError(f"{field_name} must be at least {rule.min_length} characters")
        
        if rule.max_length and len(value) > rule.max_length:
            raise ValidationError(f"{field_name} must not exceed {rule.max_length} characters")
        
        # Check for common weak patterns
        if value.lower() in ['password', '123456', 'qwerty', 'abc123']:
            raise ValidationError(f"{field_name} is too weak")
        
        return value
    
    def _validate_json(self, value: Any, rule: ValidationRule, field_name: str) -> str:
        """Validate JSON string"""
        if not isinstance(value, str):
            value = str(value)
        
        try:
            import json
            json.loads(value)
        except json.JSONDecodeError:
            raise ValidationError(f"{field_name} must be valid JSON")
        
        return value
    
    def _validate_timestamp(self, value: Any, rule: ValidationRule, field_name: str) -> datetime:
        """Validate timestamp"""
        if isinstance(value, datetime):
            return value
        elif isinstance(value, (int, float)):
            try:
                return datetime.fromtimestamp(value)
            except (ValueError, OSError):
                raise ValidationError(f"{field_name} is not a valid timestamp")
        elif isinstance(value, str):
            try:
                # Try ISO format first
                return datetime.fromisoformat(value.replace('Z', '+00:00'))
            except ValueError:
                try:
                    # Try timestamp
                    return datetime.fromtimestamp(float(value))
                except ValueError:
                    raise ValidationError(f"{field_name} must be a valid timestamp")
        else:
            raise ValidationError(f"{field_name} must be a timestamp")
    
    def validate_dict(self, data: Dict[str, Any], schema: Dict[str, ValidationRule]) -> Dict[str, Any]:
        """Validate a dictionary against a schema"""
        if not isinstance(data, dict):
            raise ValidationError("Input must be a dictionary")
        
        validated_data = {}
        
        # Validate each field
        for field_name, rule in schema.items():
            value = data.get(field_name)
            validated_data[field_name] = self.validate_value(value, rule, field_name)
        
        # Check for unexpected fields
        unexpected_fields = set(data.keys()) - set(schema.keys())
        if unexpected_fields:
            self.logger.warning(f"Unexpected fields in input: {unexpected_fields}")
        
        return validated_data
    
    def create_schema(self, **field_rules) -> Dict[str, ValidationRule]:
        """Create validation schema from field rules"""
        schema = {}
        for field_name, rule_config in field_rules.items():
            if isinstance(rule_config, ValidationRule):
                schema[field_name] = rule_config
            elif isinstance(rule_config, dict):
                validation_type = rule_config.get('type', ValidationType.STRING)
                if isinstance(validation_type, str):
                    validation_type = ValidationType(validation_type)
                
                schema[field_name] = ValidationRule(
                    validation_type=validation_type,
                    required=rule_config.get('required', True),
                    min_length=rule_config.get('min_length'),
                    max_length=rule_config.get('max_length'),
                    min_value=rule_config.get('min_value'),
                    max_value=rule_config.get('max_value'),
                    pattern=rule_config.get('pattern'),
                    allowed_values=set(rule_config.get('allowed_values', [])) if rule_config.get('allowed_values') else None,
                    custom_validator=rule_config.get('custom_validator'),
                    sanitizer=rule_config.get('sanitizer'),
                    error_message=rule_config.get('error_message')
                )
            else:
                # Assume it's a validation type
                if isinstance(rule_config, str):
                    rule_config = ValidationType(rule_config)
                schema[field_name] = self.default_rules.get(rule_config, ValidationRule(rule_config))
        
        return schema


# Validation decorators

def validate_input(schema: Dict[str, ValidationRule]):
    """Decorator to validate function input parameters"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            validator = get_input_validator()
            
            # Validate kwargs against schema
            validated_kwargs = validator.validate_dict(kwargs, schema)
            
            return func(*args, **validated_kwargs)
        return wrapper
    return decorator


# Global instance
_input_validator = None

def get_input_validator() -> InputValidator:
    """Get global input validator"""
    global _input_validator
    if _input_validator is None:
        _input_validator = InputValidator()
    return _input_validator