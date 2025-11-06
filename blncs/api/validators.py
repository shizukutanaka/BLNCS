#!/usr/bin/env python3
"""
BLNCS API Validators
Lightweight request validation and data sanitization for API endpoints.
"""

from flask import request
from functools import wraps
import re
import hashlib
import secrets
from typing import Any, Dict, List, Optional, Callable, Union
import logging

logger = logging.getLogger(__name__)

class ValidationError(Exception):
    """Custom validation error"""
    
    def __init__(self, message: str, field: str = None, code: str = None):
        self.message = message
        self.field = field
        self.code = code or "VALIDATION_ERROR"
        super().__init__(self.message)

class FieldValidator:
    """Individual field validator"""
    
    def __init__(self, field_name: str, required: bool = False):
        self.field_name = field_name
        self.required = required
        self.validators = []
    
    def required_if(self, condition: Callable[[Dict], bool]):
        """Make field required based on condition"""
        def validator(value, data):
            if condition(data) and (value is None or value == ""):
                raise ValidationError(f"{self.field_name} is required", self.field_name, "REQUIRED")
            return value
        self.validators.append(validator)
        return self
    
    def type(self, expected_type: type):
        """Validate field type"""
        def validator(value, data):
            if value is not None and not isinstance(value, expected_type):
                raise ValidationError(
                    f"{self.field_name} must be of type {expected_type.__name__}",
                    self.field_name,
                    "INVALID_TYPE"
                )
            return value
        self.validators.append(validator)
        return self
    
    def min_length(self, length: int):
        """Validate minimum string length"""
        def validator(value, data):
            if value is not None and len(str(value)) < length:
                raise ValidationError(
                    f"{self.field_name} must be at least {length} characters",
                    self.field_name,
                    "MIN_LENGTH"
                )
            return value
        self.validators.append(validator)
        return self
    
    def max_length(self, length: int):
        """Validate maximum string length"""
        def validator(value, data):
            if value is not None and len(str(value)) > length:
                raise ValidationError(
                    f"{self.field_name} must be no more than {length} characters",
                    self.field_name,
                    "MAX_LENGTH"
                )
            return value
        self.validators.append(validator)
        return self
    
    def pattern(self, regex: str, message: str = None):
        """Validate against regex pattern"""
        compiled_pattern = re.compile(regex)
        def validator(value, data):
            if value is not None and not compiled_pattern.match(str(value)):
                error_msg = message or f"{self.field_name} format is invalid"
                raise ValidationError(error_msg, self.field_name, "INVALID_FORMAT")
            return value
        self.validators.append(validator)
        return self
    
    def email(self):
        """Validate email format"""
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return self.pattern(email_pattern, f"{self.field_name} must be a valid email address")
    
    def choices(self, valid_choices: List[Any]):
        """Validate value is in allowed choices"""
        def validator(value, data):
            if value is not None and value not in valid_choices:
                raise ValidationError(
                    f"{self.field_name} must be one of: {', '.join(map(str, valid_choices))}",
                    self.field_name,
                    "INVALID_CHOICE"
                )
            return value
        self.validators.append(validator)
        return self
    
    def min_value(self, min_val: Union[int, float]):
        """Validate minimum numeric value"""
        def validator(value, data):
            if value is not None and value < min_val:
                raise ValidationError(
                    f"{self.field_name} must be at least {min_val}",
                    self.field_name,
                    "MIN_VALUE"
                )
            return value
        self.validators.append(validator)
        return self
    
    def max_value(self, max_val: Union[int, float]):
        """Validate maximum numeric value"""
        def validator(value, data):
            if value is not None and value > max_val:
                raise ValidationError(
                    f"{self.field_name} must be no more than {max_val}",
                    self.field_name,
                    "MAX_VALUE"
                )
            return value
        self.validators.append(validator)
        return self
    
    def datetime_format(self, format_string: str = "%Y-%m-%d %H:%M:%S"):
        """Validate datetime format"""
        def validator(value, data):
            if value is not None:
                try:
                    datetime.strptime(str(value), format_string)
                except ValueError:
                    raise ValidationError(
                        f"{self.field_name} must be in format {format_string}",
                        self.field_name,
                        "INVALID_DATETIME"
                    )
            return value
        self.validators.append(validator)
        return self
    
    def custom(self, validator_func: Callable[[Any, Dict], Any]):
        """Add custom validator function"""
        self.validators.append(validator_func)
        return self
    
    def validate(self, value: Any, data: Dict) -> Any:
        """Run all validators on the value"""
        # Check required
        if self.required and (value is None or value == ""):
            raise ValidationError(f"{self.field_name} is required", self.field_name, "REQUIRED")
        
        # Run all validators
        for validator in self.validators:
            value = validator(value, data)
        
        return value

class RequestValidator:
    """Request validator with field definitions"""
    
    def __init__(self):
        self.fields: Dict[str, FieldValidator] = {}
        self.global_validators = []
    
    def field(self, name: str, required: bool = False) -> FieldValidator:
        """Define a field validator"""
        validator = FieldValidator(name, required)
        self.fields[name] = validator
        return validator
    
    def add_global_validator(self, validator: Callable[[Dict], Dict]):
        """Add global validator that operates on entire data"""
        self.global_validators.append(validator)
        return self
    
    def validate(self, data: Dict) -> Dict:
        """Validate request data"""
        validated_data = {}
        errors = {}
        
        # Validate individual fields
        for field_name, validator in self.fields.items():
            try:
                value = data.get(field_name)
                validated_data[field_name] = validator.validate(value, data)
            except ValidationError as e:
                errors[field_name] = {
                    'message': e.message,
                    'code': e.code
                }
        
        # Run global validators if no field errors
        if not errors:
            for global_validator in self.global_validators:
                try:
                    validated_data = global_validator(validated_data)
                except ValidationError as e:
                    errors['_global'] = {
                        'message': e.message,
                        'code': e.code
                    }
                    break
        
        if errors:
            raise ValidationError("Validation failed", None, "VALIDATION_ERROR")
        
        return validated_data

# Predefined validators
def backup_item_validator() -> RequestValidator:
    """Validator for backup item creation"""
    validator = RequestValidator()
    
    validator.field('name', required=True).type(str).min_length(1).max_length(100)
    validator.field('source_path', required=True).type(str).min_length(1)
    validator.field('backup_type').choices(['full', 'incremental', 'differential'])
    validator.field('priority').type(int).min_value(1).max_value(10)
    validator.field('enabled').type(bool)
    validator.field('encryption').type(bool)
    validator.field('compression').type(bool)
    
    return validator

def backup_creation_validator() -> RequestValidator:
    """Validator for backup creation"""
    validator = RequestValidator()
    
    validator.field('backup_name').type(str).max_length(200)
    validator.field('backup_type').choices(['full', 'incremental', 'differential'])
    validator.field('items').type(list)
    validator.field('encryption').type(bool)
    validator.field('compression').type(bool)
    
    return validator

def schedule_validator() -> RequestValidator:
    """Validator for backup schedule creation"""
    validator = RequestValidator()
    
    validator.field('name', required=True).type(str).min_length(1).max_length(100)
    validator.field('backup_items', required=True).type(list)
    validator.field('schedule_type', required=True).choices(['hourly', 'daily', 'weekly', 'monthly'])
    validator.field('schedule_config', required=True).type(dict)
    validator.field('backup_type').choices(['full', 'incremental', 'differential'])
    validator.field('retention_days').type(int).min_value(1).max_value(365)
    validator.field('enabled').type(bool)
    
    # Custom validator for schedule_config
    def validate_schedule_config(data):
        schedule_type = data.get('schedule_type')
        config = data.get('schedule_config', {})
        
        if schedule_type == 'hourly':
            if 'minute' not in config or not (0 <= config['minute'] <= 59):
                raise ValidationError("Hourly schedule requires 'minute' field (0-59)")
        elif schedule_type == 'daily':
            if 'hour' not in config or not (0 <= config['hour'] <= 23):
                raise ValidationError("Daily schedule requires 'hour' field (0-23)")
            if 'minute' not in config or not (0 <= config['minute'] <= 59):
                raise ValidationError("Daily schedule requires 'minute' field (0-59)")
        elif schedule_type == 'weekly':
            if 'day_of_week' not in config or not (0 <= config['day_of_week'] <= 6):
                raise ValidationError("Weekly schedule requires 'day_of_week' field (0-6)")
            if 'hour' not in config or not (0 <= config['hour'] <= 23):
                raise ValidationError("Weekly schedule requires 'hour' field (0-23)")
            if 'minute' not in config or not (0 <= config['minute'] <= 59):
                raise ValidationError("Weekly schedule requires 'minute' field (0-59)")
        elif schedule_type == 'monthly':
            if 'day' not in config or not (1 <= config['day'] <= 31):
                raise ValidationError("Monthly schedule requires 'day' field (1-31)")
            if 'hour' not in config or not (0 <= config['hour'] <= 23):
                raise ValidationError("Monthly schedule requires 'hour' field (0-23)")
            if 'minute' not in config or not (0 <= config['minute'] <= 59):
                raise ValidationError("Monthly schedule requires 'minute' field (0-59)")
        
        return data
    
    validator.add_global_validator(validate_schedule_config)
    return validator

def recovery_validator() -> RequestValidator:
    """Validator for recovery operations"""
    validator = RequestValidator()
    
    validator.field('backup_id', required=True).type(str).min_length(1)
    validator.field('target_directory').type(str)
    validator.field('items').type(list)
    validator.field('overwrite_existing').type(bool)
    validator.field('verify_integrity').type(bool)
    
    return validator

def storage_backend_validator() -> RequestValidator:
    """Validator for storage backend configuration"""
    validator = RequestValidator()
    
    validator.field('name', required=True).type(str).min_length(1).max_length(100)
    validator.field('storage_type', required=True).choices(['local', 's3', 'sftp', 'azure', 'gcs'])
    validator.field('config', required=True).type(dict)
    validator.field('enabled').type(bool)
    validator.field('priority').type(int).min_value(1).max_value(10)
    validator.field('encryption_enabled').type(bool)
    
    return validator

def pagination_validator() -> RequestValidator:
    """Validator for pagination parameters"""
    validator = RequestValidator()
    
    validator.field('page').type(int).min_value(1)
    validator.field('per_page').type(int).min_value(1).max_value(100)
    validator.field('sort_by').type(str)
    validator.field('sort_order').choices(['asc', 'desc'])
    
    return validator

# Decorator for request validation
def validate_request(validator: RequestValidator, source: str = 'json'):
    """Decorator to validate request data"""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from .responses import validation_error_response
            
            try:
                # Get data from request
                if source == 'json':
                    data = request.get_json() or {}
                elif source == 'form':
                    data = request.form.to_dict()
                elif source == 'args':
                    data = request.args.to_dict()
                else:
                    data = {}
                
                # Validate data
                validated_data = validator.validate(data)
                
                # Store validated data in request context
                request.validated_data = validated_data
                
                return f(*args, **kwargs)
                
            except ValidationError as e:
                # Collect all validation errors
                errors = {}
                if hasattr(e, 'field') and e.field:
                    errors[e.field] = {
                        'message': e.message,
                        'code': e.code
                    }
                else:
                    errors['_general'] = {
                        'message': e.message,
                        'code': e.code
                    }
                
                return validation_error_response(errors, e.message)
            
            except Exception as e:
                logger.error(f"Validation error: {e}")
                return validation_error_response(
                    {'_general': {'message': 'Validation failed', 'code': 'VALIDATION_ERROR'}},
                    'Request validation failed'
                )
        
        return decorated_function
    return decorator

# Utility functions
def sanitize_string(value: str, max_length: int = None) -> str:
    """Sanitize string input"""
    if not isinstance(value, str):
        return str(value)
    
    # Strip whitespace
    value = value.strip()
    
    # Limit length
    if max_length and len(value) > max_length:
        value = value[:max_length]
    
    return value

def validate_backup_id(backup_id: str) -> bool:
    """Validate backup ID format"""
    if not backup_id:
        return False
    
    # Backup IDs should be alphanumeric with underscores and hyphens
    pattern = r'^[a-zA-Z0-9_-]+$'
    return bool(re.match(pattern, backup_id))

def validate_file_path(path: str) -> bool:
    """Validate file path is safe"""
    if not path:
        return False

    # Prevent directory traversal
    if '..' in path or path.startswith('/'):
        return False

    return True

# Security functions
def generate_api_key() -> str:
    """Generate secure API key"""
    return secrets.token_urlsafe(32)

def hash_password(password: str, salt: str = None) -> tuple:
    """Hash password with salt"""
    if not salt:
        salt = secrets.token_hex(16)

    # Use SHA256 for password hashing (simple but secure)
    hashed = hashlib.sha256((password + salt).encode()).hexdigest()
    return hashed, salt

def verify_password(password: str, hashed: str, salt: str) -> bool:
    """Verify password against hash"""
    check_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(check_hash, hashed)

def sanitize_lightning_invoice(invoice: str) -> str:
    """Sanitize Lightning invoice"""
    if not invoice:
        return ""

    # Remove any non-alphanumeric chars except necessary ones
    invoice = re.sub(r'[^a-zA-Z0-9_-]', '', invoice)

    # Validate invoice format
    if not invoice.startswith('lnbc'):
        raise ValidationError("Invalid Lightning invoice format", "invoice", "INVALID_INVOICE")

    return invoice[:500]  # Limit length

def rate_limit_check(identifier: str, limit: int = 100, window: int = 60) -> bool:
    """Simple rate limiting check"""
    # In production, use Redis or similar
    # This is a placeholder for demonstration
    return True