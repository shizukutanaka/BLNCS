"""
Data Validation and Sanitization for BLNCS
セキュアで実用的なデータ検証・無害化
"""

import re
import html
import json
from typing import Any, Dict, List, Optional, Union, Callable
from dataclasses import dataclass
from enum import Enum
import logging


class ValidationLevel(Enum):
    """Validation strictness levels"""
    LENIENT = "lenient"
    NORMAL = "normal"
    STRICT = "strict"


@dataclass
class ValidationRule:
    """Single validation rule"""
    name: str
    validator: Callable[[Any], bool]
    message: str
    sanitizer: Optional[Callable[[Any], Any]] = None


@dataclass
class ValidationResult:
    """Validation result"""
    valid: bool
    sanitized_value: Any = None
    errors: List[str] = None
    warnings: List[str] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []


class DataValidator:
    """Comprehensive data validator and sanitizer"""

    def __init__(self, level: ValidationLevel = ValidationLevel.NORMAL):
        self.level = level
        self.logger = logging.getLogger(__name__)

        # Common patterns
        self.patterns = {
            'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
            'bitcoin_address': re.compile(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$'),
            'lightning_invoice': re.compile(r'^ln[a-z]{2,5}[0-9]{1,}[a-z0-9]+$', re.IGNORECASE),
            'payment_hash': re.compile(r'^[a-fA-F0-9]{64}$'),
            'node_pubkey': re.compile(r'^[a-fA-F0-9]{66}$'),
            'alphanumeric': re.compile(r'^[a-zA-Z0-9]+$'),
            'safe_string': re.compile(r'^[a-zA-Z0-9\s\-_.,!?]+$'),
            'sql_injection': re.compile(r'(\'|(\')\s*(or|and)\s*(\'|\')|\-\-|;|\*|\/\*|\*\/)', re.IGNORECASE),
            'xss_pattern': re.compile(r'<[^>]*script[^>]*>|javascript:|on\w+\s*=', re.IGNORECASE)
        }

    def validate_amount(self, amount: Any, min_value: int = 1, max_value: int = 100000000) -> ValidationResult:
        """Validate Bitcoin/Lightning amount in satoshis"""
        try:
            if isinstance(amount, str):
                amount = int(amount)

            if not isinstance(amount, int):
                return ValidationResult(valid=False, errors=["Amount must be an integer"])

            if amount < min_value:
                return ValidationResult(valid=False, errors=[f"Amount must be at least {min_value} satoshis"])

            if amount > max_value:
                return ValidationResult(valid=False, errors=[f"Amount cannot exceed {max_value} satoshis"])

            return ValidationResult(valid=True, sanitized_value=amount)

        except ValueError:
            return ValidationResult(valid=False, errors=["Invalid amount format"])

    def validate_memo(self, memo: Any, max_length: int = 200) -> ValidationResult:
        """Validate and sanitize memo text"""
        if memo is None:
            return ValidationResult(valid=True, sanitized_value="")

        if not isinstance(memo, str):
            memo = str(memo)

        # Sanitize
        sanitized = self.sanitize_text(memo)

        # Check length
        if len(sanitized) > max_length:
            if self.level == ValidationLevel.STRICT:
                return ValidationResult(valid=False, errors=[f"Memo too long (max {max_length} characters)"])
            else:
                # Truncate in lenient/normal mode
                sanitized = sanitized[:max_length]

        # Check for suspicious content
        warnings = []
        if self.patterns['xss_pattern'].search(sanitized):
            if self.level == ValidationLevel.STRICT:
                return ValidationResult(valid=False, errors=["Memo contains potentially dangerous content"])
            else:
                # Further sanitize
                sanitized = re.sub(r'<[^>]*>', '', sanitized)
                warnings.append("HTML tags removed from memo")

        return ValidationResult(valid=True, sanitized_value=sanitized, warnings=warnings)

    def validate_lightning_invoice(self, invoice: Any) -> ValidationResult:
        """Validate Lightning Network invoice"""
        if not isinstance(invoice, str):
            return ValidationResult(valid=False, errors=["Invoice must be a string"])

        # Remove whitespace
        invoice = invoice.strip()

        if not invoice:
            return ValidationResult(valid=False, errors=["Invoice cannot be empty"])

        # Basic format check
        if not self.patterns['lightning_invoice'].match(invoice):
            return ValidationResult(valid=False, errors=["Invalid Lightning invoice format"])

        # Length check (invoices are typically 200-400 characters)
        if len(invoice) < 100 or len(invoice) > 1000:
            return ValidationResult(valid=False, errors=["Invoice length is suspicious"])

        return ValidationResult(valid=True, sanitized_value=invoice)

    def validate_api_key(self, api_key: Any) -> ValidationResult:
        """Validate API key format"""
        if not isinstance(api_key, str):
            return ValidationResult(valid=False, errors=["API key must be a string"])

        api_key = api_key.strip()

        if not api_key:
            return ValidationResult(valid=False, errors=["API key cannot be empty"])

        # Check format (expecting blncs_xxxxx format)
        if not api_key.startswith('blncs_'):
            return ValidationResult(valid=False, errors=["Invalid API key format"])

        # Check length and character set
        key_part = api_key[6:]  # Remove 'blncs_' prefix
        if len(key_part) != 32 or not re.match(r'^[a-fA-F0-9]+$', key_part):
            return ValidationResult(valid=False, errors=["Invalid API key format"])

        return ValidationResult(valid=True, sanitized_value=api_key)

    def validate_json_data(self, data: Any, schema: Optional[Dict[str, Any]] = None) -> ValidationResult:
        """Validate JSON data structure"""
        try:
            if isinstance(data, str):
                data = json.loads(data)

            if not isinstance(data, (dict, list)):
                return ValidationResult(valid=False, errors=["Data must be JSON object or array"])

            # Basic schema validation if provided
            if schema and isinstance(data, dict):
                for required_field in schema.get('required', []):
                    if required_field not in data:
                        return ValidationResult(valid=False, errors=[f"Missing required field: {required_field}"])

            # Sanitize recursive
            sanitized = self.sanitize_json(data)

            return ValidationResult(valid=True, sanitized_value=sanitized)

        except json.JSONDecodeError as e:
            return ValidationResult(valid=False, errors=[f"Invalid JSON: {str(e)}"])

    def validate_pagination(self, page: Any, per_page: Any, max_per_page: int = 100) -> ValidationResult:
        """Validate pagination parameters"""
        errors = []
        sanitized = {}

        # Validate page
        try:
            page = int(page) if page is not None else 1
            if page < 1:
                page = 1
            sanitized['page'] = page
        except ValueError:
            errors.append("Invalid page number")

        # Validate per_page
        try:
            per_page = int(per_page) if per_page is not None else 20
            if per_page < 1:
                per_page = 1
            elif per_page > max_per_page:
                per_page = max_per_page
            sanitized['per_page'] = per_page
        except ValueError:
            errors.append("Invalid per_page value")

        if errors:
            return ValidationResult(valid=False, errors=errors)

        return ValidationResult(valid=True, sanitized_value=sanitized)

    def sanitize_text(self, text: str) -> str:
        """Sanitize text input"""
        if not isinstance(text, str):
            text = str(text)

        # HTML escape
        text = html.escape(text)

        # Remove null bytes
        text = text.replace('\x00', '')

        # Remove or replace dangerous characters
        if self.level == ValidationLevel.STRICT:
            # Only allow safe characters
            text = re.sub(r'[^\w\s\-_.,!?@#$%^&*()+=\[\]{}|;:\'",.<>/?`~]', '', text)

        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text).strip()

        return text

    def sanitize_json(self, data: Any) -> Any:
        """Recursively sanitize JSON data"""
        if isinstance(data, dict):
            return {
                self.sanitize_text(str(k)): self.sanitize_json(v)
                for k, v in data.items()
            }
        elif isinstance(data, list):
            return [self.sanitize_json(item) for item in data]
        elif isinstance(data, str):
            return self.sanitize_text(data)
        else:
            return data

    def check_sql_injection(self, value: str) -> bool:
        """Check for SQL injection patterns"""
        return bool(self.patterns['sql_injection'].search(value))

    def check_xss(self, value: str) -> bool:
        """Check for XSS patterns"""
        return bool(self.patterns['xss_pattern'].search(value))

    def validate_batch(self, data: Dict[str, Any], rules: Dict[str, ValidationRule]) -> Dict[str, ValidationResult]:
        """Validate multiple fields with different rules"""
        results = {}

        for field_name, rule in rules.items():
            value = data.get(field_name)

            try:
                # Run validator
                is_valid = rule.validator(value)

                if is_valid:
                    # Apply sanitizer if available
                    sanitized_value = rule.sanitizer(value) if rule.sanitizer else value
                    results[field_name] = ValidationResult(valid=True, sanitized_value=sanitized_value)
                else:
                    results[field_name] = ValidationResult(valid=False, errors=[rule.message])

            except Exception as e:
                results[field_name] = ValidationResult(valid=False, errors=[f"Validation error: {str(e)}"])

        return results

    def validate_input(self, value: Any, input_type: str = "text") -> bool:
        """Generic input validation (for compatibility)"""
        try:
            if input_type == "text":
                result = self.sanitize_text(str(value))
                return len(result) > 0
            elif input_type == "amount":
                result = self.validate_amount(value)
                return result.valid
            elif input_type == "invoice":
                result = self.validate_lightning_invoice(value)
                return result.valid
            else:
                # Basic validation - not empty and no dangerous characters
                text = str(value)
                return len(text) > 0 and not self.check_sql_injection(text) and not self.check_xss(text)
        except Exception:
            return False

    def create_invoice_validator(self) -> Dict[str, ValidationRule]:
        """Create validation rules for invoice creation"""
        return {
            'amount': ValidationRule(
                name='amount',
                validator=lambda x: isinstance(x, (int, str)) and int(x) > 0,
                message='Amount must be a positive integer',
                sanitizer=lambda x: int(x)
            ),
            'memo': ValidationRule(
                name='memo',
                validator=lambda x: x is None or (isinstance(x, str) and len(x) <= 200),
                message='Memo must be a string with max 200 characters',
                sanitizer=self.sanitize_text
            )
        }

    def create_payment_validator(self) -> Dict[str, ValidationRule]:
        """Create validation rules for payments"""
        return {
            'payment_request': ValidationRule(
                name='payment_request',
                validator=lambda x: isinstance(x, str) and self.patterns['lightning_invoice'].match(x.strip()),
                message='Invalid Lightning invoice format',
                sanitizer=lambda x: x.strip()
            )
        }


# Decorator for automatic validation
def validate_request(validator_func: Callable[[DataValidator], Dict[str, ValidationRule]]):
    """Decorator to validate request data"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                from flask import request, jsonify

                validator = DataValidator()
                rules = validator_func(validator)

                # Get request data
                if request.method in ['POST', 'PUT', 'PATCH']:
                    data = request.get_json() or {}
                else:
                    data = dict(request.args)

                # Validate
                results = validator.validate_batch(data, rules)

                # Check for validation errors
                errors = []
                sanitized_data = {}

                for field, result in results.items():
                    if not result.valid:
                        errors.extend([f"{field}: {error}" for error in result.errors])
                    else:
                        sanitized_data[field] = result.sanitized_value

                if errors:
                    return jsonify({'error': 'Validation failed', 'details': errors}), 400

                # Add sanitized data to kwargs
                kwargs['validated_data'] = sanitized_data
                return func(*args, **kwargs)

            except Exception as e:
                return jsonify({'error': f'Validation error: {str(e)}'}), 500

        return wrapper
    return decorator


# Global validator instance
_global_validator = None


def get_validator(level: ValidationLevel = ValidationLevel.NORMAL) -> DataValidator:
    """Get global validator instance"""
    global _global_validator
    if _global_validator is None:
        _global_validator = DataValidator(level)
    return _global_validator


# Convenience functions
def validate_amount(amount: Any, min_value: int = 1, max_value: int = 100000000) -> ValidationResult:
    """Quick amount validation"""
    return get_validator().validate_amount(amount, min_value, max_value)


def sanitize_text(text: str) -> str:
    """Quick text sanitization"""
    return get_validator().sanitize_text(text)


def validate_invoice(invoice: str) -> ValidationResult:
    """Quick invoice validation"""
    return get_validator().validate_lightning_invoice(invoice)


__all__ = [
    'DataValidator', 'ValidationRule', 'ValidationResult', 'ValidationLevel',
    'validate_request', 'get_validator',
    'validate_amount', 'sanitize_text', 'validate_invoice'
]