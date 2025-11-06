#!/usr/bin/env python3
"""
Comprehensive Input Validation System
Production-grade validation for national-level security requirements
"""

import re
import ipaddress
from typing import Any, Dict, List, Optional, Union
from decimal import Decimal, InvalidOperation
from urllib.parse import urlparse
import html
import json
from pathlib import Path


class ValidationError(Exception):
    """Custom validation error with detailed information"""
    def __init__(self, field: str, message: str, value: Any = None):
        self.field = field
        self.message = message
        self.value = value
        super().__init__(f"Validation failed for '{field}': {message}")


class InputValidator:
    """
    Comprehensive input validation system with defense-in-depth approach
    Protects against: SQL injection, XSS, path traversal, command injection, etc.
    """

    # Security patterns
    SQL_INJECTION_PATTERNS = [
        r"('|(\\')|(--)|(%27)|(;)|(\bOR\b)|(\bAND\b))",
        r"(\bUNION\b.*\bSELECT\b)|(\bINSERT\b.*\bINTO\b)|(\bUPDATE\b.*\bSET\b)",
        r"(\bDELETE\b.*\bFROM\b)|(\bDROP\b.*\bTABLE\b)|(\bEXEC\b)|(\bEXECUTE\b)",
    ]

    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe",
        r"<embed",
        r"<object",
    ]

    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.",
        r"\.\.\\",
        r"%2e%2e",
        r"%252e%252e",
    ]

    COMMAND_INJECTION_PATTERNS = [
        r"[;&|`$]",
        r"\$\(",
        r">\s*&",
        r"<\s*&",
    ]

    # Lightning Network specific patterns
    BOLT11_PATTERN = r"^(lnbc|lntb|lnbcrt)[0-9]{1,}[a-z0-9]+$"
    NODE_PUBKEY_PATTERN = r"^[0-9a-f]{66}$"
    CHANNEL_ID_PATTERN = r"^[0-9]+x[0-9]+x[0-9]+$"

    @classmethod
    def validate_string(
        cls,
        value: Any,
        field: str = "input",
        min_length: int = 0,
        max_length: int = 1000,
        pattern: Optional[str] = None,
        allow_empty: bool = False,
        sanitize: bool = True
    ) -> str:
        """
        Validate and sanitize string input

        Args:
            value: Input value to validate
            field: Field name for error messages
            min_length: Minimum allowed length
            max_length: Maximum allowed length
            pattern: Optional regex pattern to match
            allow_empty: Whether to allow empty strings
            sanitize: Whether to sanitize HTML/special characters

        Returns:
            Validated and sanitized string

        Raises:
            ValidationError: If validation fails
        """
        # Type check
        if not isinstance(value, str):
            raise ValidationError(field, f"Must be a string, got {type(value).__name__}", value)

        # Empty check
        if not value and not allow_empty:
            raise ValidationError(field, "Cannot be empty", value)

        # Length validation
        if len(value) < min_length:
            raise ValidationError(field, f"Must be at least {min_length} characters", value)

        if len(value) > max_length:
            raise ValidationError(field, f"Must not exceed {max_length} characters", value)

        # Security checks
        cls._check_sql_injection(value, field)
        cls._check_xss(value, field)
        cls._check_command_injection(value, field)

        # Pattern validation
        if pattern and not re.match(pattern, value, re.IGNORECASE):
            raise ValidationError(field, f"Does not match required pattern", value)

        # Sanitization
        if sanitize:
            value = html.escape(value)

        return value

    @classmethod
    def validate_integer(
        cls,
        value: Any,
        field: str = "input",
        min_value: Optional[int] = None,
        max_value: Optional[int] = None,
        allow_negative: bool = False
    ) -> int:
        """
        Validate integer input

        Args:
            value: Input value to validate
            field: Field name for error messages
            min_value: Minimum allowed value
            max_value: Maximum allowed value
            allow_negative: Whether to allow negative values

        Returns:
            Validated integer

        Raises:
            ValidationError: If validation fails
        """
        # Type conversion
        try:
            if isinstance(value, str):
                value = int(value)
            elif not isinstance(value, int):
                raise ValueError()
        except (ValueError, TypeError):
            raise ValidationError(field, f"Must be a valid integer", value)

        # Negative check
        if not allow_negative and value < 0:
            raise ValidationError(field, "Cannot be negative", value)

        # Range validation
        if min_value is not None and value < min_value:
            raise ValidationError(field, f"Must be at least {min_value}", value)

        if max_value is not None and value > max_value:
            raise ValidationError(field, f"Must not exceed {max_value}", value)

        return value

    @classmethod
    def validate_decimal(
        cls,
        value: Any,
        field: str = "input",
        min_value: Optional[Decimal] = None,
        max_value: Optional[Decimal] = None,
        max_decimals: int = 8
    ) -> Decimal:
        """
        Validate decimal/float input with precision control

        Args:
            value: Input value to validate
            field: Field name for error messages
            min_value: Minimum allowed value
            max_value: Maximum allowed value
            max_decimals: Maximum decimal places

        Returns:
            Validated Decimal value

        Raises:
            ValidationError: If validation fails
        """
        try:
            value = Decimal(str(value))
        except (InvalidOperation, ValueError, TypeError):
            raise ValidationError(field, "Must be a valid decimal number", value)

        # Check decimal places
        if abs(value.as_tuple().exponent) > max_decimals:
            raise ValidationError(field, f"Cannot have more than {max_decimals} decimal places", value)

        # Range validation
        if min_value is not None and value < min_value:
            raise ValidationError(field, f"Must be at least {min_value}", value)

        if max_value is not None and value > max_value:
            raise ValidationError(field, f"Must not exceed {max_value}", value)

        return value

    @classmethod
    def validate_amount_sats(cls, value: Any, field: str = "amount") -> int:
        """
        Validate Bitcoin/Lightning amount in satoshis

        Args:
            value: Amount in satoshis
            field: Field name for error messages

        Returns:
            Validated amount in satoshis

        Raises:
            ValidationError: If validation fails
        """
        # Max supply: 21 million BTC = 2.1e15 sats
        MAX_SATS = 21_000_000 * 100_000_000

        amount = cls.validate_integer(
            value,
            field=field,
            min_value=1,
            max_value=MAX_SATS,
            allow_negative=False
        )

        return amount

    @classmethod
    def validate_bolt11_invoice(cls, value: Any, field: str = "invoice") -> str:
        """
        Validate Lightning BOLT11 invoice

        Args:
            value: Invoice string
            field: Field name for error messages

        Returns:
            Validated invoice string

        Raises:
            ValidationError: If validation fails
        """
        invoice = cls.validate_string(
            value,
            field=field,
            min_length=10,
            max_length=2000,
            sanitize=False
        )

        # Check BOLT11 format
        if not re.match(cls.BOLT11_PATTERN, invoice, re.IGNORECASE):
            raise ValidationError(field, "Invalid BOLT11 invoice format", value)

        return invoice

    @classmethod
    def validate_node_pubkey(cls, value: Any, field: str = "node_pubkey") -> str:
        """
        Validate Lightning node public key

        Args:
            value: Node public key (33 bytes hex)
            field: Field name for error messages

        Returns:
            Validated node public key

        Raises:
            ValidationError: If validation fails
        """
        pubkey = cls.validate_string(
            value,
            field=field,
            min_length=66,
            max_length=66,
            sanitize=False
        )

        if not re.match(cls.NODE_PUBKEY_PATTERN, pubkey, re.IGNORECASE):
            raise ValidationError(field, "Invalid node public key format", value)

        return pubkey.lower()

    @classmethod
    def validate_channel_id(cls, value: Any, field: str = "channel_id") -> str:
        """
        Validate Lightning channel ID

        Args:
            value: Channel ID in format block:tx:output
            field: Field name for error messages

        Returns:
            Validated channel ID

        Raises:
            ValidationError: If validation fails
        """
        channel_id = cls.validate_string(
            value,
            field=field,
            min_length=5,
            max_length=30,
            sanitize=False
        )

        if not re.match(cls.CHANNEL_ID_PATTERN, channel_id):
            raise ValidationError(field, "Invalid channel ID format (expected: block:tx:output)", value)

        return channel_id

    @classmethod
    def validate_ip_address(cls, value: Any, field: str = "ip_address") -> str:
        """
        Validate IP address (IPv4 or IPv6)

        Args:
            value: IP address string
            field: Field name for error messages

        Returns:
            Validated IP address

        Raises:
            ValidationError: If validation fails
        """
        ip_str = cls.validate_string(value, field=field, sanitize=False)

        try:
            ipaddress.ip_address(ip_str)
        except ValueError:
            raise ValidationError(field, "Invalid IP address format", value)

        return ip_str

    @classmethod
    def validate_url(
        cls,
        value: Any,
        field: str = "url",
        allowed_schemes: Optional[List[str]] = None,
        require_tls: bool = True
    ) -> str:
        """
        Validate URL

        Args:
            value: URL string
            field: Field name for error messages
            allowed_schemes: List of allowed URL schemes
            require_tls: Whether to require HTTPS/TLS

        Returns:
            Validated URL

        Raises:
            ValidationError: If validation fails
        """
        url_str = cls.validate_string(value, field=field, max_length=2048, sanitize=False)

        try:
            parsed = urlparse(url_str)
        except Exception:
            raise ValidationError(field, "Invalid URL format", value)

        # Scheme validation
        if allowed_schemes is None:
            allowed_schemes = ['https', 'http', 'wss', 'ws']

        if parsed.scheme not in allowed_schemes:
            raise ValidationError(field, f"URL scheme must be one of: {', '.join(allowed_schemes)}", value)

        # TLS requirement
        if require_tls and parsed.scheme in ['http', 'ws']:
            raise ValidationError(field, "URL must use secure protocol (HTTPS/WSS)", value)

        # Host validation
        if not parsed.netloc:
            raise ValidationError(field, "URL must include a valid host", value)

        return url_str

    @classmethod
    def validate_file_path(
        cls,
        value: Any,
        field: str = "file_path",
        must_exist: bool = False,
        allowed_extensions: Optional[List[str]] = None,
        base_directory: Optional[str] = None
    ) -> Path:
        """
        Validate file path with path traversal protection

        Args:
            value: File path string
            field: Field name for error messages
            must_exist: Whether the file must exist
            allowed_extensions: List of allowed file extensions
            base_directory: Base directory to restrict paths to

        Returns:
            Validated Path object

        Raises:
            ValidationError: If validation fails
        """
        path_str = cls.validate_string(value, field=field, sanitize=False)

        # Path traversal check
        cls._check_path_traversal(path_str, field)

        try:
            path = Path(path_str).resolve()
        except Exception as e:
            raise ValidationError(field, f"Invalid file path: {e}", value)

        # Base directory restriction
        if base_directory:
            base_path = Path(base_directory).resolve()
            try:
                path.relative_to(base_path)
            except ValueError:
                raise ValidationError(field, "Path outside allowed directory", value)

        # Existence check
        if must_exist and not path.exists():
            raise ValidationError(field, "File does not exist", value)

        # Extension validation
        if allowed_extensions and path.suffix not in allowed_extensions:
            raise ValidationError(field, f"File extension must be one of: {', '.join(allowed_extensions)}", value)

        return path

    @classmethod
    def validate_json(cls, value: Any, field: str = "json_data") -> Dict[str, Any]:
        """
        Validate JSON data

        Args:
            value: JSON string or dict
            field: Field name for error messages

        Returns:
            Validated JSON as dict

        Raises:
            ValidationError: If validation fails
        """
        if isinstance(value, dict):
            return value

        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError as e:
                raise ValidationError(field, f"Invalid JSON: {e}", value)

        raise ValidationError(field, "Must be JSON string or dict", value)

    @classmethod
    def validate_email(cls, value: Any, field: str = "email") -> str:
        """
        Validate email address

        Args:
            value: Email address string
            field: Field name for error messages

        Returns:
            Validated email address

        Raises:
            ValidationError: If validation fails
        """
        email = cls.validate_string(value, field=field, max_length=254, sanitize=False)

        # RFC 5322 compliant pattern
        pattern = r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"

        if not re.match(pattern, email):
            raise ValidationError(field, "Invalid email address format", value)

        return email.lower()

    @classmethod
    def _check_sql_injection(cls, value: str, field: str):
        """Check for SQL injection patterns"""
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValidationError(field, "Potential SQL injection detected", value)

    @classmethod
    def _check_xss(cls, value: str, field: str):
        """Check for XSS patterns"""
        for pattern in cls.XSS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValidationError(field, "Potential XSS attack detected", value)

    @classmethod
    def _check_command_injection(cls, value: str, field: str):
        """Check for command injection patterns"""
        for pattern in cls.COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, value):
                raise ValidationError(field, "Potential command injection detected", value)

    @classmethod
    def _check_path_traversal(cls, value: str, field: str):
        """Check for path traversal patterns"""
        for pattern in cls.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValidationError(field, "Potential path traversal attack detected", value)


class RequestValidator:
    """Validate HTTP requests"""

    @staticmethod
    def validate_headers(headers: Dict[str, str], required: Optional[List[str]] = None) -> Dict[str, str]:
        """
        Validate HTTP headers

        Args:
            headers: Request headers
            required: List of required header names

        Returns:
            Validated headers

        Raises:
            ValidationError: If validation fails
        """
        if required:
            for header in required:
                if header not in headers:
                    raise ValidationError("headers", f"Required header '{header}' missing")

        # Validate header values
        validated = {}
        for key, value in headers.items():
            try:
                validated[key] = InputValidator.validate_string(
                    value,
                    field=f"header:{key}",
                    max_length=8192
                )
            except ValidationError:
                # Skip invalid headers rather than failing entire request
                continue

        return validated

    @staticmethod
    def validate_query_params(params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate query parameters

        Args:
            params: Query parameters

        Returns:
            Validated parameters

        Raises:
            ValidationError: If validation fails
        """
        validated = {}

        for key, value in params.items():
            # Validate key
            clean_key = InputValidator.validate_string(
                key,
                field="param_name",
                max_length=128,
                pattern=r"^[a-zA-Z0-9_-]+$"
            )

            # Validate value
            if isinstance(value, list):
                validated[clean_key] = [
                    InputValidator.validate_string(v, field=f"param:{clean_key}")
                    for v in value
                ]
            else:
                validated[clean_key] = InputValidator.validate_string(
                    value,
                    field=f"param:{clean_key}"
                )

        return validated
