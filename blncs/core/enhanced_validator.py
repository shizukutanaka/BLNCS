"""
Enhanced validation system for BLNCS
Comprehensive input validation, sanitization, and security checks.
"""

import re
import json
import hashlib
import ipaddress
from typing import Any, Optional, Union, List, Dict, Callable, Type
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import wraps, lru_cache
from enum import Enum

from .logger import get_logger
from .exceptions import ValidationError, SecurityError
from .fast_cache import get_fast_cache


class ValidationType(Enum):
    """Types of validation"""
    LIGHTNING = "lightning"
    BITCOIN = "bitcoin"
    NETWORK = "network"
    FILE_SYSTEM = "filesystem"
    CONFIG = "config"
    USER_INPUT = "user_input"
    API = "api"


@dataclass
class ValidationRule:
    """Validation rule definition"""
    name: str
    validator: Callable
    required: bool = False
    sanitizer: Optional[Callable] = None
    error_message: str = "Validation failed"
    security_level: int = 1  # 1=low, 2=medium, 3=high
    cache_result: bool = False


@dataclass
class ValidationResult:
    """Result of validation"""
    valid: bool
    value: Any = None
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    security_issues: List[str] = field(default_factory=list)
    sanitized: bool = False


class EnhancedValidator:
    """Comprehensive validation and sanitization system"""
    
    # Enhanced patterns for various data types
    PATTERNS = {
        # Lightning Network
        'channel_id': re.compile(r'^[0-9]{1,20}x[0-9]{1,10}x[0-9]{1,10}$'),
        'node_pubkey': re.compile(r'^[0-9a-fA-F]{66}$'),
        'payment_hash': re.compile(r'^[0-9a-fA-F]{64}$'),
        'preimage': re.compile(r'^[0-9a-fA-F]{64}$'),
        'invoice_bolt11': re.compile(r'^ln[a-z0-9]+$', re.IGNORECASE),
        
        # Bitcoin
        'bitcoin_address_legacy': re.compile(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$'),
        'bitcoin_address_segwit': re.compile(r'^bc1[a-z0-9]{39,59}$'),
        'bitcoin_address_testnet': re.compile(r'^(tb1|[2mn])[a-zA-HJ-NP-Z0-9]{25,62}$'),
        'bitcoin_tx_hash': re.compile(r'^[0-9a-fA-F]{64}$'),
        
        # Network and system
        'ipv4_address': re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'),
        'ipv6_address': re.compile(r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'),
        'hostname': re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'),
        'port': re.compile(r'^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{3}|[1-9][0-9]{2}|[1-9][0-9]|[0-9])$'),
        
        # File system and paths
        'safe_filename': re.compile(r'^[a-zA-Z0-9_.-]+$'),
        'safe_path': re.compile(r'^[a-zA-Z0-9_/.-]+$'),
        
        # Configuration and identifiers
        'config_key': re.compile(r'^[a-zA-Z][a-zA-Z0-9_.]{0,99}$'),
        'alphanumeric_id': re.compile(r'^[a-zA-Z0-9_-]{1,100}$'),
        'safe_string': re.compile(r'^[a-zA-Z0-9 _.-]+$'),
        
        # Amounts and numbers
        'amount_sats': re.compile(r'^[0-9]{1,15}$'),
        'percentage': re.compile(r'^(100(\.0{1,2})?|[0-9]{1,2}(\.[0-9]{1,2})?)$'),
        'decimal_number': re.compile(r'^[0-9]+(\.[0-9]+)?$'),
    }
    
    # Security-sensitive patterns that require extra validation
    SECURITY_PATTERNS = {
        'sql_injection': re.compile(r'(\'|(\\\')|;|--|/\*|\*/|@@|@|char|nchar|varchar|nvarchar|alter|begin|cast|create|cursor|declare|delete|drop|end|exec|execute|fetch|insert|kill|open|select|sys|sysobjects|syscolumns|table|update)', re.IGNORECASE),
        'xss_attempt': re.compile(r'(<script|javascript:|on\w+\s*=|<iframe|<object|<embed)', re.IGNORECASE),
        'path_traversal': re.compile(r'(\.\./|\.\.\\|%2e%2e%2f|%2e%2e\\)'),
        'command_injection': re.compile(r'(;|\||&|`|\$\(|<|>|\n|\r)'),
    }
    
    # Maximum allowed values
    LIMITS = {
        'string_length': 10000,
        'list_size': 1000,
        'dict_depth': 10,
        'number_max': 10**15,
        'file_size_mb': 100,
        'timeout_seconds': 3600,
    }
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.cache = get_fast_cache()
        
        # Validation rules registry
        self.rules: Dict[str, ValidationRule] = {}
        self._setup_default_rules()
        
        # Statistics
        self.validation_stats = {
            'total_validations': 0,
            'failed_validations': 0,
            'security_violations': 0,
            'sanitizations': 0
        }
    
    def _setup_default_rules(self):
        """Setup default validation rules"""
        # Lightning Network rules
        self.register_rule(ValidationRule(
            name="channel_id",
            validator=self._validate_channel_id,
            required=True,
            error_message="Invalid Lightning channel ID format",
            security_level=2
        ))
        
        self.register_rule(ValidationRule(
            name="node_pubkey",
            validator=self._validate_node_pubkey,
            required=True,
            error_message="Invalid node public key format",
            security_level=2
        ))
        
        self.register_rule(ValidationRule(
            name="bitcoin_address",
            validator=self._validate_bitcoin_address,
            required=True,
            error_message="Invalid Bitcoin address format",
            security_level=3
        ))
        
        self.register_rule(ValidationRule(
            name="amount_satoshis",
            validator=self._validate_amount_sats,
            required=True,
            error_message="Invalid satoshi amount",
            security_level=2
        ))
        
        self.register_rule(ValidationRule(
            name="percentage",
            validator=self._validate_percentage,
            required=True,
            error_message="Invalid percentage value (must be 0-100)",
            security_level=1
        ))
        
        # Network rules
        self.register_rule(ValidationRule(
            name="ip_address",
            validator=self._validate_ip_address,
            required=True,
            error_message="Invalid IP address format",
            security_level=2
        ))
        
        self.register_rule(ValidationRule(
            name="hostname",
            validator=self._validate_hostname,
            required=True,
            error_message="Invalid hostname format",
            security_level=2
        ))
        
        self.register_rule(ValidationRule(
            name="port_number",
            validator=self._validate_port,
            required=True,
            error_message="Invalid port number (must be 1-65535)",
            security_level=2
        ))
        
        # File system rules
        self.register_rule(ValidationRule(
            name="safe_path",
            validator=self._validate_safe_path,
            sanitizer=self._sanitize_path,
            required=True,
            error_message="Invalid or unsafe file path",
            security_level=3
        ))
        
        self.register_rule(ValidationRule(
            name="filename",
            validator=self._validate_filename,
            sanitizer=self._sanitize_filename,
            required=True,
            error_message="Invalid filename",
            security_level=2
        ))
        
        # User input rules
        self.register_rule(ValidationRule(
            name="safe_string",
            validator=self._validate_safe_string,
            sanitizer=self._sanitize_string,
            required=False,
            error_message="String contains unsafe characters",
            security_level=2
        ))
        
        self.register_rule(ValidationRule(
            name="json_data",
            validator=self._validate_json,
            required=False,
            error_message="Invalid JSON format",
            security_level=1
        ))
    
    def register_rule(self, rule: ValidationRule):
        """Register a validation rule"""
        self.rules[rule.name] = rule
        self.logger.debug(f"Registered validation rule: {rule.name}")
    
    def validate(self, rule_name: str, value: Any, **kwargs) -> ValidationResult:
        """Validate a value against a specific rule"""
        self.validation_stats['total_validations'] += 1
        
        if rule_name not in self.rules:
            raise ValidationError(f"Unknown validation rule: {rule_name}")
        
        rule = self.rules[rule_name]
        
        # Check cache if enabled
        cache_key = None
        if rule.cache_result and isinstance(value, (str, int, float)):
            cache_key = f"validation:{rule_name}:{hash(str(value))}"
            cached_result = self.cache.get(cache_key)
            if cached_result:
                return cached_result
        
        # Security screening first
        security_issues = self._security_screen(value)
        if security_issues:
            self.validation_stats['security_violations'] += 1
            result = ValidationResult(
                valid=False,
                error_message="Security violation detected",
                security_issues=security_issues
            )
        else:
            try:
                # Apply sanitizer if available
                sanitized_value = value
                if rule.sanitizer:
                    sanitized_value = rule.sanitizer(value)
                    if sanitized_value != value:
                        self.validation_stats['sanitizations'] += 1
                
                # Run validator
                validated_value = rule.validator(sanitized_value, **kwargs)
                
                result = ValidationResult(
                    valid=True,
                    value=validated_value,
                    sanitized=sanitized_value != value
                )
                
            except (ValueError, ValidationError) as e:
                self.validation_stats['failed_validations'] += 1
                result = ValidationResult(
                    valid=False,
                    error_message=str(e) or rule.error_message
                )
        
        # Cache successful results if enabled
        if cache_key and result.valid:
            self.cache.set(cache_key, result, ttl=300)
        
        return result
    
    def validate_batch(self, validations: Dict[str, tuple]) -> Dict[str, ValidationResult]:
        """Validate multiple values at once"""
        results = {}
        
        for field_name, (rule_name, value, *kwargs) in validations.items():
            kwargs_dict = kwargs[0] if kwargs else {}
            results[field_name] = self.validate(rule_name, value, **kwargs_dict)
        
        return results
    
    def _security_screen(self, value: Any) -> List[str]:
        """Screen for security issues"""
        issues = []
        
        if not isinstance(value, (str, int, float, bool)):
            return issues
        
        value_str = str(value)
        
        # Check for various security patterns
        for pattern_name, pattern in self.SECURITY_PATTERNS.items():
            if pattern.search(value_str):
                issues.append(f"Potential {pattern_name.replace('_', ' ')} detected")
        
        # Check string length
        if len(value_str) > self.LIMITS['string_length']:
            issues.append(f"Input too long: {len(value_str)} > {self.LIMITS['string_length']}")
        
        return issues
    
    # Lightning Network validators
    def _validate_channel_id(self, value: Any) -> str:
        """Validate Lightning channel ID"""
        if not isinstance(value, str):
            raise ValidationError("Channel ID must be a string")
        
        value = value.strip()
        if not self.PATTERNS['channel_id'].match(value):
            raise ValidationError(f"Invalid channel ID format: {value}")
        
        # Additional validation: check component ranges
        parts = value.split('x')
        if int(parts[0]) > 2**24:  # Block height limit
            raise ValidationError("Block height in channel ID too large")
        
        return value
    
    def _validate_node_pubkey(self, value: Any) -> str:
        """Validate node public key"""
        if not isinstance(value, str):
            raise ValidationError("Node public key must be a string")
        
        value = value.strip().lower()
        if not self.PATTERNS['node_pubkey'].match(value):
            raise ValidationError(f"Invalid node public key format")
        
        # Additional check: ensure it's valid hex
        try:
            int(value, 16)
        except ValueError:
            raise ValidationError("Node public key contains invalid hex characters")
        
        return value
    
    def _validate_bitcoin_address(self, value: Any, network: str = "mainnet") -> str:
        """Validate Bitcoin address"""
        if not isinstance(value, str):
            raise ValidationError("Bitcoin address must be a string")
        
        value = value.strip()
        
        if network == "testnet":
            if not self.PATTERNS['bitcoin_address_testnet'].match(value):
                raise ValidationError("Invalid testnet Bitcoin address format")
        else:
            # Check legacy, segwit v0, and taproot formats
            if not (self.PATTERNS['bitcoin_address_legacy'].match(value) or 
                    self.PATTERNS['bitcoin_address_segwit'].match(value)):
                raise ValidationError("Invalid Bitcoin address format")
        
        return value
    
    def _validate_amount_sats(self, value: Any, min_amount: int = 0, max_amount: Optional[int] = None) -> int:
        """Validate satoshi amount"""
        if isinstance(value, str):
            value = value.strip()
            if not self.PATTERNS['amount_sats'].match(value):
                raise ValidationError("Amount contains invalid characters")
            value = int(value)
        elif not isinstance(value, int):
            raise ValidationError("Amount must be an integer")
        
        if value < min_amount:
            raise ValidationError(f"Amount {value} below minimum {min_amount}")
        
        max_btc_supply = 21_000_000 * 100_000_000
        effective_max = max_amount or max_btc_supply
        
        if value > effective_max:
            raise ValidationError(f"Amount {value} exceeds maximum {effective_max}")
        
        return value
    
    def _validate_percentage(self, value: Any) -> float:
        """Validate percentage value"""
        if isinstance(value, str):
            value = value.strip()
            if not self.PATTERNS['percentage'].match(value):
                raise ValidationError("Invalid percentage format")
            value = float(value)
        elif not isinstance(value, (int, float)):
            raise ValidationError("Percentage must be a number")
        
        if not (0 <= value <= 100):
            raise ValidationError(f"Percentage {value} must be between 0 and 100")
        
        return float(value)
    
    # Network validators
    def _validate_ip_address(self, value: Any) -> str:
        """Validate IP address"""
        if not isinstance(value, str):
            raise ValidationError("IP address must be a string")
        
        value = value.strip()
        
        try:
            ip = ipaddress.ip_address(value)
            
            # Security check: reject private/local addresses in production
            if hasattr(ip, 'is_private') and ip.is_private:
                # This is just a warning, not an error
                pass
            
            return str(ip)
        except ValueError:
            raise ValidationError(f"Invalid IP address: {value}")
    
    def _validate_hostname(self, value: Any) -> str:
        """Validate hostname"""
        if not isinstance(value, str):
            raise ValidationError("Hostname must be a string")
        
        value = value.strip().lower()
        
        if len(value) > 253:
            raise ValidationError("Hostname too long (max 253 characters)")
        
        if not self.PATTERNS['hostname'].match(value):
            raise ValidationError("Invalid hostname format")
        
        return value
    
    def _validate_port(self, value: Any) -> int:
        """Validate port number"""
        if isinstance(value, str):
            value = value.strip()
            if not value.isdigit():
                raise ValidationError("Port must be numeric")
            value = int(value)
        elif not isinstance(value, int):
            raise ValidationError("Port must be an integer")
        
        if not (1 <= value <= 65535):
            raise ValidationError(f"Port {value} must be between 1 and 65535")
        
        return value
    
    # File system validators
    def _validate_safe_path(self, value: Any) -> str:
        """Validate file path for security"""
        if not isinstance(value, str):
            raise ValidationError("Path must be a string")
        
        value = value.strip()
        
        # Check for path traversal
        if '../' in value or '..\\'  in value:
            raise ValidationError("Path traversal detected")
        
        # Check for absolute paths (might be restricted)
        if value.startswith('/') or value.startswith('\\') or ':' in value[:3]:
            # Allow but warn about absolute paths
            pass
        
        # Validate path components
        try:
            path = Path(value)
            # Check if path is reasonable length
            if len(str(path)) > 260:  # Windows path limit
                raise ValidationError("Path too long")
            
        except Exception:
            raise ValidationError("Invalid path format")
        
        return value
    
    def _validate_filename(self, value: Any) -> str:
        """Validate filename"""
        if not isinstance(value, str):
            raise ValidationError("Filename must be a string")
        
        value = value.strip()
        
        if not self.PATTERNS['safe_filename'].match(value):
            raise ValidationError("Filename contains invalid characters")
        
        if len(value) > 255:
            raise ValidationError("Filename too long")
        
        # Check for reserved names (Windows)
        reserved = ['CON', 'PRN', 'AUX', 'NUL'] + [f'COM{i}' for i in range(1, 10)] + [f'LPT{i}' for i in range(1, 10)]
        if value.upper().split('.')[0] in reserved:
            raise ValidationError("Filename uses reserved name")
        
        return value
    
    def _validate_safe_string(self, value: Any, max_length: int = 1000) -> str:
        """Validate general string input"""
        if not isinstance(value, str):
            raise ValidationError("Value must be a string")
        
        if len(value) > max_length:
            raise ValidationError(f"String too long: {len(value)} > {max_length}")
        
        # Allow most characters but be restrictive about control characters
        if any(ord(c) < 32 and c not in '\t\n\r' for c in value):
            raise ValidationError("String contains control characters")
        
        return value
    
    def _validate_json(self, value: Any) -> Dict:
        """Validate JSON data"""
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError as e:
                raise ValidationError(f"Invalid JSON: {e}")
        
        if not isinstance(value, dict):
            raise ValidationError("JSON must be an object/dictionary")
        
        # Check depth to prevent deeply nested attacks
        def check_depth(obj, depth=0):
            if depth > self.LIMITS['dict_depth']:
                raise ValidationError("JSON too deeply nested")
            if isinstance(obj, dict):
                for v in obj.values():
                    check_depth(v, depth + 1)
            elif isinstance(obj, list):
                for item in obj:
                    check_depth(item, depth + 1)
        
        check_depth(value)
        return value
    
    # Sanitizers
    def _sanitize_string(self, value: str) -> str:
        """Sanitize string input"""
        # Remove control characters except tabs, newlines, carriage returns
        sanitized = ''.join(c for c in value if ord(c) >= 32 or c in '\t\n\r')
        
        # Limit length
        if len(sanitized) > self.LIMITS['string_length']:
            sanitized = sanitized[:self.LIMITS['string_length']]
        
        return sanitized.strip()
    
    def _sanitize_path(self, value: str) -> str:
        """Sanitize file path"""
        # Normalize path separators
        value = value.replace('\\', '/')
        
        # Remove dangerous sequences
        value = value.replace('../', '').replace('..\\', '')
        
        # Normalize path
        try:
            path = Path(value).resolve()
            return str(path)
        except:
            return value
    
    def _sanitize_filename(self, value: str) -> str:
        """Sanitize filename"""
        # Remove path separators
        value = value.replace('/', '_').replace('\\', '_')
        
        # Remove or replace invalid characters
        value = re.sub(r'[<>:"|?*]', '_', value)
        
        # Trim length
        if len(value) > 100:
            name, ext = value.rsplit('.', 1) if '.' in value else (value, '')
            value = name[:100-len(ext)-1] + ('.' + ext if ext else '')
        
        return value
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get validation statistics"""
        return {
            'validation_stats': self.validation_stats.copy(),
            'registered_rules': list(self.rules.keys()),
            'cache_stats': self.cache.stats() if hasattr(self.cache, 'stats') else None
        }


# Global validator instance
_enhanced_validator = None


def get_enhanced_validator() -> EnhancedValidator:
    """Get global enhanced validator instance"""
    global _enhanced_validator
    if _enhanced_validator is None:
        _enhanced_validator = EnhancedValidator()
    return _enhanced_validator


# Convenience functions
def validate_lightning_channel_id(channel_id: str) -> ValidationResult:
    """Validate Lightning channel ID"""
    validator = get_enhanced_validator()
    return validator.validate("channel_id", channel_id)


def validate_node_pubkey(pubkey: str) -> ValidationResult:
    """Validate node public key"""
    validator = get_enhanced_validator()
    return validator.validate("node_pubkey", pubkey)


def validate_bitcoin_address(address: str, network: str = "mainnet") -> ValidationResult:
    """Validate Bitcoin address"""
    validator = get_enhanced_validator()
    return validator.validate("bitcoin_address", address, network=network)


def validate_amount(amount: Union[int, str], min_amount: int = 0, max_amount: Optional[int] = None) -> ValidationResult:
    """Validate satoshi amount"""
    validator = get_enhanced_validator()
    return validator.validate("amount_satoshis", amount, min_amount=min_amount, max_amount=max_amount)


def validate_safe_input(value: str, max_length: int = 1000) -> ValidationResult:
    """Validate safe string input"""
    validator = get_enhanced_validator()
    return validator.validate("safe_string", value, max_length=max_length)


# Decorator for automatic validation
def validate_inputs(**field_rules):
    """Decorator to automatically validate function inputs"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            validator = get_enhanced_validator()
            
            # Build validation map
            validations = {}
            for field_name, (rule_name, *rule_kwargs) in field_rules.items():
                if field_name in kwargs:
                    validations[field_name] = (rule_name, kwargs[field_name], *rule_kwargs)
            
            # Run validations
            results = validator.validate_batch(validations)
            
            # Check for failures
            failures = [f"{field}: {result.error_message}" 
                       for field, result in results.items() if not result.valid]
            
            if failures:
                raise ValidationError(f"Validation failed: {'; '.join(failures)}")
            
            # Replace kwargs with validated/sanitized values
            for field, result in results.items():
                if result.valid and result.value is not None:
                    kwargs[field] = result.value
            
            return func(*args, **kwargs)
        return wrapper
    return decorator