"""
BLNCS Security Validator
Production-grade security validation and sanitization
"""

import re
import hashlib
import secrets
import hmac
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of validation operation"""
    valid: bool
    sanitized_value: Any = None
    errors: List[str] = None
    warnings: List[str] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []


class SecurityValidator:
    """
    Production-grade security validator with comprehensive input validation,
    sanitization, and attack prevention
    """

    # Regex patterns for validation
    PAYMENT_HASH_PATTERN = re.compile(r'^[0-9a-f]{64}$', re.IGNORECASE)
    LIGHTNING_INVOICE_PATTERN = re.compile(r'^ln[a-z0-9]+$', re.IGNORECASE)
    NODE_PUBKEY_PATTERN = re.compile(r'^[0-9a-f]{66}$', re.IGNORECASE)
    CHANNEL_ID_PATTERN = re.compile(r'^[0-9]+:[0-9]+:[0-9]+$')

    # SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        re.compile(r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)", re.IGNORECASE),
        re.compile(r"(--|\#|\/\*|\*\/)", re.IGNORECASE),
        re.compile(r"(\bOR\b.*=.*)", re.IGNORECASE),
        re.compile(r"(\bAND\b.*=.*)", re.IGNORECASE),
        re.compile(r"(UNION.*SELECT)", re.IGNORECASE),
    ]

    # XSS patterns
    XSS_PATTERNS = [
        re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
        re.compile(r"javascript:", re.IGNORECASE),
        re.compile(r"on\w+\s*=", re.IGNORECASE),
        re.compile(r"<iframe[^>]*>", re.IGNORECASE),
        re.compile(r"<object[^>]*>", re.IGNORECASE),
        re.compile(r"<embed[^>]*>", re.IGNORECASE),
    ]

    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        re.compile(r"\.\./"),
        re.compile(r"\.\./"),
        re.compile(r"%2e%2e/", re.IGNORECASE),
        re.compile(r"\.\.\\"),
    ]

    def __init__(self, max_string_length: int = 10000):
        self.max_string_length = max_string_length
        self._rate_limit_cache: Dict[str, List[datetime]] = {}

    def validate_payment_hash(self, payment_hash: str) -> ValidationResult:
        """Validate Lightning payment hash"""
        if not payment_hash or not isinstance(payment_hash, str):
            return ValidationResult(valid=False, errors=["Payment hash required"])

        if len(payment_hash) != 64:
            return ValidationResult(valid=False, errors=["Payment hash must be 64 characters"])

        if not self.PAYMENT_HASH_PATTERN.match(payment_hash):
            return ValidationResult(valid=False, errors=["Invalid payment hash format"])

        return ValidationResult(valid=True, sanitized_value=payment_hash.lower())

    def validate_lightning_invoice(self, invoice: str) -> ValidationResult:
        """Validate Lightning invoice (bolt11)"""
        if not invoice or not isinstance(invoice, str):
            return ValidationResult(valid=False, errors=["Invoice required"])

        invoice = invoice.strip()

        if len(invoice) < 10 or len(invoice) > 2000:
            return ValidationResult(valid=False, errors=["Invalid invoice length"])

        if not self.LIGHTNING_INVOICE_PATTERN.match(invoice):
            return ValidationResult(valid=False, errors=["Invalid Lightning invoice format"])

        return ValidationResult(valid=True, sanitized_value=invoice)

    def validate_amount(self, amount: Any, min_value: int = 1, max_value: int = 21_000_000_000_000) -> ValidationResult:
        """Validate satoshi amount"""
        try:
            amount_int = int(amount)
        except (TypeError, ValueError):
            return ValidationResult(valid=False, errors=["Amount must be an integer"])

        if amount_int < min_value:
            return ValidationResult(valid=False, errors=[f"Amount must be at least {min_value} sats"])

        if amount_int > max_value:
            return ValidationResult(valid=False, errors=[f"Amount cannot exceed {max_value} sats"])

        return ValidationResult(valid=True, sanitized_value=amount_int)

    def validate_memo(self, memo: str, max_length: int = 1000) -> ValidationResult:
        """Validate and sanitize memo/description"""
        if not memo:
            return ValidationResult(valid=True, sanitized_value="")

        if not isinstance(memo, str):
            return ValidationResult(valid=False, errors=["Memo must be a string"])

        # Check for XSS attempts
        for pattern in self.XSS_PATTERNS:
            if pattern.search(memo):
                return ValidationResult(valid=False, errors=["Memo contains forbidden content"])

        # Sanitize and truncate
        sanitized = memo.strip()[:max_length]

        warnings = []
        if len(memo) > max_length:
            warnings.append(f"Memo truncated to {max_length} characters")

        return ValidationResult(valid=True, sanitized_value=sanitized, warnings=warnings)

    def validate_node_pubkey(self, pubkey: str) -> ValidationResult:
        """Validate Lightning node public key"""
        if not pubkey or not isinstance(pubkey, str):
            return ValidationResult(valid=False, errors=["Node pubkey required"])

        if len(pubkey) != 66:
            return ValidationResult(valid=False, errors=["Node pubkey must be 66 characters"])

        if not self.NODE_PUBKEY_PATTERN.match(pubkey):
            return ValidationResult(valid=False, errors=["Invalid node pubkey format"])

        return ValidationResult(valid=True, sanitized_value=pubkey.lower())

    def validate_channel_id(self, channel_id: str) -> ValidationResult:
        """Validate Lightning channel ID"""
        if not channel_id or not isinstance(channel_id, str):
            return ValidationResult(valid=False, errors=["Channel ID required"])

        if not self.CHANNEL_ID_PATTERN.match(channel_id):
            return ValidationResult(valid=False, errors=["Invalid channel ID format (expected block:tx:output)"])

        return ValidationResult(valid=True, sanitized_value=channel_id)

    def detect_sql_injection(self, text: str) -> bool:
        """Detect potential SQL injection attempts"""
        if not isinstance(text, str):
            return False

        for pattern in self.SQL_INJECTION_PATTERNS:
            if pattern.search(text):
                logger.warning("Potential SQL injection detected", extra={"text": text[:100]})
                return True
        return False

    def detect_xss(self, text: str) -> bool:
        """Detect potential XSS attempts"""
        if not isinstance(text, str):
            return False

        for pattern in self.XSS_PATTERNS:
            if pattern.search(text):
                logger.warning("Potential XSS detected", extra={"text": text[:100]})
                return True
        return False

    def detect_path_traversal(self, text: str) -> bool:
        """Detect potential path traversal attempts"""
        if not isinstance(text, str):
            return False

        for pattern in self.PATH_TRAVERSAL_PATTERNS:
            if pattern.search(text):
                logger.warning("Potential path traversal detected", extra={"text": text[:100]})
                return True
        return False

    def sanitize_string(self, text: str, max_length: Optional[int] = None) -> str:
        """Sanitize string input"""
        if not isinstance(text, str):
            return ""

        # Remove null bytes
        text = text.replace('\x00', '')

        # Normalize whitespace
        text = ' '.join(text.split())

        # Truncate if needed
        if max_length:
            text = text[:max_length]
        elif len(text) > self.max_string_length:
            text = text[:self.max_string_length]

        return text.strip()

    def validate_ip_address(self, ip_str: str) -> ValidationResult:
        """Validate IP address"""
        if not ip_str or not isinstance(ip_str, str):
            return ValidationResult(valid=False, errors=["IP address required"])

        try:
            ip_obj = ip_address(ip_str)

            # Check for private/reserved IPs in production
            warnings = []
            if ip_obj.is_private:
                warnings.append("IP address is private")
            if ip_obj.is_loopback:
                warnings.append("IP address is loopback")
            if ip_obj.is_reserved:
                warnings.append("IP address is reserved")

            return ValidationResult(valid=True, sanitized_value=str(ip_obj), warnings=warnings)
        except ValueError as e:
            return ValidationResult(valid=False, errors=[f"Invalid IP address: {e}"])

    def validate_port(self, port: Any) -> ValidationResult:
        """Validate network port"""
        try:
            port_int = int(port)
        except (TypeError, ValueError):
            return ValidationResult(valid=False, errors=["Port must be an integer"])

        if port_int < 1 or port_int > 65535:
            return ValidationResult(valid=False, errors=["Port must be between 1 and 65535"])

        warnings = []
        if port_int < 1024:
            warnings.append("Port is privileged (< 1024)")

        return ValidationResult(valid=True, sanitized_value=port_int, warnings=warnings)

    def validate_json_payload(self, data: Dict[str, Any], required_fields: Optional[Set[str]] = None) -> ValidationResult:
        """Validate JSON payload structure"""
        if not isinstance(data, dict):
            return ValidationResult(valid=False, errors=["Payload must be a JSON object"])

        errors = []

        # Check required fields
        if required_fields:
            missing = required_fields - set(data.keys())
            if missing:
                errors.append(f"Missing required fields: {', '.join(missing)}")

        # Check for suspicious keys
        for key in data.keys():
            if self.detect_sql_injection(str(key)):
                errors.append(f"Suspicious key detected: {key}")
            if self.detect_path_traversal(str(key)):
                errors.append(f"Path traversal in key: {key}")

        if errors:
            return ValidationResult(valid=False, errors=errors)

        return ValidationResult(valid=True, sanitized_value=data)

    def generate_secure_token(self, length: int = 32) -> str:
        """Generate cryptographically secure token"""
        return secrets.token_urlsafe(length)

    def hash_password(self, password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """Hash password with salt using PBKDF2"""
        if not salt:
            salt = secrets.token_hex(32)

        # Use PBKDF2 with SHA-256
        pwd_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # iterations
        )

        return pwd_hash.hex(), salt

    def verify_password(self, password: str, password_hash: str, salt: str) -> bool:
        """Verify password against hash"""
        computed_hash, _ = self.hash_password(password, salt)
        return hmac.compare_digest(computed_hash, password_hash)

    def check_rate_limit(self, identifier: str, max_requests: int = 100, window_seconds: int = 60) -> bool:
        """Simple rate limiting check"""
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=window_seconds)

        # Initialize if new identifier
        if identifier not in self._rate_limit_cache:
            self._rate_limit_cache[identifier] = []

        # Clean old entries
        self._rate_limit_cache[identifier] = [
            ts for ts in self._rate_limit_cache[identifier]
            if ts > window_start
        ]

        # Check limit
        if len(self._rate_limit_cache[identifier]) >= max_requests:
            return False

        # Add new request
        self._rate_limit_cache[identifier].append(now)
        return True

    def validate_hostname(self, hostname: str) -> ValidationResult:
        """Validate hostname"""
        if not hostname or not isinstance(hostname, str):
            return ValidationResult(valid=False, errors=["Hostname required"])

        # Check length
        if len(hostname) > 253:
            return ValidationResult(valid=False, errors=["Hostname too long"])

        # Check for invalid characters
        if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
            return ValidationResult(valid=False, errors=["Invalid hostname characters"])

        # Check each label
        labels = hostname.split('.')
        for label in labels:
            if len(label) > 63:
                return ValidationResult(valid=False, errors=["Hostname label too long"])
            if label.startswith('-') or label.endswith('-'):
                return ValidationResult(valid=False, errors=["Hostname label cannot start/end with hyphen"])

        return ValidationResult(valid=True, sanitized_value=hostname.lower())


# Singleton instance
_security_validator: Optional[SecurityValidator] = None

def get_security_validator() -> SecurityValidator:
    """Get or create security validator singleton"""
    global _security_validator
    if _security_validator is None:
        _security_validator = SecurityValidator()
    return _security_validator


__all__ = ['SecurityValidator', 'ValidationResult', 'get_security_validator']
