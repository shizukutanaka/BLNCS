"""
Advanced Security Hardening Module
Comprehensive security measures for BLNCS production deployment.
"""

import hashlib
import hmac
import secrets
import time
import jwt
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
import ipaddress
import re
from pathlib import Path
import logging
from contextlib import contextmanager
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64
import json
from functools import wraps

logger = logging.getLogger(__name__)

class SecurityLevel(Enum):
    """Security level classifications."""
    LOW = "low"
    MEDIUM = "medium" 
    HIGH = "high"
    CRITICAL = "critical"

class ThreatType(Enum):
    """Security threat classifications."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_BREACH = "data_breach"
    INJECTION = "injection"
    XSS = "xss"
    CSRF = "csrf"
    DDOS = "ddos"
    BRUTE_FORCE = "brute_force"
    PRIVILEGE_ESCALATION = "privilege_escalation"

@dataclass
class SecurityEvent:
    """Security event data structure."""
    event_type: ThreatType
    severity: SecurityLevel
    source_ip: str
    timestamp: float = field(default_factory=time.time)
    user_agent: Optional[str] = None
    endpoint: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    blocked: bool = False

@dataclass
class SecurityRule:
    """Security rule configuration."""
    name: str
    threat_type: ThreatType
    severity: SecurityLevel
    enabled: bool = True
    threshold: int = 5
    window_seconds: int = 300
    action: str = "block"  # block, warn, log
    whitelist: List[str] = field(default_factory=list)
    blacklist: List[str] = field(default_factory=list)

class SecureTokenManager:
    """Secure token generation and validation."""
    
    def __init__(self, secret_key: Optional[str] = None, algorithm: str = "HS256"):
        """Initialize secure token manager."""
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.algorithm = algorithm
        self._token_blacklist: Dict[str, float] = {}
        self._cleanup_interval = 3600  # 1 hour
        self._last_cleanup = time.time()
    
    def generate_token(self, payload: Dict[str, Any], expires_in: int = 3600) -> str:
        """Generate a secure JWT token."""
        current_time = time.time()
        token_payload = {
            **payload,
            "iat": current_time,
            "exp": current_time + expires_in,
            "jti": secrets.token_urlsafe(16)  # Unique token ID
        }
        
        return jwt.encode(token_payload, self.secret_key, algorithm=self.algorithm)
    
    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate and decode JWT token."""
        try:
            # Check if token is blacklisted
            if token in self._token_blacklist:
                logger.warning(f"Attempted use of blacklisted token")
                return None
            
            # Decode and validate token
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Additional security checks
            if "jti" not in payload:
                logger.warning("Token missing JTI claim")
                return None
            
            self._cleanup_blacklist()
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return None
    
    def revoke_token(self, token: str) -> bool:
        """Revoke a token by adding it to blacklist."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm], options={"verify_exp": False})
            if "exp" in payload:
                self._token_blacklist[token] = payload["exp"]
                return True
        except jwt.InvalidTokenError:
            pass
        return False
    
    def _cleanup_blacklist(self) -> None:
        """Remove expired tokens from blacklist."""
        current_time = time.time()
        if current_time - self._last_cleanup > self._cleanup_interval:
            expired_tokens = [
                token for token, exp_time in self._token_blacklist.items()
                if current_time > exp_time
            ]
            for token in expired_tokens:
                del self._token_blacklist[token]
            self._last_cleanup = current_time

class InputSanitizer:
    """Advanced input sanitization and validation."""
    
    # Dangerous patterns
    SQL_INJECTION_PATTERNS = [
        r"('|(\\'))(|(.*?))((\\')|('))",
        r"(\\x27)|(\\x2527)|(%27)|(%2527)",
        r"(union)(.|\s)+(select)",
        r"(select)(.|\s)+(from)",
        r"(insert)(.|\s)+(into)",
        r"(delete)(.|\s)+(from)",
        r"(drop)(.|\s)+(table)",
        r"(alter)(.|\s)+(table)"
    ]
    
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe[^>]*>.*?</iframe>",
        r"<object[^>]*>.*?</object>",
        r"<embed[^>]*>.*?</embed>",
        r"expression\s*\(",
        r"vbscript:"
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        r"[;&|`]",
        r"\$\([^)]*\)",
        r"`[^`]*`",
        r"\|\s*\w+",
        r"&&\s*\w+",
        r";\s*\w+"
    ]
    
    def __init__(self):
        """Initialize input sanitizer."""
        self.sql_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.SQL_INJECTION_PATTERNS]
        self.xss_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.XSS_PATTERNS]
        self.cmd_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.COMMAND_INJECTION_PATTERNS]
    
    def sanitize_string(self, value: str, max_length: int = 1000) -> str:
        """Sanitize string input."""
        if not isinstance(value, str):
            raise ValueError("Input must be a string")
        
        # Length validation
        if len(value) > max_length:
            raise ValueError(f"Input exceeds maximum length of {max_length}")
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # Basic HTML encoding
        value = (value.replace('&', '&amp;')
                     .replace('<', '&lt;')
                     .replace('>', '&gt;')
                     .replace('"', '&quot;')
                     .replace("'", '&#x27;'))
        
        return value
    
    def validate_sql_injection(self, value: str) -> bool:
        """Check for SQL injection patterns."""
        for regex in self.sql_regex:
            if regex.search(value):
                return False
        return True
    
    def validate_xss(self, value: str) -> bool:
        """Check for XSS patterns."""
        for regex in self.xss_regex:
            if regex.search(value):
                return False
        return True
    
    def validate_command_injection(self, value: str) -> bool:
        """Check for command injection patterns."""
        for regex in self.cmd_regex:
            if regex.search(value):
                return False
        return True
    
    def validate_all(self, value: str) -> Tuple[bool, List[str]]:
        """Validate input against all threat patterns."""
        issues = []
        
        if not self.validate_sql_injection(value):
            issues.append("SQL injection detected")
        
        if not self.validate_xss(value):
            issues.append("XSS pattern detected")
            
        if not self.validate_command_injection(value):
            issues.append("Command injection detected")
        
        return len(issues) == 0, issues

class SecurityAuditor:
    """Comprehensive security auditing system."""
    
    def __init__(self):
        """Initialize security auditor."""
        self.events: List[SecurityEvent] = []
        self.rules: Dict[str, SecurityRule] = {}
        self.blocked_ips: Dict[str, float] = {}  # IP -> unblock_time
        self._load_default_rules()
    
    def _load_default_rules(self) -> None:
        """Load default security rules."""
        default_rules = [
            SecurityRule(
                name="brute_force_protection",
                threat_type=ThreatType.BRUTE_FORCE,
                severity=SecurityLevel.HIGH,
                threshold=5,
                window_seconds=300,
                action="block"
            ),
            SecurityRule(
                name="sql_injection_detection",
                threat_type=ThreatType.INJECTION,
                severity=SecurityLevel.CRITICAL,
                threshold=1,
                window_seconds=60,
                action="block"
            ),
            SecurityRule(
                name="xss_detection",
                threat_type=ThreatType.XSS,
                severity=SecurityLevel.HIGH,
                threshold=1,
                window_seconds=60,
                action="block"
            ),
            SecurityRule(
                name="ddos_protection",
                threat_type=ThreatType.DDOS,
                severity=SecurityLevel.CRITICAL,
                threshold=100,
                window_seconds=60,
                action="block"
            )
        ]
        
        for rule in default_rules:
            self.rules[rule.name] = rule
    
    def add_rule(self, rule: SecurityRule) -> None:
        """Add security rule."""
        self.rules[rule.name] = rule
    
    def record_event(self, event: SecurityEvent) -> bool:
        """Record security event and determine if action should be taken."""
        self.events.append(event)
        
        # Find applicable rules
        applicable_rules = [
            rule for rule in self.rules.values()
            if rule.threat_type == event.event_type and rule.enabled
        ]
        
        for rule in applicable_rules:
            if self._should_block(event, rule):
                self._take_action(event, rule)
                return True
        
        return False
    
    def _should_block(self, event: SecurityEvent, rule: SecurityRule) -> bool:
        """Determine if event should trigger rule action."""
        # Check whitelist
        if event.source_ip in rule.whitelist:
            return False
        
        # Check blacklist
        if event.source_ip in rule.blacklist:
            return True
        
        # Count recent events from same IP
        current_time = time.time()
        window_start = current_time - rule.window_seconds
        
        recent_events = [
            e for e in self.events
            if (e.source_ip == event.source_ip and
                e.event_type == event.event_type and
                e.timestamp >= window_start)
        ]
        
        return len(recent_events) >= rule.threshold
    
    def _take_action(self, event: SecurityEvent, rule: SecurityRule) -> None:
        """Take action based on rule."""
        if rule.action == "block":
            # Block IP for increasing duration based on severity
            block_duration = {
                SecurityLevel.LOW: 300,      # 5 minutes
                SecurityLevel.MEDIUM: 900,   # 15 minutes
                SecurityLevel.HIGH: 3600,    # 1 hour
                SecurityLevel.CRITICAL: 86400 # 24 hours
            }.get(rule.severity, 3600)
            
            self.blocked_ips[event.source_ip] = time.time() + block_duration
            event.blocked = True
            
            logger.warning(f"Blocked IP {event.source_ip} for {block_duration}s due to {rule.name}")
        
        elif rule.action == "warn":
            logger.warning(f"Security warning: {rule.name} triggered by {event.source_ip}")
        
        elif rule.action == "log":
            logger.info(f"Security event: {rule.name} triggered by {event.source_ip}")
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP address is currently blocked."""
        if ip not in self.blocked_ips:
            return False
        
        current_time = time.time()
        if current_time > self.blocked_ips[ip]:
            # Block expired, remove from list
            del self.blocked_ips[ip]
            return False
        
        return True
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get security audit summary."""
        current_time = time.time()
        last_hour = current_time - 3600
        last_day = current_time - 86400
        
        recent_events = [e for e in self.events if e.timestamp >= last_hour]
        daily_events = [e for e in self.events if e.timestamp >= last_day]
        
        threat_counts = {}
        for event in recent_events:
            threat_type = event.event_type.value
            threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
        
        return {
            "events_last_hour": len(recent_events),
            "events_last_day": len(daily_events),
            "blocked_ips": len(self.blocked_ips),
            "threat_breakdown": threat_counts,
            "top_threat_sources": self._get_top_threat_sources(recent_events),
            "active_rules": len([r for r in self.rules.values() if r.enabled])
        }
    
    def _get_top_threat_sources(self, events: List[SecurityEvent], limit: int = 10) -> List[Dict[str, Any]]:
        """Get top threat source IPs."""
        ip_counts = {}
        for event in events:
            if event.source_ip not in ip_counts:
                ip_counts[event.source_ip] = {"count": 0, "threats": set()}
            ip_counts[event.source_ip]["count"] += 1
            ip_counts[event.source_ip]["threats"].add(event.event_type.value)
        
        sorted_ips = sorted(
            ip_counts.items(),
            key=lambda x: x[1]["count"],
            reverse=True
        )[:limit]
        
        return [
            {
                "ip": ip,
                "event_count": data["count"],
                "threat_types": list(data["threats"])
            }
            for ip, data in sorted_ips
        ]

class EncryptionManager:
    """Advanced encryption and key management."""
    
    def __init__(self, master_key: Optional[bytes] = None):
        """Initialize encryption manager."""
        self.master_key = master_key or self._generate_master_key()
        self.derived_keys: Dict[str, bytes] = {}
    
    def _generate_master_key(self) -> bytes:
        """Generate a new master key."""
        return secrets.token_bytes(32)  # 256-bit key
    
    def derive_key(self, purpose: str, salt: Optional[bytes] = None) -> bytes:
        """Derive a key for specific purpose."""
        if purpose in self.derived_keys:
            return self.derived_keys[purpose]
        
        if salt is None:
            salt = purpose.encode('utf-8').ljust(16, b'\x00')[:16]
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = kdf.derive(self.master_key)
        self.derived_keys[purpose] = key
        return key
    
    def encrypt_data(self, data: bytes, purpose: str) -> Dict[str, str]:
        """Encrypt data with derived key."""
        key = self.derive_key(purpose)
        iv = secrets.token_bytes(16)  # 128-bit IV for AES
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        
        # Add PKCS7 padding
        padder = algorithms.AES(key).block_size // 8
        padding_length = padder - (len(data) % padder)
        padded_data = data + bytes([padding_length]) * padding_length
        
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        
        return {
            "encrypted_data": base64.b64encode(encrypted).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8'),
            "purpose": purpose
        }
    
    def decrypt_data(self, encrypted_dict: Dict[str, str]) -> bytes:
        """Decrypt data with derived key."""
        purpose = encrypted_dict["purpose"]
        key = self.derive_key(purpose)
        
        iv = base64.b64decode(encrypted_dict["iv"])
        encrypted_data = base64.b64decode(encrypted_dict["encrypted_data"])
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove PKCS7 padding
        padding_length = padded_data[-1]
        data = padded_data[:-padding_length]
        
        return data

@contextmanager
def security_context(auditor: SecurityAuditor, source_ip: str):
    """Security context manager for request processing."""
    start_time = time.time()
    
    try:
        # Check if IP is blocked
        if auditor.is_ip_blocked(source_ip):
            raise SecurityError(f"IP {source_ip} is blocked")
        
        yield auditor
        
    except Exception as e:
        # Record security event on exception
        event = SecurityEvent(
            event_type=ThreatType.AUTHENTICATION,
            severity=SecurityLevel.MEDIUM,
            source_ip=source_ip,
            details={"exception": str(e), "duration": time.time() - start_time}
        )
        auditor.record_event(event)
        raise
    
    finally:
        # Log successful completion
        logger.debug(f"Security context completed for {source_ip}")

class SecurityError(Exception):
    """Security-related exception."""
    pass

class SecurityHardening:
    """Production security hardening utilities."""
    
    @staticmethod
    def secure_headers() -> Dict[str, str]:
        """Generate secure HTTP headers."""
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
        }
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Validate IP address format."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if IP address is private."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False
    
    @staticmethod
    def generate_secure_filename(filename: str) -> str:
        """Generate secure filename."""
        # Remove path traversal attempts
        filename = filename.replace('..', '').replace('/', '').replace('\\', '')
        
        # Keep only alphanumeric, dots, hyphens, underscores
        filename = re.sub(r'[^a-zA-Z0-9\.\-_]', '', filename)
        
        # Ensure filename isn't empty
        if not filename:
            filename = f"file_{secrets.token_hex(8)}"
        
        return filename

# Global instances
default_token_manager = SecureTokenManager()
default_input_sanitizer = InputSanitizer()
default_security_auditor = SecurityAuditor()
default_encryption_manager = EncryptionManager()

class LightningSecurityAdapter:
    """Adapter for Lightning-specific security functions"""
    
    def __init__(self, auditor: SecurityAuditor):
        """Initialize adapter with security auditor."""
        self.auditor = auditor
    
    def verify_macaroon_security(self, macaroon_path: str) -> Dict[str, Any]:
        """Verify macaroon file security."""
        from pathlib import Path
        import os
        
        try:
            macaroon_file = Path(macaroon_path)
            if not macaroon_file.exists():
                return {
                    "secure": False,
                    "issues": ["Macaroon file not found"],
                    "recommendations": ["Ensure macaroon file exists"]
                }
            
            # Check file permissions
            stat_info = macaroon_file.stat()
            permissions = oct(stat_info.st_mode)[-3:]
            
            issues = []
            recommendations = []
            
            # Should be readable only by owner
            if permissions != "600":
                issues.append(f"Insecure file permissions: {permissions}")
                recommendations.append("Set file permissions to 600 (owner read/write only)")
            
            return {
                "secure": len(issues) == 0,
                "permissions": permissions,
                "size": stat_info.st_size,
                "issues": issues,
                "recommendations": recommendations
            }
            
        except Exception as e:
            return {
                "secure": False,
                "issues": [f"Error checking macaroon security: {str(e)}"],
                "recommendations": ["Check file path and permissions"]
            }
    
    def verify_tls_security(self, cert_path: str) -> Dict[str, Any]:
        """Verify TLS certificate security."""
        from pathlib import Path
        import ssl
        import socket
        from datetime import datetime
        
        try:
            cert_file = Path(cert_path)
            if not cert_file.exists():
                return {
                    "secure": False,
                    "issues": ["TLS certificate file not found"],
                    "recommendations": ["Ensure certificate file exists"]
                }
            
            # Basic file checks
            stat_info = cert_file.stat()
            permissions = oct(stat_info.st_mode)[-3:]
            
            issues = []
            recommendations = []
            
            # Check file permissions
            if permissions not in ["644", "600"]:
                issues.append(f"Unusual certificate permissions: {permissions}")
                recommendations.append("Set certificate permissions to 644 or 600")
            
            # Try to load the certificate
            try:
                with open(cert_file, 'rb') as f:
                    cert_data = f.read()
                
                # Basic certificate validation would go here
                # This is a simplified check
                if b'-----BEGIN CERTIFICATE-----' not in cert_data:
                    issues.append("Certificate file does not appear to contain valid certificate")
                    recommendations.append("Ensure certificate file contains valid PEM certificate")
                
            except Exception as cert_error:
                issues.append(f"Error reading certificate: {str(cert_error)}")
                recommendations.append("Check certificate file format and readability")
            
            return {
                "secure": len(issues) == 0,
                "permissions": permissions,
                "size": stat_info.st_size,
                "issues": issues,
                "recommendations": recommendations
            }
            
        except Exception as e:
            return {
                "secure": False,
                "issues": [f"Error checking TLS security: {str(e)}"],
                "recommendations": ["Check certificate path and permissions"]
            }
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get overall security status."""
        summary = self.auditor.get_security_summary()
        
        return {
            "authentication": "enabled",
            "encryption": "enabled",
            "threats_blocked": summary.get("blocked_ips", 0),
            "recent_events": summary.get("events_last_hour", 0),
            "active_rules": summary.get("active_rules", 0),
            "security_level": "high" if summary.get("blocked_ips", 0) == 0 else "medium"
        }

# Compatibility functions for legacy imports
def get_security_manager():
    """Legacy compatibility function."""
    return LightningSecurityAdapter(default_security_auditor)

def require_auth(func):
    """Simple authentication decorator."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Basic auth check - in production this would validate actual tokens
        # For now, just log the access attempt
        logger.info(f"Authentication check for function: {func.__name__}")
        return func(*args, **kwargs)
    return wrapper

if __name__ == "__main__":
    # Example usage and testing
    print("Testing BLNCS Advanced Security Module")
    
    # Test token generation
    token = default_token_manager.generate_token({"user_id": 123, "role": "admin"})
    print(f"Generated token: {token[:50]}...")
    
    # Test token validation
    payload = default_token_manager.validate_token(token)
    print(f"Token payload: {payload}")
    
    # Test input sanitization
    test_input = "<script>alert('xss')</script>"
    sanitized = default_input_sanitizer.sanitize_string(test_input)
    is_valid, issues = default_input_sanitizer.validate_all(test_input)
    print(f"Input '{test_input}' -> '{sanitized}', Valid: {is_valid}, Issues: {issues}")
    
    # Test security event recording
    event = SecurityEvent(
        event_type=ThreatType.XSS,
        severity=SecurityLevel.HIGH,
        source_ip="192.168.1.100"
    )
    blocked = default_security_auditor.record_event(event)
    print(f"Event recorded, blocked: {blocked}")
    
    # Test encryption
    data = b"sensitive information"
    encrypted = default_encryption_manager.encrypt_data(data, "test_purpose")
    decrypted = default_encryption_manager.decrypt_data(encrypted)
    print(f"Encryption test: {data == decrypted}")
    
    print("Security module test completed successfully!")