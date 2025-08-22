# BLRCS Security Module
# Comprehensive security implementation following OWASP best practices
import hashlib
import hmac
import secrets
import time
import json
import re
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timedelta
from pathlib import Path
import asyncio
from collections import defaultdict
from enum import Enum

class SecurityLevel(Enum):
    """Security levels for different environments"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    PARANOID = "paranoid"

class SecurityManager:
    """
    Central security manager implementing defense in depth.
    Following Rob Pike's simplicity principle with Carmack's performance awareness.
    """
    
    def __init__(self, level: SecurityLevel = SecurityLevel.HIGH):
        self.level = level
        self.failed_attempts = defaultdict(list)
        self.blocked_ips = set()
        self.session_store = {}
        self.audit_log = []
        self.max_failed_attempts = 5
        self.block_duration = 3600  # 1 hour
        self.session_timeout = 1800  # 30 minutes
        
        # Security headers
        self.security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
        }
        
        # Enhanced input validation patterns
        self.validators = {
            "email": re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
            "username": re.compile(r'^[a-zA-Z0-9_-]{3,32}$'),
            "password": re.compile(r'^.{12,256}$'),  # Increased minimum length
            "uuid": re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
            "ipv4": re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'),
            "ipv6": re.compile(r'^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$'),
            "port": re.compile(r'^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$'),
            "path": re.compile(r'^[a-zA-Z0-9/_.-]+$'),
            "alphanumeric": re.compile(r'^[a-zA-Z0-9]+$'),
            "numeric": re.compile(r'^[0-9]+$'),
            "hex": re.compile(r'^[0-9a-fA-F]+$')
        }
        
        # Input length limits
        self.input_limits = {
            "text": 1000,      # Reduced from potentially unlimited
            "json": 5000,      # Limit JSON input size
            "file_name": 255,  # Standard filename limit
            "query": 500,      # Database query limit
            "comment": 2000,   # Comment field limit
            "description": 5000 # Description field limit
        }
        
        # Dangerous patterns to block
        self.dangerous_patterns = [
            re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
            re.compile(r'javascript:', re.IGNORECASE),
            re.compile(r'vbscript:', re.IGNORECASE),
            re.compile(r'on\w+\s*=', re.IGNORECASE),
            re.compile(r'data:.*?base64', re.IGNORECASE),
            re.compile(r'eval\s*\(', re.IGNORECASE),
            re.compile(r'expression\s*\(', re.IGNORECASE),
            re.compile(r'url\s*\(.*?javascript:', re.IGNORECASE),
            re.compile(r'import\s+|from\s+.*\s+import', re.IGNORECASE),  # Prevent code injection
            re.compile(r'exec\s*\(|eval\s*\(', re.IGNORECASE),
            re.compile(r'__.*__', re.IGNORECASE),  # Python dunder methods
            re.compile(r'\.\./', re.IGNORECASE),   # Path traversal
            re.compile(r'\/etc\/|\/proc\/|\/sys\/', re.IGNORECASE),  # System paths
        ]
    
    def hash_password(self, password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
        """
        Hash password using PBKDF2-SHA256.
        Returns (hash, salt) as hex strings.
        """
        if salt is None:
            salt = secrets.token_bytes(32)
        
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000  # iterations
        )
        
        return key.hex(), salt.hex()
    
    def verify_password(self, password: str, password_hash: str, salt: str) -> bool:
        """Verify password against hash"""
        try:
            computed_hash, _ = self.hash_password(password, bytes.fromhex(salt))
            return secrets.compare_digest(computed_hash, password_hash)
        except:
            return False
    
    def generate_token(self, length: int = 32) -> str:
        """Generate secure random token"""
        return secrets.token_urlsafe(length)
    
    def generate_session_id(self) -> str:
        """Generate secure session ID"""
        return self.generate_token(32)
    
    def create_session(self, user_id: str, ip_address: str, user_agent: str = "") -> str:
        """Create new session"""
        session_id = self.generate_session_id()
        self.session_store[session_id] = {
            "user_id": user_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "created_at": time.time(),
            "last_activity": time.time(),
            "data": {}
        }
        
        self.audit_log.append({
            "event": "session_created",
            "user_id": user_id,
            "ip_address": ip_address,
            "timestamp": datetime.now().isoformat()
        })
        
        return session_id
    
    def validate_session(self, session_id: str, ip_address: str) -> Optional[Dict]:
        """Validate and refresh session"""
        if session_id not in self.session_store:
            return None
        
        session = self.session_store[session_id]
        
        # Check session timeout
        if time.time() - session["last_activity"] > self.session_timeout:
            self.destroy_session(session_id)
            return None
        
        # Check IP address (optional strict mode)
        if self.level == SecurityLevel.PARANOID and session["ip_address"] != ip_address:
            self.destroy_session(session_id)
            return None
        
        # Update last activity
        session["last_activity"] = time.time()
        return session
    
    def destroy_session(self, session_id: str):
        """Destroy session"""
        if session_id in self.session_store:
            session = self.session_store[session_id]
            self.audit_log.append({
                "event": "session_destroyed",
                "user_id": session["user_id"],
                "timestamp": datetime.now().isoformat()
            })
            del self.session_store[session_id]
    
    def check_rate_limit(self, identifier: str, max_attempts: int = 10, window: int = 60) -> bool:
        """
        Check if rate limit exceeded.
        Returns True if allowed, False if rate limited.
        """
        now = time.time()
        
        # Clean old attempts
        self.failed_attempts[identifier] = [
            t for t in self.failed_attempts[identifier]
            if now - t < window
        ]
        
        # Check limit
        if len(self.failed_attempts[identifier]) >= max_attempts:
            return False
        
        # Record attempt
        self.failed_attempts[identifier].append(now)
        return True
    
    def record_failed_login(self, ip_address: str, username: str = ""):
        """Record failed login attempt"""
        self.audit_log.append({
            "event": "failed_login",
            "ip_address": ip_address,
            "username": username,
            "timestamp": datetime.now().isoformat()
        })
        
        # Check if should block IP
        now = time.time()
        recent_failures = [
            t for t in self.failed_attempts[ip_address]
            if now - t < 300  # 5 minutes
        ]
        
        if len(recent_failures) >= self.max_failed_attempts:
            self.block_ip(ip_address)
    
    def block_ip(self, ip_address: str):
        """Block IP address"""
        self.blocked_ips.add(ip_address)
        self.audit_log.append({
            "event": "ip_blocked",
            "ip_address": ip_address,
            "timestamp": datetime.now().isoformat()
        })
    
    def is_ip_blocked(self, ip_address: str) -> bool:
        """Check if IP is blocked"""
        return ip_address in self.blocked_ips
    
    def validate_input(self, value: str, input_type: str) -> bool:
        """Validate input against patterns"""
        if input_type not in self.validators:
            return False
        
        pattern = self.validators[input_type]
        return bool(pattern.match(value))
    
    def sanitize_input(self, value: str, input_type: str = "text") -> str:
        """
        Enhanced input sanitization with pattern detection.
        Removes dangerous patterns and limits length based on type.
        """
        if not value:
            return ""
        
        # Get appropriate length limit
        max_length = self.input_limits.get(input_type, 1000)
        value = value[:max_length]
        
        # Check for dangerous patterns first
        for pattern in self.dangerous_patterns:
            if pattern.search(value):
                # Log security event
                self.audit_log.append({
                    "event": "dangerous_input_blocked",
                    "pattern": pattern.pattern,
                    "input": value[:100],  # Log first 100 chars only
                    "timestamp": datetime.now().isoformat()
                })
                # Return empty string for dangerous input
                return ""
        
        # Remove null bytes and other control characters
        value = value.replace('\x00', '')
        
        # Remove control characters except newline and tab
        value = ''.join(
            char for char in value
            if char == '\n' or char == '\t' or ord(char) >= 32
        )
        
        # Enhanced HTML entity encoding
        replacements = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '&': '&amp;',
            '/': '&#x2F;',
            '\\': '&#x5C;',
            '`': '&#x60;',
            '=': '&#x3D;'
        }
        
        for old, new in replacements.items():
            value = value.replace(old, new)
        
        return value
    
    def sanitize_path(self, path: str) -> str:
        """
        Sanitize file path to prevent directory traversal.
        """
        # Remove any parent directory references
        path = path.replace('..', '')
        path = path.replace('//', '/')
        path = path.replace('\\', '/')
        
        # Remove leading slashes
        path = path.lstrip('/')
        
        # Only allow safe characters
        safe_path = ''.join(
            char for char in path
            if char.isalnum() or char in '/_.-'
        )
        
        return safe_path
    
    def generate_csrf_token(self, session_id: str) -> str:
        """Generate CSRF token for session"""
        if session_id not in self.session_store:
            return ""
        
        # Generate token tied to session
        token = self.generate_token(32)
        self.session_store[session_id]["data"]["csrf_token"] = token
        return token
    
    def validate_csrf_token(self, session_id: str, token: str) -> bool:
        """Validate CSRF token"""
        if session_id not in self.session_store:
            return False
        
        stored_token = self.session_store[session_id]["data"].get("csrf_token")
        if not stored_token:
            return False
        
        return secrets.compare_digest(stored_token, token)
    
    def encrypt_data(self, data: bytes, key: bytes) -> bytes:
        """
        Encrypt data using AES-256-GCM.
        Returns encrypted data with nonce prepended.
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        return nonce + ciphertext
    
    def decrypt_data(self, encrypted_data: bytes, key: bytes) -> bytes:
        """
        Decrypt data encrypted with encrypt_data.
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    
    def get_security_headers(self) -> Dict[str, str]:
        """Get security headers for HTTP responses"""
        return self.security_headers.copy()
    
    def check_password_strength(self, password: str) -> Tuple[bool, List[str]]:
        """
        Check password strength.
        Returns (is_strong, [issues])
        """
        issues = []
        
        if len(password) < 8:
            issues.append("Password must be at least 8 characters")
        
        if len(password) > 128:
            issues.append("Password must be less than 128 characters")
        
        if not re.search(r'[A-Z]', password):
            issues.append("Password must contain uppercase letter")
        
        if not re.search(r'[a-z]', password):
            issues.append("Password must contain lowercase letter")
        
        if not re.search(r'[0-9]', password):
            issues.append("Password must contain number")
        
        if self.level >= SecurityLevel.HIGH:
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                issues.append("Password must contain special character")
        
        # Check common passwords
        common_passwords = {
            'password', '12345678', 'qwerty', 'abc123', 'password123',
            'admin', 'letmein', 'welcome', 'monkey', '1234567890'
        }
        
        if password.lower() in common_passwords:
            issues.append("Password is too common")
        
        return len(issues) == 0, issues
    
    def log_security_event(self, event_type: str, details: Dict[str, Any]):
        """Log security event"""
        self.audit_log.append({
            "event": event_type,
            "details": details,
            "timestamp": datetime.now().isoformat()
        })
    
    def get_audit_log(self, limit: int = 100) -> List[Dict]:
        """Get recent audit log entries"""
        return self.audit_log[-limit:]
    
    def clear_old_sessions(self):
        """Clear expired sessions"""
        now = time.time()
        expired = [
            sid for sid, session in self.session_store.items()
            if now - session["last_activity"] > self.session_timeout
        ]
        
        for sid in expired:
            self.destroy_session(sid)
    
    async def periodic_cleanup(self):
        """Periodic cleanup task"""
        while True:
            try:
                self.clear_old_sessions()
                
                # Clear old failed attempts
                now = time.time()
                for identifier in list(self.failed_attempts.keys()):
                    self.failed_attempts[identifier] = [
                        t for t in self.failed_attempts[identifier]
                        if now - t < 3600  # Keep last hour
                    ]
                    
                    if not self.failed_attempts[identifier]:
                        del self.failed_attempts[identifier]
                
                # Clear old blocked IPs
                # In production, this would check block duration
                
                await asyncio.sleep(300)  # Run every 5 minutes
            except:
                await asyncio.sleep(60)

class ContentSecurityPolicy:
    """
    Content Security Policy builder.
    Helps create secure CSP headers.
    """
    
    def __init__(self):
        self.directives = {
            "default-src": ["'self'"],
            "script-src": ["'self'"],
            "style-src": ["'self'"],
            "img-src": ["'self'", "data:", "https:"],
            "font-src": ["'self'"],
            "connect-src": ["'self'"],
            "frame-ancestors": ["'none'"],
            "base-uri": ["'self'"],
            "form-action": ["'self'"]
        }
    
    def add_source(self, directive: str, source: str):
        """Add source to directive"""
        if directive not in self.directives:
            self.directives[directive] = []
        
        if source not in self.directives[directive]:
            self.directives[directive].append(source)
    
    def allow_inline_scripts(self):
        """Allow inline scripts (not recommended)"""
        self.add_source("script-src", "'unsafe-inline'")
    
    def allow_inline_styles(self):
        """Allow inline styles"""
        self.add_source("style-src", "'unsafe-inline'")
    
    def add_nonce(self, directive: str, nonce: str):
        """Add nonce for inline content"""
        self.add_source(directive, f"'nonce-{nonce}'")
    
    def build(self) -> str:
        """Build CSP header string"""
        parts = []
        for directive, sources in self.directives.items():
            if sources:
                parts.append(f"{directive} {' '.join(sources)}")
        
        return "; ".join(parts)

class SQLInjectionProtector:
    """
    SQL injection protection utilities.
    """
    
    @staticmethod
    def sanitize_identifier(identifier: str) -> str:
        """
        Sanitize SQL identifier (table/column name).
        Only allows alphanumeric and underscore.
        """
        return ''.join(char for char in identifier if char.isalnum() or char == '_')
    
    @staticmethod
    def escape_like_pattern(pattern: str) -> str:
        """Escape special characters in LIKE patterns"""
        pattern = pattern.replace('\\', '\\\\')
        pattern = pattern.replace('%', '\\%')
        pattern = pattern.replace('_', '\\_')
        return pattern
    
    @staticmethod
    def validate_order_by(column: str, allowed_columns: List[str]) -> Optional[str]:
        """Validate ORDER BY column against whitelist"""
        if column in allowed_columns:
            return column
        return None