#!/usr/bin/env python3
"""
Unified Security Management System for BLNCS
統一されたセキュリティ管理システム

Consolidates functionality from:
- commercial_security_system.py
- enhanced_security.py
- enterprise_security_system.py
- national_security_framework.py
"""

import secrets
import time
import jwt
import bcrypt
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union, Callable
from dataclasses import dataclass, field
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging
import json
import ipaddress
from pathlib import Path
import threading
from collections import defaultdict, deque
import base64
import hashlib
import hmac
import os

# Try to import pyotp for TOTP support
try:
    import pyotp
    HAS_PYOTP = True
except ImportError:
    pyotp = None
    HAS_PYOTP = False

logger = logging.getLogger(__name__)

@dataclass
class SecurityEvent:
    """Security event data structure"""
    event_type: str
    severity: str  # low, medium, high, critical
    description: str
    source_ip: Optional[str] = None
    user_id: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class MFASecret:
    """MFA secret data structure"""
    user_id: str
    secret: str
    backup_codes: List[str] = field(default_factory=list)
    enabled: bool = True
    created_at: float = field(default_factory=time.time)
    last_used: Optional[float] = None

@dataclass
class MFAAuthentication:
    """MFA authentication attempt"""
    user_id: str
    method: str  # 'totp', 'sms', 'email', 'backup_code'
    code: str
    timestamp: float = field(default_factory=time.time)
    success: bool = False
    ip_address: Optional[str] = None

class MultiFactorAuthenticator:
    """Multi-factor authentication system"""

    def __init__(self):
        self.secrets: Dict[str, MFASecret] = {}
        self.attempts: deque = deque(maxlen=1000)  # Keep last 1000 attempts
        self.lock = threading.Lock()
        self.max_attempts_per_hour = 5
        self.totp_window = 1  # Allow 1 step before/after for clock skew

    def generate_totp_secret(self, user_id: str) -> str:
        """Generate a new TOTP secret for user"""
        if not HAS_PYOTP:
            raise RuntimeError("pyotp library not available for TOTP support")

        secret = pyotp.random_base32()
        backup_codes = [secrets.token_hex(4) for _ in range(10)]  # 10 backup codes

        with self.lock:
            self.secrets[user_id] = MFASecret(
                user_id=user_id,
                secret=secret,
                backup_codes=backup_codes
            )

        logger.info(f"Generated TOTP secret for user: {user_id}")
        return secret

    def get_totp_uri(self, user_id: str, issuer: str = "BLNCS") -> str:
        """Get TOTP URI for QR code generation"""
        if not HAS_PYOTP:
            raise RuntimeError("pyotp library not available for TOTP support")

        if user_id not in self.secrets:
            raise ValueError(f"No MFA secret found for user: {user_id}")

        secret = self.secrets[user_id]
        totp = pyotp.TOTP(secret.secret)
        return totp.provisioning_uri(name=user_id, issuer_name=issuer)

    def verify_totp(self, user_id: str, code: str, ip_address: Optional[str] = None) -> bool:
        """Verify TOTP code"""
        if not HAS_PYOTP:
            raise RuntimeError("pyotp library not available for TOTP support")

        if user_id not in self.secrets:
            logger.warning(f"MFA verification attempted for unknown user: {user_id}")
            return False

        secret = self.secrets[user_id]
        if not secret.enabled:
            return False

        # Check rate limiting
        if not self._check_rate_limit(user_id):
            logger.warning(f"MFA rate limit exceeded for user: {user_id}")
            return False

        totp = pyotp.TOTP(secret.secret)
        is_valid = totp.verify(code, valid_window=self.totp_window)

        # Record attempt
        attempt = MFAAuthentication(
            user_id=user_id,
            method='totp',
            code=code,
            success=is_valid,
            ip_address=ip_address
        )

        with self.lock:
            self.attempts.append(attempt)
            if is_valid:
                secret.last_used = time.time()

        if is_valid:
            logger.info(f"Successful TOTP verification for user: {user_id}")
        else:
            logger.warning(f"Failed TOTP verification for user: {user_id}")

        return is_valid

    def verify_backup_code(self, user_id: str, code: str, ip_address: Optional[str] = None) -> bool:
        """Verify backup code (one-time use)"""
        if user_id not in self.secrets:
            return False

        secret = self.secrets[user_id]
        if not secret.enabled or code not in secret.backup_codes:
            return False

        # Remove used backup code
        with self.lock:
            secret.backup_codes.remove(code)

        # Record attempt
        attempt = MFAAuthentication(
            user_id=user_id,
            method='backup_code',
            code=code,
            success=True,
            ip_address=ip_address
        )
        self.attempts.append(attempt)

        logger.info(f"Successful backup code verification for user: {user_id}")
        return True

    def _check_rate_limit(self, user_id: str) -> bool:
        """Check MFA attempt rate limiting"""
        current_time = time.time()
        window_start = current_time - 3600  # 1 hour window

        recent_attempts = [
            attempt for attempt in self.attempts
            if attempt.user_id == user_id and attempt.timestamp > window_start
        ]

        return len(recent_attempts) < self.max_attempts_per_hour

    def enable_mfa(self, user_id: str) -> bool:
        """Enable MFA for user"""
        if user_id not in self.secrets:
            return False

        with self.lock:
            self.secrets[user_id].enabled = True

        logger.info(f"Enabled MFA for user: {user_id}")
        return True

    def disable_mfa(self, user_id: str) -> bool:
        """Disable MFA for user"""
        if user_id not in self.secrets:
            return False

        with self.lock:
            self.secrets[user_id].enabled = False

        logger.info(f"Disabled MFA for user: {user_id}")
        return True

    def is_mfa_enabled(self, user_id: str) -> bool:
        """Check if MFA is enabled for user"""
        return user_id in self.secrets and self.secrets[user_id].enabled

    def get_mfa_status(self, user_id: str) -> Dict[str, Any]:
        """Get MFA status for user"""
        if user_id not in self.secrets:
            return {'enabled': False, 'configured': False}

        secret = self.secrets[user_id]
        return {
            'enabled': secret.enabled,
            'configured': True,
            'backup_codes_remaining': len(secret.backup_codes),
            'last_used': secret.last_used,
            'created_at': secret.created_at
        }

    def get_mfa_attempts(self, user_id: Optional[str] = None, limit: int = 50) -> List[MFAAuthentication]:
        """Get MFA authentication attempts"""
        attempts = list(self.attempts)
        if user_id:
            attempts = [a for a in attempts if a.user_id == user_id]

        return attempts[-limit:]  # Return most recent

@dataclass
class ZKPChallenge:
    """Zero-Knowledge Proof challenge"""
    user_id: str
    challenge: str
    timestamp: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 300)  # 5 minutes
    used: bool = False

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def is_valid(self) -> bool:
        return not self.is_expired and not self.used


@dataclass
class ZKPSecret:
    """Zero-Knowledge Proof secret data"""
    user_id: str
    salt: str
    verifier: str  # Stored verifier for SRP-like protocol
    created_at: float = field(default_factory=time.time)
    enabled: bool = True


class ZeroKnowledgeAuthenticator:
    """Zero-Knowledge Proof authentication system"""

    def __init__(self):
        self.secrets: Dict[str, ZKPSecret] = {}
        self.challenges: Dict[str, ZKPChallenge] = {}
        self.lock = threading.Lock()
        self.challenge_timeout = 300  # 5 minutes

    def register_user(self, user_id: str, password: str) -> bool:
        """Register user with ZKP-compatible password storage"""
        if user_id in self.secrets:
            return False

        # Generate salt and create verifier
        salt = secrets.token_hex(32)
        verifier = self._create_verifier(password, salt)

        with self.lock:
            self.secrets[user_id] = ZKPSecret(
                user_id=user_id,
                salt=salt,
                verifier=verifier
            )

        logger.info(f"Registered ZKP credentials for user: {user_id}")
        return True

    def _create_verifier(self, password: str, salt: str) -> str:
        """Create password verifier using PBKDF2"""
        # Use PBKDF2 to derive a key from password + salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt.encode(),
            iterations=100000,
        )
        key = kdf.derive(password.encode())
        return base64.b64encode(key).decode()

    def initiate_authentication(self, user_id: str) -> Optional[str]:
        """Initiate ZKP authentication by sending challenge"""
        if user_id not in self.secrets or not self.secrets[user_id].enabled:
            return None

        # Generate random challenge
        challenge = secrets.token_hex(32)

        with self.lock:
            self.challenges[user_id] = ZKPChallenge(
                user_id=user_id,
                challenge=challenge,
                expires_at=time.time() + self.challenge_timeout
            )

        logger.info(f"Initiated ZKP authentication for user: {user_id}")
        return challenge

    def verify_proof(self, user_id: str, client_proof: str, challenge: str) -> bool:
        """Verify client's zero-knowledge proof"""
        if user_id not in self.secrets:
            return False

        secret = self.secrets[user_id]
        if not secret.enabled:
            return False

        # Check if challenge exists and is valid
        if user_id not in self.challenges:
            return False

        stored_challenge = self.challenges[user_id]
        if not stored_challenge.is_valid or stored_challenge.challenge != challenge:
            return False

        # Verify proof using stored verifier
        expected_proof = self._compute_proof(secret.verifier, challenge)

        # Mark challenge as used
        with self.lock:
            stored_challenge.used = True

        is_valid = hmac.compare_digest(expected_proof, client_proof)

        if is_valid:
            logger.info(f"Successful ZKP verification for user: {user_id}")
        else:
            logger.warning(f"Failed ZKP verification for user: {user_id}")

        return is_valid

    def _compute_proof(self, verifier: str, challenge: str) -> str:
        """Compute expected proof from verifier and challenge"""
        # Simple HMAC-based proof computation
        key = base64.b64decode(verifier)
        message = challenge.encode()
        proof = hmac.new(key, message, hashlib.sha256).hexdigest()
        return proof

    def enable_zkp(self, user_id: str) -> bool:
        """Enable ZKP authentication for user"""
        if user_id not in self.secrets:
            return False

        with self.lock:
            self.secrets[user_id].enabled = True

        logger.info(f"Enabled ZKP authentication for user: {user_id}")
        return True

    def disable_zkp(self, user_id: str) -> bool:
        """Disable ZKP authentication for user"""
        if user_id not in self.secrets:
            return False

        with self.lock:
            self.secrets[user_id].enabled = False

        logger.info(f"Disabled ZKP authentication for user: {user_id}")
        return True

    def is_zkp_enabled(self, user_id: str) -> bool:
        """Check if ZKP is enabled for user"""
        return user_id in self.secrets and self.secrets[user_id].enabled

    def reset_zkp(self, user_id: str) -> bool:
        """Reset ZKP credentials for user"""
        if user_id in self.secrets:
            with self.lock:
                del self.secrets[user_id]
                if user_id in self.challenges:
                    del self.challenges[user_id]
            logger.info(f"Reset ZKP credentials for user: {user_id}")
            return True
        return False

    def cleanup_expired_challenges(self):
        """Clean up expired challenges"""
        current_time = time.time()
        expired_users = []

        with self.lock:
            for user_id, challenge in self.challenges.items():
                if challenge.is_expired:
                    expired_users.append(user_id)

            for user_id in expired_users:
                del self.challenges[user_id]

@dataclass
class FirewallRule:
    """Dynamic firewall rule"""
    rule_id: str
    source_ip: str
    action: str  # 'allow', 'deny', 'block'
    protocol: Optional[str] = None
    port: Optional[int] = None
    reason: str = ""
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    priority: int = 100  # Lower number = higher priority
    hit_count: int = 0
    last_hit: Optional[float] = None

    @property
    def is_expired(self) -> bool:
        return self.expires_at is not None and time.time() > self.expires_at

    @property
    def is_active(self) -> bool:
        return not self.is_expired


@dataclass
class ThreatPattern:
    """Threat pattern for rule generation"""
    pattern_id: str
    description: str
    severity: str  # 'low', 'medium', 'high', 'critical'
    triggers: List[str]  # Events that trigger this pattern
    actions: List[str]  # Actions to take
    rule_template: Dict[str, Any]  # Template for firewall rule
    cooldown_period: int = 3600  # Don't trigger again for 1 hour
    last_triggered: Optional[float] = None


class DynamicFirewall:
    """Dynamic firewall rule generation and management"""

    def __init__(self):
        self.rules: Dict[str, FirewallRule] = {}
        self.threat_patterns: Dict[str, ThreatPattern] = {}
        self.lock = threading.Lock()
        self.rule_counter = 0

        # Initialize default threat patterns
        self._initialize_threat_patterns()

    def _initialize_threat_patterns(self):
        """Initialize default threat patterns"""
        self.threat_patterns = {
            'brute_force': ThreatPattern(
                pattern_id='brute_force',
                description='Brute force login attempts',
                severity='high',
                triggers=['authentication', 'failed_login'],
                actions=['block_ip', 'alert_admin'],
                rule_template={
                    'action': 'deny',
                    'protocol': 'tcp',
                    'port': [22, 80, 443],  # SSH, HTTP, HTTPS
                    'duration_hours': 24
                },
                cooldown_period=3600
            ),
            'suspicious_traffic': ThreatPattern(
                pattern_id='suspicious_traffic',
                description='Suspicious network traffic patterns',
                severity='medium',
                triggers=['high_traffic', 'unusual_ports'],
                actions=['rate_limit', 'monitor'],
                rule_template={
                    'action': 'rate_limit',
                    'protocol': 'tcp',
                    'rate_limit': '10/minute',
                    'duration_hours': 1
                },
                cooldown_period=1800
            ),
            'failed_mfa': ThreatPattern(
                pattern_id='failed_mfa',
                description='Multiple MFA failures',
                severity='critical',
                triggers=['mfa_failed'],
                actions=['block_ip', 'require_captcha', 'alert_security'],
                rule_template={
                    'action': 'block',
                    'protocol': 'tcp',
                    'port': 'all',
                    'duration_hours': 48
                },
                cooldown_period=7200
            ),
            'suspicious_api': ThreatPattern(
                pattern_id='suspicious_api',
                description='Suspicious API access patterns',
                severity='medium',
                triggers=['rate_limit_exceeded', 'invalid_tokens'],
                actions=['block_ip', 'require_api_key'],
                rule_template={
                    'action': 'deny',
                    'protocol': 'tcp',
                    'port': [3000, 8080],  # API ports
                    'duration_hours': 6
                },
                cooldown_period=1800
            )
        }

    def generate_rule_from_event(self, security_event: SecurityEvent) -> Optional[FirewallRule]:
        """Generate firewall rule from security event"""
        matching_patterns = []

        # Find matching threat patterns
        for pattern in self.threat_patterns.values():
            if any(trigger in security_event.event_type.lower() for trigger in pattern.triggers):
                # Check cooldown period
                if (pattern.last_triggered is None or
                    time.time() - pattern.last_triggered > pattern.cooldown_period):
                    matching_patterns.append(pattern)

        if not matching_patterns:
            return None

        # Use the highest severity pattern
        pattern = max(matching_patterns, key=lambda p: self._get_severity_score(p.severity))

        # Create rule from template
        rule_id = f"auto_{pattern.pattern_id}_{int(time.time())}_{self.rule_counter}"
        self.rule_counter += 1

        template = pattern.rule_template
        expires_at = None
        if 'duration_hours' in template:
            expires_at = time.time() + (template['duration_hours'] * 3600)

        rule = FirewallRule(
            rule_id=rule_id,
            source_ip=security_event.source_ip or 'unknown',
            action=template['action'],
            protocol=template.get('protocol'),
            port=template.get('port'),
            reason=f"Auto-generated from {pattern.description}",
            expires_at=expires_at,
            priority=self._get_priority_from_severity(pattern.severity)
        )

        # Update pattern last triggered
        pattern.last_triggered = time.time()

        # Store rule
        with self.lock:
            self.rules[rule_id] = rule

        logger.info(f"Generated firewall rule: {rule_id} for IP {rule.source_ip}")
        return rule

    def _get_severity_score(self, severity: str) -> int:
        """Get numerical score for severity"""
        scores = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        return scores.get(severity, 1)

    def _get_priority_from_severity(self, severity: str) -> int:
        """Get rule priority from severity"""
        priorities = {'low': 200, 'medium': 150, 'high': 100, 'critical': 50}
        return priorities.get(severity, 200)

    def check_traffic(self, source_ip: str, protocol: str = 'tcp', port: int = 0) -> str:
        """Check if traffic should be allowed based on rules"""
        applicable_rules = []

        with self.lock:
            for rule in self.rules.values():
                if not rule.is_active:
                    continue

                if rule.source_ip == source_ip or rule.source_ip == '0.0.0.0/0':
                    # Check protocol
                    if rule.protocol and rule.protocol != protocol:
                        continue

                    # Check port
                    if rule.port:
                        if isinstance(rule.port, list):
                            if port not in rule.port:
                                continue
                        elif rule.port != port and rule.port != 'all':
                            continue

                    applicable_rules.append(rule)

        if not applicable_rules:
            return 'allow'

        # Apply highest priority rule (lowest priority number)
        rule = min(applicable_rules, key=lambda r: r.priority)

        # Update hit statistics
        rule.hit_count += 1
        rule.last_hit = time.time()

        return rule.action

    def add_manual_rule(
        self,
        source_ip: str,
        action: str,
        protocol: Optional[str] = None,
        port: Optional[int] = None,
        reason: str = "Manual rule",
        duration_hours: Optional[int] = None
    ) -> str:
        """Add manual firewall rule"""
        rule_id = f"manual_{int(time.time())}_{self.rule_counter}"
        self.rule_counter += 1

        expires_at = None
        if duration_hours:
            expires_at = time.time() + (duration_hours * 3600)

        rule = FirewallRule(
            rule_id=rule_id,
            source_ip=source_ip,
            action=action,
            protocol=protocol,
            port=port,
            reason=reason,
            expires_at=expires_at,
            priority=10  # Manual rules have high priority
        )

        with self.lock:
            self.rules[rule_id] = rule

        logger.info(f"Added manual firewall rule: {rule_id}")
        return rule_id

    def remove_rule(self, rule_id: str) -> bool:
        """Remove firewall rule"""
        with self.lock:
            if rule_id in self.rules:
                del self.rules[rule_id]
                logger.info(f"Removed firewall rule: {rule_id}")
                return True
        return False

    def get_active_rules(self) -> List[FirewallRule]:
        """Get all active firewall rules"""
        with self.lock:
            return [rule for rule in self.rules.values() if rule.is_active]

    def cleanup_expired_rules(self) -> int:
        """Clean up expired rules"""
        expired_count = 0
        current_time = time.time()

        with self.lock:
            expired_rules = [
                rule_id for rule_id, rule in self.rules.items()
                if rule.is_expired
            ]

            for rule_id in expired_rules:
                del self.rules[rule_id]
                expired_count += 1

        if expired_count > 0:
            logger.info(f"Cleaned up {expired_count} expired firewall rules")

        return expired_count

    def get_firewall_report(self) -> Dict[str, Any]:
        """Get firewall status report"""
        active_rules = self.get_active_rules()

        # Group rules by action
        actions = {}
        for rule in active_rules:
            if rule.action not in actions:
                actions[rule.action] = []
            actions[rule.action].append({
                'rule_id': rule.rule_id,
                'source_ip': rule.source_ip,
                'protocol': rule.protocol,
                'port': rule.port,
                'reason': rule.reason,
                'hit_count': rule.hit_count,
                'last_hit': rule.last_hit
            })

        return {
            'timestamp': time.time(),
            'total_active_rules': len(active_rules),
            'rules_by_action': actions,
            'threat_patterns': len(self.threat_patterns),
            'last_cleanup': getattr(self, '_last_cleanup', None)
        }

class RateLimiter:
    """Rate limiting implementation"""

    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(deque)
        self.lock = threading.Lock()

    def is_allowed(self, identifier: str) -> bool:
        """Check if request is allowed under rate limit"""
        current_time = time.time()
        window_start = current_time - self.window_seconds

        with self.lock:
            request_times = self.requests[identifier]

            # Remove old requests outside the window
            while request_times and request_times[0] < window_start:
                request_times.popleft()

            # Check if under limit
            if len(request_times) < self.max_requests:
                request_times.append(current_time)
                return True

            return False

    def get_remaining_requests(self, identifier: str) -> int:
        """Get remaining requests for identifier"""
        current_time = time.time()
        window_start = current_time - self.window_seconds

        with self.lock:
            request_times = self.requests[identifier]

            # Remove old requests
            while request_times and request_times[0] < window_start:
                request_times.popleft()

            return max(0, self.max_requests - len(request_times))

class EncryptionManager:
    """Advanced encryption management"""

    def __init__(self, master_key: Optional[bytes] = None):
        if master_key:
            self.master_key = master_key
        else:
            # Generate or load master key
            self.master_key = self._load_or_generate_master_key()

        self.fernet = Fernet(base64.urlsafe_b64encode(self.master_key[:32]))

    def _load_or_generate_master_key(self) -> bytes:
        """Load existing master key or generate new one"""
        key_file = Path("config/master.key")

        if key_file.exists():
            try:
                return key_file.read_bytes()
            except Exception as e:
                logger.warning(f"Failed to load master key: {e}, generating new one")

        # Generate new key
        key = secrets.token_bytes(32)

        # Save key securely
        try:
            key_file.parent.mkdir(parents=True, exist_ok=True)
            key_file.write_bytes(key)
            key_file.chmod(0o600)  # Read/write for owner only
            logger.info("Generated new master encryption key")
        except Exception as e:
            logger.error(f"Failed to save master key: {e}")

        return key

    def encrypt(self, data: Union[str, bytes]) -> bytes:
        """Encrypt data"""
        if isinstance(data, str):
            data = data.encode()
        return self.fernet.encrypt(data)

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt data"""
        return self.fernet.decrypt(encrypted_data)

    def encrypt_string(self, text: str) -> str:
        """Encrypt string and return base64 encoded result"""
        encrypted = self.encrypt(text)
        return base64.b64encode(encrypted).decode()

    def decrypt_string(self, encrypted_text: str) -> str:
        """Decrypt base64 encoded string"""
        encrypted_data = base64.b64decode(encrypted_text.encode())
        decrypted = self.decrypt(encrypted_data)
        return decrypted.decode()

    def generate_key_pair(self) -> Tuple[bytes, bytes]:
        """Generate RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_pem, public_pem

    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode(), salt)
        return hashed.decode()

    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode(), hashed.encode())

class JWTManager:
    """JWT token management"""

    def __init__(self, secret_key: Optional[str] = None, algorithm: str = "HS256"):
        self.secret_key = secret_key or os.getenv('JWT_SECRET', secrets.token_urlsafe(32))
        self.algorithm = algorithm
        self.active_tokens: Dict[str, AuthToken] = {}
        self.blacklisted_tokens: set = set()

    def create_token(
        self,
        user_id: str,
        permissions: List[str] = None,
        expires_in: int = 3600,
        **kwargs
    ) -> AuthToken:
        """Create JWT token"""
        now = time.time()
        expires_at = now + expires_in

        payload = {
            'user_id': user_id,
            'permissions': permissions or [],
            'iat': now,
            'exp': expires_at,
            **kwargs
        }

        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

        auth_token = AuthToken(
            token=token,
            user_id=user_id,
            expires_at=expires_at,
            permissions=permissions or [],
            metadata=kwargs
        )

        self.active_tokens[token] = auth_token
        return auth_token

    def verify_token(self, token: str) -> Optional[AuthToken]:
        """Verify and decode JWT token"""
        if token in self.blacklisted_tokens:
            return None

        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])

            # Check if token exists in active tokens
            if token in self.active_tokens:
                auth_token = self.active_tokens[token]
                if not auth_token.is_expired:
                    return auth_token

            # Create token from payload if valid
            auth_token = AuthToken(
                token=token,
                user_id=payload.get('user_id', ''),
                expires_at=payload.get('exp', 0),
                permissions=payload.get('permissions', []),
                metadata={k: v for k, v in payload.items()
                         if k not in ['user_id', 'permissions', 'iat', 'exp']}
            )

            if not auth_token.is_expired:
                self.active_tokens[token] = auth_token
                return auth_token

        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid JWT token: {e}")

        return None

    def revoke_token(self, token: str):
        """Revoke a token"""
        self.blacklisted_tokens.add(token)
        if token in self.active_tokens:
            del self.active_tokens[token]

    def refresh_token(self, token: str, expires_in: int = 3600) -> Optional[AuthToken]:
        """Refresh an existing token"""
        auth_token = self.verify_token(token)
        if not auth_token:
            return None

        # Revoke old token
        self.revoke_token(token)

        # Create new token
        return self.create_token(
            user_id=auth_token.user_id,
            permissions=auth_token.permissions,
            expires_in=expires_in,
            **auth_token.metadata
        )

    def cleanup_expired_tokens(self):
        try:
            # Clean up expired tokens
            current_time = time.time()
            expired_tokens = []

            for token, auth_token in self.active_tokens.items():
                if auth_token.is_expired:
                    expired_tokens.append(token)

            for token in expired_tokens:
                del self.active_tokens[token]

            # Clean up old blacklisted tokens (keep last 1000)
            if len(self.blacklisted_tokens) > 1000:
                # Convert to list, sort by some criteria (we'll use lexicographic for simplicity)
                sorted_tokens = sorted(list(self.blacklisted_tokens))
                self.blacklisted_tokens = set(sorted_tokens[-1000:])

            logger.debug(f"Cleaned up {len(expired_tokens)} expired tokens")

        except Exception as e:
            logger.error(f"Error during token cleanup: {e}")

    def get_active_token_count(self) -> int:
        """Get count of active tokens"""
        return len(self.active_tokens)

    def get_blacklisted_token_count(self) -> int:
        """Get count of blacklisted tokens"""
        return len(self.blacklisted_tokens)


@dataclass
class AuthToken:
    """Authentication token with enhanced security features"""
    token: str
    user_id: str
    expires_at: float
    permissions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    access_count: int = 0

    @property
    def is_expired(self) -> bool:
        """Check if token is expired"""
        return time.time() > self.expires_at

    @property
    def time_to_expiry(self) -> float:
        """Get seconds until expiry"""
        return max(0, self.expires_at - time.time())

    @property
    def is_near_expiry(self) -> bool:
        """Check if token is near expiry (within 5 minutes)"""
        return self.time_to_expiry < 300

    def update_access(self):
        """Update access tracking"""
        self.last_accessed = time.time()
        self.access_count += 1

    def has_permission(self, permission: str) -> bool:
        """Check if token has specific permission"""
        return permission in self.permissions

    def has_any_permission(self, permissions: List[str]) -> bool:
        """Check if token has any of the specified permissions"""
        return any(perm in self.permissions for perm in permissions)

    def has_all_permissions(self, permissions: List[str]) -> bool:
        """Check if token has all specified permissions"""
        return all(perm in self.permissions for perm in permissions)


class SecurityAuditor:
    """Enhanced security auditing with advanced analytics"""

    def __init__(self, max_events: int = 10000):
        self.events: deque = deque(maxlen=max_events)
        self.lock = threading.Lock()
        self.event_counts: Dict[str, int] = {}
        self.severity_counts: Dict[str, int] = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        self.user_activity: Dict[str, List[SecurityEvent]] = {}
        self.ip_activity: Dict[str, List[SecurityEvent]] = {}

    def log_event(
        self,
        event_type: str,
        severity: str,
        description: str,
        source_ip: Optional[str] = None,
        user_id: Optional[str] = None,
        **metadata
    ):
        """Log security event with enhanced tracking"""
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            description=description,
            source_ip=source_ip,
            user_id=user_id,
            metadata=metadata
        )

        # Log to standard logger as well
        log_level = {
            'low': logging.INFO,
            'medium': logging.WARNING,
            'high': logging.ERROR,
            'critical': logging.CRITICAL
        }.get(severity, logging.INFO)

        logger.log(log_level, f"Security Event [{event_type}]: {description}")

        # Note: Dynamic firewall rule generation is handled by UnifiedSecurityManager

    def get_events(
        self,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        since: Optional[float] = None,
        limit: Optional[int] = None
    ) -> List[SecurityEvent]:
        """Get filtered security events"""
        with self.lock:
            events = list(self.events)

        # Apply filters
        if event_type:
            events = [e for e in events if e.event_type == event_type]

        if severity:
            events = [e for e in events if e.severity == severity]

        if since:
            events = [e for e in events if e.timestamp >= since]

        # Sort by timestamp (newest first)
        events.sort(key=lambda e: e.timestamp, reverse=True)

        if limit:
            events = events[:limit]

        return events

    def get_event_summary(self) -> Dict[str, Any]:
        """Get summary of security events"""
        with self.lock:
            total_events = len(self.events)
            event_counts = dict(self.event_counts)

        # Count by severity
        severity_counts = defaultdict(int)
        event_type_counts = defaultdict(int)

        for key, count in event_counts.items():
            event_type, severity = key.split(':', 1)
            severity_counts[severity] += count
            event_type_counts[event_type] += count

        return {
            'total_events': total_events,
            'severity_counts': dict(severity_counts),
            'event_type_counts': dict(event_type_counts),
            'recent_events': self.get_events(limit=10)
        }

class UnifiedSecurityManager:
    """
    Main security management system that unifies all security functionality
    """

    def __init__(
        self,
        jwt_secret: Optional[str] = None,
        master_key: Optional[bytes] = None,
        rate_limit_requests: int = 100,
        rate_limit_window: int = 60
    ):
        # Initialize components
        self.encryption = EncryptionManager(master_key)
        self.jwt_manager = JWTManager(jwt_secret)
        self.rate_limiter = RateLimiter(rate_limit_requests, rate_limit_window)
        self.auditor = SecurityAuditor()
        self.mfa = MultiFactorAuthenticator()
        self.zkp = ZeroKnowledgeAuthenticator()
        self.firewall = DynamicFirewall()

        # Security policies
        self.policies = {
            'password_min_length': 8,
            'password_require_special': True,
            'password_require_numbers': True,
            'password_require_uppercase': True,
            'max_login_attempts': 5,
            'account_lockout_duration': 300,  # 5 minutes
            'token_expiry_default': 3600,  # 1 hour
            'allowed_ip_ranges': [],
            'blocked_ip_addresses': set(),
            'require_2fa': False,
            'mfa_required_for_admin': True,  # Require MFA for admin users
            'zkp_enabled': False,  # Enable ZKP authentication
            'zkp_required_for_sensitive': False,  # Require ZKP for sensitive operations
            'dynamic_firewall_enabled': True,  # Enable dynamic firewall
            'auto_block_suspicious': True  # Auto-block suspicious IPs
        }

        # User session tracking
        self.failed_login_attempts = defaultdict(list)
        self.locked_accounts = {}

        # Background cleanup thread
        self.cleanup_thread = None
        self.shutdown_event = threading.Event()
        self.start_background_cleanup()

    def authenticate_user(
        self,
        username: str,
        password: str,
        source_ip: Optional[str] = None,
        mfa_code: Optional[str] = None
    ) -> Tuple[Optional[AuthToken], Optional[str]]:
        """
        Authenticate user and return token
        Returns (token, mfa_challenge) where mfa_challenge is None if no MFA needed
        """

        # Check rate limiting
        if not self.rate_limiter.is_allowed(f"login:{username}"):
            self.auditor.log_event(
                'authentication',
                'medium',
                f'Rate limit exceeded for user {username}',
                source_ip=source_ip,
                user_id=username
            )
            return None, None

        # Check account lockout
        if self.is_account_locked(username):
            self.auditor.log_event(
                'authentication',
                'medium',
                f'Login attempt on locked account {username}',
                source_ip=source_ip,
                user_id=username
            )
            return None, None

        # Check IP restrictions
        if not self.is_ip_allowed(source_ip):
            self.auditor.log_event(
                'authentication',
                'high',
                f'Login attempt from blocked IP {source_ip}',
                source_ip=source_ip,
                user_id=username
            )
            return None, None

        # Verify password
        if self.verify_user_password(username, password):
            # Clear failed attempts on successful login
            if username in self.failed_login_attempts:
                del self.failed_login_attempts[username]

            # Check if MFA is required
            requires_mfa = self.policies['require_2fa'] or (
                self.policies['mfa_required_for_admin'] and
                'admin' in self.get_user_permissions(username)
            )

            if requires_mfa and self.mfa.is_mfa_enabled(username):
                # MFA is required and configured
                if mfa_code:
                    # Verify MFA code
                    if self.mfa.verify_totp(username, mfa_code, source_ip):
                        # MFA successful - create token
                        token = self.jwt_manager.create_token(
                            user_id=username,
                            permissions=self.get_user_permissions(username),
                            expires_in=self.policies['token_expiry_default']
                        )

                        self.auditor.log_event(
                            'authentication',
                            'low',
                            f'Successful MFA login for user {username}',
                            source_ip=source_ip,
                            user_id=username
                        )

                        return token, None
                    else:
                        # MFA failed
                        self.auditor.log_event(
                            'authentication',
                            'medium',
                            f'Failed MFA verification for user {username}',
                            source_ip=source_ip,
                            user_id=username
                        )
                        return None, None
                else:
                    # MFA required but not provided - return challenge
                    self.auditor.log_event(
                        'authentication',
                        'low',
                        f'MFA challenge sent to user {username}',
                        source_ip=source_ip,
                        user_id=username
                    )
                    return None, "MFA_REQUIRED"
            else:
                # No MFA required - create token directly
                token = self.jwt_manager.create_token(
                    user_id=username,
                    permissions=self.get_user_permissions(username),
                    expires_in=self.policies['token_expiry_default']
                )

                self.auditor.log_event(
                    'authentication',
                    'low',
                    f'Successful login for user {username}',
                    source_ip=source_ip,
                    user_id=username
                )

                return token, None
        else:
            # Track failed attempt
            self.record_failed_login(username, source_ip)

            self.auditor.log_event(
                'authentication',
                'medium',
                f'Failed login attempt for user {username}',
                source_ip=source_ip,
                user_id=username
            )

            return None, None

    def verify_user_password(self, username: str, password: str) -> bool:
        """Verify user password (mock implementation)"""
        # TODO: Implement actual password verification against database
        # This is a placeholder for demonstration
        test_passwords = {
            'admin': 'admin123',
            'test': 'test123',
            'demo': 'demo123'
        }
        return test_passwords.get(username) == password

    def get_user_permissions(self, username: str) -> List[str]:
        """Get user permissions (mock implementation)"""
        # TODO: Implement actual permission lookup
        permission_map = {
            'admin': ['read', 'write', 'admin'],
            'test': ['read'],
            'demo': ['read', 'write']
        }
        return permission_map.get(username, ['read'])

    def verify_token(self, token: str) -> Optional[AuthToken]:
        """Verify authentication token"""
        return self.jwt_manager.verify_token(token)

    def revoke_token(self, token: str):
        """Revoke authentication token"""
        self.jwt_manager.revoke_token(token)
        self.auditor.log_event(
            'authorization',
            'low',
            'Token revoked',
            metadata={'token_prefix': token[:8] + '...'}
        )

    def record_failed_login(self, username: str, source_ip: Optional[str] = None):
        """Record failed login attempt"""
        current_time = time.time()
        self.failed_login_attempts[username].append({
            'timestamp': current_time,
            'source_ip': source_ip
        })

        # Keep only recent attempts (last hour)
        cutoff_time = current_time - 3600
        self.failed_login_attempts[username] = [
            attempt for attempt in self.failed_login_attempts[username]
            if attempt['timestamp'] > cutoff_time
        ]

        # Check if account should be locked
        if len(self.failed_login_attempts[username]) >= self.policies['max_login_attempts']:
            self.lock_account(username)

    def lock_account(self, username: str):
        """Lock user account"""
        lock_until = time.time() + self.policies['account_lockout_duration']
        self.locked_accounts[username] = lock_until

        self.auditor.log_event(
            'security',
            'high',
            f'Account {username} locked due to failed login attempts',
            user_id=username
        )

    def is_account_locked(self, username: str) -> bool:
        """Check if account is locked"""
        if username not in self.locked_accounts:
            return False

        if time.time() > self.locked_accounts[username]:
            # Unlock expired lockout
            del self.locked_accounts[username]
            return False

        return True

    def is_ip_allowed(self, ip_address: Optional[str]) -> bool:
        """Check if IP address is allowed"""
        if not ip_address:
            return True

        # Check blocked IPs
        if ip_address in self.policies['blocked_ip_addresses']:
            return False

        # Check allowed ranges (if configured)
        if self.policies['allowed_ip_ranges']:
            try:
                ip = ipaddress.ip_address(ip_address)
                for range_str in self.policies['allowed_ip_ranges']:
                    if ip in ipaddress.ip_network(range_str):
                        return True
                return False
            except ValueError:
                return False

        return True

    def validate_password_strength(self, password: str) -> Tuple[bool, List[str]]:
        """Validate password strength"""
        issues = []

        if len(password) < self.policies['password_min_length']:
            issues.append(f"Password must be at least {self.policies['password_min_length']} characters")

        if self.policies['password_require_uppercase'] and not any(c.isupper() for c in password):
            issues.append("Password must contain uppercase letters")

        if self.policies['password_require_numbers'] and not any(c.isdigit() for c in password):
            issues.append("Password must contain numbers")

        if self.policies['password_require_special'] and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            issues.append("Password must contain special characters")

        return len(issues) == 0, issues

    def encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        return self.encryption.encrypt_string(data)

    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        return self.encryption.decrypt_string(encrypted_data)

    def get_security_report(self) -> Dict[str, Any]:
        """Get comprehensive security report"""
        return {
            'timestamp': time.time(),
            'active_tokens': len(self.jwt_manager.active_tokens),
            'blacklisted_tokens': len(self.jwt_manager.blacklisted_tokens),
            'locked_accounts': len(self.locked_accounts),
            'failed_login_attempts': len(self.failed_login_attempts),
            'blocked_ips': len(self.policies['blocked_ip_addresses']),
            'security_events': self.auditor.get_event_summary(),
            'policies': self.policies.copy()
        }

    def start_background_cleanup(self):
        """Start background cleanup thread"""
        def cleanup_loop():
            while not self.shutdown_event.is_set():
                try:
                    # Cleanup expired tokens
                    expired_count = self.jwt_manager.cleanup_expired_tokens()
                    if expired_count > 0:
                        logger.info(f"Cleaned up {expired_count} expired tokens")

                    # Cleanup expired account locks
                    current_time = time.time()
                    expired_locks = [
                        username for username, unlock_time in self.locked_accounts.items()
                        if current_time > unlock_time
                    ]
                    for username in expired_locks:
                        del self.locked_accounts[username]

                    if expired_locks:
                        logger.info(f"Unlocked {len(expired_locks)} accounts")

                except Exception as e:
                    logger.error(f"Security cleanup failed: {e}")

                # Wait for 5 minutes or shutdown
                self.shutdown_event.wait(300)

        self.cleanup_thread = threading.Thread(
            target=cleanup_loop,
            name="SecurityCleanup",
            daemon=True
        )
        self.cleanup_thread.start()

    def setup_mfa(self, user_id: str) -> Dict[str, Any]:
        """Setup MFA for user"""
        try:
            secret = self.mfa.generate_totp_secret(user_id)
            uri = self.mfa.get_totp_uri(user_id)

            self.auditor.log_event(
                'security',
                'low',
                f'MFA setup initiated for user {user_id}',
                user_id=user_id
            )

            return {
                'success': True,
                'secret': secret,
                'uri': uri,
                'backup_codes': self.mfa.secrets[user_id].backup_codes.copy()
            }
        except Exception as e:
            logger.error(f"MFA setup failed for user {user_id}: {e}")
            return {'success': False, 'error': str(e)}

    def enable_mfa(self, user_id: str) -> bool:
        """Enable MFA for user"""
        return self.mfa.enable_mfa(user_id)

    def disable_mfa(self, user_id: str) -> bool:
        """Disable MFA for user"""
        return self.mfa.disable_mfa(user_id)

    def verify_mfa_code(self, user_id: str, code: str, ip_address: Optional[str] = None) -> bool:
        """Verify MFA code"""
        return self.mfa.verify_totp(user_id, code, ip_address)

    def verify_backup_code(self, user_id: str, code: str, ip_address: Optional[str] = None) -> bool:
        """Verify backup code"""
        return self.mfa.verify_backup_code(user_id, code, ip_address)

    def get_mfa_status(self, user_id: str) -> Dict[str, Any]:
        """Get MFA status for user"""
        return self.mfa.get_mfa_status(user_id)

    def reset_mfa(self, user_id: str) -> bool:
        """Reset MFA for user"""
        return self.mfa.reset_mfa(user_id)

    def log_event(
        self,
        event_type: str,
        severity: str,
        description: str,
        source_ip: Optional[str] = None,
        user_id: Optional[str] = None,
        **metadata
    ):
        """Log security event with dynamic firewall rule generation"""
        # Log to auditor
        self.auditor.log_event(
            event_type=event_type,
            severity=severity,
            description=description,
            source_ip=source_ip,
            user_id=user_id,
            **metadata
        )

        # Generate dynamic firewall rule if enabled
        if self.policies.get('dynamic_firewall_enabled', False) and self.policies.get('auto_block_suspicious', False):
            try:
                event = SecurityEvent(
                    event_type=event_type,
                    severity=severity,
                    description=description,
                    source_ip=source_ip,
                    user_id=user_id,
                    timestamp=time.time(),
                    metadata=metadata
                )
                rule = self.firewall.generate_rule_from_event(event)
                if rule:
                    logger.info(f"Generated firewall rule from security event: {rule.rule_id}")
            except Exception as e:
                logger.warning(f"Failed to generate firewall rule: {e}")

    def check_firewall_traffic(self, source_ip: str, protocol: str = 'tcp', port: int = 0) -> str:
        """Check if traffic should be allowed by firewall"""
        return self.firewall.check_traffic(source_ip, protocol, port)

    def add_firewall_rule(
        self,
        source_ip: str,
        action: str,
        protocol: Optional[str] = None,
        port: Optional[int] = None,
        reason: str = "Manual rule",
        duration_hours: Optional[int] = None
    ) -> str:
        """Add manual firewall rule"""
        return self.firewall.add_manual_rule(source_ip, action, protocol, port, reason, duration_hours)

    def remove_firewall_rule(self, rule_id: str) -> bool:
        """Remove firewall rule"""
        return self.firewall.remove_rule(rule_id)

    def get_firewall_rules(self) -> List[FirewallRule]:
        """Get active firewall rules"""
        return self.firewall.get_active_rules()

    def cleanup_firewall_rules(self) -> int:
        """Clean up expired firewall rules"""
        return self.firewall.cleanup_expired_rules()

    def register_zkp_user(self, user_id: str, password: str) -> bool:
        """Register user for ZKP authentication"""
        return self.zkp.register_user(user_id, password)

    def initiate_zkp_authentication(self, user_id: str) -> Optional[str]:
        """Initiate ZKP authentication"""
        return self.zkp.initiate_authentication(user_id)

    def verify_zkp_proof(self, user_id: str, client_proof: str, challenge: str) -> bool:
        """Verify ZKP proof"""
        return self.zkp.verify_proof(user_id, client_proof, challenge)

    def enable_zkp(self, user_id: str) -> bool:
        """Enable ZKP authentication for user"""
        return self.zkp.enable_zkp(user_id)

    def disable_zkp(self, user_id: str) -> bool:
        """Disable ZKP authentication for user"""
        return self.zkp.disable_zkp(user_id)

    def is_zkp_enabled(self, user_id: str) -> bool:
        """Check if ZKP is enabled for user"""
        return self.zkp.is_zkp_enabled(user_id)

    def reset_zkp(self, user_id: str) -> bool:
        """Reset ZKP credentials for user"""
        return self.zkp.reset_zkp(user_id)

    def authenticate_with_zkp(
        self,
        username: str,
        client_proof: str,
        challenge: str,
        source_ip: Optional[str] = None
    ) -> Optional[AuthToken]:
        """Authenticate user using ZKP"""
        if not self.policies['zkp_enabled']:
            self.auditor.log_event(
                'authentication',
                'medium',
                'ZKP authentication attempted but disabled',
                source_ip=source_ip,
                user_id=username
            )
            return None

        # Check rate limiting
        if not self.rate_limiter.is_allowed(f"zkp:{username}"):
            self.auditor.log_event(
                'authentication',
                'medium',
                f'ZKP rate limit exceeded for user {username}',
                source_ip=source_ip,
                user_id=username
            )
            return None

        # Verify ZKP proof
        if self.zkp.verify_proof(username, client_proof, challenge):
            # Create token
            token = self.jwt_manager.create_token(
                user_id=username,
                permissions=self.get_user_permissions(username),
                expires_in=self.policies['token_expiry_default']
            )

            self.auditor.log_event(
                'authentication',
                'low',
                f'Successful ZKP authentication for user {username}',
                source_ip=source_ip,
                user_id=username
            )

            return token
        else:
            self.auditor.log_event(
                'authentication',
                'medium',
                f'Failed ZKP authentication for user {username}',
                source_ip=source_ip,
                user_id=username
            )
            return None

# Global security manager instance
_security_manager: Optional[UnifiedSecurityManager] = None

def get_security_manager() -> UnifiedSecurityManager:
    """Get or create global security manager"""
    global _security_manager
    if _security_manager is None:
        _security_manager = UnifiedSecurityManager()
    return _security_manager

def authenticate_user(username: str, password: str, source_ip: Optional[str] = None, mfa_code: Optional[str] = None) -> Tuple[Optional[AuthToken], Optional[str]]:
    """Authenticate user with optional MFA"""
    manager = get_security_manager()
    return manager.authenticate_user(username, password, source_ip, mfa_code)

def setup_mfa(user_id: str) -> Dict[str, Any]:
    """Setup MFA for user"""
    manager = get_security_manager()
    return manager.setup_mfa(user_id)

def enable_mfa(user_id: str) -> bool:
    """Enable MFA for user"""
    manager = get_security_manager()
    return manager.enable_mfa(user_id)

def disable_mfa(user_id: str) -> bool:
    """Disable MFA for user"""
    manager = get_security_manager()
    return manager.disable_mfa(user_id)

def verify_mfa_code(user_id: str, code: str, ip_address: Optional[str] = None) -> bool:
    """Verify MFA code"""
    manager = get_security_manager()
    return manager.verify_mfa_code(user_id, code, ip_address)

def verify_backup_code(user_id: str, code: str, ip_address: Optional[str] = None) -> bool:
    """Verify backup code"""
    manager = get_security_manager()
    return manager.verify_backup_code(user_id, code, ip_address)

def get_mfa_status(user_id: str) -> Dict[str, Any]:
    """Get MFA status for user"""
    manager = get_security_manager()
    return manager.get_mfa_status(user_id)

def reset_mfa(user_id: str) -> bool:
    """Reset MFA for user"""
    manager = get_security_manager()
    return manager.reset_mfa(user_id)

def get_mfa_attempts(user_id: Optional[str] = None, limit: int = 50) -> List[MFAAuthentication]:
    """Get MFA authentication attempts"""
    manager = get_security_manager()
    return manager.get_mfa_attempts(user_id, limit)

def register_zkp_user(user_id: str, password: str) -> bool:
    """Register user for ZKP authentication"""
    manager = get_security_manager()
    return manager.register_zkp_user(user_id, password)

def initiate_zkp_authentication(user_id: str) -> Optional[str]:
    """Initiate ZKP authentication"""
    manager = get_security_manager()
    return manager.initiate_zkp_authentication(user_id)

def verify_zkp_proof(user_id: str, client_proof: str, challenge: str) -> bool:
    """Verify ZKP proof"""
    manager = get_security_manager()
    return manager.verify_zkp_proof(user_id, client_proof, challenge)

def authenticate_with_zkp(username: str, client_proof: str, challenge: str, source_ip: Optional[str] = None) -> Optional[AuthToken]:
    """Authenticate user using ZKP"""
    manager = get_security_manager()
    return manager.authenticate_with_zkp(username, client_proof, challenge, source_ip)

def enable_zkp(user_id: str) -> bool:
    """Enable ZKP authentication for user"""
    manager = get_security_manager()
    return manager.enable_zkp(user_id)

def disable_zkp(user_id: str) -> bool:
    """Disable ZKP authentication for user"""
    manager = get_security_manager()
    return manager.disable_zkp(user_id)

def is_zkp_enabled(user_id: str) -> bool:
    """Check if ZKP is enabled for user"""
    manager = get_security_manager()
    return manager.is_zkp_enabled(user_id)

def reset_zkp(user_id: str) -> bool:
    """Reset ZKP credentials for user"""
    manager = get_security_manager()
    return manager.reset_zkp(user_id)

def check_firewall_traffic(source_ip: str, protocol: str = 'tcp', port: int = 0) -> str:
    """Check if traffic should be allowed by firewall"""
    manager = get_security_manager()
    return manager.check_firewall_traffic(source_ip, protocol, port)

def add_firewall_rule(
    source_ip: str,
    action: str,
    protocol: Optional[str] = None,
    port: Optional[int] = None,
    reason: str = "Manual rule",
    duration_hours: Optional[int] = None
) -> str:
    """Add manual firewall rule"""
    manager = get_security_manager()
    return manager.add_firewall_rule(source_ip, action, protocol, port, reason, duration_hours)

def remove_firewall_rule(rule_id: str) -> bool:
    """Remove firewall rule"""
    manager = get_security_manager()
    return manager.remove_firewall_rule(rule_id)

def get_firewall_rules() -> List[FirewallRule]:
    """Get active firewall rules"""
    manager = get_security_manager()
    return manager.get_firewall_rules()

def cleanup_firewall_rules() -> int:
    """Clean up expired firewall rules"""
    manager = get_security_manager()
    return manager.cleanup_firewall_rules()

def get_firewall_report() -> Dict[str, Any]:
    """Get firewall status report"""
    manager = get_security_manager()
    return manager.firewall.get_firewall_report()

def verify_token(token: str) -> Optional[AuthToken]:
    """Verify authentication token"""
    manager = get_security_manager()
    return manager.verify_token(token)

def encrypt_data(data: str) -> str:
    """Encrypt sensitive data"""
    manager = get_security_manager()
    return manager.encrypt_sensitive_data(data)

def decrypt_data(encrypted_data: str) -> str:
    """Decrypt sensitive data"""
    manager = get_security_manager()
    return manager.decrypt_sensitive_data(encrypted_data)

def get_security_report() -> Dict[str, Any]:
    """Get security report"""
    manager = get_security_manager()
    return manager.get_security_report()

# Cleanup on shutdown
import atexit
def _cleanup_security_manager():
    global _security_manager
    if _security_manager:
        _security_manager.stop_background_cleanup()

atexit.register(_cleanup_security_manager)

__all__ = [
    'UnifiedSecurityManager',
    'SecurityEvent',
    'AuthToken',
    'MFASecret',
    'MFAAuthentication',
    'MultiFactorAuthenticator',
    'ZKPChallenge',
    'ZKPSecret',
    'ZeroKnowledgeAuthenticator',
    'FirewallRule',
    'ThreatPattern',
    'DynamicFirewall',
    'RateLimiter',
    'EncryptionManager',
    'JWTManager',
    'SecurityAuditor',
    'get_security_manager',
    'authenticate_user',
    'setup_mfa',
    'enable_mfa',
    'disable_mfa',
    'verify_mfa_code',
    'verify_backup_code',
    'get_mfa_status',
    'reset_mfa',
    'get_mfa_attempts',
    'register_zkp_user',
    'initiate_zkp_authentication',
    'verify_zkp_proof',
    'authenticate_with_zkp',
    'enable_zkp',
    'disable_zkp',
    'is_zkp_enabled',
    'reset_zkp',
    'check_firewall_traffic',
    'add_firewall_rule',
    'remove_firewall_rule',
    'get_firewall_rules',
    'cleanup_firewall_rules',
    'get_firewall_report',
    'verify_token',
    'encrypt_data',
    'decrypt_data',
    'get_security_report'
]