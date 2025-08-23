"""
Authentication and Authorization System
Government-grade identity and access management
"""

import time
import jwt
import hashlib
import hmac
import secrets
import base64
import json
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import threading
import re


class AuthMethod(Enum):
    """Authentication methods"""
    PASSWORD = "password"
    API_KEY = "api_key"
    JWT = "jwt"
    OAUTH2 = "oauth2"
    SAML = "saml"
    CERTIFICATE = "certificate"
    BIOMETRIC = "biometric"
    MFA = "mfa"


class Permission(Enum):
    """System permissions"""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    ADMIN = "admin"
    AUDIT = "audit"
    CONFIGURE = "configure"
    APPROVE = "approve"


class Role(Enum):
    """User roles"""
    GUEST = "guest"
    USER = "user"
    OPERATOR = "operator"
    ANALYST = "analyst"
    ADMIN = "admin"
    SECURITY_ADMIN = "security_admin"
    SYSTEM_ADMIN = "system_admin"
    AUDITOR = "auditor"


@dataclass
class User:
    """User account"""
    id: str
    username: str
    email: str
    roles: Set[Role] = field(default_factory=set)
    permissions: Set[Permission] = field(default_factory=set)
    created_at: float = field(default_factory=time.time)
    last_login: Optional[float] = None
    failed_attempts: int = 0
    locked_until: Optional[float] = None
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    active: bool = True
    
    def is_locked(self) -> bool:
        """Check if account is locked"""
        if self.locked_until:
            return time.time() < self.locked_until
        return False
        
    def has_role(self, role: Role) -> bool:
        """Check if user has role"""
        return role in self.roles
        
    def has_permission(self, permission: Permission) -> bool:
        """Check if user has permission"""
        return permission in self.permissions or self.has_role(Role.ADMIN)


@dataclass
class Session:
    """User session"""
    id: str
    user_id: str
    token: str
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    expires_at: float = 0
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_expired(self) -> bool:
        """Check if session is expired"""
        return time.time() > self.expires_at
        
    def is_inactive(self, timeout: int = 1800) -> bool:
        """Check if session is inactive"""
        return time.time() - self.last_activity > timeout
        
    def update_activity(self):
        """Update last activity time"""
        self.last_activity = time.time()


@dataclass
class ApiKey:
    """API key"""
    key: str
    user_id: str
    name: str
    created_at: float = field(default_factory=time.time)
    last_used: Optional[float] = None
    expires_at: Optional[float] = None
    permissions: Set[Permission] = field(default_factory=set)
    rate_limit: int = 1000
    active: bool = True
    
    def is_expired(self) -> bool:
        """Check if API key is expired"""
        if self.expires_at:
            return time.time() > self.expires_at
        return False
        
    def update_usage(self):
        """Update last used time"""
        self.last_used = time.time()


class PasswordPolicy:
    """Password policy enforcement"""
    
    def __init__(self):
        self.min_length = 12
        self.max_length = 128
        self.require_uppercase = True
        self.require_lowercase = True
        self.require_numbers = True
        self.require_special = True
        self.special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        self.prevent_common = True
        self.prevent_reuse = 5
        self.max_age_days = 90
        
    def validate(self, password: str) -> Tuple[bool, List[str]]:
        """Validate password against policy"""
        errors = []
        
        # Length check
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters")
        if len(password) > self.max_length:
            errors.append(f"Password must be at most {self.max_length} characters")
            
        # Character requirements
        if self.require_uppercase and not re.search(r'[A-Z]', password):
            errors.append("Password must contain uppercase letters")
        if self.require_lowercase and not re.search(r'[a-z]', password):
            errors.append("Password must contain lowercase letters")
        if self.require_numbers and not re.search(r'\d', password):
            errors.append("Password must contain numbers")
        if self.require_special and not any(c in self.special_chars for c in password):
            errors.append("Password must contain special characters")
            
        # Common password check
        if self.prevent_common:
            common_passwords = ["password", "123456", "admin", "letmein", "welcome"]
            if password.lower() in common_passwords:
                errors.append("Password is too common")
                
        return len(errors) == 0, errors
        
    def generate_strong_password(self, length: int = 16) -> str:
        """Generate strong random password"""
        import string
        import random
        
        chars = []
        if self.require_uppercase:
            chars.extend(string.ascii_uppercase)
        if self.require_lowercase:
            chars.extend(string.ascii_lowercase)
        if self.require_numbers:
            chars.extend(string.digits)
        if self.require_special:
            chars.extend(self.special_chars)
            
        # Ensure at least one of each required type
        password = []
        if self.require_uppercase:
            password.append(random.choice(string.ascii_uppercase))
        if self.require_lowercase:
            password.append(random.choice(string.ascii_lowercase))
        if self.require_numbers:
            password.append(random.choice(string.digits))
        if self.require_special:
            password.append(random.choice(self.special_chars))
            
        # Fill the rest
        for _ in range(length - len(password)):
            password.append(random.choice(chars))
            
        # Shuffle
        random.shuffle(password)
        
        return ''.join(password)


class PasswordHasher:
    """Secure password hashing"""
    
    def __init__(self):
        self.algorithm = "pbkdf2_sha256"
        self.iterations = 260000
        self.salt_length = 32
        
    def hash_password(self, password: str) -> str:
        """Hash password"""
        salt = secrets.token_bytes(self.salt_length)
        
        if self.algorithm == "pbkdf2_sha256":
            key = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt,
                self.iterations
            )
        else:
            # Default to SHA256
            key = hashlib.sha256(salt + password.encode('utf-8')).digest()
            
        # Format: algorithm$iterations$salt$hash
        return f"{self.algorithm}${self.iterations}${base64.b64encode(salt).decode()}${base64.b64encode(key).decode()}"
        
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        try:
            parts = hashed.split('$')
            if len(parts) != 4:
                return False
                
            algorithm, iterations, salt_b64, hash_b64 = parts
            iterations = int(iterations)
            salt = base64.b64decode(salt_b64)
            stored_hash = base64.b64decode(hash_b64)
            
            if algorithm == "pbkdf2_sha256":
                key = hashlib.pbkdf2_hmac(
                    'sha256',
                    password.encode('utf-8'),
                    salt,
                    iterations
                )
            else:
                key = hashlib.sha256(salt + password.encode('utf-8')).digest()
                
            return hmac.compare_digest(key, stored_hash)
            
        except Exception:
            return False


class MFAProvider:
    """Multi-factor authentication provider"""
    
    def __init__(self):
        self.totp_window = 1
        self.totp_period = 30
        self.totp_digits = 6
        
    def generate_secret(self) -> str:
        """Generate MFA secret"""
        return base64.b32encode(secrets.token_bytes(32)).decode('utf-8')
        
    def generate_qr_code(self, user: str, secret: str, issuer: str = "BLRCS") -> str:
        """Generate QR code URL for MFA setup"""
        return f"otpauth://totp/{issuer}:{user}?secret={secret}&issuer={issuer}"
        
    def generate_totp(self, secret: str, timestamp: Optional[int] = None) -> str:
        """Generate TOTP code"""
        if timestamp is None:
            timestamp = int(time.time())
            
        counter = timestamp // self.totp_period
        
        # Decode secret
        key = base64.b32decode(secret)
        
        # Generate HMAC
        counter_bytes = counter.to_bytes(8, 'big')
        hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()
        
        # Dynamic truncation
        offset = hmac_hash[-1] & 0x0f
        truncated = hmac_hash[offset:offset + 4]
        
        # Generate code
        code = int.from_bytes(truncated, 'big') & 0x7fffffff
        code = code % (10 ** self.totp_digits)
        
        return str(code).zfill(self.totp_digits)
        
    def verify_totp(self, secret: str, code: str) -> bool:
        """Verify TOTP code"""
        timestamp = int(time.time())
        
        # Check within window
        for i in range(-self.totp_window, self.totp_window + 1):
            test_timestamp = timestamp + (i * self.totp_period)
            expected_code = self.generate_totp(secret, test_timestamp)
            
            if hmac.compare_digest(code, expected_code):
                return True
                
        return False


class JWTProvider:
    """JWT token provider"""
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self.algorithm = "HS256"
        self.access_token_ttl = 3600  # 1 hour
        self.refresh_token_ttl = 604800  # 7 days
        
    def generate_access_token(self, user_id: str, **claims) -> str:
        """Generate access token"""
        payload = {
            "user_id": user_id,
            "type": "access",
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(seconds=self.access_token_ttl),
            "jti": secrets.token_hex(16),
            **claims
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        
    def generate_refresh_token(self, user_id: str) -> str:
        """Generate refresh token"""
        payload = {
            "user_id": user_id,
            "type": "refresh",
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(seconds=self.refresh_token_ttl),
            "jti": secrets.token_hex(16)
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        
    def verify_token(self, token: str, token_type: str = "access") -> Optional[Dict[str, Any]]:
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            if payload.get("type") != token_type:
                return None
                
            return payload
            
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None


class RBACManager:
    """Role-based access control manager"""
    
    def __init__(self):
        self.role_permissions = {
            Role.GUEST: {Permission.READ},
            Role.USER: {Permission.READ, Permission.WRITE},
            Role.OPERATOR: {Permission.READ, Permission.WRITE, Permission.EXECUTE},
            Role.ANALYST: {Permission.READ, Permission.AUDIT},
            Role.ADMIN: {Permission.READ, Permission.WRITE, Permission.DELETE, 
                        Permission.EXECUTE, Permission.CONFIGURE},
            Role.SECURITY_ADMIN: {Permission.READ, Permission.WRITE, Permission.DELETE,
                                 Permission.EXECUTE, Permission.CONFIGURE, Permission.AUDIT},
            Role.SYSTEM_ADMIN: set(Permission),  # All permissions
            Role.AUDITOR: {Permission.READ, Permission.AUDIT}
        }
        
        self.resource_permissions = {}
        self.lock = threading.Lock()
        
    def get_role_permissions(self, role: Role) -> Set[Permission]:
        """Get permissions for role"""
        return self.role_permissions.get(role, set())
        
    def check_permission(self, user: User, resource: str, 
                        permission: Permission) -> bool:
        """Check if user has permission for resource"""
        # Check direct permissions
        if permission in user.permissions:
            return True
            
        # Check role permissions
        for role in user.roles:
            if permission in self.get_role_permissions(role):
                return True
                
        # Check resource-specific permissions
        with self.lock:
            if resource in self.resource_permissions:
                resource_perms = self.resource_permissions[resource]
                if user.id in resource_perms:
                    if permission in resource_perms[user.id]:
                        return True
                        
        return False
        
    def grant_permission(self, user_id: str, resource: str, 
                        permission: Permission):
        """Grant permission to user for resource"""
        with self.lock:
            if resource not in self.resource_permissions:
                self.resource_permissions[resource] = {}
                
            if user_id not in self.resource_permissions[resource]:
                self.resource_permissions[resource][user_id] = set()
                
            self.resource_permissions[resource][user_id].add(permission)
            
    def revoke_permission(self, user_id: str, resource: str, 
                         permission: Permission):
        """Revoke permission from user for resource"""
        with self.lock:
            if resource in self.resource_permissions:
                if user_id in self.resource_permissions[resource]:
                    self.resource_permissions[resource][user_id].discard(permission)


class AuthenticationSystem:
    """Complete authentication system"""
    
    def __init__(self, secret_key: str = None):
        self.secret_key = secret_key or secrets.token_hex(32)
        self.users = {}
        self.sessions = {}
        self.api_keys = {}
        self.password_policy = PasswordPolicy()
        self.password_hasher = PasswordHasher()
        self.mfa_provider = MFAProvider()
        self.jwt_provider = JWTProvider(self.secret_key)
        self.rbac_manager = RBACManager()
        self.lock = threading.Lock()
        
        # Security settings
        self.max_login_attempts = 5
        self.lockout_duration = 900  # 15 minutes
        self.session_timeout = 3600  # 1 hour
        self.require_mfa_for_admin = True
        
    def create_user(self, username: str, email: str, password: str,
                   roles: Optional[Set[Role]] = None) -> Tuple[bool, Union[User, str]]:
        """Create new user"""
        with self.lock:
            # Check if user exists
            if username in self.users:
                return False, "Username already exists"
                
            # Validate password
            valid, errors = self.password_policy.validate(password)
            if not valid:
                return False, "; ".join(errors)
                
            # Create user
            user_id = hashlib.sha256(f"{username}{time.time()}".encode()).hexdigest()[:16]
            
            user = User(
                id=user_id,
                username=username,
                email=email,
                roles=roles or {Role.USER}
            )
            
            # Hash password
            user.metadata['password_hash'] = self.password_hasher.hash_password(password)
            
            # Enable MFA for admin roles
            if self.require_mfa_for_admin and Role.ADMIN in user.roles:
                user.mfa_enabled = True
                user.mfa_secret = self.mfa_provider.generate_secret()
                
            self.users[username] = user
            
            return True, user
            
    def authenticate(self, username: str, password: str, 
                    mfa_code: Optional[str] = None) -> Tuple[bool, Union[Session, str]]:
        """Authenticate user"""
        with self.lock:
            # Check if user exists
            if username not in self.users:
                return False, "Invalid credentials"
                
            user = self.users[username]
            
            # Check if account is locked
            if user.is_locked():
                return False, "Account is locked"
                
            # Verify password
            password_hash = user.metadata.get('password_hash')
            if not self.password_hasher.verify_password(password, password_hash):
                user.failed_attempts += 1
                
                # Lock account if too many attempts
                if user.failed_attempts >= self.max_login_attempts:
                    user.locked_until = time.time() + self.lockout_duration
                    return False, "Account locked due to too many failed attempts"
                    
                return False, "Invalid credentials"
                
            # Verify MFA if enabled
            if user.mfa_enabled:
                if not mfa_code:
                    return False, "MFA code required"
                    
                if not self.mfa_provider.verify_totp(user.mfa_secret, mfa_code):
                    return False, "Invalid MFA code"
                    
            # Reset failed attempts
            user.failed_attempts = 0
            user.last_login = time.time()
            
            # Create session
            session = self._create_session(user)
            
            return True, session
            
    def _create_session(self, user: User) -> Session:
        """Create user session"""
        session_id = secrets.token_hex(32)
        token = self.jwt_provider.generate_access_token(user.id)
        
        session = Session(
            id=session_id,
            user_id=user.id,
            token=token,
            expires_at=time.time() + self.session_timeout
        )
        
        self.sessions[session_id] = session
        
        return session
        
    def validate_session(self, session_id: str) -> Optional[User]:
        """Validate session and return user"""
        with self.lock:
            if session_id not in self.sessions:
                return None
                
            session = self.sessions[session_id]
            
            # Check expiration
            if session.is_expired():
                del self.sessions[session_id]
                return None
                
            # Check inactivity
            if session.is_inactive(self.session_timeout):
                del self.sessions[session_id]
                return None
                
            # Update activity
            session.update_activity()
            
            # Get user
            for user in self.users.values():
                if user.id == session.user_id:
                    return user
                    
        return None
        
    def create_api_key(self, user_id: str, name: str, 
                       permissions: Optional[Set[Permission]] = None) -> ApiKey:
        """Create API key"""
        key = f"blrcs_{secrets.token_hex(32)}"
        
        api_key = ApiKey(
            key=key,
            user_id=user_id,
            name=name,
            permissions=permissions or set()
        )
        
        with self.lock:
            self.api_keys[key] = api_key
            
        return api_key
        
    def validate_api_key(self, key: str) -> Optional[User]:
        """Validate API key and return user"""
        with self.lock:
            if key not in self.api_keys:
                return None
                
            api_key = self.api_keys[key]
            
            if not api_key.active:
                return None
                
            if api_key.is_expired():
                return None
                
            api_key.update_usage()
            
            # Get user
            for user in self.users.values():
                if user.id == api_key.user_id:
                    # Add API key permissions to user
                    user.permissions.update(api_key.permissions)
                    return user
                    
        return None
        
    def logout(self, session_id: str):
        """Logout user"""
        with self.lock:
            if session_id in self.sessions:
                del self.sessions[session_id]


# Global authentication system
_auth_system = None


def get_auth_system() -> AuthenticationSystem:
    """Get global authentication system"""
    global _auth_system
    if _auth_system is None:
        _auth_system = AuthenticationSystem()
    return _auth_system


def init_auth_system(secret_key: str = None) -> AuthenticationSystem:
    """Initialize authentication system"""
    global _auth_system
    _auth_system = AuthenticationSystem(secret_key)
    return _auth_system