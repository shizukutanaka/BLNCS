# BLRCS User Management System
# Enterprise-grade user management with advanced security
import bcrypt
import secrets
import time
import uuid
import json
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Set, Any, Union, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import threading
from collections import defaultdict, deque
import re

class UserRole(Enum):
    """User roles with hierarchical permissions"""
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"
    GUEST = "guest"

class UserStatus(Enum):
    """User account status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    LOCKED = "locked"
    PENDING = "pending"
    EXPIRED = "expired"

class SessionStatus(Enum):
    """Session status"""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    TERMINATED = "terminated"

@dataclass
class UserPermission:
    """User permission definition"""
    name: str
    description: str
    resource: str
    action: str
    conditions: Dict[str, Any] = field(default_factory=dict)

@dataclass
class User:
    """User account with enhanced security features"""
    id: str
    username: str
    email: str
    password_hash: str
    role: UserRole
    status: UserStatus = UserStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    last_login: Optional[datetime] = None
    login_attempts: int = 0
    last_attempt: Optional[datetime] = None
    password_expires: Optional[datetime] = None
    two_factor_enabled: bool = False
    two_factor_secret: Optional[str] = None
    backup_codes: List[str] = field(default_factory=list)
    preferences: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if isinstance(self.role, str):
            self.role = UserRole(self.role)
        if isinstance(self.status, str):
            self.status = UserStatus(self.status)
        if isinstance(self.created_at, str):
            self.created_at = datetime.fromisoformat(self.created_at)
        if isinstance(self.updated_at, str):
            self.updated_at = datetime.fromisoformat(self.updated_at)
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Convert user to dictionary"""
        data = asdict(self)
        
        # Convert enums to strings
        data['role'] = self.role.value
        data['status'] = self.status.value
        
        # Convert datetime to ISO format
        data['created_at'] = self.created_at.isoformat()
        data['updated_at'] = self.updated_at.isoformat()
        if self.last_login:
            data['last_login'] = self.last_login.isoformat()
        if self.last_attempt:
            data['last_attempt'] = self.last_attempt.isoformat()
        if self.password_expires:
            data['password_expires'] = self.password_expires.isoformat()
        
        # Remove sensitive data if not requested
        if not include_sensitive:
            data.pop('password_hash', None)
            data.pop('two_factor_secret', None)
            data.pop('backup_codes', None)
        
        return data
    
    def is_active(self) -> bool:
        """Check if user account is active"""
        return self.status == UserStatus.ACTIVE
    
    def is_locked(self) -> bool:
        """Check if user account is locked"""
        return self.status in [UserStatus.LOCKED, UserStatus.SUSPENDED]
    
    def password_expired(self) -> bool:
        """Check if password has expired"""
        if not self.password_expires:
            return False
        return datetime.now() > self.password_expires

@dataclass
class Session:
    """User session with security tracking"""
    id: str
    user_id: str
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: datetime = field(default_factory=lambda: datetime.now() + timedelta(hours=8))
    last_activity: datetime = field(default_factory=datetime.now)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    status: SessionStatus = SessionStatus.ACTIVE
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if isinstance(self.status, str):
            self.status = SessionStatus(self.status)
        if isinstance(self.created_at, str):
            self.created_at = datetime.fromisoformat(self.created_at)
        if isinstance(self.expires_at, str):
            self.expires_at = datetime.fromisoformat(self.expires_at)
        if isinstance(self.last_activity, str):
            self.last_activity = datetime.fromisoformat(self.last_activity)
    
    def is_valid(self) -> bool:
        """Check if session is valid"""
        return (
            self.status == SessionStatus.ACTIVE and
            datetime.now() < self.expires_at
        )
    
    def is_expired(self) -> bool:
        """Check if session has expired"""
        return datetime.now() >= self.expires_at
    
    def refresh(self, extend_hours: int = 8):
        """Refresh session expiration"""
        self.last_activity = datetime.now()
        self.expires_at = datetime.now() + timedelta(hours=extend_hours)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary"""
        data = asdict(self)
        data['status'] = self.status.value
        data['created_at'] = self.created_at.isoformat()
        data['expires_at'] = self.expires_at.isoformat()
        data['last_activity'] = self.last_activity.isoformat()
        return data

class PasswordPolicy:
    """Password policy enforcement"""
    
    def __init__(self):
        self.min_length = 12
        self.max_length = 128
        self.require_uppercase = True
        self.require_lowercase = True
        self.require_digits = True
        self.require_special = True
        self.special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        self.max_repeated_chars = 3
        self.min_unique_chars = 8
        self.password_history_count = 12
        self.password_expiry_days = 90
        self.common_passwords_file = None
        self._common_passwords: Set[str] = set()
        
        # Load common passwords if available
        self._load_common_passwords()
    
    def _load_common_passwords(self):
        """Load common passwords list"""
        if self.common_passwords_file and Path(self.common_passwords_file).exists():
            try:
                with open(self.common_passwords_file, 'r') as f:
                    self._common_passwords = {line.strip().lower() for line in f}
            except Exception:
                pass
        
        # Add some basic common passwords
        self._common_passwords.update({
            'password', '123456', 'password123', 'admin', 'letmein',
            'welcome', 'monkey', '1234567890', 'qwerty', 'abc123'
        })
    
    def validate(self, password: str, username: str = "", email: str = "") -> tuple[bool, List[str]]:
        """Validate password against policy"""
        errors = []
        
        # Length check
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters long")
        
        if len(password) > self.max_length:
            errors.append(f"Password must not exceed {self.max_length} characters")
        
        # Character requirements
        if self.require_uppercase and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if self.require_lowercase and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if self.require_digits and not re.search(r'\d', password):
            errors.append("Password must contain at least one digit")
        
        if self.require_special and not re.search(f'[{re.escape(self.special_chars)}]', password):
            errors.append(f"Password must contain at least one special character: {self.special_chars}")
        
        # Repeated characters
        if self._has_too_many_repeated_chars(password):
            errors.append(f"Password cannot have more than {self.max_repeated_chars} consecutive repeated characters")
        
        # Unique characters
        if len(set(password)) < self.min_unique_chars:
            errors.append(f"Password must contain at least {self.min_unique_chars} unique characters")
        
        # Common passwords
        if password.lower() in self._common_passwords:
            errors.append("Password is too common and easily guessable")
        
        # Username/email similarity
        if username and username.lower() in password.lower():
            errors.append("Password cannot contain username")
        
        if email:
            email_local = email.split('@')[0].lower()
            if len(email_local) > 3 and email_local in password.lower():
                errors.append("Password cannot contain email address")
        
        # Keyboard patterns
        if self._has_keyboard_pattern(password):
            errors.append("Password cannot contain keyboard patterns")
        
        return len(errors) == 0, errors
    
    def _has_too_many_repeated_chars(self, password: str) -> bool:
        """Check for too many repeated characters"""
        count = 1
        for i in range(1, len(password)):
            if password[i] == password[i-1]:
                count += 1
                if count > self.max_repeated_chars:
                    return True
            else:
                count = 1
        return False
    
    def _has_keyboard_pattern(self, password: str) -> bool:
        """Check for keyboard patterns"""
        keyboard_patterns = [
            'qwerty', 'asdf', 'zxcv', '1234', 'abcd',
            'qwertyuiop', 'asdfghjkl', 'zxcvbnm'
        ]
        
        password_lower = password.lower()
        for pattern in keyboard_patterns:
            if pattern in password_lower or pattern[::-1] in password_lower:
                return True
        
        return False
    
    def generate_secure_password(self, length: int = None) -> str:
        """Generate a secure password"""
        if length is None:
            length = max(self.min_length, 16)
        
        chars = ""
        if self.require_lowercase:
            chars += "abcdefghijklmnopqrstuvwxyz"
        if self.require_uppercase:
            chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if self.require_digits:
            chars += "0123456789"
        if self.require_special:
            chars += self.special_chars
        
        # Ensure at least one character from each required category
        password = []
        if self.require_lowercase:
            password.append(secrets.choice("abcdefghijklmnopqrstuvwxyz"))
        if self.require_uppercase:
            password.append(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
        if self.require_digits:
            password.append(secrets.choice("0123456789"))
        if self.require_special:
            password.append(secrets.choice(self.special_chars))
        
        # Fill the rest randomly
        for _ in range(length - len(password)):
            password.append(secrets.choice(chars))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)

class TwoFactorAuth:
    """Two-factor authentication management"""
    
    def __init__(self):
        self.backup_codes_count = 10
        self.backup_code_length = 8
        self.totp_window = 1  # Allow 1 window before/after current
    
    def generate_secret(self) -> str:
        """Generate TOTP secret"""
        return secrets.token_urlsafe(32)
    
    def generate_backup_codes(self) -> List[str]:
        """Generate backup codes"""
        codes = []
        for _ in range(self.backup_codes_count):
            code = ''.join(secrets.choice('0123456789') for _ in range(self.backup_code_length))
            # Add dash for readability
            formatted_code = f"{code[:4]}-{code[4:]}"
            codes.append(formatted_code)
        return codes
    
    def verify_totp(self, secret: str, token: str) -> bool:
        """Verify TOTP token"""
        try:
            import pyotp
            totp = pyotp.TOTP(secret)
            return totp.verify(token, valid_window=self.totp_window)
        except ImportError:
            # Fallback implementation without pyotp
            return self._simple_totp_verify(secret, token)
    
    def _simple_totp_verify(self, secret: str, token: str) -> bool:
        """Simple TOTP verification without external library"""
        # This is a simplified implementation
        # In production, use a proper TOTP library like pyotp
        try:
            current_time = int(time.time()) // 30
            expected_tokens = []
            
            # Check current and adjacent time windows
            for time_offset in range(-self.totp_window, self.totp_window + 1):
                time_step = current_time + time_offset
                expected_token = self._generate_totp_token(secret, time_step)
                expected_tokens.append(expected_token)
            
            return token in expected_tokens
        except Exception:
            return False
    
    def _generate_totp_token(self, secret: str, time_step: int) -> str:
        """Generate TOTP token for given time step"""
        # Simplified TOTP implementation
        key = secret.encode()
        time_bytes = time_step.to_bytes(8, 'big')
        
        # HMAC-SHA256 (強化セキュリティ)
        hmac_digest = hmac.new(key, time_bytes, hashlib.sha256).digest()
        
        # Dynamic truncation
        offset = hmac_digest[-1] & 0x0f
        binary_code = int.from_bytes(hmac_digest[offset:offset+4], 'big') & 0x7fffffff
        
        # Generate 6-digit code
        token = str(binary_code % 1000000).zfill(6)
        return token
    
    def verify_backup_code(self, backup_codes: List[str], code: str) -> tuple[bool, List[str]]:
        """Verify backup code and remove it if valid"""
        # Remove formatting
        clean_code = code.replace('-', '').replace(' ', '')
        
        for i, backup_code in enumerate(backup_codes):
            clean_backup = backup_code.replace('-', '').replace(' ', '')
            if clean_code == clean_backup:
                # Remove used backup code
                new_codes = backup_codes.copy()
                new_codes.pop(i)
                return True, new_codes
        
        return False, backup_codes

class AuditEvent:
    """Audit event for user actions"""
    
    def __init__(self, user_id: str, action: str, resource: str = "",
                 details: Dict[str, Any] = None, ip_address: str = "",
                 user_agent: str = "", success: bool = True):
        self.id = str(uuid.uuid4())
        self.user_id = user_id
        self.action = action
        self.resource = resource
        self.details = details or {}
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.success = success
        self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'resource': self.resource,
            'details': self.details,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'success': self.success,
            'timestamp': self.timestamp.isoformat()
        }

class UserManager:
    """Comprehensive user management system"""
    
    def __init__(self, database=None, logger=None):
        self.database = database
        self.logger = logger
        self.users: Dict[str, User] = {}
        self.sessions: Dict[str, Session] = {}
        self.password_policy = PasswordPolicy()
        self.two_factor = TwoFactorAuth()
        self.audit_events: deque = deque(maxlen=10000)
        self.lock = threading.RLock()
        
        # Security settings
        self.max_login_attempts = 5
        self.lockout_duration = timedelta(minutes=30)
        self.session_timeout = timedelta(hours=8)
        self.max_sessions_per_user = 5
        
        # Password history for each user
        self.password_history: Dict[str, List[str]] = defaultdict(list)
        
        # Rate limiting
        self.rate_limiter = defaultdict(lambda: deque())
        self.rate_limit_window = 300  # 5 minutes
        self.rate_limit_max_attempts = 20
        
        # Load existing users if database is available
        self._load_users()
    
    def _load_users(self):
        """Load users from database"""
        if not self.database:
            return
        
        try:
            # Load users
            user_data = self.database.select('users')
            for row in user_data:
                user = User(**row)
                self.users[user.id] = user
            
            # Load sessions
            session_data = self.database.select('sessions')
            for row in session_data:
                session = Session(**row)
                self.sessions[session.id] = session
            
            # Clean expired sessions
            self._cleanup_expired_sessions()
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to load users: {e}")
    
    def create_user(self, username: str, email: str, password: str, 
                   role: UserRole = UserRole.VIEWER, **kwargs) -> tuple[bool, str, Optional[User]]:
        """Create new user account"""
        with self.lock:
            try:
                # Validate input
                if not username or not email or not password:
                    return False, "Username, email, and password are required", None
                
                # Check if user already exists
                if self._user_exists(username, email):
                    return False, "User with this username or email already exists", None
                
                # Validate password
                valid, errors = self.password_policy.validate(password, username, email)
                if not valid:
                    return False, "; ".join(errors), None
                
                # Create user
                user_id = str(uuid.uuid4())
                password_hash = self._hash_password(password)
                
                # Set password expiration
                password_expires = None
                if self.password_policy.password_expiry_days > 0:
                    password_expires = datetime.now() + timedelta(days=self.password_policy.password_expiry_days)
                
                user = User(
                    id=user_id,
                    username=username,
                    email=email,
                    password_hash=password_hash,
                    role=role,
                    password_expires=password_expires,
                    **kwargs
                )
                
                # Store user
                self.users[user_id] = user
                self._save_user(user)
                
                # Store password in history
                self.password_history[user_id].append(password_hash)
                
                # Audit log
                self._log_audit_event(user_id, "user_created", "user", {"username": username, "role": role.value})
                
                if self.logger:
                    self.logger.info(f"User created: {username} ({user_id})")
                
                return True, "User created successfully", user
                
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Failed to create user: {e}")
                return False, f"Failed to create user: {str(e)}", None
    
    def authenticate(self, username: str, password: str, 
                    totp_token: str = "", ip_address: str = "", 
                    user_agent: str = "") -> tuple[bool, str, Optional[Session]]:
        """Authenticate user and create session"""
        with self.lock:
            try:
                # Rate limiting check
                if not self._check_rate_limit(ip_address):
                    self._log_audit_event("", "login_rate_limited", "authentication", 
                                        {"ip_address": ip_address}, success=False)
                    return False, "Too many login attempts. Please try again later.", None
                
                # Find user
                user = self._find_user_by_username(username)
                if not user:
                    self._log_audit_event("", "login_failed", "authentication", 
                                        {"username": username, "reason": "user_not_found"}, success=False)
                    return False, "Invalid username or password", None
                
                # Check account status
                if not user.is_active():
                    self._log_audit_event(user.id, "login_failed", "authentication", 
                                        {"reason": "account_inactive"}, success=False)
                    return False, f"Account is {user.status.value}", None
                
                if user.is_locked():
                    # Check if lockout has expired
                    if user.last_attempt and datetime.now() - user.last_attempt > self.lockout_duration:
                        user.status = UserStatus.ACTIVE
                        user.login_attempts = 0
                        self._save_user(user)
                    else:
                        self._log_audit_event(user.id, "login_failed", "authentication", 
                                            {"reason": "account_locked"}, success=False)
                        return False, "Account is locked due to too many failed login attempts", None
                
                # Check password expiration
                if user.password_expired():
                    self._log_audit_event(user.id, "login_failed", "authentication", 
                                        {"reason": "password_expired"}, success=False)
                    return False, "Password has expired. Please reset your password.", None
                
                # Verify password
                if not self._verify_password(password, user.password_hash):
                    user.login_attempts += 1
                    user.last_attempt = datetime.now()
                    
                    if user.login_attempts >= self.max_login_attempts:
                        user.status = UserStatus.LOCKED
                        self._log_audit_event(user.id, "account_locked", "user", 
                                            {"reason": "too_many_failed_attempts"})
                    
                    self._save_user(user)
                    self._log_audit_event(user.id, "login_failed", "authentication", 
                                        {"reason": "invalid_password"}, success=False)
                    return False, "Invalid username or password", None
                
                # Two-factor authentication
                if user.two_factor_enabled:
                    if not totp_token:
                        return False, "Two-factor authentication token required", None
                    
                    # Verify TOTP or backup code
                    totp_valid = self.two_factor.verify_totp(user.two_factor_secret, totp_token)
                    backup_valid = False
                    
                    if not totp_valid:
                        backup_valid, new_backup_codes = self.two_factor.verify_backup_code(
                            user.backup_codes, totp_token
                        )
                        if backup_valid:
                            user.backup_codes = new_backup_codes
                            self._save_user(user)
                    
                    if not totp_valid and not backup_valid:
                        user.login_attempts += 1
                        user.last_attempt = datetime.now()
                        self._save_user(user)
                        self._log_audit_event(user.id, "login_failed", "authentication", 
                                            {"reason": "invalid_2fa_token"}, success=False)
                        return False, "Invalid two-factor authentication token", None
                
                # Successful login
                user.login_attempts = 0
                user.last_login = datetime.now()
                user.last_attempt = None
                self._save_user(user)
                
                # Create session
                session = self._create_session(user.id, ip_address, user_agent)
                
                # Cleanup old sessions if user has too many
                self._cleanup_user_sessions(user.id)
                
                self._log_audit_event(user.id, "login_success", "authentication", 
                                    {"session_id": session.id, "ip_address": ip_address})
                
                if self.logger:
                    self.logger.info(f"User authenticated: {username} ({user.id})")
                
                return True, "Authentication successful", session
                
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Authentication failed: {e}")
                return False, f"Authentication failed: {str(e)}", None
    
    def logout(self, session_id: str) -> tuple[bool, str]:
        """Logout user and invalidate session"""
        with self.lock:
            try:
                session = self.sessions.get(session_id)
                if not session:
                    return False, "Session not found"
                
                # Invalidate session
                session.status = SessionStatus.TERMINATED
                self._save_session(session)
                
                self._log_audit_event(session.user_id, "logout", "authentication", 
                                    {"session_id": session_id})
                
                if self.logger:
                    self.logger.info(f"User logged out: session {session_id}")
                
                return True, "Logged out successfully"
                
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Logout failed: {e}")
                return False, f"Logout failed: {str(e)}"
    
    def change_password(self, user_id: str, old_password: str, 
                       new_password: str) -> tuple[bool, str]:
        """Change user password"""
        with self.lock:
            try:
                user = self.users.get(user_id)
                if not user:
                    return False, "User not found"
                
                # Verify old password
                if not self._verify_password(old_password, user.password_hash):
                    self._log_audit_event(user_id, "password_change_failed", "user", 
                                        {"reason": "invalid_old_password"}, success=False)
                    return False, "Current password is incorrect"
                
                # Validate new password
                valid, errors = self.password_policy.validate(new_password, user.username, user.email)
                if not valid:
                    return False, "; ".join(errors)
                
                # Check password history
                new_hash = self._hash_password(new_password)
                if new_hash in self.password_history[user_id]:
                    return False, "Cannot reuse a previous password"
                
                # Update password
                user.password_hash = new_hash
                user.updated_at = datetime.now()
                
                # Set new expiration
                if self.password_policy.password_expiry_days > 0:
                    user.password_expires = datetime.now() + timedelta(days=self.password_policy.password_expiry_days)
                
                self._save_user(user)
                
                # Update password history
                self.password_history[user_id].append(new_hash)
                if len(self.password_history[user_id]) > self.password_policy.password_history_count:
                    self.password_history[user_id].pop(0)
                
                # Invalidate all sessions except current one
                self._invalidate_user_sessions(user_id)
                
                self._log_audit_event(user_id, "password_changed", "user")
                
                if self.logger:
                    self.logger.info(f"Password changed for user: {user.username}")
                
                return True, "Password changed successfully"
                
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Password change failed: {e}")
                return False, f"Password change failed: {str(e)}"
    
    def enable_two_factor(self, user_id: str) -> tuple[bool, str, Optional[Dict[str, Any]]]:
        """Enable two-factor authentication"""
        with self.lock:
            try:
                user = self.users.get(user_id)
                if not user:
                    return False, "User not found", None
                
                if user.two_factor_enabled:
                    return False, "Two-factor authentication is already enabled", None
                
                # Generate secret and backup codes
                secret = self.two_factor.generate_secret()
                backup_codes = self.two_factor.generate_backup_codes()
                
                user.two_factor_secret = secret
                user.backup_codes = backup_codes
                user.two_factor_enabled = True
                user.updated_at = datetime.now()
                
                self._save_user(user)
                
                self._log_audit_event(user_id, "2fa_enabled", "user")
                
                # Return setup information
                setup_info = {
                    'secret': secret,
                    'backup_codes': backup_codes,
                    'qr_code_url': f"otpauth://totp/{user.email}?secret={secret}&issuer=BLRCS"
                }
                
                return True, "Two-factor authentication enabled", setup_info
                
            except Exception as e:
                if self.logger:
                    self.logger.error(f"2FA enable failed: {e}")
                return False, f"Failed to enable 2FA: {str(e)}", None
    
    def validate_session(self, session_id: str) -> tuple[bool, Optional[User], Optional[Session]]:
        """Validate user session"""
        with self.lock:
            try:
                session = self.sessions.get(session_id)
                if not session:
                    return False, None, None
                
                if not session.is_valid():
                    if session.is_expired():
                        session.status = SessionStatus.EXPIRED
                        self._save_session(session)
                    return False, None, session
                
                # Get user
                user = self.users.get(session.user_id)
                if not user or not user.is_active():
                    session.status = SessionStatus.REVOKED
                    self._save_session(session)
                    return False, user, session
                
                # Refresh session activity
                session.refresh()
                self._save_session(session)
                
                return True, user, session
                
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Session validation failed: {e}")
                return False, None, None
    
    # Helper methods
    def _user_exists(self, username: str, email: str) -> bool:
        """Check if user exists"""
        for user in self.users.values():
            if user.username.lower() == username.lower() or user.email.lower() == email.lower():
                return True
        return False
    
    def _find_user_by_username(self, username: str) -> Optional[User]:
        """Find user by username or email"""
        for user in self.users.values():
            if user.username.lower() == username.lower() or user.email.lower() == username.lower():
                return user
        return None
    
    def _hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def _verify_password(self, password: str, hash_str: str) -> bool:
        """Verify password against hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hash_str.encode('utf-8'))
        except Exception:
            return False
    
    def _create_session(self, user_id: str, ip_address: str = "", user_agent: str = "") -> Session:
        """Create new user session"""
        session_id = secrets.token_urlsafe(32)
        session = Session(
            id=session_id,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=datetime.now() + self.session_timeout
        )
        
        self.sessions[session_id] = session
        self._save_session(session)
        
        return session
    
    def _check_rate_limit(self, identifier: str) -> bool:
        """Check rate limiting"""
        now = time.time()
        attempts = self.rate_limiter[identifier]
        
        # Remove old attempts
        while attempts and attempts[0] < now - self.rate_limit_window:
            attempts.popleft()
        
        # Check if under limit
        if len(attempts) >= self.rate_limit_max_attempts:
            return False
        
        # Add current attempt
        attempts.append(now)
        return True
    
    def _cleanup_expired_sessions(self):
        """Remove expired sessions"""
        expired_sessions = []
        for session_id, session in self.sessions.items():
            if session.is_expired():
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del self.sessions[session_id]
            if self.database:
                self.database.delete('sessions', {'id': session_id})
    
    def _cleanup_user_sessions(self, user_id: str):
        """Cleanup old sessions for user"""
        user_sessions = [(s.last_activity, s.id) for s in self.sessions.values() 
                        if s.user_id == user_id and s.is_valid()]
        
        if len(user_sessions) > self.max_sessions_per_user:
            # Sort by last activity and remove oldest
            user_sessions.sort()
            sessions_to_remove = user_sessions[:-self.max_sessions_per_user]
            
            for _, session_id in sessions_to_remove:
                session = self.sessions[session_id]
                session.status = SessionStatus.TERMINATED
                self._save_session(session)
    
    def _invalidate_user_sessions(self, user_id: str, except_session: str = ""):
        """Invalidate all user sessions except specified one"""
        for session in self.sessions.values():
            if session.user_id == user_id and session.id != except_session:
                session.status = SessionStatus.REVOKED
                self._save_session(session)
    
    def _save_user(self, user: User):
        """Save user to database"""
        if self.database:
            user_data = user.to_dict(include_sensitive=True)
            if self.database.select('users', {'id': user.id}):
                self.database.update('users', user_data, {'id': user.id})
            else:
                self.database.insert('users', user_data)
    
    def _save_session(self, session: Session):
        """Save session to database"""
        if self.database:
            session_data = session.to_dict()
            if self.database.select('sessions', {'id': session.id}):
                self.database.update('sessions', session_data, {'id': session.id})
            else:
                self.database.insert('sessions', session_data)
    
    def _log_audit_event(self, user_id: str, action: str, resource: str = "",
                        details: Dict[str, Any] = None, success: bool = True):
        """Log audit event"""
        event = AuditEvent(user_id, action, resource, details, success=success)
        self.audit_events.append(event)
        
        if self.database:
            self.database.insert('audit_events', event.to_dict())
        
        if self.logger:
            level = "info" if success else "warning"
            getattr(self.logger, level)(f"Audit: {action} - {resource} - User: {user_id}")

# Factory function
def create_user_manager(database=None, logger=None) -> UserManager:
    """Create user manager instance"""
    return UserManager(database, logger)

# Export main classes
__all__ = [
    'UserRole', 'UserStatus', 'User', 'Session', 'UserManager',
    'PasswordPolicy', 'TwoFactorAuth', 'AuditEvent',
    'create_user_manager'
]