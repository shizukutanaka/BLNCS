"""
Enterprise Authentication System for BLNCS
JWT-based authentication with role-based access control (RBAC) and session management.
"""

import jwt
import bcrypt
import secrets
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Union, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
import json
import asyncio
from pathlib import Path

from ..structured_logging import get_structured_logger, LogCategory
from ..async_database import get_async_db_manager
from ..error_handler import get_error_handler, ErrorContext
from ..exceptions import SecurityError, ValidationError


class UserRole(Enum):
    """User roles for RBAC"""
    ADMIN = "admin"
    OPERATOR = "operator" 
    VIEWER = "viewer"
    AUDITOR = "auditor"
    
    def __lt__(self, other):
        """Role hierarchy for privilege comparison"""
        if not isinstance(other, UserRole):
            return NotImplemented
        
        hierarchy = {
            UserRole.VIEWER: 0,
            UserRole.AUDITOR: 1,
            UserRole.OPERATOR: 2,
            UserRole.ADMIN: 3
        }
        return hierarchy[self] < hierarchy[other]


class Permission(Enum):
    """System permissions"""
    # Lightning Network operations
    VIEW_NODE_INFO = "lightning:view_node_info"
    MANAGE_CHANNELS = "lightning:manage_channels"
    SEND_PAYMENTS = "lightning:send_payments"
    CREATE_INVOICES = "lightning:create_invoices"
    VIEW_PAYMENTS = "lightning:view_payments"
    
    # System operations
    VIEW_SYSTEM_INFO = "system:view_info"
    MANAGE_SYSTEM_CONFIG = "system:manage_config"
    VIEW_LOGS = "system:view_logs"
    MANAGE_BACKUPS = "system:manage_backups"
    
    # Security operations
    MANAGE_USERS = "security:manage_users"
    VIEW_AUDIT_LOGS = "security:view_audit_logs"
    MANAGE_SECURITY_CONFIG = "security:manage_config"
    
    # Database operations
    VIEW_DATABASE = "database:view"
    MANAGE_DATABASE = "database:manage"


@dataclass
class UserProfile:
    """User profile with authentication and authorization data"""
    user_id: str
    username: str
    email: Optional[str] = None
    role: UserRole = UserRole.VIEWER
    permissions: Set[Permission] = field(default_factory=set)
    created_at: datetime = field(default_factory=datetime.now)
    last_login: Optional[datetime] = None
    password_hash: Optional[str] = None
    failed_login_attempts: int = 0
    locked_until: Optional[datetime] = None
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None
    api_key_hash: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = {
            'user_id': self.user_id,
            'username': self.username,
            'email': self.email,
            'role': self.role.value,
            'permissions': [p.value for p in self.permissions],
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'failed_login_attempts': self.failed_login_attempts,
            'locked_until': self.locked_until.isoformat() if self.locked_until else None,
            'mfa_enabled': self.mfa_enabled,
            'metadata': self.metadata
        }
        
        if include_sensitive:
            data.update({
                'password_hash': self.password_hash,
                'mfa_secret': self.mfa_secret,
                'api_key_hash': self.api_key_hash
            })
        
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UserProfile':
        """Create from dictionary"""
        permissions = {Permission(p) for p in data.get('permissions', [])}
        
        return cls(
            user_id=data['user_id'],
            username=data['username'],
            email=data.get('email'),
            role=UserRole(data['role']),
            permissions=permissions,
            created_at=datetime.fromisoformat(data['created_at']),
            last_login=datetime.fromisoformat(data['last_login']) if data.get('last_login') else None,
            password_hash=data.get('password_hash'),
            failed_login_attempts=data.get('failed_login_attempts', 0),
            locked_until=datetime.fromisoformat(data['locked_until']) if data.get('locked_until') else None,
            mfa_enabled=data.get('mfa_enabled', False),
            mfa_secret=data.get('mfa_secret'),
            api_key_hash=data.get('api_key_hash'),
            metadata=data.get('metadata', {})
        )


@dataclass
class AuthSession:
    """Authentication session"""
    session_id: str
    user_id: str
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    last_activity: datetime = field(default_factory=datetime.now)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    is_active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthToken:
    """JWT token data"""
    access_token: str
    refresh_token: Optional[str] = None
    expires_in: int = 3600  # 1 hour
    token_type: str = "Bearer"
    scope: Optional[str] = None


class AuthenticationManager:
    """Enterprise authentication and session management"""
    
    def __init__(self, 
                 secret_key: Optional[str] = None,
                 token_expiry: int = 3600,
                 refresh_token_expiry: int = 604800,  # 7 days
                 max_failed_attempts: int = 5,
                 lockout_duration: int = 900):  # 15 minutes
        
        self.secret_key = secret_key or secrets.token_urlsafe(64)
        self.token_expiry = token_expiry
        self.refresh_token_expiry = refresh_token_expiry
        self.max_failed_attempts = max_failed_attempts
        self.lockout_duration = lockout_duration
        
        self.logger = get_structured_logger(__name__)
        self.error_handler = get_error_handler()
        
        # Active sessions
        self.active_sessions: Dict[str, AuthSession] = {}
        
        # Database manager
        self.db_manager = None
        
        # Role-permission mapping
        self.role_permissions = {
            UserRole.VIEWER: {
                Permission.VIEW_NODE_INFO,
                Permission.VIEW_PAYMENTS,
                Permission.VIEW_SYSTEM_INFO,
                Permission.VIEW_LOGS,
                Permission.VIEW_DATABASE
            },
            UserRole.AUDITOR: {
                Permission.VIEW_NODE_INFO,
                Permission.VIEW_PAYMENTS,
                Permission.VIEW_SYSTEM_INFO,
                Permission.VIEW_LOGS,
                Permission.VIEW_DATABASE,
                Permission.VIEW_AUDIT_LOGS
            },
            UserRole.OPERATOR: {
                Permission.VIEW_NODE_INFO,
                Permission.MANAGE_CHANNELS,
                Permission.SEND_PAYMENTS,
                Permission.CREATE_INVOICES,
                Permission.VIEW_PAYMENTS,
                Permission.VIEW_SYSTEM_INFO,
                Permission.MANAGE_BACKUPS,
                Permission.VIEW_LOGS,
                Permission.VIEW_DATABASE
            },
            UserRole.ADMIN: set(Permission)  # All permissions
        }
    
    async def initialize(self):
        """Initialize authentication system"""
        try:
            self.db_manager = await get_async_db_manager()
            
            # Create authentication tables
            await self._create_tables()
            
            # Create default admin user if none exists
            await self._create_default_admin()
            
            self.logger.info(
                "Authentication system initialized",
                category=LogCategory.SECURITY,
                data={"token_expiry": self.token_expiry}
            )
            
        except Exception as e:
            self.error_handler.handle_error(
                e,
                ErrorContext(
                    component="authentication",
                    operation="initialize",
                    severity="critical"
                )
            )
            raise
    
    async def _create_tables(self):
        """Create authentication database tables"""
        tables = [
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE,
                role TEXT NOT NULL DEFAULT 'viewer',
                password_hash TEXT,
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until DATETIME,
                mfa_enabled BOOLEAN DEFAULT FALSE,
                mfa_secret TEXT,
                api_key_hash TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME,
                metadata TEXT DEFAULT '{}'
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS user_permissions (
                user_id TEXT NOT NULL,
                permission TEXT NOT NULL,
                granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                granted_by TEXT,
                PRIMARY KEY (user_id, permission),
                FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS auth_sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME,
                last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                user_agent TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                metadata TEXT DEFAULT '{}',
                FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS auth_tokens (
                token_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                token_type TEXT DEFAULT 'refresh',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                revoked_at DATETIME,
                last_used DATETIME,
                metadata TEXT DEFAULT '{}',
                FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
            )
            """,
            
            # Indexes for performance
            "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)",
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON auth_sessions(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON auth_sessions(expires_at)",
            "CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON auth_tokens(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON auth_tokens(expires_at)"
        ]
        
        for table_sql in tables:
            await self.db_manager.execute(table_sql, fetch_results=False)
    
    async def _create_default_admin(self):
        """Create default admin user if none exists"""
        try:
            # Check if any admin users exist
            result = await self.db_manager.fetch_one(
                "SELECT COUNT(*) as count FROM users WHERE role = 'admin'"
            )
            
            if result and result['count'] == 0:
                # Create default admin
                admin_password = secrets.token_urlsafe(16)
                
                await self.create_user(
                    username="admin",
                    password=admin_password,
                    email="admin@blncs.local",
                    role=UserRole.ADMIN
                )
                
                self.logger.info(
                    "Default admin user created",
                    category=LogCategory.SECURITY,
                    data={
                        "username": "admin",
                        "temporary_password": admin_password
                    }
                )
                
                # Save credentials to file
                creds_file = Path("admin_credentials.txt")
                creds_file.write_text(
                    f"Default Admin Credentials\n"
                    f"Username: admin\n"
                    f"Password: {admin_password}\n"
                    f"Please change this password immediately!\n"
                )
                
        except Exception as e:
            self.logger.warning(f"Failed to create default admin: {e}")
    
    def _hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def _verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except Exception:
            return False
    
    def _generate_token(self, user_id: str, permissions: List[str], token_type: str = "access") -> str:
        """Generate JWT token"""
        now = datetime.now()
        
        if token_type == "access":
            expires_at = now + timedelta(seconds=self.token_expiry)
        else:
            expires_at = now + timedelta(seconds=self.refresh_token_expiry)
        
        payload = {
            'user_id': user_id,
            'permissions': permissions,
            'token_type': token_type,
            'iat': int(now.timestamp()),
            'exp': int(expires_at.timestamp()),
            'iss': 'blncs-auth'
        }
        
        return jwt.encode(payload, self.secret_key, algorithm='HS256')
    
    def _verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            
            # Check expiration
            if datetime.now().timestamp() > payload.get('exp', 0):
                return None
            
            return payload
            
        except jwt.InvalidTokenError:
            return None
    
    async def create_user(
        self,
        username: str,
        password: str,
        email: Optional[str] = None,
        role: UserRole = UserRole.VIEWER,
        permissions: Optional[Set[Permission]] = None
    ) -> UserProfile:
        """Create new user"""
        
        # Validate input
        if not username or len(username) < 3:
            raise ValidationError("Username must be at least 3 characters")
        
        if not password or len(password) < 8:
            raise ValidationError("Password must be at least 8 characters")
        
        # Check if user exists
        existing_user = await self.db_manager.fetch_one(
            "SELECT user_id FROM users WHERE username = ? OR email = ?",
            (username, email)
        )
        
        if existing_user:
            raise SecurityError("User already exists")
        
        # Create user profile
        user_id = secrets.token_urlsafe(16)
        password_hash = self._hash_password(password)
        
        # Set default permissions based on role
        if permissions is None:
            permissions = self.role_permissions.get(role, set())
        
        user_profile = UserProfile(
            user_id=user_id,
            username=username,
            email=email,
            role=role,
            permissions=permissions,
            password_hash=password_hash
        )
        
        # Store in database
        await self.db_manager.insert('users', {
            'user_id': user_id,
            'username': username,
            'email': email,
            'role': role.value,
            'password_hash': password_hash,
            'created_at': user_profile.created_at.isoformat(),
            'metadata': json.dumps(user_profile.metadata)
        })
        
        # Store permissions
        for permission in permissions:
            await self.db_manager.insert('user_permissions', {
                'user_id': user_id,
                'permission': permission.value,
                'granted_by': 'system'
            })
        
        self.logger.audit(
            "User created",
            data={
                'user_id': user_id,
                'username': username,
                'role': role.value,
                'permissions_count': len(permissions)
            }
        )
        
        return user_profile
    
    async def authenticate(
        self,
        username: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Optional[AuthToken]:
        """Authenticate user and create session"""
        
        try:
            # Get user
            user_data = await self.db_manager.fetch_one(
                """
                SELECT u.*, 
                       GROUP_CONCAT(up.permission) as permissions
                FROM users u
                LEFT JOIN user_permissions up ON u.user_id = up.user_id
                WHERE u.username = ?
                GROUP BY u.user_id
                """,
                (username,)
            )
            
            if not user_data:
                self.logger.warning(
                    "Authentication failed: User not found",
                    category=LogCategory.SECURITY,
                    data={'username': username, 'ip_address': ip_address}
                )
                return None
            
            # Check if account is locked
            if user_data['locked_until']:
                locked_until = datetime.fromisoformat(user_data['locked_until'])
                if datetime.now() < locked_until:
                    self.logger.warning(
                        "Authentication failed: Account locked",
                        category=LogCategory.SECURITY,
                        data={'username': username, 'locked_until': locked_until.isoformat()}
                    )
                    return None
            
            # Verify password
            if not self._verify_password(password, user_data['password_hash']):
                # Increment failed attempts
                failed_attempts = user_data['failed_login_attempts'] + 1
                
                # Lock account if max attempts reached
                locked_until = None
                if failed_attempts >= self.max_failed_attempts:
                    locked_until = datetime.now() + timedelta(seconds=self.lockout_duration)
                
                await self.db_manager.update(
                    'users',
                    {
                        'failed_login_attempts': failed_attempts,
                        'locked_until': locked_until.isoformat() if locked_until else None
                    },
                    'user_id = ?',
                    (user_data['user_id'],)
                )
                
                self.logger.warning(
                    "Authentication failed: Invalid password",
                    category=LogCategory.SECURITY,
                    data={
                        'username': username,
                        'failed_attempts': failed_attempts,
                        'ip_address': ip_address
                    }
                )
                return None
            
            # Reset failed attempts on successful login
            await self.db_manager.update(
                'users',
                {
                    'failed_login_attempts': 0,
                    'locked_until': None,
                    'last_login': datetime.now().isoformat()
                },
                'user_id = ?',
                (user_data['user_id'],)
            )
            
            # Get permissions
            permissions = []
            if user_data['permissions']:
                permissions = user_data['permissions'].split(',')
            
            # Generate tokens
            access_token = self._generate_token(user_data['user_id'], permissions, 'access')
            refresh_token = self._generate_token(user_data['user_id'], permissions, 'refresh')
            
            # Create session
            session_id = secrets.token_urlsafe(32)
            session = AuthSession(
                session_id=session_id,
                user_id=user_data['user_id'],
                expires_at=datetime.now() + timedelta(seconds=self.token_expiry),
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            # Store session
            self.active_sessions[session_id] = session
            await self.db_manager.insert('auth_sessions', {
                'session_id': session_id,
                'user_id': user_data['user_id'],
                'expires_at': session.expires_at.isoformat(),
                'ip_address': ip_address,
                'user_agent': user_agent,
                'metadata': json.dumps(session.metadata)
            })
            
            # Store refresh token
            token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
            await self.db_manager.insert('auth_tokens', {
                'token_id': secrets.token_urlsafe(16),
                'user_id': user_data['user_id'],
                'token_hash': token_hash,
                'token_type': 'refresh',
                'expires_at': (datetime.now() + timedelta(seconds=self.refresh_token_expiry)).isoformat()
            })
            
            self.logger.audit(
                "User authenticated successfully",
                data={
                    'user_id': user_data['user_id'],
                    'username': username,
                    'session_id': session_id,
                    'ip_address': ip_address
                }
            )
            
            return AuthToken(
                access_token=access_token,
                refresh_token=refresh_token,
                expires_in=self.token_expiry
            )
            
        except Exception as e:
            self.error_handler.handle_error(
                e,
                ErrorContext(
                    component="authentication",
                    operation="authenticate",
                    metadata={'username': username}
                )
            )
            return None
    
    async def validate_token(self, token: str) -> Optional[UserProfile]:
        """Validate access token and return user profile"""
        
        payload = self._verify_token(token)
        if not payload:
            return None
        
        user_id = payload.get('user_id')
        if not user_id:
            return None
        
        # Get user from database
        user_data = await self.db_manager.fetch_one(
            """
            SELECT u.*, 
                   GROUP_CONCAT(up.permission) as permissions
            FROM users u
            LEFT JOIN user_permissions up ON u.user_id = up.user_id
            WHERE u.user_id = ?
            GROUP BY u.user_id
            """,
            (user_id,)
        )
        
        if not user_data:
            return None
        
        # Build user profile
        permissions = set()
        if user_data['permissions']:
            permissions = {Permission(p) for p in user_data['permissions'].split(',')}
        
        return UserProfile(
            user_id=user_data['user_id'],
            username=user_data['username'],
            email=user_data['email'],
            role=UserRole(user_data['role']),
            permissions=permissions,
            created_at=datetime.fromisoformat(user_data['created_at']),
            last_login=datetime.fromisoformat(user_data['last_login']) if user_data['last_login'] else None,
            mfa_enabled=bool(user_data['mfa_enabled']),
            metadata=json.loads(user_data['metadata'] or '{}')
        )
    
    async def refresh_token(self, refresh_token: str) -> Optional[AuthToken]:
        """Refresh access token using refresh token"""
        
        payload = self._verify_token(refresh_token)
        if not payload or payload.get('token_type') != 'refresh':
            return None
        
        user_id = payload.get('user_id')
        
        # Verify refresh token exists in database
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        token_record = await self.db_manager.fetch_one(
            """
            SELECT * FROM auth_tokens 
            WHERE user_id = ? AND token_hash = ? AND token_type = 'refresh' 
            AND revoked_at IS NULL AND expires_at > datetime('now')
            """,
            (user_id, token_hash)
        )
        
        if not token_record:
            return None
        
        # Update last used
        await self.db_manager.update(
            'auth_tokens',
            {'last_used': datetime.now().isoformat()},
            'token_id = ?',
            (token_record['token_id'],)
        )
        
        # Get user permissions
        permissions_data = await self.db_manager.fetch_all(
            "SELECT permission FROM user_permissions WHERE user_id = ?",
            (user_id,)
        )
        permissions = [p['permission'] for p in permissions_data]
        
        # Generate new access token
        access_token = self._generate_token(user_id, permissions, 'access')
        
        return AuthToken(
            access_token=access_token,
            expires_in=self.token_expiry
        )
    
    async def logout(self, session_id: str):
        """Logout user and invalidate session"""
        
        # Remove from active sessions
        if session_id in self.active_sessions:
            user_id = self.active_sessions[session_id].user_id
            del self.active_sessions[session_id]
            
            # Mark session as inactive in database
            await self.db_manager.update(
                'auth_sessions',
                {'is_active': False},
                'session_id = ?',
                (session_id,)
            )
            
            self.logger.audit(
                "User logged out",
                data={'session_id': session_id, 'user_id': user_id}
            )
    
    async def has_permission(self, user_id: str, permission: Permission) -> bool:
        """Check if user has specific permission"""
        
        result = await self.db_manager.fetch_one(
            "SELECT COUNT(*) as count FROM user_permissions WHERE user_id = ? AND permission = ?",
            (user_id, permission.value)
        )
        
        return result and result['count'] > 0
    
    async def cleanup_expired_sessions(self):
        """Clean up expired sessions and tokens"""
        
        now = datetime.now()
        
        # Remove expired sessions from memory
        expired_sessions = [
            sid for sid, session in self.active_sessions.items()
            if session.expires_at and session.expires_at < now
        ]
        
        for session_id in expired_sessions:
            del self.active_sessions[session_id]
        
        # Clean up database
        await self.db_manager.execute(
            "DELETE FROM auth_sessions WHERE expires_at < ?",
            (now.isoformat(),),
            fetch_results=False
        )
        
        await self.db_manager.execute(
            "DELETE FROM auth_tokens WHERE expires_at < ?",
            (now.isoformat(),),
            fetch_results=False
        )
        
        if expired_sessions:
            self.logger.info(
                f"Cleaned up {len(expired_sessions)} expired sessions",
                category=LogCategory.SECURITY
            )


# Global authentication manager
_global_auth_manager: Optional[AuthenticationManager] = None


async def get_auth_manager() -> AuthenticationManager:
    """Get global authentication manager"""
    global _global_auth_manager
    if _global_auth_manager is None:
        _global_auth_manager = AuthenticationManager()
        await _global_auth_manager.initialize()
    return _global_auth_manager


__all__ = [
    'UserRole',
    'Permission',
    'UserProfile',
    'AuthSession',
    'AuthToken',
    'AuthenticationManager',
    'get_auth_manager'
]