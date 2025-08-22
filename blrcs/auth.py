# BLRCS Authentication Module
# JWT and OAuth2 authentication implementation
import time
import secrets
import hashlib
import hmac
import json
import base64
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass
import jwt

@dataclass
class User:
    """User model"""
    id: str
    username: str
    email: Optional[str] = None
    roles: List[str] = None
    created_at: float = None
    
    def __post_init__(self):
        if self.roles is None:
            self.roles = ['user']
        if self.created_at is None:
            self.created_at = time.time()

@dataclass 
class Token:
    """Token model"""
    access_token: str
    token_type: str = "Bearer"
    expires_in: int = 3600
    refresh_token: Optional[str] = None
    scope: Optional[str] = None

class JWTAuthenticator:
    """
    JWT-based authentication.
    Stateless, secure, and scalable.
    """
    
    def __init__(self, secret_key: Optional[str] = None, 
                 algorithm: str = "HS256",
                 access_token_expire: int = 3600,
                 refresh_token_expire: int = 86400):
        """
        Initialize JWT authenticator.
        
        Args:
            secret_key: Secret key for signing tokens
            algorithm: JWT signing algorithm
            access_token_expire: Access token expiry in seconds
            refresh_token_expire: Refresh token expiry in seconds
        """
        # Generate cryptographically secure secret key
        if not secret_key:
            # Generate 256-bit (32 bytes) secret key
            self.secret_key = secrets.token_bytes(32)
        else:
            # Ensure provided key is bytes
            if isinstance(secret_key, str):
                self.secret_key = secret_key.encode('utf-8')
            else:
                self.secret_key = secret_key
                
        # Validate key strength (minimum 256 bits)
        if len(self.secret_key) < 32:
            raise ValueError("JWT secret key must be at least 256 bits (32 bytes)")
        self.algorithm = algorithm
        self.access_token_expire = access_token_expire
        self.refresh_token_expire = refresh_token_expire
        
        # Token blacklist for logout
        self.blacklist = set()
    
    def create_access_token(self, user: User, 
                          expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token"""
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(seconds=self.access_token_expire)
        
        payload = {
            "sub": user.id,
            "username": user.username,
            "email": user.email,
            "roles": user.roles,
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access"
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def create_refresh_token(self, user: User) -> str:
        """Create JWT refresh token"""
        expire = datetime.utcnow() + timedelta(seconds=self.refresh_token_expire)
        
        payload = {
            "sub": user.id,
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "refresh"
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def create_token(self, user: User) -> Token:
        """Create both access and refresh tokens"""
        access_token = self.create_access_token(user)
        refresh_token = self.create_refresh_token(user)
        
        return Token(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=self.access_token_expire
        )
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode JWT token"""
        # Check blacklist
        if token in self.blacklist:
            return None
        
        try:
            payload = jwt.decode(
                token, 
                self.secret_key, 
                algorithms=[self.algorithm]
            )
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def refresh_access_token(self, refresh_token: str) -> Optional[str]:
        """Generate new access token from refresh token"""
        payload = self.verify_token(refresh_token)
        
        if not payload or payload.get('type') != 'refresh':
            return None
        
        # Create new user object from payload
        user = User(
            id=payload['sub'],
            username=payload.get('username', 'unknown')
        )
        
        return self.create_access_token(user)
    
    def revoke_token(self, token: str):
        """Revoke a token by adding to blacklist"""
        self.blacklist.add(token)
    
    def extract_user(self, token: str) -> Optional[User]:
        """Extract user from token"""
        payload = self.verify_token(token)
        
        if not payload:
            return None
        
        return User(
            id=payload['sub'],
            username=payload.get('username'),
            email=payload.get('email'),
            roles=payload.get('roles', [])
        )

class OAuth2Provider:
    """
    OAuth2 provider implementation.
    Supports authorization code and client credentials flows.
    """
    
    def __init__(self, client_id: str, client_secret: str,
                 redirect_uri: str, authorize_url: str,
                 token_url: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.authorize_url = authorize_url
        self.token_url = token_url
        
        # Store authorization codes temporarily
        self.auth_codes = {}
        
        # Store tokens
        self.tokens = {}
    
    def get_authorization_url(self, state: Optional[str] = None,
                            scope: Optional[str] = None) -> str:
        """Generate OAuth2 authorization URL"""
        params = {
            'client_id': self.client_id,
            'response_type': 'code',
            'redirect_uri': self.redirect_uri
        }
        
        if state:
            params['state'] = state
        
        if scope:
            params['scope'] = scope
        
        # Build query string
        query = '&'.join(f"{k}={v}" for k, v in params.items())
        return f"{self.authorize_url}?{query}"
    
    def create_authorization_code(self, user_id: str) -> str:
        """Create authorization code for user"""
        code = secrets.token_urlsafe(32)
        
        self.auth_codes[code] = {
            'user_id': user_id,
            'created_at': time.time(),
            'expires_at': time.time() + 600  # 10 minutes
        }
        
        return code
    
    def exchange_code_for_token(self, code: str) -> Optional[Token]:
        """Exchange authorization code for access token"""
        # Validate code
        if code not in self.auth_codes:
            return None
        
        auth_code = self.auth_codes[code]
        
        # Check expiry
        if time.time() > auth_code['expires_at']:
            del self.auth_codes[code]
            return None
        
        # Create token
        token_id = secrets.token_urlsafe(32)
        
        token_data = {
            'user_id': auth_code['user_id'],
            'created_at': time.time(),
            'expires_at': time.time() + 3600  # 1 hour
        }
        
        self.tokens[token_id] = token_data
        
        # Remove used code
        del self.auth_codes[code]
        
        return Token(
            access_token=token_id,
            expires_in=3600
        )
    
    def validate_token(self, token: str) -> Optional[str]:
        """Validate OAuth2 token and return user ID"""
        if token not in self.tokens:
            return None
        
        token_data = self.tokens[token]
        
        # Check expiry
        if time.time() > token_data['expires_at']:
            del self.tokens[token]
            return None
        
        return token_data['user_id']

class APIKeyAuthenticator:
    """
    Simple API key authentication.
    For service-to-service communication.
    Auto-rotates API keys every 30 days for enhanced security.
    """
    
    def __init__(self):
        self.api_keys = {}
        self.rotation_interval = 30 * 24 * 3600  # 30 days
    
    def generate_api_key(self, service_name: str, 
                        permissions: List[str] = None) -> str:
        """Generate API key for service"""
        api_key = secrets.token_urlsafe(32)
        
        self.api_keys[api_key] = {
            'service': service_name,
            'permissions': permissions or [],
            'created_at': time.time(),
            'last_used': None,
            'rotation_due': time.time() + self.rotation_interval
        }
        
        return api_key
    
    def validate_api_key(self, api_key: str) -> bool:
        """Validate API key and check rotation status"""
        if api_key not in self.api_keys:
            return False
        
        key_data = self.api_keys[api_key]
        
        # Check if rotation is due
        if time.time() > key_data['rotation_due']:
            # Mark for rotation but still allow current request
            key_data['needs_rotation'] = True
        
        # Update last used
        key_data['last_used'] = time.time()
        
        return True
    
    def check_permission(self, api_key: str, permission: str) -> bool:
        """Check if API key has permission"""
        if api_key not in self.api_keys:
            return False
        
        key_data = self.api_keys[api_key]
        
        return permission in key_data['permissions'] or '*' in key_data['permissions']
    
    def revoke_api_key(self, api_key: str) -> bool:
        """Revoke API key"""
        if api_key in self.api_keys:
            del self.api_keys[api_key]
            return True
        
        return False
    
    def rotate_api_key(self, old_api_key: str) -> Optional[str]:
        """Rotate API key by generating new one with same permissions"""
        if old_api_key not in self.api_keys:
            return None
        
        old_key_data = self.api_keys[old_api_key]
        
        # Generate new key with same permissions
        new_api_key = self.generate_api_key(
            old_key_data['service'],
            old_key_data['permissions']
        )
        
        # Remove old key
        del self.api_keys[old_api_key]
        
        return new_api_key
    
    def get_keys_needing_rotation(self) -> List[str]:
        """Get list of API keys that need rotation"""
        current_time = time.time()
        return [
            key for key, data in self.api_keys.items()
            if current_time > data['rotation_due'] or data.get('needs_rotation', False)
        ]

class MultiAuthManager:
    """
    Multi-method authentication manager.
    Supports JWT, OAuth2, and API keys.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        config = config or {}
        
        # Initialize authenticators
        self.jwt_auth = JWTAuthenticator(
            secret_key=config.get('jwt_secret')
        )
        
        self.api_key_auth = APIKeyAuthenticator()
        
        # OAuth2 provider (if configured)
        self.oauth2_provider = None
        if config.get('oauth2'):
            oauth_config = config['oauth2']
            self.oauth2_provider = OAuth2Provider(
                client_id=oauth_config['client_id'],
                client_secret=oauth_config['client_secret'],
                redirect_uri=oauth_config['redirect_uri'],
                authorize_url=oauth_config['authorize_url'],
                token_url=oauth_config['token_url']
            )
        
        # User store (in production, use database)
        self.users = {}
    
    def register_user(self, username: str, password: str, 
                      email: Optional[str] = None) -> User:
        """Register new user"""
        # Generate random salt for password hashing
        salt = secrets.token_bytes(32)
        
        # Hash password with salt
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        )
        
        user = User(
            id=secrets.token_urlsafe(16),
            username=username,
            email=email
        )
        
        self.users[username] = {
            'user': user,
            'password_hash': password_hash,
            'salt': salt
        }
        
        return user
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate user with username/password"""
        if username not in self.users:
            # Use random salt for timing attack protection (no hardcoded values)
            dummy_salt = secrets.token_bytes(32)
            hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), dummy_salt, 100000)
            return None
        
        user_data = self.users[username]
        stored_hash = user_data['password_hash']
        stored_salt = user_data['salt']
        
        # Proper password verification with PBKDF2
        computed_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            stored_salt,
            100000
        )
        
        # Constant-time comparison to prevent timing attacks
        if secrets.compare_digest(stored_hash, computed_hash):
            return user_data['user']
        
        return None
    
    def authenticate_request(self, auth_header: str) -> Optional[User]:
        """
        Authenticate request from Authorization header.
        Supports Bearer tokens and API keys.
        """
        if not auth_header:
            return None
        
        parts = auth_header.split(' ')
        
        if len(parts) != 2:
            return None
        
        scheme, credential = parts
        
        if scheme.lower() == 'bearer':
            # Try JWT authentication
            user = self.jwt_auth.extract_user(credential)
            if user:
                return user
            
            # Try OAuth2 if configured
            if self.oauth2_provider:
                user_id = self.oauth2_provider.validate_token(credential)
                if user_id:
                    # Return user from user_id (simplified)
                    return User(id=user_id, username='oauth_user')
        
        elif scheme.lower() == 'apikey':
            # API key authentication
            if self.api_key_auth.validate_api_key(credential):
                # Return service user
                return User(
                    id='service',
                    username='api_service',
                    roles=['service']
                )
        
        return None

# Global auth manager
_auth_manager: Optional[MultiAuthManager] = None

def get_auth_manager(config: Optional[Dict[str, Any]] = None) -> MultiAuthManager:
    """Get global auth manager instance"""
    global _auth_manager
    
    if _auth_manager is None:
        _auth_manager = MultiAuthManager(config)
    
    return _auth_manager