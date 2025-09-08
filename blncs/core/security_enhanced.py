"""
Enhanced Security System for BLNCS
Comprehensive security features including encryption, credential management,
security monitoring, threat detection, and audit logging.
"""

import os
import secrets
import hashlib
import hmac
import base64
import json
import time
import threading
from typing import Dict, Any, List, Optional, Union, Callable
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
from contextlib import contextmanager
from functools import wraps

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

from .logger import get_logger
from .config_manager import get_config_manager
from .fast_cache import get_fast_cache
from .enhanced_validator import get_enhanced_validator


class SecurityLevel(Enum):
    """Security levels for operations"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ThreatType(Enum):
    """Types of security threats"""
    BRUTE_FORCE = "brute_force"
    INJECTION = "injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    UNAUTHORIZED_ACCESS = "unauthorized_access"


@dataclass
class SecurityEvent:
    """Security event record"""
    timestamp: datetime
    event_type: str
    severity: SecurityLevel
    threat_type: Optional[ThreatType]
    source_ip: Optional[str] = None
    user_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    blocked: bool = False
    resolved: bool = False


@dataclass
class Credential:
    """Secure credential storage"""
    name: str
    encrypted_value: bytes
    created_at: datetime
    last_used: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class SecureKeyManager:
    """Secure key and credential management"""
    
    def __init__(self, master_key: Optional[bytes] = None):
        self.logger = get_logger(__name__)
        
        if not CRYPTO_AVAILABLE:
            self.logger.warning("Cryptography library not available. Encryption features disabled.")
            self.encryption_enabled = False
            return
        
        self.encryption_enabled = True
        
        # Key management
        self.key_file = Path('./security/.master_key')
        self.credentials_file = Path('./security/credentials.enc')
        
        # Ensure security directory exists with proper permissions
        security_dir = Path('./security')
        security_dir.mkdir(mode=0o700, exist_ok=True)
        
        # Initialize encryption key
        if master_key:
            self.master_key = master_key
        else:
            self.master_key = self._load_or_create_master_key()
        
        # Initialize cipher
        self.cipher = Fernet(self.master_key)
        
        # Credential storage
        self.credentials: Dict[str, Credential] = {}
        self._load_credentials()
        
        # Lock for thread safety
        self._lock = threading.RLock()
    
    def _derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def _load_or_create_master_key(self) -> bytes:
        """Load existing master key or create new one"""
        if self.key_file.exists():
            try:
                with open(self.key_file, 'rb') as f:
                    return f.read()
            except Exception as e:
                self.logger.error(f"Failed to load master key: {e}")
        
        # Generate new key
        key = Fernet.generate_key()
        try:
            with open(self.key_file, 'wb') as f:
                f.write(key)
            os.chmod(self.key_file, 0o600)  # Owner read/write only
            self.logger.info("Generated new master encryption key")
        except Exception as e:
            self.logger.error(f"Failed to save master key: {e}")
        
        return key
    
    def _load_credentials(self):
        """Load encrypted credentials from file"""
        if not self.credentials_file.exists():
            return
        
        try:
            with open(self.credentials_file, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.cipher.decrypt(encrypted_data)
            creds_data = json.loads(decrypted_data.decode())
            
            for name, cred_dict in creds_data.items():
                self.credentials[name] = Credential(
                    name=cred_dict['name'],
                    encrypted_value=base64.b64decode(cred_dict['encrypted_value']),
                    created_at=datetime.fromisoformat(cred_dict['created_at']),
                    last_used=datetime.fromisoformat(cred_dict['last_used']) if cred_dict.get('last_used') else None,
                    expires_at=datetime.fromisoformat(cred_dict['expires_at']) if cred_dict.get('expires_at') else None,
                    metadata=cred_dict.get('metadata', {})
                )
            
            self.logger.info(f"Loaded {len(self.credentials)} credentials")
            
        except Exception as e:
            self.logger.error(f"Failed to load credentials: {e}")
    
    def _save_credentials(self):
        """Save encrypted credentials to file"""
        try:
            # Prepare data for serialization
            creds_data = {}
            for name, cred in self.credentials.items():
                creds_data[name] = {
                    'name': cred.name,
                    'encrypted_value': base64.b64encode(cred.encrypted_value).decode(),
                    'created_at': cred.created_at.isoformat(),
                    'last_used': cred.last_used.isoformat() if cred.last_used else None,
                    'expires_at': cred.expires_at.isoformat() if cred.expires_at else None,
                    'metadata': cred.metadata
                }
            
            # Encrypt and save
            data_json = json.dumps(creds_data).encode()
            encrypted_data = self.cipher.encrypt(data_json)
            
            with open(self.credentials_file, 'wb') as f:
                f.write(encrypted_data)
            
            os.chmod(self.credentials_file, 0o600)  # Owner read/write only
            
        except Exception as e:
            self.logger.error(f"Failed to save credentials: {e}")
    
    def store_credential(self, name: str, value: str, expires_in: Optional[int] = None,
                        metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Store encrypted credential"""
        if not self.encryption_enabled:
            self.logger.error("Encryption not available")
            return False
        
        try:
            with self._lock:
                # Encrypt the credential value
                encrypted_value = self.cipher.encrypt(value.encode())
                
                # Calculate expiration
                expires_at = None
                if expires_in:
                    expires_at = datetime.now() + timedelta(seconds=expires_in)
                
                # Create credential object
                credential = Credential(
                    name=name,
                    encrypted_value=encrypted_value,
                    created_at=datetime.now(),
                    expires_at=expires_at,
                    metadata=metadata or {}
                )
                
                self.credentials[name] = credential
                self._save_credentials()
                
                self.logger.info(f"Stored credential: {name}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to store credential {name}: {e}")
            return False
    
    def get_credential(self, name: str) -> Optional[str]:
        """Retrieve and decrypt credential"""
        if not self.encryption_enabled:
            self.logger.error("Encryption not available")
            return None
        
        try:
            with self._lock:
                credential = self.credentials.get(name)
                if not credential:
                    return None
                
                # Check expiration
                if credential.expires_at and datetime.now() > credential.expires_at:
                    self.logger.warning(f"Credential {name} has expired")
                    del self.credentials[name]
                    self._save_credentials()
                    return None
                
                # Decrypt and return
                decrypted_value = self.cipher.decrypt(credential.encrypted_value).decode()
                
                # Update last used time
                credential.last_used = datetime.now()
                self._save_credentials()
                
                return decrypted_value
                
        except Exception as e:
            self.logger.error(f"Failed to retrieve credential {name}: {e}")
            return None
    
    def delete_credential(self, name: str) -> bool:
        """Delete credential"""
        try:
            with self._lock:
                if name in self.credentials:
                    del self.credentials[name]
                    self._save_credentials()
                    self.logger.info(f"Deleted credential: {name}")
                    return True
                return False
        except Exception as e:
            self.logger.error(f"Failed to delete credential {name}: {e}")
            return False
    
    def list_credentials(self) -> List[Dict[str, Any]]:
        """List all credentials (without values)"""
        with self._lock:
            result = []
            for name, cred in self.credentials.items():
                result.append({
                    'name': name,
                    'created_at': cred.created_at.isoformat(),
                    'last_used': cred.last_used.isoformat() if cred.last_used else None,
                    'expires_at': cred.expires_at.isoformat() if cred.expires_at else None,
                    'expired': cred.expires_at and datetime.now() > cred.expires_at,
                    'metadata': cred.metadata
                })
            return result
    
    def rotate_master_key(self, new_password: Optional[str] = None) -> bool:
        """Rotate master encryption key"""
        if not self.encryption_enabled:
            self.logger.error("Encryption not available")
            return False
        
        try:
            with self._lock:
                # Generate new key
                if new_password:
                    salt = secrets.token_bytes(32)
                    new_key = self._derive_key_from_password(new_password, salt)
                else:
                    new_key = Fernet.generate_key()
                
                new_cipher = Fernet(new_key)
                
                # Re-encrypt all credentials with new key
                for name, credential in self.credentials.items():
                    # Decrypt with old key
                    decrypted_value = self.cipher.decrypt(credential.encrypted_value)
                    # Re-encrypt with new key
                    credential.encrypted_value = new_cipher.encrypt(decrypted_value)
                
                # Update master key and cipher
                self.master_key = new_key
                self.cipher = new_cipher
                
                # Save new key and credentials
                with open(self.key_file, 'wb') as f:
                    f.write(new_key)
                os.chmod(self.key_file, 0o600)
                
                self._save_credentials()
                
                self.logger.info("Master key rotated successfully")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to rotate master key: {e}")
            return False


class ThreatDetector:
    """Real-time threat detection and prevention"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.validator = get_enhanced_validator()
        self.cache = get_fast_cache()
        
        # Rate limiting
        self.rate_limits = {}
        self.rate_limit_window = 300  # 5 minutes
        self.rate_limit_max_requests = 100
        
        # Threat detection settings
        self.brute_force_threshold = 10
        self.brute_force_window = 600  # 10 minutes
        
        # Blocked IPs and users
        self.blocked_ips = set()
        self.blocked_users = set()
        self.temp_blocks = {}  # IP -> expiration time
        
        # Lock for thread safety
        self._lock = threading.RLock()
    
    def check_rate_limit(self, identifier: str, max_requests: Optional[int] = None,
                        window: Optional[int] = None) -> Dict[str, Any]:
        """Check rate limiting for IP or user"""
        max_req = max_requests or self.rate_limit_max_requests
        time_window = window or self.rate_limit_window
        current_time = time.time()
        
        with self._lock:
            if identifier not in self.rate_limits:
                self.rate_limits[identifier] = []
            
            # Clean old entries
            self.rate_limits[identifier] = [
                req_time for req_time in self.rate_limits[identifier]
                if current_time - req_time < time_window
            ]
            
            # Check limit
            request_count = len(self.rate_limits[identifier])
            
            if request_count >= max_req:
                return {
                    'allowed': False,
                    'reason': 'rate_limit_exceeded',
                    'requests_made': request_count,
                    'max_requests': max_req,
                    'reset_time': current_time + time_window
                }
            
            # Record this request
            self.rate_limits[identifier].append(current_time)
            
            return {
                'allowed': True,
                'requests_made': request_count + 1,
                'max_requests': max_req,
                'reset_time': current_time + time_window
            }
    
    def detect_brute_force(self, identifier: str, failed_attempt: bool) -> Dict[str, Any]:
        """Detect brute force attacks"""
        cache_key = f"failed_attempts:{identifier}"
        current_time = time.time()
        
        if failed_attempt:
            # Get existing attempts
            attempts = self.cache.get(cache_key, [])
            
            # Clean old attempts
            attempts = [attempt_time for attempt_time in attempts 
                       if current_time - attempt_time < self.brute_force_window]
            
            # Add new attempt
            attempts.append(current_time)
            self.cache.set(cache_key, attempts, ttl=self.brute_force_window)
            
            # Check threshold
            if len(attempts) >= self.brute_force_threshold:
                return {
                    'brute_force_detected': True,
                    'attempts': len(attempts),
                    'threshold': self.brute_force_threshold,
                    'action_required': 'block_temporarily'
                }
        
        return {
            'brute_force_detected': False,
            'attempts': len(self.cache.get(cache_key, [])),
            'threshold': self.brute_force_threshold
        }
    
    def check_malicious_input(self, input_value: str, context: str = "general") -> Dict[str, Any]:
        """Check input for malicious patterns"""
        threats_detected = []
        
        # SQL injection detection
        if self.validator.SECURITY_PATTERNS['sql_injection'].search(input_value):
            threats_detected.append({
                'type': ThreatType.INJECTION,
                'pattern': 'sql_injection',
                'severity': SecurityLevel.HIGH
            })
        
        # XSS detection
        if self.validator.SECURITY_PATTERNS['xss_attempt'].search(input_value):
            threats_detected.append({
                'type': ThreatType.XSS,
                'pattern': 'xss_attempt',
                'severity': SecurityLevel.HIGH
            })
        
        # Path traversal detection
        if self.validator.SECURITY_PATTERNS['path_traversal'].search(input_value):
            threats_detected.append({
                'type': ThreatType.PATH_TRAVERSAL,
                'pattern': 'path_traversal',
                'severity': SecurityLevel.CRITICAL
            })
        
        # Command injection detection
        if self.validator.SECURITY_PATTERNS['command_injection'].search(input_value):
            threats_detected.append({
                'type': ThreatType.INJECTION,
                'pattern': 'command_injection',
                'severity': SecurityLevel.CRITICAL
            })
        
        return {
            'malicious': len(threats_detected) > 0,
            'threats': threats_detected,
            'should_block': any(t['severity'] in [SecurityLevel.HIGH, SecurityLevel.CRITICAL] 
                              for t in threats_detected)
        }
    
    def block_ip_temporarily(self, ip: str, duration: int = 3600) -> bool:
        """Temporarily block an IP address"""
        with self._lock:
            expiration = time.time() + duration
            self.temp_blocks[ip] = expiration
            self.logger.warning(f"Temporarily blocked IP {ip} for {duration} seconds")
            return True
    
    def is_blocked(self, ip: str, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Check if IP or user is blocked"""
        current_time = time.time()
        
        with self._lock:
            # Check permanent blocks
            if ip in self.blocked_ips:
                return {
                    'blocked': True,
                    'reason': 'permanently_blocked',
                    'type': 'ip'
                }
            
            if user_id and user_id in self.blocked_users:
                return {
                    'blocked': True,
                    'reason': 'permanently_blocked',
                    'type': 'user'
                }
            
            # Check temporary blocks
            if ip in self.temp_blocks:
                if current_time < self.temp_blocks[ip]:
                    return {
                        'blocked': True,
                        'reason': 'temporarily_blocked',
                        'type': 'ip',
                        'expires_at': self.temp_blocks[ip]
                    }
                else:
                    # Block expired
                    del self.temp_blocks[ip]
            
            return {'blocked': False}


class SecurityAuditor:
    """Security audit and compliance system"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config_manager = get_config_manager()
        
        # Audit log
        self.audit_log_file = Path('./security/audit.log')
        self.security_events: List[SecurityEvent] = []
        
        # Compliance checks
        self.compliance_rules = self._load_compliance_rules()
        
        # Lock for thread safety
        self._lock = threading.RLock()
    
    def _load_compliance_rules(self) -> Dict[str, Any]:
        """Load security compliance rules"""
        return {
            'password_requirements': {
                'min_length': 12,
                'require_uppercase': True,
                'require_lowercase': True,
                'require_numbers': True,
                'require_special': True,
                'max_age_days': 90
            },
            'session_security': {
                'max_duration': 3600,
                'require_https': True,
                'secure_cookies': True
            },
            'file_permissions': {
                'config_files': 0o600,
                'log_files': 0o640,
                'key_files': 0o600
            },
            'network_security': {
                'allowed_ports': [8080, 9735, 10009],
                'require_tls': True
            }
        }
    
    def log_security_event(self, event: SecurityEvent) -> None:
        """Log security event"""
        with self._lock:
            self.security_events.append(event)
            
            # Write to audit log
            audit_entry = {
                'timestamp': event.timestamp.isoformat(),
                'event_type': event.event_type,
                'severity': event.severity.name,
                'threat_type': event.threat_type.value if event.threat_type else None,
                'source_ip': event.source_ip,
                'user_id': event.user_id,
                'details': event.details,
                'blocked': event.blocked
            }
            
            try:
                with open(self.audit_log_file, 'a') as f:
                    f.write(json.dumps(audit_entry) + '\n')
            except Exception as e:
                self.logger.error(f"Failed to write audit log: {e}")
    
    def check_file_permissions(self, file_path: str) -> Dict[str, Any]:
        """Check file permissions compliance"""
        try:
            path = Path(file_path)
            if not path.exists():
                return {
                    'compliant': False,
                    'reason': 'file_not_found',
                    'file_path': file_path
                }
            
            current_mode = path.stat().st_mode & 0o777
            
            # Determine expected permissions based on file type
            if file_path.endswith(('.key', '.pem', 'macaroon')):
                expected_mode = self.compliance_rules['file_permissions']['key_files']
            elif file_path.endswith('.log'):
                expected_mode = self.compliance_rules['file_permissions']['log_files']
            else:
                expected_mode = self.compliance_rules['file_permissions']['config_files']
            
            compliant = current_mode <= expected_mode
            
            return {
                'compliant': compliant,
                'current_permissions': oct(current_mode),
                'expected_permissions': oct(expected_mode),
                'file_path': file_path,
                'recommendation': f"chmod {oct(expected_mode)[2:]} {file_path}" if not compliant else None
            }
            
        except Exception as e:
            return {
                'compliant': False,
                'reason': f'check_failed: {e}',
                'file_path': file_path
            }
    
    def audit_system_security(self) -> Dict[str, Any]:
        """Comprehensive security audit"""
        audit_results = {
            'timestamp': datetime.now().isoformat(),
            'overall_score': 0,
            'checks_performed': 0,
            'checks_passed': 0,
            'critical_issues': [],
            'warnings': [],
            'recommendations': [],
            'compliance_status': {}
        }
        
        # Check file permissions
        important_files = [
            './security/.master_key',
            './security/credentials.enc',
            './security/auth.json',
            './blncs.log'
        ]
        
        file_checks = []
        for file_path in important_files:
            if Path(file_path).exists():
                check_result = self.check_file_permissions(file_path)
                file_checks.append(check_result)
                audit_results['checks_performed'] += 1
                
                if check_result['compliant']:
                    audit_results['checks_passed'] += 1
                else:
                    if file_path.endswith(('.key', 'macaroon')):
                        audit_results['critical_issues'].append(f"Insecure permissions on {file_path}")
                    else:
                        audit_results['warnings'].append(f"Suboptimal permissions on {file_path}")
                    
                    if check_result.get('recommendation'):
                        audit_results['recommendations'].append(check_result['recommendation'])
        
        audit_results['compliance_status']['file_permissions'] = file_checks
        
        # Check configuration security
        config_security = self._audit_configuration()
        audit_results['compliance_status']['configuration'] = config_security
        audit_results['checks_performed'] += len(config_security.get('checks', []))
        audit_results['checks_passed'] += len([c for c in config_security.get('checks', []) if c.get('passed', False)])
        
        # Calculate overall score
        if audit_results['checks_performed'] > 0:
            audit_results['overall_score'] = (audit_results['checks_passed'] / audit_results['checks_performed']) * 100
        
        return audit_results
    
    def _audit_configuration(self) -> Dict[str, Any]:
        """Audit configuration security"""
        checks = []
        
        # Check if authentication is enabled
        auth_enabled = self.config_manager.get('security.enable_api_auth', False)
        checks.append({
            'name': 'API Authentication',
            'passed': auth_enabled,
            'severity': 'high' if not auth_enabled else 'info',
            'message': 'API authentication is enabled' if auth_enabled else 'API authentication is disabled',
            'recommendation': 'Enable API authentication for production use' if not auth_enabled else None
        })
        
        # Check session timeout
        session_timeout = self.config_manager.get('security.session_timeout', 3600)
        max_timeout = self.compliance_rules['session_security']['max_duration']
        timeout_ok = session_timeout <= max_timeout
        checks.append({
            'name': 'Session Timeout',
            'passed': timeout_ok,
            'severity': 'medium' if not timeout_ok else 'info',
            'message': f'Session timeout: {session_timeout}s',
            'recommendation': f'Reduce session timeout to {max_timeout}s or less' if not timeout_ok else None
        })
        
        # Check TLS configuration
        tls_enabled = bool(self.config_manager.get('lightning.cert_path'))
        checks.append({
            'name': 'TLS Configuration',
            'passed': tls_enabled,
            'severity': 'critical' if not tls_enabled else 'info',
            'message': 'TLS certificate configured' if tls_enabled else 'TLS certificate not configured',
            'recommendation': 'Configure TLS certificate for secure communications' if not tls_enabled else None
        })
        
        return {'checks': checks}


class EnhancedSecurityManager:
    """Enhanced security management system"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config_manager = get_config_manager()
        
        # Initialize components
        self.key_manager = SecureKeyManager()
        self.threat_detector = ThreatDetector()
        self.auditor = SecurityAuditor()
        
        # Security monitoring
        self.monitoring_enabled = self.config_manager.get('security.monitoring_enabled', True)
        self._monitoring_thread = None
        self._stop_monitoring = threading.Event()
        
        # Security settings
        self.security_level = SecurityLevel(self.config_manager.get('security.level', SecurityLevel.MEDIUM.value))
        self.auto_block_threats = self.config_manager.get('security.auto_block_threats', True)
        
        if self.monitoring_enabled:
            self.start_monitoring()
    
    def start_monitoring(self):
        """Start security monitoring"""
        if self._monitoring_thread and self._monitoring_thread.is_alive():
            return
        
        self._stop_monitoring.clear()
        self._monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self._monitoring_thread.start()
        self.logger.info("Security monitoring started")
    
    def stop_monitoring(self):
        """Stop security monitoring"""
        self._stop_monitoring.set()
        if self._monitoring_thread:
            self._monitoring_thread.join(timeout=5)
        self.logger.info("Security monitoring stopped")
    
    def _monitoring_loop(self):
        """Security monitoring loop"""
        while not self._stop_monitoring.is_set():
            try:
                # Perform periodic security checks
                self._check_temp_blocks()
                self._check_credential_expiration()
                
                # Wait for next check
                self._stop_monitoring.wait(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Security monitoring error: {e}")
    
    def _check_temp_blocks(self):
        """Clean up expired temporary blocks"""
        current_time = time.time()
        expired_blocks = [
            ip for ip, expiry in self.threat_detector.temp_blocks.items()
            if current_time >= expiry
        ]
        
        for ip in expired_blocks:
            del self.threat_detector.temp_blocks[ip]
            self.logger.info(f"Temporary block expired for IP: {ip}")
    
    def _check_credential_expiration(self):
        """Check for expiring credentials"""
        if not self.key_manager.encryption_enabled:
            return
        
        credentials = self.key_manager.list_credentials()
        soon_expiring = []
        
        for cred in credentials:
            if cred['expires_at']:
                expires_at = datetime.fromisoformat(cred['expires_at'])
                if expires_at <= datetime.now() + timedelta(days=7):  # Expires within 7 days
                    soon_expiring.append(cred['name'])
        
        if soon_expiring:
            self.logger.warning(f"Credentials expiring soon: {', '.join(soon_expiring)}")
    
    @contextmanager
    def security_context(self, operation: str, user_id: Optional[str] = None, 
                        source_ip: Optional[str] = None):
        """Security context manager for operations"""
        start_time = time.time()
        
        try:
            # Pre-operation security checks
            if source_ip:
                block_status = self.threat_detector.is_blocked(source_ip, user_id)
                if block_status['blocked']:
                    raise SecurityError(f"Access blocked: {block_status['reason']}")
                
                rate_limit = self.threat_detector.check_rate_limit(source_ip)
                if not rate_limit['allowed']:
                    raise SecurityError("Rate limit exceeded")
            
            yield
            
            # Log successful operation
            event = SecurityEvent(
                timestamp=datetime.now(),
                event_type='operation_completed',
                severity=SecurityLevel.LOW,
                threat_type=None,
                source_ip=source_ip,
                user_id=user_id,
                details={'operation': operation, 'duration': time.time() - start_time}
            )
            self.auditor.log_security_event(event)
            
        except SecurityError:
            # Log security violation
            event = SecurityEvent(
                timestamp=datetime.now(),
                event_type='security_violation',
                severity=SecurityLevel.HIGH,
                threat_type=ThreatType.UNAUTHORIZED_ACCESS,
                source_ip=source_ip,
                user_id=user_id,
                details={'operation': operation, 'blocked': True},
                blocked=True
            )
            self.auditor.log_security_event(event)
            raise
        except Exception as e:
            # Log operation failure
            event = SecurityEvent(
                timestamp=datetime.now(),
                event_type='operation_failed',
                severity=SecurityLevel.MEDIUM,
                threat_type=None,
                source_ip=source_ip,
                user_id=user_id,
                details={'operation': operation, 'error': str(e)}
            )
            self.auditor.log_security_event(event)
            raise
    
    def validate_input(self, input_value: str, context: str = "general") -> Dict[str, Any]:
        """Validate input for security threats"""
        malicious_check = self.threat_detector.check_malicious_input(input_value, context)
        
        if malicious_check['malicious'] and self.auto_block_threats:
            # Log threat detection
            event = SecurityEvent(
                timestamp=datetime.now(),
                event_type='threat_detected',
                severity=SecurityLevel.HIGH,
                threat_type=malicious_check['threats'][0]['type'] if malicious_check['threats'] else None,
                details={'input': input_value[:100], 'threats': malicious_check['threats']}
            )
            self.auditor.log_security_event(event)
            
            if malicious_check['should_block']:
                raise SecurityError("Malicious input detected and blocked")
        
        return malicious_check
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get comprehensive security status"""
        return {
            'security_level': self.security_level.name,
            'encryption_available': self.key_manager.encryption_enabled,
            'monitoring_enabled': self.monitoring_enabled,
            'credentials_stored': len(self.key_manager.credentials),
            'temp_blocked_ips': len(self.threat_detector.temp_blocks),
            'permanently_blocked_ips': len(self.threat_detector.blocked_ips),
            'recent_events': len([e for e in self.auditor.security_events 
                                 if e.timestamp >= datetime.now() - timedelta(hours=24)]),
            'last_audit': None,  # TODO: Implement audit tracking
            'compliance_score': None  # TODO: Implement compliance scoring
        }


# Security decorators
def require_security_level(min_level: SecurityLevel):
    """Decorator to require minimum security level"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            security_manager = get_enhanced_security_manager()
            if security_manager.security_level.value < min_level.value:
                raise SecurityError(f"Operation requires security level {min_level.name}")
            return func(*args, **kwargs)
        return wrapper
    return decorator


def log_security_event(event_type: str, severity: SecurityLevel = SecurityLevel.MEDIUM):
    """Decorator to log security events"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            security_manager = get_enhanced_security_manager()
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                
                event = SecurityEvent(
                    timestamp=datetime.now(),
                    event_type=event_type,
                    severity=severity,
                    threat_type=None,
                    details={
                        'function': func.__name__,
                        'duration': time.time() - start_time,
                        'success': True
                    }
                )
                security_manager.auditor.log_security_event(event)
                
                return result
                
            except Exception as e:
                event = SecurityEvent(
                    timestamp=datetime.now(),
                    event_type=event_type,
                    severity=SecurityLevel.HIGH,
                    threat_type=None,
                    details={
                        'function': func.__name__,
                        'duration': time.time() - start_time,
                        'success': False,
                        'error': str(e)
                    }
                )
                security_manager.auditor.log_security_event(event)
                raise
        return wrapper
    return decorator


# Global enhanced security manager instance
_enhanced_security_manager = None

def get_enhanced_security_manager() -> EnhancedSecurityManager:
    """Get or create global enhanced security manager instance"""
    global _enhanced_security_manager
    if _enhanced_security_manager is None:
        _enhanced_security_manager = EnhancedSecurityManager()
    return _enhanced_security_manager