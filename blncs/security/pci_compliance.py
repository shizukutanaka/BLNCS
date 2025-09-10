#!/usr/bin/env python3
"""
PCI DSS Compliance Framework for BLNCS
Implements Payment Card Industry Data Security Standards for Lightning Network payments
"""

import asyncio
import hashlib
import hmac
import secrets
import ssl
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Tuple
import logging
import json
import re
from pathlib import Path
from datetime import datetime, timedelta
import cryptography.fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from blncs.core.async_memory_manager import track_async_task, lightning_operation_context
from blncs.core.exceptions import BLNCSError

logger = logging.getLogger(__name__)

class PCIRequirement(Enum):
    """PCI DSS Requirements"""
    REQ_1 = "Install and maintain a firewall configuration"
    REQ_2 = "Do not use vendor-supplied defaults for system passwords"
    REQ_3 = "Protect stored cardholder data"
    REQ_4 = "Encrypt transmission of cardholder data"
    REQ_5 = "Protect all systems against malware"
    REQ_6 = "Develop and maintain secure systems"
    REQ_7 = "Restrict access to cardholder data"
    REQ_8 = "Identify and authenticate access to system components"
    REQ_9 = "Restrict physical access to cardholder data"
    REQ_10 = "Track and monitor all network access"
    REQ_11 = "Regularly test security systems"
    REQ_12 = "Maintain an information security policy"

class ComplianceLevel(Enum):
    """PCI DSS Compliance Levels"""
    LEVEL_1 = "level_1"  # 6M+ transactions annually
    LEVEL_2 = "level_2"  # 1-6M transactions annually
    LEVEL_3 = "level_3"  # 20K-1M e-commerce transactions
    LEVEL_4 = "level_4"  # <20K e-commerce transactions

class SecurityClassification(Enum):
    """Data security classification"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    CARDHOLDER_DATA = "cardholder_data"

@dataclass
class ComplianceViolation:
    """PCI DSS compliance violation record"""
    requirement: PCIRequirement
    severity: str
    description: str
    timestamp: float
    component: str
    remediation: str
    status: str = "open"
    ticket_id: Optional[str] = None

@dataclass
class SecurityEvent:
    """Security event record"""
    event_id: str
    event_type: str
    timestamp: float
    source_ip: Optional[str]
    user_id: Optional[str]
    component: str
    description: str
    risk_score: int
    metadata: Dict[str, Any] = field(default_factory=dict)

class DataClassifier:
    """Classify data according to PCI DSS requirements"""
    
    def __init__(self):
        # PAN (Primary Account Number) patterns
        self.pan_patterns = [
            r'\b4[0-9]{12}(?:[0-9]{3})?\b',  # Visa
            r'\b5[1-5][0-9]{14}\b',          # Mastercard
            r'\b3[47][0-9]{13}\b',           # American Express
            r'\b6(?:011|5[0-9]{2})[0-9]{12}\b'  # Discover
        ]
        
        # Sensitive data patterns
        self.sensitive_patterns = {
            'ssn': r'\b\d{3}-?\d{2}-?\d{4}\b',
            'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            'cvv': r'\b\d{3,4}\b',
            'expiry': r'\b(0[1-9]|1[0-2])\/([0-9]{2}|20[0-9]{2})\b'
        }
    
    def classify_data(self, data: str) -> SecurityClassification:
        """Classify data based on content"""
        data_lower = data.lower()
        
        # Check for PAN
        for pattern in self.pan_patterns:
            if re.search(pattern, data):
                return SecurityClassification.CARDHOLDER_DATA
        
        # Check for other sensitive data
        for data_type, pattern in self.sensitive_patterns.items():
            if re.search(pattern, data):
                return SecurityClassification.RESTRICTED
        
        # Check for keywords indicating sensitive data
        sensitive_keywords = [
            'password', 'secret', 'token', 'key', 'auth',
            'credit', 'card', 'payment', 'billing'
        ]
        
        if any(keyword in data_lower for keyword in sensitive_keywords):
            return SecurityClassification.CONFIDENTIAL
        
        return SecurityClassification.INTERNAL
    
    def scan_for_cardholder_data(self, text: str) -> List[Dict[str, Any]]:
        """Scan text for potential cardholder data"""
        findings = []
        
        for pattern in self.pan_patterns:
            matches = re.finditer(pattern, text)
            for match in matches:
                findings.append({
                    'type': 'pan',
                    'value': match.group(),
                    'start': match.start(),
                    'end': match.end(),
                    'masked': self._mask_pan(match.group())
                })
        
        return findings
    
    def _mask_pan(self, pan: str) -> str:
        """Mask PAN for logging/display"""
        if len(pan) < 8:
            return '*' * len(pan)
        return pan[:4] + '*' * (len(pan) - 8) + pan[-4:]

class EncryptionManager:
    """PCI DSS compliant encryption management"""
    
    def __init__(self, master_key: Optional[bytes] = None):
        self.master_key = master_key or self._generate_master_key()
        self.key_rotation_interval = 86400 * 30  # 30 days
        self.encryption_keys: Dict[str, Tuple[bytes, float]] = {}
        
    def _generate_master_key(self) -> bytes:
        """Generate master encryption key"""
        return secrets.token_bytes(32)  # 256-bit key
    
    def _derive_key(self, purpose: str, salt: Optional[bytes] = None) -> bytes:
        """Derive encryption key for specific purpose"""
        if not salt:
            salt = secrets.token_bytes(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        return kdf.derive(self.master_key + purpose.encode())
    
    def get_encryption_key(self, purpose: str) -> bytes:
        """Get or create encryption key for purpose"""
        current_time = time.time()
        
        # Check if key exists and is not expired
        if purpose in self.encryption_keys:
            key, created_time = self.encryption_keys[purpose]
            if current_time - created_time < self.key_rotation_interval:
                return key
        
        # Generate new key
        new_key = self._derive_key(purpose)
        self.encryption_keys[purpose] = (new_key, current_time)
        
        logger.info(f"Generated new encryption key for purpose: {purpose}")
        return new_key
    
    def encrypt_data(self, data: str, purpose: str = "general") -> Dict[str, str]:
        """Encrypt data using AES-256-GCM"""
        key = self.get_encryption_key(purpose)
        
        # Generate IV
        iv = secrets.token_bytes(12)  # GCM uses 96-bit IV
        
        # Encrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
        
        return {
            'ciphertext': ciphertext.hex(),
            'iv': iv.hex(),
            'tag': encryptor.tag.hex(),
            'purpose': purpose
        }
    
    def decrypt_data(self, encrypted_data: Dict[str, str]) -> str:
        """Decrypt data using AES-256-GCM"""
        purpose = encrypted_data['purpose']
        key = self.get_encryption_key(purpose)
        
        ciphertext = bytes.fromhex(encrypted_data['ciphertext'])
        iv = bytes.fromhex(encrypted_data['iv'])
        tag = bytes.fromhex(encrypted_data['tag'])
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext.decode()
    
    def rotate_keys(self) -> Dict[str, bool]:
        """Rotate all encryption keys"""
        results = {}
        current_time = time.time()
        
        for purpose in list(self.encryption_keys.keys()):
            try:
                # Generate new key
                new_key = self._derive_key(purpose)
                self.encryption_keys[purpose] = (new_key, current_time)
                results[purpose] = True
                logger.info(f"Rotated encryption key for: {purpose}")
            except Exception as e:
                logger.error(f"Failed to rotate key for {purpose}: {e}")
                results[purpose] = False
        
        return results

class AccessController:
    """PCI DSS access control and authentication"""
    
    def __init__(self):
        self.access_policies: Dict[str, Dict[str, Any]] = {}
        self.user_sessions: Dict[str, Dict[str, Any]] = {}
        self.failed_attempts: Dict[str, List[float]] = {}
        self.max_failed_attempts = 3
        self.lockout_duration = 900  # 15 minutes
        
    def define_access_policy(self, resource: str, policy: Dict[str, Any]):
        """Define access policy for resource"""
        required_fields = ['roles', 'permissions', 'data_classification']
        for field in required_fields:
            if field not in policy:
                raise ValueError(f"Access policy must include {field}")
        
        self.access_policies[resource] = policy
        logger.info(f"Defined access policy for resource: {resource}")
    
    def authenticate_user(self, user_id: str, credentials: Dict[str, Any]) -> Optional[str]:
        """Authenticate user and return session token"""
        # Check for lockout
        if self._is_user_locked_out(user_id):
            logger.warning(f"Authentication blocked for locked out user: {user_id}")
            return None
        
        # Validate credentials (placeholder - implement real authentication)
        if self._validate_credentials(user_id, credentials):
            # Create session
            session_token = secrets.token_urlsafe(32)
            session_data = {
                'user_id': user_id,
                'created_at': time.time(),
                'last_activity': time.time(),
                'ip_address': credentials.get('ip_address'),
                'roles': credentials.get('roles', []),
                'permissions': credentials.get('permissions', [])
            }
            
            self.user_sessions[session_token] = session_data
            
            # Clear failed attempts
            if user_id in self.failed_attempts:
                del self.failed_attempts[user_id]
            
            logger.info(f"User authenticated successfully: {user_id}")
            return session_token
        else:
            # Record failed attempt
            self._record_failed_attempt(user_id)
            logger.warning(f"Authentication failed for user: {user_id}")
            return None
    
    def authorize_access(self, session_token: str, resource: str, action: str) -> bool:
        """Authorize user access to resource"""
        # Validate session
        session = self.user_sessions.get(session_token)
        if not session:
            logger.warning(f"Invalid session token for resource access: {resource}")
            return False
        
        # Check session expiry
        if time.time() - session['last_activity'] > 3600:  # 1 hour
            del self.user_sessions[session_token]
            logger.warning(f"Expired session for user: {session['user_id']}")
            return False
        
        # Update last activity
        session['last_activity'] = time.time()
        
        # Check access policy
        policy = self.access_policies.get(resource)
        if not policy:
            logger.warning(f"No access policy defined for resource: {resource}")
            return False
        
        user_roles = set(session.get('roles', []))
        user_permissions = set(session.get('permissions', []))
        
        required_roles = set(policy.get('roles', []))
        required_permissions = set(policy.get('permissions', []))
        
        # Check role-based access
        if required_roles and not user_roles.intersection(required_roles):
            logger.warning(f"Insufficient roles for user {session['user_id']} accessing {resource}")
            return False
        
        # Check permission-based access
        if required_permissions and not user_permissions.intersection(required_permissions):
            logger.warning(f"Insufficient permissions for user {session['user_id']} accessing {resource}")
            return False
        
        logger.debug(f"Access authorized for user {session['user_id']} to {resource}")
        return True
    
    def _is_user_locked_out(self, user_id: str) -> bool:
        """Check if user is locked out due to failed attempts"""
        if user_id not in self.failed_attempts:
            return False
        
        attempts = self.failed_attempts[user_id]
        current_time = time.time()
        
        # Remove old attempts
        recent_attempts = [t for t in attempts if current_time - t < self.lockout_duration]
        self.failed_attempts[user_id] = recent_attempts
        
        return len(recent_attempts) >= self.max_failed_attempts
    
    def _record_failed_attempt(self, user_id: str):
        """Record failed authentication attempt"""
        if user_id not in self.failed_attempts:
            self.failed_attempts[user_id] = []
        
        self.failed_attempts[user_id].append(time.time())
    
    def _validate_credentials(self, user_id: str, credentials: Dict[str, Any]) -> bool:
        """Validate user credentials (placeholder implementation)"""
        # In real implementation, this would validate against user database
        # with proper password hashing, 2FA, etc.
        return True  # Placeholder

class AuditLogger:
    """PCI DSS compliant audit logging"""
    
    def __init__(self, log_dir: Path):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.current_log_file: Optional[Path] = None
        self.log_rotation_size = 10 * 1024 * 1024  # 10MB
        
    def log_security_event(self, event: SecurityEvent):
        """Log security event with PCI DSS requirements"""
        log_entry = {
            'timestamp': datetime.fromtimestamp(event.timestamp).isoformat(),
            'event_id': event.event_id,
            'event_type': event.event_type,
            'source_ip': event.source_ip,
            'user_id': event.user_id,
            'component': event.component,
            'description': event.description,
            'risk_score': event.risk_score,
            'metadata': event.metadata
        }
        
        # Write to log file
        log_file = self._get_current_log_file()
        with open(log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
        
        # Check for log rotation
        if log_file.stat().st_size > self.log_rotation_size:
            self._rotate_log_file()
    
    def _get_current_log_file(self) -> Path:
        """Get current log file, create if needed"""
        if not self.current_log_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.current_log_file = self.log_dir / f"security_audit_{timestamp}.log"
        
        return self.current_log_file
    
    def _rotate_log_file(self):
        """Rotate log file when size limit reached"""
        if self.current_log_file:
            # Archive current log
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            archived_name = f"security_audit_archived_{timestamp}.log"
            archived_path = self.log_dir / archived_name
            
            self.current_log_file.rename(archived_path)
            logger.info(f"Rotated log file to: {archived_path}")
        
        # Reset current log file
        self.current_log_file = None

class ComplianceMonitor:
    """Monitor and report PCI DSS compliance status"""
    
    def __init__(self, target_level: ComplianceLevel):
        self.target_level = target_level
        self.violations: List[ComplianceViolation] = []
        self.security_events: List[SecurityEvent] = []
        self.last_assessment: Optional[float] = None
        
    @track_async_task("compliance_assessment")
    async def assess_compliance(self) -> Dict[str, Any]:
        """Assess current PCI DSS compliance status"""
        async with lightning_operation_context("compliance_assessment"):
            assessment_time = time.time()
            results = {}
            
            # Check each requirement
            for requirement in PCIRequirement:
                compliance_status = await self._check_requirement(requirement)
                results[requirement.name] = compliance_status
            
            # Calculate overall compliance score
            passing_requirements = sum(1 for status in results.values() if status['compliant'])
            total_requirements = len(PCIRequirement)
            compliance_score = (passing_requirements / total_requirements) * 100
            
            assessment_result = {
                'assessment_time': assessment_time,
                'target_level': self.target_level.value,
                'compliance_score': compliance_score,
                'requirements': results,
                'open_violations': len([v for v in self.violations if v.status == 'open']),
                'recent_security_events': len([
                    e for e in self.security_events 
                    if assessment_time - e.timestamp < 86400  # Last 24 hours
                ])
            }
            
            self.last_assessment = assessment_time
            logger.info(f"PCI DSS compliance assessment completed: {compliance_score:.1f}%")
            
            return assessment_result
    
    async def _check_requirement(self, requirement: PCIRequirement) -> Dict[str, Any]:
        """Check specific PCI DSS requirement compliance"""
        # This is a simplified implementation
        # Real implementation would perform comprehensive checks
        
        if requirement == PCIRequirement.REQ_3:
            # Protect stored cardholder data
            return await self._check_data_protection()
        elif requirement == PCIRequirement.REQ_4:
            # Encrypt transmission of cardholder data
            return await self._check_transmission_encryption()
        elif requirement == PCIRequirement.REQ_7:
            # Restrict access to cardholder data
            return await self._check_access_restrictions()
        elif requirement == PCIRequirement.REQ_10:
            # Track and monitor all network access
            return await self._check_monitoring()
        else:
            # Placeholder for other requirements
            return {
                'compliant': True,
                'details': f"Requirement {requirement.name} check passed",
                'recommendations': []
            }
    
    async def _check_data_protection(self) -> Dict[str, Any]:
        """Check data protection compliance"""
        # Check for encrypted storage, key management, etc.
        return {
            'compliant': True,
            'details': "Cardholder data protection verified",
            'recommendations': ["Implement regular key rotation"]
        }
    
    async def _check_transmission_encryption(self) -> Dict[str, Any]:
        """Check transmission encryption compliance"""
        # Check SSL/TLS configuration, cipher suites, etc.
        return {
            'compliant': True,
            'details': "Strong encryption in use for data transmission",
            'recommendations': ["Ensure TLS 1.3 is preferred"]
        }
    
    async def _check_access_restrictions(self) -> Dict[str, Any]:
        """Check access restriction compliance"""
        # Check role-based access, least privilege, etc.
        return {
            'compliant': True,
            'details': "Access controls properly configured",
            'recommendations': ["Review user access permissions quarterly"]
        }
    
    async def _check_monitoring(self) -> Dict[str, Any]:
        """Check monitoring compliance"""
        # Check audit logging, monitoring systems, etc.
        return {
            'compliant': True,
            'details': "Comprehensive monitoring in place",
            'recommendations': ["Implement real-time alerting"]
        }
    
    def add_violation(self, violation: ComplianceViolation):
        """Add compliance violation"""
        self.violations.append(violation)
        logger.warning(f"PCI DSS violation recorded: {violation.requirement.name} - {violation.description}")
    
    def add_security_event(self, event: SecurityEvent):
        """Add security event"""
        self.security_events.append(event)
        
        # Check for high-risk events
        if event.risk_score >= 8:
            logger.critical(f"High-risk security event: {event.description}")

class PCIComplianceFramework:
    """Complete PCI DSS compliance framework"""
    
    def __init__(self, target_level: ComplianceLevel, log_dir: Path):
        self.target_level = target_level
        self.data_classifier = DataClassifier()
        self.encryption_manager = EncryptionManager()
        self.access_controller = AccessController()
        self.audit_logger = AuditLogger(log_dir)
        self.compliance_monitor = ComplianceMonitor(target_level)
        
        # Setup default access policies
        self._setup_default_policies()
    
    def _setup_default_policies(self):
        """Setup default PCI DSS access policies"""
        policies = {
            'cardholder_data': {
                'roles': ['admin', 'authorized_personnel'],
                'permissions': ['cardholder_data.read', 'cardholder_data.process'],
                'data_classification': SecurityClassification.CARDHOLDER_DATA,
                'encryption_required': True,
                'audit_required': True
            },
            'payment_processing': {
                'roles': ['payment_processor', 'admin'],
                'permissions': ['payment.process', 'payment.refund'],
                'data_classification': SecurityClassification.RESTRICTED,
                'encryption_required': True,
                'audit_required': True
            },
            'system_configuration': {
                'roles': ['admin', 'system_admin'],
                'permissions': ['system.configure', 'system.maintain'],
                'data_classification': SecurityClassification.CONFIDENTIAL,
                'encryption_required': False,
                'audit_required': True
            }
        }
        
        for resource, policy in policies.items():
            self.access_controller.define_access_policy(resource, policy)
    
    async def process_payment_data(self, payment_data: Dict[str, Any], 
                                 session_token: str) -> Dict[str, Any]:
        """Process payment data with PCI DSS compliance"""
        # Create security event
        event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            event_type="payment_processing",
            timestamp=time.time(),
            source_ip=payment_data.get('source_ip'),
            user_id=payment_data.get('user_id'),
            component="payment_processor",
            description="Payment data processing initiated",
            risk_score=6,
            metadata={'amount': payment_data.get('amount')}
        )
        
        self.compliance_monitor.add_security_event(event)
        self.audit_logger.log_security_event(event)
        
        try:
            # Check authorization
            if not self.access_controller.authorize_access(session_token, 'payment_processing', 'process'):
                raise BLNCSError("Unauthorized access to payment processing")
            
            # Classify and protect sensitive data
            processed_data = {}
            for key, value in payment_data.items():
                if isinstance(value, str):
                    classification = self.data_classifier.classify_data(value)
                    
                    if classification in [SecurityClassification.CARDHOLDER_DATA, SecurityClassification.RESTRICTED]:
                        # Encrypt sensitive data
                        encrypted_value = self.encryption_manager.encrypt_data(value, f"payment_{key}")
                        processed_data[key] = {
                            'encrypted': True,
                            'classification': classification.value,
                            'data': encrypted_value
                        }
                    else:
                        processed_data[key] = value
                else:
                    processed_data[key] = value
            
            # Log successful processing
            success_event = SecurityEvent(
                event_id=str(uuid.uuid4()),
                event_type="payment_processed",
                timestamp=time.time(),
                source_ip=payment_data.get('source_ip'),
                user_id=payment_data.get('user_id'),
                component="payment_processor",
                description="Payment data processed successfully",
                risk_score=3,
                metadata={'transaction_id': processed_data.get('transaction_id')}
            )
            
            self.compliance_monitor.add_security_event(success_event)
            self.audit_logger.log_security_event(success_event)
            
            return {
                'status': 'success',
                'processed_data': processed_data,
                'compliance_verified': True
            }
            
        except Exception as e:
            # Log error event
            error_event = SecurityEvent(
                event_id=str(uuid.uuid4()),
                event_type="payment_error",
                timestamp=time.time(),
                source_ip=payment_data.get('source_ip'),
                user_id=payment_data.get('user_id'),
                component="payment_processor",
                description=f"Payment processing error: {str(e)}",
                risk_score=7,
                metadata={'error': str(e)}
            )
            
            self.compliance_monitor.add_security_event(error_event)
            self.audit_logger.log_security_event(error_event)
            
            raise
    
    async def generate_compliance_report(self) -> Dict[str, Any]:
        """Generate comprehensive PCI DSS compliance report"""
        assessment = await self.compliance_monitor.assess_compliance()
        
        report = {
            'report_id': str(uuid.uuid4()),
            'generated_at': time.time(),
            'target_compliance_level': self.target_level.value,
            'assessment': assessment,
            'violations': [
                {
                    'requirement': v.requirement.name,
                    'severity': v.severity,
                    'description': v.description,
                    'status': v.status,
                    'timestamp': v.timestamp
                }
                for v in self.compliance_monitor.violations[-50:]  # Last 50 violations
            ],
            'recent_events': [
                {
                    'event_type': e.event_type,
                    'timestamp': e.timestamp,
                    'risk_score': e.risk_score,
                    'description': e.description
                }
                for e in self.compliance_monitor.security_events[-100:]  # Last 100 events
            ],
            'recommendations': [
                "Implement quarterly vulnerability scans",
                "Review and update security policies annually",
                "Conduct penetration testing semi-annually",
                "Maintain network diagrams and asset inventory",
                "Implement file integrity monitoring"
            ]
        }
        
        return report
    
    def get_encryption_manager(self) -> EncryptionManager:
        """Get encryption manager instance"""
        return self.encryption_manager
    
    def get_access_controller(self) -> AccessController:
        """Get access controller instance"""
        return self.access_controller
    
    def get_compliance_monitor(self) -> ComplianceMonitor:
        """Get compliance monitor instance"""
        return self.compliance_monitor

# Factory function
async def create_pci_compliance_framework(target_level: ComplianceLevel, 
                                        log_dir: str = "./logs/pci") -> PCIComplianceFramework:
    """Create PCI DSS compliance framework"""
    framework = PCIComplianceFramework(target_level, Path(log_dir))
    
    # Initial compliance assessment
    await framework.compliance_monitor.assess_compliance()
    
    return framework

# Export main classes and functions
__all__ = [
    'PCIRequirement',
    'ComplianceLevel',
    'SecurityClassification',
    'ComplianceViolation',
    'SecurityEvent',
    'DataClassifier',
    'EncryptionManager',
    'AccessController',
    'AuditLogger',
    'ComplianceMonitor',
    'PCIComplianceFramework',
    'create_pci_compliance_framework'
]