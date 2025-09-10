"""
Enterprise Compliance and Regulatory Framework
KYC/AML, audit trails, regulatory reporting, and data protection compliance.
"""

import asyncio
import logging
import json
import hashlib
import uuid
from typing import Dict, List, Optional, Any, Set, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import threading
from concurrent.futures import ThreadPoolExecutor
import sqlite3
from pathlib import Path
import re

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False
    Fernet = None

logger = logging.getLogger(__name__)

class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    SOX = "sox"
    BSA_AML = "bsa_aml"
    FATCA = "fatca"
    MLD5 = "mld5"  # EU 5th Anti-Money Laundering Directive
    TRAVEL_RULE = "travel_rule"
    ISO27001 = "iso27001"

class RiskLevel(Enum):
    """Risk assessment levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class TransactionType(Enum):
    """Types of transactions for monitoring."""
    LIGHTNING_PAYMENT = "lightning_payment"
    CHANNEL_OPEN = "channel_open"
    CHANNEL_CLOSE = "channel_close"
    ON_CHAIN_DEPOSIT = "on_chain_deposit"
    ON_CHAIN_WITHDRAWAL = "on_chain_withdrawal"
    SUBMARINE_SWAP = "submarine_swap"

class KYCStatus(Enum):
    """KYC verification status."""
    PENDING = "pending"
    VERIFIED = "verified"
    REJECTED = "rejected"
    EXPIRED = "expired"
    UNDER_REVIEW = "under_review"

class AuditEventType(Enum):
    """Types of audit events."""
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    PERMISSION_CHANGE = "permission_change"
    TRANSACTION_CREATED = "transaction_created"
    COMPLIANCE_CHECK = "compliance_check"
    DATA_ACCESS = "data_access"
    CONFIGURATION_CHANGE = "configuration_change"
    SECURITY_INCIDENT = "security_incident"

@dataclass
class PersonalData:
    """Personal data subject to GDPR."""
    data_id: str
    subject_id: str
    data_type: str
    data_value: str
    purpose: str
    legal_basis: str
    retention_period: timedelta
    created_at: datetime = field(default_factory=datetime.utcnow)
    encrypted: bool = True
    anonymized: bool = False
    
    def is_expired(self) -> bool:
        """Check if data retention period has expired."""
        return datetime.utcnow() > (self.created_at + self.retention_period)

@dataclass
class KYCRecord:
    """KYC verification record."""
    kyc_id: str
    user_id: str
    status: KYCStatus
    risk_level: RiskLevel
    verification_data: Dict[str, Any] = field(default_factory=dict)
    documents: List[str] = field(default_factory=list)
    verified_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    verifier_id: Optional[str] = None
    rejection_reason: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    def needs_renewal(self) -> bool:
        """Check if KYC verification needs renewal."""
        if self.expires_at:
            return datetime.utcnow() > self.expires_at
        return False

@dataclass
class ComplianceTransaction:
    """Transaction record for compliance monitoring."""
    transaction_id: str
    user_id: str
    transaction_type: TransactionType
    amount_sats: int
    counterparty: Optional[str] = None
    risk_score: float = 0.0
    risk_factors: List[str] = field(default_factory=list)
    screening_results: Dict[str, Any] = field(default_factory=dict)
    flagged: bool = False
    reported: bool = False
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def calculate_risk_score(self) -> float:
        """Calculate transaction risk score."""
        score = 0.0
        
        # Amount-based risk
        if self.amount_sats > 1000000:  # > 0.01 BTC
            score += 0.2
        if self.amount_sats > 10000000:  # > 0.1 BTC
            score += 0.3
        if self.amount_sats > 100000000:  # > 1 BTC
            score += 0.5
        
        # Risk factor-based scoring
        score += len(self.risk_factors) * 0.1
        
        # Screening results
        if self.screening_results.get('sanctions_match'):
            score += 0.8
        if self.screening_results.get('pep_match'):
            score += 0.6
        if self.screening_results.get('adverse_media'):
            score += 0.4
        
        return min(score, 1.0)

@dataclass
class AuditEvent:
    """Immutable audit log event."""
    event_id: str
    event_type: AuditEventType
    user_id: Optional[str]
    resource_id: Optional[str]
    action: str
    outcome: str
    details: Dict[str, Any] = field(default_factory=dict)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    hash_chain: Optional[str] = None  # For audit trail integrity
    
    def calculate_hash(self, previous_hash: str = "") -> str:
        """Calculate hash for audit trail integrity."""
        data = f"{self.event_id}{self.timestamp.isoformat()}{self.action}{previous_hash}"
        return hashlib.sha256(data.encode()).hexdigest()

@dataclass
class ComplianceAlert:
    """Compliance monitoring alert."""
    alert_id: str
    alert_type: str
    severity: str
    description: str
    entity_id: str
    entity_type: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    resolution_notes: Optional[str] = None
    
    @property
    def is_resolved(self) -> bool:
        """Check if alert is resolved."""
        return self.resolved_at is not None

class ComplianceManager:
    """Enterprise compliance and regulatory framework."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the compliance manager."""
        self.config = config or self._get_default_config()
        
        # Compliance data
        self.kyc_records: Dict[str, KYCRecord] = {}
        self.personal_data: Dict[str, PersonalData] = {}
        self.compliance_transactions: List[ComplianceTransaction] = []
        self.audit_trail: List[AuditEvent] = []
        self.compliance_alerts: Dict[str, ComplianceAlert] = {}
        
        # Threading
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="compliance")
        self.monitoring_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        
        # Database and encryption
        self.db_path = Path(self.config.get('database_path', 'compliance.db'))
        self.encryption_key = self._get_or_create_encryption_key()
        
        # Initialize database
        self._init_database()
        
        # Load existing data
        self._load_data()
        
        # Sanctions and PEP lists
        self.sanctions_list: Set[str] = set()
        self.pep_list: Set[str] = set()
        self._load_screening_lists()
        
        logger.info("Compliance and regulatory framework initialized")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default compliance configuration."""
        return {
            'database_path': 'compliance.db',
            'enabled_frameworks': [
                ComplianceFramework.GDPR,
                ComplianceFramework.BSA_AML,
                ComplianceFramework.PCI_DSS
            ],
            'kyc_renewal_days': 365,  # Annual KYC renewal
            'data_retention': {
                'audit_logs': timedelta(days=2555),  # 7 years
                'transaction_records': timedelta(days=2555),  # 7 years
                'personal_data': timedelta(days=1095),  # 3 years default
                'kyc_records': timedelta(days=2190),  # 6 years
            },
            'risk_thresholds': {
                'high_value_transaction': 100000000,  # 1 BTC in sats
                'suspicious_frequency': 10,  # transactions per hour
                'max_daily_volume': 1000000000,  # 10 BTC in sats
            },
            'reporting': {
                'ctr_threshold': 1000000000,  # CTR reporting threshold
                'sar_enabled': True,  # Suspicious Activity Reports
                'automated_reporting': True
            },
            'encryption_enabled': True,
            'audit_all_actions': True,
            'monitoring_interval': 300  # 5 minutes
        }
    
    def _get_or_create_encryption_key(self) -> Optional[bytes]:
        """Get or create encryption key for sensitive data."""
        if not HAS_CRYPTOGRAPHY:
            logger.warning("Cryptography not available, compliance data will not be encrypted")
            return None
        
        key_file = Path('compliance_encryption.key')
        
        if key_file.exists():
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            # Generate key from password (in production, use proper key management)
            password = "compliance_key_blncs_2024".encode()  # Should be from secure config
            salt = b"compliance_salt_blncs"
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            
            with open(key_file, 'wb') as f:
                f.write(key)
            
            return key
    
    def _encrypt_data(self, data: str) -> str:
        """Encrypt sensitive compliance data."""
        if not self.encryption_key or not HAS_CRYPTOGRAPHY:
            return data
        
        try:
            fernet = Fernet(self.encryption_key)
            encrypted = fernet.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Failed to encrypt compliance data: {e}")
            return data
    
    def _decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive compliance data."""
        if not self.encryption_key or not HAS_CRYPTOGRAPHY:
            return encrypted_data
        
        try:
            fernet = Fernet(self.encryption_key)
            decoded = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = fernet.decrypt(decoded)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Failed to decrypt compliance data: {e}")
            return encrypted_data
    
    def _init_database(self) -> None:
        """Initialize compliance database."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                # KYC records table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS kyc_records (
                        kyc_id TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        status TEXT NOT NULL,
                        risk_level TEXT NOT NULL,
                        verification_data TEXT,
                        documents TEXT,
                        verified_at TEXT,
                        expires_at TEXT,
                        verifier_id TEXT,
                        rejection_reason TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                ''')
                
                # Personal data table (GDPR compliance)
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS personal_data (
                        data_id TEXT PRIMARY KEY,
                        subject_id TEXT NOT NULL,
                        data_type TEXT NOT NULL,
                        encrypted_data TEXT NOT NULL,
                        purpose TEXT NOT NULL,
                        legal_basis TEXT NOT NULL,
                        retention_period INTEGER NOT NULL,
                        created_at TEXT NOT NULL,
                        encrypted BOOLEAN DEFAULT 1,
                        anonymized BOOLEAN DEFAULT 0
                    )
                ''')
                
                # Compliance transactions table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS compliance_transactions (
                        transaction_id TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        transaction_type TEXT NOT NULL,
                        amount_sats INTEGER NOT NULL,
                        counterparty TEXT,
                        risk_score REAL NOT NULL,
                        risk_factors TEXT,
                        screening_results TEXT,
                        flagged BOOLEAN DEFAULT 0,
                        reported BOOLEAN DEFAULT 0,
                        timestamp TEXT NOT NULL,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Audit events table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS audit_events (
                        event_id TEXT PRIMARY KEY,
                        event_type TEXT NOT NULL,
                        user_id TEXT,
                        resource_id TEXT,
                        action TEXT NOT NULL,
                        outcome TEXT NOT NULL,
                        details TEXT,
                        ip_address TEXT,
                        user_agent TEXT,
                        timestamp TEXT NOT NULL,
                        hash_chain TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Compliance alerts table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS compliance_alerts (
                        alert_id TEXT PRIMARY KEY,
                        alert_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        description TEXT NOT NULL,
                        entity_id TEXT NOT NULL,
                        entity_type TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        resolved_at TEXT,
                        resolved_by TEXT,
                        resolution_notes TEXT
                    )
                ''')
                
                # Sanctions and PEP screening lists
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS screening_lists (
                        list_type TEXT NOT NULL,
                        entity_name TEXT NOT NULL,
                        entity_id TEXT,
                        risk_category TEXT,
                        source TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY (list_type, entity_name)
                    )
                ''')
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to initialize compliance database: {e}")
            raise
    
    def _load_data(self) -> None:
        """Load existing compliance data."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                # Load KYC records
                cursor = conn.execute('SELECT * FROM kyc_records')
                for row in cursor.fetchall():
                    kyc_record = KYCRecord(
                        kyc_id=row[0],
                        user_id=row[1],
                        status=KYCStatus(row[2]),
                        risk_level=RiskLevel(row[3]),
                        verification_data=json.loads(self._decrypt_data(row[4])) if row[4] else {},
                        documents=json.loads(row[5]) if row[5] else [],
                        verified_at=datetime.fromisoformat(row[6]) if row[6] else None,
                        expires_at=datetime.fromisoformat(row[7]) if row[7] else None,
                        verifier_id=row[8],
                        rejection_reason=row[9],
                        created_at=datetime.fromisoformat(row[10]),
                        updated_at=datetime.fromisoformat(row[11])
                    )
                    self.kyc_records[row[0]] = kyc_record
                
                # Load personal data
                cursor = conn.execute('SELECT * FROM personal_data')
                for row in cursor.fetchall():
                    personal_data = PersonalData(
                        data_id=row[0],
                        subject_id=row[1],
                        data_type=row[2],
                        data_value=self._decrypt_data(row[3]),
                        purpose=row[4],
                        legal_basis=row[5],
                        retention_period=timedelta(seconds=row[6]),
                        created_at=datetime.fromisoformat(row[7]),
                        encrypted=bool(row[8]),
                        anonymized=bool(row[9])
                    )
                    self.personal_data[row[0]] = personal_data
                
                # Load compliance alerts
                cursor = conn.execute('SELECT * FROM compliance_alerts WHERE resolved_at IS NULL')
                for row in cursor.fetchall():
                    alert = ComplianceAlert(
                        alert_id=row[0],
                        alert_type=row[1],
                        severity=row[2],
                        description=row[3],
                        entity_id=row[4],
                        entity_type=row[5],
                        created_at=datetime.fromisoformat(row[6]),
                        resolved_at=datetime.fromisoformat(row[7]) if row[7] else None,
                        resolved_by=row[8],
                        resolution_notes=row[9]
                    )
                    self.compliance_alerts[row[0]] = alert
                
        except Exception as e:
            logger.error(f"Failed to load compliance data: {e}")
    
    def _load_screening_lists(self) -> None:
        """Load sanctions and PEP screening lists."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                # Load sanctions list
                cursor = conn.execute('SELECT entity_name FROM screening_lists WHERE list_type = "sanctions"')
                for row in cursor.fetchall():
                    self.sanctions_list.add(row[0].lower())
                
                # Load PEP list
                cursor = conn.execute('SELECT entity_name FROM screening_lists WHERE list_type = "pep"')
                for row in cursor.fetchall():
                    self.pep_list.add(row[0].lower())
                
                logger.info(f"Loaded {len(self.sanctions_list)} sanctions entries and {len(self.pep_list)} PEP entries")
                
        except Exception as e:
            logger.error(f"Failed to load screening lists: {e}")
    
    # KYC Management
    async def initiate_kyc(self, user_id: str, initial_data: Dict[str, Any]) -> str:
        """Initiate KYC verification process."""
        kyc_id = str(uuid.uuid4())
        
        kyc_record = KYCRecord(
            kyc_id=kyc_id,
            user_id=user_id,
            status=KYCStatus.PENDING,
            risk_level=RiskLevel.MEDIUM,  # Default to medium until assessment
            verification_data=initial_data
        )
        
        # Perform initial risk assessment
        kyc_record.risk_level = await self._assess_kyc_risk(initial_data)
        
        self.kyc_records[kyc_id] = kyc_record
        await self._save_kyc_record(kyc_record)
        
        # Log audit event
        await self.log_audit_event(
            event_type=AuditEventType.COMPLIANCE_CHECK,
            user_id=user_id,
            action="kyc_initiated",
            outcome="success",
            details={"kyc_id": kyc_id, "risk_level": kyc_record.risk_level.value}
        )
        
        logger.info(f"Initiated KYC verification {kyc_id} for user {user_id}")
        return kyc_id
    
    async def _assess_kyc_risk(self, data: Dict[str, Any]) -> RiskLevel:
        """Assess KYC risk level based on provided data."""
        risk_score = 0.0
        
        # Country risk assessment
        country = data.get('country', '').upper()
        high_risk_countries = {'AF', 'IR', 'KP', 'SY'}  # Example high-risk countries
        if country in high_risk_countries:
            risk_score += 0.4
        
        # Age assessment
        age = data.get('age', 0)
        if age < 18:
            risk_score += 0.8  # Minors are high risk
        elif age > 80:
            risk_score += 0.2  # Elderly might need additional verification
        
        # Occupation assessment
        occupation = data.get('occupation', '').lower()
        high_risk_occupations = {'politician', 'military', 'diplomat', 'judge'}
        if any(occ in occupation for occ in high_risk_occupations):
            risk_score += 0.3
        
        # Name screening
        full_name = f"{data.get('first_name', '')} {data.get('last_name', '')}".lower()
        if self._screen_name(full_name):
            risk_score += 0.6
        
        # Determine risk level
        if risk_score >= 0.7:
            return RiskLevel.CRITICAL
        elif risk_score >= 0.5:
            return RiskLevel.HIGH
        elif risk_score >= 0.3:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _screen_name(self, name: str) -> bool:
        """Screen name against sanctions and PEP lists."""
        name_lower = name.lower()
        
        # Check exact matches first
        if name_lower in self.sanctions_list or name_lower in self.pep_list:
            return True
        
        # Check for partial matches (fuzzy matching could be added here)
        for sanctions_name in self.sanctions_list:
            if len(sanctions_name) > 5 and sanctions_name in name_lower:
                return True
        
        return False
    
    async def update_kyc_status(self, kyc_id: str, status: KYCStatus, 
                               verifier_id: Optional[str] = None,
                               rejection_reason: Optional[str] = None) -> bool:
        """Update KYC verification status."""
        kyc_record = self.kyc_records.get(kyc_id)
        if not kyc_record:
            return False
        
        old_status = kyc_record.status
        kyc_record.status = status
        kyc_record.updated_at = datetime.utcnow()
        
        if status == KYCStatus.VERIFIED:
            kyc_record.verified_at = datetime.utcnow()
            kyc_record.verifier_id = verifier_id
            # Set expiration date
            renewal_days = self.config.get('kyc_renewal_days', 365)
            kyc_record.expires_at = datetime.utcnow() + timedelta(days=renewal_days)
        elif status == KYCStatus.REJECTED:
            kyc_record.rejection_reason = rejection_reason
        
        await self._save_kyc_record(kyc_record)
        
        # Log audit event
        await self.log_audit_event(
            event_type=AuditEventType.COMPLIANCE_CHECK,
            user_id=kyc_record.user_id,
            action="kyc_status_updated",
            outcome="success",
            details={
                "kyc_id": kyc_id,
                "old_status": old_status.value,
                "new_status": status.value,
                "verifier_id": verifier_id
            }
        )
        
        logger.info(f"Updated KYC {kyc_id} status from {old_status.value} to {status.value}")
        return True
    
    async def _save_kyc_record(self, kyc_record: KYCRecord) -> None:
        """Save KYC record to database."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                encrypted_data = self._encrypt_data(json.dumps(kyc_record.verification_data))
                
                conn.execute('''
                    INSERT OR REPLACE INTO kyc_records (
                        kyc_id, user_id, status, risk_level, verification_data,
                        documents, verified_at, expires_at, verifier_id,
                        rejection_reason, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    kyc_record.kyc_id,
                    kyc_record.user_id,
                    kyc_record.status.value,
                    kyc_record.risk_level.value,
                    encrypted_data,
                    json.dumps(kyc_record.documents),
                    kyc_record.verified_at.isoformat() if kyc_record.verified_at else None,
                    kyc_record.expires_at.isoformat() if kyc_record.expires_at else None,
                    kyc_record.verifier_id,
                    kyc_record.rejection_reason,
                    kyc_record.created_at.isoformat(),
                    kyc_record.updated_at.isoformat()
                ))
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to save KYC record {kyc_record.kyc_id}: {e}")
    
    def get_kyc_status(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get KYC status for user."""
        for kyc_record in self.kyc_records.values():
            if kyc_record.user_id == user_id:
                return {
                    'kyc_id': kyc_record.kyc_id,
                    'status': kyc_record.status.value,
                    'risk_level': kyc_record.risk_level.value,
                    'verified_at': kyc_record.verified_at.isoformat() if kyc_record.verified_at else None,
                    'expires_at': kyc_record.expires_at.isoformat() if kyc_record.expires_at else None,
                    'needs_renewal': kyc_record.needs_renewal()
                }
        return None
    
    # Transaction Monitoring
    async def monitor_transaction(self, transaction_id: str, user_id: str,
                                 transaction_type: TransactionType,
                                 amount_sats: int, counterparty: Optional[str] = None) -> ComplianceTransaction:
        """Monitor transaction for compliance issues."""
        tx = ComplianceTransaction(
            transaction_id=transaction_id,
            user_id=user_id,
            transaction_type=transaction_type,
            amount_sats=amount_sats,
            counterparty=counterparty
        )
        
        # Perform compliance screening
        await self._screen_transaction(tx)
        
        # Calculate risk score
        tx.risk_score = tx.calculate_risk_score()
        
        # Check if transaction should be flagged
        if tx.risk_score > 0.7 or tx.screening_results.get('sanctions_match'):
            tx.flagged = True
            
            # Create compliance alert
            await self._create_compliance_alert(
                alert_type="high_risk_transaction",
                severity="high",
                description=f"High risk transaction detected: {transaction_id}",
                entity_id=transaction_id,
                entity_type="transaction"
            )
        
        self.compliance_transactions.append(tx)
        await self._save_compliance_transaction(tx)
        
        # Check reporting thresholds
        await self._check_reporting_requirements(tx)
        
        # Log audit event
        await self.log_audit_event(
            event_type=AuditEventType.COMPLIANCE_CHECK,
            user_id=user_id,
            action="transaction_monitored",
            outcome="success",
            details={
                "transaction_id": transaction_id,
                "risk_score": tx.risk_score,
                "flagged": tx.flagged
            }
        )
        
        return tx
    
    async def _screen_transaction(self, tx: ComplianceTransaction) -> None:
        """Screen transaction for compliance issues."""
        screening_results = {
            'sanctions_match': False,
            'pep_match': False,
            'adverse_media': False,
            'high_risk_jurisdiction': False
        }
        
        # Screen counterparty if available
        if tx.counterparty:
            counterparty_lower = tx.counterparty.lower()
            
            if counterparty_lower in self.sanctions_list:
                screening_results['sanctions_match'] = True
                tx.risk_factors.append("sanctions_list_match")
            
            if counterparty_lower in self.pep_list:
                screening_results['pep_match'] = True
                tx.risk_factors.append("pep_list_match")
        
        # Amount-based risk factors
        thresholds = self.config.get('risk_thresholds', {})
        if tx.amount_sats >= thresholds.get('high_value_transaction', 100000000):
            tx.risk_factors.append("high_value_transaction")
        
        # Frequency analysis
        recent_transactions = await self._get_recent_transactions(tx.user_id, hours=1)
        if len(recent_transactions) >= thresholds.get('suspicious_frequency', 10):
            tx.risk_factors.append("high_frequency_transactions")
        
        # Daily volume check
        daily_volume = await self._get_daily_volume(tx.user_id)
        if daily_volume >= thresholds.get('max_daily_volume', 1000000000):
            tx.risk_factors.append("high_daily_volume")
        
        tx.screening_results = screening_results
    
    async def _get_recent_transactions(self, user_id: str, hours: int = 24) -> List[ComplianceTransaction]:
        """Get recent transactions for user."""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        return [
            tx for tx in self.compliance_transactions
            if tx.user_id == user_id and tx.timestamp > cutoff_time
        ]
    
    async def _get_daily_volume(self, user_id: str) -> int:
        """Get daily transaction volume for user."""
        today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        daily_transactions = [
            tx for tx in self.compliance_transactions
            if tx.user_id == user_id and tx.timestamp >= today_start
        ]
        return sum(tx.amount_sats for tx in daily_transactions)
    
    async def _check_reporting_requirements(self, tx: ComplianceTransaction) -> None:
        """Check if transaction meets reporting requirements."""
        reporting_config = self.config.get('reporting', {})
        
        # CTR (Currency Transaction Report) threshold
        ctr_threshold = reporting_config.get('ctr_threshold', 1000000000)  # 10 BTC
        if tx.amount_sats >= ctr_threshold:
            if reporting_config.get('automated_reporting', True):
                await self._generate_ctr_report(tx)
        
        # SAR (Suspicious Activity Report)
        if tx.flagged and reporting_config.get('sar_enabled', True):
            await self._generate_sar_report(tx)
    
    async def _generate_ctr_report(self, tx: ComplianceTransaction) -> None:
        """Generate Currency Transaction Report."""
        report_data = {
            'report_type': 'CTR',
            'transaction_id': tx.transaction_id,
            'user_id': tx.user_id,
            'amount_sats': tx.amount_sats,
            'timestamp': tx.timestamp.isoformat(),
            'generated_at': datetime.utcnow().isoformat()
        }
        
        # In a real implementation, this would submit to FinCEN or relevant authority
        logger.info(f"Generated CTR report for transaction {tx.transaction_id}")
        
        tx.reported = True
    
    async def _generate_sar_report(self, tx: ComplianceTransaction) -> None:
        """Generate Suspicious Activity Report."""
        report_data = {
            'report_type': 'SAR',
            'transaction_id': tx.transaction_id,
            'user_id': tx.user_id,
            'amount_sats': tx.amount_sats,
            'risk_score': tx.risk_score,
            'risk_factors': tx.risk_factors,
            'screening_results': tx.screening_results,
            'timestamp': tx.timestamp.isoformat(),
            'generated_at': datetime.utcnow().isoformat()
        }
        
        # In a real implementation, this would submit to FinCEN or relevant authority
        logger.warning(f"Generated SAR report for suspicious transaction {tx.transaction_id}")
        
        tx.reported = True
    
    async def _save_compliance_transaction(self, tx: ComplianceTransaction) -> None:
        """Save compliance transaction to database."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO compliance_transactions (
                        transaction_id, user_id, transaction_type, amount_sats,
                        counterparty, risk_score, risk_factors, screening_results,
                        flagged, reported, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    tx.transaction_id,
                    tx.user_id,
                    tx.transaction_type.value,
                    tx.amount_sats,
                    tx.counterparty,
                    tx.risk_score,
                    json.dumps(tx.risk_factors),
                    json.dumps(tx.screening_results),
                    tx.flagged,
                    tx.reported,
                    tx.timestamp.isoformat()
                ))
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to save compliance transaction {tx.transaction_id}: {e}")
    
    # Personal Data Management (GDPR)
    async def store_personal_data(self, subject_id: str, data_type: str, 
                                 data_value: str, purpose: str, 
                                 legal_basis: str, retention_days: int = 1095) -> str:
        """Store personal data with GDPR compliance."""
        data_id = str(uuid.uuid4())
        
        personal_data = PersonalData(
            data_id=data_id,
            subject_id=subject_id,
            data_type=data_type,
            data_value=data_value,
            purpose=purpose,
            legal_basis=legal_basis,
            retention_period=timedelta(days=retention_days)
        )
        
        self.personal_data[data_id] = personal_data
        await self._save_personal_data(personal_data)
        
        # Log audit event
        await self.log_audit_event(
            event_type=AuditEventType.DATA_ACCESS,
            user_id=subject_id,
            action="personal_data_stored",
            outcome="success",
            details={"data_id": data_id, "data_type": data_type, "purpose": purpose}
        )
        
        return data_id
    
    async def _save_personal_data(self, personal_data: PersonalData) -> None:
        """Save personal data to database."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                encrypted_data = self._encrypt_data(personal_data.data_value)
                
                conn.execute('''
                    INSERT OR REPLACE INTO personal_data (
                        data_id, subject_id, data_type, encrypted_data,
                        purpose, legal_basis, retention_period, created_at,
                        encrypted, anonymized
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    personal_data.data_id,
                    personal_data.subject_id,
                    personal_data.data_type,
                    encrypted_data,
                    personal_data.purpose,
                    personal_data.legal_basis,
                    int(personal_data.retention_period.total_seconds()),
                    personal_data.created_at.isoformat(),
                    personal_data.encrypted,
                    personal_data.anonymized
                ))
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to save personal data {personal_data.data_id}: {e}")
    
    async def delete_personal_data(self, subject_id: str) -> int:
        """Delete personal data for subject (right to be forgotten)."""
        deleted_count = 0
        to_delete = []
        
        for data_id, personal_data in self.personal_data.items():
            if personal_data.subject_id == subject_id:
                to_delete.append(data_id)
        
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                for data_id in to_delete:
                    conn.execute('DELETE FROM personal_data WHERE data_id = ?', (data_id,))
                    del self.personal_data[data_id]
                    deleted_count += 1
                
                conn.commit()
                
            # Log audit event
            await self.log_audit_event(
                event_type=AuditEventType.DATA_ACCESS,
                user_id=subject_id,
                action="personal_data_deleted",
                outcome="success",
                details={"deleted_records": deleted_count}
            )
            
            logger.info(f"Deleted {deleted_count} personal data records for subject {subject_id}")
            
        except Exception as e:
            logger.error(f"Failed to delete personal data for subject {subject_id}: {e}")
        
        return deleted_count
    
    async def anonymize_expired_data(self) -> int:
        """Anonymize expired personal data."""
        anonymized_count = 0
        
        for personal_data in self.personal_data.values():
            if personal_data.is_expired() and not personal_data.anonymized:
                # Anonymize the data
                personal_data.data_value = self._anonymize_data(personal_data.data_value, personal_data.data_type)
                personal_data.anonymized = True
                
                await self._save_personal_data(personal_data)
                anonymized_count += 1
        
        if anonymized_count > 0:
            logger.info(f"Anonymized {anonymized_count} expired personal data records")
        
        return anonymized_count
    
    def _anonymize_data(self, data_value: str, data_type: str) -> str:
        """Anonymize personal data based on type."""
        if data_type in ['email', 'phone']:
            return hashlib.sha256(data_value.encode()).hexdigest()[:16]
        elif data_type == 'name':
            return f"Anonymous_{hashlib.sha256(data_value.encode()).hexdigest()[:8]}"
        elif data_type == 'address':
            return "Address anonymized"
        else:
            return f"Anonymized_{hashlib.sha256(data_value.encode()).hexdigest()[:12]}"
    
    # Audit Logging
    async def log_audit_event(self, event_type: AuditEventType, action: str, 
                             outcome: str, user_id: Optional[str] = None,
                             resource_id: Optional[str] = None,
                             details: Optional[Dict[str, Any]] = None,
                             ip_address: Optional[str] = None,
                             user_agent: Optional[str] = None) -> str:
        """Log immutable audit event."""
        event_id = str(uuid.uuid4())
        
        # Get previous hash for integrity chain
        previous_hash = ""
        if self.audit_trail:
            previous_hash = self.audit_trail[-1].hash_chain or ""
        
        audit_event = AuditEvent(
            event_id=event_id,
            event_type=event_type,
            user_id=user_id,
            resource_id=resource_id,
            action=action,
            outcome=outcome,
            details=details or {},
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Calculate hash for integrity
        audit_event.hash_chain = audit_event.calculate_hash(previous_hash)
        
        self.audit_trail.append(audit_event)
        await self._save_audit_event(audit_event)
        
        return event_id
    
    async def _save_audit_event(self, audit_event: AuditEvent) -> None:
        """Save audit event to database."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute('''
                    INSERT INTO audit_events (
                        event_id, event_type, user_id, resource_id, action,
                        outcome, details, ip_address, user_agent, timestamp, hash_chain
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    audit_event.event_id,
                    audit_event.event_type.value,
                    audit_event.user_id,
                    audit_event.resource_id,
                    audit_event.action,
                    audit_event.outcome,
                    json.dumps(audit_event.details),
                    audit_event.ip_address,
                    audit_event.user_agent,
                    audit_event.timestamp.isoformat(),
                    audit_event.hash_chain
                ))
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to save audit event {audit_event.event_id}: {e}")
    
    def verify_audit_integrity(self) -> bool:
        """Verify integrity of audit trail."""
        if not self.audit_trail:
            return True
        
        previous_hash = ""
        for event in self.audit_trail:
            expected_hash = event.calculate_hash(previous_hash)
            if event.hash_chain != expected_hash:
                logger.error(f"Audit trail integrity violation at event {event.event_id}")
                return False
            previous_hash = event.hash_chain
        
        return True
    
    # Compliance Alerts
    async def _create_compliance_alert(self, alert_type: str, severity: str,
                                      description: str, entity_id: str,
                                      entity_type: str) -> str:
        """Create compliance alert."""
        alert_id = str(uuid.uuid4())
        
        alert = ComplianceAlert(
            alert_id=alert_id,
            alert_type=alert_type,
            severity=severity,
            description=description,
            entity_id=entity_id,
            entity_type=entity_type
        )
        
        self.compliance_alerts[alert_id] = alert
        await self._save_compliance_alert(alert)
        
        logger.warning(f"Created compliance alert {alert_id}: {description}")
        return alert_id
    
    async def _save_compliance_alert(self, alert: ComplianceAlert) -> None:
        """Save compliance alert to database."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO compliance_alerts (
                        alert_id, alert_type, severity, description,
                        entity_id, entity_type, created_at, resolved_at,
                        resolved_by, resolution_notes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    alert.alert_id,
                    alert.alert_type,
                    alert.severity,
                    alert.description,
                    alert.entity_id,
                    alert.entity_type,
                    alert.created_at.isoformat(),
                    alert.resolved_at.isoformat() if alert.resolved_at else None,
                    alert.resolved_by,
                    alert.resolution_notes
                ))
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to save compliance alert {alert.alert_id}: {e}")
    
    async def resolve_compliance_alert(self, alert_id: str, resolved_by: str,
                                      resolution_notes: str) -> bool:
        """Resolve compliance alert."""
        alert = self.compliance_alerts.get(alert_id)
        if not alert or alert.is_resolved:
            return False
        
        alert.resolved_at = datetime.utcnow()
        alert.resolved_by = resolved_by
        alert.resolution_notes = resolution_notes
        
        await self._save_compliance_alert(alert)
        
        # Log audit event
        await self.log_audit_event(
            event_type=AuditEventType.COMPLIANCE_CHECK,
            user_id=resolved_by,
            action="compliance_alert_resolved",
            outcome="success",
            details={"alert_id": alert_id, "alert_type": alert.alert_type}
        )
        
        logger.info(f"Resolved compliance alert {alert_id} by {resolved_by}")
        return True
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get active compliance alerts."""
        active_alerts = []
        
        for alert in self.compliance_alerts.values():
            if not alert.is_resolved:
                active_alerts.append({
                    'alert_id': alert.alert_id,
                    'alert_type': alert.alert_type,
                    'severity': alert.severity,
                    'description': alert.description,
                    'entity_id': alert.entity_id,
                    'entity_type': alert.entity_type,
                    'created_at': alert.created_at.isoformat()
                })
        
        # Sort by severity and creation time
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        active_alerts.sort(key=lambda x: (severity_order.get(x['severity'], 4), x['created_at']))
        
        return active_alerts
    
    # Monitoring and Maintenance
    def start_monitoring(self) -> None:
        """Start compliance monitoring thread."""
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            logger.warning("Compliance monitoring already running")
            return
        
        self.stop_event.clear()
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            name="compliance-monitor",
            daemon=True
        )
        self.monitoring_thread.start()
        
        logger.info("Started compliance monitoring")
    
    def stop_monitoring(self) -> None:
        """Stop compliance monitoring thread."""
        if not self.monitoring_thread or not self.monitoring_thread.is_alive():
            return
        
        self.stop_event.set()
        self.monitoring_thread.join(timeout=5.0)
        
        if self.monitoring_thread.is_alive():
            logger.warning("Compliance monitoring thread did not stop gracefully")
        else:
            logger.info("Stopped compliance monitoring")
    
    def _monitoring_loop(self) -> None:
        """Main compliance monitoring loop."""
        interval = self.config.get('monitoring_interval', 300)
        
        while not self.stop_event.is_set():
            try:
                # Check for expired KYC records
                asyncio.run_coroutine_threadsafe(
                    self._check_kyc_renewals(),
                    asyncio.get_event_loop()
                )
                
                # Anonymize expired personal data
                asyncio.run_coroutine_threadsafe(
                    self.anonymize_expired_data(),
                    asyncio.get_event_loop()
                )
                
                # Update screening lists (in real implementation)
                # asyncio.run_coroutine_threadsafe(
                #     self._update_screening_lists(),
                #     asyncio.get_event_loop()
                # )
                
                # Wait for next monitoring interval
                if self.stop_event.wait(interval):
                    break
                    
            except Exception as e:
                logger.error(f"Error in compliance monitoring loop: {e}")
                # Wait before retrying
                if self.stop_event.wait(60):
                    break
    
    async def _check_kyc_renewals(self) -> None:
        """Check for KYC records that need renewal."""
        renewal_alerts = 0
        
        for kyc_record in self.kyc_records.values():
            if kyc_record.needs_renewal() and kyc_record.status == KYCStatus.VERIFIED:
                # Create alert for KYC renewal needed
                await self._create_compliance_alert(
                    alert_type="kyc_renewal_required",
                    severity="medium",
                    description=f"KYC renewal required for user {kyc_record.user_id}",
                    entity_id=kyc_record.user_id,
                    entity_type="user"
                )
                renewal_alerts += 1
        
        if renewal_alerts > 0:
            logger.info(f"Created {renewal_alerts} KYC renewal alerts")
    
    async def get_compliance_summary(self) -> Dict[str, Any]:
        """Get compliance status summary."""
        # KYC statistics
        kyc_stats = {
            'total': len(self.kyc_records),
            'verified': len([k for k in self.kyc_records.values() if k.status == KYCStatus.VERIFIED]),
            'pending': len([k for k in self.kyc_records.values() if k.status == KYCStatus.PENDING]),
            'expired': len([k for k in self.kyc_records.values() if k.needs_renewal()])
        }
        
        # Transaction monitoring
        recent_transactions = await self._get_recent_transactions("", hours=24)  # All users
        transaction_stats = {
            'total_24h': len(recent_transactions),
            'flagged_24h': len([t for t in recent_transactions if t.flagged]),
            'reported_24h': len([t for t in recent_transactions if t.reported]),
            'avg_risk_score': sum(t.risk_score for t in recent_transactions) / len(recent_transactions) if recent_transactions else 0
        }
        
        # Personal data
        personal_data_stats = {
            'total_records': len(self.personal_data),
            'expired': len([d for d in self.personal_data.values() if d.is_expired()]),
            'anonymized': len([d for d in self.personal_data.values() if d.anonymized])
        }
        
        # Alerts
        alert_stats = {
            'active_alerts': len([a for a in self.compliance_alerts.values() if not a.is_resolved]),
            'critical_alerts': len([a for a in self.compliance_alerts.values() if not a.is_resolved and a.severity == 'critical']),
            'high_alerts': len([a for a in self.compliance_alerts.values() if not a.is_resolved and a.severity == 'high'])
        }
        
        return {
            'kyc': kyc_stats,
            'transactions': transaction_stats,
            'personal_data': personal_data_stats,
            'alerts': alert_stats,
            'audit_trail_integrity': self.verify_audit_integrity(),
            'enabled_frameworks': [f.value for f in self.config.get('enabled_frameworks', [])]
        }
    
    async def shutdown(self) -> None:
        """Shutdown the compliance manager."""
        logger.info("Shutting down compliance and regulatory framework...")
        
        self.stop_monitoring()
        self.executor.shutdown(wait=True, timeout=10.0)
        
        # Final data anonymization
        await self.anonymize_expired_data()
        
        logger.info("Compliance and regulatory framework shutdown complete")

# Global instance
_compliance_manager: Optional[ComplianceManager] = None

def get_compliance_manager() -> ComplianceManager:
    """Get the global compliance manager instance."""
    global _compliance_manager
    
    if _compliance_manager is None:
        _compliance_manager = ComplianceManager()
    
    return _compliance_manager

def initialize_compliance(config: Optional[Dict[str, Any]] = None) -> ComplianceManager:
    """Initialize the global compliance manager."""
    global _compliance_manager
    
    _compliance_manager = ComplianceManager(config)
    _compliance_manager.start_monitoring()
    
    logger.info("Initialized compliance and regulatory framework")
    return _compliance_manager