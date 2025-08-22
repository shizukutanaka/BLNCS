# BLRCS Comprehensive Audit System
# Complete audit trail and compliance logging for national-level systems

import os
import json
import hashlib
import hmac
import secrets
import time
import logging
import threading
import gzip
import sqlite3
from typing import Dict, List, Any, Optional, Set, Tuple, Union, Callable, Iterator
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, deque
import queue
import asyncio
import csv
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

class AuditEventType(Enum):
    """Types of audit events"""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED = "access_denied"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    SYSTEM_CONFIGURATION = "system_configuration"
    SECURITY_EVENT = "security_event"
    ADMINISTRATIVE_ACTION = "administrative_action"
    ERROR_EVENT = "error_event"
    COMPLIANCE_EVENT = "compliance_event"
    THREAT_DETECTED = "threat_detected"
    VULNERABILITY_FOUND = "vulnerability_found"
    ENCRYPTION_EVENT = "encryption_event"
    BACKUP_EVENT = "backup_event"
    RECOVERY_EVENT = "recovery_event"
    PERFORMANCE_EVENT = "performance_event"
    NETWORK_EVENT = "network_event"
    FILE_OPERATION = "file_operation"
    API_CALL = "api_call"

class AuditLevel(Enum):
    """Audit detail levels"""
    MINIMAL = 1    # Critical events only
    STANDARD = 2   # Standard business events
    DETAILED = 3   # Detailed operational events
    VERBOSE = 4    # All events including debug
    FORENSIC = 5   # Maximum detail for forensic analysis

class ComplianceStandard(Enum):
    """Compliance standards for audit logging"""
    SOX = "sox"           # Sarbanes-Oxley
    HIPAA = "hipaa"       # Health Insurance Portability and Accountability Act
    PCI_DSS = "pci_dss"   # Payment Card Industry Data Security Standard
    GDPR = "gdpr"         # General Data Protection Regulation
    ISO_27001 = "iso_27001"
    NIST = "nist"
    FedRAMP = "fedramp"
    CMMC = "cmmc"         # Cybersecurity Maturity Model Certification
    FISMA = "fisma"       # Federal Information Security Management Act

class AuditStatus(Enum):
    """Audit record status"""
    ACTIVE = "active"
    ARCHIVED = "archived"
    DELETED = "deleted"
    ENCRYPTED = "encrypted"
    EXPORTED = "exported"

@dataclass
class AuditEvent:
    """Individual audit event record"""
    id: str
    timestamp: datetime
    event_type: AuditEventType
    level: AuditLevel
    source: str
    actor: str = ""  # Who performed the action
    target: str = ""  # What was acted upon
    action: str = ""  # What action was performed
    outcome: str = "unknown"  # success, failure, error
    details: Dict[str, Any] = field(default_factory=dict)
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    tags: Set[str] = field(default_factory=set)
    compliance_flags: Set[ComplianceStandard] = field(default_factory=set)
    risk_score: float = 0.0
    checksum: Optional[str] = None
    encrypted: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Calculate checksum for integrity verification"""
        if not self.checksum:
            self.checksum = self._calculate_checksum()
    
    def _calculate_checksum(self) -> str:
        """Calculate SHA-256 checksum of audit event"""
        # Create a deterministic string representation
        data = {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.value,
            'source': self.source,
            'actor': self.actor,
            'target': self.target,
            'action': self.action,
            'outcome': self.outcome,
            'details': json.dumps(self.details, sort_keys=True),
            'session_id': self.session_id,
            'ip_address': self.ip_address
        }
        
        content = json.dumps(data, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()
    
    def verify_integrity(self) -> bool:
        """Verify audit event integrity"""
        if not self.checksum:
            return False
        return self.checksum == self._calculate_checksum()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.value,
            'level': self.level.value,
            'source': self.source,
            'actor': self.actor,
            'target': self.target,
            'action': self.action,
            'outcome': self.outcome,
            'details': self.details,
            'session_id': self.session_id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'tags': list(self.tags),
            'compliance_flags': [flag.value for flag in self.compliance_flags],
            'risk_score': self.risk_score,
            'checksum': self.checksum,
            'encrypted': self.encrypted,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuditEvent':
        """Create from dictionary"""
        event = cls(
            id=data['id'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            event_type=AuditEventType(data['event_type']),
            level=AuditLevel(data['level']),
            source=data['source'],
            actor=data.get('actor', ''),
            target=data.get('target', ''),
            action=data.get('action', ''),
            outcome=data.get('outcome', 'unknown'),
            details=data.get('details', {}),
            session_id=data.get('session_id'),
            ip_address=data.get('ip_address'),
            user_agent=data.get('user_agent'),
            tags=set(data.get('tags', [])),
            compliance_flags=set(ComplianceStandard(flag) for flag in data.get('compliance_flags', [])),
            risk_score=data.get('risk_score', 0.0),
            checksum=data.get('checksum'),
            encrypted=data.get('encrypted', False),
            metadata=data.get('metadata', {})
        )
        return event

@dataclass
class AuditQuery:
    """Audit log query parameters"""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    event_types: Optional[List[AuditEventType]] = None
    actors: Optional[List[str]] = None
    targets: Optional[List[str]] = None
    outcomes: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    compliance_standards: Optional[List[ComplianceStandard]] = None
    risk_score_min: Optional[float] = None
    risk_score_max: Optional[float] = None
    ip_addresses: Optional[List[str]] = None
    session_ids: Optional[List[str]] = None
    text_search: Optional[str] = None
    limit: int = 1000
    offset: int = 0

class AuditStorage:
    """Audit log storage backend"""
    
    def __init__(self, storage_path: Path):
        self.storage_path = storage_path
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.db_path = self.storage_path / "audit.db"
        self.lock = threading.Lock()
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database for audit logs"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS audit_events (
                        id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        level INTEGER NOT NULL,
                        source TEXT NOT NULL,
                        actor TEXT,
                        target TEXT,
                        action TEXT,
                        outcome TEXT,
                        details TEXT,
                        session_id TEXT,
                        ip_address TEXT,
                        user_agent TEXT,
                        tags TEXT,
                        compliance_flags TEXT,
                        risk_score REAL,
                        checksum TEXT,
                        encrypted INTEGER,
                        metadata TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Create indexes for performance
                conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_events(timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_event_type ON audit_events(event_type)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_actor ON audit_events(actor)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_target ON audit_events(target)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_session_id ON audit_events(session_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_ip_address ON audit_events(ip_address)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_risk_score ON audit_events(risk_score)")
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to initialize audit database: {e}")
    
    def store_event(self, event: AuditEvent) -> bool:
        """Store audit event"""
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT INTO audit_events (
                            id, timestamp, event_type, level, source, actor, target,
                            action, outcome, details, session_id, ip_address, user_agent,
                            tags, compliance_flags, risk_score, checksum, encrypted, metadata
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        event.id,
                        event.timestamp.isoformat(),
                        event.event_type.value,
                        event.level.value,
                        event.source,
                        event.actor,
                        event.target,
                        event.action,
                        event.outcome,
                        json.dumps(event.details),
                        event.session_id,
                        event.ip_address,
                        event.user_agent,
                        json.dumps(list(event.tags)),
                        json.dumps([flag.value for flag in event.compliance_flags]),
                        event.risk_score,
                        event.checksum,
                        1 if event.encrypted else 0,
                        json.dumps(event.metadata)
                    ))
                    conn.commit()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to store audit event {event.id}: {e}")
            return False
    
    def query_events(self, query: AuditQuery) -> List[AuditEvent]:
        """Query audit events"""
        try:
            sql = "SELECT * FROM audit_events WHERE 1=1"
            params = []
            
            # Build query conditions
            if query.start_time:
                sql += " AND timestamp >= ?"
                params.append(query.start_time.isoformat())
            
            if query.end_time:
                sql += " AND timestamp <= ?"
                params.append(query.end_time.isoformat())
            
            if query.event_types:
                placeholders = ','.join('?' * len(query.event_types))
                sql += f" AND event_type IN ({placeholders})"
                params.extend([et.value for et in query.event_types])
            
            if query.actors:
                placeholders = ','.join('?' * len(query.actors))
                sql += f" AND actor IN ({placeholders})"
                params.extend(query.actors)
            
            if query.targets:
                placeholders = ','.join('?' * len(query.targets))
                sql += f" AND target IN ({placeholders})"
                params.extend(query.targets)
            
            if query.outcomes:
                placeholders = ','.join('?' * len(query.outcomes))
                sql += f" AND outcome IN ({placeholders})"
                params.extend(query.outcomes)
            
            if query.risk_score_min is not None:
                sql += " AND risk_score >= ?"
                params.append(query.risk_score_min)
            
            if query.risk_score_max is not None:
                sql += " AND risk_score <= ?"
                params.append(query.risk_score_max)
            
            if query.ip_addresses:
                placeholders = ','.join('?' * len(query.ip_addresses))
                sql += f" AND ip_address IN ({placeholders})"
                params.extend(query.ip_addresses)
            
            if query.session_ids:
                placeholders = ','.join('?' * len(query.session_ids))
                sql += f" AND session_id IN ({placeholders})"
                params.extend(query.session_ids)
            
            if query.text_search:
                sql += " AND (details LIKE ? OR action LIKE ? OR target LIKE ?)"
                search_term = f"%{query.text_search}%"
                params.extend([search_term, search_term, search_term])
            
            # Add ordering and pagination
            sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([query.limit, query.offset])
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(sql, params)
                rows = cursor.fetchall()
                
                events = []
                for row in rows:
                    event_data = {
                        'id': row[0],
                        'timestamp': row[1],
                        'event_type': row[2],
                        'level': row[3],
                        'source': row[4],
                        'actor': row[5] or '',
                        'target': row[6] or '',
                        'action': row[7] or '',
                        'outcome': row[8] or 'unknown',
                        'details': json.loads(row[9] or '{}'),
                        'session_id': row[10],
                        'ip_address': row[11],
                        'user_agent': row[12],
                        'tags': json.loads(row[13] or '[]'),
                        'compliance_flags': json.loads(row[14] or '[]'),
                        'risk_score': row[15] or 0.0,
                        'checksum': row[16],
                        'encrypted': bool(row[17]),
                        'metadata': json.loads(row[18] or '{}')
                    }
                    
                    event = AuditEvent.from_dict(event_data)
                    events.append(event)
                
                return events
                
        except Exception as e:
            logger.error(f"Failed to query audit events: {e}")
            return []
    
    def get_event_count(self, query: AuditQuery) -> int:
        """Get count of events matching query"""
        try:
            sql = "SELECT COUNT(*) FROM audit_events WHERE 1=1"
            params = []
            
            # Use same conditions as query_events but without LIMIT/OFFSET
            if query.start_time:
                sql += " AND timestamp >= ?"
                params.append(query.start_time.isoformat())
            
            if query.end_time:
                sql += " AND timestamp <= ?"
                params.append(query.end_time.isoformat())
            
            if query.event_types:
                placeholders = ','.join('?' * len(query.event_types))
                sql += f" AND event_type IN ({placeholders})"
                params.extend([et.value for et in query.event_types])
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(sql, params)
                return cursor.fetchone()[0]
                
        except Exception as e:
            logger.error(f"Failed to get event count: {e}")
            return 0
    
    def archive_old_events(self, days_old: int = 365) -> int:
        """Archive events older than specified days"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_old)
            
            with self.lock:
                # Export old events to archive file
                archive_query = AuditQuery(
                    end_time=cutoff_date,
                    limit=10000
                )
                
                old_events = self.query_events(archive_query)
                if old_events:
                    archive_file = self.storage_path / f"archive_{int(time.time())}.json.gz"
                    
                    with gzip.open(archive_file, 'wt') as f:
                        for event in old_events:
                            json.dump(event.to_dict(), f)
                            f.write('\n')
                
                # Delete from main database
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.execute(
                        "DELETE FROM audit_events WHERE timestamp < ?",
                        (cutoff_date.isoformat(),)
                    )
                    deleted_count = cursor.rowcount
                    conn.commit()
                
                logger.info(f"Archived {deleted_count} old audit events")
                return deleted_count
                
        except Exception as e:
            logger.error(f"Failed to archive old events: {e}")
            return 0

class ComplianceReporter:
    """Generate compliance reports from audit logs"""
    
    def __init__(self, storage: AuditStorage):
        self.storage = storage
        self.report_templates = self._load_report_templates()
    
    def _load_report_templates(self) -> Dict[str, Dict[str, Any]]:
        """Load compliance report templates"""
        return {
            'sox': {
                'name': 'Sarbanes-Oxley Compliance Report',
                'required_events': [
                    AuditEventType.DATA_MODIFICATION,
                    AuditEventType.ADMINISTRATIVE_ACTION,
                    AuditEventType.ACCESS_GRANTED,
                    AuditEventType.SYSTEM_CONFIGURATION
                ],
                'fields': ['timestamp', 'actor', 'action', 'target', 'outcome'],
                'retention_days': 2555  # 7 years
            },
            'hipaa': {
                'name': 'HIPAA Compliance Report',
                'required_events': [
                    AuditEventType.DATA_ACCESS,
                    AuditEventType.DATA_MODIFICATION,
                    AuditEventType.AUTHENTICATION,
                    AuditEventType.AUTHORIZATION
                ],
                'fields': ['timestamp', 'actor', 'action', 'target', 'outcome', 'ip_address'],
                'retention_days': 2190  # 6 years
            },
            'pci_dss': {
                'name': 'PCI DSS Compliance Report',
                'required_events': [
                    AuditEventType.ACCESS_GRANTED,
                    AuditEventType.ACCESS_DENIED,
                    AuditEventType.DATA_ACCESS,
                    AuditEventType.SECURITY_EVENT
                ],
                'fields': ['timestamp', 'actor', 'action', 'target', 'outcome', 'ip_address'],
                'retention_days': 365
            },
            'gdpr': {
                'name': 'GDPR Compliance Report',
                'required_events': [
                    AuditEventType.DATA_ACCESS,
                    AuditEventType.DATA_MODIFICATION,
                    AuditEventType.COMPLIANCE_EVENT
                ],
                'fields': ['timestamp', 'actor', 'action', 'target', 'outcome', 'details'],
                'retention_days': 1095  # 3 years
            }
        }
    
    def generate_compliance_report(self, 
                                 standard: ComplianceStandard,
                                 start_date: datetime,
                                 end_date: datetime,
                                 format_type: str = 'json') -> Dict[str, Any]:
        """Generate compliance report"""
        template = self.report_templates.get(standard.value)
        if not template:
            raise ValueError(f"No template for compliance standard: {standard.value}")
        
        # Query events for compliance standard
        query = AuditQuery(
            start_time=start_date,
            end_time=end_date,
            event_types=template['required_events'],
            compliance_standards=[standard],
            limit=100000
        )
        
        events = self.storage.query_events(query)
        
        # Generate report data
        report = {
            'standard': standard.value,
            'name': template['name'],
            'period': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            },
            'generated_at': datetime.now().isoformat(),
            'total_events': len(events),
            'summary': self._generate_summary(events),
            'events': []
        }
        
        # Include event details
        for event in events:
            event_data = {}
            for field in template['fields']:
                if hasattr(event, field):
                    value = getattr(event, field)
                    if isinstance(value, datetime):
                        value = value.isoformat()
                    elif isinstance(value, set):
                        value = list(value)
                    event_data[field] = value
            report['events'].append(event_data)
        
        return report
    
    def _generate_summary(self, events: List[AuditEvent]) -> Dict[str, Any]:
        """Generate summary statistics for events"""
        summary = {
            'total_events': len(events),
            'by_type': defaultdict(int),
            'by_outcome': defaultdict(int),
            'by_actor': defaultdict(int),
            'by_hour': defaultdict(int),
            'high_risk_events': 0,
            'failed_events': 0,
            'unique_actors': set(),
            'unique_targets': set()
        }
        
        for event in events:
            summary['by_type'][event.event_type.value] += 1
            summary['by_outcome'][event.outcome] += 1
            summary['by_actor'][event.actor] += 1
            summary['by_hour'][event.timestamp.hour] += 1
            
            if event.risk_score > 0.7:
                summary['high_risk_events'] += 1
            
            if event.outcome == 'failure':
                summary['failed_events'] += 1
            
            summary['unique_actors'].add(event.actor)
            summary['unique_targets'].add(event.target)
        
        # Convert sets to counts
        summary['unique_actors'] = len(summary['unique_actors'])
        summary['unique_targets'] = len(summary['unique_targets'])
        
        # Convert defaultdicts to regular dicts
        summary['by_type'] = dict(summary['by_type'])
        summary['by_outcome'] = dict(summary['by_outcome'])
        summary['by_actor'] = dict(summary['by_actor'])
        summary['by_hour'] = dict(summary['by_hour'])
        
        return summary
    
    def export_report(self, report: Dict[str, Any], output_path: Path, format_type: str = 'json'):
        """Export compliance report to file"""
        try:
            if format_type == 'json':
                with open(output_path, 'w') as f:
                    json.dump(report, f, indent=2)
            
            elif format_type == 'csv':
                with open(output_path, 'w', newline='') as f:
                    if report['events']:
                        writer = csv.DictWriter(f, fieldnames=report['events'][0].keys())
                        writer.writeheader()
                        writer.writerows(report['events'])
            
            elif format_type == 'xml':
                root = ET.Element('ComplianceReport')
                root.set('standard', report['standard'])
                root.set('generated_at', report['generated_at'])
                
                # Add summary
                summary_elem = ET.SubElement(root, 'Summary')
                for key, value in report['summary'].items():
                    elem = ET.SubElement(summary_elem, key.replace(' ', '_'))
                    elem.text = str(value)
                
                # Add events
                events_elem = ET.SubElement(root, 'Events')
                for event in report['events']:
                    event_elem = ET.SubElement(events_elem, 'Event')
                    for key, value in event.items():
                        elem = ET.SubElement(event_elem, key)
                        elem.text = str(value) if value is not None else ''
                
                tree = ET.ElementTree(root)
                tree.write(output_path, encoding='utf-8', xml_declaration=True)
            
            logger.info(f"Exported compliance report to: {output_path}")
            
        except Exception as e:
            logger.error(f"Failed to export report: {e}")

class AuditProcessor:
    """Process and enrich audit events"""
    
    def __init__(self):
        self.enrichment_rules = []
        self.risk_calculators = []
        self.compliance_mappers = []
    
    def add_enrichment_rule(self, rule: Callable[[AuditEvent], AuditEvent]):
        """Add event enrichment rule"""
        self.enrichment_rules.append(rule)
    
    def add_risk_calculator(self, calculator: Callable[[AuditEvent], float]):
        """Add risk score calculator"""
        self.risk_calculators.append(calculator)
    
    def add_compliance_mapper(self, mapper: Callable[[AuditEvent], Set[ComplianceStandard]]):
        """Add compliance standard mapper"""
        self.compliance_mappers.append(mapper)
    
    def process_event(self, event: AuditEvent) -> AuditEvent:
        """Process and enrich audit event"""
        # Apply enrichment rules
        for rule in self.enrichment_rules:
            try:
                event = rule(event)
            except Exception as e:
                logger.error(f"Enrichment rule failed: {e}")
        
        # Calculate risk score
        risk_scores = []
        for calculator in self.risk_calculators:
            try:
                score = calculator(event)
                risk_scores.append(score)
            except Exception as e:
                logger.error(f"Risk calculator failed: {e}")
        
        if risk_scores:
            event.risk_score = max(risk_scores)
        
        # Map compliance standards
        for mapper in self.compliance_mappers:
            try:
                standards = mapper(event)
                event.compliance_flags.update(standards)
            except Exception as e:
                logger.error(f"Compliance mapper failed: {e}")
        
        return event

class AuditManager:
    """Main audit system manager"""
    
    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = config_dir or Path.home() / ".blrcs" / "audit"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.storage = AuditStorage(self.config_dir / "storage")
        self.processor = AuditProcessor()
        self.reporter = ComplianceReporter(self.storage)
        
        self.event_queue = queue.Queue(maxsize=10000)
        self.processing_thread = None
        self.running = False
        self.lock = threading.Lock()
        
        # Set up default enrichment rules
        self._setup_default_rules()
        
        # Start processing thread
        self.start_processing()
    
    def _setup_default_rules(self):
        """Set up default enrichment and analysis rules"""
        
        # IP geolocation enrichment
        def geo_enrichment(event: AuditEvent) -> AuditEvent:
            if event.ip_address and 'geo_location' not in event.metadata:
                # In production, integrate with GeoIP service
                event.metadata['geo_location'] = {'country': 'Unknown', 'city': 'Unknown'}
            return event
        
        # Risk score calculation
        def calculate_risk(event: AuditEvent) -> float:
            risk = 0.0
            
            # High risk events
            if event.event_type in [AuditEventType.SECURITY_EVENT, AuditEventType.THREAT_DETECTED]:
                risk += 0.8
            elif event.event_type == AuditEventType.ACCESS_DENIED:
                risk += 0.3
            elif event.event_type == AuditEventType.ADMINISTRATIVE_ACTION:
                risk += 0.2
            
            # Failed outcomes
            if event.outcome == 'failure':
                risk += 0.4
            
            # After hours access
            hour = event.timestamp.hour
            if hour < 6 or hour > 22:  # Outside business hours
                risk += 0.2
            
            # Unknown IP addresses
            if event.ip_address and not self._is_known_ip(event.ip_address):
                risk += 0.1
            
            return min(risk, 1.0)
        
        # Compliance mapping
        def map_compliance(event: AuditEvent) -> Set[ComplianceStandard]:
            standards = set()
            
            # Data access events map to multiple standards
            if event.event_type in [AuditEventType.DATA_ACCESS, AuditEventType.DATA_MODIFICATION]:
                standards.update([
                    ComplianceStandard.HIPAA,
                    ComplianceStandard.GDPR,
                    ComplianceStandard.PCI_DSS
                ])
            
            # Administrative actions for SOX
            if event.event_type == AuditEventType.ADMINISTRATIVE_ACTION:
                standards.add(ComplianceStandard.SOX)
            
            # Security events for all standards
            if event.event_type == AuditEventType.SECURITY_EVENT:
                standards.update([
                    ComplianceStandard.NIST,
                    ComplianceStandard.ISO_27001,
                    ComplianceStandard.CMMC
                ])
            
            return standards
        
        self.processor.add_enrichment_rule(geo_enrichment)
        self.processor.add_risk_calculator(calculate_risk)
        self.processor.add_compliance_mapper(map_compliance)
    
    def _is_known_ip(self, ip_address: str) -> bool:
        """Check if IP address is known/trusted"""
        # In production, maintain a database of known IPs
        private_ranges = ['127.', '192.168.', '10.', '172.']
        return any(ip_address.startswith(range_) for range_ in private_ranges)
    
    def start_processing(self):
        """Start audit event processing thread"""
        if not self.running:
            self.running = True
            self.processing_thread = threading.Thread(target=self._process_events, daemon=True)
            self.processing_thread.start()
            logger.info("Audit processing started")
    
    def stop_processing(self):
        """Stop audit event processing"""
        self.running = False
        if self.processing_thread:
            self.processing_thread.join(timeout=5)
        logger.info("Audit processing stopped")
    
    def _process_events(self):
        """Process audit events from queue"""
        while self.running:
            try:
                # Get event from queue with timeout
                event = self.event_queue.get(timeout=1.0)
                
                # Process and enrich event
                processed_event = self.processor.process_event(event)
                
                # Store in database
                success = self.storage.store_event(processed_event)
                if not success:
                    logger.error(f"Failed to store audit event: {processed_event.id}")
                
                self.event_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing audit event: {e}")
    
    def log_event(self,
                  event_type: AuditEventType,
                  source: str,
                  actor: str = "",
                  target: str = "",
                  action: str = "",
                  outcome: str = "success",
                  details: Optional[Dict[str, Any]] = None,
                  level: AuditLevel = AuditLevel.STANDARD,
                  session_id: Optional[str] = None,
                  ip_address: Optional[str] = None,
                  user_agent: Optional[str] = None) -> str:
        """Log audit event"""
        
        event_id = f"audit_{int(time.time() * 1000)}_{secrets.token_hex(4)}"
        
        event = AuditEvent(
            id=event_id,
            timestamp=datetime.now(),
            event_type=event_type,
            level=level,
            source=source,
            actor=actor,
            target=target,
            action=action,
            outcome=outcome,
            details=details or {},
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        try:
            # Add to processing queue
            self.event_queue.put(event, timeout=1.0)
            logger.debug(f"Queued audit event: {event_id}")
            return event_id
            
        except queue.Full:
            logger.error("Audit event queue is full, dropping event")
            return ""
        except Exception as e:
            logger.error(f"Failed to queue audit event: {e}")
            return ""
    
    def query_events(self, query: AuditQuery) -> Tuple[List[AuditEvent], int]:
        """Query audit events with total count"""
        events = self.storage.query_events(query)
        total_count = self.storage.get_event_count(query)
        return events, total_count
    
    def generate_compliance_report(self,
                                 standard: ComplianceStandard,
                                 start_date: datetime,
                                 end_date: datetime) -> Dict[str, Any]:
        """Generate compliance report"""
        return self.reporter.generate_compliance_report(standard, start_date, end_date)
    
    def export_compliance_report(self,
                               report: Dict[str, Any],
                               output_path: Path,
                               format_type: str = 'json'):
        """Export compliance report"""
        self.reporter.export_report(report, output_path, format_type)
    
    def get_audit_statistics(self, days: int = 30) -> Dict[str, Any]:
        """Get audit system statistics"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        query = AuditQuery(start_time=start_date, end_time=end_date, limit=100000)
        events, total_count = self.query_events(query)
        
        stats = {
            'period_days': days,
            'total_events': total_count,
            'events_per_day': total_count / days if days > 0 else 0,
            'by_type': defaultdict(int),
            'by_level': defaultdict(int),
            'by_outcome': defaultdict(int),
            'by_source': defaultdict(int),
            'high_risk_events': 0,
            'compliance_events': defaultdict(int),
            'queue_size': self.event_queue.qsize(),
            'storage_size': self._get_storage_size()
        }
        
        for event in events:
            stats['by_type'][event.event_type.value] += 1
            stats['by_level'][event.level.value] += 1
            stats['by_outcome'][event.outcome] += 1
            stats['by_source'][event.source] += 1
            
            if event.risk_score > 0.7:
                stats['high_risk_events'] += 1
            
            for flag in event.compliance_flags:
                stats['compliance_events'][flag.value] += 1
        
        # Convert defaultdicts to regular dicts
        stats['by_type'] = dict(stats['by_type'])
        stats['by_level'] = dict(stats['by_level'])
        stats['by_outcome'] = dict(stats['by_outcome'])
        stats['by_source'] = dict(stats['by_source'])
        stats['compliance_events'] = dict(stats['compliance_events'])
        
        return stats
    
    def _get_storage_size(self) -> int:
        """Get total storage size in bytes"""
        total_size = 0
        try:
            for file_path in self.config_dir.rglob('*'):
                if file_path.is_file():
                    total_size += file_path.stat().st_size
        except Exception as e:
            logger.error(f"Failed to calculate storage size: {e}")
        
        return total_size
    
    def archive_old_events(self, days_old: int = 365) -> int:
        """Archive old audit events"""
        return self.storage.archive_old_events(days_old)
    
    def verify_integrity(self, start_date: Optional[datetime] = None, 
                        end_date: Optional[datetime] = None) -> Dict[str, Any]:
        """Verify audit log integrity"""
        query = AuditQuery(start_time=start_date, end_time=end_date, limit=100000)
        events, total_count = self.query_events(query)
        
        integrity_results = {
            'total_events': total_count,
            'verified_events': 0,
            'failed_verification': 0,
            'missing_checksums': 0,
            'integrity_percentage': 0.0
        }
        
        for event in events:
            if not event.checksum:
                integrity_results['missing_checksums'] += 1
            elif event.verify_integrity():
                integrity_results['verified_events'] += 1
            else:
                integrity_results['failed_verification'] += 1
        
        if total_count > 0:
            integrity_results['integrity_percentage'] = (
                integrity_results['verified_events'] / total_count * 100
            )
        
        return integrity_results

# Global audit manager instance
audit_manager = AuditManager()

# Convenience functions
def log_audit_event(event_type: AuditEventType, source: str, actor: str = "", 
                   target: str = "", action: str = "", outcome: str = "success",
                   details: Dict[str, Any] = None, **kwargs) -> str:
    """Log audit event"""
    return audit_manager.log_event(
        event_type, source, actor, target, action, outcome, details, **kwargs
    )

def query_audit_events(start_time: datetime = None, end_time: datetime = None,
                      event_types: List[AuditEventType] = None, **kwargs) -> List[AuditEvent]:
    """Query audit events"""
    query = AuditQuery(
        start_time=start_time,
        end_time=end_time,
        event_types=event_types,
        **kwargs
    )
    events, _ = audit_manager.query_events(query)
    return events

def generate_compliance_report(standard: ComplianceStandard, days_back: int = 30) -> Dict[str, Any]:
    """Generate compliance report for recent period"""
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days_back)
    return audit_manager.generate_compliance_report(standard, start_date, end_date)

# Export main classes and functions
__all__ = [
    'AuditEventType', 'AuditLevel', 'ComplianceStandard', 'AuditStatus',
    'AuditEvent', 'AuditQuery', 'AuditStorage', 'ComplianceReporter',
    'AuditProcessor', 'AuditManager', 'audit_manager',
    'log_audit_event', 'query_audit_events', 'generate_compliance_report'
]