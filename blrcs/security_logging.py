# BLRCS Security Logging System
# Advanced security event logging and monitoring
import json
import time
import hashlib
import hmac
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from collections import deque, defaultdict
import re
import ipaddress

class SecurityEventType(Enum):
    """Security event types"""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    ACCOUNT_LOCKED = "account_locked"
    PERMISSION_DENIED = "permission_denied"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    CONFIGURATION_CHANGE = "configuration_change"
    SYSTEM_ACCESS = "system_access"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    BRUTE_FORCE_ATTACK = "brute_force_attack"
    SQL_INJECTION_ATTEMPT = "sql_injection_attempt"
    XSS_ATTEMPT = "xss_attempt"
    UNAUTHORIZED_API_ACCESS = "unauthorized_api_access"
    FILE_ACCESS = "file_access"
    ENCRYPTION_EVENT = "encryption_event"
    BACKUP_EVENT = "backup_event"
    SYSTEM_ERROR = "system_error"
    COMPLIANCE_VIOLATION = "compliance_violation"

class SeverityLevel(Enum):
    """Security event severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5

class ThreatLevel(Enum):
    """Threat assessment levels"""
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    CRITICAL = "critical"

@dataclass
class SecurityEvent:
    """Security event with comprehensive details"""
    id: str
    event_type: SecurityEventType
    severity: SeverityLevel
    timestamp: datetime
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    success: bool = True
    threat_level: ThreatLevel = ThreatLevel.BENIGN
    correlation_id: Optional[str] = None
    geolocation: Optional[Dict[str, str]] = None
    fingerprint: Optional[str] = None
    
    def __post_init__(self):
        if isinstance(self.event_type, str):
            self.event_type = SecurityEventType(self.event_type)
        if isinstance(self.severity, str):
            self.severity = SeverityLevel[self.severity]
        if isinstance(self.threat_level, str):
            self.threat_level = ThreatLevel(self.threat_level)
        if isinstance(self.timestamp, str):
            self.timestamp = datetime.fromisoformat(self.timestamp)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'event_type': self.event_type.value,
            'severity': self.severity.name,
            'timestamp': self.timestamp.isoformat(),
            'user_id': self.user_id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'resource': self.resource,
            'action': self.action,
            'details': self.details,
            'success': self.success,
            'threat_level': self.threat_level.value,
            'correlation_id': self.correlation_id,
            'geolocation': self.geolocation,
            'fingerprint': self.fingerprint
        }
    
    def calculate_fingerprint(self) -> str:
        """Calculate event fingerprint for deduplication"""
        fingerprint_data = {
            'event_type': self.event_type.value,
            'user_id': self.user_id,
            'ip_address': self.ip_address,
            'resource': self.resource,
            'action': self.action
        }
        
        fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]

@dataclass
class SecurityAlert:
    """Security alert generated from events"""
    id: str
    alert_type: str
    severity: SeverityLevel
    message: str
    events: List[str] = field(default_factory=list)  # Event IDs
    timestamp: datetime = field(default_factory=datetime.now)
    acknowledged: bool = False
    resolved: bool = False
    assignee: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'alert_type': self.alert_type,
            'severity': self.severity.name,
            'message': self.message,
            'events': self.events,
            'timestamp': self.timestamp.isoformat(),
            'acknowledged': self.acknowledged,
            'resolved': self.resolved,
            'assignee': self.assignee,
            'metadata': self.metadata
        }

class ThreatDetector:
    """Threat detection engine"""
    
    def __init__(self):
        self.patterns = self._load_threat_patterns()
        self.ip_whitelist: Set[str] = set()
        self.ip_blacklist: Set[str] = set()
        self.suspicious_ips: Dict[str, int] = defaultdict(int)
        self.rate_limits = {
            'login_attempts': (5, 300),  # 5 attempts per 5 minutes
            'api_calls': (100, 60),      # 100 calls per minute
            'data_access': (50, 300)     # 50 accesses per 5 minutes
        }
    
    def _load_threat_patterns(self) -> Dict[str, List[str]]:
        """Load threat detection patterns"""
        return {
            'sql_injection': [
                r"('|(\\')|(;)|(\-\-)|(\s(or|and)\s)",
                r"(union\s+select|select\s+.*\s+from)",
                r"(drop\s+table|delete\s+from|insert\s+into)"
            ],
            'xss': [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"on(load|error|click|mouseover)\s*="
            ],
            'path_traversal': [
                r"\.\./",
                r"\.\.\\",
                r"/etc/passwd",
                r"\\windows\\system32"
            ],
            'command_injection': [
                r"[;&|`$]",
                r"(wget|curl|nc|netcat)\s+",
                r"(rm|del|format)\s+.*"
            ]
        }
    
    def detect_threats(self, event: SecurityEvent) -> ThreatLevel:
        """Detect threat level for security event"""
        threat_score = 0
        
        # Check IP reputation
        if event.ip_address:
            threat_score += self._check_ip_reputation(event.ip_address)
        
        # Check for known attack patterns
        threat_score += self._check_attack_patterns(event)
        
        # Check for suspicious behavior
        threat_score += self._check_suspicious_behavior(event)
        
        # Check rate limiting violations
        threat_score += self._check_rate_limits(event)
        
        # Determine threat level
        if threat_score >= 8:
            return ThreatLevel.CRITICAL
        elif threat_score >= 5:
            return ThreatLevel.MALICIOUS
        elif threat_score >= 2:
            return ThreatLevel.SUSPICIOUS
        else:
            return ThreatLevel.BENIGN
    
    def _check_ip_reputation(self, ip_address: str) -> int:
        """Check IP address reputation"""
        score = 0
        
        try:
            ip = ipaddress.ip_address(ip_address)
            
            # Check blacklist
            if ip_address in self.ip_blacklist:
                score += 5
            
            # Check if IP is in suspicious list
            if ip_address in self.suspicious_ips:
                score += min(self.suspicious_ips[ip_address], 3)
            
            # Check for private/local IPs (less suspicious)
            if ip.is_private or ip.is_loopback:
                score -= 1
            
        except ValueError:
            # Invalid IP format is suspicious
            score += 2
        
        return max(0, score)
    
    def _check_attack_patterns(self, event: SecurityEvent) -> int:
        """Check for known attack patterns"""
        score = 0
        
        # Check patterns in various fields
        text_fields = [
            event.details.get('query', ''),
            event.details.get('payload', ''),
            event.details.get('input', ''),
            event.user_agent or '',
            event.resource or ''
        ]
        
        for field_text in text_fields:
            if not field_text:
                continue
            
            field_text = str(field_text).lower()
            
            for pattern_type, patterns in self.patterns.items():
                for pattern in patterns:
                    if re.search(pattern, field_text, re.IGNORECASE):
                        score += 3
                        event.details[f'detected_{pattern_type}'] = True
                        break
        
        return score
    
    def _check_suspicious_behavior(self, event: SecurityEvent) -> int:
        """Check for suspicious behavioral patterns"""
        score = 0
        
        # Failed login from multiple IPs
        if event.event_type == SecurityEventType.LOGIN_FAILURE:
            score += 1
        
        # Access to sensitive resources
        sensitive_resources = ['config', 'admin', 'users', 'logs', 'backup']
        if event.resource and any(res in event.resource.lower() for res in sensitive_resources):
            score += 1
        
        # Unusual user agents
        if event.user_agent:
            suspicious_agents = ['bot', 'crawler', 'scanner', 'curl', 'wget']
            if any(agent in event.user_agent.lower() for agent in suspicious_agents):
                score += 1
        
        # Permission denied events
        if event.event_type == SecurityEventType.PERMISSION_DENIED:
            score += 1
        
        # System access attempts
        if event.event_type == SecurityEventType.SYSTEM_ACCESS:
            score += 2
        
        return score
    
    def _check_rate_limits(self, event: SecurityEvent) -> int:
        """Check for rate limit violations"""
        # This would require implementing rate limiting tracking
        # For now, return 0
        return 0
    
    def add_suspicious_ip(self, ip_address: str):
        """Add IP to suspicious list"""
        self.suspicious_ips[ip_address] += 1
    
    def blacklist_ip(self, ip_address: str):
        """Add IP to blacklist"""
        self.ip_blacklist.add(ip_address)
    
    def whitelist_ip(self, ip_address: str):
        """Add IP to whitelist"""
        self.ip_whitelist.add(ip_address)

class SecurityAlertManager:
    """Manages security alerts and notifications"""
    
    def __init__(self):
        self.alerts: Dict[str, SecurityAlert] = {}
        self.alert_rules: List[Dict[str, Any]] = []
        self.notification_handlers: List[Callable] = []
        self.lock = threading.Lock()
        
        # Load default alert rules
        self._setup_default_rules()
    
    def _setup_default_rules(self):
        """Setup default alerting rules"""
        default_rules = [
            {
                'name': 'Multiple Failed Logins',
                'conditions': {
                    'event_type': SecurityEventType.LOGIN_FAILURE,
                    'count': 5,
                    'timeframe': 300  # 5 minutes
                },
                'severity': SeverityLevel.HIGH,
                'message': 'Multiple failed login attempts detected'
            },
            {
                'name': 'Privilege Escalation',
                'conditions': {
                    'event_type': SecurityEventType.PRIVILEGE_ESCALATION
                },
                'severity': SeverityLevel.CRITICAL,
                'message': 'Privilege escalation attempt detected'
            },
            {
                'name': 'Suspicious Activity',
                'conditions': {
                    'threat_level': ThreatLevel.MALICIOUS
                },
                'severity': SeverityLevel.HIGH,
                'message': 'Malicious activity detected'
            },
            {
                'name': 'System Access',
                'conditions': {
                    'event_type': SecurityEventType.SYSTEM_ACCESS,
                    'success': False
                },
                'severity': SeverityLevel.MEDIUM,
                'message': 'Unauthorized system access attempt'
            }
        ]
        
        self.alert_rules.extend(default_rules)
    
    def evaluate_alerts(self, event: SecurityEvent, recent_events: List[SecurityEvent]):
        """Evaluate if alerts should be generated"""
        with self.lock:
            for rule in self.alert_rules:
                if self._rule_matches(rule, event, recent_events):
                    alert = self._create_alert(rule, event, recent_events)
                    self.alerts[alert.id] = alert
                    self._notify_alert(alert)
    
    def _rule_matches(self, rule: Dict[str, Any], event: SecurityEvent, 
                     recent_events: List[SecurityEvent]) -> bool:
        """Check if rule matches current conditions"""
        conditions = rule['conditions']
        
        # Check event type
        if 'event_type' in conditions:
            if event.event_type != conditions['event_type']:
                return False
        
        # Check threat level
        if 'threat_level' in conditions:
            if event.threat_level != conditions['threat_level']:
                return False
        
        # Check success status
        if 'success' in conditions:
            if event.success != conditions['success']:
                return False
        
        # Check count-based conditions
        if 'count' in conditions and 'timeframe' in conditions:
            count = conditions['count']
            timeframe = conditions['timeframe']
            cutoff_time = datetime.now() - timedelta(seconds=timeframe)
            
            matching_events = []
            for e in recent_events:
                if (e.timestamp > cutoff_time and
                    e.event_type == conditions.get('event_type', e.event_type)):
                    matching_events.append(e)
            
            if len(matching_events) < count:
                return False
        
        return True
    
    def _create_alert(self, rule: Dict[str, Any], event: SecurityEvent,
                     related_events: List[SecurityEvent]) -> SecurityAlert:
        """Create security alert"""
        alert_id = f"alert_{int(time.time())}_{hash(rule['name'])}"
        
        event_ids = [event.id]
        if 'count' in rule['conditions']:
            event_ids.extend([e.id for e in related_events])
        
        alert = SecurityAlert(
            id=alert_id,
            alert_type=rule['name'],
            severity=rule['severity'],
            message=rule['message'],
            events=event_ids,
            metadata={
                'rule': rule['name'],
                'primary_event': event.id,
                'related_events': len(related_events)
            }
        )
        
        return alert
    
    def _notify_alert(self, alert: SecurityAlert):
        """Send alert notifications"""
        for handler in self.notification_handlers:
            try:
                handler(alert)
            except Exception:
                pass  # Don't let notification failures break the system
    
    def add_notification_handler(self, handler: Callable):
        """Add alert notification handler"""
        self.notification_handlers.append(handler)
    
    def acknowledge_alert(self, alert_id: str, user_id: str) -> bool:
        """Acknowledge security alert"""
        if alert_id in self.alerts:
            self.alerts[alert_id].acknowledged = True
            self.alerts[alert_id].assignee = user_id
            return True
        return False
    
    def resolve_alert(self, alert_id: str, user_id: str) -> bool:
        """Resolve security alert"""
        if alert_id in self.alerts:
            self.alerts[alert_id].resolved = True
            self.alerts[alert_id].assignee = user_id
            return True
        return False

class SecurityLogger:
    """Main security logging system"""
    
    def __init__(self, database=None, logger=None):
        self.database = database
        self.logger = logger
        self.events: deque = deque(maxlen=50000)
        self.threat_detector = ThreatDetector()
        self.alert_manager = SecurityAlertManager()
        self.lock = threading.RLock()
        
        # Event storage and indexing
        self.events_by_type: Dict[SecurityEventType, deque] = defaultdict(lambda: deque(maxlen=5000))
        self.events_by_user: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.events_by_ip: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        
        # Security metrics
        self.metrics = {
            'total_events': 0,
            'threats_detected': 0,
            'alerts_generated': 0,
            'blocked_ips': 0
        }
        
        # Load existing events if database available
        self._load_recent_events()
    
    def _load_recent_events(self):
        """Load recent security events from database"""
        if not self.database:
            return
        
        try:
            # Load events from last 24 hours
            cutoff_time = datetime.now() - timedelta(days=1)
            events_data = self.database.select('security_events', {
                'timestamp': {'gte': cutoff_time.isoformat()}
            })
            
            for event_data in events_data:
                event = SecurityEvent(**event_data)
                self.events.append(event)
                self._index_event(event)
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to load security events: {e}")
    
    def log_event(self, event_type: Union[SecurityEventType, str], 
                  severity: Union[SeverityLevel, str] = SeverityLevel.MEDIUM,
                  user_id: str = None, ip_address: str = None, 
                  user_agent: str = None, resource: str = None,
                  action: str = None, success: bool = True,
                  details: Dict[str, Any] = None,
                  correlation_id: str = None) -> SecurityEvent:
        """Log security event"""
        
        with self.lock:
            try:
                # Convert string enums
                if isinstance(event_type, str):
                    event_type = SecurityEventType(event_type)
                if isinstance(severity, str):
                    severity = SeverityLevel[severity]
                
                # Create event
                event_id = f"sec_{int(time.time() * 1000)}_{hash(str(details))}"
                event = SecurityEvent(
                    id=event_id,
                    event_type=event_type,
                    severity=severity,
                    timestamp=datetime.now(),
                    user_id=user_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    resource=resource,
                    action=action,
                    success=success,
                    details=details or {},
                    correlation_id=correlation_id
                )
                
                # Calculate fingerprint
                event.fingerprint = event.calculate_fingerprint()
                
                # Detect threats
                event.threat_level = self.threat_detector.detect_threats(event)
                
                # Store event
                self.events.append(event)
                self._index_event(event)
                
                # Update metrics
                self.metrics['total_events'] += 1
                if event.threat_level in [ThreatLevel.MALICIOUS, ThreatLevel.CRITICAL]:
                    self.metrics['threats_detected'] += 1
                
                # Save to database
                if self.database:
                    self.database.insert('security_events', event.to_dict())
                
                # Check for alerts
                recent_events = list(self.events)[-100:]  # Last 100 events
                self.alert_manager.evaluate_alerts(event, recent_events)
                
                # Log to standard logger
                if self.logger:
                    log_level = self._get_log_level(event.severity)
                    getattr(self.logger, log_level)(
                        f"Security Event: {event.event_type.value} - "
                        f"User: {user_id or 'N/A'} - IP: {ip_address or 'N/A'} - "
                        f"Threat: {event.threat_level.value}"
                    )
                
                return event
                
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Failed to log security event: {e}")
                raise
    
    def _index_event(self, event: SecurityEvent):
        """Index event for fast retrieval"""
        self.events_by_type[event.event_type].append(event)
        
        if event.user_id:
            self.events_by_user[event.user_id].append(event)
        
        if event.ip_address:
            self.events_by_ip[event.ip_address].append(event)
    
    def _get_log_level(self, severity: SeverityLevel) -> str:
        """Get log level for severity"""
        level_map = {
            SeverityLevel.LOW: 'info',
            SeverityLevel.MEDIUM: 'info',
            SeverityLevel.HIGH: 'warning',
            SeverityLevel.CRITICAL: 'error',
            SeverityLevel.EMERGENCY: 'critical'
        }
        return level_map.get(severity, 'info')
    
    def get_events(self, event_type: SecurityEventType = None,
                   user_id: str = None, ip_address: str = None,
                   start_time: datetime = None, end_time: datetime = None,
                   threat_level: ThreatLevel = None,
                   limit: int = 100) -> List[SecurityEvent]:
        """Get filtered security events"""
        
        with self.lock:
            # Choose appropriate index
            if event_type:
                events_source = self.events_by_type[event_type]
            elif user_id:
                events_source = self.events_by_user[user_id]
            elif ip_address:
                events_source = self.events_by_ip[ip_address]
            else:
                events_source = self.events
            
            # Filter events
            filtered_events = []
            for event in reversed(events_source):  # Most recent first
                # Time range filter
                if start_time and event.timestamp < start_time:
                    continue
                if end_time and event.timestamp > end_time:
                    continue
                
                # Threat level filter
                if threat_level and event.threat_level != threat_level:
                    continue
                
                # Additional filters
                if user_id and event.user_id != user_id:
                    continue
                if ip_address and event.ip_address != ip_address:
                    continue
                if event_type and event.event_type != event_type:
                    continue
                
                filtered_events.append(event)
                
                if len(filtered_events) >= limit:
                    break
            
            return filtered_events
    
    def get_security_stats(self, timeframe_hours: int = 24) -> Dict[str, Any]:
        """Get security statistics"""
        cutoff_time = datetime.now() - timedelta(hours=timeframe_hours)
        recent_events = [e for e in self.events if e.timestamp > cutoff_time]
        
        stats = {
            'timeframe_hours': timeframe_hours,
            'total_events': len(recent_events),
            'events_by_type': defaultdict(int),
            'events_by_severity': defaultdict(int),
            'events_by_threat_level': defaultdict(int),
            'unique_users': set(),
            'unique_ips': set(),
            'success_rate': 0,
            'top_resources': defaultdict(int),
            'alerts': {
                'total': len(self.alert_manager.alerts),
                'unresolved': len([a for a in self.alert_manager.alerts.values() if not a.resolved])
            }
        }
        
        successful_events = 0
        
        for event in recent_events:
            stats['events_by_type'][event.event_type.value] += 1
            stats['events_by_severity'][event.severity.name] += 1
            stats['events_by_threat_level'][event.threat_level.value] += 1
            
            if event.user_id:
                stats['unique_users'].add(event.user_id)
            if event.ip_address:
                stats['unique_ips'].add(event.ip_address)
            if event.resource:
                stats['top_resources'][event.resource] += 1
            if event.success:
                successful_events += 1
        
        if recent_events:
            stats['success_rate'] = successful_events / len(recent_events) * 100
        
        # Convert sets to counts
        stats['unique_users'] = len(stats['unique_users'])
        stats['unique_ips'] = len(stats['unique_ips'])
        
        # Get top resources
        stats['top_resources'] = dict(sorted(
            stats['top_resources'].items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10])
        
        return stats
    
    def export_events(self, file_path: Path, format_type: str = 'json',
                     **filters) -> bool:
        """Export security events to file"""
        try:
            events = self.get_events(**filters)
            
            if format_type == 'json':
                with open(file_path, 'w') as f:
                    json.dump([event.to_dict() for event in events], f, indent=2)
            elif format_type == 'csv':
                import csv
                with open(file_path, 'w', newline='') as f:
                    if events:
                        writer = csv.DictWriter(f, fieldnames=events[0].to_dict().keys())
                        writer.writeheader()
                        for event in events:
                            writer.writerow(event.to_dict())
            
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to export events: {e}")
            return False

# Convenience functions
def log_login_attempt(security_logger: SecurityLogger, user_id: str, 
                     ip_address: str, success: bool, details: Dict[str, Any] = None):
    """Log login attempt"""
    event_type = SecurityEventType.LOGIN_SUCCESS if success else SecurityEventType.LOGIN_FAILURE
    severity = SeverityLevel.LOW if success else SeverityLevel.MEDIUM
    
    security_logger.log_event(
        event_type=event_type,
        severity=severity,
        user_id=user_id,
        ip_address=ip_address,
        action='login',
        success=success,
        details=details or {}
    )

def log_permission_denied(security_logger: SecurityLogger, user_id: str,
                         resource: str, action: str, ip_address: str = None):
    """Log permission denied event"""
    security_logger.log_event(
        event_type=SecurityEventType.PERMISSION_DENIED,
        severity=SeverityLevel.MEDIUM,
        user_id=user_id,
        ip_address=ip_address,
        resource=resource,
        action=action,
        success=False
    )

def log_data_access(security_logger: SecurityLogger, user_id: str,
                   resource: str, action: str, ip_address: str = None,
                   sensitive: bool = False):
    """Log data access event"""
    severity = SeverityLevel.HIGH if sensitive else SeverityLevel.LOW
    
    security_logger.log_event(
        event_type=SecurityEventType.DATA_ACCESS,
        severity=severity,
        user_id=user_id,
        ip_address=ip_address,
        resource=resource,
        action=action,
        success=True,
        details={'sensitive': sensitive}
    )

# Factory function
def create_security_logger(database=None, logger=None) -> SecurityLogger:
    """Create security logger instance"""
    return SecurityLogger(database, logger)

# Export main classes
__all__ = [
    'SecurityEventType', 'SeverityLevel', 'ThreatLevel',
    'SecurityEvent', 'SecurityAlert', 'SecurityLogger',
    'ThreatDetector', 'SecurityAlertManager',
    'log_login_attempt', 'log_permission_denied', 'log_data_access',
    'create_security_logger'
]