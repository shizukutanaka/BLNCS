"""
Security Hardening System
Comprehensive security features for BLNCS.
"""

import hashlib
import secrets
import time
import threading
from typing import Dict, List, Any, Optional, Callable, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
from enum import Enum
import ipaddress
import re
import json
from pathlib import Path

from .logger import get_logger
from .config_manager import get_config_manager
from .database import get_database_manager
from .exceptions import SecurityError, ValidationError


class SecurityLevel(Enum):
    """Security hardening levels"""
    BASIC = "basic"
    ENHANCED = "enhanced"
    PARANOID = "paranoid"


class ThreatLevel(Enum):
    """Security threat levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackType(Enum):
    """Types of security attacks"""
    BRUTE_FORCE = "brute_force"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    INVALID_INPUT = "invalid_input"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    INJECTION = "injection"
    UNAUTHORIZED_ACCESS = "unauthorized_access"


@dataclass
class SecurityEvent:
    """Security event data"""
    event_type: AttackType
    threat_level: ThreatLevel
    source_ip: Optional[str] = None
    user_id: Optional[str] = None
    description: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    blocked: bool = False


@dataclass
class RateLimitRule:
    """Rate limiting rule"""
    name: str
    max_requests: int
    window_seconds: int
    block_duration_seconds: int = 300
    enabled: bool = True


class SecurityTokenManager:
    """Secure token management"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.active_tokens: Dict[str, Dict[str, Any]] = {}
        self.token_lock = threading.RLock()
        
    def generate_secure_token(self, purpose: str, expires_in: int = 3600) -> str:
        """Generate cryptographically secure token"""
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(seconds=expires_in)
        
        with self.token_lock:
            self.active_tokens[token] = {
                'purpose': purpose,
                'created_at': datetime.now(),
                'expires_at': expires_at,
                'used': False
            }
        
        return token
    
    def validate_token(self, token: str, purpose: str = None, consume: bool = True) -> bool:
        """Validate and optionally consume token"""
        with self.token_lock:
            token_data = self.active_tokens.get(token)
            
            if not token_data:
                return False
            
            # Check expiration
            if datetime.now() > token_data['expires_at']:
                del self.active_tokens[token]
                return False
            
            # Check purpose if specified
            if purpose and token_data['purpose'] != purpose:
                return False
            
            # Check if already used (single use tokens)
            if token_data['used']:
                return False
            
            # Mark as used if consuming
            if consume:
                token_data['used'] = True
            
            return True
    
    def cleanup_expired_tokens(self):
        """Remove expired tokens"""
        with self.token_lock:
            current_time = datetime.now()
            expired_tokens = [
                token for token, data in self.active_tokens.items()
                if current_time > data['expires_at']
            ]
            
            for token in expired_tokens:
                del self.active_tokens[token]
            
            if expired_tokens:
                self.logger.debug(f"Cleaned up {len(expired_tokens)} expired tokens")


class RateLimiter:
    """Advanced rate limiting system"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.request_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.blocked_ips: Dict[str, datetime] = {}
        self.rules: Dict[str, RateLimitRule] = {}
        self.lock = threading.RLock()
        
        # Default rules
        self._setup_default_rules()
    
    def _setup_default_rules(self):
        """Setup default rate limiting rules"""
        self.add_rule(RateLimitRule("api_general", 100, 60))  # 100 requests per minute
        self.add_rule(RateLimitRule("login_attempts", 5, 300, 900))  # 5 login attempts per 5 min, block 15 min
        self.add_rule(RateLimitRule("backup_operations", 10, 3600))  # 10 backup ops per hour
        self.add_rule(RateLimitRule("config_changes", 20, 600))  # 20 config changes per 10 min
    
    def add_rule(self, rule: RateLimitRule):
        """Add rate limiting rule"""
        with self.lock:
            self.rules[rule.name] = rule
            self.logger.info(f"Added rate limit rule: {rule.name}")
    
    def check_rate_limit(self, identifier: str, rule_name: str = "api_general") -> bool:
        """Check if request is within rate limits"""
        with self.lock:
            # Check if IP is blocked
            if identifier in self.blocked_ips:
                if datetime.now() < self.blocked_ips[identifier]:
                    return False  # Still blocked
                else:
                    del self.blocked_ips[identifier]  # Unblock
            
            rule = self.rules.get(rule_name)
            if not rule or not rule.enabled:
                return True
            
            current_time = time.time()
            window_start = current_time - rule.window_seconds
            
            # Get request history for this identifier
            requests = self.request_history[f"{identifier}:{rule_name}"]
            
            # Remove old requests outside the window
            while requests and requests[0] < window_start:
                requests.popleft()
            
            # Check if limit exceeded
            if len(requests) >= rule.max_requests:
                # Block the identifier
                self.blocked_ips[identifier] = datetime.now() + timedelta(seconds=rule.block_duration_seconds)
                self.logger.warning(f"Rate limit exceeded for {identifier} on rule {rule_name}")
                return False
            
            # Add current request
            requests.append(current_time)
            return True
    
    def get_rate_limit_status(self, identifier: str, rule_name: str = "api_general") -> Dict[str, Any]:
        """Get rate limit status for identifier"""
        with self.lock:
            rule = self.rules.get(rule_name)
            if not rule:
                return {"error": "Rule not found"}
            
            # Check if blocked
            if identifier in self.blocked_ips:
                blocked_until = self.blocked_ips[identifier]
                if datetime.now() < blocked_until:
                    return {
                        "blocked": True,
                        "blocked_until": blocked_until.isoformat(),
                        "remaining_block_time": (blocked_until - datetime.now()).total_seconds()
                    }
            
            # Count current requests in window
            current_time = time.time()
            window_start = current_time - rule.window_seconds
            requests = self.request_history[f"{identifier}:{rule_name}"]
            
            current_count = sum(1 for req_time in requests if req_time >= window_start)
            
            return {
                "blocked": False,
                "current_requests": current_count,
                "max_requests": rule.max_requests,
                "window_seconds": rule.window_seconds,
                "remaining_requests": max(0, rule.max_requests - current_count),
                "reset_time": window_start + rule.window_seconds
            }


class InputSanitizer:
    """Enhanced input sanitization for security"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        
        # Dangerous patterns
        self.sql_injection_patterns = [
            r"(\bUNION\b.*\bSELECT\b)",
            r"(\bINSERT\b.*\bINTO\b)",
            r"(\bDELETE\b.*\bFROM\b)",
            r"(\bUPDATE\b.*\bSET\b)",
            r"(\bDROP\b.*\bTABLE\b)",
            r"('.*'.*\bOR\b.*'.*')",
            r"(;.*--)",
        ]
        
        self.xss_patterns = [
            r"(<script[^>]*>.*?</script>)",
            r"(javascript:)",
            r"(onload=)",
            r"(onerror=)",
            r"(onclick=)",
            r"(<iframe[^>]*>)",
            r"(<object[^>]*>)",
            r"(<embed[^>]*>)",
        ]
        
        self.path_traversal_patterns = [
            r"(\.\.[\\/])",
            r"([\\/]\.\.[\\/])",
            r"(%2e%2e[\\/])",
            r"(\.\.%2f)",
            r"(%2e%2e%2f)",
        ]
        
        self.command_injection_patterns = [
            r"(\||&|;|`|\$\(|\${)",
            r"(>\s*\w+)",
            r"(<\s*\w+)",
            r"(\bnc\b|\bnetcat\b)",
            r"(\bcurl\b|\bwget\b)",
            r"(\bsh\b|\bbash\b|\bzsh\b)",
        ]
    
    def detect_sql_injection(self, input_str: str) -> bool:
        """Detect potential SQL injection attempts"""
        return self._check_patterns(input_str.upper(), self.sql_injection_patterns)
    
    def detect_xss(self, input_str: str) -> bool:
        """Detect potential XSS attempts"""
        return self._check_patterns(input_str.lower(), self.xss_patterns)
    
    def detect_path_traversal(self, input_str: str) -> bool:
        """Detect potential path traversal attempts"""
        return self._check_patterns(input_str.lower(), self.path_traversal_patterns)
    
    def detect_command_injection(self, input_str: str) -> bool:
        """Detect potential command injection attempts"""
        return self._check_patterns(input_str, self.command_injection_patterns)
    
    def _check_patterns(self, input_str: str, patterns: List[str]) -> bool:
        """Check input against pattern list"""
        for pattern in patterns:
            if re.search(pattern, input_str, re.IGNORECASE):
                return True
        return False
    
    def sanitize_and_validate(self, input_str: str, input_type: str = "general") -> str:
        """Comprehensive input sanitization and validation"""
        if not isinstance(input_str, str):
            input_str = str(input_str)
        
        original_input = input_str
        
        # Check for malicious patterns
        threats_detected = []
        
        if self.detect_sql_injection(input_str):
            threats_detected.append("sql_injection")
        
        if self.detect_xss(input_str):
            threats_detected.append("xss")
        
        if self.detect_path_traversal(input_str):
            threats_detected.append("path_traversal")
        
        if self.detect_command_injection(input_str):
            threats_detected.append("command_injection")
        
        if threats_detected:
            self.logger.warning(f"Malicious input detected: {threats_detected} in '{original_input[:100]}'")
            raise SecurityError(f"Malicious input detected: {', '.join(threats_detected)}")
        
        # Basic sanitization
        input_str = input_str.strip()
        
        # Remove null bytes
        input_str = input_str.replace('\x00', '')
        
        # Type-specific sanitization
        if input_type == "filename":
            # Remove dangerous characters for filenames
            input_str = re.sub(r'[<>:"/\\|?*]', '', input_str)
            input_str = input_str.replace('..', '')
        elif input_type == "email":
            # Basic email sanitization
            if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', input_str):
                raise ValidationError("Invalid email format")
        elif input_type == "url":
            # URL validation
            if not re.match(r'^https?://[^\s/$.?#].[^\s]*$', input_str):
                raise ValidationError("Invalid URL format")
        
        return input_str


class SecurityHardeningManager:
    """Main security hardening system"""
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.ENHANCED):
        self.logger = get_logger(__name__)
        self.config_manager = get_config_manager()
        self.db = get_database_manager()
        
        self.security_level = security_level
        self.token_manager = SecurityTokenManager()
        self.rate_limiter = RateLimiter()
        self.input_sanitizer = InputSanitizer()
        
        # Security events
        self.security_events: deque = deque(maxlen=10000)
        self.blocked_ips: Set[str] = set()
        self.suspicious_activities: Dict[str, List[SecurityEvent]] = defaultdict(list)
        
        # Monitoring
        self.monitoring_active = False
        self.monitoring_thread: Optional[threading.Thread] = None
        
        # Security policies
        self.security_policies = self._get_security_policies()
        
        self.logger.info(f"Security hardening initialized with {security_level.value} level")
    
    def _get_security_policies(self) -> Dict[str, Any]:
        """Get security policies based on security level"""
        base_policies = {
            "max_login_attempts": 5,
            "session_timeout_minutes": 60,
            "password_min_length": 8,
            "require_https": True,
            "log_security_events": True,
            "auto_block_threats": True,
            "token_expiry_minutes": 60
        }
        
        if self.security_level == SecurityLevel.ENHANCED:
            base_policies.update({
                "max_login_attempts": 3,
                "session_timeout_minutes": 30,
                "password_min_length": 12,
                "require_2fa": True,
                "strict_input_validation": True,
                "enhanced_logging": True
            })
        elif self.security_level == SecurityLevel.PARANOID:
            base_policies.update({
                "max_login_attempts": 2,
                "session_timeout_minutes": 15,
                "password_min_length": 16,
                "require_2fa": True,
                "require_password_complexity": True,
                "strict_input_validation": True,
                "enhanced_logging": True,
                "require_ip_whitelist": True,
                "encrypt_all_communications": True
            })
        
        return base_policies
    
    def record_security_event(self, event: SecurityEvent):
        """Record a security event"""
        self.security_events.append(event)
        
        # Log to database
        if self.security_policies.get("log_security_events", True):
            try:
                self.db.record_event(
                    event_type="security_event",
                    severity="warning" if event.threat_level in [ThreatLevel.LOW, ThreatLevel.MEDIUM] else "error",
                    message=f"Security event: {event.event_type.value} - {event.description}",
                    details={
                        "attack_type": event.event_type.value,
                        "threat_level": event.threat_level.value,
                        "source_ip": event.source_ip,
                        "user_id": event.user_id,
                        "blocked": event.blocked,
                        "metadata": event.metadata
                    }
                )
            except Exception as e:
                self.logger.error(f"Failed to log security event: {e}")
        
        # Auto-block if configured
        if (self.security_policies.get("auto_block_threats", True) and 
            event.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL] and
            event.source_ip):
            self.block_ip(event.source_ip, f"Auto-blocked due to {event.event_type.value}")
        
        self.logger.warning(f"Security event recorded: {event.event_type.value} from {event.source_ip or 'unknown'}")
    
    def block_ip(self, ip_address: str, reason: str = "Security violation"):
        """Block an IP address"""
        try:
            # Validate IP address
            ipaddress.ip_address(ip_address)
            
            self.blocked_ips.add(ip_address)
            
            # Record blocking event
            event = SecurityEvent(
                event_type=AttackType.UNAUTHORIZED_ACCESS,
                threat_level=ThreatLevel.HIGH,
                source_ip=ip_address,
                description=f"IP blocked: {reason}",
                blocked=True
            )
            self.record_security_event(event)
            
            self.logger.warning(f"Blocked IP {ip_address}: {reason}")
            
        except ValueError:
            self.logger.error(f"Invalid IP address format: {ip_address}")
    
    def unblock_ip(self, ip_address: str):
        """Unblock an IP address"""
        if ip_address in self.blocked_ips:
            self.blocked_ips.remove(ip_address)
            self.logger.info(f"Unblocked IP {ip_address}")
    
    def is_ip_blocked(self, ip_address: str) -> bool:
        """Check if IP address is blocked"""
        return ip_address in self.blocked_ips
    
    def validate_and_sanitize_input(self, input_data: Any, input_type: str = "general",
                                   source_ip: str = None) -> Any:
        """Comprehensive input validation and sanitization"""
        try:
            if isinstance(input_data, str):
                return self.input_sanitizer.sanitize_and_validate(input_data, input_type)
            elif isinstance(input_data, dict):
                sanitized_dict = {}
                for key, value in input_data.items():
                    sanitized_key = self.input_sanitizer.sanitize_and_validate(str(key), "general")
                    if isinstance(value, str):
                        sanitized_value = self.input_sanitizer.sanitize_and_validate(value, input_type)
                    else:
                        sanitized_value = value
                    sanitized_dict[sanitized_key] = sanitized_value
                return sanitized_dict
            else:
                return input_data
                
        except (SecurityError, ValidationError) as e:
            # Record security event
            event = SecurityEvent(
                event_type=AttackType.INVALID_INPUT,
                threat_level=ThreatLevel.MEDIUM,
                source_ip=source_ip,
                description=f"Invalid input detected: {str(e)}",
                metadata={"input_type": input_type}
            )
            self.record_security_event(event)
            raise
    
    def check_rate_limit(self, identifier: str, operation: str = "api_general") -> bool:
        """Check rate limits for operation"""
        return self.rate_limiter.check_rate_limit(identifier, operation)
    
    def generate_secure_session_token(self, user_id: str) -> str:
        """Generate secure session token"""
        token = self.token_manager.generate_secure_token(
            purpose=f"session:{user_id}",
            expires_in=self.security_policies.get("token_expiry_minutes", 60) * 60
        )
        
        self.logger.info(f"Generated session token for user {user_id}")
        return token
    
    def validate_session_token(self, token: str, user_id: str) -> bool:
        """Validate session token"""
        return self.token_manager.validate_token(token, f"session:{user_id}", consume=False)
    
    def get_security_metrics(self) -> Dict[str, Any]:
        """Get security metrics and statistics"""
        # Count events by type and threat level
        event_counts = defaultdict(int)
        threat_level_counts = defaultdict(int)
        
        for event in self.security_events:
            event_counts[event.event_type.value] += 1
            threat_level_counts[event.threat_level.value] += 1
        
        # Recent events (last 24 hours)
        recent_cutoff = datetime.now() - timedelta(hours=24)
        recent_events = sum(1 for event in self.security_events if event.timestamp > recent_cutoff)
        
        return {
            "security_level": self.security_level.value,
            "total_events": len(self.security_events),
            "recent_events_24h": recent_events,
            "blocked_ips_count": len(self.blocked_ips),
            "event_types": dict(event_counts),
            "threat_levels": dict(threat_level_counts),
            "active_tokens": len(self.token_manager.active_tokens),
            "rate_limit_rules": len(self.rate_limiter.rules),
            "policies": self.security_policies
        }
    
    def get_security_report(self) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        metrics = self.get_security_metrics()
        
        # Top threat sources
        ip_threat_counts = defaultdict(int)
        for event in self.security_events:
            if event.source_ip:
                ip_threat_counts[event.source_ip] += 1
        
        top_threat_sources = sorted(ip_threat_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Recent critical events
        recent_critical = [
            {
                "type": event.event_type.value,
                "threat_level": event.threat_level.value,
                "source_ip": event.source_ip,
                "description": event.description,
                "timestamp": event.timestamp.isoformat()
            }
            for event in reversed(list(self.security_events))
            if event.threat_level == ThreatLevel.CRITICAL
        ][:10]
        
        # Security recommendations
        recommendations = self._generate_security_recommendations()
        
        return {
            "timestamp": datetime.now().isoformat(),
            "metrics": metrics,
            "top_threat_sources": [{"ip": ip, "event_count": count} for ip, count in top_threat_sources],
            "recent_critical_events": recent_critical,
            "blocked_ips": list(self.blocked_ips),
            "recommendations": recommendations
        }
    
    def _generate_security_recommendations(self) -> List[str]:
        """Generate security recommendations based on current state"""
        recommendations = []
        
        # Check for high-frequency attacks
        recent_events = [e for e in self.security_events 
                        if e.timestamp > datetime.now() - timedelta(hours=1)]
        
        if len(recent_events) > 10:
            recommendations.append("High number of security events detected in the last hour. Consider reviewing access patterns.")
        
        # Check blocked IPs
        if len(self.blocked_ips) > 5:
            recommendations.append("Multiple IPs have been blocked. Review threat sources and consider additional security measures.")
        
        # Security level recommendations
        if self.security_level == SecurityLevel.BASIC:
            recommendations.append("Consider upgrading to Enhanced security level for better protection.")
        
        # Rate limiting
        if not self.rate_limiter.rules:
            recommendations.append("No rate limiting rules configured. Enable rate limiting for better security.")
        
        if not recommendations:
            recommendations.append("Security posture is good. Continue monitoring.")
        
        return recommendations
    
    def start_monitoring(self):
        """Start security monitoring"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        self.logger.info("Security monitoring started")
    
    def stop_monitoring(self):
        """Stop security monitoring"""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        self.logger.info("Security monitoring stopped")
    
    def _monitoring_loop(self):
        """Security monitoring loop"""
        while self.monitoring_active:
            try:
                # Cleanup expired tokens
                self.token_manager.cleanup_expired_tokens()
                
                # Analyze recent events for patterns
                self._analyze_threat_patterns()
                
                # Check system security state
                self._check_system_security()
                
                time.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Error in security monitoring loop: {e}")
                time.sleep(60)
    
    def _analyze_threat_patterns(self):
        """Analyze recent events for threat patterns"""
        recent_cutoff = datetime.now() - timedelta(minutes=15)
        recent_events = [e for e in self.security_events if e.timestamp > recent_cutoff]
        
        # Group by source IP
        ip_events = defaultdict(list)
        for event in recent_events:
            if event.source_ip:
                ip_events[event.source_ip].append(event)
        
        # Check for suspicious patterns
        for ip, events in ip_events.items():
            if len(events) >= 5:  # 5 or more events in 15 minutes
                if ip not in self.blocked_ips:
                    self.block_ip(ip, f"Suspicious activity: {len(events)} events in 15 minutes")
    
    def _check_system_security(self):
        """Check overall system security state"""
        # This could include checking file permissions, configuration security, etc.
        pass


# Security decorators

def require_security_token(token_purpose: str = "general"):
    """Decorator to require valid security token"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # This would need to be implemented with actual token validation
            # For now, just a placeholder
            return func(*args, **kwargs)
        return wrapper
    return decorator


def rate_limited(rule_name: str = "api_general"):
    """Decorator for rate limiting"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            security_manager = get_security_hardening_manager()
            
            # Extract identifier (would need actual implementation)
            identifier = "default"  # This should be extracted from request context
            
            if not security_manager.check_rate_limit(identifier, rule_name):
                raise SecurityError("Rate limit exceeded")
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


# Global instance
_security_hardening_manager = None

def get_security_hardening_manager() -> SecurityHardeningManager:
    """Get global security hardening manager"""
    global _security_hardening_manager
    if _security_hardening_manager is None:
        _security_hardening_manager = SecurityHardeningManager()
    return _security_hardening_manager