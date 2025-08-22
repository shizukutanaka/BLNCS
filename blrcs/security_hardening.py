# BLRCS Security Hardening Module
# Advanced security features and hardening measures
import os
import re
import time
import hashlib
import secrets
import ipaddress
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
from collections import defaultdict

@dataclass
class SecurityEvent:
    """Security event record"""
    timestamp: float
    event_type: str
    severity: str
    source_ip: str
    user_agent: str
    details: Dict[str, Any]
    blocked: bool

@dataclass
class ThreatIntelligence:
    """Threat intelligence data"""
    ip_address: str
    threat_type: str
    confidence: float
    first_seen: float
    last_seen: float
    attack_count: int

class InputValidator:
    """Advanced input validation and sanitization"""
    
    # Dangerous patterns
    SQL_INJECTION_PATTERNS = [
        r"(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b)",
        r"(;|\|\||&&|--|\#|\*|\/\*)",
        r"(\bOR\b|\bAND\b)[\s]+[\d\w]+[\s]*=[\s]*[\d\w]+",
        r"(1=1|1\s*=\s*1|true|TRUE)"
    ]
    
    XSS_PATTERNS = [
        r"<\s*script[^>]*>.*?<\s*/\s*script\s*>",
        r"javascript:",
        r"on\w+\s*=",
        r"<\s*iframe[^>]*>",
        r"<\s*object[^>]*>",
        r"<\s*embed[^>]*>",
        r"<\s*link[^>]*>"
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\.[\\/]",
        r"[\\/]\.\.[\\/]",
        r"[\\/]\.\.($|[\\/])",
        r"^\.\.[\\/]"
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        r"[;&|`$()]",
        r"\b(cat|ls|dir|type|echo|curl|wget|nc|netcat)\b",
        r"(>|>>|<|\||&)"
    ]
    
    def __init__(self):
        self.blocked_inputs: List[str] = []
    
    def validate_sql_input(self, input_str: str) -> Tuple[bool, str]:
        """Validate input for SQL injection attempts"""
        if not input_str:
            return True, ""
        
        input_lower = input_str.lower()
        
        for pattern in self.SQL_INJECTION_PATTERNS:
            if re.search(pattern, input_lower, re.IGNORECASE):
                self.blocked_inputs.append(input_str)
                return False, f"SQL injection pattern detected: {pattern}"
        
        return True, ""
    
    def validate_xss_input(self, input_str: str) -> Tuple[bool, str]:
        """Validate input for XSS attempts"""
        if not input_str:
            return True, ""
        
        for pattern in self.XSS_PATTERNS:
            if re.search(pattern, input_str, re.IGNORECASE):
                self.blocked_inputs.append(input_str)
                return False, f"XSS pattern detected: {pattern}"
        
        return True, ""
    
    def validate_path_traversal(self, path_str: str) -> Tuple[bool, str]:
        """Validate path for traversal attempts"""
        if not path_str:
            return True, ""
        
        for pattern in self.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, path_str):
                self.blocked_inputs.append(path_str)
                return False, f"Path traversal pattern detected: {pattern}"
        
        return True, ""
    
    def validate_command_injection(self, input_str: str) -> Tuple[bool, str]:
        """Validate input for command injection attempts"""
        if not input_str:
            return True, ""
        
        for pattern in self.COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, input_str, re.IGNORECASE):
                self.blocked_inputs.append(input_str)
                return False, f"Command injection pattern detected: {pattern}"
        
        return True, ""
    
    def sanitize_input(self, input_str: str, max_length: int = 500) -> str:
        """Enhanced input sanitization with strict filtering"""
        if not input_str:
            return ""
        
        # Truncate to max length (reduced from 1000 to 500)
        sanitized = input_str[:max_length]
        
        # Remove null bytes and control characters
        sanitized = ''.join(char for char in sanitized if ord(char) >= 32 or char in '\t\n\r')
        
        # Remove potential script injection
        dangerous_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'vbscript:',
            r'on\w+\s*=',
            r'data:text/html',
            r'data:application/javascript'
        ]
        
        for pattern in dangerous_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE | re.DOTALL)
        
        # Escape HTML entities
        sanitized = sanitized.replace('&', '&amp;')
        sanitized = sanitized.replace('<', '&lt;')
        sanitized = sanitized.replace('>', '&gt;')
        sanitized = sanitized.replace('"', '&quot;')
        sanitized = sanitized.replace("'", '&#x27;')
        sanitized = sanitized.replace('/', '&#x2F;')
        
        return sanitized
    
    def validate_all(self, input_str: str) -> Tuple[bool, List[str]]:
        """Run all validation checks"""
        errors = []
        
        sql_valid, sql_error = self.validate_sql_input(input_str)
        if not sql_valid:
            errors.append(sql_error)
        
        xss_valid, xss_error = self.validate_xss_input(input_str)
        if not xss_valid:
            errors.append(xss_error)
        
        path_valid, path_error = self.validate_path_traversal(input_str)
        if not path_valid:
            errors.append(path_error)
        
        cmd_valid, cmd_error = self.validate_command_injection(input_str)
        if not cmd_valid:
            errors.append(cmd_error)
        
        return len(errors) == 0, errors

class ThreatDetection:
    """Advanced threat detection system"""
    
    def __init__(self):
        self.security_events: List[SecurityEvent] = []
        self.threat_intelligence: Dict[str, ThreatIntelligence] = {}
        self.blocked_ips: Set[str] = set()
        self.suspicious_patterns: Dict[str, int] = defaultdict(int)
        
        # Load known malicious IPs
        self._load_threat_intelligence()
    
    def _load_threat_intelligence(self):
        """Load threat intelligence data"""
        # Known malicious IP ranges (examples)
        malicious_ranges = [
            "10.0.0.0/8",    # Private ranges that shouldn't be external
            "127.0.0.0/8",   # Localhost
            "169.254.0.0/16", # Link-local
            "172.16.0.0/12", # Private
            "192.168.0.0/16" # Private
        ]
        
        for ip_range in malicious_ranges:
            self.threat_intelligence[ip_range] = ThreatIntelligence(
                ip_address=ip_range,
                threat_type="suspicious_range",
                confidence=0.8,
                first_seen=time.time(),
                last_seen=time.time(),
                attack_count=0
            )
    
    def is_ip_malicious(self, ip_address: str) -> Tuple[bool, str]:
        """Check if IP address is known to be malicious"""
        try:
            ip = ipaddress.ip_address(ip_address)
            
            # Check against threat intelligence
            for range_str, threat in self.threat_intelligence.items():
                if '/' in range_str:
                    try:
                        network = ipaddress.ip_network(range_str)
                        if ip in network:
                            return True, threat.threat_type
                    except:
                        continue
                elif ip_address == range_str:
                    return True, threat.threat_type
            
            return False, ""
        
        except ValueError:
            return True, "invalid_ip"
    
    def detect_brute_force(self, ip_address: str, failed_attempts: int, 
                          time_window: int = 300) -> bool:
        """Detect brute force attacks"""
        current_time = time.time()
        
        # Count recent failed attempts from this IP
        recent_events = [
            event for event in self.security_events
            if (event.source_ip == ip_address and 
                event.event_type == "auth_failure" and
                current_time - event.timestamp < time_window)
        ]
        
        return len(recent_events) >= failed_attempts
    
    def detect_rate_limiting_abuse(self, ip_address: str, 
                                  request_count: int, time_window: int = 60) -> bool:
        """Detect rate limiting abuse"""
        current_time = time.time()
        
        recent_requests = [
            event for event in self.security_events
            if (event.source_ip == ip_address and 
                current_time - event.timestamp < time_window)
        ]
        
        return len(recent_requests) >= request_count
    
    def detect_suspicious_user_agent(self, user_agent: str) -> bool:
        """Detect suspicious user agents"""
        suspicious_patterns = [
            r"bot|crawler|spider|scraper",
            r"curl|wget|python|perl|ruby",
            r"scanner|exploit|hack|attack",
            r"nikto|sqlmap|nmap|metasploit"
        ]
        
        if not user_agent:
            return True
        
        user_agent_lower = user_agent.lower()
        
        for pattern in suspicious_patterns:
            if re.search(pattern, user_agent_lower):
                return True
        
        return False
    
    def log_security_event(self, event_type: str, severity: str,
                          source_ip: str, user_agent: str,
                          details: Dict[str, Any], blocked: bool = False):
        """Log security event"""
        event = SecurityEvent(
            timestamp=time.time(),
            event_type=event_type,
            severity=severity,
            source_ip=source_ip,
            user_agent=user_agent,
            details=details,
            blocked=blocked
        )
        
        self.security_events.append(event)
        
        # Update threat intelligence
        if source_ip not in self.threat_intelligence:
            self.threat_intelligence[source_ip] = ThreatIntelligence(
                ip_address=source_ip,
                threat_type=event_type,
                confidence=0.5,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                attack_count=1
            )
        else:
            threat = self.threat_intelligence[source_ip]
            threat.last_seen = event.timestamp
            threat.attack_count += 1
            threat.confidence = min(1.0, threat.confidence + 0.1)
    
    def get_security_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get security summary for specified hours"""
        cutoff_time = time.time() - (hours * 3600)
        
        recent_events = [
            event for event in self.security_events
            if event.timestamp >= cutoff_time
        ]
        
        # Group by event type
        event_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        top_attackers = defaultdict(int)
        
        for event in recent_events:
            event_counts[event.event_type] += 1
            severity_counts[event.severity] += 1
            top_attackers[event.source_ip] += 1
        
        return {
            "time_period_hours": hours,
            "total_events": len(recent_events),
            "blocked_events": sum(1 for e in recent_events if e.blocked),
            "event_types": dict(event_counts),
            "severity_levels": dict(severity_counts),
            "top_attackers": dict(sorted(top_attackers.items(), 
                                       key=lambda x: x[1], reverse=True)[:10]),
            "blocked_ips_count": len(self.blocked_ips)
        }

class SecurityHeaders:
    """Security headers management"""
    
    @staticmethod
    def get_security_headers() -> Dict[str, str]:
        """Get comprehensive security headers"""
        return {
            # Content Security Policy
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "font-src 'self'; "
                "connect-src 'self'; "
                "media-src 'self'; "
                "object-src 'none'; "
                "child-src 'none'; "
                "worker-src 'none'; "
                "frame-ancestors 'none'; "
                "form-action 'self'; "
                "upgrade-insecure-requests;"
            ),
            
            # HTTPS Transport Security
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            
            # Prevent MIME type sniffing
            "X-Content-Type-Options": "nosniff",
            
            # XSS Protection
            "X-XSS-Protection": "1; mode=block",
            
            # Frame Options
            "X-Frame-Options": "DENY",
            
            # Referrer Policy
            "Referrer-Policy": "strict-origin-when-cross-origin",
            
            # Permissions Policy
            "Permissions-Policy": (
                "accelerometer=(), "
                "camera=(), "
                "geolocation=(), "
                "gyroscope=(), "
                "magnetometer=(), "
                "microphone=(), "
                "payment=(), "
                "usb=()"
            ),
            
            # Cache Control for sensitive pages
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
            
            # Server identification
            "Server": "BLRCS/1.0"
        }

class FileSystemSecurity:
    """File system security and access control"""
    
    def __init__(self, allowed_extensions: Set[str] = None,
                 max_file_size: int = 10 * 1024 * 1024):  # 10MB
        self.allowed_extensions = allowed_extensions or {
            '.txt', '.json', '.csv', '.xml', '.log'
        }
        self.max_file_size = max_file_size
        self.quarantine_dir = Path("quarantine")
        self.quarantine_dir.mkdir(exist_ok=True)
    
    def validate_file_upload(self, file_path: Path, content: bytes) -> Tuple[bool, str]:
        """Validate file upload for security"""
        # Check file size
        if len(content) > self.max_file_size:
            return False, f"File too large: {len(content)} bytes"
        
        # Check file extension
        if file_path.suffix.lower() not in self.allowed_extensions:
            return False, f"File extension not allowed: {file_path.suffix}"
        
        # Check for dangerous content
        dangerous_patterns = [
            b'<script',
            b'javascript:',
            b'<?php',
            b'<%',
            b'\x00',  # Null bytes
            b'\xff\xd8\xff',  # JPEG header (if not allowing images)
            b'\x89PNG',  # PNG header
            b'GIF8',  # GIF header
        ]
        
        content_lower = content.lower()
        for pattern in dangerous_patterns:
            if pattern in content_lower:
                return False, f"Dangerous content detected: {pattern}"
        
        return True, ""
    
    def quarantine_file(self, file_path: Path, reason: str):
        """Move suspicious file to quarantine"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        quarantine_file = self.quarantine_dir / f"{timestamp}_{file_path.name}"
        
        try:
            file_path.rename(quarantine_file)
            
            # Create info file
            info_file = quarantine_file.with_suffix('.info')
            with open(info_file, 'w') as f:
                json.dump({
                    'original_path': str(file_path),
                    'quarantine_time': timestamp,
                    'reason': reason
                }, f, indent=2)
        
        except Exception:
            pass

class SecurityHardening:
    """Main security hardening coordinator"""
    
    def __init__(self):
        self.input_validator = InputValidator()
        self.threat_detection = ThreatDetection()
        self.filesystem_security = FileSystemSecurity()
        self.security_config = self._load_security_config()
    
    def _load_security_config(self) -> Dict[str, Any]:
        """Load enhanced security configuration"""
        return {
            "max_login_attempts": 3,  # Reduced from 5 to 3
            "lockout_duration": 900,  # 15 minutes
            "session_timeout": 900,   # Reduced to 15 minutes
            "password_min_length": 14,  # Increased from 12 to 14
            "password_require_special": True,
            "password_require_uppercase": True,
            "password_require_lowercase": True,
            "password_require_numbers": True,
            "password_max_age_days": 90,
            "password_history_count": 12,
            "enable_2fa": True,
            "log_all_requests": True,
            "enable_honeypot": True,
            "input_max_length": 500,  # Reduced from 1000
            "api_key_rotation_days": 30,
            "enable_rate_limiting": True,
            "rate_limit_window": 60,  # 1 minute
            "rate_limit_requests": 100,
            "enable_ip_whitelist": False,
            "allowed_ip_ranges": [],
            "blocked_user_agents": [
                "bot", "crawler", "spider", "scraper",
                "curl", "wget", "python-requests"
            ]
        }
    
    def validate_request(self, request_data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Comprehensive request validation"""
        errors = []
        
        # Validate IP address
        source_ip = request_data.get('source_ip', '')
        is_malicious, threat_type = self.threat_detection.is_ip_malicious(source_ip)
        
        if is_malicious:
            errors.append(f"Malicious IP detected: {threat_type}")
            self.threat_detection.log_security_event(
                "malicious_ip", "high", source_ip, 
                request_data.get('user_agent', ''),
                {"threat_type": threat_type}, blocked=True
            )
        
        # Validate user agent
        user_agent = request_data.get('user_agent', '')
        if self.threat_detection.detect_suspicious_user_agent(user_agent):
            errors.append("Suspicious user agent detected")
            self.threat_detection.log_security_event(
                "suspicious_user_agent", "medium", source_ip, user_agent,
                {"user_agent": user_agent}
            )
        
        # Validate input parameters
        for key, value in request_data.get('parameters', {}).items():
            if isinstance(value, str):
                is_valid, validation_errors = self.input_validator.validate_all(value)
                if not is_valid:
                    errors.extend([f"{key}: {err}" for err in validation_errors])
                    self.threat_detection.log_security_event(
                        "input_validation_failure", "high", source_ip, user_agent,
                        {"parameter": key, "errors": validation_errors}, blocked=True
                    )
        
        return len(errors) == 0, errors
    
    def generate_security_report(self) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        summary = self.threat_detection.get_security_summary(24)
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "security_summary": summary,
            "threat_intelligence": {
                "total_threats": len(self.threat_detection.threat_intelligence),
                "blocked_ips": len(self.threat_detection.blocked_ips),
                "high_confidence_threats": sum(
                    1 for t in self.threat_detection.threat_intelligence.values()
                    if t.confidence > 0.8
                )
            },
            "input_validation": {
                "blocked_inputs": len(self.input_validator.blocked_inputs),
                "recent_blocks": self.input_validator.blocked_inputs[-10:]
            },
            "recommendations": self._generate_security_recommendations()
        }
        
        return report
    
    def _generate_security_recommendations(self) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # Check for high attack volume
        summary = self.threat_detection.get_security_summary(1)
        if summary["total_events"] > 100:
            recommendations.append("High attack volume detected - consider enabling additional rate limiting")
        
        # Check for blocked IPs
        if len(self.threat_detection.blocked_ips) > 50:
            recommendations.append("Large number of blocked IPs - review firewall rules")
        
        # Check for input validation failures
        if len(self.input_validator.blocked_inputs) > 20:
            recommendations.append("High number of input validation failures - review application input handling")
        
        return recommendations

# Global security hardening instance
_security_hardening: Optional[SecurityHardening] = None

def get_security_hardening() -> SecurityHardening:
    """Get global security hardening instance"""
    global _security_hardening
    
    if _security_hardening is None:
        _security_hardening = SecurityHardening()
    
    return _security_hardening

def validate_input(input_str: str) -> Tuple[bool, List[str]]:
    """Quick input validation function"""
    validator = InputValidator()
    return validator.validate_all(input_str)

def get_security_headers() -> Dict[str, str]:
    """Get security headers for HTTP responses"""
    return SecurityHeaders.get_security_headers()