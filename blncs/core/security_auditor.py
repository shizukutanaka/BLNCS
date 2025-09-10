"""
Security Auditing and Hardening System
Implements security checks, file permission auditing, and anomaly detection.
"""

import os
import stat
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum
import hashlib
import json
from pathlib import Path

from .logger import get_logger
from .config_manager import get_config_manager
from .database import get_database_manager
from .metrics import get_metrics_collector, increment_counter, set_gauge


class SecurityRiskLevel(Enum):
    """Security risk levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityCheckType(Enum):
    """Types of security checks"""
    FILE_PERMISSIONS = "file_permissions"
    CONFIGURATION = "configuration"
    NETWORK_ACCESS = "network_access"
    LOG_ANALYSIS = "log_analysis"
    PROCESS_MONITORING = "process_monitoring"


@dataclass
class SecurityFinding:
    """A security finding or vulnerability"""
    finding_id: str
    check_type: SecurityCheckType
    risk_level: SecurityRiskLevel
    title: str
    description: str
    affected_resource: str
    recommendation: str
    timestamp: datetime
    resolved: bool = False
    false_positive: bool = False


@dataclass
class FileSecurityInfo:
    """File security information"""
    path: str
    permissions: str
    owner: str
    group: str
    size: int
    modified_time: datetime
    is_sensitive: bool = False
    expected_permissions: Optional[str] = None


class SecurityAuditor:
    """Comprehensive security auditing system"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config_manager()
        self.db = get_database_manager()
        
        # Metrics
        self.metrics = get_metrics_collector()
        
        # State management
        self.is_running = False
        self.audit_thread = None
        self._stop_event = threading.Event()
        
        # Security findings
        self.findings: Dict[str, SecurityFinding] = {}
        self.finding_history: deque = deque(maxlen=500)
        
        # File monitoring
        self.monitored_files: Dict[str, FileSecurityInfo] = {}
        self.file_baselines: Dict[str, str] = {}  # path -> hash
        
        # Configuration
        self.audit_interval = self.config.get('security.audit_interval_minutes', 60) * 60
        self.sensitive_paths = self._get_sensitive_paths()
        self.security_rules = self._load_security_rules()
        
        # Log analysis
        self.suspicious_patterns = [
            r'failed.*login',
            r'authentication.*failed',
            r'permission.*denied',
            r'unauthorized.*access',
            r'security.*violation',
            r'malicious.*activity',
            r'exploit.*attempt'
        ]
        
        self.logger.info("Security auditor initialized")
    
    def _get_sensitive_paths(self) -> List[str]:
        """Get list of sensitive file paths to monitor"""
        default_paths = [
            "config/config.yaml",
            "blncs.db",
            ".env",
            "security/",
            "~/.lnd/",
            "~/.lightning/",
            "/etc/lnd.conf",
            "/etc/lightning/"
        ]
        
        config_paths = self.config.get('security.sensitive_paths', [])
        return list(set(default_paths + config_paths))
    
    def _load_security_rules(self) -> Dict[str, Any]:
        """Load security rules and policies"""
        default_rules = {
            'file_permissions': {
                'config/config.yaml': '600',
                'blncs.db': '600',
                '.env': '600',
                'security/': '700'
            },
            'forbidden_patterns': [
                'password',
                'secret',
                'private_key',
                'mnemonic'
            ],
            'max_file_age_days': 365,
            'max_log_file_size_mb': 100
        }
        
        config_rules = self.config.get('security.rules', {})
        return {**default_rules, **config_rules}
    
    def start_auditing(self) -> bool:
        """Start security auditing"""
        if self.is_running:
            self.logger.warning("Security auditing is already running")
            return False
        
        self.is_running = True
        self._stop_event.clear()
        
        # Perform initial security scan
        self._perform_comprehensive_audit()
        
        # Start continuous monitoring
        self.audit_thread = threading.Thread(
            target=self._audit_loop,
            name="SecurityAuditThread",
            daemon=True
        )
        self.audit_thread.start()
        
        self.logger.info("Security auditing started")
        increment_counter('security_audits_started_total')
        return True
    
    def stop_auditing(self) -> bool:
        """Stop security auditing"""
        if not self.is_running:
            return False
        
        self.is_running = False
        self._stop_event.set()
        
        if self.audit_thread and self.audit_thread.is_alive():
            self.audit_thread.join(timeout=10)
        
        self.logger.info("Security auditing stopped")
        increment_counter('security_audits_stopped_total')
        return True
    
    def _audit_loop(self):
        """Main security audit loop"""
        self.logger.info(f"Security audit loop started (interval: {self.audit_interval}s)")
        
        while not self._stop_event.wait(self.audit_interval):
            try:
                start_time = time.time()
                
                # Perform security checks
                findings_count = self._perform_comprehensive_audit()
                
                # Update metrics
                duration = time.time() - start_time
                set_gauge('security_audit_duration_seconds', duration)
                set_gauge('security_active_findings', len([f for f in self.findings.values() if not f.resolved]))
                
                if findings_count > 0:
                    self.logger.warning(f"Security audit completed: {findings_count} new findings")
                    increment_counter('security_audits_with_findings_total')
                else:
                    increment_counter('security_audits_clean_total')
                
            except Exception as e:
                self.logger.error(f"Security audit loop error: {e}")
                increment_counter('security_audit_errors_total')
        
        self.logger.info("Security audit loop stopped")
    
    def _perform_comprehensive_audit(self) -> int:
        """Perform comprehensive security audit"""
        new_findings = 0
        
        try:
            # File permission checks
            new_findings += self._audit_file_permissions()
            
            # Configuration security
            new_findings += self._audit_configuration_security()
            
            # File integrity monitoring
            new_findings += self._audit_file_integrity()
            
            # Log analysis
            new_findings += self._audit_log_files()
            
            # Process monitoring
            new_findings += self._audit_running_processes()
            
            # Network security
            new_findings += self._audit_network_security()
            
        except Exception as e:
            self.logger.error(f"Error during comprehensive audit: {e}")
        
        return new_findings
    
    def _audit_file_permissions(self) -> int:
        """Audit file permissions for sensitive files"""
        new_findings = 0
        
        try:
            expected_perms = self.security_rules.get('file_permissions', {})
            
            for path_pattern, expected_perm in expected_perms.items():
                # Handle glob patterns and direct paths
                if '*' in path_pattern or '?' in path_pattern:
                    from glob import glob
                    paths = glob(path_pattern)
                else:
                    paths = [path_pattern] if os.path.exists(path_pattern) else []
                
                for file_path in paths:
                    try:
                        if not os.path.exists(file_path):
                            continue
                        
                        # Get file permissions
                        file_stat = os.stat(file_path)
                        current_perm = oct(file_stat.st_mode)[-3:]
                        
                        # Check if permissions are too permissive
                        if current_perm != expected_perm:
                            risk_level = self._assess_permission_risk(current_perm, expected_perm)
                            
                            finding = SecurityFinding(
                                finding_id=f"perm_{hashlib.md5(file_path.encode()).hexdigest()[:8]}",
                                check_type=SecurityCheckType.FILE_PERMISSIONS,
                                risk_level=risk_level,
                                title="Incorrect File Permissions",
                                description=f"File {file_path} has permissions {current_perm}, expected {expected_perm}",
                                affected_resource=file_path,
                                recommendation=f"Run: chmod {expected_perm} {file_path}",
                                timestamp=datetime.now()
                            )
                            
                            if self._add_finding(finding):
                                new_findings += 1
                    
                    except Exception as e:
                        self.logger.debug(f"Error checking permissions for {file_path}: {e}")
        
        except Exception as e:
            self.logger.error(f"File permissions audit failed: {e}")
        
        return new_findings
    
    def _assess_permission_risk(self, current: str, expected: str) -> SecurityRiskLevel:
        """Assess the risk level of incorrect file permissions"""
        current_int = int(current, 8)
        expected_int = int(expected, 8)
        
        # Check if permissions are more permissive than expected
        if current_int > expected_int:
            # World-readable sensitive files are high risk
            if current_int & 0o004:  # World readable
                return SecurityRiskLevel.HIGH
            elif current_int & 0o040:  # Group readable
                return SecurityRiskLevel.MEDIUM
            else:
                return SecurityRiskLevel.LOW
        else:
            return SecurityRiskLevel.LOW
    
    def _audit_configuration_security(self) -> int:
        """Audit configuration files for security issues"""
        new_findings = 0
        
        try:
            config_files = ['config/config.yaml', '.env']
            forbidden_patterns = self.security_rules.get('forbidden_patterns', [])
            
            for config_file in config_files:
                if not os.path.exists(config_file):
                    continue
                
                try:
                    with open(config_file, 'r') as f:
                        content = f.read().lower()
                    
                    # Check for forbidden patterns
                    for pattern in forbidden_patterns:
                        if pattern.lower() in content:
                            finding = SecurityFinding(
                                finding_id=f"config_{hashlib.md5(f'{config_file}_{pattern}'.encode()).hexdigest()[:8]}",
                                check_type=SecurityCheckType.CONFIGURATION,
                                risk_level=SecurityRiskLevel.MEDIUM,
                                title="Sensitive Data in Configuration",
                                description=f"Configuration file {config_file} may contain sensitive data: '{pattern}'",
                                affected_resource=config_file,
                                recommendation="Review configuration file and remove or encrypt sensitive data",
                                timestamp=datetime.now()
                            )
                            
                            if self._add_finding(finding):
                                new_findings += 1
                
                except Exception as e:
                    self.logger.debug(f"Error auditing config file {config_file}: {e}")
        
        except Exception as e:
            self.logger.error(f"Configuration security audit failed: {e}")
        
        return new_findings
    
    def _audit_file_integrity(self) -> int:
        """Monitor file integrity for sensitive files"""
        new_findings = 0
        
        try:
            for path_pattern in self.sensitive_paths:
                # Handle glob patterns
                if '*' in path_pattern or '?' in path_pattern:
                    from glob import glob
                    paths = glob(path_pattern)
                else:
                    paths = [path_pattern] if os.path.exists(path_pattern) else []
                
                for file_path in paths:
                    if not os.path.isfile(file_path):
                        continue
                    
                    try:
                        # Calculate file hash
                        with open(file_path, 'rb') as f:
                            file_hash = hashlib.sha256(f.read()).hexdigest()
                        
                        # Check if this is first time seeing this file
                        if file_path not in self.file_baselines:
                            self.file_baselines[file_path] = file_hash
                            continue
                        
                        # Check if file has changed
                        if self.file_baselines[file_path] != file_hash:
                            finding = SecurityFinding(
                                finding_id=f"integrity_{hashlib.md5(file_path.encode()).hexdigest()[:8]}",
                                check_type=SecurityCheckType.FILE_PERMISSIONS,
                                risk_level=SecurityRiskLevel.MEDIUM,
                                title="File Integrity Change",
                                description=f"Sensitive file {file_path} has been modified",
                                affected_resource=file_path,
                                recommendation="Verify that file modification was authorized",
                                timestamp=datetime.now()
                            )
                            
                            if self._add_finding(finding):
                                new_findings += 1
                            
                            # Update baseline
                            self.file_baselines[file_path] = file_hash
                    
                    except Exception as e:
                        self.logger.debug(f"Error checking integrity for {file_path}: {e}")
        
        except Exception as e:
            self.logger.error(f"File integrity audit failed: {e}")
        
        return new_findings
    
    def _audit_log_files(self) -> int:
        """Analyze log files for security events"""
        new_findings = 0
        
        try:
            log_files = []
            
            # Find log files
            log_patterns = ['*.log', 'logs/*.log', 'log/*.log']
            for pattern in log_patterns:
                from glob import glob
                log_files.extend(glob(pattern))
            
            for log_file in log_files:
                try:
                    # Check log file size
                    max_size_mb = self.security_rules.get('max_log_file_size_mb', 100)
                    file_size_mb = os.path.getsize(log_file) / (1024 * 1024)
                    
                    if file_size_mb > max_size_mb:
                        finding = SecurityFinding(
                            finding_id=f"logsize_{hashlib.md5(log_file.encode()).hexdigest()[:8]}",
                            check_type=SecurityCheckType.LOG_ANALYSIS,
                            risk_level=SecurityRiskLevel.LOW,
                            title="Large Log File",
                            description=f"Log file {log_file} is {file_size_mb:.1f}MB (limit: {max_size_mb}MB)",
                            affected_resource=log_file,
                            recommendation="Review and rotate log files to prevent disk space issues",
                            timestamp=datetime.now()
                        )
                        
                        if self._add_finding(finding):
                            new_findings += 1
                    
                    # Analyze recent log entries for suspicious patterns
                    try:
                        with open(log_file, 'r') as f:
                            # Read last 1000 lines
                            lines = deque(f, 1000)
                        
                        # Check for suspicious patterns
                        for line in lines:
                            line_lower = line.lower()
                            for pattern in self.suspicious_patterns:
                                import re
                                if re.search(pattern, line_lower):
                                    finding = SecurityFinding(
                                        finding_id=f"logsec_{hashlib.md5(f'{log_file}_{pattern}'.encode()).hexdigest()[:8]}",
                                        check_type=SecurityCheckType.LOG_ANALYSIS,
                                        risk_level=SecurityRiskLevel.MEDIUM,
                                        title="Suspicious Log Entry",
                                        description=f"Suspicious pattern '{pattern}' found in {log_file}",
                                        affected_resource=log_file,
                                        recommendation="Review log entry and investigate potential security incident",
                                        timestamp=datetime.now()
                                    )
                                    
                                    if self._add_finding(finding):
                                        new_findings += 1
                                    break  # One finding per line
                    
                    except UnicodeDecodeError:
                        # Skip binary log files
                        pass
                
                except Exception as e:
                    self.logger.debug(f"Error analyzing log file {log_file}: {e}")
        
        except Exception as e:
            self.logger.error(f"Log analysis audit failed: {e}")
        
        return new_findings
    
    def _audit_running_processes(self) -> int:
        """Monitor running processes for anomalies"""
        new_findings = 0
        
        try:
            # Check if psutil is available
            try:
                import psutil
            except ImportError:
                return 0
            
            # Get running processes
            current_processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent']):
                try:
                    proc_info = proc.info
                    if proc_info['name']:
                        current_processes.append(proc_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Check for processes with suspicious names or high CPU usage
            suspicious_names = ['bitcoin-miner', 'xmrig', 'cryptonight', 'monero']
            high_cpu_threshold = 90.0
            
            for proc in current_processes:
                # Check for suspicious process names
                proc_name = proc['name'].lower()
                for suspicious_name in suspicious_names:
                    if suspicious_name in proc_name:
                        finding = SecurityFinding(
                            finding_id=f"proc_{proc['pid']}_{proc['name']}",
                            check_type=SecurityCheckType.PROCESS_MONITORING,
                            risk_level=SecurityRiskLevel.HIGH,
                            title="Suspicious Process Detected",
                            description=f"Process '{proc['name']}' (PID: {proc['pid']}) may be malicious",
                            affected_resource=f"PID {proc['pid']}",
                            recommendation="Investigate process and terminate if malicious",
                            timestamp=datetime.now()
                        )
                        
                        if self._add_finding(finding):
                            new_findings += 1
                
                # Check for high CPU usage
                cpu_percent = proc.get('cpu_percent', 0)
                if cpu_percent > high_cpu_threshold:
                    finding = SecurityFinding(
                        finding_id=f"highcpu_{proc['pid']}",
                        check_type=SecurityCheckType.PROCESS_MONITORING,
                        risk_level=SecurityRiskLevel.MEDIUM,
                        title="High CPU Usage Process",
                        description=f"Process '{proc['name']}' (PID: {proc['pid']}) using {cpu_percent:.1f}% CPU",
                        affected_resource=f"PID {proc['pid']}",
                        recommendation="Monitor process and investigate if CPU usage remains high",
                        timestamp=datetime.now()
                    )
                    
                    if self._add_finding(finding):
                        new_findings += 1
        
        except Exception as e:
            self.logger.error(f"Process monitoring audit failed: {e}")
        
        return new_findings
    
    def _audit_network_security(self) -> int:
        """Audit network security configuration"""
        new_findings = 0
        
        try:
            # Check for open ports that shouldn't be
            try:
                import psutil
                connections = psutil.net_connections(kind='inet')
                
                # Common ports that should be restricted
                restricted_ports = [22, 3389, 5432, 3306, 27017]  # SSH, RDP, PostgreSQL, MySQL, MongoDB
                
                for conn in connections:
                    if conn.status == 'LISTEN' and conn.laddr:
                        port = conn.laddr.port
                        if port in restricted_ports and conn.laddr.ip == '0.0.0.0':
                            finding = SecurityFinding(
                                finding_id=f"openport_{port}",
                                check_type=SecurityCheckType.NETWORK_ACCESS,
                                risk_level=SecurityRiskLevel.MEDIUM,
                                title="Unrestricted Network Port",
                                description=f"Port {port} is listening on all interfaces (0.0.0.0)",
                                affected_resource=f"Port {port}",
                                recommendation="Restrict port access to specific interfaces or use firewall rules",
                                timestamp=datetime.now()
                            )
                            
                            if self._add_finding(finding):
                                new_findings += 1
            
            except ImportError:
                pass
        
        except Exception as e:
            self.logger.error(f"Network security audit failed: {e}")
        
        return new_findings
    
    def _add_finding(self, finding: SecurityFinding) -> bool:
        """Add a new security finding if it doesn't already exist"""
        if finding.finding_id not in self.findings:
            self.findings[finding.finding_id] = finding
            self.finding_history.append(finding)
            
            # Log the finding
            self.logger.warning(f"SECURITY [{finding.risk_level.value.upper()}] {finding.title}: {finding.description}")
            
            # Update metrics
            increment_counter('security_findings_total', {"risk_level": finding.risk_level.value})
            
            return True
        return False
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get current security status"""
        active_findings = [f for f in self.findings.values() if not f.resolved]
        
        risk_summary = defaultdict(int)
        for finding in active_findings:
            risk_summary[finding.risk_level.value] += 1
        
        return {
            'is_running': self.is_running,
            'audit_interval_minutes': self.audit_interval // 60,
            'total_findings': len(self.findings),
            'active_findings': len(active_findings),
            'resolved_findings': len(self.findings) - len(active_findings),
            'risk_summary': dict(risk_summary),
            'monitored_files': len(self.monitored_files),
            'last_audit': datetime.now().isoformat() if self.is_running else None
        }
    
    def get_security_findings(self, include_resolved: bool = False) -> List[Dict[str, Any]]:
        """Get security findings"""
        findings = list(self.findings.values())
        
        if not include_resolved:
            findings = [f for f in findings if not f.resolved]
        
        return [
            {
                'finding_id': f.finding_id,
                'check_type': f.check_type.value,
                'risk_level': f.risk_level.value,
                'title': f.title,
                'description': f.description,
                'affected_resource': f.affected_resource,
                'recommendation': f.recommendation,
                'timestamp': f.timestamp.isoformat(),
                'resolved': f.resolved,
                'false_positive': f.false_positive
            }
            for f in findings
        ]
    
    def resolve_finding(self, finding_id: str) -> bool:
        """Mark a security finding as resolved"""
        if finding_id in self.findings:
            self.findings[finding_id].resolved = True
            self.logger.info(f"Security finding {finding_id} resolved")
            increment_counter('security_findings_resolved_total')
            return True
        return False
    
    def mark_false_positive(self, finding_id: str) -> bool:
        """Mark a security finding as false positive"""
        if finding_id in self.findings:
            self.findings[finding_id].false_positive = True
            self.findings[finding_id].resolved = True
            self.logger.info(f"Security finding {finding_id} marked as false positive")
            return True
        return False


# Global security auditor instance
_security_auditor = None

def get_security_auditor() -> SecurityAuditor:
    """Get global security auditor instance"""
    global _security_auditor
    if _security_auditor is None:
        _security_auditor = SecurityAuditor()
    return _security_auditor

def stop_security_auditor():
    """Stop the global security auditor"""
    global _security_auditor
    if _security_auditor:
        _security_auditor.stop_auditing()
        _security_auditor = None