"""
Security Auditor - Comprehensive security monitoring and auditing
"""

import json
import hashlib
import os
import threading
import time
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
import logging

logger = logging.getLogger(__name__)

class SecurityRiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class SecurityFinding:
    def __init__(self, finding_id: str, title: str, description: str, 
                 risk_level: SecurityRiskLevel, check_type: str, 
                 affected_resource: str, recommendation: str):
        self.finding_id = finding_id
        self.title = title
        self.description = description
        self.risk_level = risk_level
        self.check_type = check_type
        self.affected_resource = affected_resource
        self.recommendation = recommendation
        self.timestamp = datetime.utcnow().isoformat()
        self.resolved = False
        self.false_positive = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            'finding_id': self.finding_id,
            'title': self.title,
            'description': self.description,
            'risk_level': self.risk_level.value,
            'check_type': self.check_type,
            'affected_resource': self.affected_resource,
            'recommendation': self.recommendation,
            'timestamp': self.timestamp,
            'resolved': self.resolved,
            'false_positive': self.false_positive
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityFinding':
        finding = cls(
            finding_id=data['finding_id'],
            title=data['title'],
            description=data['description'],
            risk_level=SecurityRiskLevel(data['risk_level']),
            check_type=data['check_type'],
            affected_resource=data['affected_resource'],
            recommendation=data['recommendation']
        )
        finding.timestamp = data['timestamp']
        finding.resolved = data.get('resolved', False)
        finding.false_positive = data.get('false_positive', False)
        return finding

class SecurityAuditor:
    def __init__(self):
        self.is_running = False
        self.audit_thread = None
        self.findings: Dict[str, SecurityFinding] = {}
        self.file_hashes: Dict[str, str] = {}
        self.last_audit_time = None
        self.audit_interval = 300  # 5 minutes
        
        # Security audit configuration
        self.audit_config = {
            'monitored_directories': [
                'blncs/',
                'config/',
                'scripts/',
                '.',  # Root directory for critical files
            ],
            'monitored_files': [
                'config.yaml',
                '.env',
                'blncs.db',
                'requirements.txt',
                'setup.py'
            ],
            'sensitive_patterns': [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'api_key\s*=\s*["\'][^"\']+["\']',
                r'secret\s*=\s*["\'][^"\']+["\']',
                r'token\s*=\s*["\'][^"\']+["\']',
                r'private_key\s*=\s*["\'][^"\']+["\']',
                r'BEGIN (RSA )?PRIVATE KEY',
            ],
            'dangerous_functions': [
                'eval(',
                'exec(',
                'subprocess.call(',
                'os.system(',
                '__import__(',
            ]
        }
        
        # Load existing findings
        self._load_findings()

    def _load_findings(self):
        """Load findings from persistent storage"""
        findings_file = Path('security/findings.json')
        if findings_file.exists():
            try:
                with open(findings_file, 'r') as f:
                    findings_data = json.load(f)
                    for data in findings_data:
                        finding = SecurityFinding.from_dict(data)
                        self.findings[finding.finding_id] = finding
                logger.info(f"Loaded {len(self.findings)} security findings")
            except Exception as e:
                logger.error(f"Failed to load security findings: {e}")

    def _save_findings(self):
        """Save findings to persistent storage"""
        findings_file = Path('security/findings.json')
        findings_file.parent.mkdir(exist_ok=True)
        
        try:
            findings_data = [finding.to_dict() for finding in self.findings.values()]
            with open(findings_file, 'w') as f:
                json.dump(findings_data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save security findings: {e}")

    def start_auditing(self) -> bool:
        """Start continuous security auditing"""
        if self.is_running:
            return True
            
        try:
            self.is_running = True
            self.audit_thread = threading.Thread(target=self._audit_loop, daemon=True)
            self.audit_thread.start()
            
            # Perform initial audit
            self._perform_comprehensive_audit()
            
            logger.info("Security auditing started")
            return True
        except Exception as e:
            logger.error(f"Failed to start security auditing: {e}")
            self.is_running = False
            return False

    def stop_auditing(self) -> bool:
        """Stop security auditing"""
        if not self.is_running:
            return True
            
        try:
            self.is_running = False
            if self.audit_thread:
                self.audit_thread.join(timeout=5)
            
            logger.info("Security auditing stopped")
            return True
        except Exception as e:
            logger.error(f"Failed to stop security auditing: {e}")
            return False

    def _audit_loop(self):
        """Main audit loop"""
        while self.is_running:
            try:
                time.sleep(self.audit_interval)
                if self.is_running:
                    self._perform_comprehensive_audit()
            except Exception as e:
                logger.error(f"Error in audit loop: {e}")

    def _perform_comprehensive_audit(self) -> int:
        """Perform comprehensive security audit"""
        new_findings_count = 0
        
        try:
            # File integrity monitoring
            new_findings_count += self._check_file_integrity()
            
            # Configuration security
            new_findings_count += self._check_configuration_security()
            
            # Code security
            new_findings_count += self._check_code_security()
            
            # Permission checks
            new_findings_count += self._check_file_permissions()
            
            # Network security
            new_findings_count += self._check_network_security()
            
            self.last_audit_time = datetime.utcnow()
            self._save_findings()
            
            logger.info(f"Security audit completed, found {new_findings_count} new findings")
            
        except Exception as e:
            logger.error(f"Error during security audit: {e}")
        
        return new_findings_count

    def _check_file_integrity(self) -> int:
        """Check for unauthorized file changes"""
        new_findings = 0
        
        for directory in self.audit_config['monitored_directories']:
            if not os.path.exists(directory):
                continue
                
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if file.endswith(('.py', '.yaml', '.yml', '.json', '.env')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'rb') as f:
                                content = f.read()
                                current_hash = hashlib.sha256(content).hexdigest()
                            
                            if file_path in self.file_hashes:
                                if self.file_hashes[file_path] != current_hash:
                                    # File changed - check if suspicious
                                    if self._is_suspicious_change(file_path, content):
                                        finding = self._create_finding(
                                            f"Suspicious file modification: {file_path}",
                                            f"Critical file {file_path} was modified with potentially suspicious content",
                                            SecurityRiskLevel.HIGH,
                                            "file_integrity",
                                            file_path,
                                            "Review the file changes and verify they are authorized"
                                        )
                                        new_findings += 1
                            
                            self.file_hashes[file_path] = current_hash
                            
                        except Exception as e:
                            logger.warning(f"Could not check file integrity for {file_path}: {e}")
        
        return new_findings

    def _check_configuration_security(self) -> int:
        """Check configuration security"""
        new_findings = 0
        
        config_files = ['config.yaml', 'config.yml', '.env', 'blncs.db']
        
        for config_file in config_files:
            if os.path.exists(config_file):
                # Check file permissions
                stat_info = os.stat(config_file)
                perms = stat_info.st_mode & 0o777
                
                if perms & 0o044:  # World or group readable
                    finding = self._create_finding(
                        f"Insecure configuration file permissions: {config_file}",
                        f"Configuration file {config_file} has overly permissive permissions ({oct(perms)})",
                        SecurityRiskLevel.HIGH,
                        "configuration_security",
                        config_file,
                        f"Set restrictive permissions: chmod 600 {config_file}"
                    )
                    new_findings += 1
        
        return new_findings

    def _check_code_security(self) -> int:
        """Check for security vulnerabilities in code"""
        new_findings = 0
        
        for directory in self.audit_config['monitored_directories']:
            if not os.path.exists(directory):
                continue
                
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if file.endswith('.py'):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                content = f.read()
                            
                            # Check for dangerous functions
                            for dangerous_func in self.audit_config['dangerous_functions']:
                                if dangerous_func in content:
                                    finding = self._create_finding(
                                        f"Dangerous function usage: {dangerous_func.rstrip('(')}",
                                        f"File {file_path} contains potentially dangerous function: {dangerous_func}",
                                        SecurityRiskLevel.MEDIUM,
                                        "code_security",
                                        file_path,
                                        f"Review usage of {dangerous_func} and consider safer alternatives"
                                    )
                                    new_findings += 1
                            
                            # Check for hardcoded secrets
                            import re
                            for pattern in self.audit_config['sensitive_patterns']:
                                matches = re.findall(pattern, content, re.IGNORECASE)
                                if matches:
                                    finding = self._create_finding(
                                        f"Potential hardcoded secret in {file_path}",
                                        f"File {file_path} may contain hardcoded sensitive information",
                                        SecurityRiskLevel.CRITICAL,
                                        "code_security",
                                        file_path,
                                        "Move sensitive data to environment variables or secure configuration"
                                    )
                                    new_findings += 1
                        
                        except Exception as e:
                            logger.warning(f"Could not check code security for {file_path}: {e}")
        
        return new_findings

    def _check_file_permissions(self) -> int:
        """Check for insecure file permissions"""
        new_findings = 0
        
        critical_files = ['blncs.db', '.env', 'config.yaml']
        
        for file_path in critical_files:
            if os.path.exists(file_path):
                stat_info = os.stat(file_path)
                perms = stat_info.st_mode & 0o777
                
                if perms & 0o022:  # World or group writable
                    finding = self._create_finding(
                        f"Insecure file permissions: {file_path}",
                        f"Critical file {file_path} has insecure permissions ({oct(perms)})",
                        SecurityRiskLevel.HIGH,
                        "file_permissions",
                        file_path,
                        f"Set secure permissions: chmod 600 {file_path}"
                    )
                    new_findings += 1
        
        return new_findings

    def _check_network_security(self) -> int:
        """Check network security configuration"""
        new_findings = 0
        
        # Check for open network services
        try:
            import socket
            
            # Check common dangerous ports
            dangerous_ports = [23, 80, 8080, 3000, 5000]  # Telnet, HTTP development ports
            
            for port in dangerous_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                
                if result == 0:  # Port is open
                    finding = self._create_finding(
                        f"Open development port: {port}",
                        f"Development port {port} is open and accessible",
                        SecurityRiskLevel.MEDIUM,
                        "network_security",
                        f"localhost:{port}",
                        f"Close development port {port} in production environment"
                    )
                    new_findings += 1
        
        except Exception as e:
            logger.warning(f"Could not check network security: {e}")
        
        return new_findings

    def _is_suspicious_change(self, file_path: str, content: bytes) -> bool:
        """Check if file change is suspicious"""
        try:
            content_str = content.decode('utf-8', errors='ignore')
            
            suspicious_patterns = [
                'import os',
                'subprocess',
                'eval(',
                'exec(',
                '__import__',
                'base64',
                'urllib',
                'requests'
            ]
            
            # Simple heuristic: if many suspicious patterns are added
            suspicious_count = sum(1 for pattern in suspicious_patterns if pattern in content_str)
            return suspicious_count >= 3
            
        except Exception:
            return False

    def _create_finding(self, title: str, description: str, risk_level: SecurityRiskLevel,
                       check_type: str, affected_resource: str, recommendation: str) -> SecurityFinding:
        """Create a new security finding"""
        finding_id = hashlib.sha256(f"{title}{affected_resource}{check_type}".encode()).hexdigest()
        
        # Check if finding already exists
        if finding_id in self.findings:
            existing_finding = self.findings[finding_id]
            if not existing_finding.resolved and not existing_finding.false_positive:
                return existing_finding  # Don't create duplicate
        
        finding = SecurityFinding(
            finding_id=finding_id,
            title=title,
            description=description,
            risk_level=risk_level,
            check_type=check_type,
            affected_resource=affected_resource,
            recommendation=recommendation
        )
        
        self.findings[finding_id] = finding
        logger.info(f"New security finding: {title} ({risk_level.value})")
        
        return finding

    def get_security_findings(self, include_resolved: bool = False) -> List[Dict[str, Any]]:
        """Get security findings"""
        findings = []
        for finding in self.findings.values():
            if include_resolved or (not finding.resolved and not finding.false_positive):
                findings.append(finding.to_dict())
        return findings

    def get_security_status(self) -> Dict[str, Any]:
        """Get overall security status"""
        active_findings = [f for f in self.findings.values() 
                          if not f.resolved and not f.false_positive]
        
        risk_summary = {}
        for finding in active_findings:
            risk_level = finding.risk_level.value
            risk_summary[risk_level] = risk_summary.get(risk_level, 0) + 1
        
        monitored_files = 0
        for directory in self.audit_config['monitored_directories']:
            if os.path.exists(directory):
                for root, dirs, files in os.walk(directory):
                    monitored_files += len([f for f in files if f.endswith(('.py', '.yaml', '.yml', '.json', '.env'))])
        
        return {
            'is_running': self.is_running,
            'audit_interval_minutes': self.audit_interval // 60,
            'last_audit': self.last_audit_time.isoformat() if self.last_audit_time else None,
            'total_findings': len(self.findings),
            'active_findings': len(active_findings),
            'resolved_findings': len([f for f in self.findings.values() if f.resolved]),
            'risk_summary': risk_summary,
            'monitored_files': monitored_files
        }

    def resolve_finding(self, finding_id: str) -> bool:
        """Resolve a security finding"""
        if finding_id in self.findings:
            self.findings[finding_id].resolved = True
            self._save_findings()
            logger.info(f"Security finding {finding_id} resolved")
            return True
        return False

    def mark_false_positive(self, finding_id: str) -> bool:
        """Mark a finding as false positive"""
        if finding_id in self.findings:
            self.findings[finding_id].false_positive = True
            self._save_findings()
            logger.info(f"Security finding {finding_id} marked as false positive")
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