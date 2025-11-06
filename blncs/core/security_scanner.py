"""
BLNCS Security Scanner
Automated security vulnerability scanning and threat detection
"""

import re
import logging
import threading
import time
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)


class VulnerabilityLevel(Enum):
    """Vulnerability severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityFinding:
    """Security vulnerability finding"""
    id: str
    level: VulnerabilityLevel
    category: str
    title: str
    description: str
    location: str
    recommendation: str
    timestamp: str
    cve_ids: List[str] = None

    def __post_init__(self):
        if self.cve_ids is None:
            self.cve_ids = []


class SecurityScanner:
    """
    Automated security scanner for:
    - Code vulnerability detection
    - Configuration security audit
    - Dependency vulnerability scanning
    - Runtime threat detection
    """

    def __init__(self):
        self._findings: List[SecurityFinding] = []
        self._lock = threading.RLock()
        self._scan_count = 0

    def scan_all(self, project_root: str = ".") -> List[SecurityFinding]:
        """
        Run comprehensive security scan

        Args:
            project_root: Root directory of project

        Returns:
            List of security findings
        """
        logger.info("Starting comprehensive security scan...")

        self._findings.clear()
        root_path = Path(project_root)

        # Run all scan types
        self._scan_code_vulnerabilities(root_path)
        self._scan_configuration_security(root_path)
        self._scan_secrets(root_path)
        self._scan_dependencies(root_path)

        self._scan_count += 1

        logger.info(
            "Security scan complete: %d findings (%d critical, %d high)",
            len(self._findings),
            sum(1 for f in self._findings if f.level == VulnerabilityLevel.CRITICAL),
            sum(1 for f in self._findings if f.level == VulnerabilityLevel.HIGH)
        )

        return self._findings

    def _scan_code_vulnerabilities(self, root_path: Path):
        """Scan for code-level vulnerabilities"""
        logger.info("Scanning for code vulnerabilities...")

        # Patterns to detect
        vulnerability_patterns = {
            'sql_injection': {
                'pattern': re.compile(
                    r'(execute\([^)]*%s|cursor\.execute\([^)]*\+|'
                    r'\.execute\([^)]*\.format\()',
                    re.IGNORECASE
                ),
                'level': VulnerabilityLevel.CRITICAL,
                'title': 'Potential SQL Injection',
                'description': 'String formatting or concatenation used in SQL query',
                'recommendation': 'Use parameterized queries with ? placeholders'
            },
            'command_injection': {
                'pattern': re.compile(
                    r'(subprocess\.(call|run|Popen)\([^)]*\+|os\.system\([^)]*\+)',
                    re.IGNORECASE
                ),
                'level': VulnerabilityLevel.HIGH,
                'title': 'Potential Command Injection',
                'description': 'User input may be used in system command',
                'recommendation': 'Use subprocess with list arguments, avoid shell=True'
            },
            'hardcoded_secret': {
                'pattern': re.compile(
                    r'(password|secret|api_key|token)\s*=\s*["\'][^"\']{8,}["\']',
                    re.IGNORECASE
                ),
                'level': VulnerabilityLevel.HIGH,
                'title': 'Hardcoded Secret',
                'description': 'Secret or credential hardcoded in source code',
                'recommendation': 'Use environment variables or secret management'
            },
            'weak_crypto': {
                'pattern': re.compile(
                    r'(hashlib\.(md5|sha1)|DES|RC4)',
                    re.IGNORECASE
                ),
                'level': VulnerabilityLevel.MEDIUM,
                'title': 'Weak Cryptography',
                'description': 'Weak or deprecated cryptographic algorithm used',
                'recommendation': 'Use SHA-256 or better, avoid MD5/SHA1'
            },
            'path_traversal': {
                'pattern': re.compile(
                    r'open\([^)]*\+|Path\([^)]*\+',
                    re.IGNORECASE
                ),
                'level': VulnerabilityLevel.HIGH,
                'title': 'Potential Path Traversal',
                'description': 'File path constructed with user input',
                'recommendation': 'Validate and sanitize file paths, use Path.resolve()'
            }
        }

        # Scan Python files
        for py_file in root_path.rglob("*.py"):
            if 'venv' in str(py_file) or '.venv' in str(py_file):
                continue

            try:
                content = py_file.read_text(encoding='utf-8')

                for vuln_id, vuln_info in vulnerability_patterns.items():
                    matches = vuln_info['pattern'].finditer(content)

                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1

                        finding = SecurityFinding(
                            id=f"{vuln_id}_{py_file.name}_{line_num}",
                            level=vuln_info['level'],
                            category='code_vulnerability',
                            title=vuln_info['title'],
                            description=vuln_info['description'],
                            location=f"{py_file}:{line_num}",
                            recommendation=vuln_info['recommendation'],
                            timestamp=datetime.now(timezone.utc).isoformat()
                        )

                        with self._lock:
                            self._findings.append(finding)

            except Exception as e:
                logger.debug("Error scanning file %s: %s", py_file, e)

    def _scan_configuration_security(self, root_path: Path):
        """Scan for insecure configurations"""
        logger.info("Scanning configuration security...")

        config_patterns = {
            'debug_enabled': {
                'pattern': re.compile(r'"debug":\s*true|debug\s*=\s*true', re.IGNORECASE),
                'level': VulnerabilityLevel.MEDIUM,
                'title': 'Debug Mode Enabled',
                'description': 'Debug mode should be disabled in production',
                'recommendation': 'Set debug=false in production configuration'
            },
            'weak_secret': {
                'pattern': re.compile(r'"secret[_-]?key":\s*"(test|dev|admin|password)"', re.IGNORECASE),
                'level': VulnerabilityLevel.CRITICAL,
                'title': 'Weak Secret Key',
                'description': 'Using weak or default secret key',
                'recommendation': 'Generate strong random secret key'
            },
            'cors_wildcard': {
                'pattern': re.compile(r'(cors_allowed_origins|CORS_ORIGINS).*"\*"', re.IGNORECASE),
                'level': VulnerabilityLevel.HIGH,
                'title': 'CORS Wildcard Origin',
                'description': 'CORS allows all origins (*)',
                'recommendation': 'Specify exact allowed origins'
            }
        }

        # Scan configuration files
        for config_file in root_path.rglob("*.json"):
            if 'venv' in str(config_file) or 'node_modules' in str(config_file):
                continue

            try:
                content = config_file.read_text(encoding='utf-8')

                for vuln_id, vuln_info in config_patterns.items():
                    if vuln_info['pattern'].search(content):
                        finding = SecurityFinding(
                            id=f"{vuln_id}_{config_file.name}",
                            level=vuln_info['level'],
                            category='configuration',
                            title=vuln_info['title'],
                            description=vuln_info['description'],
                            location=str(config_file),
                            recommendation=vuln_info['recommendation'],
                            timestamp=datetime.now(timezone.utc).isoformat()
                        )

                        with self._lock:
                            self._findings.append(finding)

            except Exception as e:
                logger.debug("Error scanning config %s: %s", config_file, e)

    def _scan_secrets(self, root_path: Path):
        """Scan for exposed secrets"""
        logger.info("Scanning for exposed secrets...")

        secret_patterns = {
            'aws_key': re.compile(r'AKIA[0-9A-Z]{16}'),
            'github_token': re.compile(r'gh[ps]_[a-zA-Z0-9]{36}'),
            'slack_token': re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,72}'),
            'private_key': re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'),
            'jwt': re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}')
        }

        # Scan all text files
        for text_file in root_path.rglob("*"):
            if not text_file.is_file():
                continue

            # Skip binary and large files
            if text_file.suffix in ['.pyc', '.so', '.dll', '.exe', '.db']:
                continue

            if 'venv' in str(text_file) or '.git' in str(text_file):
                continue

            try:
                # Skip large files
                if text_file.stat().st_size > 1024 * 1024:  # 1MB
                    continue

                content = text_file.read_text(encoding='utf-8', errors='ignore')

                for secret_type, pattern in secret_patterns.items():
                    if pattern.search(content):
                        finding = SecurityFinding(
                            id=f"secret_{secret_type}_{text_file.name}",
                            level=VulnerabilityLevel.CRITICAL,
                            category='exposed_secret',
                            title=f'Exposed {secret_type.replace("_", " ").title()}',
                            description=f'Potential {secret_type} found in file',
                            location=str(text_file),
                            recommendation='Remove secret from code, use environment variables',
                            timestamp=datetime.now(timezone.utc).isoformat()
                        )

                        with self._lock:
                            self._findings.append(finding)

            except Exception as e:
                logger.debug("Error scanning secrets in %s: %s", text_file, e)

    def _scan_dependencies(self, root_path: Path):
        """Scan for vulnerable dependencies"""
        logger.info("Scanning dependencies...")

        # Known vulnerable packages (example list)
        vulnerable_packages = {
            'urllib3<1.26.5': {
                'level': VulnerabilityLevel.HIGH,
                'cve': ['CVE-2021-33503'],
                'recommendation': 'Upgrade to urllib3>=1.26.5'
            },
            'cryptography<3.3': {
                'level': VulnerabilityLevel.HIGH,
                'cve': ['CVE-2020-36242'],
                'recommendation': 'Upgrade to cryptography>=3.3'
            }
        }

        requirements_file = root_path / "requirements.txt"
        if requirements_file.exists():
            try:
                content = requirements_file.read_text()

                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    # Simple version check (production would use proper parsing)
                    for vuln_pattern, vuln_info in vulnerable_packages.items():
                        package_name = vuln_pattern.split('<')[0]
                        if package_name in line:
                            finding = SecurityFinding(
                                id=f"dependency_{package_name}",
                                level=vuln_info['level'],
                                category='vulnerable_dependency',
                                title=f'Vulnerable Dependency: {package_name}',
                                description=f'Package {vuln_pattern} has known vulnerabilities',
                                location=str(requirements_file),
                                recommendation=vuln_info['recommendation'],
                                timestamp=datetime.now(timezone.utc).isoformat(),
                                cve_ids=vuln_info['cve']
                            )

                            with self._lock:
                                self._findings.append(finding)

            except Exception as e:
                logger.error("Error scanning dependencies: %s", e)

    def get_findings_by_level(self, level: VulnerabilityLevel) -> List[SecurityFinding]:
        """Get findings filtered by severity level"""
        with self._lock:
            return [f for f in self._findings if f.level == level]

    def get_critical_findings(self) -> List[SecurityFinding]:
        """Get critical findings"""
        return self.get_findings_by_level(VulnerabilityLevel.CRITICAL)

    def get_findings_summary(self) -> Dict[str, int]:
        """Get summary of findings by severity"""
        with self._lock:
            return {
                'critical': sum(1 for f in self._findings if f.level == VulnerabilityLevel.CRITICAL),
                'high': sum(1 for f in self._findings if f.level == VulnerabilityLevel.HIGH),
                'medium': sum(1 for f in self._findings if f.level == VulnerabilityLevel.MEDIUM),
                'low': sum(1 for f in self._findings if f.level == VulnerabilityLevel.LOW),
                'info': sum(1 for f in self._findings if f.level == VulnerabilityLevel.INFO),
                'total': len(self._findings)
            }

    def export_report(self, output_file: str):
        """Export findings to JSON report"""
        import json

        report = {
            'scan_time': datetime.now(timezone.utc).isoformat(),
            'scan_count': self._scan_count,
            'summary': self.get_findings_summary(),
            'findings': [
                {
                    'id': f.id,
                    'level': f.level.value,
                    'category': f.category,
                    'title': f.title,
                    'description': f.description,
                    'location': f.location,
                    'recommendation': f.recommendation,
                    'timestamp': f.timestamp,
                    'cve_ids': f.cve_ids
                }
                for f in self._findings
            ]
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        logger.info("Security report exported to %s", output_file)


# Global security scanner
_security_scanner: Optional[SecurityScanner] = None


def get_security_scanner() -> SecurityScanner:
    """Get or create global security scanner"""
    global _security_scanner

    if _security_scanner is None:
        _security_scanner = SecurityScanner()

    return _security_scanner


__all__ = ['SecurityScanner', 'SecurityFinding', 'VulnerabilityLevel', 'get_security_scanner']
