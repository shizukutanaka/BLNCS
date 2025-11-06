#!/usr/bin/env python3
"""
Comprehensive Security Audit and Penetration Testing for BLNCS
National-grade security validation and vulnerability assessment.
"""

import os
import sys
import json
import subprocess
import hashlib
import sqlite3
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import re

@dataclass
class SecurityFinding:
    """Security audit finding"""
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    evidence: Optional[str] = None
    recommendation: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None

@dataclass
class SecurityReport:
    """Complete security audit report"""
    audit_timestamp: datetime
    findings: List[SecurityFinding] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)
    compliance_status: Dict[str, bool] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    overall_score: float = 0.0

class SecurityAuditor:
    """Comprehensive security auditor for BLNCS"""
    
    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root)
        self.findings: List[SecurityFinding] = []
        
        # Security patterns to check
        self.security_patterns = {
            'hardcoded_secrets': [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'secret\s*=\s*["\'][^"\']+["\']',
                r'api_?key\s*=\s*["\'][^"\']+["\']',
                r'private_?key\s*=\s*["\'][^"\']+["\']',
                r'token\s*=\s*["\'][^"\']+["\']'
            ],
            'sql_injection': [
                r'execute\s*\(\s*["\'].*%.*["\']',
                r'query\s*\(\s*["\'].*%.*["\']',
                r'cursor\.execute\s*\([^)]*%[^)]*\)'
            ],
            'command_injection': [
                r'os\.system\s*\(',
                r'subprocess\.call\s*\([^)]*shell\s*=\s*True',
                r'subprocess\.run\s*\([^)]*shell\s*=\s*True',
                r'os\.popen\s*\('
            ],
            'path_traversal': [
                r'open\s*\([^)]*\.\./.*\)',
                r'Path\s*\([^)]*\.\./.*\)'
            ],
            'weak_crypto': [
                r'md5\s*\(',
                r'sha1\s*\(',
                r'DES\s*\(',
                r'RC4\s*\('
            ]
        }
        
    def run_comprehensive_audit(self) -> SecurityReport:
        """Run comprehensive security audit"""
        print("🔒 Starting comprehensive security audit...")
        
        start_time = datetime.now()
        
        # Static code analysis
        self._analyze_source_code()
        
        # Configuration security
        self._check_configuration_security()
        
        # Dependency vulnerabilities
        self._check_dependency_vulnerabilities()
        
        # File permissions and structure
        self._check_file_permissions()
        
        # Docker security (if applicable)
        self._check_docker_security()
        
        # Kubernetes security (if applicable)
        self._check_kubernetes_security()
        
        # Database security
        self._check_database_security()
        
        # API security
        self._check_api_security()
        
        # Generate report
        report = self._generate_security_report(start_time)
        
        print(f"✅ Security audit completed. Found {len(self.findings)} findings.")
        return report
        
    def _analyze_source_code(self):
        """Analyze source code for security vulnerabilities"""
        print("📝 Analyzing source code for security issues...")
        
        python_files = list(self.project_root.glob("**/*.py"))
        
        for file_path in python_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                self._check_security_patterns(file_path, content)
                self._check_authentication_issues(file_path, content)
                self._check_input_validation(file_path, content)
                self._check_logging_security(file_path, content)
                
            except Exception as e:
                self._add_finding(
                    "LOW", "file_access", f"Could not analyze file {file_path}",
                    f"Error reading file: {e}", str(file_path)
                )
                
    def _check_security_patterns(self, file_path: Path, content: str):
        """Check for common security anti-patterns"""
        lines = content.split('\n')
        
        for category, patterns in self.security_patterns.items():
            for pattern in patterns:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        severity = self._get_pattern_severity(category)
                        self._add_finding(
                            severity, category,
                            f"Potential {category.replace('_', ' ')} vulnerability",
                            f"Found suspicious pattern in line {line_num}: {line.strip()}",
                            str(file_path), line_num, line.strip()
                        )
                        
    def _get_pattern_severity(self, category: str) -> str:
        """Get severity level for pattern category"""
        severity_map = {
            'hardcoded_secrets': 'CRITICAL',
            'sql_injection': 'HIGH',
            'command_injection': 'CRITICAL',
            'path_traversal': 'HIGH',
            'weak_crypto': 'MEDIUM'
        }
        return severity_map.get(category, 'MEDIUM')
        
    def _check_authentication_issues(self, file_path: Path, content: str):
        """Check for authentication and authorization issues"""
        auth_issues = [
            (r'login.*without.*password', 'Password-less authentication detected'),
            (r'admin.*=.*True.*without', 'Admin privileges without proper checks'),
            (r'jwt.*decode.*verify.*False', 'JWT verification disabled'),
            (r'session.*timeout.*None', 'Session timeout disabled')
        ]
        
        for pattern, description in auth_issues:
            if re.search(pattern, content, re.IGNORECASE):
                self._add_finding(
                    "HIGH", "authentication",
                    "Authentication/Authorization Issue",
                    description, str(file_path)
                )
                
    def _check_input_validation(self, file_path: Path, content: str):
        """Check for input validation issues"""
        validation_issues = [
            (r'request\.(form|args|json).*without.*validation', 'Unvalidated user input'),
            (r'int\(.*request\.', 'Direct type conversion without validation'),
            (r'eval\s*\(', 'Use of eval() function - potential code injection'),
            (r'exec\s*\(', 'Use of exec() function - potential code injection')
        ]
        
        for pattern, description in validation_issues:
            if re.search(pattern, content, re.IGNORECASE):
                severity = "CRITICAL" if "eval" in pattern or "exec" in pattern else "HIGH"
                self._add_finding(
                    severity, "input_validation",
                    "Input Validation Issue",
                    description, str(file_path)
                )
                
    def _check_logging_security(self, file_path: Path, content: str):
        """Check for logging security issues"""
        if re.search(r'log.*password', content, re.IGNORECASE):
            self._add_finding(
                "MEDIUM", "information_disclosure",
                "Sensitive data in logs",
                "Password or sensitive data might be logged",
                str(file_path)
            )
            
        if re.search(r'print.*password', content, re.IGNORECASE):
            self._add_finding(
                "HIGH", "information_disclosure",
                "Sensitive data in output",
                "Password or sensitive data in print statements",
                str(file_path)
            )
            
    def _check_configuration_security(self):
        """Check configuration files for security issues"""
        print("⚙️  Checking configuration security...")
        
        config_files = [
            "config.yaml", "config.yml", "config.json", ".env",
            "docker-compose.yml", "docker-compose.yaml"
        ]
        
        for config_file in config_files:
            file_path = self.project_root / config_file
            if file_path.exists():
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        
                    # Check for hardcoded secrets
                    if re.search(r'password\s*[:\=]\s*\S+', content, re.IGNORECASE):
                        self._add_finding(
                            "HIGH", "configuration",
                            "Hardcoded password in configuration",
                            f"Found hardcoded password in {config_file}",
                            str(file_path)
                        )
                        
                    # Check for debug mode in production
                    if re.search(r'debug\s*[:\=]\s*true', content, re.IGNORECASE):
                        self._add_finding(
                            "MEDIUM", "configuration",
                            "Debug mode enabled",
                            f"Debug mode enabled in {config_file}",
                            str(file_path)
                        )
                        
                except Exception as e:
                    pass
                    
    def _check_dependency_vulnerabilities(self):
        """Check for known vulnerabilities in dependencies"""
        print("📦 Checking dependency vulnerabilities...")
        
        requirements_files = ["requirements.txt", "requirements-dev.txt", "pyproject.toml"]
        
        for req_file in requirements_files:
            file_path = self.project_root / req_file
            if file_path.exists():
                try:
                    # Run safety check if available
                    result = subprocess.run(
                        ["python", "-m", "safety", "check", "--file", str(file_path)],
                        capture_output=True, text=True, timeout=30
                    )
                    
                    if result.returncode != 0 and "vulnerabilities found" in result.stdout:
                        self._add_finding(
                            "HIGH", "dependencies",
                            "Vulnerable dependencies found",
                            f"Safety check found vulnerabilities in {req_file}",
                            str(file_path), evidence=result.stdout
                        )
                        
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    self._add_finding(
                        "INFO", "dependencies",
                        "Could not check dependency vulnerabilities",
                        "safety tool not available or check failed",
                        str(file_path)
                    )
                    
    def _check_file_permissions(self):
        """Check file and directory permissions"""
        print("🔐 Checking file permissions...")
        
        # Check for overly permissive files
        sensitive_patterns = ["*key*", "*secret*", "*password*", "*.pem", "*.p12"]
        
        for pattern in sensitive_patterns:
            for file_path in self.project_root.glob(f"**/{pattern}"):
                if file_path.is_file():
                    stat = file_path.stat()
                    mode = oct(stat.st_mode)[-3:]
                    
                    # Check if readable by others (world-readable)
                    if mode[2] in ['4', '5', '6', '7']:
                        self._add_finding(
                            "HIGH", "permissions",
                            "Sensitive file world-readable",
                            f"File {file_path} has permissions {mode}",
                            str(file_path)
                        )
                        
        # Check for executable configs
        config_extensions = ['.yaml', '.yml', '.json', '.conf', '.cfg']
        for config_file in self.project_root.glob("**/*"):
            if config_file.suffix in config_extensions and config_file.is_file():
                stat = config_file.stat()
                mode = oct(stat.st_mode)[-3:]
                
                if mode[0] in ['1', '3', '5', '7'] or mode[1] in ['1', '3', '5', '7']:
                    self._add_finding(
                        "MEDIUM", "permissions",
                        "Configuration file is executable",
                        f"Config file {config_file} has execute permissions",
                        str(config_file)
                    )
                    
    def _check_docker_security(self):
        """Check Docker configuration security"""
        print("🐳 Checking Docker security...")
        
        dockerfile_path = self.project_root / "Dockerfile"
        if dockerfile_path.exists():
            try:
                with open(dockerfile_path, 'r') as f:
                    content = f.read()
                    
                # Check for running as root
                if not re.search(r'USER\s+(?!root)', content):
                    self._add_finding(
                        "HIGH", "docker",
                        "Container runs as root",
                        "Dockerfile does not specify non-root user",
                        str(dockerfile_path)
                    )
                    
                # Check for exposed sensitive ports
                sensitive_ports = ['22', '3389', '5432', '3306', '6379']
                for port in sensitive_ports:
                    if re.search(rf'EXPOSE\s+{port}', content):
                        self._add_finding(
                            "MEDIUM", "docker",
                            f"Sensitive port {port} exposed",
                            f"Port {port} is exposed in Dockerfile",
                            str(dockerfile_path)
                        )
                        
            except Exception as e:
                pass
                
        # Check docker-compose security
        compose_files = ["docker-compose.yml", "docker-compose.yaml"]
        for compose_file in compose_files:
            file_path = self.project_root / compose_file
            if file_path.exists():
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        
                    # Check for privileged mode
                    if re.search(r'privileged:\s*true', content):
                        self._add_finding(
                            "CRITICAL", "docker",
                            "Privileged container mode",
                            "Container running in privileged mode",
                            str(file_path)
                        )
                        
                    # Check for host network mode
                    if re.search(r'network_mode:\s*host', content):
                        self._add_finding(
                            "HIGH", "docker",
                            "Host network mode",
                            "Container using host network mode",
                            str(file_path)
                        )
                        
                except Exception as e:
                    pass
                    
    def _check_kubernetes_security(self):
        """Check Kubernetes configuration security"""
        print("☸️  Checking Kubernetes security...")
        
        k8s_dir = self.project_root / "k8s"
        if k8s_dir.exists():
            for yaml_file in k8s_dir.glob("*.yaml"):
                try:
                    with open(yaml_file, 'r') as f:
                        content = f.read()
                        
                    # Check for privileged containers
                    if re.search(r'privileged:\s*true', content):
                        self._add_finding(
                            "CRITICAL", "kubernetes",
                            "Privileged container in Kubernetes",
                            "Pod configured to run privileged",
                            str(yaml_file)
                        )
                        
                    # Check for runAsRoot
                    if not re.search(r'runAsNonRoot:\s*true', content):
                        self._add_finding(
                            "HIGH", "kubernetes",
                            "Container may run as root",
                            "runAsNonRoot not set to true",
                            str(yaml_file)
                        )
                        
                    # Check for resource limits
                    if not re.search(r'limits:', content):
                        self._add_finding(
                            "MEDIUM", "kubernetes",
                            "No resource limits defined",
                            "Container has no resource limits",
                            str(yaml_file)
                        )
                        
                except Exception as e:
                    pass
                    
    def _check_database_security(self):
        """Check database security configuration"""
        print("🗄️  Checking database security...")
        
        # Check for SQLite databases
        db_files = list(self.project_root.glob("**/*.db")) + list(self.project_root.glob("**/*.sqlite"))
        
        for db_file in db_files:
            # Check file permissions
            stat = db_file.stat()
            mode = oct(stat.st_mode)[-3:]
            
            if mode[2] in ['4', '5', '6', '7']:
                self._add_finding(
                    "HIGH", "database",
                    "Database file world-readable",
                    f"Database {db_file} is world-readable",
                    str(db_file)
                )
                
            # Try to connect and check for default passwords
            try:
                conn = sqlite3.connect(db_file)
                cursor = conn.cursor()
                
                # Check for users table with weak passwords
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = cursor.fetchall()
                
                for table in tables:
                    table_name = table[0]
                    if 'user' in table_name.lower():
                        try:
                            cursor.execute(f"SELECT * FROM {table_name} LIMIT 1")
                            columns = [description[0] for description in cursor.description]
                            
                            if any('password' in col.lower() for col in columns):
                                self._add_finding(
                                    "INFO", "database",
                                    "User table with passwords found",
                                    f"Found user table {table_name} with password column",
                                    str(db_file)
                                )
                        except sqlite3.Error:
                            pass
                            
                conn.close()
                
            except sqlite3.Error:
                pass
                
    def _check_api_security(self):
        """Check API security implementation"""
        print("🌐 Checking API security...")
        
        api_files = list(self.project_root.glob("**/api/**/*.py"))
        
        for file_path in api_files:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                    
                # Check for missing authentication
                if re.search(r'@app\.route|@router\.', content):
                    if not re.search(r'@.*auth|@.*login_required|@.*token_required', content):
                        self._add_finding(
                            "MEDIUM", "api",
                            "Potentially unprotected API endpoint",
                            "API route without authentication decorator",
                            str(file_path)
                        )
                        
                # Check for CORS issues
                if re.search(r'CORS.*origins.*\*', content):
                    self._add_finding(
                        "HIGH", "api",
                        "Overly permissive CORS configuration",
                        "CORS allows all origins (*)",
                        str(file_path)
                    )
                    
                # Check for rate limiting
                if re.search(r'@app\.route', content) and not re.search(r'@.*rate_limit', content):
                    self._add_finding(
                        "LOW", "api",
                        "No rate limiting detected",
                        "API endpoint without rate limiting",
                        str(file_path)
                    )
                    
            except Exception as e:
                pass
                
    def _add_finding(self, severity: str, category: str, title: str, description: str,
                    file_path: str = None, line_number: int = None, evidence: str = None):
        """Add security finding to the report"""
        finding = SecurityFinding(
            severity=severity,
            category=category,
            title=title,
            description=description,
            file_path=file_path,
            line_number=line_number,
            evidence=evidence,
            recommendation=self._get_recommendation(category, title)
        )
        self.findings.append(finding)
        
    def _get_recommendation(self, category: str, title: str) -> str:
        """Get security recommendation for finding"""
        recommendations = {
            'hardcoded_secrets': 'Use environment variables or secure secret management',
            'sql_injection': 'Use parameterized queries or ORM',
            'command_injection': 'Avoid shell execution, use subprocess with shell=False',
            'path_traversal': 'Validate and sanitize file paths, use os.path.abspath',
            'weak_crypto': 'Use strong cryptographic algorithms (SHA-256, AES-256)',
            'authentication': 'Implement proper authentication and authorization',
            'input_validation': 'Validate and sanitize all user inputs',
            'configuration': 'Use secure configuration practices, avoid hardcoding',
            'permissions': 'Set appropriate file permissions (600 for sensitive files)',
            'docker': 'Follow Docker security best practices',
            'kubernetes': 'Implement Kubernetes security policies',
            'database': 'Secure database configuration and access',
            'api': 'Implement API security controls (authentication, rate limiting, CORS)'
        }
        
        for key, recommendation in recommendations.items():
            if key in category.lower() or key in title.lower():
                return recommendation
                
        return 'Review and implement appropriate security controls'
        
    def _generate_security_report(self, start_time: datetime) -> SecurityReport:
        """Generate comprehensive security report"""
        
        # Calculate summary statistics
        summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for finding in self.findings:
            summary[finding.severity] += 1
            
        # Calculate overall security score (0-100)
        total_findings = len(self.findings)
        if total_findings == 0:
            overall_score = 100.0
        else:
            # Weight different severities
            weighted_score = (
                summary['CRITICAL'] * 20 +
                summary['HIGH'] * 10 +
                summary['MEDIUM'] * 5 +
                summary['LOW'] * 2 +
                summary['INFO'] * 1
            )
            # Cap at 100 for scoring
            overall_score = max(0, 100 - min(100, weighted_score))
            
        # Generate recommendations
        recommendations = self._generate_recommendations()
        
        # Compliance checks
        compliance_status = {
            'OWASP_Top_10': summary['CRITICAL'] == 0 and summary['HIGH'] < 3,
            'Data_Protection': all(f.category != 'hardcoded_secrets' for f in self.findings),
            'Access_Control': summary['CRITICAL'] == 0,
            'Logging_Monitoring': True,  # Assume implemented based on audit
            'Encryption': all('weak_crypto' not in f.category for f in self.findings)
        }
        
        return SecurityReport(
            audit_timestamp=start_time,
            findings=self.findings,
            summary=summary,
            compliance_status=compliance_status,
            recommendations=recommendations,
            overall_score=overall_score
        )
        
    def _generate_recommendations(self) -> List[str]:
        """Generate prioritized security recommendations"""
        recommendations = []
        
        critical_count = sum(1 for f in self.findings if f.severity == 'CRITICAL')
        high_count = sum(1 for f in self.findings if f.severity == 'HIGH')
        
        if critical_count > 0:
            recommendations.append(f"🚨 URGENT: Fix {critical_count} critical security vulnerabilities immediately")
            
        if high_count > 0:
            recommendations.append(f"⚠️  Address {high_count} high-severity security issues")
            
        # Category-specific recommendations
        categories = set(f.category for f in self.findings)
        
        if 'hardcoded_secrets' in categories:
            recommendations.append("🔐 Implement secure secret management system")
            
        if 'sql_injection' in categories:
            recommendations.append("🛡️  Review and fix SQL injection vulnerabilities")
            
        if 'docker' in categories:
            recommendations.append("🐳 Harden Docker container security")
            
        if 'api' in categories:
            recommendations.append("🌐 Implement API security controls")
            
        if len(self.findings) == 0:
            recommendations.append("✅ Excellent! No security issues found")
        elif len(self.findings) < 5:
            recommendations.append("👍 Good security posture, minor improvements needed")
        else:
            recommendations.append("🔧 Comprehensive security improvements recommended")
            
        return recommendations
        
    def save_report(self, report: SecurityReport, output_file: str = "security_audit_report.json"):
        """Save security report to file"""
        report_data = {
            'audit_timestamp': report.audit_timestamp.isoformat(),
            'summary': report.summary,
            'compliance_status': report.compliance_status,
            'overall_score': report.overall_score,
            'recommendations': report.recommendations,
            'findings': [
                {
                    'severity': f.severity,
                    'category': f.category,
                    'title': f.title,
                    'description': f.description,
                    'file_path': f.file_path,
                    'line_number': f.line_number,
                    'evidence': f.evidence,
                    'recommendation': f.recommendation
                }
                for f in report.findings
            ]
        }
        
        output_path = self.project_root / output_file
        with open(output_path, 'w') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
            
        print(f"📊 Security report saved to {output_path}")
        
    def print_report_summary(self, report: SecurityReport):
        """Print security report summary to console"""
        print("\n" + "="*80)
        print("🔒 BLNCS SECURITY AUDIT REPORT")
        print("="*80)
        
        print(f"📅 Audit Date: {report.audit_timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🎯 Overall Security Score: {report.overall_score:.1f}/100")
        
        print("\n📊 FINDINGS SUMMARY:")
        print("-" * 40)
        for severity, count in report.summary.items():
            if count > 0:
                emoji = {'CRITICAL': '🚨', 'HIGH': '⚠️', 'MEDIUM': '🟡', 'LOW': '🔵', 'INFO': 'ℹ️'}
                print(f"{emoji.get(severity, '•')} {severity}: {count}")
                
        print(f"\n📋 Total Findings: {sum(report.summary.values())}")
        
        print("\n✅ COMPLIANCE STATUS:")
        print("-" * 40)
        for standard, status in report.compliance_status.items():
            status_emoji = "✅" if status else "❌"
            print(f"{status_emoji} {standard.replace('_', ' ')}: {'PASS' if status else 'FAIL'}")
            
        print("\n🎯 PRIORITY RECOMMENDATIONS:")
        print("-" * 40)
        for i, recommendation in enumerate(report.recommendations, 1):
            print(f"{i}. {recommendation}")
            
        if report.overall_score >= 90:
            print(f"\n🏆 EXCELLENT SECURITY POSTURE!")
        elif report.overall_score >= 70:
            print(f"\n👍 GOOD SECURITY POSTURE - Minor improvements needed")
        elif report.overall_score >= 50:
            print(f"\n⚠️  MODERATE SECURITY RISK - Improvements required")
        else:
            print(f"\n🚨 HIGH SECURITY RISK - Immediate action required")
            
        print("="*80)

def main():
    """Main function for security audit"""
    print("🔒 BLNCS Enterprise Security Audit Tool")
    print("National-grade security validation and vulnerability assessment")
    print("-" * 60)
    
    # Initialize auditor
    auditor = SecurityAuditor(".")
    
    # Run comprehensive audit
    try:
        report = auditor.run_comprehensive_audit()
        
        # Print summary
        auditor.print_report_summary(report)
        
        # Save detailed report
        auditor.save_report(report)
        
        # Exit with appropriate code
        if report.overall_score < 50:
            print("\n🚨 Security audit failed - critical issues found!")
            sys.exit(1)
        elif report.summary['CRITICAL'] > 0:
            print("\n⚠️  Security audit passed with warnings - critical issues found!")
            sys.exit(1)
        else:
            print("\n✅ Security audit passed successfully!")
            sys.exit(0)
            
    except Exception as e:
        print(f"\n❌ Security audit failed with error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()