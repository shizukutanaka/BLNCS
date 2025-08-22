# BLRCS Security Auto-Configuration System
# Automatic security configuration for all expertise levels

import os
import secrets
import hashlib
import json
import logging
import ssl
import socket
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import subprocess
import platform
import psutil
import re

logger = logging.getLogger(__name__)

class SecurityLevel(Enum):
    """Security level definitions"""
    MINIMAL = 1      # Basic protection
    STANDARD = 2     # Standard enterprise security
    ENHANCED = 3     # Enhanced security
    MAXIMUM = 4      # Maximum security (government/military grade)
    PARANOID = 5     # Ultra-high security with performance trade-offs

class ComplianceStandard(Enum):
    """Compliance standards"""
    NONE = "none"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    ISO_27001 = "iso_27001"
    NIST = "nist"
    FedRAMP = "fedramp"
    CMMC = "cmmc"
    SOC2 = "soc2"

@dataclass
class SecurityConfig:
    """Security configuration container"""
    level: SecurityLevel = SecurityLevel.STANDARD
    compliance: List[ComplianceStandard] = field(default_factory=list)
    encryption_key_size: int = 256
    password_min_length: int = 12
    password_complexity: bool = True
    mfa_enabled: bool = True
    session_timeout: int = 3600
    max_login_attempts: int = 5
    lockout_duration: int = 1800
    audit_logging: bool = True
    data_encryption_at_rest: bool = True
    data_encryption_in_transit: bool = True
    secure_headers: bool = True
    rate_limiting: bool = True
    intrusion_detection: bool = True
    vulnerability_scanning: bool = True
    automatic_updates: bool = True
    backup_encryption: bool = True
    secure_deletion: bool = True
    network_segmentation: bool = False
    zero_trust_architecture: bool = False

class SecurityAutoConfigurator:
    """Automatic security configuration system"""
    
    def __init__(self):
        self.config_path = Path.home() / ".blrcs" / "security"
        self.config_path.mkdir(parents=True, exist_ok=True)
        self.config_file = self.config_path / "auto_config.json"
        self.current_config = SecurityConfig()
        self.system_info = self._gather_system_info()
        
    def _gather_system_info(self) -> Dict[str, Any]:
        """Gather system information for security decisions"""
        info = {
            "os": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "memory_gb": psutil.virtual_memory().total / (1024**3),
            "cpu_count": psutil.cpu_count(),
            "network_interfaces": len(psutil.net_if_addrs()),
            "disk_encryption": self._check_disk_encryption(),
            "firewall_enabled": self._check_firewall(),
            "antivirus_installed": self._check_antivirus(),
            "running_as_admin": self._check_admin_privileges(),
        }
        return info
    
    def _check_disk_encryption(self) -> bool:
        """Check if disk encryption is enabled"""
        if platform.system() == "Windows":
            try:
                result = subprocess.run(
                    ["manage-bde", "-status"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                return "Encrypted" in result.stdout
            except:
                return False
        elif platform.system() == "Linux":
            try:
                result = subprocess.run(
                    ["lsblk", "-o", "NAME,FSTYPE"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                return "crypto_LUKS" in result.stdout
            except:
                return False
        elif platform.system() == "Darwin":  # macOS
            try:
                result = subprocess.run(
                    ["fdesetup", "status"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                return "FileVault is On" in result.stdout
            except:
                return False
        return False
    
    def _check_firewall(self) -> bool:
        """Check if firewall is enabled"""
        if platform.system() == "Windows":
            try:
                result = subprocess.run(
                    ["netsh", "advfirewall", "show", "currentprofile"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                return "ON" in result.stdout
            except:
                return False
        elif platform.system() == "Linux":
            try:
                # Check iptables
                result = subprocess.run(
                    ["iptables", "-L", "-n"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                return len(result.stdout.split('\n')) > 10
            except:
                return False
        return False
    
    def _check_antivirus(self) -> bool:
        """Check if antivirus is installed"""
        if platform.system() == "Windows":
            try:
                result = subprocess.run(
                    ["wmic", "/namespace:\\\\root\\SecurityCenter2", "path", "AntiVirusProduct", "get", "displayName"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                return "displayName" in result.stdout and len(result.stdout.split('\n')) > 2
            except:
                return False
        return False
    
    def _check_admin_privileges(self) -> bool:
        """Check if running with admin privileges"""
        try:
            return os.getuid() == 0
        except AttributeError:
            # Windows
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
    
    def auto_detect_security_level(self) -> SecurityLevel:
        """Automatically detect appropriate security level"""
        score = 0
        
        # Environment analysis
        if self.system_info["disk_encryption"]:
            score += 2
        if self.system_info["firewall_enabled"]:
            score += 1
        if self.system_info["antivirus_installed"]:
            score += 1
        if not self.system_info["running_as_admin"]:
            score += 1
        
        # Network exposure check
        if self.system_info["network_interfaces"] > 2:
            score += 1
        
        # Resource availability
        if self.system_info["memory_gb"] >= 16:
            score += 1
        if self.system_info["cpu_count"] >= 8:
            score += 1
        
        # Determine level based on score
        if score >= 7:
            return SecurityLevel.MAXIMUM
        elif score >= 5:
            return SecurityLevel.ENHANCED
        elif score >= 3:
            return SecurityLevel.STANDARD
        else:
            return SecurityLevel.MINIMAL
    
    def configure_for_level(self, level: Optional[SecurityLevel] = None) -> SecurityConfig:
        """Configure security settings based on level"""
        if level is None:
            level = self.auto_detect_security_level()
        
        config = SecurityConfig(level=level)
        
        if level == SecurityLevel.MINIMAL:
            config.encryption_key_size = 128
            config.password_min_length = 8
            config.mfa_enabled = False
            config.session_timeout = 7200
            config.intrusion_detection = False
            config.vulnerability_scanning = False
            
        elif level == SecurityLevel.STANDARD:
            config.encryption_key_size = 256
            config.password_min_length = 12
            config.mfa_enabled = True
            config.session_timeout = 3600
            
        elif level == SecurityLevel.ENHANCED:
            config.encryption_key_size = 256
            config.password_min_length = 16
            config.mfa_enabled = True
            config.session_timeout = 1800
            config.max_login_attempts = 3
            config.network_segmentation = True
            
        elif level == SecurityLevel.MAXIMUM:
            config.encryption_key_size = 512
            config.password_min_length = 20
            config.mfa_enabled = True
            config.session_timeout = 900
            config.max_login_attempts = 3
            config.lockout_duration = 3600
            config.network_segmentation = True
            config.zero_trust_architecture = True
            
        elif level == SecurityLevel.PARANOID:
            config.encryption_key_size = 512
            config.password_min_length = 32
            config.mfa_enabled = True
            config.session_timeout = 300
            config.max_login_attempts = 2
            config.lockout_duration = 7200
            config.network_segmentation = True
            config.zero_trust_architecture = True
            config.secure_deletion = True
        
        self.current_config = config
        return config
    
    def apply_compliance_requirements(self, standards: List[ComplianceStandard]) -> None:
        """Apply compliance-specific requirements"""
        for standard in standards:
            if standard == ComplianceStandard.PCI_DSS:
                self.current_config.encryption_key_size = max(256, self.current_config.encryption_key_size)
                self.current_config.password_min_length = max(7, self.current_config.password_min_length)
                self.current_config.password_complexity = True
                self.current_config.session_timeout = min(900, self.current_config.session_timeout)
                self.current_config.audit_logging = True
                
            elif standard == ComplianceStandard.HIPAA:
                self.current_config.encryption_key_size = max(256, self.current_config.encryption_key_size)
                self.current_config.data_encryption_at_rest = True
                self.current_config.data_encryption_in_transit = True
                self.current_config.audit_logging = True
                self.current_config.automatic_updates = True
                
            elif standard == ComplianceStandard.GDPR:
                self.current_config.data_encryption_at_rest = True
                self.current_config.audit_logging = True
                self.current_config.secure_deletion = True
                
            elif standard == ComplianceStandard.ISO_27001:
                self.current_config.password_min_length = max(8, self.current_config.password_min_length)
                self.current_config.audit_logging = True
                self.current_config.vulnerability_scanning = True
                self.current_config.backup_encryption = True
                
            elif standard == ComplianceStandard.NIST:
                self.current_config.encryption_key_size = max(256, self.current_config.encryption_key_size)
                self.current_config.password_min_length = max(12, self.current_config.password_min_length)
                self.current_config.mfa_enabled = True
                self.current_config.audit_logging = True
                
            elif standard == ComplianceStandard.FedRAMP:
                self.current_config.encryption_key_size = max(256, self.current_config.encryption_key_size)
                self.current_config.password_min_length = max(20, self.current_config.password_min_length)
                self.current_config.mfa_enabled = True
                self.current_config.audit_logging = True
                self.current_config.vulnerability_scanning = True
                self.current_config.zero_trust_architecture = True
        
        self.current_config.compliance = standards
    
    def generate_secure_keys(self) -> Dict[str, str]:
        """Generate secure keys and secrets"""
        keys = {
            "secret_key": secrets.token_urlsafe(64),
            "jwt_secret": secrets.token_urlsafe(64),
            "encryption_key": secrets.token_hex(self.current_config.encryption_key_size // 8),
            "database_key": secrets.token_urlsafe(32),
            "api_key": secrets.token_urlsafe(48),
            "csrf_key": secrets.token_urlsafe(32),
            "session_key": secrets.token_urlsafe(32),
        }
        
        # Save keys securely
        key_file = self.config_path / "keys.json"
        with open(key_file, 'w') as f:
            json.dump(keys, f, indent=2)
        
        # Set restrictive permissions
        os.chmod(key_file, 0o600)
        
        return keys
    
    def create_ssl_certificates(self) -> Tuple[str, str]:
        """Create self-signed SSL certificates"""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096 if self.current_config.level >= SecurityLevel.ENHANCED else 2048,
        )
        
        # Generate certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BLRCS"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("127.0.0.1"),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Save certificate and key
        cert_path = self.config_path / "cert.pem"
        key_path = self.config_path / "key.pem"
        
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Set restrictive permissions
        os.chmod(cert_path, 0o644)
        os.chmod(key_path, 0o600)
        
        return str(cert_path), str(key_path)
    
    def save_configuration(self) -> None:
        """Save current configuration"""
        config_dict = {
            "level": self.current_config.level.name,
            "compliance": [c.value for c in self.current_config.compliance],
            "settings": {
                "encryption_key_size": self.current_config.encryption_key_size,
                "password_min_length": self.current_config.password_min_length,
                "password_complexity": self.current_config.password_complexity,
                "mfa_enabled": self.current_config.mfa_enabled,
                "session_timeout": self.current_config.session_timeout,
                "max_login_attempts": self.current_config.max_login_attempts,
                "lockout_duration": self.current_config.lockout_duration,
                "audit_logging": self.current_config.audit_logging,
                "data_encryption_at_rest": self.current_config.data_encryption_at_rest,
                "data_encryption_in_transit": self.current_config.data_encryption_in_transit,
                "secure_headers": self.current_config.secure_headers,
                "rate_limiting": self.current_config.rate_limiting,
                "intrusion_detection": self.current_config.intrusion_detection,
                "vulnerability_scanning": self.current_config.vulnerability_scanning,
                "automatic_updates": self.current_config.automatic_updates,
                "backup_encryption": self.current_config.backup_encryption,
                "secure_deletion": self.current_config.secure_deletion,
                "network_segmentation": self.current_config.network_segmentation,
                "zero_trust_architecture": self.current_config.zero_trust_architecture,
            },
            "system_info": self.system_info,
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        with open(self.config_file, 'w') as f:
            json.dump(config_dict, f, indent=2)
        
        os.chmod(self.config_file, 0o600)
    
    def load_configuration(self) -> Optional[SecurityConfig]:
        """Load saved configuration"""
        if not self.config_file.exists():
            return None
        
        try:
            with open(self.config_file, 'r') as f:
                data = json.load(f)
            
            config = SecurityConfig()
            config.level = SecurityLevel[data["level"]]
            config.compliance = [ComplianceStandard(c) for c in data["compliance"]]
            
            for key, value in data["settings"].items():
                if hasattr(config, key):
                    setattr(config, key, value)
            
            return config
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            return None
    
    def get_security_recommendations(self) -> List[str]:
        """Get security recommendations based on current system"""
        recommendations = []
        
        if not self.system_info["disk_encryption"]:
            recommendations.append("Enable disk encryption for data protection")
        
        if not self.system_info["firewall_enabled"]:
            recommendations.append("Enable system firewall")
        
        if not self.system_info["antivirus_installed"] and platform.system() == "Windows":
            recommendations.append("Install antivirus software")
        
        if self.system_info["running_as_admin"]:
            recommendations.append("Run application with standard user privileges")
        
        if self.current_config.level < SecurityLevel.STANDARD:
            recommendations.append("Consider upgrading to STANDARD security level")
        
        if not self.current_config.mfa_enabled:
            recommendations.append("Enable Multi-Factor Authentication")
        
        if self.current_config.password_min_length < 12:
            recommendations.append("Increase minimum password length to 12+ characters")
        
        if not self.current_config.audit_logging:
            recommendations.append("Enable audit logging for compliance")
        
        return recommendations

# Global instance
security_configurator = SecurityAutoConfigurator()

def auto_configure_security(
    level: Optional[SecurityLevel] = None,
    compliance: Optional[List[ComplianceStandard]] = None
) -> Dict[str, Any]:
    """Main function to auto-configure security"""
    
    # Auto-detect or use specified level
    if level is None:
        level = security_configurator.auto_detect_security_level()
    
    # Configure for level
    config = security_configurator.configure_for_level(level)
    
    # Apply compliance if specified
    if compliance:
        security_configurator.apply_compliance_requirements(compliance)
    
    # Generate secure keys
    keys = security_configurator.generate_secure_keys()
    
    # Create SSL certificates
    cert_path, key_path = security_configurator.create_ssl_certificates()
    
    # Save configuration
    security_configurator.save_configuration()
    
    # Get recommendations
    recommendations = security_configurator.get_security_recommendations()
    
    return {
        "config": config,
        "keys_generated": list(keys.keys()),
        "ssl_cert": cert_path,
        "ssl_key": key_path,
        "recommendations": recommendations,
        "system_info": security_configurator.system_info,
    }