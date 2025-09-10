"""
Enterprise Container Security and Secrets Management
Advanced container hardening, secrets rotation, and runtime protection.
"""

import asyncio
import logging
import json
import hashlib
import secrets
import os
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import base64
import subprocess

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.fernet import Fernet
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

try:
    import hvac
    HAS_VAULT = True
except ImportError:
    HAS_VAULT = False
    hvac = None

try:
    import docker
    HAS_DOCKER = True
except ImportError:
    HAS_DOCKER = False
    docker = None

logger = logging.getLogger(__name__)

class SecretType(Enum):
    """Types of secrets managed."""
    API_KEY = "api_key"
    DATABASE_PASSWORD = "database_password"
    TLS_CERTIFICATE = "tls_certificate"
    TLS_PRIVATE_KEY = "tls_private_key"
    JWT_SECRET = "jwt_secret"
    ENCRYPTION_KEY = "encryption_key"
    LIGHTNING_MACAROON = "lightning_macaroon"
    WEBHOOK_SECRET = "webhook_secret"

class SecretStatus(Enum):
    """Secret lifecycle status."""
    ACTIVE = "active"
    ROTATING = "rotating"
    EXPIRED = "expired"
    REVOKED = "revoked"
    PENDING_DELETION = "pending_deletion"

class ContainerSecurityLevel(Enum):
    """Container security compliance levels."""
    BASELINE = "baseline"
    RESTRICTED = "restricted"
    HARDENED = "hardened"

class RuntimeProtection(Enum):
    """Runtime protection mechanisms."""
    SECCOMP = "seccomp"
    APPARMOR = "apparmor"
    SELINUX = "selinux"
    CAPABILITIES = "capabilities"
    NAMESPACE = "namespace"

@dataclass
class Secret:
    """Secret definition with metadata."""
    secret_id: str
    name: str
    secret_type: SecretType
    value: str  # Encrypted
    status: SecretStatus
    version: int
    created_at: datetime
    expires_at: Optional[datetime] = None
    rotated_at: Optional[datetime] = None
    last_accessed: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_expired(self) -> bool:
        """Check if secret is expired."""
        if self.expires_at:
            return datetime.utcnow() > self.expires_at
        return False
    
    def needs_rotation(self, rotation_days: int = 90) -> bool:
        """Check if secret needs rotation."""
        if self.rotated_at:
            return datetime.utcnow() > (self.rotated_at + timedelta(days=rotation_days))
        return datetime.utcnow() > (self.created_at + timedelta(days=rotation_days))

@dataclass
class ContainerSecurityPolicy:
    """Container security policy configuration."""
    name: str
    level: ContainerSecurityLevel
    runtime_protections: List[RuntimeProtection] = field(default_factory=list)
    allowed_capabilities: List[str] = field(default_factory=list)
    dropped_capabilities: List[str] = field(default_factory=list)
    read_only_root_filesystem: bool = True
    no_new_privileges: bool = True
    run_as_non_root: bool = True
    user_id: int = 1000
    group_id: int = 1000
    seccomp_profile: Optional[str] = None
    apparmor_profile: Optional[str] = None
    selinux_context: Optional[Dict[str, str]] = None
    resource_limits: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ContainerScanResult:
    """Container security scan results."""
    image_id: str
    scan_time: datetime
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    malware_detected: bool = False
    secrets_found: List[str] = field(default_factory=list)
    compliance_issues: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    
    @property
    def critical_vulns(self) -> int:
        """Count critical vulnerabilities."""
        return len([v for v in self.vulnerabilities if v.get('severity') == 'CRITICAL'])
    
    @property
    def high_vulns(self) -> int:
        """Count high severity vulnerabilities."""
        return len([v for v in self.vulnerabilities if v.get('severity') == 'HIGH'])

class SecretsManager:
    """Enterprise secrets management system."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize secrets manager."""
        self.config = config or self._get_default_config()
        self.secrets: Dict[str, Secret] = {}
        self.encryption_key = self._derive_master_key()
        
        # Vault integration
        self.vault_client: Optional[hvac.Client] = None
        if HAS_VAULT and self.config.get('vault_enabled', False):
            self._init_vault_client()
        
        # Threading
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="secrets")
        self.rotation_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        
        # Storage
        self.secrets_dir = Path(self.config.get('secrets_directory', '/var/lib/blncs/secrets'))
        self.secrets_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        
        logger.info("Secrets manager initialized")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            'secrets_directory': '/var/lib/blncs/secrets',
            'vault_enabled': False,
            'vault_url': 'http://localhost:8200',
            'vault_token': None,
            'vault_namespace': 'blncs',
            'rotation_interval': 86400,  # 24 hours
            'rotation_days': {
                SecretType.API_KEY: 90,
                SecretType.DATABASE_PASSWORD: 60,
                SecretType.TLS_CERTIFICATE: 365,
                SecretType.JWT_SECRET: 180,
                SecretType.ENCRYPTION_KEY: 365,
                SecretType.LIGHTNING_MACAROON: 30
            },
            'encryption_algorithm': 'AES-256-GCM',
            'key_derivation_iterations': 100000
        }
    
    def _derive_master_key(self) -> bytes:
        """Derive master encryption key."""
        if not HAS_CRYPTOGRAPHY:
            logger.warning("Cryptography not available, using simple key")
            return b'simple_key_for_testing_only' * 2
        
        # In production, this should use a hardware security module (HSM)
        # or key management service (KMS)
        master_password = os.environ.get('BLNCS_MASTER_KEY', 'default_master_key')
        salt = b'blncs_secret_salt_2024'
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.config['key_derivation_iterations'],
            backend=default_backend()
        )
        
        return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    
    def _init_vault_client(self) -> None:
        """Initialize HashiCorp Vault client."""
        if not HAS_VAULT:
            return
        
        try:
            self.vault_client = hvac.Client(
                url=self.config['vault_url'],
                token=self.config.get('vault_token') or os.environ.get('VAULT_TOKEN')
            )
            
            if not self.vault_client.is_authenticated():
                logger.error("Failed to authenticate with Vault")
                self.vault_client = None
            else:
                # Enable KV secrets engine if not already enabled
                namespace = self.config['vault_namespace']
                try:
                    self.vault_client.sys.enable_secrets_engine(
                        backend_type='kv-v2',
                        path=namespace
                    )
                except hvac.exceptions.InvalidRequest:
                    pass  # Already enabled
                
                logger.info("Successfully connected to HashiCorp Vault")
                
        except Exception as e:
            logger.error(f"Failed to initialize Vault client: {e}")
            self.vault_client = None
    
    def _encrypt_value(self, value: str) -> str:
        """Encrypt secret value."""
        if not HAS_CRYPTOGRAPHY:
            # Simple base64 encoding for testing
            return base64.b64encode(value.encode()).decode()
        
        fernet = Fernet(self.encryption_key)
        encrypted = fernet.encrypt(value.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def _decrypt_value(self, encrypted_value: str) -> str:
        """Decrypt secret value."""
        if not HAS_CRYPTOGRAPHY:
            # Simple base64 decoding for testing
            return base64.b64decode(encrypted_value.encode()).decode()
        
        try:
            fernet = Fernet(self.encryption_key)
            decoded = base64.urlsafe_b64decode(encrypted_value.encode())
            decrypted = fernet.decrypt(decoded)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Failed to decrypt secret: {e}")
            raise
    
    async def create_secret(self, name: str, value: str, secret_type: SecretType,
                          expires_days: Optional[int] = None) -> str:
        """Create a new secret."""
        secret_id = f"{name}_{int(datetime.utcnow().timestamp())}"
        
        expires_at = None
        if expires_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_days)
        
        secret = Secret(
            secret_id=secret_id,
            name=name,
            secret_type=secret_type,
            value=self._encrypt_value(value),
            status=SecretStatus.ACTIVE,
            version=1,
            created_at=datetime.utcnow(),
            expires_at=expires_at
        )
        
        # Store in Vault if available
        if self.vault_client:
            await self._store_in_vault(secret, value)
        
        # Store locally
        self.secrets[secret_id] = secret
        await self._save_secret_metadata(secret)
        
        logger.info(f"Created secret {secret_id} of type {secret_type.value}")
        return secret_id
    
    async def _store_in_vault(self, secret: Secret, raw_value: str) -> None:
        """Store secret in HashiCorp Vault."""
        if not self.vault_client:
            return
        
        try:
            path = f"{self.config['vault_namespace']}/{secret.name}"
            
            self.vault_client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret={
                    'value': raw_value,
                    'type': secret.secret_type.value,
                    'version': secret.version,
                    'created_at': secret.created_at.isoformat(),
                    'expires_at': secret.expires_at.isoformat() if secret.expires_at else None
                },
                mount_point=self.config['vault_namespace']
            )
            
            logger.debug(f"Stored secret {secret.secret_id} in Vault")
            
        except Exception as e:
            logger.error(f"Failed to store secret in Vault: {e}")
    
    async def get_secret(self, secret_id: str) -> Optional[str]:
        """Retrieve secret value."""
        secret = self.secrets.get(secret_id)
        if not secret:
            return None
        
        if secret.status != SecretStatus.ACTIVE:
            logger.warning(f"Attempted to access non-active secret {secret_id}")
            return None
        
        if secret.is_expired():
            secret.status = SecretStatus.EXPIRED
            logger.warning(f"Secret {secret_id} has expired")
            return None
        
        # Update last accessed time
        secret.last_accessed = datetime.utcnow()
        
        # Try to get from Vault first
        if self.vault_client:
            vault_value = await self._get_from_vault(secret)
            if vault_value:
                return vault_value
        
        # Decrypt local value
        return self._decrypt_value(secret.value)
    
    async def _get_from_vault(self, secret: Secret) -> Optional[str]:
        """Get secret from HashiCorp Vault."""
        if not self.vault_client:
            return None
        
        try:
            path = f"{self.config['vault_namespace']}/{secret.name}"
            
            response = self.vault_client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=self.config['vault_namespace']
            )
            
            if response and 'data' in response and 'data' in response['data']:
                return response['data']['data'].get('value')
                
        except Exception as e:
            logger.error(f"Failed to get secret from Vault: {e}")
        
        return None
    
    async def rotate_secret(self, secret_id: str, new_value: str) -> bool:
        """Rotate a secret to a new value."""
        secret = self.secrets.get(secret_id)
        if not secret:
            return False
        
        old_value = secret.value
        secret.status = SecretStatus.ROTATING
        
        try:
            # Create new version
            secret.value = self._encrypt_value(new_value)
            secret.version += 1
            secret.rotated_at = datetime.utcnow()
            secret.status = SecretStatus.ACTIVE
            
            # Update in Vault
            if self.vault_client:
                await self._store_in_vault(secret, new_value)
            
            # Save metadata
            await self._save_secret_metadata(secret)
            
            logger.info(f"Rotated secret {secret_id} to version {secret.version}")
            return True
            
        except Exception as e:
            # Rollback on failure
            secret.value = old_value
            secret.version -= 1
            secret.status = SecretStatus.ACTIVE
            logger.error(f"Failed to rotate secret {secret_id}: {e}")
            return False
    
    async def delete_secret(self, secret_id: str, grace_period_days: int = 7) -> bool:
        """Delete a secret with optional grace period."""
        secret = self.secrets.get(secret_id)
        if not secret:
            return False
        
        if grace_period_days > 0:
            # Mark for deletion after grace period
            secret.status = SecretStatus.PENDING_DELETION
            secret.expires_at = datetime.utcnow() + timedelta(days=grace_period_days)
            await self._save_secret_metadata(secret)
            
            logger.info(f"Secret {secret_id} marked for deletion in {grace_period_days} days")
        else:
            # Immediate deletion
            if self.vault_client:
                await self._delete_from_vault(secret)
            
            del self.secrets[secret_id]
            
            # Delete metadata file
            metadata_file = self.secrets_dir / f"{secret_id}.json"
            if metadata_file.exists():
                metadata_file.unlink()
            
            logger.info(f"Secret {secret_id} deleted immediately")
        
        return True
    
    async def _delete_from_vault(self, secret: Secret) -> None:
        """Delete secret from HashiCorp Vault."""
        if not self.vault_client:
            return
        
        try:
            path = f"{self.config['vault_namespace']}/{secret.name}"
            
            self.vault_client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=path,
                mount_point=self.config['vault_namespace']
            )
            
            logger.debug(f"Deleted secret {secret.secret_id} from Vault")
            
        except Exception as e:
            logger.error(f"Failed to delete secret from Vault: {e}")
    
    async def _save_secret_metadata(self, secret: Secret) -> None:
        """Save secret metadata to disk."""
        metadata = {
            'secret_id': secret.secret_id,
            'name': secret.name,
            'type': secret.secret_type.value,
            'status': secret.status.value,
            'version': secret.version,
            'created_at': secret.created_at.isoformat(),
            'expires_at': secret.expires_at.isoformat() if secret.expires_at else None,
            'rotated_at': secret.rotated_at.isoformat() if secret.rotated_at else None,
            'metadata': secret.metadata
        }
        
        metadata_file = self.secrets_dir / f"{secret.secret_id}.json"
        
        # Write atomically
        temp_file = metadata_file.with_suffix('.tmp')
        with open(temp_file, 'w') as f:
            json.dump(metadata, f)
        
        temp_file.replace(metadata_file)
        
        # Set restrictive permissions
        os.chmod(metadata_file, 0o600)
    
    def start_auto_rotation(self) -> None:
        """Start automatic secret rotation."""
        if self.rotation_thread and self.rotation_thread.is_alive():
            logger.warning("Secret rotation already running")
            return
        
        self.stop_event.clear()
        self.rotation_thread = threading.Thread(
            target=self._rotation_loop,
            name="secret-rotation",
            daemon=True
        )
        self.rotation_thread.start()
        
        logger.info("Started automatic secret rotation")
    
    def stop_auto_rotation(self) -> None:
        """Stop automatic secret rotation."""
        if not self.rotation_thread or not self.rotation_thread.is_alive():
            return
        
        self.stop_event.set()
        self.rotation_thread.join(timeout=5.0)
        
        logger.info("Stopped automatic secret rotation")
    
    def _rotation_loop(self) -> None:
        """Secret rotation loop."""
        interval = self.config.get('rotation_interval', 86400)
        
        while not self.stop_event.is_set():
            try:
                asyncio.run(self._check_and_rotate_secrets())
                
                # Wait for next rotation check
                if self.stop_event.wait(interval):
                    break
                    
            except Exception as e:
                logger.error(f"Error in secret rotation loop: {e}")
                # Wait before retrying
                if self.stop_event.wait(300):
                    break
    
    async def _check_and_rotate_secrets(self) -> None:
        """Check and rotate secrets that need rotation."""
        rotation_days = self.config.get('rotation_days', {})
        
        for secret in list(self.secrets.values()):
            if secret.status != SecretStatus.ACTIVE:
                continue
            
            # Check if secret needs rotation
            days = rotation_days.get(secret.secret_type, 90)
            if secret.needs_rotation(days):
                # Generate new value based on type
                new_value = await self._generate_secret_value(secret.secret_type)
                
                if await self.rotate_secret(secret.secret_id, new_value):
                    logger.info(f"Auto-rotated secret {secret.secret_id}")
            
            # Check for expired secrets
            if secret.is_expired():
                secret.status = SecretStatus.EXPIRED
                await self._save_secret_metadata(secret)
            
            # Clean up pending deletion secrets
            if (secret.status == SecretStatus.PENDING_DELETION and 
                secret.expires_at and datetime.utcnow() > secret.expires_at):
                await self.delete_secret(secret.secret_id, grace_period_days=0)
    
    async def _generate_secret_value(self, secret_type: SecretType) -> str:
        """Generate a new secret value based on type."""
        if secret_type == SecretType.API_KEY:
            return secrets.token_urlsafe(32)
        elif secret_type == SecretType.DATABASE_PASSWORD:
            return secrets.token_urlsafe(24)
        elif secret_type == SecretType.JWT_SECRET:
            return secrets.token_hex(32)
        elif secret_type == SecretType.ENCRYPTION_KEY:
            return base64.b64encode(secrets.token_bytes(32)).decode()
        elif secret_type == SecretType.WEBHOOK_SECRET:
            return secrets.token_hex(16)
        else:
            return secrets.token_urlsafe(32)

class ContainerSecurityManager:
    """Container security and runtime protection manager."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize container security manager."""
        self.config = config or self._get_default_config()
        self.policies: Dict[str, ContainerSecurityPolicy] = {}
        self.scan_results: Dict[str, ContainerScanResult] = {}
        
        # Docker client
        self.docker_client: Optional[docker.DockerClient] = None
        if HAS_DOCKER:
            try:
                self.docker_client = docker.from_env()
            except Exception as e:
                logger.error(f"Failed to initialize Docker client: {e}")
        
        # Initialize default policies
        self._init_default_policies()
        
        logger.info("Container security manager initialized")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            'scan_on_build': True,
            'scan_on_deploy': True,
            'block_on_critical': True,
            'max_critical_vulns': 0,
            'max_high_vulns': 5,
            'required_labels': ['version', 'maintainer', 'security-scan'],
            'forbidden_packages': ['netcat', 'telnet', 'ssh'],
            'trusted_registries': ['docker.io', 'gcr.io', 'quay.io'],
            'scan_tools': ['trivy', 'clair', 'anchore']
        }
    
    def _init_default_policies(self) -> None:
        """Initialize default security policies."""
        # Baseline policy
        self.policies['baseline'] = ContainerSecurityPolicy(
            name='baseline',
            level=ContainerSecurityLevel.BASELINE,
            runtime_protections=[RuntimeProtection.CAPABILITIES],
            dropped_capabilities=['ALL'],
            allowed_capabilities=['CHOWN', 'SETUID', 'SETGID', 'NET_BIND_SERVICE'],
            read_only_root_filesystem=False,
            no_new_privileges=True,
            run_as_non_root=False
        )
        
        # Restricted policy
        self.policies['restricted'] = ContainerSecurityPolicy(
            name='restricted',
            level=ContainerSecurityLevel.RESTRICTED,
            runtime_protections=[
                RuntimeProtection.CAPABILITIES,
                RuntimeProtection.SECCOMP,
                RuntimeProtection.NAMESPACE
            ],
            dropped_capabilities=['ALL'],
            allowed_capabilities=['NET_BIND_SERVICE'],
            read_only_root_filesystem=True,
            no_new_privileges=True,
            run_as_non_root=True,
            user_id=1000,
            group_id=1000,
            seccomp_profile='runtime/default'
        )
        
        # Hardened policy
        self.policies['hardened'] = ContainerSecurityPolicy(
            name='hardened',
            level=ContainerSecurityLevel.HARDENED,
            runtime_protections=[
                RuntimeProtection.CAPABILITIES,
                RuntimeProtection.SECCOMP,
                RuntimeProtection.APPARMOR,
                RuntimeProtection.NAMESPACE
            ],
            dropped_capabilities=['ALL'],
            allowed_capabilities=[],
            read_only_root_filesystem=True,
            no_new_privileges=True,
            run_as_non_root=True,
            user_id=65534,  # nobody user
            group_id=65534,
            seccomp_profile='runtime/default',
            apparmor_profile='docker-default',
            resource_limits={
                'memory': '512Mi',
                'cpu': '500m',
                'ephemeral-storage': '1Gi'
            }
        )
    
    async def scan_image(self, image_name: str, tag: str = 'latest') -> ContainerScanResult:
        """Scan container image for vulnerabilities."""
        image_id = f"{image_name}:{tag}"
        scan_result = ContainerScanResult(
            image_id=image_id,
            scan_time=datetime.utcnow()
        )
        
        # Run security scans
        for tool in self.config.get('scan_tools', ['trivy']):
            if tool == 'trivy':
                vulns = await self._scan_with_trivy(image_id)
                scan_result.vulnerabilities.extend(vulns)
        
        # Check for secrets
        scan_result.secrets_found = await self._scan_for_secrets(image_id)
        
        # Check compliance
        scan_result.compliance_issues = await self._check_compliance(image_id)
        
        # Calculate risk score
        scan_result.risk_score = self._calculate_risk_score(scan_result)
        
        # Store result
        self.scan_results[image_id] = scan_result
        
        # Check if should block
        if self._should_block_deployment(scan_result):
            logger.error(f"Image {image_id} failed security scan - blocking deployment")
            raise RuntimeError(f"Image {image_id} failed security requirements")
        
        return scan_result
    
    async def _scan_with_trivy(self, image_id: str) -> List[Dict[str, Any]]:
        """Scan image with Trivy."""
        vulnerabilities = []
        
        try:
            # Run Trivy scan
            result = subprocess.run(
                ['trivy', 'image', '--format', 'json', '--quiet', image_id],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                scan_data = json.loads(result.stdout)
                
                # Extract vulnerabilities
                for target in scan_data.get('Results', []):
                    for vuln in target.get('Vulnerabilities', []):
                        vulnerabilities.append({
                            'id': vuln.get('VulnerabilityID'),
                            'package': vuln.get('PkgName'),
                            'version': vuln.get('InstalledVersion'),
                            'severity': vuln.get('Severity'),
                            'title': vuln.get('Title'),
                            'description': vuln.get('Description'),
                            'fixed_version': vuln.get('FixedVersion')
                        })
                        
        except subprocess.TimeoutExpired:
            logger.error(f"Trivy scan timed out for {image_id}")
        except Exception as e:
            logger.error(f"Failed to scan with Trivy: {e}")
        
        return vulnerabilities
    
    async def _scan_for_secrets(self, image_id: str) -> List[str]:
        """Scan image for embedded secrets."""
        secrets_found = []
        
        # Common secret patterns
        secret_patterns = [
            r'(?i)(api[_-]?key|apikey)',
            r'(?i)(secret[_-]?key|secretkey)',
            r'(?i)(password|passwd|pwd)',
            r'(?i)(token|bearer)',
            r'(?i)BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY',
            r'(?i)aws[_-]?access[_-]?key',
            r'(?i)aws[_-]?secret'
        ]
        
        # In production, this would inspect image layers
        # For now, return empty list
        return secrets_found
    
    async def _check_compliance(self, image_id: str) -> List[str]:
        """Check image compliance with policies."""
        issues = []
        
        if not self.docker_client:
            return issues
        
        try:
            # Get image details
            image = self.docker_client.images.get(image_id)
            
            # Check required labels
            for label in self.config.get('required_labels', []):
                if label not in image.labels:
                    issues.append(f"Missing required label: {label}")
            
            # Check for forbidden packages (would require image inspection)
            # This is simplified for demonstration
            
            # Check registry trust
            registry = image_id.split('/')[0] if '/' in image_id else 'docker.io'
            if registry not in self.config.get('trusted_registries', []):
                issues.append(f"Image from untrusted registry: {registry}")
                
        except docker.errors.ImageNotFound:
            issues.append(f"Image not found: {image_id}")
        except Exception as e:
            logger.error(f"Failed to check compliance: {e}")
        
        return issues
    
    def _calculate_risk_score(self, scan_result: ContainerScanResult) -> float:
        """Calculate risk score for scan results."""
        score = 0.0
        
        # Vulnerability scoring
        score += scan_result.critical_vulns * 10.0
        score += scan_result.high_vulns * 5.0
        score += len([v for v in scan_result.vulnerabilities if v.get('severity') == 'MEDIUM']) * 2.0
        score += len([v for v in scan_result.vulnerabilities if v.get('severity') == 'LOW']) * 0.5
        
        # Secrets found
        score += len(scan_result.secrets_found) * 15.0
        
        # Compliance issues
        score += len(scan_result.compliance_issues) * 3.0
        
        # Malware
        if scan_result.malware_detected:
            score += 50.0
        
        # Normalize to 0-100
        return min(score, 100.0)
    
    def _should_block_deployment(self, scan_result: ContainerScanResult) -> bool:
        """Determine if deployment should be blocked."""
        if not self.config.get('block_on_critical', True):
            return False
        
        if scan_result.critical_vulns > self.config.get('max_critical_vulns', 0):
            return True
        
        if scan_result.high_vulns > self.config.get('max_high_vulns', 5):
            return True
        
        if scan_result.malware_detected:
            return True
        
        if scan_result.secrets_found:
            return True
        
        return False
    
    def generate_security_context(self, policy_name: str = 'restricted') -> Dict[str, Any]:
        """Generate Kubernetes security context from policy."""
        policy = self.policies.get(policy_name, self.policies['baseline'])
        
        security_context = {
            'runAsNonRoot': policy.run_as_non_root,
            'readOnlyRootFilesystem': policy.read_only_root_filesystem,
            'allowPrivilegeEscalation': not policy.no_new_privileges
        }
        
        if policy.run_as_non_root:
            security_context['runAsUser'] = policy.user_id
            security_context['runAsGroup'] = policy.group_id
            security_context['fsGroup'] = policy.group_id
        
        if policy.dropped_capabilities or policy.allowed_capabilities:
            security_context['capabilities'] = {
                'drop': policy.dropped_capabilities,
                'add': policy.allowed_capabilities
            }
        
        if policy.seccomp_profile:
            security_context['seccompProfile'] = {
                'type': 'RuntimeDefault' if policy.seccomp_profile == 'runtime/default' else 'Localhost',
                'localhostProfile': policy.seccomp_profile if policy.seccomp_profile != 'runtime/default' else None
            }
        
        if policy.selinux_context:
            security_context['seLinuxOptions'] = policy.selinux_context
        
        return security_context
    
    def generate_pod_security_policy(self, policy_name: str = 'restricted') -> Dict[str, Any]:
        """Generate Kubernetes Pod Security Policy."""
        policy = self.policies.get(policy_name, self.policies['baseline'])
        
        psp = {
            'apiVersion': 'policy/v1beta1',
            'kind': 'PodSecurityPolicy',
            'metadata': {
                'name': f'blncs-{policy_name}',
                'labels': {
                    'app': 'blncs',
                    'security-level': policy.level.value
                }
            },
            'spec': {
                'privileged': False,
                'allowPrivilegeEscalation': not policy.no_new_privileges,
                'requiredDropCapabilities': policy.dropped_capabilities,
                'allowedCapabilities': policy.allowed_capabilities,
                'volumes': ['configMap', 'emptyDir', 'projected', 'secret', 'downwardAPI', 'persistentVolumeClaim'],
                'hostNetwork': False,
                'hostIPC': False,
                'hostPID': False,
                'runAsUser': {
                    'rule': 'MustRunAsNonRoot' if policy.run_as_non_root else 'RunAsAny'
                },
                'seLinux': {
                    'rule': 'RunAsAny'
                },
                'supplementalGroups': {
                    'rule': 'RunAsAny'
                },
                'fsGroup': {
                    'rule': 'RunAsAny'
                },
                'readOnlyRootFilesystem': policy.read_only_root_filesystem
            }
        }
        
        if policy.run_as_non_root:
            psp['spec']['runAsUser']['ranges'] = [{
                'min': policy.user_id,
                'max': policy.user_id
            }]
        
        return psp
    
    async def audit_running_containers(self) -> List[Dict[str, Any]]:
        """Audit security of running containers."""
        audit_results = []
        
        if not self.docker_client:
            return audit_results
        
        try:
            containers = self.docker_client.containers.list()
            
            for container in containers:
                result = {
                    'container_id': container.short_id,
                    'container_name': container.name,
                    'image': container.image.tags[0] if container.image.tags else 'unknown',
                    'status': container.status,
                    'issues': []
                }
                
                # Check if running as root
                top_info = container.top()
                if top_info and any(proc[1] == '0' for proc in top_info.get('Processes', [])):
                    result['issues'].append('Running as root user')
                
                # Check capabilities
                inspect_data = container.attrs
                if 'HostConfig' in inspect_data:
                    cap_add = inspect_data['HostConfig'].get('CapAdd', [])
                    if cap_add and 'ALL' in cap_add:
                        result['issues'].append('Running with all capabilities')
                
                # Check privileged mode
                if inspect_data.get('HostConfig', {}).get('Privileged', False):
                    result['issues'].append('Running in privileged mode')
                
                # Check resource limits
                if not inspect_data.get('HostConfig', {}).get('Memory'):
                    result['issues'].append('No memory limit set')
                
                if not inspect_data.get('HostConfig', {}).get('CpuQuota'):
                    result['issues'].append('No CPU limit set')
                
                audit_results.append(result)
                
        except Exception as e:
            logger.error(f"Failed to audit running containers: {e}")
        
        return audit_results

# Global instances
_secrets_manager: Optional[SecretsManager] = None
_container_security_manager: Optional[ContainerSecurityManager] = None

def get_secrets_manager() -> SecretsManager:
    """Get the global secrets manager instance."""
    global _secrets_manager
    
    if _secrets_manager is None:
        _secrets_manager = SecretsManager()
    
    return _secrets_manager

def get_container_security_manager() -> ContainerSecurityManager:
    """Get the global container security manager instance."""
    global _container_security_manager
    
    if _container_security_manager is None:
        _container_security_manager = ContainerSecurityManager()
    
    return _container_security_manager

def initialize_container_security(config: Optional[Dict[str, Any]] = None) -> Tuple[SecretsManager, ContainerSecurityManager]:
    """Initialize container security systems."""
    global _secrets_manager, _container_security_manager
    
    _secrets_manager = SecretsManager(config)
    _container_security_manager = ContainerSecurityManager(config)
    
    # Start auto-rotation
    _secrets_manager.start_auto_rotation()
    
    logger.info("Initialized container security and secrets management")
    return _secrets_manager, _container_security_manager