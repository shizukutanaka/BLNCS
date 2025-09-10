"""
Zero-Touch Deployment and Update System
Fully automated deployment, updates, and rollback capabilities with minimal human intervention.
"""

import asyncio
import json
import logging
import os
import shutil
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from enum import Enum
from dataclasses import dataclass, field
import structlog
from pathlib import Path
import yaml
import hashlib
import tempfile
import tarfile
import zipfile
from urllib.parse import urlparse
import requests
import semantic_version
import docker
import kubernetes

logger = structlog.get_logger(__name__)

class DeploymentStatus(Enum):
    PENDING = "pending"
    DOWNLOADING = "downloading"
    VALIDATING = "validating"
    TESTING = "testing"
    DEPLOYING = "deploying"
    DEPLOYED = "deployed"
    FAILED = "failed"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"

class DeploymentStrategy(Enum):
    BLUE_GREEN = "blue_green"
    ROLLING = "rolling"
    CANARY = "canary"
    RECREATE = "recreate"

class Environment(Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"

@dataclass
class DeploymentConfig:
    name: str
    version: str
    environment: Environment
    strategy: DeploymentStrategy = DeploymentStrategy.ROLLING
    source_url: Optional[str] = None
    source_type: str = "git"  # git, docker, package, archive
    build_commands: List[str] = field(default_factory=list)
    test_commands: List[str] = field(default_factory=list)
    pre_deploy_commands: List[str] = field(default_factory=list)
    post_deploy_commands: List[str] = field(default_factory=list)
    health_check_url: Optional[str] = None
    health_check_timeout: int = 300
    rollback_enabled: bool = True
    backup_before_deploy: bool = True
    auto_approve: bool = False
    notifications: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DeploymentResult:
    deployment_id: str
    config: DeploymentConfig
    status: DeploymentStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    logs: List[str] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)
    rollback_id: Optional[str] = None
    error_message: Optional[str] = None
    metrics: Dict[str, Any] = field(default_factory=dict)

class ZeroTouchDeployment:
    """
    Zero-touch deployment system with automated updates and rollback capabilities.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._default_config()
        self.deployment_history: List[DeploymentResult] = []
        self.active_deployments: Dict[str, DeploymentResult] = {}
        self.environment_states: Dict[str, Dict[str, Any]] = {}
        
        self.version_manager = VersionManager()
        self.artifact_manager = ArtifactManager(self.config)
        self.health_monitor = HealthMonitor()
        self.notification_service = NotificationService()
        self.backup_manager = BackupManager()
        
        # Deployment strategies
        self.strategies = {
            DeploymentStrategy.BLUE_GREEN: BlueGreenDeployment(),
            DeploymentStrategy.ROLLING: RollingDeployment(),
            DeploymentStrategy.CANARY: CanaryDeployment(),
            DeploymentStrategy.RECREATE: RecreateDeployment()
        }
        
        self.stats = {
            'deployments_attempted': 0,
            'deployments_successful': 0,
            'deployments_failed': 0,
            'rollbacks_performed': 0,
            'average_deployment_time': 0,
            'zero_downtime_percentage': 0
        }

    def _default_config(self) -> Dict[str, Any]:
        """Default configuration for zero-touch deployment."""
        return {
            'working_directory': '/tmp/blncs_deployments',
            'artifact_storage': '/var/lib/blncs/artifacts',
            'backup_retention_days': 30,
            'max_concurrent_deployments': 3,
            'default_timeout': 1800,  # 30 minutes
            'auto_rollback_on_failure': True,
            'health_check_retries': 5,
            'health_check_interval': 30,
            'notification_channels': ['email', 'slack'],
            'security_scan_enabled': True,
            'performance_test_enabled': True,
            'approval_required_for_prod': True,
            'kubernetes': {
                'enabled': False,
                'config_path': '~/.kube/config',
                'namespace': 'default'
            },
            'docker': {
                'enabled': True,
                'registry': 'localhost:5000'
            }
        }

    async def deploy(self, config: DeploymentConfig) -> str:
        """Deploy a new version with zero-touch automation."""
        deployment_id = f"deploy-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{config.name}"
        
        result = DeploymentResult(
            deployment_id=deployment_id,
            config=config,
            status=DeploymentStatus.PENDING,
            start_time=datetime.now()
        )
        
        self.active_deployments[deployment_id] = result
        self.stats['deployments_attempted'] += 1
        
        logger.info(f"Starting deployment: {deployment_id}")
        
        try:
            # Execute deployment pipeline
            await self._execute_deployment_pipeline(result)
            
            if result.status == DeploymentStatus.DEPLOYED:
                self.stats['deployments_successful'] += 1
                logger.info(f"Deployment successful: {deployment_id}")
            else:
                self.stats['deployments_failed'] += 1
                logger.error(f"Deployment failed: {deployment_id}")
                
                # Auto rollback if enabled
                if (self.config['auto_rollback_on_failure'] and 
                    result.config.rollback_enabled and 
                    result.status == DeploymentStatus.FAILED):
                    await self.rollback(deployment_id)
            
        except Exception as e:
            result.status = DeploymentStatus.FAILED
            result.error_message = str(e)
            logger.error(f"Deployment error: {deployment_id} - {e}")
            
        finally:
            result.end_time = datetime.now()
            self.deployment_history.append(result)
            if deployment_id in self.active_deployments:
                del self.active_deployments[deployment_id]
        
        return deployment_id

    async def _execute_deployment_pipeline(self, result: DeploymentResult):
        """Execute the complete deployment pipeline."""
        config = result.config
        
        try:
            # Stage 1: Download and validate
            result.status = DeploymentStatus.DOWNLOADING
            await self._download_artifacts(result)
            
            result.status = DeploymentStatus.VALIDATING
            await self._validate_artifacts(result)
            
            # Stage 2: Build and test
            await self._build_application(result)
            
            result.status = DeploymentStatus.TESTING
            await self._run_tests(result)
            
            # Stage 3: Pre-deployment
            if config.backup_before_deploy:
                await self.backup_manager.create_backup(
                    f"pre-deploy-{result.deployment_id}",
                    config.environment.value
                )
            
            await self._run_pre_deploy_commands(result)
            
            # Stage 4: Deploy using selected strategy
            result.status = DeploymentStatus.DEPLOYING
            strategy = self.strategies[config.strategy]
            await strategy.deploy(result)
            
            # Stage 5: Health checks
            await self._perform_health_checks(result)
            
            # Stage 6: Post-deployment
            await self._run_post_deploy_commands(result)
            
            result.status = DeploymentStatus.DEPLOYED
            
        except Exception as e:
            result.status = DeploymentStatus.FAILED
            result.error_message = str(e)
            result.logs.append(f"Pipeline failed: {e}")
            raise

    async def _download_artifacts(self, result: DeploymentResult):
        """Download deployment artifacts."""
        config = result.config
        
        if not config.source_url:
            result.logs.append("No source URL provided, skipping download")
            return
        
        result.logs.append(f"Downloading from: {config.source_url}")
        
        try:
            artifact_path = await self.artifact_manager.download_artifact(
                config.source_url,
                config.source_type,
                result.deployment_id
            )
            
            result.artifacts.append(artifact_path)
            result.logs.append(f"Downloaded to: {artifact_path}")
            
        except Exception as e:
            result.logs.append(f"Download failed: {e}")
            raise

    async def _validate_artifacts(self, result: DeploymentResult):
        """Validate downloaded artifacts."""
        result.logs.append("Validating artifacts")
        
        for artifact_path in result.artifacts:
            # Validate file integrity
            if not Path(artifact_path).exists():
                raise FileNotFoundError(f"Artifact not found: {artifact_path}")
            
            # Security scan if enabled
            if self.config['security_scan_enabled']:
                security_result = await self._security_scan(artifact_path)
                if not security_result:
                    raise SecurityError("Security scan failed")
            
            result.logs.append(f"Artifact validated: {artifact_path}")

    async def _build_application(self, result: DeploymentResult):
        """Build the application if build commands are specified."""
        config = result.config
        
        if not config.build_commands:
            result.logs.append("No build commands specified, skipping build")
            return
        
        result.logs.append("Building application")
        
        for command in config.build_commands:
            result.logs.append(f"Executing build command: {command}")
            
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.config['working_directory']
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                error_msg = f"Build command failed: {command}\nStderr: {stderr.decode()}"
                result.logs.append(error_msg)
                raise BuildError(error_msg)
            
            result.logs.append(f"Build output: {stdout.decode()}")

    async def _run_tests(self, result: DeploymentResult):
        """Run automated tests."""
        config = result.config
        
        if not config.test_commands:
            result.logs.append("No test commands specified, skipping tests")
            return
        
        result.logs.append("Running tests")
        
        for command in config.test_commands:
            result.logs.append(f"Executing test command: {command}")
            
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.config['working_directory']
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                error_msg = f"Test failed: {command}\nStderr: {stderr.decode()}"
                result.logs.append(error_msg)
                raise TestError(error_msg)
            
            result.logs.append(f"Test output: {stdout.decode()}")

    async def _perform_health_checks(self, result: DeploymentResult):
        """Perform health checks after deployment."""
        config = result.config
        
        if not config.health_check_url:
            result.logs.append("No health check URL specified, skipping health checks")
            return
        
        result.logs.append(f"Performing health checks: {config.health_check_url}")
        
        start_time = datetime.now()
        max_time = start_time + timedelta(seconds=config.health_check_timeout)
        
        while datetime.now() < max_time:
            try:
                is_healthy = await self.health_monitor.check_health(config.health_check_url)
                
                if is_healthy:
                    result.logs.append("Health check passed")
                    return
                
                result.logs.append("Health check failed, retrying...")
                await asyncio.sleep(self.config['health_check_interval'])
                
            except Exception as e:
                result.logs.append(f"Health check error: {e}")
                await asyncio.sleep(self.config['health_check_interval'])
        
        raise HealthCheckError("Health checks failed after timeout")

    async def _run_pre_deploy_commands(self, result: DeploymentResult):
        """Run pre-deployment commands."""
        await self._run_command_list(result, result.config.pre_deploy_commands, "pre-deploy")

    async def _run_post_deploy_commands(self, result: DeploymentResult):
        """Run post-deployment commands."""
        await self._run_command_list(result, result.config.post_deploy_commands, "post-deploy")

    async def _run_command_list(self, result: DeploymentResult, commands: List[str], stage: str):
        """Run a list of commands."""
        if not commands:
            result.logs.append(f"No {stage} commands specified")
            return
        
        result.logs.append(f"Running {stage} commands")
        
        for command in commands:
            result.logs.append(f"Executing {stage} command: {command}")
            
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.config['working_directory']
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                error_msg = f"{stage} command failed: {command}\nStderr: {stderr.decode()}"
                result.logs.append(error_msg)
                raise CommandError(error_msg)
            
            result.logs.append(f"{stage} output: {stdout.decode()}")

    async def rollback(self, deployment_id: str) -> str:
        """Rollback a deployment to the previous version."""
        if deployment_id not in [d.deployment_id for d in self.deployment_history]:
            raise ValueError(f"Deployment {deployment_id} not found")
        
        rollback_id = f"rollback-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{deployment_id}"
        
        logger.info(f"Starting rollback: {rollback_id}")
        
        try:
            # Find the deployment to rollback
            deployment = next(d for d in self.deployment_history if d.deployment_id == deployment_id)
            
            # Create rollback result
            rollback_result = DeploymentResult(
                deployment_id=rollback_id,
                config=deployment.config,
                status=DeploymentStatus.ROLLING_BACK,
                start_time=datetime.now()
            )
            
            # Find previous successful deployment
            previous_deployment = self._find_previous_deployment(deployment)
            
            if previous_deployment:
                # Rollback to previous version
                strategy = self.strategies[deployment.config.strategy]
                await strategy.rollback(rollback_result, previous_deployment)
            else:
                # Restore from backup
                await self.backup_manager.restore_backup(
                    f"pre-deploy-{deployment_id}",
                    deployment.config.environment.value
                )
            
            rollback_result.status = DeploymentStatus.ROLLED_BACK
            rollback_result.end_time = datetime.now()
            
            # Update original deployment with rollback info
            deployment.rollback_id = rollback_id
            
            self.deployment_history.append(rollback_result)
            self.stats['rollbacks_performed'] += 1
            
            logger.info(f"Rollback successful: {rollback_id}")
            
        except Exception as e:
            logger.error(f"Rollback failed: {rollback_id} - {e}")
            raise
        
        return rollback_id

    def _find_previous_deployment(self, current_deployment: DeploymentResult) -> Optional[DeploymentResult]:
        """Find the previous successful deployment."""
        for deployment in reversed(self.deployment_history):
            if (deployment.config.name == current_deployment.config.name and
                deployment.config.environment == current_deployment.config.environment and
                deployment.status == DeploymentStatus.DEPLOYED and
                deployment.start_time < current_deployment.start_time):
                return deployment
        return None

    async def _security_scan(self, artifact_path: str) -> bool:
        """Perform security scan on artifacts."""
        logger.info(f"Performing security scan on: {artifact_path}")
        # Placeholder for actual security scanning
        return True

    async def get_deployment_status(self, deployment_id: str) -> Optional[DeploymentResult]:
        """Get the status of a deployment."""
        # Check active deployments first
        if deployment_id in self.active_deployments:
            return self.active_deployments[deployment_id]
        
        # Check deployment history
        for deployment in self.deployment_history:
            if deployment.deployment_id == deployment_id:
                return deployment
        
        return None

    async def list_deployments(self, 
                             environment: Optional[Environment] = None,
                             status: Optional[DeploymentStatus] = None,
                             limit: int = 50) -> List[DeploymentResult]:
        """List deployments with optional filtering."""
        deployments = self.deployment_history.copy()
        
        if environment:
            deployments = [d for d in deployments if d.config.environment == environment]
        
        if status:
            deployments = [d for d in deployments if d.status == status]
        
        # Sort by start time (most recent first)
        deployments.sort(key=lambda d: d.start_time, reverse=True)
        
        return deployments[:limit]

class ArtifactManager:
    """Manage deployment artifacts."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.storage_path = Path(config['artifact_storage'])
        self.storage_path.mkdir(parents=True, exist_ok=True)
    
    async def download_artifact(self, source_url: str, source_type: str, deployment_id: str) -> str:
        """Download artifact from source."""
        parsed_url = urlparse(source_url)
        artifact_dir = self.storage_path / deployment_id
        artifact_dir.mkdir(parents=True, exist_ok=True)
        
        if source_type == 'git':
            return await self._download_git_repo(source_url, artifact_dir)
        elif source_type == 'http':
            return await self._download_http_artifact(source_url, artifact_dir)
        elif source_type == 'docker':
            return await self._download_docker_image(source_url, artifact_dir)
        else:
            raise ValueError(f"Unsupported source type: {source_type}")
    
    async def _download_git_repo(self, repo_url: str, target_dir: Path) -> str:
        """Download Git repository."""
        process = await asyncio.create_subprocess_exec(
            'git', 'clone', repo_url, str(target_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            raise Exception(f"Git clone failed: {stderr.decode()}")
        
        return str(target_dir)
    
    async def _download_http_artifact(self, url: str, target_dir: Path) -> str:
        """Download HTTP artifact."""
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        filename = url.split('/')[-1] or 'artifact'
        artifact_path = target_dir / filename
        
        with open(artifact_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        # Extract if it's an archive
        if artifact_path.suffix in ['.zip', '.tar', '.tar.gz', '.tgz']:
            await self._extract_archive(artifact_path, target_dir)
        
        return str(target_dir)
    
    async def _download_docker_image(self, image_url: str, target_dir: Path) -> str:
        """Download Docker image."""
        # This would integrate with Docker API
        logger.info(f"Downloading Docker image: {image_url}")
        return str(target_dir)
    
    async def _extract_archive(self, archive_path: Path, target_dir: Path):
        """Extract archive file."""
        if archive_path.suffix == '.zip':
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(target_dir)
        elif archive_path.suffix in ['.tar', '.tar.gz', '.tgz']:
            with tarfile.open(archive_path, 'r') as tar_ref:
                tar_ref.extractall(target_dir)

class HealthMonitor:
    """Monitor application health."""
    
    async def check_health(self, health_url: str) -> bool:
        """Check application health."""
        try:
            response = requests.get(health_url, timeout=10)
            return response.status_code == 200
        except Exception:
            return False

class NotificationService:
    """Send deployment notifications."""
    
    async def notify_deployment_started(self, deployment: DeploymentResult):
        """Notify that deployment started."""
        pass
    
    async def notify_deployment_completed(self, deployment: DeploymentResult):
        """Notify that deployment completed."""
        pass
    
    async def notify_deployment_failed(self, deployment: DeploymentResult):
        """Notify that deployment failed."""
        pass

class BackupManager:
    """Manage deployment backups."""
    
    async def create_backup(self, backup_id: str, environment: str) -> str:
        """Create a backup before deployment."""
        logger.info(f"Creating backup: {backup_id} for {environment}")
        return backup_id
    
    async def restore_backup(self, backup_id: str, environment: str):
        """Restore from backup."""
        logger.info(f"Restoring backup: {backup_id} for {environment}")

# Deployment Strategy Implementations

class BlueGreenDeployment:
    """Blue-green deployment strategy."""
    
    async def deploy(self, result: DeploymentResult):
        """Execute blue-green deployment."""
        result.logs.append("Executing blue-green deployment")
        # Implementation would handle blue-green deployment logic
    
    async def rollback(self, result: DeploymentResult, previous_deployment: DeploymentResult):
        """Rollback blue-green deployment."""
        result.logs.append("Rolling back blue-green deployment")

class RollingDeployment:
    """Rolling deployment strategy."""
    
    async def deploy(self, result: DeploymentResult):
        """Execute rolling deployment."""
        result.logs.append("Executing rolling deployment")
        # Implementation would handle rolling deployment logic
    
    async def rollback(self, result: DeploymentResult, previous_deployment: DeploymentResult):
        """Rollback rolling deployment."""
        result.logs.append("Rolling back rolling deployment")

class CanaryDeployment:
    """Canary deployment strategy."""
    
    async def deploy(self, result: DeploymentResult):
        """Execute canary deployment."""
        result.logs.append("Executing canary deployment")
        # Implementation would handle canary deployment logic
    
    async def rollback(self, result: DeploymentResult, previous_deployment: DeploymentResult):
        """Rollback canary deployment."""
        result.logs.append("Rolling back canary deployment")

class RecreateDeployment:
    """Recreate deployment strategy."""
    
    async def deploy(self, result: DeploymentResult):
        """Execute recreate deployment."""
        result.logs.append("Executing recreate deployment")
        # Implementation would handle recreate deployment logic
    
    async def rollback(self, result: DeploymentResult, previous_deployment: DeploymentResult):
        """Rollback recreate deployment."""
        result.logs.append("Rolling back recreate deployment")

class VersionManager:
    """Manage application versions."""
    
    def __init__(self):
        self.versions: Dict[str, str] = {}
    
    def get_current_version(self, app_name: str) -> Optional[str]:
        """Get current deployed version."""
        return self.versions.get(app_name)
    
    def set_version(self, app_name: str, version: str):
        """Set deployed version."""
        self.versions[app_name] = version

# Custom Exceptions
class DeploymentError(Exception):
    """Base deployment error."""
    pass

class BuildError(DeploymentError):
    """Build process error."""
    pass

class TestError(DeploymentError):
    """Test failure error."""
    pass

class HealthCheckError(DeploymentError):
    """Health check failure error."""
    pass

class SecurityError(DeploymentError):
    """Security scan failure error."""
    pass

class CommandError(DeploymentError):
    """Command execution error."""
    pass

# Global deployment system instance
_deployment_system_instance = None

def get_deployment_system(config: Optional[Dict[str, Any]] = None) -> ZeroTouchDeployment:
    """Get the global deployment system instance."""
    global _deployment_system_instance
    if _deployment_system_instance is None:
        _deployment_system_instance = ZeroTouchDeployment(config)
    return _deployment_system_instance

async def initialize_deployment_system(config: Optional[Dict[str, Any]] = None):
    """Initialize the zero-touch deployment system."""
    system = get_deployment_system(config)
    logger.info("Zero-touch deployment system initialized successfully")
    return system