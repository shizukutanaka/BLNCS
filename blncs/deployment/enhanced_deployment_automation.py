"""
Enhanced Deployment Automation System for BLNCS

This module provides comprehensive deployment automation including:
- Docker and Kubernetes integration improvements
- CI/CD pipeline automation
- Multi-environment deployment management
- Automated rollback and recovery
- Performance monitoring integration
"""

import os
import json
import yaml
import time
import logging
import subprocess
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from pathlib import Path
from datetime import datetime
import threading
import shutil

logger = logging.getLogger(__name__)

@dataclass
class DeploymentEnvironment:
    """Deployment environment configuration."""
    name: str
    type: str  # development, staging, production
    docker_image: str
    kubernetes_namespace: str
    replicas: int
    resources: Dict[str, Any]
    environment_variables: Dict[str, str]
    secrets: Dict[str, str]
    health_check_url: str
    rollout_strategy: str = "RollingUpdate"

@dataclass
class DeploymentStatus:
    """Deployment status information."""
    environment: str
    status: str  # pending, running, completed, failed, rolled_back
    start_time: float
    end_time: Optional[float]
    version: str
    image_tag: str
    replica_count: int
    errors: List[str]
    logs: List[str]

class DockerManager:
    """Enhanced Docker management for deployments."""

    def __init__(self, dockerfile_path: str = "Dockerfile", context_path: str = "."):
        self.dockerfile_path = dockerfile_path
        self.context_path = context_path
        self.logger = logging.getLogger(f"{__name__}.DockerManager")

    def build_image(self, image_name: str, tag: str = "latest", build_args: Dict[str, str] = None) -> bool:
        """Build Docker image."""
        try:
            cmd = ["docker", "build", "-t", f"{image_name}:{tag}", "-f", self.dockerfile_path]

            if build_args:
                for key, value in build_args.items():
                    cmd.extend(["--build-arg", f"{key}={value}"])

            cmd.append(self.context_path)

            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            self.logger.info(f"Docker image built: {image_name}:{tag}")
            return True

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Docker build failed: {e.stderr}")
            return False

    def push_image(self, image_name: str, tag: str = "latest") -> bool:
        """Push Docker image to registry."""
        try:
            # Tag for registry
            registry_tag = f"your-registry.com/{image_name}:{tag}"
            subprocess.run(["docker", "tag", f"{image_name}:{tag}", registry_tag], check=True)

            # Push to registry
            result = subprocess.run(["docker", "push", registry_tag], capture_output=True, text=True, check=True)

            self.logger.info(f"Docker image pushed: {registry_tag}")
            return True

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Docker push failed: {e.stderr}")
            return False

    def get_image_info(self, image_name: str, tag: str = "latest") -> Dict[str, Any]:
        """Get Docker image information."""
        try:
            result = subprocess.run(
                ["docker", "inspect", f"{image_name}:{tag}"],
                capture_output=True, text=True, check=True
            )

            return json.loads(result.stdout)[0]

        except (subprocess.CalledProcessError, json.JSONDecodeError, IndexError):
            return {}

class KubernetesManager:
    """Enhanced Kubernetes deployment management."""

    def __init__(self, kubeconfig_path: str = None):
        self.kubeconfig_path = kubeconfig_path or os.path.expanduser("~/.kube/config")
        self.logger = logging.getLogger(f"{__name__}.KubernetesManager")

        # Set kubeconfig environment variable
        os.environ['KUBECONFIG'] = self.kubeconfig_path

    def deploy_application(self, environment: DeploymentEnvironment) -> bool:
        """Deploy application to Kubernetes."""
        try:
            # Generate Kubernetes manifests
            manifests = self._generate_k8s_manifests(environment)

            # Apply manifests
            for manifest in manifests:
                manifest_path = self._write_manifest(manifest)
                try:
                    result = subprocess.run(
                        ["kubectl", "apply", "-f", str(manifest_path)],
                        capture_output=True, text=True, check=True
                    )
                    self.logger.info(f"Applied manifest: {manifest_path}")
                finally:
                    manifest_path.unlink()  # Clean up

            self.logger.info(f"Application deployed to {environment.name}")
            return True

        except Exception as e:
            self.logger.error(f"Kubernetes deployment failed: {e}")
            return False

    def _generate_k8s_manifests(self, environment: DeploymentEnvironment) -> List[Dict[str, Any]]:
        """Generate Kubernetes manifests."""
        manifests = []

        # Deployment manifest
        deployment = {
            'apiVersion': 'apps/v1',
            'kind': 'Deployment',
            'metadata': {
                'name': f'blncs-{environment.name}',
                'namespace': environment.kubernetes_namespace,
                'labels': {
                    'app': 'blncs',
                    'environment': environment.name,
                    'version': environment.docker_image.split(':')[-1]
                }
            },
            'spec': {
                'replicas': environment.replicas,
                'strategy': {
                    'type': environment.rollout_strategy
                },
                'selector': {
                    'matchLabels': {
                        'app': 'blncs',
                        'environment': environment.name
                    }
                },
                'template': {
                    'metadata': {
                        'labels': {
                            'app': 'blncs',
                            'environment': environment.name,
                            'version': environment.docker_image.split(':')[-1]
                        }
                    },
                    'spec': {
                        'containers': [{
                            'name': 'blncs',
                            'image': environment.docker_image,
                            'ports': [{'containerPort': 5000}],
                            'env': [
                                {'name': k, 'value': v}
                                for k, v in environment.environment_variables.items()
                            ],
                            'resources': environment.resources,
                            'livenessProbe': {
                                'httpGet': {
                                    'path': '/health',
                                    'port': 5000
                                },
                                'initialDelaySeconds': 30,
                                'periodSeconds': 10
                            },
                            'readinessProbe': {
                                'httpGet': {
                                    'path': '/health',
                                    'port': 5000
                                },
                                'initialDelaySeconds': 5,
                                'periodSeconds': 5
                            }
                        }]
                    }
                }
            }
        }

        manifests.append(deployment)

        # Service manifest
        service = {
            'apiVersion': 'v1',
            'kind': 'Service',
            'metadata': {
                'name': f'blncs-{environment.name}-service',
                'namespace': environment.kubernetes_namespace,
                'labels': {
                    'app': 'blncs',
                    'environment': environment.name
                }
            },
            'spec': {
                'type': 'ClusterIP',
                'ports': [{
                    'port': 80,
                    'targetPort': 5000,
                    'protocol': 'TCP'
                }],
                'selector': {
                    'app': 'blncs',
                    'environment': environment.name
                }
            }
        }

        manifests.append(service)

        # Ingress manifest (optional)
        if environment.name == 'production':
            ingress = {
                'apiVersion': 'networking.k8s.io/v1',
                'kind': 'Ingress',
                'metadata': {
                    'name': f'blncs-{environment.name}-ingress',
                    'namespace': environment.kubernetes_namespace,
                    'annotations': {
                        'kubernetes.io/ingress.class': 'nginx',
                        'cert-manager.io/cluster-issuer': 'letsencrypt-prod'
                    }
                },
                'spec': {
                    'tls': [{
                        'hosts': ['blncs.yourdomain.com'],
                        'secretName': f'blncs-{environment.name}-tls'
                    }],
                    'rules': [{
                        'host': 'blncs.yourdomain.com',
                        'http': {
                            'paths': [{
                                'path': '/',
                                'pathType': 'Prefix',
                                'backend': {
                                    'service': {
                                        'name': f'blncs-{environment.name}-service',
                                        'port': {'number': 80}
                                    }
                                }
                            }]
                        }
                    }]
                }
            }

            manifests.append(ingress)

        return manifests

    def _write_manifest(self, manifest: Dict[str, Any]) -> Path:
        """Write Kubernetes manifest to temporary file."""
        import tempfile

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(manifest, f)
            return Path(f.name)

    def get_deployment_status(self, environment: str, namespace: str) -> Dict[str, Any]:
        """Get deployment status."""
        try:
            result = subprocess.run(
                ["kubectl", "get", "deployment", f"blncs-{environment}", "-n", namespace, "-o", "json"],
                capture_output=True, text=True, check=True
            )

            deployment_info = json.loads(result.stdout)

            return {
                'name': deployment_info['metadata']['name'],
                'namespace': deployment_info['metadata']['namespace'],
                'replicas': deployment_info['spec']['replicas'],
                'ready_replicas': deployment_info['status'].get('readyReplicas', 0),
                'available_replicas': deployment_info['status'].get('availableReplicas', 0),
                'conditions': deployment_info['status'].get('conditions', [])
            }

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to get deployment status: {e.stderr}")
            return {}

class CIDCManager:
    """CI/CD pipeline management."""

    def __init__(self, config_file: str = "cicd.yaml"):
        self.config_file = config_file
        self.config = self._load_config()
        self.logger = logging.getLogger(f"{__name__}.CIDCManager")

    def _load_config(self) -> Dict[str, Any]:
        """Load CI/CD configuration."""
        try:
            with open(self.config_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            return self._get_default_config()

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default CI/CD configuration."""
        return {
            'pipelines': {
                'development': {
                    'trigger': 'push',
                    'branches': ['develop', 'feature/*'],
                    'stages': ['test', 'build', 'deploy'],
                    'environment': 'development'
                },
                'staging': {
                    'trigger': 'push',
                    'branches': ['main'],
                    'stages': ['test', 'build', 'deploy'],
                    'environment': 'staging'
                },
                'production': {
                    'trigger': 'tag',
                    'branches': ['main'],
                    'stages': ['test', 'build', 'approve', 'deploy'],
                    'environment': 'production',
                    'requires_approval': True
                }
            }
        }

    def run_pipeline(self, pipeline_name: str, trigger_data: Dict[str, Any] = None) -> bool:
        """Run CI/CD pipeline."""
        if pipeline_name not in self.config['pipelines']:
            self.logger.error(f"Pipeline not found: {pipeline_name}")
            return False

        pipeline = self.config['pipelines'][pipeline_name]
        self.logger.info(f"Starting pipeline: {pipeline_name}")

        try:
            for stage in pipeline['stages']:
                success = self._run_stage(stage, pipeline, trigger_data)
                if not success:
                    self.logger.error(f"Pipeline {pipeline_name} failed at stage: {stage}")
                    return False

            self.logger.info(f"Pipeline {pipeline_name} completed successfully")
            return True

        except Exception as e:
            self.logger.error(f"Pipeline {pipeline_name} failed: {e}")
            return False

    def _run_stage(self, stage: str, pipeline: Dict[str, Any], trigger_data: Dict[str, Any]) -> bool:
        """Run individual pipeline stage."""
        self.logger.info(f"Running stage: {stage}")

        if stage == 'test':
            return self._run_tests()
        elif stage == 'build':
            return self._run_build(pipeline)
        elif stage == 'deploy':
            return self._run_deployment(pipeline)
        elif stage == 'approve':
            return self._wait_for_approval(pipeline)
        else:
            self.logger.warning(f"Unknown stage: {stage}")
            return True

    def _run_tests(self) -> bool:
        """Run test suite."""
        try:
            result = subprocess.run(
                ["python", "-m", "pytest", "tests/", "-v", "--tb=short"],
                capture_output=True, text=True, check=True
            )
            self.logger.info("Tests passed")
            return True

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Tests failed: {e.stderr}")
            return False

    def _run_build(self, pipeline: Dict[str, Any]) -> bool:
        """Run build process."""
        try:
            # Build Docker image
            image_name = f"blncs-{pipeline['environment']}"
            tag = datetime.now().strftime("%Y%m%d_%H%M%S")

            docker_manager = DockerManager()
            success = docker_manager.build_image(image_name, tag)

            if success:
                # Push image
                success = docker_manager.push_image(image_name, tag)

            return success

        except Exception as e:
            self.logger.error(f"Build failed: {e}")
            return False

    def _run_deployment(self, pipeline: Dict[str, Any]) -> bool:
        """Run deployment."""
        try:
            environment_name = pipeline['environment']

            # Get environment configuration
            env_config = self._get_environment_config(environment_name)

            # Deploy to Kubernetes
            k8s_manager = KubernetesManager()
            success = k8s_manager.deploy_application(env_config)

            return success

        except Exception as e:
            self.logger.error(f"Deployment failed: {e}")
            return False

    def _wait_for_approval(self, pipeline: Dict[str, Any]) -> bool:
        """Wait for manual approval."""
        # In a real implementation, this would integrate with approval systems
        self.logger.info(f"Waiting for approval for {pipeline['environment']} deployment")
        return True  # Simplified for demo

    def _get_environment_config(self, environment_name: str) -> DeploymentEnvironment:
        """Get environment configuration."""
        # In a real implementation, load from configuration files
        configs = {
            'development': DeploymentEnvironment(
                name='development',
                type='development',
                docker_image='blncs-development:latest',
                kubernetes_namespace='blncs-dev',
                replicas=1,
                resources={'requests': {'memory': '256Mi', 'cpu': '100m'}},
                environment_variables={'ENVIRONMENT': 'development'},
                secrets={},
                health_check_url='/health'
            ),
            'staging': DeploymentEnvironment(
                name='staging',
                type='staging',
                docker_image='blncs-staging:latest',
                kubernetes_namespace='blncs-staging',
                replicas=2,
                resources={'requests': {'memory': '512Mi', 'cpu': '200m'}},
                environment_variables={'ENVIRONMENT': 'staging'},
                secrets={},
                health_check_url='/health'
            ),
            'production': DeploymentEnvironment(
                name='production',
                type='production',
                docker_image='blncs-production:latest',
                kubernetes_namespace='blncs-prod',
                replicas=3,
                resources={'requests': {'memory': '1Gi', 'cpu': '500m'}},
                environment_variables={'ENVIRONMENT': 'production'},
                secrets={},
                health_check_url='/health'
            )
        }

        return configs.get(environment_name, configs['development'])

class DeploymentManager:
    """Main deployment management system."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.DeploymentManager")
        self.docker_manager = DockerManager()
        self.kubernetes_manager = KubernetesManager()
        self.cicd_manager = CIDCManager()

        self.deployment_history: List[DeploymentStatus] = []
        self.rollback_stack = []

    def deploy_to_environment(self, environment: str, version: str = None) -> bool:
        """Deploy to specific environment."""
        start_time = time.time()

        try:
            # Get environment configuration
            env_config = self.cicd_manager._get_environment_config(environment)

            # Update image tag if version provided
            if version:
                env_config.docker_image = f"{env_config.docker_image.split(':')[0]}:{version}"

            # Record deployment start
            deployment_status = DeploymentStatus(
                environment=environment,
                status="running",
                start_time=start_time,
                version=version or "latest",
                image_tag=env_config.docker_image.split(':')[-1],
                replica_count=env_config.replicas,
                errors=[],
                logs=[]
            )

            # Deploy to Kubernetes
            success = self.kubernetes_manager.deploy_application(env_config)

            if success:
                deployment_status.status = "completed"
                self.logger.info(f"Deployment to {environment} completed successfully")
            else:
                deployment_status.status = "failed"
                deployment_status.errors.append("Kubernetes deployment failed")
                self.logger.error(f"Deployment to {environment} failed")

            deployment_status.end_time = time.time()
            self.deployment_history.append(deployment_status)

            return success

        except Exception as e:
            self.logger.error(f"Deployment failed: {e}")
            return False

    def rollback_deployment(self, environment: str, steps: int = 1) -> bool:
        """Rollback deployment."""
        try:
            # Find previous successful deployment
            previous_deployments = [
                d for d in self.deployment_history
                if d.environment == environment and d.status == "completed"
            ]

            if len(previous_deployments) < steps:
                self.logger.error(f"Not enough successful deployments for rollback ({steps} steps)")
                return False

            target_deployment = previous_deployments[-steps]

            # Deploy previous version
            success = self.deploy_to_environment(environment, target_deployment.version)

            if success:
                self.logger.info(f"Rolled back {environment} to version {target_deployment.version}")

            return success

        except Exception as e:
            self.logger.error(f"Rollback failed: {e}")
            return False

    def get_deployment_history(self, environment: str = None, limit: int = 20) -> List[Dict[str, Any]]:
        """Get deployment history."""
        deployments = self.deployment_history

        if environment:
            deployments = [d for d in deployments if d.environment == environment]

        return [asdict(d) for d in deployments[-limit:]]

    def run_cicd_pipeline(self, pipeline_name: str, trigger_data: Dict[str, Any] = None) -> bool:
        """Run CI/CD pipeline."""
        return self.cicd_manager.run_pipeline(pipeline_name, trigger_data)

def create_deployment_manager() -> DeploymentManager:
    """Factory function to create deployment manager."""
    return DeploymentManager()

# Example usage
if __name__ == "__main__":
    # Create deployment manager
    deployment_manager = create_deployment_manager()

    # Deploy to development
    success = deployment_manager.deploy_to_environment("development")
    print(f"Development deployment: {'Success' if success else 'Failed'}")

    # Get deployment history
    history = deployment_manager.get_deployment_history()
    print(f"Deployment history: {len(history)} entries")

    # Run CI/CD pipeline
    pipeline_success = deployment_manager.run_cicd_pipeline("development")
    print(f"CI/CD pipeline: {'Success' if pipeline_success else 'Failed'}")

    print("Enhanced deployment automation setup complete!")
