"""
Kubernetes Operator for BLNCS Enterprise Deployment
Production-grade orchestration with service mesh and GitOps integration.
"""

import asyncio
import json
import yaml
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from enum import Enum
from dataclasses import dataclass, asdict
from pathlib import Path
import kubernetes
from kubernetes import client, config, watch
import helm3
import threading
import time
import hashlib

logger = logging.getLogger(__name__)

class RolloutStrategy(Enum):
    BLUE_GREEN = "blue_green"
    CANARY = "canary"  
    ROLLING_UPDATE = "rolling_update"
    RECREATE = "recreate"

class ServiceMesh(Enum):
    ISTIO = "istio"
    LINKERD = "linkerd"
    CONSUL_CONNECT = "consul_connect"
    NONE = "none"

class GitOpsProvider(Enum):
    ARGOCD = "argocd"
    FLUXCD = "fluxcd"
    TEKTON = "tekton"

@dataclass
class HealthCheck:
    path: str
    port: int
    timeout_seconds: int = 30
    period_seconds: int = 10
    failure_threshold: int = 3
    success_threshold: int = 1
    initial_delay_seconds: int = 30

@dataclass 
class ScalingConfig:
    min_replicas: int = 2
    max_replicas: int = 10
    target_cpu_percentage: int = 70
    target_memory_percentage: int = 80
    scale_up_stabilization: int = 60  # seconds
    scale_down_stabilization: int = 300  # seconds

@dataclass
class NetworkPolicy:
    name: str
    namespace: str
    pod_selector: Dict[str, str]
    ingress_rules: List[Dict[str, Any]]
    egress_rules: List[Dict[str, Any]]
    enabled: bool = True

@dataclass
class ResourceQuota:
    cpu_limit: str = "2000m"
    memory_limit: str = "4Gi"
    cpu_request: str = "100m"
    memory_request: str = "256Mi"
    storage_limit: str = "10Gi"

@dataclass
class ServiceMeshConfig:
    provider: ServiceMesh = ServiceMesh.ISTIO
    mtls_enabled: bool = True
    traffic_policy: Dict[str, Any] = None
    destination_rules: List[Dict[str, Any]] = None
    virtual_services: List[Dict[str, Any]] = None
    gateway_config: Dict[str, Any] = None

@dataclass
class GitOpsConfig:
    provider: GitOpsProvider = GitOpsProvider.ARGOCD
    repository_url: str = ""
    branch: str = "main"
    path: str = "k8s"
    sync_policy: Dict[str, Any] = None
    auto_sync: bool = True

@dataclass
class DeploymentSpec:
    name: str
    namespace: str = "blncs"
    image: str = "blncs/blncs:latest"
    version: str = "1.0.0"
    replicas: int = 3
    rollout_strategy: RolloutStrategy = RolloutStrategy.ROLLING_UPDATE
    health_check: HealthCheck = None
    scaling_config: ScalingConfig = None
    resource_quota: ResourceQuota = None
    network_policies: List[NetworkPolicy] = None
    service_mesh: ServiceMeshConfig = None
    gitops: GitOpsConfig = None
    env_vars: Dict[str, str] = None
    secrets: Dict[str, str] = None
    config_maps: Dict[str, str] = None
    persistent_volumes: List[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.health_check is None:
            self.health_check = HealthCheck(path="/health", port=8080)
        if self.scaling_config is None:
            self.scaling_config = ScalingConfig()
        if self.resource_quota is None:
            self.resource_quota = ResourceQuota()
        if self.network_policies is None:
            self.network_policies = []
        if self.service_mesh is None:
            self.service_mesh = ServiceMeshConfig()
        if self.gitops is None:
            self.gitops = GitOpsConfig()
        if self.env_vars is None:
            self.env_vars = {}
        if self.secrets is None:
            self.secrets = {}
        if self.config_maps is None:
            self.config_maps = {}
        if self.persistent_volumes is None:
            self.persistent_volumes = []

@dataclass
class BLNCSResource:
    api_version: str = "blncs.io/v1"
    kind: str = "BLNCS"
    metadata: Dict[str, Any] = None
    spec: DeploymentSpec = None
    status: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {"name": "blncs-deployment", "namespace": "blncs"}
        if self.status is None:
            self.status = {"phase": "Pending", "conditions": []}

class BLNCSOperator:
    def __init__(self, kubeconfig_path: Optional[str] = None):
        self.kubeconfig_path = kubeconfig_path
        self.k8s_client = None
        self.apps_v1 = None
        self.core_v1 = None
        self.networking_v1 = None
        self.autoscaling_v1 = None
        self.custom_objects_api = None
        self.helm_client = None
        self.running = False
        self.watch_thread = None
        self.resources = {}
        
    async def initialize(self):
        """Initialize Kubernetes client and Helm"""
        try:
            if self.kubeconfig_path:
                config.load_kube_config(config_file=self.kubeconfig_path)
            else:
                try:
                    config.load_incluster_config()
                except config.ConfigException:
                    config.load_kube_config()
            
            self.k8s_client = client.ApiClient()
            self.apps_v1 = client.AppsV1Api()
            self.core_v1 = client.CoreV1Api()
            self.networking_v1 = client.NetworkingV1Api()
            self.autoscaling_v1 = client.AutoscalingV1Api()
            self.custom_objects_api = client.CustomObjectsApi()
            
            # Initialize Helm client
            self.helm_client = helm3.Helm3()
            
            logger.info("BLNCS Operator initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize operator: {e}")
            return False
    
    async def start_operator(self):
        """Start the operator main loop"""
        if not await self.initialize():
            raise RuntimeError("Failed to initialize operator")
        
        self.running = True
        self.watch_thread = threading.Thread(target=self._watch_resources)
        self.watch_thread.start()
        
        logger.info("BLNCS Operator started")
    
    async def stop_operator(self):
        """Stop the operator"""
        self.running = False
        if self.watch_thread:
            self.watch_thread.join(timeout=30)
        
        logger.info("BLNCS Operator stopped")
    
    def _watch_resources(self):
        """Watch for BLNCS resource changes"""
        w = watch.Watch()
        
        while self.running:
            try:
                for event in w.stream(
                    self.custom_objects_api.list_cluster_custom_object,
                    group="blncs.io",
                    version="v1",
                    plural="blncs",
                    timeout_seconds=60
                ):
                    if not self.running:
                        break
                    
                    event_type = event['type']
                    resource = event['object']
                    
                    asyncio.run(self._handle_resource_event(event_type, resource))
                    
            except Exception as e:
                logger.error(f"Error watching resources: {e}")
                if self.running:
                    time.sleep(10)  # Wait before retrying
    
    async def _handle_resource_event(self, event_type: str, resource: dict):
        """Handle resource change events"""
        try:
            name = resource['metadata']['name']
            namespace = resource['metadata']['namespace']
            resource_key = f"{namespace}/{name}"
            
            logger.info(f"Handling {event_type} event for {resource_key}")
            
            if event_type == "ADDED":
                await self._handle_resource_added(resource)
            elif event_type == "MODIFIED":
                await self._handle_resource_modified(resource)
            elif event_type == "DELETED":
                await self._handle_resource_deleted(resource)
                
        except Exception as e:
            logger.error(f"Error handling resource event: {e}")
    
    async def _handle_resource_added(self, resource: dict):
        """Handle new BLNCS resource"""
        spec = resource.get('spec', {})
        deployment_spec = self._parse_deployment_spec(spec)
        
        # Deploy BLNCS instance
        success = await self._deploy_blncs(deployment_spec)
        
        # Update resource status
        await self._update_resource_status(
            resource,
            "Running" if success else "Failed",
            f"Deployment {'successful' if success else 'failed'}"
        )
    
    async def _handle_resource_modified(self, resource: dict):
        """Handle BLNCS resource updates"""
        spec = resource.get('spec', {})
        deployment_spec = self._parse_deployment_spec(spec)
        
        # Update BLNCS deployment
        success = await self._update_blncs(deployment_spec)
        
        # Update resource status
        await self._update_resource_status(
            resource,
            "Running" if success else "Failed", 
            f"Update {'successful' if success else 'failed'}"
        )
    
    async def _handle_resource_deleted(self, resource: dict):
        """Handle BLNCS resource deletion"""
        spec = resource.get('spec', {})
        deployment_spec = self._parse_deployment_spec(spec)
        
        # Clean up BLNCS deployment
        await self._cleanup_blncs(deployment_spec)
    
    def _parse_deployment_spec(self, spec: dict) -> DeploymentSpec:
        """Parse Kubernetes resource spec to DeploymentSpec"""
        return DeploymentSpec(
            name=spec.get('name', 'blncs'),
            namespace=spec.get('namespace', 'blncs'),
            image=spec.get('image', 'blncs/blncs:latest'),
            version=spec.get('version', '1.0.0'),
            replicas=spec.get('replicas', 3),
            rollout_strategy=RolloutStrategy(spec.get('rolloutStrategy', 'rolling_update')),
            health_check=HealthCheck(**spec.get('healthCheck', {})),
            scaling_config=ScalingConfig(**spec.get('scalingConfig', {})),
            resource_quota=ResourceQuota(**spec.get('resourceQuota', {})),
            service_mesh=ServiceMeshConfig(**spec.get('serviceMesh', {})),
            gitops=GitOpsConfig(**spec.get('gitops', {})),
            env_vars=spec.get('envVars', {}),
            secrets=spec.get('secrets', {}),
            config_maps=spec.get('configMaps', {}),
            persistent_volumes=spec.get('persistentVolumes', [])
        )
    
    async def _deploy_blncs(self, spec: DeploymentSpec) -> bool:
        """Deploy BLNCS instance using Helm"""
        try:
            # Generate Helm values
            helm_values = self._generate_helm_values(spec)
            
            # Install or upgrade Helm chart
            result = await self._helm_install_upgrade(
                release_name=spec.name,
                namespace=spec.namespace,
                chart_path="charts/blncs",
                values=helm_values
            )
            
            if result:
                # Configure service mesh if enabled
                if spec.service_mesh.provider != ServiceMesh.NONE:
                    await self._configure_service_mesh(spec)
                
                # Apply network policies
                await self._apply_network_policies(spec)
                
                # Configure HPA
                await self._configure_autoscaling(spec)
                
                # Setup GitOps if configured
                if spec.gitops.auto_sync:
                    await self._setup_gitops(spec)
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to deploy BLNCS: {e}")
            return False
    
    async def _update_blncs(self, spec: DeploymentSpec) -> bool:
        """Update existing BLNCS deployment"""
        try:
            # Determine rollout strategy
            if spec.rollout_strategy == RolloutStrategy.BLUE_GREEN:
                return await self._blue_green_update(spec)
            elif spec.rollout_strategy == RolloutStrategy.CANARY:
                return await self._canary_update(spec)
            else:
                return await self._rolling_update(spec)
                
        except Exception as e:
            logger.error(f"Failed to update BLNCS: {e}")
            return False
    
    async def _cleanup_blncs(self, spec: DeploymentSpec):
        """Clean up BLNCS deployment"""
        try:
            # Uninstall Helm release
            await self._helm_uninstall(spec.name, spec.namespace)
            
            # Clean up network policies
            await self._cleanup_network_policies(spec)
            
            # Clean up PVCs if needed
            await self._cleanup_persistent_volumes(spec)
            
            logger.info(f"Cleaned up BLNCS deployment: {spec.name}")
            
        except Exception as e:
            logger.error(f"Failed to cleanup BLNCS: {e}")
    
    def _generate_helm_values(self, spec: DeploymentSpec) -> Dict[str, Any]:
        """Generate Helm values from deployment spec"""
        values = {
            "image": {
                "repository": spec.image.split(':')[0],
                "tag": spec.image.split(':')[1] if ':' in spec.image else spec.version,
                "pullPolicy": "Always"
            },
            "replicaCount": spec.replicas,
            "service": {
                "type": "ClusterIP",
                "port": 8080
            },
            "ingress": {
                "enabled": False
            },
            "resources": {
                "limits": {
                    "cpu": spec.resource_quota.cpu_limit,
                    "memory": spec.resource_quota.memory_limit
                },
                "requests": {
                    "cpu": spec.resource_quota.cpu_request,
                    "memory": spec.resource_quota.memory_request
                }
            },
            "livenessProbe": {
                "httpGet": {
                    "path": spec.health_check.path,
                    "port": spec.health_check.port
                },
                "initialDelaySeconds": spec.health_check.initial_delay_seconds,
                "periodSeconds": spec.health_check.period_seconds,
                "timeoutSeconds": spec.health_check.timeout_seconds,
                "failureThreshold": spec.health_check.failure_threshold
            },
            "readinessProbe": {
                "httpGet": {
                    "path": spec.health_check.path,
                    "port": spec.health_check.port
                },
                "initialDelaySeconds": 5,
                "periodSeconds": spec.health_check.period_seconds,
                "timeoutSeconds": spec.health_check.timeout_seconds,
                "successThreshold": spec.health_check.success_threshold
            },
            "env": spec.env_vars,
            "secrets": spec.secrets,
            "configMaps": spec.config_maps,
            "persistentVolumes": spec.persistent_volumes
        }
        
        return values
    
    async def _helm_install_upgrade(self, release_name: str, namespace: str, 
                                   chart_path: str, values: Dict[str, Any]) -> bool:
        """Install or upgrade Helm chart"""
        try:
            # Create namespace if it doesn't exist
            await self._ensure_namespace(namespace)
            
            # Generate values file
            values_file = f"/tmp/{release_name}-values.yaml"
            with open(values_file, 'w') as f:
                yaml.dump(values, f)
            
            # Check if release exists
            try:
                status = self.helm_client.get_release_status(release_name, namespace)
                # Release exists, upgrade it
                result = self.helm_client.upgrade_release(
                    release_name, chart_path, namespace,
                    values_file=values_file,
                    wait=True,
                    timeout=600
                )
            except:
                # Release doesn't exist, install it
                result = self.helm_client.install_release(
                    release_name, chart_path, namespace,
                    values_file=values_file,
                    wait=True,
                    timeout=600
                )
            
            # Clean up values file
            Path(values_file).unlink(missing_ok=True)
            
            return result is not None
            
        except Exception as e:
            logger.error(f"Helm install/upgrade failed: {e}")
            return False
    
    async def _helm_uninstall(self, release_name: str, namespace: str):
        """Uninstall Helm release"""
        try:
            self.helm_client.uninstall_release(release_name, namespace)
            logger.info(f"Uninstalled Helm release: {release_name}")
        except Exception as e:
            logger.error(f"Helm uninstall failed: {e}")
    
    async def _ensure_namespace(self, namespace: str):
        """Ensure namespace exists"""
        try:
            self.core_v1.read_namespace(namespace)
        except client.ApiException as e:
            if e.status == 404:
                # Namespace doesn't exist, create it
                namespace_obj = client.V1Namespace(
                    metadata=client.V1ObjectMeta(name=namespace)
                )
                self.core_v1.create_namespace(namespace_obj)
                logger.info(f"Created namespace: {namespace}")
    
    async def _configure_service_mesh(self, spec: DeploymentSpec):
        """Configure service mesh for deployment"""
        if spec.service_mesh.provider == ServiceMesh.ISTIO:
            await self._configure_istio(spec)
        elif spec.service_mesh.provider == ServiceMesh.LINKERD:
            await self._configure_linkerd(spec)
    
    async def _configure_istio(self, spec: DeploymentSpec):
        """Configure Istio service mesh"""
        try:
            # Enable sidecar injection
            namespace_patch = {
                "metadata": {
                    "labels": {
                        "istio-injection": "enabled"
                    }
                }
            }
            self.core_v1.patch_namespace(spec.namespace, namespace_patch)
            
            # Apply destination rules if provided
            if spec.service_mesh.destination_rules:
                for dr in spec.service_mesh.destination_rules:
                    await self._apply_istio_resource("DestinationRule", dr, spec.namespace)
            
            # Apply virtual services if provided
            if spec.service_mesh.virtual_services:
                for vs in spec.service_mesh.virtual_services:
                    await self._apply_istio_resource("VirtualService", vs, spec.namespace)
            
            logger.info(f"Configured Istio for {spec.name}")
            
        except Exception as e:
            logger.error(f"Failed to configure Istio: {e}")
    
    async def _apply_istio_resource(self, kind: str, resource: Dict[str, Any], namespace: str):
        """Apply Istio custom resource"""
        try:
            self.custom_objects_api.create_namespaced_custom_object(
                group="networking.istio.io",
                version="v1beta1",
                namespace=namespace,
                plural=kind.lower() + "s",
                body=resource
            )
        except client.ApiException as e:
            if e.status == 409:  # Already exists
                self.custom_objects_api.patch_namespaced_custom_object(
                    group="networking.istio.io",
                    version="v1beta1",
                    namespace=namespace,
                    plural=kind.lower() + "s",
                    name=resource['metadata']['name'],
                    body=resource
                )
    
    async def _apply_network_policies(self, spec: DeploymentSpec):
        """Apply network policies"""
        for policy in spec.network_policies:
            if policy.enabled:
                await self._apply_network_policy(policy)
    
    async def _apply_network_policy(self, policy: NetworkPolicy):
        """Apply single network policy"""
        try:
            network_policy = client.V1NetworkPolicy(
                metadata=client.V1ObjectMeta(
                    name=policy.name,
                    namespace=policy.namespace
                ),
                spec=client.V1NetworkPolicySpec(
                    pod_selector=client.V1LabelSelector(
                        match_labels=policy.pod_selector
                    ),
                    ingress=[client.V1NetworkPolicyIngressRule(**rule) for rule in policy.ingress_rules],
                    egress=[client.V1NetworkPolicyEgressRule(**rule) for rule in policy.egress_rules]
                )
            )
            
            try:
                self.networking_v1.create_namespaced_network_policy(
                    policy.namespace, network_policy
                )
            except client.ApiException as e:
                if e.status == 409:  # Already exists
                    self.networking_v1.patch_namespaced_network_policy(
                        policy.name, policy.namespace, network_policy
                    )
            
            logger.info(f"Applied network policy: {policy.name}")
            
        except Exception as e:
            logger.error(f"Failed to apply network policy {policy.name}: {e}")
    
    async def _configure_autoscaling(self, spec: DeploymentSpec):
        """Configure horizontal pod autoscaler"""
        try:
            hpa = client.V1HorizontalPodAutoscaler(
                metadata=client.V1ObjectMeta(
                    name=f"{spec.name}-hpa",
                    namespace=spec.namespace
                ),
                spec=client.V1HorizontalPodAutoscalerSpec(
                    scale_target_ref=client.V1CrossVersionObjectReference(
                        api_version="apps/v1",
                        kind="Deployment",
                        name=spec.name
                    ),
                    min_replicas=spec.scaling_config.min_replicas,
                    max_replicas=spec.scaling_config.max_replicas,
                    target_cpu_utilization_percentage=spec.scaling_config.target_cpu_percentage
                )
            )
            
            try:
                self.autoscaling_v1.create_namespaced_horizontal_pod_autoscaler(
                    spec.namespace, hpa
                )
            except client.ApiException as e:
                if e.status == 409:  # Already exists
                    self.autoscaling_v1.patch_namespaced_horizontal_pod_autoscaler(
                        f"{spec.name}-hpa", spec.namespace, hpa
                    )
            
            logger.info(f"Configured HPA for {spec.name}")
            
        except Exception as e:
            logger.error(f"Failed to configure HPA: {e}")
    
    async def _blue_green_update(self, spec: DeploymentSpec) -> bool:
        """Perform blue-green deployment"""
        try:
            # Create green deployment
            green_name = f"{spec.name}-green"
            green_spec = spec
            green_spec.name = green_name
            
            # Deploy green version
            if not await self._deploy_blncs(green_spec):
                return False
            
            # Wait for green deployment to be ready
            await self._wait_for_deployment_ready(green_name, spec.namespace)
            
            # Switch service to green
            await self._switch_service_to_deployment(spec.name, green_name, spec.namespace)
            
            # Clean up blue deployment
            await self._cleanup_deployment(spec.name, spec.namespace)
            
            # Rename green to blue
            await self._rename_deployment(green_name, spec.name, spec.namespace)
            
            return True
            
        except Exception as e:
            logger.error(f"Blue-green update failed: {e}")
            return False
    
    async def _canary_update(self, spec: DeploymentSpec) -> bool:
        """Perform canary deployment"""
        try:
            # Create canary deployment with 10% traffic
            canary_name = f"{spec.name}-canary"
            canary_spec = spec
            canary_spec.name = canary_name
            canary_spec.replicas = max(1, spec.replicas // 10)
            
            # Deploy canary version
            if not await self._deploy_blncs(canary_spec):
                return False
            
            # Wait for canary to be ready
            await self._wait_for_deployment_ready(canary_name, spec.namespace)
            
            # Monitor canary for 5 minutes
            canary_healthy = await self._monitor_canary(canary_name, spec.namespace, 300)
            
            if canary_healthy:
                # Gradually increase canary traffic
                for traffic_percent in [25, 50, 75, 100]:
                    await self._adjust_canary_traffic(
                        spec.name, canary_name, spec.namespace, traffic_percent
                    )
                    await asyncio.sleep(60)  # Wait 1 minute between increases
                
                # Promote canary to production
                await self._promote_canary(spec.name, canary_name, spec.namespace)
                return True
            else:
                # Rollback canary
                await self._cleanup_deployment(canary_name, spec.namespace)
                return False
                
        except Exception as e:
            logger.error(f"Canary update failed: {e}")
            return False
    
    async def _rolling_update(self, spec: DeploymentSpec) -> bool:
        """Perform rolling update"""
        try:
            # Update deployment with new image/config
            return await self._deploy_blncs(spec)
            
        except Exception as e:
            logger.error(f"Rolling update failed: {e}")
            return False
    
    async def _update_resource_status(self, resource: dict, phase: str, message: str):
        """Update BLNCS resource status"""
        try:
            name = resource['metadata']['name']
            namespace = resource['metadata']['namespace']
            
            status_patch = {
                "status": {
                    "phase": phase,
                    "message": message,
                    "lastUpdateTime": datetime.utcnow().isoformat() + "Z"
                }
            }
            
            self.custom_objects_api.patch_namespaced_custom_object_status(
                group="blncs.io",
                version="v1",
                namespace=namespace,
                plural="blncs",
                name=name,
                body=status_patch
            )
            
        except Exception as e:
            logger.error(f"Failed to update resource status: {e}")

# Global operator instance
_operator_instance = None

async def get_k8s_operator(kubeconfig_path: Optional[str] = None) -> BLNCSOperator:
    """Get or create BLNCS Kubernetes operator"""
    global _operator_instance
    
    if _operator_instance is None:
        _operator_instance = BLNCSOperator(kubeconfig_path)
        await _operator_instance.start_operator()
    
    return _operator_instance

async def create_blncs_deployment(spec: DeploymentSpec) -> bool:
    """Create BLNCS deployment using operator"""
    operator = await get_k8s_operator()
    return await operator._deploy_blncs(spec)