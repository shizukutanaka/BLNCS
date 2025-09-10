"""
BLNCS Automation System
Maximum automation and labor-saving features for complete system autonomy.
"""

from .intelligent_orchestrator import (
    IntelligentOrchestrator,
    AutomationTask,
    AutomationType,
    Priority,
    ExecutionMode,
    get_orchestrator,
    initialize_automation_system
)

from .resource_optimizer import (
    ResourceOptimizer,
    ResourceMetrics,
    ScalingRecommendation,
    ResourceType,
    ScalingDirection,
    OptimizationStrategy,
    get_resource_optimizer,
    initialize_resource_optimization
)

from .self_healing import (
    SelfHealingSystem,
    HealthCheck,
    HealthResult,
    HealthStatus,
    MaintenanceTask,
    MaintenanceType,
    RecoveryAction,
    get_self_healing_system,
    initialize_self_healing_system
)

from .zero_touch_deployment import (
    ZeroTouchDeployment,
    DeploymentConfig,
    DeploymentResult,
    DeploymentStatus,
    DeploymentStrategy,
    Environment,
    get_deployment_system,
    initialize_deployment_system
)

__all__ = [
    # Intelligent Orchestrator
    "IntelligentOrchestrator",
    "AutomationTask",
    "AutomationType",
    "Priority",
    "ExecutionMode",
    "get_orchestrator",
    "initialize_automation_system",
    
    # Resource Optimizer
    "ResourceOptimizer",
    "ResourceMetrics",
    "ScalingRecommendation",
    "ResourceType",
    "ScalingDirection",
    "OptimizationStrategy",
    "get_resource_optimizer",
    "initialize_resource_optimization",
    
    # Self-Healing System
    "SelfHealingSystem",
    "HealthCheck",
    "HealthResult",
    "HealthStatus",
    "MaintenanceTask",
    "MaintenanceType",
    "RecoveryAction",
    "get_self_healing_system",
    "initialize_self_healing_system",
    
    # Zero-Touch Deployment
    "ZeroTouchDeployment",
    "DeploymentConfig",
    "DeploymentResult",
    "DeploymentStatus",
    "DeploymentStrategy",
    "Environment",
    "get_deployment_system",
    "initialize_deployment_system"
]