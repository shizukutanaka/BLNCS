"""
Lightweight Deployment Utilities
Practical deployment helpers for BLNCS production systems.
"""

import os
import sys
import time
import json
import subprocess
import signal
from typing import Dict, Any, List, Optional, Union
from pathlib import Path
from dataclasses import dataclass, field
from contextlib import contextmanager

from ..core.logger import get_logger
from ..core.config_manager import get_config_manager
from ..core.health_check import get_health_checker

logger = get_logger(__name__)

@dataclass
class DeploymentConfig:
    """Deployment configuration."""
    service_name: str = "blncs"
    port: int = 8000
    workers: int = 1
    timeout: int = 30
    log_level: str = "INFO"
    max_requests: int = 1000
    max_requests_jitter: int = 100
    preload_app: bool = True
    environment: str = "production"

class DeploymentManager:
    """Manages BLNCS deployment operations."""
    
    def __init__(self, config: Optional[DeploymentConfig] = None):
        """Initialize deployment manager."""
        self.logger = get_logger(__name__)
        self.config_manager = get_config_manager()
        self.health_checker = get_health_checker()
        self.deployment_config = config or DeploymentConfig()
        
        # Set up signal handlers for graceful shutdown
        self.shutdown_requested = False
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        self.logger.info(f"Received signal {signum}, initiating graceful shutdown")
        self.shutdown_requested = True
    
    def validate_environment(self) -> Dict[str, Any]:
        """Validate deployment environment."""
        checks = {}
        
        # Check Python version
        python_version = sys.version_info
        checks["python_version"] = {
            "value": f"{python_version.major}.{python_version.minor}.{python_version.micro}",
            "valid": python_version >= (3, 8),
            "required": ">=3.8"
        }
        
        # Check required environment variables
        required_env_vars = ["BLNCS_ENV", "BLNCS_LOG_LEVEL"]
        env_checks = {}
        for var in required_env_vars:
            env_checks[var] = {
                "value": os.getenv(var),
                "valid": os.getenv(var) is not None
            }
        checks["environment_variables"] = env_checks
        
        # Check system resources
        health_summary = self.health_checker.get_health_summary()
        checks["system_health"] = {
            "status": health_summary["overall_status"],
            "valid": health_summary["overall_status"] in ["healthy", "warning"]
        }
        
        # Check disk space for logs and data
        try:
            import shutil
            total, used, free = shutil.disk_usage("/")
            free_gb = free // (1024**3)
            checks["disk_space"] = {
                "free_gb": free_gb,
                "valid": free_gb > 1  # At least 1GB free
            }
        except Exception as e:
            checks["disk_space"] = {
                "error": str(e),
                "valid": False
            }
        
        return checks
    
    def create_systemd_service(self, install_path: str = "/etc/systemd/system") -> str:
        """Create systemd service file."""
        service_content = f"""[Unit]
Description=BLNCS - Bitcoin Lightning Network Control System
After=network.target
Wants=network.target

[Service]
Type=exec
User=blncs
Group=blncs
WorkingDirectory=/opt/blncs
ExecStart=/opt/blncs/.venv/bin/python -m blncs.cli.main daemon
ExecReload=/bin/kill -HUP $MAINPID
KillMode=mixed
Restart=always
RestartSec=10

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/blncs/data /opt/blncs/logs /var/log/blncs

# Resource limits
LimitNOFILE=65536
MemoryLimit=1G

# Environment
Environment=BLNCS_ENV={self.deployment_config.environment}
Environment=BLNCS_LOG_LEVEL={self.deployment_config.log_level}
Environment=PYTHONPATH=/opt/blncs

[Install]
WantedBy=multi-user.target
"""
        
        service_file = Path(install_path) / f"{self.deployment_config.service_name}.service"
        
        try:
            with open(service_file, 'w') as f:
                f.write(service_content)
            
            self.logger.info(f"Created systemd service file: {service_file}")
            return str(service_file)
            
        except Exception as e:
            self.logger.error(f"Failed to create systemd service file: {e}")
            raise
    
    def create_docker_config(self) -> str:
        """Create Docker configuration."""
        dockerfile_content = """FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    curl \\
    ca-certificates \\
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install BLNCS
RUN pip install -e .

# Create non-root user
RUN useradd -m -u 1000 blncs && chown -R blncs:blncs /app
USER blncs

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \\
    CMD python -c "from blncs.core.health_check import readiness_probe; exit(0 if readiness_probe() else 1)"

# Run the application
CMD ["python", "-m", "blncs.cli.main", "daemon"]
"""
        
        try:
            with open("Dockerfile", 'w') as f:
                f.write(dockerfile_content)
            
            self.logger.info("Created Dockerfile")
            return "Dockerfile"
            
        except Exception as e:
            self.logger.error(f"Failed to create Dockerfile: {e}")
            raise
    
    def create_k8s_manifests(self) -> Dict[str, str]:
        """Create Kubernetes manifests."""
        
        # Deployment manifest
        deployment_yaml = f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: blncs
  labels:
    app: blncs
spec:
  replicas: {self.deployment_config.workers}
  selector:
    matchLabels:
      app: blncs
  template:
    metadata:
      labels:
        app: blncs
    spec:
      containers:
      - name: blncs
        image: blncs:latest
        ports:
        - containerPort: {self.deployment_config.port}
        env:
        - name: BLNCS_ENV
          value: "{self.deployment_config.environment}"
        - name: BLNCS_LOG_LEVEL
          value: "{self.deployment_config.log_level}"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: {self.deployment_config.port}
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: {self.deployment_config.port}
          initialDelaySeconds: 10
          periodSeconds: 5
"""
        
        # Service manifest
        service_yaml = f"""apiVersion: v1
kind: Service
metadata:
  name: blncs-service
  labels:
    app: blncs
spec:
  type: ClusterIP
  ports:
  - port: 80
    targetPort: {self.deployment_config.port}
    protocol: TCP
  selector:
    app: blncs
"""
        
        # ConfigMap for configuration
        configmap_yaml = """apiVersion: v1
kind: ConfigMap
metadata:
  name: blncs-config
data:
  config.yaml: |
    logging:
      level: INFO
      format: json
    server:
      port: 8000
      workers: 1
"""
        
        files = {}
        try:
            files["deployment.yaml"] = deployment_yaml
            files["service.yaml"] = service_yaml
            files["configmap.yaml"] = configmap_yaml
            
            # Write files
            for filename, content in files.items():
                with open(f"k8s-{filename}", 'w') as f:
                    f.write(content)
            
            self.logger.info("Created Kubernetes manifests")
            return {f"k8s-{k}": v for k, v in files.items()}
            
        except Exception as e:
            self.logger.error(f"Failed to create Kubernetes manifests: {e}")
            raise
    
    def run_deployment_checks(self) -> bool:
        """Run pre-deployment checks."""
        self.logger.info("Running deployment validation checks...")
        
        validation_results = self.validate_environment()
        all_valid = True
        
        for check_name, result in validation_results.items():
            if isinstance(result, dict):
                if "valid" in result and not result["valid"]:
                    all_valid = False
                    self.logger.error(f"Validation failed for {check_name}: {result}")
                else:
                    self.logger.info(f"Validation passed for {check_name}")
            else:
                # Handle nested checks like environment_variables
                for sub_check, sub_result in result.items():
                    if not sub_result.get("valid", True):
                        all_valid = False
                        self.logger.error(f"Validation failed for {check_name}.{sub_check}: {sub_result}")
        
        if all_valid:
            self.logger.info("All deployment checks passed")
        else:
            self.logger.error("Some deployment checks failed")
        
        return all_valid
    
    @contextmanager
    def graceful_shutdown_handler(self):
        """Context manager for graceful shutdown handling."""
        try:
            yield
        finally:
            if self.shutdown_requested:
                self.logger.info("Performing graceful shutdown...")
                # Add any cleanup operations here
                time.sleep(1)  # Give time for cleanup
                self.logger.info("Graceful shutdown completed")

def create_deployment_package(output_dir: str = "deployment") -> str:
    """Create complete deployment package."""
    manager = DeploymentManager()
    
    # Create output directory
    deploy_dir = Path(output_dir)
    deploy_dir.mkdir(exist_ok=True)
    
    os.chdir(deploy_dir)
    
    try:
        # Create all deployment files
        systemd_file = manager.create_systemd_service(".")
        docker_file = manager.create_docker_config()
        k8s_files = manager.create_k8s_manifests()
        
        # Create deployment script
        deploy_script = """#!/bin/bash
set -e

echo "BLNCS Deployment Script"
echo "======================"

# Check if running as root for systemd installation
if [ "$1" = "systemd" ]; then
    if [ "$EUID" -ne 0 ]; then
        echo "Please run as root for systemd installation"
        exit 1
    fi
    
    echo "Installing systemd service..."
    cp blncs.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable blncs
    systemctl start blncs
    systemctl status blncs
    echo "Systemd service installed and started"
    
elif [ "$1" = "docker" ]; then
    echo "Building Docker image..."
    docker build -t blncs:latest .
    echo "Docker image built successfully"
    
elif [ "$1" = "k8s" ]; then
    echo "Deploying to Kubernetes..."
    kubectl apply -f k8s-configmap.yaml
    kubectl apply -f k8s-deployment.yaml
    kubectl apply -f k8s-service.yaml
    echo "Kubernetes deployment completed"
    
else
    echo "Usage: $0 {systemd|docker|k8s}"
    exit 1
fi
"""
        
        with open("deploy.sh", 'w') as f:
            f.write(deploy_script)
        os.chmod("deploy.sh", 0o755)
        
        # Create README
        readme_content = """# BLNCS Deployment Package

This package contains all files needed to deploy BLNCS in various environments.

## Files Included

- `blncs.service` - Systemd service file
- `Dockerfile` - Docker container configuration  
- `k8s-*.yaml` - Kubernetes manifests
- `deploy.sh` - Deployment script

## Deployment Options

### Systemd (Linux service)
```bash
sudo ./deploy.sh systemd
```

### Docker
```bash
./deploy.sh docker
docker run -d -p 8000:8000 blncs:latest
```

### Kubernetes
```bash
./deploy.sh k8s
```

## Health Checks

BLNCS includes built-in health check endpoints:
- `/health` - Full health check
- `/ready` - Readiness probe  
- `/live` - Liveness probe

## Configuration

Set environment variables:
- `BLNCS_ENV` - Environment (production, staging, development)
- `BLNCS_LOG_LEVEL` - Logging level (INFO, DEBUG, WARNING, ERROR)
"""
        
        with open("README.md", 'w') as f:
            f.write(readme_content)
        
        manager.logger.info(f"Deployment package created in: {deploy_dir.absolute()}")
        return str(deploy_dir.absolute())
        
    except Exception as e:
        manager.logger.error(f"Failed to create deployment package: {e}")
        raise
    finally:
        os.chdir("..")

if __name__ == "__main__":
    # Create a deployment package
    package_path = create_deployment_package()
    print(f"Deployment package created at: {package_path}")
    
    # Run deployment checks
    manager = DeploymentManager()
    if manager.run_deployment_checks():
        print("All deployment checks passed!")
    else:
        print("Some deployment checks failed - review logs")