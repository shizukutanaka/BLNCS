#!/usr/bin/env python3
"""
BLNCS System Integration Manager
Unified system management and optimization
"""

import os
import sys
import time
import json
from typing import Dict, Any, List, Optional
from pathlib import Path

class SystemIntegrationManager:
    """Unified system management and optimization"""

    def __init__(self):
        self.components = {}
        self.start_time = time.time()
        self.system_status = 'initializing'

    def register_component(self, name: str, component_class):
        """Register a system component"""
        self.components[name] = {
            'class': component_class,
            'instance': None,
            'status': 'registered'
        }

    def initialize_component(self, name: str) -> bool:
        """Initialize a system component"""
        if name not in self.components:
            return False

        try:
            component_info = self.components[name]
            component_info['instance'] = component_info['class']()
            component_info['status'] = 'initialized'
            return True
        except Exception as e:
            component_info['status'] = f'error: {e}'
            return False

    def get_component_status(self) -> Dict[str, Any]:
        """Get status of all components"""
        status = {}
        for name, info in self.components.items():
            status[name] = {
                'status': info['status'],
                'initialized': info['instance'] is not None
            }
        return status

    def optimize_system(self) -> Dict[str, Any]:
        """Run comprehensive system optimization"""
        print("🚀 Starting system optimization...")

        results = {
            'components_initialized': 0,
            'total_components': len(self.components),
            'optimization_time': 0,
            'memory_usage': self.get_memory_usage(),
            'component_status': {}
        }

        start_time = time.time()

        # Initialize critical components
        critical_components = [
            'config_manager',
            'logger',
            'database_manager',
            'cache_manager'
        ]

        for component_name in critical_components:
            if self.initialize_component(component_name):
                results['components_initialized'] += 1

        # Update component status
        results['component_status'] = self.get_component_status()
        results['optimization_time'] = time.time() - start_time

        print(f"✅ System optimization completed in {results['optimization_time']".2f"}s")
        print(f"   Components initialized: {results['components_initialized']}/{results['total_components']}")

        return results

    def get_memory_usage(self) -> Dict[str, Any]:
        """Get system memory usage"""
        try:
            import psutil
            process = psutil.Process()
            memory_info = process.memory_info()

            return {
                'rss_mb': memory_info.rss / 1024 / 1024,
                'vms_mb': memory_info.vms / 1024 / 1024,
                'percent': process.memory_percent()
            }
        except ImportError:
            return {
                'rss_mb': 0,
                'vms_mb': 0,
                'percent': 0
            }

    def get_system_health(self) -> Dict[str, Any]:
        """Get overall system health"""
        component_status = self.get_component_status()
        memory_usage = self.get_memory_usage()

        healthy_components = sum(1 for c in component_status.values() if c['status'] == 'initialized')
        total_components = len(component_status)

        health_score = (healthy_components / total_components) * 100 if total_components > 0 else 0

        return {
            'health_score': health_score,
            'healthy_components': healthy_components,
            'total_components': total_components,
            'memory_usage': memory_usage,
            'uptime': time.time() - self.start_time,
            'status': 'healthy' if health_score > 80 else 'warning' if health_score > 50 else 'critical'
        }

    def create_system_report(self) -> Dict[str, Any]:
        """Create comprehensive system report"""
        return {
            'timestamp': time.time(),
            'system_health': self.get_system_health(),
            'component_status': self.get_component_status(),
            'memory_usage': self.get_memory_usage(),
            'optimization_results': self.optimize_system(),
            'system_info': {
                'python_version': sys.version.split()[0],
                'platform': sys.platform,
                'working_directory': str(Path.cwd())
            }
        }

# Global integration manager
_integration_manager = None

def get_system_integration_manager() -> SystemIntegrationManager:
    """Get global integration manager"""
    global _integration_manager
    if _integration_manager is None:
        _integration_manager = SystemIntegrationManager()
    return _integration_manager

def register_component(name: str, component_class):
    """Register a system component"""
    manager = get_system_integration_manager()
    manager.register_component(name, component_class)

def initialize_component(name: str) -> bool:
    """Initialize a system component"""
    manager = get_system_integration_manager()
    return manager.initialize_component(name)

def get_system_health() -> Dict[str, Any]:
    """Get system health"""
    manager = get_system_integration_manager()
    return manager.get_system_health()

def get_component_status() -> Dict[str, Any]:
    """Get component status"""
    manager = get_system_integration_manager()
    return manager.get_component_status()

def optimize_system() -> Dict[str, Any]:
    """Optimize system"""
    manager = get_system_integration_manager()
    return manager.optimize_system()

def create_system_report() -> Dict[str, Any]:
    """Create system report"""
    manager = get_system_integration_manager()
    return manager.create_system_report()

if __name__ == '__main__':
    # Test system integration manager
    manager = get_system_integration_manager()

    # Register example components
    class ExampleComponent:
        def __init__(self):
            self.name = "example"

    register_component('example_component', ExampleComponent)

    # Initialize and test
    initialize_component('example_component')

    # Get system health
    health = get_system_health()
    print(f"✅ System health: {health['health_score']:.1f}% ({health['status']})")

    # Get component status
    status = get_component_status()
    print(f"✅ Component status: {status}")

    # Optimize system
    optimization = optimize_system()
    print(f"✅ Optimization: {optimization['components_initialized']}/{optimization['total_components']} components")

    # Create report
    report = create_system_report()
    print(f"✅ System report created with {len(report)} sections")

    print("🎉 System integration manager test completed!")
