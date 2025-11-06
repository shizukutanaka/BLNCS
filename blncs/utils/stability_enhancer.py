#!/usr/bin/env python3
"""
BLNCS System Stability Enhancer
Lightweight system stability improvements
"""

import os
import sys
import time
import json
from typing import Dict, Any, Optional
from pathlib import Path

def optimize_imports():
    """Optimize Python imports for better performance"""
    try:
        # Pre-import commonly used modules
        import sqlite3
        import json
        import hashlib
        import logging

        # Set optimal GC thresholds
        import gc
        gc.set_threshold(500, 10, 10)

        return True
    except Exception:
        return False

def validate_environment():
    """Validate system environment"""
    issues = []

    # Check Python version
    python_version = sys.version_info
    if python_version < (3, 8):
        issues.append(f"Python version {python_version} may not be fully supported")

    # Check available disk space
    try:
        import shutil
        disk_usage = shutil.disk_usage('.')
        free_gb = disk_usage.free / (1024**3)
        if free_gb < 1:
            issues.append(f"Low disk space: {free_gb:.1f} GB free")
    except Exception:
        pass

    # Check critical directories
    critical_dirs = ['config', 'data', 'logs']
    for dir_name in critical_dirs:
        if not Path(dir_name).exists():
            try:
                Path(dir_name).mkdir(exist_ok=True)
            except Exception:
                issues.append(f"Cannot create directory: {dir_name}")

    return issues

def enhance_error_handling():
    """Enhance global error handling"""
    def custom_excepthook(exc_type, exc_value, exc_traceback):
        # Log critical errors
        error_msg = f"Unhandled exception: {exc_type.__name__}: {exc_value}"
        print(f"❌ {error_msg}", file=sys.stderr)

        # Try to log to file
        try:
            with open('logs/error.log', 'a') as f:
                f.write(f"{time.ctime()}: {error_msg}\n")
        except Exception:
            pass

        # Call original exception handler
        sys.__excepthook__(exc_type, exc_value, exc_traceback)

    sys.excepthook = custom_excepthook

def setup_lightweight_components():
    """Setup lightweight system components"""
    try:
        # Import and initialize lightweight components
        from blncs.core.lightweight_logger import get_lightweight_logger
        from blncs.core.lightweight_config import get_lightweight_config_manager
        from blncs.core.lightweight_cache import get_lightweight_cache
        from blncs.core.lightweight_error_handler import get_lightweight_error_handler
        from blncs.monitoring.lightweight_monitor import get_lightweight_monitor

        # Initialize components
        logger = get_lightweight_logger()
        config_manager = get_lightweight_config_manager()
        cache = get_lightweight_cache()
        error_handler = get_lightweight_error_handler()
        monitor = get_lightweight_monitor()

        return True
    except Exception as e:
        print(f"Warning: Could not initialize lightweight components: {e}")
        return False

def create_system_report():
    """Create system status report"""
    report = {
        'timestamp': time.time(),
        'python_version': sys.version,
        'platform': sys.platform,
        'working_directory': os.getcwd(),
        'components_initialized': False,
        'environment_issues': []
    }

    # Check environment
    report['environment_issues'] = validate_environment()

    # Check components
    report['components_initialized'] = setup_lightweight_components()

    return report

def main():
    """Main stability enhancement function"""
    print("🔧 Enhancing system stability...")

    # Optimize imports
    optimize_imports()
    print("✅ Import optimization completed")

    # Validate environment
    issues = validate_environment()
    if issues:
        print(f"⚠️  Environment issues found: {len(issues)}")
        for issue in issues:
            print(f"   • {issue}")
    else:
        print("✅ Environment validation passed")

    # Enhance error handling
    enhance_error_handling()
    print("✅ Error handling enhanced")

    # Setup lightweight components
    components_ok = setup_lightweight_components()
    if components_ok:
        print("✅ Lightweight components initialized")
    else:
        print("⚠️  Some lightweight components failed to initialize")

    # Create system report
    report = create_system_report()
    print(f"✅ System report created: {len(report['environment_issues'])} issues, components: {report['components_initialized']}")

    print("🎉 System stability enhancement completed!")

    return report

if __name__ == '__main__':
    report = main()
    if report:
        print(f"\n📊 System Report Summary:")
        print(f"   Issues: {len(report['environment_issues'])}")
        print(f"   Components: {'✅' if report['components_initialized'] else '❌'}")
        print(f"   Platform: {report['platform']}")
        print(f"   Python: {report['python_version'].split()[0]}")
