#!/usr/bin/env python3
"""
System Information Utility
Lightweight system resource monitoring and diagnostics using standard library only.
"""

import os
import shutil
import platform
import subprocess
import sys
from typing import Dict, Any, Optional
from datetime import datetime


def get_basic_system_info() -> Dict[str, Any]:
    """Get basic system information"""
    try:
        return {
            "platform": platform.system(),
            "platform_version": platform.version(),
            "architecture": platform.architecture()[0],
            "processor": platform.processor() or "Unknown",
            "hostname": platform.node(),
            "python_version": platform.python_version(),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {"error": f"Failed to get system info: {e}"}


def get_memory_info() -> Dict[str, Any]:
    """Get memory usage information using system commands"""
    try:
        if platform.system() == "Linux":
            # Read /proc/meminfo on Linux
            with open('/proc/meminfo', 'r') as f:
                meminfo = f.read()
            
            mem_total = 0
            mem_available = 0
            
            for line in meminfo.split('\n'):
                if 'MemTotal:' in line:
                    mem_total = int(line.split()[1]) * 1024  # Convert KB to bytes
                elif 'MemAvailable:' in line:
                    mem_available = int(line.split()[1]) * 1024
            
            if mem_total > 0:
                used = mem_total - mem_available
                return {
                    "total_gb": round(mem_total / (1024**3), 2),
                    "available_gb": round(mem_available / (1024**3), 2),
                    "used_gb": round(used / (1024**3), 2),
                    "used_percent": round((used / mem_total) * 100, 1)
                }
        
        # Fallback for other systems
        return {"status": "Memory info not available on this platform"}
    except Exception as e:
        return {"error": f"Failed to get memory info: {e}"}


def get_cpu_info() -> Dict[str, Any]:
    """Get CPU usage information using standard library"""
    try:
        # Get CPU count
        cpu_count = os.cpu_count() or 1
        
        # Try to get load average on Unix systems
        load_info = {}
        if hasattr(os, 'getloadavg'):
            load1, load5, load15 = os.getloadavg()
            load_info = {
                "load_1min": round(load1, 2),
                "load_5min": round(load5, 2),
                "load_15min": round(load15, 2)
            }
        
        result = {
            "logical_cores": cpu_count
        }
        result.update(load_info)
        return result
        
    except Exception as e:
        return {"error": f"Failed to get CPU info: {e}"}


def get_disk_info() -> Dict[str, Any]:
    """Get disk usage information using standard library"""
    try:
        # Use shutil.disk_usage for cross-platform disk info
        total, used, free = shutil.disk_usage('.')
        
        return {
            "total_gb": round(total / (1024**3), 2),
            "used_gb": round(used / (1024**3), 2),
            "free_gb": round(free / (1024**3), 2),
            "used_percent": round((used / total) * 100, 1)
        }
    except Exception as e:
        return {"error": f"Failed to get disk info: {e}"}


def get_network_connections() -> Dict[str, Any]:
    """Get basic network information"""
    try:
        # Simple check - just verify if we have network interfaces
        if platform.system() == "Linux":
            with open('/proc/net/dev', 'r') as f:
                lines = f.readlines()[2:]  # Skip header lines
                interfaces = [line.split(':')[0].strip() for line in lines]
                interfaces = [iface for iface in interfaces if iface != 'lo']  # Exclude loopback
                
                return {
                    "network_interfaces": len(interfaces),
                    "interface_names": interfaces[:3]  # Show first 3 only
                }
        
        return {"status": "Network info not available on this platform"}
    except Exception as e:
        return {"error": f"Failed to get network info: {e}"}


def get_process_count() -> Dict[str, Any]:
    """Get basic process information"""
    try:
        # Just return current process info
        return {
            "current_pid": os.getpid(),
            "parent_pid": os.getppid() if hasattr(os, 'getppid') else None,
            "python_executable": sys.executable
        }
    except Exception as e:
        return {"error": f"Failed to get process info: {e}"}


def get_comprehensive_system_report() -> Dict[str, Any]:
    """Get comprehensive system report"""
    return {
        "system": get_basic_system_info(),
        "memory": get_memory_info(),
        "cpu": get_cpu_info(),
        "disk": get_disk_info(),
        "network": get_network_connections(),
        "processes": get_process_count()
    }


def format_system_report(report: Dict[str, Any]) -> str:
    """Format system report for display"""
    output = []
    output.append("System Information Report")
    output.append("=" * 40)
    
    # System Info
    system = report.get("system", {})
    if "error" not in system:
        output.append("System:")
        output.append(f"  Platform: {system.get('platform', 'Unknown')} ({system.get('architecture', 'Unknown')})")
        output.append(f"  Hostname: {system.get('hostname', 'Unknown')}")
        output.append(f"  Python: {system.get('python_version', 'Unknown')}")
        output.append("")
    
    # CPU Info
    cpu = report.get("cpu", {})
    if "error" not in cpu:
        output.append("CPU:")
        output.append(f"  Cores: {cpu.get('logical_cores', 0)} logical")
        if cpu.get('load_1min') is not None:
            output.append(f"  Load Average: {cpu['load_1min']} (1min), {cpu['load_5min']} (5min)")
        output.append("")
    
    # Memory Info
    memory = report.get("memory", {})
    if "error" not in memory:
        output.append("Memory:")
        output.append(f"  Usage: {memory.get('used_percent', 0):.1f}% ({memory.get('used_gb', 0):.1f}GB / {memory.get('total_gb', 0):.1f}GB)")
        output.append(f"  Available: {memory.get('available_gb', 0):.1f}GB")
        if memory.get('swap_total_gb', 0) > 0:
            output.append(f"  Swap: {memory.get('swap_percent', 0):.1f}% ({memory.get('swap_used_gb', 0):.1f}GB / {memory.get('swap_total_gb', 0):.1f}GB)")
        output.append("")
    
    # Disk Info
    disk = report.get("disk", {})
    if "error" not in disk:
        output.append("Disk:")
        output.append(f"  Usage: {disk.get('used_percent', 0):.1f}% ({disk.get('used_gb', 0):.1f}GB / {disk.get('total_gb', 0):.1f}GB)")
        output.append(f"  Free Space: {disk.get('free_gb', 0):.1f}GB")
        output.append("")
    
    # Process Info
    processes = report.get("processes", {})
    if "error" not in processes:
        output.append("Process Info:")
        output.append(f"  Current PID: {processes.get('current_pid', 'Unknown')}")
        if processes.get('parent_pid'):
            output.append(f"  Parent PID: {processes['parent_pid']}")
        output.append(f"  Python: {processes.get('python_executable', 'Unknown')}")
        output.append("")
    
    # Network Info (summary only)
    network = report.get("network", {})
    if "error" not in network and "status" not in network:
        output.append("Network:")
        output.append(f"  Interfaces: {network.get('network_interfaces', 0)}")
        if network.get('interface_names'):
            output.append(f"  Names: {', '.join(network['interface_names'])}")
        output.append("")
    
    return "\n".join(output)


if __name__ == "__main__":
    # Quick system report when run directly
    report = get_comprehensive_system_report()
    print(format_system_report(report))