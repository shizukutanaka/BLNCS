#!/usr/bin/env python3
"""
Lightning Network connectivity testing utility
Simple, lightweight network diagnostic tools.
"""

import socket
import time
import requests
from typing import Dict, Any, Optional
from datetime import datetime


def test_internet_connection(timeout: int = 5) -> Dict[str, Any]:
    """Test basic internet connectivity"""
    try:
        # Test DNS resolution
        socket.gethostbyname("google.com")
        
        # Test HTTP connection
        response = requests.get("https://httpbin.org/status/200", timeout=timeout)
        
        return {
            "status": "connected",
            "dns": True,
            "http": response.status_code == 200,
            "response_time": response.elapsed.total_seconds()
        }
    except Exception as e:
        return {
            "status": "disconnected",
            "error": str(e)
        }


def test_lightning_port(host: str = "localhost", port: int = 9735, timeout: int = 3) -> Dict[str, Any]:
    """Test Lightning Network port connectivity"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        start_time = time.time()
        result = sock.connect_ex((host, port))
        end_time = time.time()
        
        sock.close()
        
        if result == 0:
            return {
                "status": "open",
                "host": host,
                "port": port,
                "response_time": end_time - start_time
            }
        else:
            return {
                "status": "closed",
                "host": host,
                "port": port,
                "error": f"Connection failed (code: {result})"
            }
    except Exception as e:
        return {
            "status": "error",
            "host": host,
            "port": port,
            "error": str(e)
        }


def test_bitcoin_node_rpc(host: str = "localhost", port: int = 8332, timeout: int = 5) -> Dict[str, Any]:
    """Test Bitcoin Core RPC connectivity (without authentication)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        start_time = time.time()
        result = sock.connect_ex((host, port))
        end_time = time.time()
        
        sock.close()
        
        if result == 0:
            return {
                "status": "reachable",
                "host": host,
                "port": port,
                "response_time": end_time - start_time,
                "note": "Port open (authentication not tested)"
            }
        else:
            return {
                "status": "unreachable",
                "host": host,
                "port": port,
                "error": f"Connection failed (code: {result})"
            }
    except Exception as e:
        return {
            "status": "error",
            "host": host,
            "port": port,
            "error": str(e)
        }


def run_network_diagnostics() -> Dict[str, Any]:
    """Run comprehensive network diagnostics"""
    results = {
        "timestamp": datetime.now().isoformat(),
        "tests": {}
    }
    
    print("Running network diagnostics...")
    
    # Test internet connectivity
    print("- Testing internet connection...")
    results["tests"]["internet"] = test_internet_connection()
    
    # Test Lightning port
    print("- Testing Lightning Network port...")
    results["tests"]["lightning_port"] = test_lightning_port()
    
    # Test Bitcoin RPC port
    print("- Testing Bitcoin Core RPC port...")
    results["tests"]["bitcoin_rpc"] = test_bitcoin_node_rpc()
    
    return results


def format_diagnostic_results(results: Dict[str, Any]) -> str:
    """Format diagnostic results for display"""
    output = []
    output.append("Network Diagnostic Results")
    output.append("=" * 40)
    output.append(f"Timestamp: {results['timestamp']}")
    output.append("")
    
    tests = results["tests"]
    
    # Internet connectivity
    if "internet" in tests:
        internet = tests["internet"]
        if internet["status"] == "connected":
            output.append("[OK] Internet: Connected")
            if "response_time" in internet:
                output.append(f"    Response time: {internet['response_time']:.3f}s")
        else:
            output.append("[ERROR] Internet: Disconnected")
            if "error" in internet:
                output.append(f"    Error: {internet['error']}")
    
    # Lightning port
    if "lightning_port" in tests:
        ln_port = tests["lightning_port"]
        if ln_port["status"] == "open":
            output.append(f"[OK] Lightning Port: {ln_port['host']}:{ln_port['port']} - Open")
            output.append(f"    Response time: {ln_port['response_time']:.3f}s")
        else:
            output.append(f"[ERROR] Lightning Port: {ln_port['host']}:{ln_port['port']} - {ln_port['status'].title()}")
            if "error" in ln_port:
                output.append(f"    Error: {ln_port['error']}")
    
    # Bitcoin RPC
    if "bitcoin_rpc" in tests:
        btc_rpc = tests["bitcoin_rpc"]
        if btc_rpc["status"] == "reachable":
            output.append(f"[OK] Bitcoin RPC: {btc_rpc['host']}:{btc_rpc['port']} - Reachable")
            output.append(f"    Response time: {btc_rpc['response_time']:.3f}s")
            if "note" in btc_rpc:
                output.append(f"    Note: {btc_rpc['note']}")
        else:
            output.append(f"[ERROR] Bitcoin RPC: {btc_rpc['host']}:{btc_rpc['port']} - {btc_rpc['status'].title()}")
            if "error" in btc_rpc:
                output.append(f"    Error: {btc_rpc['error']}")
    
    return "\n".join(output)


if __name__ == "__main__":
    # Quick test when run directly
    results = run_network_diagnostics()
    print("\n" + format_diagnostic_results(results))