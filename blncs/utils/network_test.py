#!/usr/bin/env python3
"""
Lightweight Network Testing Utilities for BLNCS
Essential network connectivity testing with minimal dependencies.
"""

import socket
import time
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

@dataclass
class NetworkTestResult:
    """Result of a network test"""
    test_name: str
    success: bool
    duration_ms: float
    error: Optional[str] = None
    timestamp: Optional[datetime] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

class SimpleNetworkTester:
    """Simple network connectivity tester"""
    
    def test_tcp_connection(self, host: str, port: int, timeout: float = 5.0) -> NetworkTestResult:
        """Test TCP connection to host:port"""
        start_time = time.time()
        
        try:
            with socket.create_connection((host, port), timeout=timeout):
                duration = (time.time() - start_time) * 1000
                return NetworkTestResult(
                    test_name=f"TCP Connection to {host}:{port}",
                    success=True,
                    duration_ms=duration
                )
        except Exception as e:
            duration = (time.time() - start_time) * 1000
            return NetworkTestResult(
                test_name=f"TCP Connection to {host}:{port}",
                success=False,
                duration_ms=duration,
                error=str(e)
            )
    
    def test_dns_resolution(self, hostname: str, timeout: float = 5.0) -> NetworkTestResult:
        """Test DNS resolution for hostname"""
        start_time = time.time()
        
        try:
            socket.setdefaulttimeout(timeout)
            ip_address = socket.gethostbyname(hostname)
            duration = (time.time() - start_time) * 1000
            
            return NetworkTestResult(
                test_name=f"DNS Resolution for {hostname}",
                success=True,
                duration_ms=duration
            )
        except Exception as e:
            duration = (time.time() - start_time) * 1000
            return NetworkTestResult(
                test_name=f"DNS Resolution for {hostname}",
                success=False,
                duration_ms=duration,
                error=str(e)
            )
        finally:
            socket.setdefaulttimeout(None)
    
    def ping_host(self, host: str, count: int = 1) -> NetworkTestResult:
        """Simple ping test (basic connectivity check)"""
        start_time = time.time()
        
        # Use TCP connection test as a simple "ping" alternative
        result = self.test_tcp_connection(host, 80, timeout=3.0)
        if not result.success:
            # Try port 443 (HTTPS) if port 80 fails
            result = self.test_tcp_connection(host, 443, timeout=3.0)
        
        result.test_name = f"Ping to {host}"
        return result
    
    def test_lightning_node_connectivity(self, host: str, port: int = 9735) -> NetworkTestResult:
        """Test connectivity to a Lightning Network node"""
        return self.test_tcp_connection(host, port, timeout=10.0)
    
    def run_basic_network_tests(self) -> Dict[str, NetworkTestResult]:
        """Run a set of basic network connectivity tests"""
        tests = {}
        
        # Test DNS resolution
        tests['dns_google'] = self.test_dns_resolution('google.com')
        tests['dns_cloudflare'] = self.test_dns_resolution('cloudflare.com')
        
        # Test internet connectivity
        tests['http_google'] = self.test_tcp_connection('google.com', 80)
        tests['https_google'] = self.test_tcp_connection('google.com', 443)
        
        # Test localhost
        tests['localhost'] = self.test_tcp_connection('127.0.0.1', 22)
        
        return tests
    
    def format_test_results(self, results: Dict[str, NetworkTestResult]) -> str:
        """Format test results for display"""
        output = "Network Connectivity Test Results\n"
        output += "=" * 40 + "\n"
        
        for test_name, result in results.items():
            status = "✓ PASS" if result.success else "✗ FAIL"
            output += f"{test_name}: {status} ({result.duration_ms:.1f}ms)\n"
            if result.error:
                output += f"  Error: {result.error}\n"
        
        return output

# Convenience functions for direct use
def test_host_port(host: str, port: int, timeout: float = 5.0) -> bool:
    """Quick test if host:port is reachable"""
    tester = SimpleNetworkTester()
    result = tester.test_tcp_connection(host, port, timeout)
    return result.success

def test_lightning_node(host: str, port: int = 9735) -> bool:
    """Quick test if Lightning node is reachable"""
    tester = SimpleNetworkTester()
    result = tester.test_lightning_node_connectivity(host, port)
    return result.success

def run_network_diagnostics() -> Dict[str, NetworkTestResult]:
    """Run comprehensive network diagnostics"""
    tester = SimpleNetworkTester()
    return tester.run_basic_network_tests()

if __name__ == "__main__":
    # Test the network diagnostics
    tester = SimpleNetworkTester()
    results = tester.run_basic_network_tests()
    print(tester.format_test_results(results))