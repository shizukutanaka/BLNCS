"""
Connection Helper for BLNCS
Simple utilities for Lightning node connections.
"""

import socket
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass


@dataclass
class ConnectionConfig:
    """Lightning node connection configuration"""
    host: str
    port: int
    cert_path: Optional[str] = None
    macaroon_path: Optional[str] = None
    network: str = "mainnet"
    timeout: int = 30

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'host': self.host,
            'port': self.port,
            'cert_path': self.cert_path,
            'macaroon_path': self.macaroon_path,
            'network': self.network,
            'timeout': self.timeout
        }


@dataclass
class ConnectionTest:
    """Connection test result"""
    host: str
    port: int
    success: bool
    response_time: float
    error: Optional[str] = None


class ConnectionHelper:
    """Simple connection utilities"""

    # Common Lightning node ports
    COMMON_PORTS = [9735, 10009, 8080, 8333]

    # Well-known test nodes
    TEST_NODES = [
        ('endurance.acinq.co', 9735),
        ('ln.bitrefill.com', 9735),
        ('yalls.org', 9735),
    ]

    @staticmethod
    def test_connection(host: str, port: int, timeout: int = 5) -> ConnectionTest:
        """Test connection to a host:port"""
        start_time = time.time()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            response_time = time.time() - start_time
            sock.close()

            success = result == 0
            error = None if success else f"Connection failed (code: {result})"

            return ConnectionTest(
                host=host,
                port=port,
                success=success,
                response_time=response_time,
                error=error
            )

        except Exception as e:
            return ConnectionTest(
                host=host,
                port=port,
                success=False,
                response_time=time.time() - start_time,
                error=str(e)
            )

    @classmethod
    def scan_ports(cls, host: str, ports: List[int] = None, timeout: int = 3) -> List[ConnectionTest]:
        """Scan multiple ports on a host"""
        if ports is None:
            ports = cls.COMMON_PORTS

        results = []
        for port in ports:
            test = cls.test_connection(host, port, timeout)
            results.append(test)

        return results

    @classmethod
    def find_available_port(cls, host: str, ports: List[int] = None, timeout: int = 3) -> Optional[int]:
        """Find first available port on host"""
        results = cls.scan_ports(host, ports, timeout)
        for test in results:
            if test.success:
                return test.port
        return None

    @classmethod
    def test_known_nodes(cls, timeout: int = 5) -> List[ConnectionTest]:
        """Test connections to well-known nodes"""
        results = []
        for host, port in cls.TEST_NODES:
            test = cls.test_connection(host, port, timeout)
            results.append(test)
        return results

    @staticmethod
    def create_connection_config(
        host: str,
        port: int = 10009,
        cert_path: str = None,
        macaroon_path: str = None,
        network: str = "mainnet"
    ) -> ConnectionConfig:
        """Create connection configuration"""
        return ConnectionConfig(
            host=host,
            port=port,
            cert_path=cert_path,
            macaroon_path=macaroon_path,
            network=network
        )

    @staticmethod
    def validate_config(config: ConnectionConfig) -> Tuple[bool, List[str]]:
        """Validate connection configuration"""
        errors = []

        # Basic validation
        if not config.host:
            errors.append("Host is required")

        if not isinstance(config.port, int) or not (1 <= config.port <= 65535):
            errors.append("Port must be between 1 and 65535")

        if config.network not in ["mainnet", "testnet", "regtest"]:
            errors.append("Network must be mainnet, testnet, or regtest")

        # File path validation
        import os
        if config.cert_path and not os.path.exists(config.cert_path):
            errors.append(f"Certificate file not found: {config.cert_path}")

        if config.macaroon_path and not os.path.exists(config.macaroon_path):
            errors.append(f"Macaroon file not found: {config.macaroon_path}")

        return len(errors) == 0, errors

    @classmethod
    def auto_detect_local_node(cls, timeout: int = 3) -> Optional[ConnectionConfig]:
        """Try to auto-detect local Lightning node"""
        # Try localhost with common ports
        for port in cls.COMMON_PORTS:
            test = cls.test_connection("localhost", port, timeout)
            if test.success:
                return ConnectionConfig(
                    host="localhost",
                    port=port,
                    network="mainnet"  # Default assumption
                )

        # Try 127.0.0.1
        for port in cls.COMMON_PORTS:
            test = cls.test_connection("127.0.0.1", port, timeout)
            if test.success:
                return ConnectionConfig(
                    host="127.0.0.1",
                    port=port,
                    network="mainnet"
                )

        return None

    @staticmethod
    def get_connection_summary(config: ConnectionConfig) -> Dict[str, Any]:
        """Get connection configuration summary"""
        return {
            'host': config.host,
            'port': config.port,
            'network': config.network,
            'has_cert': config.cert_path is not None,
            'has_macaroon': config.macaroon_path is not None,
            'connection_string': f"{config.host}:{config.port}"
        }


# Global utilities
def quick_test(host: str, port: int = 10009) -> bool:
    """Quick connection test"""
    test = ConnectionHelper.test_connection(host, port)
    return test.success


def scan_local_nodes() -> List[ConnectionConfig]:
    """Scan for local Lightning nodes"""
    configs = []

    # Test common local addresses
    hosts = ["localhost", "127.0.0.1"]

    for host in hosts:
        for port in ConnectionHelper.COMMON_PORTS:
            if quick_test(host, port):
                config = ConnectionConfig(host=host, port=port)
                configs.append(config)

    return configs


def test_external_connectivity() -> bool:
    """Test external network connectivity"""
    tests = ConnectionHelper.test_known_nodes(timeout=10)
    return any(test.success for test in tests)


# Example usage
if __name__ == "__main__":
    print("BLNCS Connection Helper")
    print("======================")

    # Test local node detection
    local_config = ConnectionHelper.auto_detect_local_node()
    if local_config:
        print(f"Local node detected: {local_config.host}:{local_config.port}")
    else:
        print("No local node detected")

    # Test external connectivity
    if test_external_connectivity():
        print("External network connectivity: OK")
    else:
        print("External network connectivity: Failed")

    # Test specific connection
    test = ConnectionHelper.test_connection("127.0.0.1", 10009)
    print(f"Test localhost:10009 - Success: {test.success}, Time: {test.response_time:.3f}s")