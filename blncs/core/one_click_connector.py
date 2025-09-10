"""
One-Click Lightning Network Connector
Simplified connection manager for automatic Lightning node discovery and setup.
"""

import os
import json
import time
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config_manager import get_config_manager
from .logger import get_logger
from ..lightning.client import LightningClient


@dataclass
class NodeConfig:
    """Configuration for a Lightning node"""
    name: str
    host: str
    port: int
    network: str
    macaroon_path: Optional[str] = None
    cert_path: Optional[str] = None
    connection_type: str = "rest"  # rest, grpc
    auto_detected: bool = False
    priority: int = 0  # Higher priority = preferred


@dataclass
class ConnectionResult:
    """Result of a connection attempt"""
    success: bool
    config: Optional[NodeConfig] = None
    error: Optional[str] = None
    node_info: Optional[Dict[str, Any]] = None
    response_time: float = 0.0


class OneClickConnector:
    """One-click Lightning Network connection manager"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config_manager = get_config_manager()
        
        # Common Lightning node configurations
        self.default_configs = [
            # LND configurations
            NodeConfig("LND-Mainnet", "localhost", 8080, "mainnet", priority=10),
            NodeConfig("LND-Testnet", "localhost", 18080, "testnet", priority=9),
            NodeConfig("LND-Regtest", "localhost", 28080, "regtest", priority=8),
            
            # Core Lightning configurations
            NodeConfig("CLN-Mainnet", "localhost", 9736, "mainnet", priority=7),
            NodeConfig("CLN-Testnet", "localhost", 19736, "testnet", priority=6),
            
            # Eclair configurations
            NodeConfig("Eclair-Mainnet", "localhost", 8080, "mainnet", priority=5),
            NodeConfig("Eclair-Testnet", "localhost", 18080, "testnet", priority=4),
            
            # Common Docker configurations
            NodeConfig("Docker-LND", "lnd", 8080, "testnet", priority=3),
            NodeConfig("Docker-CLN", "lightningd", 9736, "testnet", priority=2),
            
            # Umbrel configurations
            NodeConfig("Umbrel-LND", "umbrel.local", 8080, "mainnet", priority=15),
            NodeConfig("Umbrel-Local", "192.168.1.1", 8080, "mainnet", priority=14),
        ]
        
        # Auto-detection patterns
        self.macaroon_paths = [
            "~/.lnd/data/chain/bitcoin/{network}/readonly.macaroon",
            "~/.lnd/data/chain/bitcoin/{network}/admin.macaroon",
            "/home/umbrel/umbrel/app-data/lightning/data/lnd/data/chain/bitcoin/{network}/readonly.macaroon",
            "/opt/lnd/data/chain/bitcoin/{network}/readonly.macaroon",
            "./lnd/data/chain/bitcoin/{network}/readonly.macaroon",
        ]
        
        self.cert_paths = [
            "~/.lnd/tls.cert",
            "/home/umbrel/umbrel/app-data/lightning/data/lnd/tls.cert",
            "/opt/lnd/tls.cert",
            "./lnd/tls.cert",
        ]
    
    def quick_connect(self, network: str = "testnet", timeout: int = 30) -> ConnectionResult:
        """
        One-click connection attempt to any available Lightning node
        
        Args:
            network: Target network (mainnet, testnet, regtest)
            timeout: Total timeout for all connection attempts
        
        Returns:
            ConnectionResult with success status and configuration
        """
        self.logger.info(f"Starting one-click connection for {network} network...")
        start_time = time.time()
        
        # Get network-specific configurations
        configs = self._get_network_configs(network)
        
        # Sort by priority (highest first)
        configs.sort(key=lambda x: x.priority, reverse=True)
        
        # Auto-detect configurations
        detected_configs = self._auto_detect_configurations(network)
        configs.extend(detected_configs)
        
        best_result = None
        connection_attempts = []
        
        # Try connections in parallel for faster discovery
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            
            for config in configs:
                if time.time() - start_time > timeout:
                    break
                    
                future = executor.submit(self._test_connection, config)
                futures.append((future, config))
            
            # Process results as they complete
            for future, config in futures:
                try:
                    result = future.result(timeout=max(1, timeout - (time.time() - start_time)))
                    connection_attempts.append(result)
                    
                    if result.success:
                        if not best_result or result.config.priority > best_result.config.priority:
                            best_result = result
                            
                        # If we found a high-priority connection, use it immediately
                        if result.config.priority >= 10:
                            break
                            
                except Exception as e:
                    self.logger.debug(f"Connection test failed for {config.name}: {e}")
        
        # Return best result or failure
        if best_result:
            self._save_successful_config(best_result.config)
            self.logger.info(f"Successfully connected to {best_result.config.name}")
            return best_result
        else:
            error_msg = f"No Lightning nodes found on {network} network after {len(connection_attempts)} attempts"
            self.logger.error(error_msg)
            return ConnectionResult(
                success=False,
                error=error_msg
            )
    
    def _get_network_configs(self, network: str) -> List[NodeConfig]:
        """Get configurations for specific network"""
        return [config for config in self.default_configs if config.network == network]
    
    def _auto_detect_configurations(self, network: str) -> List[NodeConfig]:
        """Auto-detect Lightning node configurations on the system"""
        detected = []
        
        # Scan for macaroon files
        for macaroon_pattern in self.macaroon_paths:
            macaroon_path = Path(macaroon_pattern.format(network=network)).expanduser()
            if macaroon_path.exists():
                # Try to infer node configuration from macaroon location
                if "umbrel" in str(macaroon_path):
                    config = NodeConfig(
                        name=f"Auto-Umbrel-{network}",
                        host="umbrel.local",
                        port=8080,
                        network=network,
                        macaroon_path=str(macaroon_path),
                        auto_detected=True,
                        priority=20
                    )
                else:
                    config = NodeConfig(
                        name=f"Auto-LND-{network}",
                        host="localhost",
                        port=8080 if network == "mainnet" else 18080,
                        network=network,
                        macaroon_path=str(macaroon_path),
                        auto_detected=True,
                        priority=18
                    )
                
                # Look for corresponding cert file
                for cert_pattern in self.cert_paths:
                    cert_path = Path(cert_pattern).expanduser()
                    if cert_path.exists():
                        config.cert_path = str(cert_path)
                        break
                
                detected.append(config)
        
        # Scan common ports
        detected.extend(self._scan_local_ports(network))
        
        return detected
    
    def _scan_local_ports(self, network: str) -> List[NodeConfig]:
        """Scan local ports for Lightning nodes"""
        common_ports = [8080, 9735, 9736, 18080, 19735, 19736, 28080]
        detected = []
        
        for port in common_ports:
            if self._is_port_open("localhost", port):
                config = NodeConfig(
                    name=f"Auto-Port-{port}-{network}",
                    host="localhost",
                    port=port,
                    network=network,
                    auto_detected=True,
                    priority=12
                )
                detected.append(config)
        
        return detected
    
    def _is_port_open(self, host: str, port: int, timeout: float = 1.0) -> bool:
        """Check if a port is open"""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (socket.error, OSError):
            return False
    
    def _test_connection(self, config: NodeConfig) -> ConnectionResult:
        """Test connection to a Lightning node"""
        start_time = time.time()
        
        try:
            # Create temporary config for testing
            test_config = {
                'lightning': {
                    'host': config.host,
                    'port': config.port,
                    'network': config.network,
                    'macaroon_path': config.macaroon_path,
                    'verify_ssl': True  # Always verify SSL, use certificates properly
                }
            }
            
            # Create test client
            client = LightningClient(test_config)
            
            # Test connection
            node_info = client.get_info()
            response_time = time.time() - start_time
            
            if node_info and node_info.get('identity_pubkey'):
                return ConnectionResult(
                    success=True,
                    config=config,
                    node_info=node_info,
                    response_time=response_time
                )
            else:
                return ConnectionResult(
                    success=False,
                    config=config,
                    error="Invalid node response",
                    response_time=response_time
                )
                
        except Exception as e:
            response_time = time.time() - start_time
            return ConnectionResult(
                success=False,
                config=config,
                error=str(e),
                response_time=response_time
            )
    
    def _save_successful_config(self, config: NodeConfig) -> None:
        """Save successful configuration for future use"""
        try:
            lightning_config = {
                'host': config.host,
                'port': config.port,
                'network': config.network,
                'auto_detected': config.auto_detected,
                'connection_type': config.connection_type
            }
            
            if config.macaroon_path:
                lightning_config['macaroon_path'] = config.macaroon_path
            if config.cert_path:
                lightning_config['cert_path'] = config.cert_path
            
            # Save to configuration
            self.config_manager.set('lightning', lightning_config)
            
            # Also save as last successful connection
            self.config_manager.set('last_connection', {
                'name': config.name,
                'timestamp': int(time.time()),
                'config': lightning_config
            })
            
            self.logger.info(f"Saved configuration for {config.name}")
            
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")
    
    def get_connection_history(self) -> List[Dict[str, Any]]:
        """Get history of successful connections"""
        try:
            history_file = Path.home() / ".blncs" / "connection_history.json"
            if history_file.exists():
                with open(history_file) as f:
                    return json.load(f)
        except Exception:
            pass
        return []
    
    def reconnect_last(self) -> ConnectionResult:
        """Reconnect to the last successful connection"""
        try:
            last_connection = self.config_manager.get('last_connection')
            if not last_connection:
                return ConnectionResult(
                    success=False,
                    error="No previous connection found"
                )
            
            config_data = last_connection['config']
            config = NodeConfig(
                name=last_connection['name'],
                host=config_data['host'],
                port=config_data['port'],
                network=config_data['network'],
                macaroon_path=config_data.get('macaroon_path'),
                cert_path=config_data.get('cert_path'),
                connection_type=config_data.get('connection_type', 'rest'),
                auto_detected=config_data.get('auto_detected', False),
                priority=25  # High priority for last successful
            )
            
            result = self._test_connection(config)
            if result.success:
                self.logger.info(f"Successfully reconnected to {config.name}")
            
            return result
            
        except Exception as e:
            return ConnectionResult(
                success=False,
                error=f"Failed to reconnect: {e}"
            )
    
    def scan_network(self, network: str = "testnet") -> List[ConnectionResult]:
        """Scan for all available Lightning nodes on the network"""
        self.logger.info(f"Scanning for Lightning nodes on {network} network...")
        
        all_configs = self._get_network_configs(network)
        all_configs.extend(self._auto_detect_configurations(network))
        
        results = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self._test_connection, config) for config in all_configs]
            
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=5)
                    results.append(result)
                except Exception as e:
                    self.logger.debug(f"Scan test failed: {e}")
        
        # Sort by success and priority
        results.sort(key=lambda x: (x.success, x.config.priority if x.config else 0), reverse=True)
        return results
    
    def setup_wizard(self, interactive: bool = True) -> ConnectionResult:
        """Interactive setup wizard for Lightning connection"""
        if not interactive:
            return self.quick_connect()
        
        print("BLNCS Lightning Network Setup Wizard")
        print("=====================================")
        
        # Step 1: Network selection
        print("\n1. Select Network:")
        print("  1) Mainnet (Real Bitcoin)")
        print("  2) Testnet (Test Bitcoin)")
        print("  3) Regtest (Local Testing)")
        
        network_choice = input("Enter choice (1-3) [2]: ").strip() or "2"
        network_map = {"1": "mainnet", "2": "testnet", "3": "regtest"}
        network = network_map.get(network_choice, "testnet")
        
        print(f"\nSelected network: {network}")
        
        # Step 2: Auto-detection
        print("\n2. Scanning for Lightning nodes...")
        results = self.scan_network(network)
        
        successful_results = [r for r in results if r.success]
        
        if successful_results:
            print(f"\nFound {len(successful_results)} available node(s):")
            for i, result in enumerate(successful_results[:5], 1):
                node_info = result.node_info or {}
                alias = node_info.get('alias', 'Unknown')
                response_time = result.response_time * 1000
                print(f"  {i}) {result.config.name} - {alias} ({response_time:.0f}ms)")
            
            choice = input(f"\nSelect node (1-{min(len(successful_results), 5)}) [1]: ").strip() or "1"
            try:
                selected_result = successful_results[int(choice) - 1]
                self._save_successful_config(selected_result.config)
                print(f"\nConnection configured successfully!")
                return selected_result
            except (ValueError, IndexError):
                print("Invalid selection. Using first available node.")
                selected_result = successful_results[0]
                self._save_successful_config(selected_result.config)
                return selected_result
        else:
            print("\nNo Lightning nodes found. Please check your setup.")
            return ConnectionResult(
                success=False,
                error="No nodes found during setup wizard"
            )


def get_one_click_connector() -> OneClickConnector:
    """Get singleton OneClickConnector instance"""
    return OneClickConnector()