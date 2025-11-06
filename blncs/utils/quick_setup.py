"""
Quick Setup Utility for BLNCS
Fast configuration and connection helper.
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

from ..core.config import get_config, save_config
from ..core.logger import get_logger

logger = get_logger(__name__)


def detect_lightning_node() -> Tuple[str, Dict[str, Any]]:
    """
    Quickly detect available Lightning node and return connection info
    Returns: (client_type, connection_config)
    """

    # Quick LND detection
    lnd_paths = [
        Path.home() / ".lnd",
        Path("/home/bitcoin/.lnd"),
        Path("/opt/lnd")
    ]

    for lnd_path in lnd_paths:
        if (lnd_path / "tls.cert").exists():
            macaroon_path = None
            for mac_path in [
                lnd_path / "data" / "chain" / "bitcoin" / "mainnet" / "admin.macaroon",
                lnd_path / "data" / "chain" / "bitcoin" / "testnet" / "admin.macaroon",
                lnd_path / "admin.macaroon"
            ]:
                if mac_path.exists():
                    macaroon_path = str(mac_path)
                    break

            return 'lnd', {
                'host': 'localhost',
                'grpc_port': 10009,
                'rest_port': 8080,
                'tls_cert_path': str(lnd_path / "tls.cert"),
                'macaroon_path': macaroon_path
            }

    # Quick Core Lightning detection
    cln_paths = [
        Path.home() / ".lightning",
        Path("/home/bitcoin/.lightning")
    ]

    for cln_path in cln_paths:
        rpc_socket = cln_path / "bitcoin" / "lightning-rpc"
        if rpc_socket.exists():
            return 'cln', {
                'host': 'localhost',
                'rest_port': 8080,
                'socket_path': str(rpc_socket)
            }

    # No real Lightning node found
    return 'mock', {'host': 'localhost', 'port': 0}


def auto_configure() -> bool:
    """Automatically configure BLNCS with detected Lightning node"""
    try:
        client_type, connection_config = detect_lightning_node()

        config = get_config()
        config.set('lightning.client_type', client_type)

        for key, value in connection_config.items():
            config.set(f'lightning.{key}', value)

        save_config()

        logger.info(f"Auto-configured for {client_type} Lightning implementation")
        return True

    except Exception as e:
        logger.error(f"Auto-configuration failed: {e}")
        return False


def quick_start() -> Dict[str, Any]:
    """Quick start setup and status check"""
    result = {
        'configured': False,
        'client_type': 'mock',
        'connection_status': 'disconnected',
        'config_path': None,
        'suggestions': []
    }

    # Auto-configure
    if auto_configure():
        result['configured'] = True
        result['config_path'] = get_config().config_file

    # Check connection
    try:
        from ..lightning.simple_client import get_lightning_client
        client = get_lightning_client()
        result['client_type'] = client.client_type

        if client.client_type != 'mock':
            info = client.get_info()
            result['connection_status'] = 'connected'
            result['node_alias'] = info.get('alias', 'Unknown')
        else:
            result['connection_status'] = 'mock'
            result['suggestions'].append("Install LND or Core Lightning for real functionality")

    except Exception as e:
        result['connection_status'] = 'error'
        result['error'] = str(e)
        result['suggestions'].append("Check Lightning node configuration")

    return result


def generate_sample_config() -> str:
    """Generate a sample configuration file"""
    sample_config = {
        "lightning": {
            "client_type": "auto",
            "host": "localhost",
            "grpc_port": 10009,
            "rest_port": 8080,
            "network": "mainnet",
            "tls_cert_path": "~/.lnd/tls.cert",
            "macaroon_path": "~/.lnd/data/chain/bitcoin/mainnet/admin.macaroon"
        },
        "api": {
            "host": "127.0.0.1",
            "port": 8080,
            "enable_cors": True
        },
        "dashboard": {
            "port": 8080,
            "auto_refresh": 30
        },
        "logging": {
            "level": "INFO",
            "file": "blncs.log"
        }
    }

    return json.dumps(sample_config, indent=2)


def health_check() -> Dict[str, Any]:
    """Perform system health check"""
    health = {
        'system': 'healthy',
        'components': {},
        'warnings': [],
        'errors': []
    }

    try:
        # Check configuration
        config = get_config()
        health['components']['config'] = 'ok'

        # Check Lightning client
        from ..lightning.simple_client import get_lightning_client
        client = get_lightning_client()

        if client.client_type == 'mock':
            health['components']['lightning'] = 'mock'
            health['warnings'].append("Using mock Lightning client")
        else:
            try:
                info = client.get_info()
                health['components']['lightning'] = 'connected'
                health['components']['channels'] = info.get('num_channels', 0)
            except Exception:
                health['components']['lightning'] = 'error'
                health['errors'].append("Lightning client connection failed")

        # Check dashboard
        try:
            from ..monitoring.dashboard import get_dashboard
            dashboard = get_dashboard()
            health['components']['dashboard'] = 'available'
        except Exception:
            health['components']['dashboard'] = 'error'
            health['errors'].append("Dashboard unavailable")

        # Overall health
        if health['errors']:
            health['system'] = 'degraded'
        elif health['warnings']:
            health['system'] = 'warning'

    except Exception as e:
        health['system'] = 'error'
        health['errors'].append(f"Health check failed: {e}")

    return health


if __name__ == "__main__":
    # Quick setup demo
    print("BLNCS Quick Setup")
    print("=================")

    status = quick_start()
    print(f"Configuration: {'✓' if status['configured'] else '✗'}")
    print(f"Client Type: {status['client_type']}")
    print(f"Connection: {status['connection_status']}")

    if status['suggestions']:
        print("\nSuggestions:")
        for suggestion in status['suggestions']:
            print(f"  • {suggestion}")

    print("\nSample config:")
    print(generate_sample_config())