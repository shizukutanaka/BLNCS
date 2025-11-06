#!/usr/bin/env python3
"""
Lightning Network API Integration for BLNCS
Provides unified interface to Lightning Network nodes (LND, CLN, etc.)
"""

import os
import json
import logging
import requests
import time
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from pathlib import Path
import grpc
import codecs
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class LightningNodeConfig:
    """Lightning Network node configuration"""
    node_type: str = "lnd"  # lnd, cln, etc.
    host: str = "localhost"
    port: int = 10009  # LND default
    tls_cert_path: Optional[str] = None
    macaroon_path: Optional[str] = None
    network: str = "testnet"
    timeout: int = 30


class LightningAPI:
    """
    Unified Lightning Network API interface
    Supports multiple Lightning implementations (LND, CLN, etc.)
    """

    def __init__(self, config: Optional[LightningNodeConfig] = None):
        self.config = config or self._load_default_config()
        self.session = None
        self._setup_session()

    def _load_default_config(self) -> LightningNodeConfig:
        """Load configuration from environment or defaults"""
        return LightningNodeConfig(
            node_type=os.getenv("LIGHTNING_NODE_TYPE", "lnd"),
            host=os.getenv("LIGHTNING_HOST", "localhost"),
            port=int(os.getenv("LIGHTNING_PORT", "10009")),
            tls_cert_path=os.getenv("LIGHTNING_TLS_CERT"),
            macaroon_path=os.getenv("LIGHTNING_MACAROON"),
            network=os.getenv("LIGHTNING_NETWORK", "testnet"),
            timeout=int(os.getenv("LIGHTNING_TIMEOUT", "30"))
        )

    def _setup_session(self):
        """Setup HTTP session for API calls"""
        self.session = requests.Session()
        self.session.timeout = self.config.timeout

        # Add authentication headers if needed
        if self.config.macaroon_path and Path(self.config.macaroon_path).exists():
            try:
                with open(self.config.macaroon_path, 'rb') as f:
                    macaroon = codecs.encode(f.read(), 'hex').decode()
                self.session.headers.update({'Grpc-Metadata-macaroon': macaroon})
            except Exception as e:
                logger.warning(f"Failed to load macaroon: {e}")

    def _get_base_url(self) -> str:
        """Get base URL for REST API"""
        return f"https://{self.config.host}:{self.config.port}"

    def _make_request(self, method: str, endpoint: str, **kwargs) -> Optional[Dict]:
        """Make HTTP request to Lightning node"""
        try:
            url = f"{self._get_base_url()}{endpoint}"
            response = self.session.request(method, url, **kwargs)

            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"API request failed: {response.status_code} - {response.text}")
                return None

        except Exception as e:
            logger.error(f"API request error: {e}")
            return None

    def get_info(self) -> Optional[Dict]:
        """Get node information"""
        return self._make_request("GET", "/v1/getinfo")

    def list_channels(self) -> Optional[List]:
        """List all channels"""
        return self._make_request("GET", "/v1/channels")

    def list_peers(self) -> Optional[List]:
        """List connected peers"""
        return self._make_request("GET", "/v1/peers")

    def connect_peer(self, pubkey: str, address: str) -> bool:
        """Connect to a peer"""
        try:
            data = {
                "addr": {
                    "pubkey": pubkey,
                    "host": address
                }
            }
            result = self._make_request("POST", "/v1/peers", json=data)
            return result is not None
        except Exception as e:
            logger.error(f"Failed to connect peer: {e}")
            return False

    def disconnect_peer(self, pubkey: str) -> bool:
        """Disconnect from a peer"""
        try:
            result = self._make_request("DELETE", f"/v1/peers/{pubkey}")
            return result is not None
        except Exception as e:
            logger.error(f"Failed to disconnect peer: {e}")
            return False

    def get_balance(self) -> Optional[Dict]:
        """Get wallet balance"""
        return self._make_request("GET", "/v1/balance/blockchain")

    def list_payments(self) -> Optional[List]:
        """List payments"""
        return self._make_request("GET", "/v1/payments")

    def send_payment(self, payment_request: str, amount: Optional[int] = None) -> Optional[Dict]:
        """Send payment"""
        try:
            data = {"payment_request": payment_request}
            if amount:
                data["amt"] = amount

            return self._make_request("POST", "/v1/channels/transactions", json=data)
        except Exception as e:
            logger.error(f"Failed to send payment: {e}")
            return None

    def create_invoice(self, amount: int, description: str = "") -> Optional[Dict]:
        """Create invoice"""
        try:
            data = {
                "value": amount,
                "memo": description
            }
            return self._make_request("POST", "/v1/invoices", json=data)
        except Exception as e:
            logger.error(f"Failed to create invoice: {e}")
            return None

    def decode_payment_request(self, payment_request: str) -> Optional[Dict]:
        """Decode payment request"""
        try:
            data = {"pay_req": payment_request}
            return self._make_request("POST", "/v1/payreq", json=data)
        except Exception as e:
            logger.error(f"Failed to decode payment request: {e}")
            return None

    def close_channel(self, channel_point: str, force: bool = False) -> bool:
        """Close channel"""
        try:
            data = {
                "channel_point": channel_point,
                "force": force
            }
            result = self._make_request("DELETE", "/v1/channels", json=data)
            return result is not None
        except Exception as e:
            logger.error(f"Failed to close channel: {e}")
            return False

    def open_channel(self, node_pubkey: str, amount: int, private: bool = False) -> bool:
        """Open channel"""
        try:
            data = {
                "node_pubkey": node_pubkey,
                "local_funding_amount": amount,
                "private": private
            }
            result = self._make_request("POST", "/v1/channels", json=data)
            return result is not None
        except Exception as e:
            logger.error(f"Failed to open channel: {e}")
            return False

    def get_channel_info(self, chan_id: int) -> Optional[Dict]:
        """Get channel information"""
        return self._make_request("GET", f"/v1/channels/{chan_id}")

    def get_node_info(self, pubkey: str) -> Optional[Dict]:
        """Get node information"""
        return self._make_request("GET", f"/v1/graph/node/{pubkey}")

    def query_routes(self, pubkey: str, amount: int, num_routes: int = 1) -> Optional[List]:
        """Query routes to destination"""
        try:
            data = {
                "pub_key": pubkey,
                "amt": amount,
                "num_routes": num_routes
            }
            return self._make_request("POST", "/v1/graph/routes", json=data)
        except Exception as e:
            logger.error(f"Failed to query routes: {e}")
            return None

    def estimate_fee(self, addr: str, amount: int) -> Optional[Dict]:
        """Estimate fee for transaction"""
        try:
            data = {
                "AddrToAmount": {
                    addr: amount
                }
            }
            return self._make_request("POST", "/v1/transactions/estimatefee", json=data)
        except Exception as e:
            logger.error(f"Failed to estimate fee: {e}")
            return None

    def send_coins(self, addr: str, amount: int, sat_per_byte: int = 1) -> Optional[Dict]:
        """Send coins to address"""
        try:
            data = {
                "addr": addr,
                "amount": amount,
                "sat_per_byte": sat_per_byte
            }
            return self._make_request("POST", "/v1/transactions", json=data)
        except Exception as e:
            logger.error(f"Failed to send coins: {e}")
            return None

    def get_transactions(self) -> Optional[List]:
        """Get transaction history"""
        return self._make_request("GET", "/v1/transactions")

    def subscribe_channel_events(self) -> None:
        """Subscribe to channel events (WebSocket)"""
        # This would implement WebSocket subscription for real-time events
        logger.info("Channel event subscription not implemented yet")
        pass

    def subscribe_invoice_events(self) -> None:
        """Subscribe to invoice events (WebSocket)"""
        # This would implement WebSocket subscription for real-time invoice events
        logger.info("Invoice event subscription not implemented yet")
        pass

    def health_check(self) -> bool:
        """Perform health check on Lightning node"""
        try:
            info = self.get_info()
            return info is not None and info.get('synced_to_chain', False)
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False


# Convenience functions for global usage
def get_lightning_api(config: Optional[LightningNodeConfig] = None) -> LightningAPI:
    """Get global Lightning API instance"""
    return LightningAPI(config)


def test_lightning_connection(config: Optional[LightningNodeConfig] = None) -> bool:
    """Test connection to Lightning node"""
    api = LightningAPI(config)
    return api.health_check()


if __name__ == "__main__":
    # Test the API connection
    api = LightningAPI()
    print("Testing Lightning API connection...")
    if api.health_check():
        print("✅ Lightning node is healthy")
        info = api.get_info()
        if info:
            print(f"Node info: {info.get('alias', 'Unknown')} - Block: {info.get('block_height', 'Unknown')}")
    else:
        print("❌ Lightning node is not responding")
