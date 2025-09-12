"""
Simple Lightning Network Client
Direct implementation following Pike's "do one thing well" principle.
Enhanced with retry logic for improved stability.
"""

import json
import os
import time
import logging
from typing import Dict, Optional, List, Any
from pathlib import Path

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    requests = None

try:
    import grpc
    HAS_GRPC = True
except ImportError:
    HAS_GRPC = False
    grpc = None

from ..core.retry_helper import RetryableClient, standard_retry, RetryConfig


class LightningError(Exception):
    """Lightning network operation error"""
    pass


class ConnectionError(LightningError):
    """Connection-specific error"""
    pass


class SimpleClient(RetryableClient):
    """
    Simple Lightning Network client with retry capability.
    Does one thing: communicates with Lightning Network node.
    """
    
    def __init__(self, host='localhost', port=8080, cert_path=None, macaroon_path=None):
        # Initialize retry capability
        super().__init__(RetryConfig(max_attempts=3, initial_delay=1.0, max_delay=10.0))
        
        self.host = host
        self.port = port
        self.cert_path = cert_path
        self.macaroon_path = macaroon_path
        self.connected = False
        self._session = None
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
    def _get_session(self):
        """Get or create HTTP session"""
        if self._session is None and HAS_REQUESTS:
            self._session = requests.Session()
            self._session.verify = self.cert_path if self.cert_path else False
            
            # Add macaroon to headers if available
            if self.macaroon_path and os.path.exists(self.macaroon_path):
                with open(self.macaroon_path, 'rb') as f:
                    macaroon = f.read().hex()
                    self._session.headers.update({'Grpc-Metadata-macaroon': macaroon})
        
        return self._session
    
    def connect(self):
        """Connect to Lightning node with retry logic"""
        if not HAS_REQUESTS:
            raise LightningError("requests library required for HTTP connection")
        
        def _attempt_connection():
            session = self._get_session()
            if session:
                # Simple ping to test connection
                response = session.get(f"https://{self.host}:{self.port}/v1/getinfo", timeout=10)
                if response.status_code == 200:
                    self.connected = True
                    return True
                else:
                    raise ConnectionError(f"HTTP {response.status_code}: {response.text}")
            raise ConnectionError("Could not create session")
        
        try:
            return self.with_retry(_attempt_connection)
        except Exception as e:
            self.logger.error(f"Connection failed after retries: {e}")
            self.connected = False
            return False
    
    def disconnect(self):
        """Disconnect from Lightning node"""
        if self._session:
            self._session.close()
            self._session = None
        self.connected = False
    
    def get_info(self) -> Dict[str, Any]:
        """Get node information"""
        if not self.connected:
            if not self.connect():
                raise LightningError("Not connected to Lightning node")
        
        session = self._get_session()
        try:
            response = session.get(f"https://{self.host}:{self.port}/v1/getinfo", timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.logger.error(f"Failed to get node info: {e}")
            raise LightningError(f"Failed to get node info: {e}")
    
    def get_balance(self) -> Dict[str, Any]:
        """Get wallet balance"""
        if not self.connected:
            if not self.connect():
                raise LightningError("Not connected to Lightning node")
        
        session = self._get_session()
        try:
            response = session.get(f"https://{self.host}:{self.port}/v1/balance/blockchain", timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.logger.error(f"Failed to get balance: {e}")
            raise LightningError(f"Failed to get balance: {e}")
    
    def list_channels(self) -> Dict[str, Any]:
        """List Lightning channels"""
        if not self.connected:
            if not self.connect():
                raise LightningError("Not connected to Lightning node")
        
        session = self._get_session()
        try:
            response = session.get(f"https://{self.host}:{self.port}/v1/channels", timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.logger.error(f"Failed to list channels: {e}")
            raise LightningError(f"Failed to list channels: {e}")
    
    def create_invoice(self, amount_sats: int, memo: str = "") -> Dict[str, Any]:
        """Create payment invoice"""
        if not self.connected:
            if not self.connect():
                raise LightningError("Not connected to Lightning node")
        
        session = self._get_session()
        payload = {
            "value": amount_sats,
            "memo": memo,
            "expiry": 3600  # 1 hour expiry
        }
        
        try:
            response = session.post(
                f"https://{self.host}:{self.port}/v1/invoices",
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.logger.error(f"Failed to create invoice: {e}")
            raise LightningError(f"Failed to create invoice: {e}")
    
    def pay_invoice(self, payment_request: str) -> Dict[str, Any]:
        """Pay Lightning invoice"""
        if not self.connected:
            if not self.connect():
                raise LightningError("Not connected to Lightning node")
        
        session = self._get_session()
        payload = {"payment_request": payment_request}
        
        try:
            response = session.post(
                f"https://{self.host}:{self.port}/v1/channels/transactions",
                json=payload,
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.logger.error(f"Failed to pay invoice: {e}")
            raise LightningError(f"Failed to pay invoice: {e}")
    
    def open_channel(self, node_pubkey: str, local_funding_amount: int) -> Dict[str, Any]:
        """Open Lightning channel"""
        if not self.connected:
            if not self.connect():
                raise LightningError("Not connected to Lightning node")
        
        session = self._get_session()
        payload = {
            "node_pubkey": node_pubkey,
            "local_funding_amount": local_funding_amount,
            "push_sat": 0,
            "target_conf": 3
        }
        
        try:
            response = session.post(
                f"https://{self.host}:{self.port}/v1/channels",
                json=payload,
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.logger.error(f"Failed to open channel: {e}")
            raise LightningError(f"Failed to open channel: {e}")
    
    def close_channel(self, funding_txid: str, output_index: int, force: bool = False) -> Dict[str, Any]:
        """Close Lightning channel"""
        if not self.connected:
            if not self.connect():
                raise LightningError("Not connected to Lightning node")
        
        session = self._get_session()
        
        try:
            response = session.delete(
                f"https://{self.host}:{self.port}/v1/channels/{funding_txid}/{output_index}?force={force}",
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.logger.error(f"Failed to close channel: {e}")
            raise LightningError(f"Failed to close channel: {e}")
    
    def decode_payment_request(self, payment_request: str) -> Dict[str, Any]:
        """Decode Lightning payment request"""
        if not self.connected:
            if not self.connect():
                raise LightningError("Not connected to Lightning node")
        
        session = self._get_session()
        try:
            response = session.get(
                f"https://{self.host}:{self.port}/v1/payreq/{payment_request}",
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.logger.error(f"Failed to decode payment request: {e}")
            raise LightningError(f"Failed to decode payment request: {e}")


class EnhancedClient(SimpleClient):
    """Enhanced Lightning client with additional features"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cached_info = None
        self._cache_timestamp = 0
        self._cache_ttl = 30  # 30 seconds cache TTL
    
    def get_info_cached(self) -> Dict[str, Any]:
        """Get node info with caching"""
        current_time = time.time()
        if (self._cached_info is None or 
            current_time - self._cache_timestamp > self._cache_ttl):
            self._cached_info = self.get_info()
            self._cache_timestamp = current_time
        return self._cached_info
    
    def get_channel_balance(self) -> Dict[str, Any]:
        """Get Lightning channel balance"""
        if not self.connected:
            if not self.connect():
                raise LightningError("Not connected to Lightning node")
        
        session = self._get_session()
        try:
            response = session.get(f"https://{self.host}:{self.port}/v1/balance/channels", timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.logger.error(f"Failed to get channel balance: {e}")
            raise LightningError(f"Failed to get channel balance: {e}")
    
    def get_network_info(self) -> Dict[str, Any]:
        """Get Lightning network information"""
        if not self.connected:
            if not self.connect():
                raise LightningError("Not connected to Lightning node")
        
        session = self._get_session()
        try:
            response = session.get(f"https://{self.host}:{self.port}/v1/graph/info", timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.logger.error(f"Failed to get network info: {e}")
            raise LightningError(f"Failed to get network info: {e}")
    
    def get_pending_channels(self) -> Dict[str, Any]:
        """Get pending channels"""
        if not self.connected:
            if not self.connect():
                raise LightningError("Not connected to Lightning node")
        
        session = self._get_session()
        try:
            response = session.get(f"https://{self.host}:{self.port}/v1/channels/pending", timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.logger.error(f"Failed to get pending channels: {e}")
            raise LightningError(f"Failed to get pending channels: {e}")
    
    def get_transactions(self, start_height: Optional[int] = None, end_height: Optional[int] = None) -> Dict[str, Any]:
        """Get on-chain transactions"""
        if not self.connected:
            if not self.connect():
                raise LightningError("Not connected to Lightning node")
        
        session = self._get_session()
        params = {}
        if start_height:
            params['start_height'] = start_height
        if end_height:
            params['end_height'] = end_height
        
        try:
            response = session.get(
                f"https://{self.host}:{self.port}/v1/transactions",
                params=params,
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.logger.error(f"Failed to get transactions: {e}")
            raise LightningError(f"Failed to get transactions: {e}")
    
    def get_payments(self) -> Dict[str, Any]:
        """Get Lightning payments"""
        if not self.connected:
            if not self.connect():
                raise LightningError("Not connected to Lightning node")
        
        session = self._get_session()
        try:
            response = session.get(f"https://{self.host}:{self.port}/v1/payments", timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.logger.error(f"Failed to get payments: {e}")
            raise LightningError(f"Failed to get payments: {e}")
    
    def get_invoices(self, pending_only: bool = False, num_max_invoices: int = 100) -> Dict[str, Any]:
        """Get Lightning invoices"""
        if not self.connected:
            if not self.connect():
                raise LightningError("Not connected to Lightning node")
        
        session = self._get_session()
        params = {
            'pending_only': str(pending_only).lower(),
            'num_max_invoices': num_max_invoices
        }
        
        try:
            response = session.get(
                f"https://{self.host}:{self.port}/v1/invoices",
                params=params,
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.logger.error(f"Failed to get invoices: {e}")
            raise LightningError(f"Failed to get invoices: {e}")


def create_client(host='localhost', port=8080, cert_path=None, macaroon_path=None, enhanced=False):
    """Factory function to create Lightning client"""
    if enhanced:
        return EnhancedClient(host, port, cert_path, macaroon_path)
    return SimpleClient(host, port, cert_path, macaroon_path)


# Utility functions
def format_satoshis(satoshis: int) -> str:
    """Format satoshis as Bitcoin amount"""
    btc = satoshis / 100_000_000
    return f"{btc:.8f} BTC"


def parse_payment_request(payment_request: str) -> Dict[str, Any]:
    """Basic payment request parsing (simplified)"""
    # This is a very basic implementation
    # In production, use proper BOLT11 decoder
    if not payment_request.startswith(('lnbc', 'lntb', 'lnbcrt')):
        raise ValueError("Invalid payment request format")
    
    return {
        "network": payment_request[:4],
        "amount": None,  # Would need proper parsing
        "description": "",
        "payment_hash": "",
        "expiry": 3600
    }