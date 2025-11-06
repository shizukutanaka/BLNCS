#!/usr/bin/env python3
"""
Lightning Network Client for BLNCS
Production-ready client supporting multiple implementations
"""

import os
import json
import time
import logging
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class NodeType(Enum):
    """Lightning node implementation types"""
    LND = "lnd"
    CLN = "cln"
    ECLAIR = "eclair"
    MOCK = "mock"


class PaymentStatus(Enum):
    """Payment status"""
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    IN_FLIGHT = "in_flight"


@dataclass
class ChannelInfo:
    """Channel information"""
    channel_id: str
    peer_id: str
    capacity: int
    local_balance: int
    remote_balance: int
    active: bool = True
    channel_point: Optional[str] = None
    fee_per_kw: int = 1000


@dataclass
class PaymentInfo:
    """Payment information"""
    payment_hash: str
    payment_request: str
    amount: int
    status: str
    fee: int = 0
    timestamp: float = field(default_factory=time.time)
    route: Optional[List[str]] = None
    attempts: int = 1


@dataclass
class InvoiceInfo:
    """Invoice information"""
    payment_hash: str
    payment_request: str
    amount: int
    description: str
    status: str = "pending"
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None

    def __post_init__(self):
        if self.expires_at is None:
            self.expires_at = self.created_at + 3600


@dataclass
class NodeInfo:
    """Node information"""
    alias: str
    identity_pubkey: str
    num_active_channels: int = 0
    num_inactive_channels: int = 0
    num_pending_channels: int = 0
    block_height: int = 0
    synced_to_chain: bool = False
    connected: bool = False
    version: str = "unknown"
    network: str = "testnet"


class LightningClientBase(ABC):
    """Base class for Lightning Network clients"""

    @abstractmethod
    def connect(self) -> bool:
        """Connect to Lightning node"""
        pass

    @abstractmethod
    def disconnect(self):
        """Disconnect from Lightning node"""
        pass

    @abstractmethod
    def get_node_info(self) -> NodeInfo:
        """Get node information"""
        pass

    @abstractmethod
    def list_channels(self) -> List[ChannelInfo]:
        """List all channels"""
        pass

    @abstractmethod
    def create_invoice(self, amount: int, description: str, **kwargs) -> InvoiceInfo:
        """Create an invoice"""
        pass

    @abstractmethod
    def pay_invoice(self, payment_request: str, **kwargs) -> PaymentInfo:
        """Pay an invoice"""
        pass

    @abstractmethod
    def decode_invoice(self, payment_request: str) -> Dict[str, Any]:
        """Decode an invoice"""
        pass


class MockLightningClient(LightningClientBase):
    """Mock Lightning client for testing"""

    def __init__(
        self,
        node_url: Optional[str] = None,
        macaroon_path: Optional[str] = None,
        tls_cert_path: Optional[str] = None,
        network: str = "testnet"
    ):
        self.node_url = node_url or 'localhost:10009'
        self.macaroon_path = macaroon_path
        self.tls_cert_path = tls_cert_path
        self.network = network

        self.channels: Dict[str, ChannelInfo] = {}
        self.payments: Dict[str, PaymentInfo] = {}
        self.invoices: Dict[str, InvoiceInfo] = {}

        self.node_info = NodeInfo(
            alias='BLNCS_Mock_Node',
            identity_pubkey=f'mock_{os.urandom(16).hex()}',
            num_active_channels=0,
            synced_to_chain=True,
            connected=True,
            version='0.1.0-mock',
            network=network
        )

    def connect(self) -> bool:
        """Connect to mock node"""
        logger.info(f"Mock client connected to {self.node_url}")
        self.node_info.connected = True
        return True

    def disconnect(self):
        """Disconnect from mock node"""
        logger.info("Mock client disconnected")
        self.node_info.connected = False

    def get_node_info(self) -> NodeInfo:
        """Get mock node info"""
        return self.node_info

    def list_channels(self) -> List[ChannelInfo]:
        """List mock channels"""
        return list(self.channels.values())

    def create_invoice(self, amount: int, description: str, **kwargs) -> InvoiceInfo:
        """Create mock invoice"""
        payment_hash = os.urandom(32).hex()
        payment_request = f"lntb{amount}1mock{payment_hash[:20]}"

        invoice = InvoiceInfo(
            payment_hash=payment_hash,
            payment_request=payment_request,
            amount=amount,
            description=description
        )

        self.invoices[payment_hash] = invoice
        logger.info(f"Created mock invoice: {payment_hash[:16]}...")
        return invoice

    def pay_invoice(self, payment_request: str, **kwargs) -> PaymentInfo:
        """Pay mock invoice"""
        payment_hash = os.urandom(32).hex()

        # Decode amount from invoice (simplified)
        amount = 1000  # Default amount

        payment = PaymentInfo(
            payment_hash=payment_hash,
            payment_request=payment_request,
            amount=amount,
            status=PaymentStatus.SUCCEEDED.value,
            fee=10
        )

        self.payments[payment_hash] = payment
        logger.info(f"Mock payment succeeded: {payment_hash[:16]}...")
        return payment

    def decode_invoice(self, payment_request: str) -> Dict[str, Any]:
        """Decode mock invoice"""
        return {
            'payment_hash': os.urandom(32).hex(),
            'description': 'Mock invoice',
            'amount': 1000,
            'timestamp': int(time.time()),
            'expiry': 3600
        }

    def get_balance(self) -> Dict[str, int]:
        """Get mock balance"""
        return {
            'total_balance': 1000000,
            'confirmed_balance': 1000000,
            'unconfirmed_balance': 0
        }

    def open_channel(self, peer_pubkey: str, amount: int, **kwargs) -> ChannelInfo:
        """Open mock channel"""
        channel_id = os.urandom(8).hex()

        channel = ChannelInfo(
            channel_id=channel_id,
            peer_id=peer_pubkey,
            capacity=amount,
            local_balance=amount,
            remote_balance=0,
            active=True
        )

        self.channels[channel_id] = channel
        self.node_info.num_active_channels += 1
        logger.info(f"Opened mock channel: {channel_id}")
        return channel

    def close_channel(self, channel_id: str, force: bool = False) -> bool:
        """Close mock channel"""
        if channel_id in self.channels:
            del self.channels[channel_id]
            self.node_info.num_active_channels -= 1
            logger.info(f"Closed mock channel: {channel_id}")
            return True
        return False


class LNDClient(LightningClientBase):
    """LND Lightning client"""

    def __init__(
        self,
        node_url: str,
        macaroon_path: str,
        tls_cert_path: str,
        network: str = "testnet"
    ):
        self.node_url = node_url
        self.macaroon_path = macaroon_path
        self.tls_cert_path = tls_cert_path
        self.network = network
        self.stub = None
        self.connected = False

    def connect(self) -> bool:
        """Connect to LND node"""
        try:
            import grpc
            from lnd_grpc import lnd_grpc

            # Load credentials
            with open(self.macaroon_path, 'rb') as f:
                macaroon = f.read()

            with open(self.tls_cert_path, 'rb') as f:
                cert = f.read()

            # Create channel
            creds = grpc.ssl_channel_credentials(cert)
            channel = grpc.secure_channel(self.node_url, creds)

            # Create stub
            self.stub = lnd_grpc.LightningStub(channel)
            self.connected = True

            logger.info(f"Connected to LND node: {self.node_url}")
            return True

        except Exception as e:
            logger.error(f"Failed to connect to LND: {e}")
            return False

    def disconnect(self):
        """Disconnect from LND"""
        self.stub = None
        self.connected = False

    def get_node_info(self) -> NodeInfo:
        """Get LND node info"""
        if not self.connected:
            raise ConnectionError("Not connected to LND")

        info = self.stub.GetInfo()
        return NodeInfo(
            alias=info.alias,
            identity_pubkey=info.identity_pubkey,
            num_active_channels=info.num_active_channels,
            num_inactive_channels=info.num_inactive_channels,
            num_pending_channels=info.num_pending_channels,
            block_height=info.block_height,
            synced_to_chain=info.synced_to_chain,
            connected=True,
            version=info.version,
            network=self.network
        )

    def list_channels(self) -> List[ChannelInfo]:
        """List LND channels"""
        if not self.connected:
            raise ConnectionError("Not connected to LND")

        response = self.stub.ListChannels()
        channels = []

        for ch in response.channels:
            channels.append(ChannelInfo(
                channel_id=str(ch.chan_id),
                peer_id=ch.remote_pubkey,
                capacity=ch.capacity,
                local_balance=ch.local_balance,
                remote_balance=ch.remote_balance,
                active=ch.active,
                channel_point=ch.channel_point
            ))

        return channels

    def create_invoice(self, amount: int, description: str, **kwargs) -> InvoiceInfo:
        """Create LND invoice"""
        if not self.connected:
            raise ConnectionError("Not connected to LND")

        from lnd_grpc import ln

        invoice = self.stub.AddInvoice(ln.Invoice(
            value=amount,
            memo=description,
            expiry=kwargs.get('expiry', 3600)
        ))

        return InvoiceInfo(
            payment_hash=invoice.r_hash.hex(),
            payment_request=invoice.payment_request,
            amount=amount,
            description=description
        )

    def pay_invoice(self, payment_request: str, **kwargs) -> PaymentInfo:
        """Pay LND invoice"""
        if not self.connected:
            raise ConnectionError("Not connected to LND")

        from lnd_grpc import ln

        response = self.stub.SendPaymentSync(ln.SendRequest(
            payment_request=payment_request,
            timeout_seconds=kwargs.get('timeout', 60)
        ))

        return PaymentInfo(
            payment_hash=response.payment_hash.hex(),
            payment_request=payment_request,
            amount=response.payment_route.total_amt,
            status=PaymentStatus.SUCCEEDED.value if not response.payment_error else PaymentStatus.FAILED.value,
            fee=response.payment_route.total_fees
        )

    def decode_invoice(self, payment_request: str) -> Dict[str, Any]:
        """Decode LND invoice"""
        if not self.connected:
            raise ConnectionError("Not connected to LND")

        from lnd_grpc import ln

        decoded = self.stub.DecodePayReq(ln.PayReqString(pay_req=payment_request))

        return {
            'payment_hash': decoded.payment_hash,
            'description': decoded.description,
            'amount': decoded.num_satoshis,
            'timestamp': decoded.timestamp,
            'expiry': decoded.expiry
        }


def create_lightning_client(
    node_type: str = "mock",
    node_url: Optional[str] = None,
    macaroon_path: Optional[str] = None,
    tls_cert_path: Optional[str] = None,
    network: str = "testnet",
    **kwargs
) -> LightningClientBase:
    """Factory function to create Lightning client"""

    node_type = node_type.lower()

    if node_type == NodeType.MOCK.value or node_type == "test":
        return MockLightningClient(node_url, macaroon_path, tls_cert_path, network)

    elif node_type == NodeType.LND.value:
        if not node_url or not macaroon_path or not tls_cert_path:
            raise ValueError("LND requires node_url, macaroon_path, and tls_cert_path")
        return LNDClient(node_url, macaroon_path, tls_cert_path, network)

    else:
        raise ValueError(f"Unsupported node type: {node_type}")


__all__ = [
    'LightningClientBase',
    'MockLightningClient',
    'LNDClient',
    'create_lightning_client',
    'NodeType',
    'PaymentStatus',
    'ChannelInfo',
    'PaymentInfo',
    'InvoiceInfo',
    'NodeInfo'
]
