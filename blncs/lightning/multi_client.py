"""
Multi-Lightning Implementation Support
Provides unified interface for LND, Core Lightning (CLN), and Eclair.
"""

import asyncio
import json
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
import grpc
from datetime import datetime, timezone

from ..domain.models import (
    NodeId, ChannelId, Amount, LightningNode, Channel, Payment, Invoice,
    PaymentStatus, ChannelState, ChannelBalance, FeePolicy
)
from ..infrastructure.resilience import circuit_breaker, retry, resilient
from ..core.structured_logging import StructuredLogger


class LightningImplementation(Enum):
    """Lightning Network implementation types."""
    LND = "lnd"
    CLN = "cln"
    ECLAIR = "eclair"
    LNBITS = "lnbits"  # For testing and development


@dataclass
class ConnectionConfig:
    """Connection configuration for Lightning implementations."""
    implementation: LightningImplementation
    host: str
    port: int
    tls_cert_path: Optional[str] = None
    macaroon_path: Optional[str] = None
    rpc_user: Optional[str] = None
    rpc_password: Optional[str] = None
    api_key: Optional[str] = None
    timeout: int = 30
    max_retries: int = 3
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return asdict(self)


@dataclass
class NodeInfo:
    """Lightning node information."""
    public_key: str
    alias: str
    color: str
    version: str
    num_peers: int
    num_active_channels: int
    num_pending_channels: int
    block_height: int
    synced_to_chain: bool
    synced_to_graph: bool
    testnet: bool
    chains: List[str]
    uris: List[str]


class LightningClientInterface(ABC):
    """Abstract interface for Lightning Network clients."""
    
    @abstractmethod
    async def connect(self) -> bool:
        """Connect to the Lightning node."""
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        """Disconnect from the Lightning node."""
        pass
    
    @abstractmethod
    async def get_info(self) -> NodeInfo:
        """Get node information."""
        pass
    
    @abstractmethod
    async def get_balance(self) -> Dict[str, int]:
        """Get wallet balance."""
        pass
    
    @abstractmethod
    async def list_channels(self) -> List[Dict[str, Any]]:
        """List all channels."""
        pass
    
    @abstractmethod
    async def get_channel(self, channel_id: str) -> Optional[Dict[str, Any]]:
        """Get specific channel information."""
        pass
    
    @abstractmethod
    async def open_channel(self, node_pubkey: str, amount: int, 
                          push_amount: int = 0, private: bool = False) -> str:
        """Open a channel."""
        pass
    
    @abstractmethod
    async def close_channel(self, channel_id: str, force: bool = False) -> str:
        """Close a channel."""
        pass
    
    @abstractmethod
    async def send_payment(self, payment_request: str, 
                          amount: Optional[int] = None) -> Dict[str, Any]:
        """Send a payment."""
        pass
    
    @abstractmethod
    async def create_invoice(self, amount: int, description: str = "",
                           expiry: int = 3600) -> Dict[str, Any]:
        """Create an invoice."""
        pass
    
    @abstractmethod
    async def decode_invoice(self, payment_request: str) -> Dict[str, Any]:
        """Decode a payment request."""
        pass
    
    @abstractmethod
    async def list_payments(self, limit: int = 100) -> List[Dict[str, Any]]:
        """List payments."""
        pass
    
    @abstractmethod
    async def list_invoices(self, limit: int = 100) -> List[Dict[str, Any]]:
        """List invoices."""
        pass
    
    @abstractmethod
    async def update_channel_policy(self, channel_id: str, 
                                   base_fee_msat: int, fee_rate_ppm: int,
                                   time_lock_delta: int) -> bool:
        """Update channel fee policy."""
        pass


class LNDClient(LightningClientInterface):
    """LND Lightning Network client."""
    
    def __init__(self, config: ConnectionConfig):
        self.config = config
        self.logger = StructuredLogger("lightning.lnd")
        self.channel = None
        self.stub = None
        self._connected = False
        
    @resilient(
        circuit_breaker_name="lnd_connection",
        retry_name="lnd_retry",
        bulkhead_name="lnd_calls",
        circuit_breaker={"failure_threshold": 3, "recovery_timeout": 60},
        retry={"max_attempts": 3, "base_delay": 1.0},
        bulkhead={"max_concurrent_calls": 10}
    )
    async def connect(self) -> bool:
        """Connect to LND node."""
        try:
            # Import LND gRPC modules
            import grpc
            import lnd_grpc
            
            # Load TLS certificate
            if self.config.tls_cert_path:
                with open(self.config.tls_cert_path, 'rb') as f:
                    cert = f.read()
                ssl_creds = grpc.ssl_channel_credentials(cert)
            else:
                ssl_creds = grpc.ssl_channel_credentials()
            
            # Create gRPC channel
            self.channel = grpc.aio.secure_channel(
                f'{self.config.host}:{self.config.port}',
                ssl_creds
            )
            
            # Create stub
            self.stub = lnd_grpc.LightningStub(self.channel)
            
            # Load macaroon if provided
            if self.config.macaroon_path:
                with open(self.config.macaroon_path, 'rb') as f:
                    macaroon = f.read().hex()
                    
                def metadata_callback(context, callback):
                    callback([('macaroon', macaroon)], None)
                
                auth_creds = grpc.metadata_call_credentials(metadata_callback)
                combined_creds = grpc.composite_channel_credentials(ssl_creds, auth_creds)
                
                self.channel = grpc.aio.secure_channel(
                    f'{self.config.host}:{self.config.port}',
                    combined_creds
                )
                self.stub = lnd_grpc.LightningStub(self.channel)
            
            # Test connection
            await self.get_info()
            self._connected = True
            
            self.logger.info("Successfully connected to LND", 
                           extra={"host": self.config.host, "port": self.config.port})
            return True
            
        except Exception as e:
            self.logger.error("Failed to connect to LND", 
                            extra={"error": str(e)})
            return False
    
    async def disconnect(self) -> None:
        """Disconnect from LND."""
        if self.channel:
            await self.channel.close()
            self.channel = None
            self.stub = None
            self._connected = False
            self.logger.info("Disconnected from LND")
    
    async def get_info(self) -> NodeInfo:
        """Get LND node information."""
        request = lnd_grpc.GetInfoRequest()
        response = await self.stub.GetInfo(request, timeout=self.config.timeout)
        
        return NodeInfo(
            public_key=response.identity_pubkey,
            alias=response.alias,
            color=response.color,
            version=response.version,
            num_peers=response.num_peers,
            num_active_channels=response.num_active_channels,
            num_pending_channels=response.num_pending_channels,
            block_height=response.block_height,
            synced_to_chain=response.synced_to_chain,
            synced_to_graph=response.synced_to_graph,
            testnet=response.testnet,
            chains=[chain for chain in response.chains],
            uris=response.uris
        )
    
    async def get_balance(self) -> Dict[str, int]:
        """Get wallet balance from LND."""
        # Get on-chain balance
        wallet_request = lnd_grpc.WalletBalanceRequest()
        wallet_response = await self.stub.WalletBalance(wallet_request)
        
        # Get channel balance
        channel_request = lnd_grpc.ChannelBalanceRequest()
        channel_response = await self.stub.ChannelBalance(channel_request)
        
        return {
            'confirmed_balance': wallet_response.confirmed_balance,
            'unconfirmed_balance': wallet_response.unconfirmed_balance,
            'local_balance': channel_response.local_balance,
            'remote_balance': channel_response.remote_balance,
            'pending_open_local_balance': channel_response.pending_open_local_balance,
            'pending_open_remote_balance': channel_response.pending_open_remote_balance
        }
    
    async def list_channels(self) -> List[Dict[str, Any]]:
        """List all channels from LND."""
        request = lnd_grpc.ListChannelsRequest()
        response = await self.stub.ListChannels(request)
        
        channels = []
        for channel in response.channels:
            channels.append({
                'channel_id': channel.chan_id,
                'channel_point': channel.channel_point,
                'remote_pubkey': channel.remote_pubkey,
                'capacity': channel.capacity,
                'local_balance': channel.local_balance,
                'remote_balance': channel.remote_balance,
                'commit_fee': channel.commit_fee,
                'fee_per_kw': channel.fee_per_kw,
                'active': channel.active,
                'private': channel.private,
                'initiator': channel.initiator
            })
        
        return channels
    
    # Additional LND-specific methods would be implemented here...


class CLNClient(LightningClientInterface):
    """Core Lightning (CLN) client implementation."""
    
    def __init__(self, config: ConnectionConfig):
        self.config = config
        self.logger = StructuredLogger("lightning.cln")
        self._socket = None
        self._connected = False
    
    @resilient(
        circuit_breaker_name="cln_connection",
        retry_name="cln_retry",
        bulkhead_name="cln_calls"
    )
    async def connect(self) -> bool:
        """Connect to CLN node via Unix socket or TCP."""
        try:
            import json
            import socket
            
            if self.config.host.startswith('/'):
                # Unix socket connection
                self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self._socket.connect(self.config.host)
            else:
                # TCP connection
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.connect((self.config.host, self.config.port))
            
            # Test connection with getinfo
            await self.get_info()
            self._connected = True
            
            self.logger.info("Successfully connected to CLN",
                           extra={"host": self.config.host})
            return True
            
        except Exception as e:
            self.logger.error("Failed to connect to CLN",
                            extra={"error": str(e)})
            return False
    
    async def disconnect(self) -> None:
        """Disconnect from CLN."""
        if self._socket:
            self._socket.close()
            self._socket = None
            self._connected = False
            self.logger.info("Disconnected from CLN")
    
    async def _send_command(self, method: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Send JSON-RPC command to CLN."""
        if not self._socket:
            raise ConnectionError("Not connected to CLN")
        
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": 1
        }
        
        request_json = json.dumps(request) + '\n'
        self._socket.send(request_json.encode())
        
        response_data = self._socket.recv(8192).decode()
        response = json.loads(response_data)
        
        if "error" in response:
            raise Exception(f"CLN RPC error: {response['error']}")
        
        return response.get("result", {})
    
    async def get_info(self) -> NodeInfo:
        """Get CLN node information."""
        info = await self._send_command("getinfo")
        
        return NodeInfo(
            public_key=info["id"],
            alias=info.get("alias", ""),
            color=info.get("color", "#000000"),
            version=info.get("version", ""),
            num_peers=len(info.get("address", [])),
            num_active_channels=info.get("num_active_channels", 0),
            num_pending_channels=info.get("num_pending_channels", 0),
            block_height=info.get("blockheight", 0),
            synced_to_chain=True,  # CLN doesn't provide this directly
            synced_to_graph=True,  # CLN doesn't provide this directly
            testnet=info.get("network") == "testnet",
            chains=[info.get("network", "bitcoin")],
            uris=[f"{info['id']}@{addr}" for addr in info.get("address", [])]
        )
    
    # Additional CLN methods would be implemented here...


class EclairClient(LightningClientInterface):
    """Eclair Lightning Network client."""
    
    def __init__(self, config: ConnectionConfig):
        self.config = config
        self.logger = StructuredLogger("lightning.eclair")
        self._session = None
        self._connected = False
    
    @resilient(
        circuit_breaker_name="eclair_connection",
        retry_name="eclair_retry",
        bulkhead_name="eclair_calls"
    )
    async def connect(self) -> bool:
        """Connect to Eclair via REST API."""
        try:
            import aiohttp
            import base64
            
            # Create session with authentication
            auth_string = f"{self.config.rpc_user}:{self.config.rpc_password}"
            auth_bytes = auth_string.encode('ascii')
            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
            
            headers = {
                'Authorization': f'Basic {auth_b64}',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            # Always use proper SSL verification, configure certificates if needed
            connector = aiohttp.TCPConnector()
            
            self._session = aiohttp.ClientSession(
                headers=headers,
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            )
            
            # Test connection
            await self.get_info()
            self._connected = True
            
            self.logger.info("Successfully connected to Eclair",
                           extra={"host": self.config.host, "port": self.config.port})
            return True
            
        except Exception as e:
            self.logger.error("Failed to connect to Eclair",
                            extra={"error": str(e)})
            return False
    
    async def disconnect(self) -> None:
        """Disconnect from Eclair."""
        if self._session:
            await self._session.close()
            self._session = None
            self._connected = False
            self.logger.info("Disconnected from Eclair")
    
    async def _post_request(self, endpoint: str, data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Send POST request to Eclair API."""
        if not self._session:
            raise ConnectionError("Not connected to Eclair")
        
        url = f"http://{self.config.host}:{self.config.port}/{endpoint}"
        
        async with self._session.post(url, data=data or {}) as response:
            if response.status == 200:
                return await response.json()
            else:
                raise Exception(f"Eclair API error: {response.status}")
    
    async def get_info(self) -> NodeInfo:
        """Get Eclair node information."""
        info = await self._post_request("getinfo")
        
        return NodeInfo(
            public_key=info["nodeId"],
            alias=info.get("alias", ""),
            color=info.get("color", "#000000"),
            version=info.get("version", ""),
            num_peers=0,  # Eclair doesn't provide this in getinfo
            num_active_channels=0,  # Need to get from channels endpoint
            num_pending_channels=0,  # Need to get from channels endpoint
            block_height=info.get("blockHeight", 0),
            synced_to_chain=True,  # Eclair doesn't provide this directly
            synced_to_graph=True,  # Eclair doesn't provide this directly
            testnet=info.get("chainHash") != "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
            chains=["bitcoin"],
            uris=info.get("publicAddresses", [])
        )
    
    # Additional Eclair methods would be implemented here...


class LightningClientFactory:
    """Factory for creating Lightning client instances."""
    
    _clients = {
        LightningImplementation.LND: LNDClient,
        LightningImplementation.CLN: CLNClient,
        LightningImplementation.ECLAIR: EclairClient
    }
    
    @classmethod
    def create_client(cls, config: ConnectionConfig) -> LightningClientInterface:
        """Create Lightning client based on implementation type."""
        client_class = cls._clients.get(config.implementation)
        
        if not client_class:
            raise ValueError(f"Unsupported Lightning implementation: {config.implementation}")
        
        return client_class(config)
    
    @classmethod
    def get_supported_implementations(cls) -> List[LightningImplementation]:
        """Get list of supported Lightning implementations."""
        return list(cls._clients.keys())


class MultiLightningManager:
    """Manager for multiple Lightning implementations."""
    
    def __init__(self):
        self.clients: Dict[str, LightningClientInterface] = {}
        self.configs: Dict[str, ConnectionConfig] = {}
        self.logger = StructuredLogger("lightning.multi_manager")
        self._active_client_id: Optional[str] = None
    
    async def add_client(self, client_id: str, config: ConnectionConfig) -> bool:
        """Add a Lightning client."""
        try:
            client = LightningClientFactory.create_client(config)
            connected = await client.connect()
            
            if connected:
                self.clients[client_id] = client
                self.configs[client_id] = config
                
                # Set as active client if it's the first one
                if not self._active_client_id:
                    self._active_client_id = client_id
                
                self.logger.info("Added Lightning client",
                               extra={
                                   "client_id": client_id,
                                   "implementation": config.implementation.value,
                                   "host": config.host
                               })
                return True
            else:
                self.logger.error("Failed to connect Lightning client",
                                extra={"client_id": client_id})
                return False
                
        except Exception as e:
            self.logger.error("Error adding Lightning client",
                            extra={"client_id": client_id, "error": str(e)})
            return False
    
    async def remove_client(self, client_id: str) -> bool:
        """Remove a Lightning client."""
        if client_id in self.clients:
            client = self.clients[client_id]
            await client.disconnect()
            
            del self.clients[client_id]
            del self.configs[client_id]
            
            # Update active client if necessary
            if self._active_client_id == client_id:
                self._active_client_id = next(iter(self.clients.keys()), None)
            
            self.logger.info("Removed Lightning client", extra={"client_id": client_id})
            return True
        
        return False
    
    def get_client(self, client_id: Optional[str] = None) -> Optional[LightningClientInterface]:
        """Get Lightning client by ID or active client."""
        target_id = client_id or self._active_client_id
        return self.clients.get(target_id)
    
    def set_active_client(self, client_id: str) -> bool:
        """Set active Lightning client."""
        if client_id in self.clients:
            self._active_client_id = client_id
            self.logger.info("Set active Lightning client", extra={"client_id": client_id})
            return True
        return False
    
    def get_active_client_id(self) -> Optional[str]:
        """Get active client ID."""
        return self._active_client_id
    
    def list_clients(self) -> Dict[str, Dict[str, Any]]:
        """List all registered clients."""
        result = {}
        for client_id, config in self.configs.items():
            result[client_id] = {
                'implementation': config.implementation.value,
                'host': config.host,
                'port': config.port,
                'active': client_id == self._active_client_id,
                'connected': client_id in self.clients
            }
        return result
    
    async def get_all_balances(self) -> Dict[str, Dict[str, int]]:
        """Get balances from all connected clients."""
        balances = {}
        
        for client_id, client in self.clients.items():
            try:
                balance = await client.get_balance()
                balances[client_id] = balance
            except Exception as e:
                self.logger.error("Failed to get balance",
                                extra={"client_id": client_id, "error": str(e)})
                balances[client_id] = {"error": str(e)}
        
        return balances
    
    async def get_all_node_info(self) -> Dict[str, NodeInfo]:
        """Get node information from all connected clients."""
        node_infos = {}
        
        for client_id, client in self.clients.items():
            try:
                info = await client.get_info()
                node_infos[client_id] = info
            except Exception as e:
                self.logger.error("Failed to get node info",
                                extra={"client_id": client_id, "error": str(e)})
        
        return node_infos
    
    async def close_all(self) -> None:
        """Close all client connections."""
        for client_id in list(self.clients.keys()):
            await self.remove_client(client_id)
        
        self.logger.info("Closed all Lightning client connections")


# Global multi-lightning manager instance
_multi_lightning_manager: Optional[MultiLightningManager] = None


def get_multi_lightning_manager() -> MultiLightningManager:
    """Get global multi-lightning manager instance."""
    global _multi_lightning_manager
    if _multi_lightning_manager is None:
        _multi_lightning_manager = MultiLightningManager()
    return _multi_lightning_manager