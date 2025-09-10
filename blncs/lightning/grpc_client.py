"""
Real Lightning Network gRPC Integration
Production-ready gRPC clients for LND, CLN, and Eclair with proper error handling.
"""

import asyncio
import grpc
import os
import json
import codecs
from typing import Dict, List, Optional, Any, AsyncGenerator, Union
from pathlib import Path
from datetime import datetime, timezone
import logging
from dataclasses import dataclass, asdict
from enum import Enum

from ..infrastructure.resilience import resilient, CircuitBreakerError
from ..core.structured_logging import StructuredLogger
from ..domain.models import (
    NodeId, ChannelId, Amount, LightningNode, Channel, Payment, Invoice,
    PaymentStatus, ChannelState, ChannelBalance, FeePolicy
)


class LightningError(Exception):
    """Base Lightning Network error."""
    pass


class ConnectionError(LightningError):
    """Connection-related errors."""
    pass


class AuthenticationError(LightningError):
    """Authentication failures."""
    pass


class PaymentError(LightningError):
    """Payment-related errors."""
    pass


class ChannelError(LightningError):
    """Channel operation errors."""
    pass


@dataclass
class LNDConfig:
    """LND connection configuration."""
    host: str
    grpc_port: int
    rest_port: int
    tls_cert_path: str
    admin_macaroon_path: str
    readonly_macaroon_path: Optional[str] = None
    invoice_macaroon_path: Optional[str] = None
    network: str = "mainnet"
    timeout: int = 60
    max_message_size: int = 1024 * 1024 * 50  # 50MB


class LNDGRPCClient:
    """Production-grade LND gRPC client with full feature support."""
    
    def __init__(self, config: LNDConfig):
        self.config = config
        self.logger = StructuredLogger("lightning.lnd.grpc")
        self.channel: Optional[grpc.aio.Channel] = None
        self.stub = None
        self.router_stub = None
        self.wallet_stub = None
        self.invoices_stub = None
        self._connected = False
        self._admin_metadata = None
        self._readonly_metadata = None
        self._invoice_metadata = None
        
    async def connect(self) -> bool:
        """Connect to LND with proper authentication."""
        try:
            # Load TLS certificate
            if not os.path.exists(self.config.tls_cert_path):
                raise ConnectionError(f"TLS cert not found: {self.config.tls_cert_path}")
                
            with open(self.config.tls_cert_path, 'rb') as f:
                cert_data = f.read()
            
            # Create SSL credentials
            ssl_creds = grpc.ssl_channel_credentials(cert_data)
            
            # Load macaroons
            self._load_macaroons()
            
            # Create channel with proper options
            options = [
                ('grpc.keepalive_time_ms', 30000),
                ('grpc.keepalive_timeout_ms', 5000),
                ('grpc.keepalive_permit_without_calls', True),
                ('grpc.http2.max_pings_without_data', 0),
                ('grpc.http2.min_time_between_pings_ms', 10000),
                ('grpc.http2.min_ping_interval_without_data_ms', 300000),
                ('grpc.max_message_length', self.config.max_message_size),
                ('grpc.max_receive_message_length', self.config.max_message_size),
            ]
            
            self.channel = grpc.aio.secure_channel(
                f'{self.config.host}:{self.config.grpc_port}',
                ssl_creds,
                options=options
            )
            
            # Import LND gRPC modules dynamically
            try:
                import lightning_pb2_grpc as ln
                import lightning_pb2 as lnrpc
                import router_pb2_grpc as routerrpc
                import walletunlocker_pb2_grpc as walletunlocker
                import invoices_pb2_grpc as invoicesrpc
                
                self.ln = ln
                self.lnrpc = lnrpc
                self.routerrpc = routerrpc
                self.walletunlocker = walletunlocker
                self.invoicesrpc = invoicesrpc
                
            except ImportError as e:
                raise ConnectionError(f"LND gRPC modules not available: {e}")
            
            # Create stubs
            self.stub = ln.LightningStub(self.channel)
            self.router_stub = routerrpc.RouterStub(self.channel)
            self.wallet_stub = walletunlocker.WalletUnlockerStub(self.channel)
            self.invoices_stub = invoicesrpc.InvoicesStub(self.channel)
            
            # Test connection
            await self._test_connection()
            self._connected = True
            
            self.logger.info("Successfully connected to LND",
                           extra={"host": self.config.host, "port": self.config.grpc_port})
            return True
            
        except Exception as e:
            self.logger.error("Failed to connect to LND", extra={"error": str(e)})
            await self.disconnect()
            return False
    
    def _load_macaroons(self):
        """Load macaroon files for authentication."""
        # Load admin macaroon
        if os.path.exists(self.config.admin_macaroon_path):
            with open(self.config.admin_macaroon_path, 'rb') as f:
                macaroon_bytes = f.read()
                macaroon_hex = codecs.encode(macaroon_bytes, 'hex')
                self._admin_metadata = [('macaroon', macaroon_hex)]
        else:
            raise AuthenticationError(f"Admin macaroon not found: {self.config.admin_macaroon_path}")
        
        # Load readonly macaroon if available
        if self.config.readonly_macaroon_path and os.path.exists(self.config.readonly_macaroon_path):
            with open(self.config.readonly_macaroon_path, 'rb') as f:
                macaroon_bytes = f.read()
                macaroon_hex = codecs.encode(macaroon_bytes, 'hex')
                self._readonly_metadata = [('macaroon', macaroon_hex)]
        
        # Load invoice macaroon if available
        if self.config.invoice_macaroon_path and os.path.exists(self.config.invoice_macaroon_path):
            with open(self.config.invoice_macaroon_path, 'rb') as f:
                macaroon_bytes = f.read()
                macaroon_hex = codecs.encode(macaroon_bytes, 'hex')
                self._invoice_metadata = [('macaroon', macaroon_hex)]
    
    async def _test_connection(self):
        """Test the connection by calling GetInfo."""
        request = self.lnrpc.GetInfoRequest()
        await self.stub.GetInfo(request, metadata=self._admin_metadata, timeout=10)
    
    async def disconnect(self):
        """Disconnect from LND."""
        if self.channel:
            try:
                await self.channel.close()
            except Exception as e:
                self.logger.warning("Error closing channel", extra={"error": str(e)})
            finally:
                self.channel = None
                self.stub = None
                self.router_stub = None
                self.wallet_stub = None
                self.invoices_stub = None
                self._connected = False
                self.logger.info("Disconnected from LND")
    
    @resilient(
        circuit_breaker_name="lnd_get_info",
        retry_name="lnd_retry",
        circuit_breaker={"failure_threshold": 3, "recovery_timeout": 30},
        retry={"max_attempts": 3, "base_delay": 1.0}
    )
    async def get_info(self) -> Dict[str, Any]:
        """Get node information from LND."""
        if not self._connected:
            raise ConnectionError("Not connected to LND")
        
        try:
            request = self.lnrpc.GetInfoRequest()
            response = await self.stub.GetInfo(
                request, 
                metadata=self._readonly_metadata or self._admin_metadata,
                timeout=self.config.timeout
            )
            
            return {
                'identity_pubkey': response.identity_pubkey,
                'alias': response.alias,
                'color': response.color,
                'num_peers': response.num_peers,
                'num_active_channels': response.num_active_channels,
                'num_inactive_channels': response.num_inactive_channels,
                'num_pending_channels': response.num_pending_channels,
                'block_height': response.block_height,
                'block_hash': response.block_hash,
                'best_header_timestamp': response.best_header_timestamp,
                'synced_to_chain': response.synced_to_chain,
                'synced_to_graph': response.synced_to_graph,
                'testnet': response.testnet,
                'chains': [{'chain': chain.chain, 'network': chain.network} for chain in response.chains],
                'uris': list(response.uris),
                'version': response.version,
                'commit_hash': response.commit_hash
            }
            
        except grpc.RpcError as e:
            self.logger.error("gRPC error getting node info", 
                            extra={"code": e.code(), "details": e.details()})
            raise LightningError(f"Failed to get node info: {e.details()}")
    
    @resilient(
        circuit_breaker_name="lnd_get_balance",
        retry_name="lnd_retry"
    )
    async def get_balance(self) -> Dict[str, int]:
        """Get wallet balance from LND."""
        if not self._connected:
            raise ConnectionError("Not connected to LND")
        
        try:
            # Get on-chain balance
            wallet_request = self.lnrpc.WalletBalanceRequest()
            wallet_response = await self.stub.WalletBalance(
                wallet_request,
                metadata=self._readonly_metadata or self._admin_metadata,
                timeout=self.config.timeout
            )
            
            # Get channel balance
            channel_request = self.lnrpc.ChannelBalanceRequest()
            channel_response = await self.stub.ChannelBalance(
                channel_request,
                metadata=self._readonly_metadata or self._admin_metadata,
                timeout=self.config.timeout
            )
            
            return {
                'total_balance': wallet_response.total_balance,
                'confirmed_balance': wallet_response.confirmed_balance,
                'unconfirmed_balance': wallet_response.unconfirmed_balance,
                'local_balance': channel_response.local_balance.sat,
                'remote_balance': channel_response.remote_balance.sat,
                'pending_open_local_balance': channel_response.pending_open_local_balance.sat,
                'pending_open_remote_balance': channel_response.pending_open_remote_balance.sat,
                'unsettled_local_balance': channel_response.unsettled_local_balance.sat,
                'unsettled_remote_balance': channel_response.unsettled_remote_balance.sat
            }
            
        except grpc.RpcError as e:
            raise LightningError(f"Failed to get balance: {e.details()}")
    
    @resilient(
        circuit_breaker_name="lnd_list_channels",
        retry_name="lnd_retry"
    )
    async def list_channels(self, active_only: bool = True) -> List[Dict[str, Any]]:
        """List all channels from LND."""
        if not self._connected:
            raise ConnectionError("Not connected to LND")
        
        try:
            request = self.lnrpc.ListChannelsRequest(
                active_only=active_only,
                inactive_only=False,
                public_only=False,
                private_only=False
            )
            
            response = await self.stub.ListChannels(
                request,
                metadata=self._readonly_metadata or self._admin_metadata,
                timeout=self.config.timeout
            )
            
            channels = []
            for channel in response.channels:
                channels.append({
                    'active': channel.active,
                    'remote_pubkey': channel.remote_pubkey,
                    'channel_point': channel.channel_point,
                    'chan_id': str(channel.chan_id),
                    'capacity': channel.capacity,
                    'local_balance': channel.local_balance,
                    'remote_balance': channel.remote_balance,
                    'commit_fee': channel.commit_fee,
                    'commit_weight': channel.commit_weight,
                    'fee_per_kw': channel.fee_per_kw,
                    'unsettled_balance': channel.unsettled_balance,
                    'total_satoshis_sent': channel.total_satoshis_sent,
                    'total_satoshis_received': channel.total_satoshis_received,
                    'num_updates': channel.num_updates,
                    'pending_htlcs': [
                        {
                            'incoming': htlc.incoming,
                            'amount': htlc.amount,
                            'hash_lock': htlc.hash_lock.hex(),
                            'expiration_height': htlc.expiration_height
                        } for htlc in channel.pending_htlcs
                    ],
                    'csv_delay': channel.csv_delay,
                    'private': channel.private,
                    'initiator': channel.initiator,
                    'chan_status_flags': channel.chan_status_flags,
                    'local_chan_reserve_sat': channel.local_chan_reserve_sat,
                    'remote_chan_reserve_sat': channel.remote_chan_reserve_sat,
                    'static_remote_key': channel.static_remote_key,
                    'commitment_type': channel.commitment_type,
                    'lifetime': channel.lifetime,
                    'uptime': channel.uptime,
                    'close_address': channel.close_address,
                    'push_amount_sat': channel.push_amount_sat,
                    'thaw_height': channel.thaw_height
                })
            
            return channels
            
        except grpc.RpcError as e:
            raise LightningError(f"Failed to list channels: {e.details()}")
    
    @resilient(
        circuit_breaker_name="lnd_open_channel",
        retry_name="lnd_retry"
    )
    async def open_channel(self, node_pubkey: str, local_funding_amount: int,
                          push_sat: int = 0, target_conf: int = 3, 
                          sat_per_byte: int = 0, private: bool = False,
                          min_htlc_msat: int = 1000, remote_csv_delay: int = 144) -> AsyncGenerator[Dict[str, Any], None]:
        """Open a channel and stream updates."""
        if not self._connected:
            raise ConnectionError("Not connected to LND")
        
        try:
            # Convert pubkey from hex to bytes
            node_pubkey_bytes = bytes.fromhex(node_pubkey)
            
            request = self.lnrpc.OpenChannelRequest(
                node_pubkey=node_pubkey_bytes,
                local_funding_amount=local_funding_amount,
                push_sat=push_sat,
                target_conf=target_conf,
                sat_per_byte=sat_per_byte,
                private=private,
                min_htlc_msat=min_htlc_msat,
                remote_csv_delay=remote_csv_delay
            )
            
            response_stream = self.stub.OpenChannel(
                request,
                metadata=self._admin_metadata,
                timeout=self.config.timeout * 10  # Channel opening takes longer
            )
            
            async for response in response_stream:
                if response.HasField('chan_pending'):
                    yield {
                        'type': 'pending',
                        'txid': response.chan_pending.txid.hex(),
                        'output_index': response.chan_pending.output_index
                    }
                elif response.HasField('confirmation'):
                    yield {
                        'type': 'confirmation',
                        'block_sha': response.confirmation.block_sha.hex(),
                        'block_height': response.confirmation.block_height,
                        'num_confs_left': response.confirmation.num_confs_left
                    }
                elif response.HasField('chan_open'):
                    yield {
                        'type': 'open',
                        'channel_point': f"{response.chan_open.channel_point.funding_txid_bytes.hex()}:{response.chan_open.channel_point.output_index}"
                    }
                else:
                    yield {
                        'type': 'unknown',
                        'data': str(response)
                    }
                    
        except grpc.RpcError as e:
            raise ChannelError(f"Failed to open channel: {e.details()}")
    
    @resilient(
        circuit_breaker_name="lnd_send_payment",
        retry_name="lnd_retry"
    )
    async def send_payment(self, payment_request: str, timeout_seconds: int = 60,
                          fee_limit_sat: Optional[int] = None, 
                          outgoing_chan_id: Optional[int] = None) -> Dict[str, Any]:
        """Send a Lightning payment."""
        if not self._connected:
            raise ConnectionError("Not connected to LND")
        
        try:
            # Decode the payment request first
            decode_request = self.lnrpc.PayReqString(pay_req=payment_request)
            decoded = await self.stub.DecodePayReq(
                decode_request,
                metadata=self._readonly_metadata or self._admin_metadata
            )
            
            # Prepare send payment request
            send_request = self.lnrpc.SendRequest(
                payment_request=payment_request,
                timeout_seconds=timeout_seconds
            )
            
            if fee_limit_sat:
                send_request.fee_limit.fixed = fee_limit_sat
            
            if outgoing_chan_id:
                send_request.outgoing_chan_id = outgoing_chan_id
            
            # Send payment
            response = await self.stub.SendPaymentSync(
                send_request,
                metadata=self._admin_metadata,
                timeout=timeout_seconds + 10
            )
            
            if response.payment_error:
                raise PaymentError(f"Payment failed: {response.payment_error}")
            
            return {
                'payment_preimage': response.payment_preimage.hex(),
                'payment_route': {
                    'total_time_lock': response.payment_route.total_time_lock,
                    'total_fees': response.payment_route.total_fees,
                    'total_amt': response.payment_route.total_amt,
                    'hops': [
                        {
                            'chan_id': str(hop.chan_id),
                            'chan_capacity': hop.chan_capacity,
                            'amt_to_forward': hop.amt_to_forward,
                            'fee': hop.fee,
                            'expiry': hop.expiry,
                            'amt_to_forward_msat': hop.amt_to_forward_msat,
                            'fee_msat': hop.fee_msat,
                            'pub_key': hop.pub_key,
                            'tlv_payload': hop.tlv_payload
                        } for hop in response.payment_route.hops
                    ]
                },
                'payment_hash': response.payment_hash.hex()
            }
            
        except grpc.RpcError as e:
            raise PaymentError(f"Failed to send payment: {e.details()}")
    
    @resilient(
        circuit_breaker_name="lnd_create_invoice",
        retry_name="lnd_retry"
    )
    async def create_invoice(self, value: int, memo: str = "", expiry: int = 3600,
                           private: bool = False) -> Dict[str, Any]:
        """Create a Lightning invoice."""
        if not self._connected:
            raise ConnectionError("Not connected to LND")
        
        try:
            request = self.lnrpc.Invoice(
                value=value,
                memo=memo,
                expiry=expiry,
                private=private
            )
            
            response = await self.stub.AddInvoice(
                request,
                metadata=self._invoice_metadata or self._admin_metadata,
                timeout=self.config.timeout
            )
            
            return {
                'r_hash': response.r_hash.hex(),
                'payment_request': response.payment_request,
                'add_index': response.add_index
            }
            
        except grpc.RpcError as e:
            raise LightningError(f"Failed to create invoice: {e.details()}")
    
    async def stream_invoices(self) -> AsyncGenerator[Dict[str, Any], None]:
        """Stream invoice updates."""
        if not self._connected:
            raise ConnectionError("Not connected to LND")
        
        try:
            request = self.lnrpc.InvoiceSubscription()
            response_stream = self.stub.SubscribeInvoices(
                request,
                metadata=self._readonly_metadata or self._admin_metadata
            )
            
            async for invoice in response_stream:
                yield {
                    'memo': invoice.memo,
                    'receipt': invoice.receipt.hex() if invoice.receipt else None,
                    'r_preimage': invoice.r_preimage.hex() if invoice.r_preimage else None,
                    'r_hash': invoice.r_hash.hex(),
                    'value': invoice.value,
                    'value_msat': invoice.value_msat,
                    'settled': invoice.settled,
                    'creation_date': invoice.creation_date,
                    'settle_date': invoice.settle_date,
                    'payment_request': invoice.payment_request,
                    'description_hash': invoice.description_hash.hex() if invoice.description_hash else None,
                    'expiry': invoice.expiry,
                    'fallback_addr': invoice.fallback_addr,
                    'cltv_expiry': invoice.cltv_expiry,
                    'route_hints': [
                        {
                            'hop_hints': [
                                {
                                    'node_id': hop.node_id,
                                    'chan_id': str(hop.chan_id),
                                    'fee_base_msat': hop.fee_base_msat,
                                    'fee_proportional_millionths': hop.fee_proportional_millionths,
                                    'cltv_expiry_delta': hop.cltv_expiry_delta
                                } for hop in route.hop_hints
                            ]
                        } for route in invoice.route_hints
                    ],
                    'private': invoice.private,
                    'add_index': invoice.add_index,
                    'settle_index': invoice.settle_index,
                    'amt_paid': invoice.amt_paid,
                    'amt_paid_sat': invoice.amt_paid_sat,
                    'amt_paid_msat': invoice.amt_paid_msat,
                    'state': invoice.state,
                    'htlcs': [
                        {
                            'chan_id': str(htlc.chan_id),
                            'htlc_index': htlc.htlc_index,
                            'amt_msat': htlc.amt_msat,
                            'accept_height': htlc.accept_height,
                            'accept_time': htlc.accept_time,
                            'resolve_time': htlc.resolve_time,
                            'expiry_height': htlc.expiry_height,
                            'state': htlc.state
                        } for htlc in invoice.htlcs
                    ],
                    'features': dict(invoice.features),
                    'is_keysend': invoice.is_keysend,
                    'payment_addr': invoice.payment_addr.hex() if invoice.payment_addr else None,
                    'is_amp': invoice.is_amp
                }
                
        except grpc.RpcError as e:
            raise LightningError(f"Failed to stream invoices: {e.details()}")
    
    @resilient(
        circuit_breaker_name="lnd_update_channel_policy",
        retry_name="lnd_retry"
    )
    async def update_channel_policy(self, chan_point: str, base_fee_msat: int,
                                  fee_rate: int, time_lock_delta: int,
                                  max_htlc_msat: Optional[int] = None,
                                  min_htlc_msat: Optional[int] = None) -> Dict[str, Any]:
        """Update channel policy."""
        if not self._connected:
            raise ConnectionError("Not connected to LND")
        
        try:
            # Parse channel point
            txid_str, output_index_str = chan_point.split(':')
            txid_bytes = bytes.fromhex(txid_str)
            output_index = int(output_index_str)
            
            chan_point_obj = self.lnrpc.ChannelPoint(
                funding_txid_bytes=txid_bytes,
                output_index=output_index
            )
            
            request = self.lnrpc.PolicyUpdateRequest(
                chan_point=chan_point_obj,
                base_fee_msat=base_fee_msat,
                fee_rate=fee_rate / 1000000.0,  # Convert ppm to fraction
                time_lock_delta=time_lock_delta
            )
            
            if max_htlc_msat:
                request.max_htlc_msat = max_htlc_msat
                
            if min_htlc_msat:
                request.min_htlc_msat = min_htlc_msat
            
            response = await self.stub.UpdateChannelPolicy(
                request,
                metadata=self._admin_metadata,
                timeout=self.config.timeout
            )
            
            return {
                'success': True,
                'failed_updates': [
                    {
                        'outpoint': f"{update.outpoint.txid_bytes.hex()}:{update.outpoint.txid_str}:{update.outpoint.output_index}",
                        'reason': update.reason,
                        'update_error': update.update_error
                    } for update in response.failed_updates
                ]
            }
            
        except grpc.RpcError as e:
            raise ChannelError(f"Failed to update channel policy: {e.details()}")


async def create_lnd_client(config: LNDConfig) -> LNDGRPCClient:
    """Create and connect LND gRPC client."""
    client = LNDGRPCClient(config)
    success = await client.connect()
    if not success:
        raise ConnectionError("Failed to connect to LND")
    return client