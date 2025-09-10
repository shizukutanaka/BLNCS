"""
Asynchronous Lightning Network Client
High-performance async implementation for Lightning Network operations.
"""

import asyncio
import aiohttp
import json
import time
from typing import Dict, Optional, List, Any, AsyncIterator
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import logging
from contextlib import asynccontextmanager
from asyncio import Queue, Semaphore

from ..core.exceptions import LightningError, ConnectionError
from ..core.config_manager import get_config_manager
from ..core.logger import get_logger


@dataclass
class AsyncConnectionPool:
    """Async connection pool for HTTP connections"""
    max_connections: int = 100
    max_connections_per_host: int = 30
    timeout: aiohttp.ClientTimeout = field(default_factory=lambda: aiohttp.ClientTimeout(total=30))
    connector: Optional[aiohttp.TCPConnector] = None
    session: Optional[aiohttp.ClientSession] = None


class AsyncLightningClient:
    """
    High-performance asynchronous Lightning Network client
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or get_config_manager().get_all()
        self.lightning_config = self.config.get('lightning', {})
        self.logger = get_logger(__name__)
        
        # Connection settings
        self.host = self.lightning_config.get('host', 'localhost')
        self.port = self.lightning_config.get('port', 8080)
        self.network = self.lightning_config.get('network', 'testnet')
        self.base_url = f"https://{self.host}:{self.port}"
        
        # Async components
        self.session: Optional[aiohttp.ClientSession] = None
        self.connector: Optional[aiohttp.TCPConnector] = None
        self._connection_pool = AsyncConnectionPool()
        
        # Rate limiting
        self.rate_limit = Semaphore(100)  # Max 100 concurrent requests
        self.request_queue: Queue = Queue(maxsize=1000)
        
        # Caching
        self._cache: Dict[str, Any] = {}
        self._cache_ttl: Dict[str, datetime] = {}
        
        # Performance tracking
        self.request_count = 0
        self.error_count = 0
        self.total_latency = 0.0
        
        # Connection state
        self.connected = False
        self._heartbeat_task: Optional[asyncio.Task] = None
        
    async def __aenter__(self):
        """Async context manager entry"""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.disconnect()
    
    async def connect(self) -> bool:
        """Establish async connection to Lightning node"""
        try:
            # Create connector with connection pooling
            self.connector = aiohttp.TCPConnector(
                limit=self._connection_pool.max_connections,
                limit_per_host=self._connection_pool.max_connections_per_host,
                force_close=False,
                enable_cleanup_closed=True
            )
            
            # Create session with timeout
            timeout = aiohttp.ClientTimeout(
                total=30,
                connect=5,
                sock_connect=5,
                sock_read=10
            )
            
            # Load macaroon for authentication
            headers = await self._get_auth_headers()
            
            self.session = aiohttp.ClientSession(
                connector=self.connector,
                timeout=timeout,
                headers=headers,
                json_serialize=json.dumps
            )
            
            # Test connection
            info = await self.get_info()
            if info:
                self.connected = True
                self.logger.info(f"Connected to Lightning node: {info.get('alias', 'Unknown')}")
                
                # Start heartbeat
                self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
                
                return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect: {e}")
            await self.disconnect()
            raise ConnectionError(f"Failed to connect to Lightning node: {e}")
        
        return False
    
    async def disconnect(self) -> None:
        """Close async connections"""
        self.connected = False
        
        # Cancel heartbeat
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
        
        # Close session
        if self.session:
            await self.session.close()
            self.session = None
        
        # Close connector
        if self.connector:
            await self.connector.close()
            self.connector = None
        
        self.logger.info("Disconnected from Lightning node")
    
    async def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers"""
        headers = {}
        
        macaroon_path = self.lightning_config.get(
            'macaroon_path',
            f'~/.lnd/data/chain/bitcoin/{self.network}/readonly.macaroon'
        )
        
        macaroon_path = Path(macaroon_path).expanduser()
        if macaroon_path.exists():
            try:
                with open(macaroon_path, 'rb') as f:
                    macaroon = f.read().hex()
                    headers['Grpc-Metadata-macaroon'] = macaroon
            except Exception as e:
                self.logger.warning(f"Could not load macaroon: {e}")
        
        return headers
    
    async def _heartbeat_loop(self) -> None:
        """Maintain connection with periodic heartbeat"""
        while self.connected:
            try:
                await asyncio.sleep(30)  # Heartbeat every 30 seconds
                await self.get_info()
            except Exception as e:
                self.logger.warning(f"Heartbeat failed: {e}")
                self.error_count += 1
    
    @asynccontextmanager
    async def _rate_limited(self):
        """Rate limiting context manager"""
        async with self.rate_limit:
            yield
    
    async def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        use_cache: bool = True,
        cache_ttl: int = 60
    ) -> Dict[str, Any]:
        """Make async HTTP request with caching and rate limiting"""
        if not self.session:
            raise ConnectionError("Not connected to Lightning node")
        
        # Check cache
        cache_key = f"{method}:{endpoint}:{json.dumps(params or {})}"
        if use_cache and method == 'GET':
            cached = self._get_cached(cache_key)
            if cached is not None:
                return cached
        
        url = f"{self.base_url}/{endpoint}"
        
        async with self._rate_limited():
            start_time = time.time()
            
            try:
                async with self.session.request(
                    method,
                    url,
                    json=data,
                    params=params,
                    ssl=True  # Always verify SSL certificates
                ) as response:
                    # Track performance
                    latency = time.time() - start_time
                    self.total_latency += latency
                    self.request_count += 1
                    
                    if response.status != 200:
                        error_text = await response.text()
                        raise LightningError(f"HTTP {response.status}: {error_text}")
                    
                    result = await response.json()
                    
                    # Cache successful GET requests
                    if use_cache and method == 'GET':
                        self._set_cached(cache_key, result, cache_ttl)
                    
                    return result
                    
            except aiohttp.ClientError as e:
                self.error_count += 1
                raise ConnectionError(f"Request failed: {e}")
            except Exception as e:
                self.error_count += 1
                raise LightningError(f"Unexpected error: {e}")
    
    def _get_cached(self, key: str) -> Optional[Any]:
        """Get cached value if not expired"""
        if key in self._cache:
            if datetime.now() < self._cache_ttl.get(key, datetime.min):
                return self._cache[key]
            else:
                # Expired, remove it
                del self._cache[key]
                del self._cache_ttl[key]
        return None
    
    def _set_cached(self, key: str, value: Any, ttl_seconds: int) -> None:
        """Set cached value with TTL"""
        self._cache[key] = value
        self._cache_ttl[key] = datetime.now() + timedelta(seconds=ttl_seconds)
        
        # Limit cache size
        if len(self._cache) > 1000:
            # Remove oldest entries
            oldest_keys = sorted(self._cache_ttl.keys(), key=lambda k: self._cache_ttl[k])[:100]
            for old_key in oldest_keys:
                del self._cache[old_key]
                del self._cache_ttl[old_key]
    
    # Lightning Network Operations (Async)
    
    async def get_info(self) -> Dict[str, Any]:
        """Get node information"""
        return await self._make_request('GET', 'v1/getinfo')
    
    async def get_balance(self) -> Dict[str, int]:
        """Get wallet and channel balance"""
        wallet_task = self._make_request('GET', 'v1/balance/blockchain')
        channel_task = self._make_request('GET', 'v1/balance/channels')
        
        wallet_balance, channel_balance = await asyncio.gather(
            wallet_task, channel_task
        )
        
        return {
            'total': int(wallet_balance.get('total_balance', 0)),
            'confirmed': int(wallet_balance.get('confirmed_balance', 0)),
            'unconfirmed': int(wallet_balance.get('unconfirmed_balance', 0)),
            'channel_local': int(channel_balance.get('local_balance', {}).get('sat', 0)),
            'channel_remote': int(channel_balance.get('remote_balance', {}).get('sat', 0))
        }
    
    async def list_channels(self) -> List[Dict[str, Any]]:
        """List all channels"""
        response = await self._make_request('GET', 'v1/channels')
        channels = response.get('channels', [])
        
        return [
            {
                'channel_id': str(ch.get('chan_id', '')),
                'capacity': int(ch.get('capacity', 0)),
                'local_balance': int(ch.get('local_balance', 0)),
                'remote_balance': int(ch.get('remote_balance', 0)),
                'active': ch.get('active', False),
                'remote_pubkey': ch.get('remote_pubkey', ''),
                'private': ch.get('private', False)
            }
            for ch in channels
        ]
    
    async def open_channel(
        self,
        node_pubkey: str,
        amount: int,
        push_amount: int = 0,
        target_conf: int = 3
    ) -> str:
        """Open a channel to a peer"""
        data = {
            'node_pubkey': bytes.fromhex(node_pubkey).hex(),
            'local_funding_amount': str(amount),
            'push_sat': str(push_amount),
            'target_conf': target_conf
        }
        
        response = await self._make_request('POST', 'v1/channels', data=data)
        return response.get('funding_txid_str', '')
    
    async def close_channel(self, channel_id: str, force: bool = False) -> bool:
        """Close a channel"""
        parts = channel_id.split(':')
        if len(parts) != 2:
            raise LightningError("Invalid channel ID format")
        
        txid, output_index = parts
        endpoint = f"v1/channels/{txid}/{output_index}"
        
        params = {'force': 'true'} if force else {}
        
        try:
            await self._make_request('DELETE', endpoint, params=params)
            return True
        except Exception as e:
            self.logger.error(f"Failed to close channel: {e}")
            return False
    
    async def create_invoice(
        self,
        amount: int,
        memo: str = "",
        expiry: int = 3600
    ) -> str:
        """Create a Lightning invoice"""
        data = {
            'value': str(amount),
            'memo': memo,
            'expiry': str(expiry)
        }
        
        response = await self._make_request('POST', 'v1/invoices', data=data)
        return response.get('payment_request', '')
    
    async def send_payment(self, payment_request: str) -> Dict[str, Any]:
        """Send payment via Lightning invoice"""
        data = {'payment_request': payment_request}
        
        response = await self._make_request(
            'POST',
            'v1/channels/transactions',
            data=data
        )
        
        return {
            'payment_hash': response.get('payment_hash', ''),
            'amount': response.get('payment_route', {}).get('total_amt', 0),
            'status': 'succeeded' if not response.get('payment_error') else 'failed',
            'error': response.get('payment_error')
        }
    
    async def list_payments(
        self,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """List recent payments"""
        params = {
            'max_payments': limit,
            'index_offset': offset
        }
        
        response = await self._make_request('GET', 'v1/payments', params=params)
        payments = response.get('payments', [])
        
        return [
            {
                'payment_hash': p.get('payment_hash', ''),
                'amount': int(p.get('value_sat', 0)),
                'timestamp': p.get('creation_date', 0),
                'status': p.get('status', 'unknown'),
                'fee': int(p.get('fee_sat', 0))
            }
            for p in payments
        ]
    
    async def subscribe_invoices(self) -> AsyncIterator[Dict[str, Any]]:
        """Subscribe to invoice updates (async generator)"""
        # This would typically use WebSocket or Server-Sent Events
        # Simplified implementation for demonstration
        while self.connected:
            try:
                # Poll for new invoices
                invoices = await self._make_request(
                    'GET',
                    'v1/invoices',
                    params={'pending_only': True},
                    use_cache=False
                )
                
                for invoice in invoices.get('invoices', []):
                    yield {
                        'payment_hash': invoice.get('r_hash', ''),
                        'payment_request': invoice.get('payment_request', ''),
                        'amount': int(invoice.get('value', 0)),
                        'settled': invoice.get('settled', False),
                        'memo': invoice.get('memo', '')
                    }
                
                await asyncio.sleep(1)  # Poll interval
                
            except Exception as e:
                self.logger.error(f"Invoice subscription error: {e}")
                await asyncio.sleep(5)  # Error backoff
    
    async def batch_request(
        self,
        requests: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Execute multiple requests in parallel"""
        tasks = []
        
        for req in requests:
            task = self._make_request(
                req.get('method', 'GET'),
                req.get('endpoint'),
                data=req.get('data'),
                params=req.get('params'),
                use_cache=req.get('use_cache', True)
            )
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return [
            {'success': not isinstance(r, Exception), 'result': r}
            for r in results
        ]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get client performance statistics"""
        avg_latency = (
            self.total_latency / self.request_count
            if self.request_count > 0
            else 0
        )
        
        return {
            'request_count': self.request_count,
            'error_count': self.error_count,
            'error_rate': self.error_count / max(self.request_count, 1),
            'average_latency': avg_latency,
            'cache_size': len(self._cache),
            'connected': self.connected
        }


# Async utility functions

async def create_async_client(config: Optional[Dict] = None) -> AsyncLightningClient:
    """Create and connect async Lightning client"""
    client = AsyncLightningClient(config)
    await client.connect()
    return client


async def async_payment_stream(
    client: AsyncLightningClient,
    payment_requests: List[str],
    max_concurrent: int = 10
) -> AsyncIterator[Dict[str, Any]]:
    """Process payments concurrently with rate limiting"""
    semaphore = Semaphore(max_concurrent)
    
    async def send_with_limit(payment_request: str):
        async with semaphore:
            try:
                result = await client.send_payment(payment_request)
                return {'payment_request': payment_request, **result}
            except Exception as e:
                return {
                    'payment_request': payment_request,
                    'status': 'failed',
                    'error': str(e)
                }
    
    tasks = [send_with_limit(pr) for pr in payment_requests]
    
    for future in asyncio.as_completed(tasks):
        result = await future
        yield result


__all__ = [
    'AsyncLightningClient',
    'AsyncConnectionPool',
    'create_async_client',
    'async_payment_stream'
]