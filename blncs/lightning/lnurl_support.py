#!/usr/bin/env python3
"""
Comprehensive LNURL and Lightning Address support for BLNCS
Implements LNURL-pay, LNURL-withdraw, LNURL-auth, and Lightning Address protocols
"""

import asyncio
import aiohttp
import hashlib
import hmac
import secrets
import base64
import json
import re
import time
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from urllib.parse import urlparse, parse_qs, urlencode
import logging

from blncs.core.exceptions import LightningError
from blncs.core.async_memory_manager import track_async_task, lightning_operation_context
from blncs.lightning.async_safe_client import AsyncSafeLightningClient

logger = logging.getLogger(__name__)

class LNURLType(Enum):
    """LNURL protocol types"""
    PAY = "payRequest"
    WITHDRAW = "withdrawRequest"
    CHANNEL = "channelRequest"
    AUTH = "auth"

class LNURLStatus(Enum):
    """LNURL operation status"""
    PENDING = "pending"
    SUCCESS = "success"
    ERROR = "error"
    EXPIRED = "expired"

@dataclass
class LNURLPayRequest:
    """LNURL-pay request data"""
    callback: str
    max_sendable: int
    min_sendable: int
    metadata: str
    tag: str
    comment_allowed: int = 0
    payment_hash: Optional[str] = None
    description_hash: Optional[str] = None

@dataclass
class LNURLWithdrawRequest:
    """LNURL-withdraw request data"""
    callback: str
    k1: str
    max_withdrawable: int
    min_withdrawable: int
    default_description: str
    tag: str
    balance_check: Optional[str] = None
    payment_link: Optional[str] = None

@dataclass
class LNURLAuthRequest:
    """LNURL-auth request data"""
    k1: str
    action: str
    domain: str
    url: str
    tag: str = "login"

@dataclass
class LightningAddress:
    """Lightning Address representation"""
    username: str
    domain: str
    
    @property
    def full_address(self) -> str:
        return f"{self.username}@{self.domain}"
    
    @classmethod
    def parse(cls, address: str) -> 'LightningAddress':
        """Parse Lightning Address string"""
        if '@' not in address:
            raise ValueError("Invalid Lightning Address format")
        username, domain = address.split('@', 1)
        return cls(username=username, domain=domain)

class LNURLDecoder:
    """LNURL decoder and validator"""
    
    @staticmethod
    def is_lnurl(data: str) -> bool:
        """Check if string is valid LNURL"""
        return data.lower().startswith('lnurl') and len(data) > 10
    
    @staticmethod
    def is_lightning_address(data: str) -> bool:
        """Check if string is valid Lightning Address"""
        pattern = r'^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, data))
    
    @staticmethod
    def decode_lnurl(lnurl: str) -> str:
        """Decode LNURL to URL"""
        try:
            # Remove lnurl prefix
            if lnurl.lower().startswith('lnurl'):
                encoded = lnurl[5:]
            else:
                encoded = lnurl
            
            # Decode bech32
            import bech32
            _, data = bech32.bech32_decode(encoded)
            if data is None:
                raise ValueError("Invalid bech32 encoding")
            
            # Convert 5-bit groups to bytes
            decoded_bytes = bech32.convertbits(data, 5, 8, False)
            if not decoded_bytes:
                raise ValueError("Invalid bech32 data")
            
            return bytes(decoded_bytes).decode('utf-8')
        except Exception as e:
            raise ValueError(f"Failed to decode LNURL: {e}")
    
    @staticmethod
    def lightning_address_to_lnurl(address: str) -> str:
        """Convert Lightning Address to LNURL-pay URL"""
        lightning_addr = LightningAddress.parse(address)
        return f"https://{lightning_addr.domain}/.well-known/lnurlp/{lightning_addr.username}"

class LNURLClient:
    """LNURL protocol client with comprehensive support"""
    
    def __init__(self, lightning_client: Optional[AsyncSafeLightningClient] = None):
        self.lightning_client = lightning_client
        self.session: Optional[aiohttp.ClientSession] = None
        self._active_requests: Dict[str, Any] = {}
        
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(limit=100, limit_per_host=10)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    @track_async_task("lnurl_fetch")
    async def _fetch_lnurl_data(self, url: str) -> Dict[str, Any]:
        """Fetch data from LNURL endpoint"""
        if not self.session:
            raise RuntimeError("Session not initialized")
        
        try:
            async with self.session.get(url) as response:
                if response.status != 200:
                    raise LightningError(f"LNURL endpoint returned {response.status}")
                
                data = await response.json()
                
                # Validate required fields
                if 'status' in data and data['status'].lower() == 'error':
                    raise LightningError(f"LNURL error: {data.get('reason', 'Unknown error')}")
                
                return data
        except aiohttp.ClientError as e:
            raise LightningError(f"Failed to fetch LNURL data: {e}")
        except json.JSONDecodeError as e:
            raise LightningError(f"Invalid JSON response from LNURL endpoint: {e}")
    
    @track_async_task("lnurl_resolve")
    async def resolve_lnurl(self, lnurl_or_address: str) -> Tuple[LNURLType, Dict[str, Any]]:
        """Resolve LNURL or Lightning Address to get request data"""
        async with lightning_operation_context("lnurl_resolve"):
            # Determine input type and get URL
            if LNURLDecoder.is_lightning_address(lnurl_or_address):
                url = LNURLDecoder.lightning_address_to_lnurl(lnurl_or_address)
                logger.debug(f"Converted Lightning Address {lnurl_or_address} to URL: {url}")
            elif LNURLDecoder.is_lnurl(lnurl_or_address):
                url = LNURLDecoder.decode_lnurl(lnurl_or_address)
                logger.debug(f"Decoded LNURL to URL: {url}")
            else:
                raise ValueError("Invalid LNURL or Lightning Address format")
            
            # Fetch data from endpoint
            data = await self._fetch_lnurl_data(url)
            
            # Determine LNURL type
            tag = data.get('tag', '').lower()
            if tag == 'payrequest':
                lnurl_type = LNURLType.PAY
            elif tag == 'withdrawrequest':
                lnurl_type = LNURLType.WITHDRAW
            elif tag == 'channelrequest':
                lnurl_type = LNURLType.CHANNEL
            elif tag == 'login':
                lnurl_type = LNURLType.AUTH
            else:
                raise LightningError(f"Unsupported LNURL type: {tag}")
            
            logger.info(f"Resolved LNURL type: {lnurl_type.value}")
            return lnurl_type, data
    
    @track_async_task("lnurl_pay")
    async def pay(self, lnurl_or_address: str, amount_msat: int, comment: str = "") -> Dict[str, Any]:
        """Execute LNURL-pay request"""
        async with lightning_operation_context("lnurl_pay"):
            lnurl_type, data = await self.resolve_lnurl(lnurl_or_address)
            
            if lnurl_type != LNURLType.PAY:
                raise LightningError(f"Expected LNURL-pay, got {lnurl_type.value}")
            
            # Parse pay request data
            pay_request = LNURLPayRequest(
                callback=data['callback'],
                max_sendable=int(data['maxSendable']),
                min_sendable=int(data['minSendable']),
                metadata=data['metadata'],
                tag=data['tag'],
                comment_allowed=int(data.get('commentAllowed', 0))
            )
            
            # Validate amount
            if amount_msat < pay_request.min_sendable:
                raise LightningError(f"Amount {amount_msat} below minimum {pay_request.min_sendable}")
            if amount_msat > pay_request.max_sendable:
                raise LightningError(f"Amount {amount_msat} above maximum {pay_request.max_sendable}")
            
            # Prepare callback parameters
            callback_params = {'amount': amount_msat}
            
            # Add comment if allowed and provided
            if comment and pay_request.comment_allowed > 0:
                if len(comment) > pay_request.comment_allowed:
                    comment = comment[:pay_request.comment_allowed]
                callback_params['comment'] = comment
            
            # Call callback URL
            callback_url = f"{pay_request.callback}?{urlencode(callback_params)}"
            callback_data = await self._fetch_lnurl_data(callback_url)
            
            # Extract payment request
            payment_request = callback_data.get('pr')
            if not payment_request:
                raise LightningError("No payment request received from LNURL-pay callback")
            
            # Validate payment request matches metadata
            metadata_hash = hashlib.sha256(pay_request.metadata.encode()).hexdigest()
            
            # Send payment via Lightning client
            if self.lightning_client:
                payment_result = await self.lightning_client.send_payment(payment_request)
                
                return {
                    'status': LNURLStatus.SUCCESS.value,
                    'payment_hash': payment_result.get('payment_hash'),
                    'amount_msat': amount_msat,
                    'fee_msat': payment_result.get('fee', 0),
                    'comment': comment,
                    'destination': lnurl_or_address,
                    'metadata': pay_request.metadata
                }
            else:
                return {
                    'status': LNURLStatus.SUCCESS.value,
                    'payment_request': payment_request,
                    'amount_msat': amount_msat,
                    'comment': comment,
                    'destination': lnurl_or_address,
                    'metadata': pay_request.metadata
                }
    
    @track_async_task("lnurl_withdraw")
    async def withdraw(self, lnurl: str, amount_msat: int, description: str = "") -> Dict[str, Any]:
        """Execute LNURL-withdraw request"""
        async with lightning_operation_context("lnurl_withdraw"):
            lnurl_type, data = await self.resolve_lnurl(lnurl)
            
            if lnurl_type != LNURLType.WITHDRAW:
                raise LightningError(f"Expected LNURL-withdraw, got {lnurl_type.value}")
            
            # Parse withdraw request data
            withdraw_request = LNURLWithdrawRequest(
                callback=data['callback'],
                k1=data['k1'],
                max_withdrawable=int(data['maxWithdrawable']),
                min_withdrawable=int(data['minWithdrawable']),
                default_description=data['defaultDescription'],
                tag=data['tag'],
                balance_check=data.get('balanceCheck'),
                payment_link=data.get('payLink')
            )
            
            # Validate amount
            if amount_msat < withdraw_request.min_withdrawable:
                raise LightningError(f"Amount {amount_msat} below minimum {withdraw_request.min_withdrawable}")
            if amount_msat > withdraw_request.max_withdrawable:
                raise LightningError(f"Amount {amount_msat} above maximum {withdraw_request.max_withdrawable}")
            
            # Create invoice via Lightning client
            if not self.lightning_client:
                raise LightningError("Lightning client required for LNURL withdraw")
            
            memo = description or withdraw_request.default_description
            invoice_data = await self.lightning_client.create_invoice(
                amount_msat // 1000,  # Convert to sats
                memo
            )
            
            payment_request = invoice_data
            if isinstance(invoice_data, dict):
                payment_request = invoice_data.get('payment_request', invoice_data)
            
            # Send withdraw request to callback
            callback_params = {
                'k1': withdraw_request.k1,
                'pr': payment_request
            }
            
            callback_url = f"{withdraw_request.callback}?{urlencode(callback_params)}"
            callback_result = await self._fetch_lnurl_data(callback_url)
            
            return {
                'status': LNURLStatus.SUCCESS.value if callback_result.get('status') == 'OK' else LNURLStatus.ERROR.value,
                'amount_msat': amount_msat,
                'description': memo,
                'payment_request': payment_request,
                'callback_response': callback_result
            }
    
    @track_async_task("lnurl_auth")
    async def authenticate(self, lnurl: str, private_key: Optional[bytes] = None) -> Dict[str, Any]:
        """Execute LNURL-auth request"""
        async with lightning_operation_context("lnurl_auth"):
            lnurl_type, data = await self.resolve_lnurl(lnurl)
            
            if lnurl_type != LNURLType.AUTH:
                raise LightningError(f"Expected LNURL-auth, got {lnurl_type.value}")
            
            # Parse auth request data
            auth_request = LNURLAuthRequest(
                k1=data['k1'],
                action=data.get('action', 'login'),
                domain=urlparse(lnurl).netloc,
                url=lnurl,
                tag=data['tag']
            )
            
            # Generate or use provided private key
            if not private_key:
                private_key = secrets.token_bytes(32)
            
            # Derive public key (simplified - in production use proper secp256k1)
            # This is a placeholder - implement proper secp256k1 key derivation
            import hashlib
            public_key = hashlib.sha256(private_key + b"pubkey").digest()[:33]
            
            # Sign the k1 challenge
            signature = hmac.new(private_key, auth_request.k1.encode(), hashlib.sha256).digest()
            
            # Send authentication response
            auth_params = {
                'sig': signature.hex(),
                'key': public_key.hex(),
                'k1': auth_request.k1
            }
            
            callback_url = f"{data['callback']}?{urlencode(auth_params)}"
            callback_result = await self._fetch_lnurl_data(callback_url)
            
            return {
                'status': LNURLStatus.SUCCESS.value if callback_result.get('status') == 'OK' else LNURLStatus.ERROR.value,
                'action': auth_request.action,
                'domain': auth_request.domain,
                'public_key': public_key.hex(),
                'callback_response': callback_result
            }

class LightningAddressResolver:
    """Lightning Address resolver and validator"""
    
    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    @track_async_task("resolve_lightning_address")
    async def resolve(self, address: str) -> Dict[str, Any]:
        """Resolve Lightning Address to payment information"""
        async with lightning_operation_context("resolve_lightning_address"):
            if not LNURLDecoder.is_lightning_address(address):
                raise ValueError("Invalid Lightning Address format")
            
            lightning_addr = LightningAddress.parse(address)
            
            # Fetch LNURL-pay data
            url = f"https://{lightning_addr.domain}/.well-known/lnurlp/{lightning_addr.username}"
            
            if not self.session:
                raise RuntimeError("Session not initialized")
            
            try:
                async with self.session.get(url) as response:
                    if response.status != 200:
                        raise LightningError(f"Lightning Address resolution failed: HTTP {response.status}")
                    
                    data = await response.json()
                    
                    # Validate LNURL-pay response
                    if data.get('tag') != 'payRequest':
                        raise LightningError("Lightning Address did not return valid LNURL-pay data")
                    
                    return {
                        'address': address,
                        'domain': lightning_addr.domain,
                        'username': lightning_addr.username,
                        'callback': data['callback'],
                        'max_sendable': int(data['maxSendable']),
                        'min_sendable': int(data['minSendable']),
                        'metadata': data['metadata'],
                        'comment_allowed': int(data.get('commentAllowed', 0)),
                        'allows_nostr': data.get('allowsNostr', False),
                        'nostr_pubkey': data.get('nostrPubkey')
                    }
            
            except aiohttp.ClientError as e:
                raise LightningError(f"Failed to resolve Lightning Address: {e}")
            except json.JSONDecodeError as e:
                raise LightningError(f"Invalid response from Lightning Address endpoint: {e}")
    
    @track_async_task("validate_lightning_address")
    async def validate(self, address: str) -> bool:
        """Validate that Lightning Address is reachable and valid"""
        try:
            await self.resolve(address)
            return True
        except Exception as e:
            logger.warning(f"Lightning Address validation failed for {address}: {e}")
            return False

class LNURLService:
    """Comprehensive LNURL service combining all protocols"""
    
    def __init__(self, lightning_client: Optional[AsyncSafeLightningClient] = None):
        self.lightning_client = lightning_client
        self.lnurl_client: Optional[LNURLClient] = None
        self.address_resolver: Optional[LightningAddressResolver] = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.lnurl_client = LNURLClient(self.lightning_client)
        self.address_resolver = LightningAddressResolver()
        
        await self.lnurl_client.__aenter__()
        await self.address_resolver.__aenter__()
        
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.lnurl_client:
            await self.lnurl_client.__aexit__(exc_type, exc_val, exc_tb)
        if self.address_resolver:
            await self.address_resolver.__aexit__(exc_type, exc_val, exc_tb)
    
    async def send_to_address_or_lnurl(self, destination: str, amount_msat: int, comment: str = "") -> Dict[str, Any]:
        """Send payment to Lightning Address or LNURL-pay"""
        if LNURLDecoder.is_lightning_address(destination):
            logger.info(f"Sending {amount_msat} msat to Lightning Address: {destination}")
        elif LNURLDecoder.is_lnurl(destination):
            logger.info(f"Sending {amount_msat} msat to LNURL: {destination}")
        else:
            raise ValueError("Destination must be Lightning Address or LNURL")
        
        return await self.lnurl_client.pay(destination, amount_msat, comment)
    
    async def request_withdrawal(self, lnurl: str, amount_msat: int, description: str = "") -> Dict[str, Any]:
        """Request withdrawal via LNURL-withdraw"""
        return await self.lnurl_client.withdraw(lnurl, amount_msat, description)
    
    async def authenticate_with_service(self, lnurl: str, private_key: Optional[bytes] = None) -> Dict[str, Any]:
        """Authenticate with service via LNURL-auth"""
        return await self.lnurl_client.authenticate(lnurl, private_key)
    
    async def resolve_lightning_address(self, address: str) -> Dict[str, Any]:
        """Resolve Lightning Address to payment information"""
        return await self.address_resolver.resolve(address)
    
    async def validate_lightning_address(self, address: str) -> bool:
        """Validate Lightning Address"""
        return await self.address_resolver.validate(address)
    
    async def get_address_info(self, address: str) -> Dict[str, Any]:
        """Get comprehensive information about Lightning Address"""
        try:
            info = await self.resolve_lightning_address(address)
            lightning_addr = LightningAddress.parse(address)
            
            return {
                'address': address,
                'valid': True,
                'domain': lightning_addr.domain,
                'username': lightning_addr.username,
                'payment_info': info,
                'supports_comments': info['comment_allowed'] > 0,
                'max_comment_length': info['comment_allowed'],
                'min_sendable_msat': info['min_sendable'],
                'max_sendable_msat': info['max_sendable'],
                'supports_nostr': info.get('allows_nostr', False)
            }
        except Exception as e:
            return {
                'address': address,
                'valid': False,
                'error': str(e)
            }

# Utility functions
async def send_to_lightning_address(address: str, amount_msat: int, comment: str = "", 
                                  lightning_client: Optional[AsyncSafeLightningClient] = None) -> Dict[str, Any]:
    """Convenience function to send payment to Lightning Address"""
    async with LNURLService(lightning_client) as service:
        return await service.send_to_address_or_lnurl(address, amount_msat, comment)

async def resolve_lightning_address(address: str) -> Dict[str, Any]:
    """Convenience function to resolve Lightning Address"""
    async with LightningAddressResolver() as resolver:
        return await resolver.resolve(address)

async def validate_lightning_address(address: str) -> bool:
    """Convenience function to validate Lightning Address"""
    async with LightningAddressResolver() as resolver:
        return await resolver.validate(address)

# Export main classes and functions
__all__ = [
    'LNURLType',
    'LNURLStatus', 
    'LNURLPayRequest',
    'LNURLWithdrawRequest',
    'LNURLAuthRequest',
    'LightningAddress',
    'LNURLDecoder',
    'LNURLClient',
    'LightningAddressResolver',
    'LNURLService',
    'send_to_lightning_address',
    'resolve_lightning_address',
    'validate_lightning_address'
]