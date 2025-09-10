"""
Advanced Payment Processing System for Lightning Network
Handles payments, invoices, and payment routing with enhanced features.
"""

import time
import json
import hashlib
import asyncio
from typing import Dict, List, Optional, Any, Tuple, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import secrets
import base64

from .client import LightningClient
from ..core.logger import get_logger
from ..core.exceptions import PaymentError, LightningError
from ..core.metrics import get_metrics_collector
from ..core.config_manager import get_config_manager


class PaymentStatus(Enum):
    """Payment status enumeration"""
    PENDING = "pending"
    IN_FLIGHT = "in_flight"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"


class InvoiceStatus(Enum):
    """Invoice status enumeration"""
    OPEN = "open"
    SETTLED = "settled"
    CANCELED = "canceled"
    EXPIRED = "expired"


@dataclass
class PaymentResult:
    """Payment execution result"""
    payment_hash: str
    status: PaymentStatus
    amount_msat: int
    fee_msat: int = 0
    payment_preimage: Optional[str] = None
    failure_reason: Optional[str] = None
    route: Optional[List[Dict]] = None
    attempts: int = 1
    created_at: datetime = field(default_factory=datetime.now)
    settled_at: Optional[datetime] = None
    total_time_seconds: float = 0.0


@dataclass
class Invoice:
    """Lightning invoice information"""
    payment_request: str
    payment_hash: str
    amount_msat: int
    description: str
    status: InvoiceStatus = InvoiceStatus.OPEN
    expiry: int = 3600  # 1 hour default
    created_at: datetime = field(default_factory=datetime.now)
    settled_at: Optional[datetime] = None
    memo: Optional[str] = None
    private: bool = False
    add_index: Optional[int] = None
    settle_index: Optional[int] = None


@dataclass
class PaymentRequest:
    """Payment request with routing preferences"""
    destination: str
    amount_msat: int
    payment_hash: Optional[str] = None
    max_fee_msat: int = 10000
    timeout_seconds: int = 60
    max_parts: int = 16  # For multi-part payments
    allow_self_payment: bool = False
    last_hop_pubkey: Optional[str] = None
    route_hints: Optional[List[Dict]] = None
    payment_request: Optional[str] = None  # If paying invoice
    description: Optional[str] = None


class PaymentManager:
    """Advanced payment processing system"""
    
    def __init__(self, client: LightningClient):
        self.client = client
        self.logger = get_logger(__name__)
        self.metrics = get_metrics_collector()
        self.config = get_config_manager().get_all()
        
        # Payment settings
        self.max_fee_ratio = self.config.get('payments', {}).get('max_fee_ratio', 0.01)
        self.payment_timeout = self.config.get('payments', {}).get('timeout', 60)
        self.retry_attempts = self.config.get('payments', {}).get('retry_attempts', 3)
        self.invoice_expiry = self.config.get('payments', {}).get('invoice_expiry', 3600)
        
        # Internal state
        self.payment_history: Dict[str, PaymentResult] = {}
        self.invoice_cache: Dict[str, Invoice] = {}
        self.pending_payments: Dict[str, PaymentRequest] = {}
        
    def create_invoice(self, amount_msat: int, description: str, 
                      expiry: int = None, memo: str = None, 
                      private: bool = False) -> Invoice:
        """Create a Lightning invoice"""
        try:
            if expiry is None:
                expiry = self.invoice_expiry
                
            self.logger.info(f"Creating invoice for {amount_msat} msat")
            
            # Prepare invoice request
            invoice_data = {
                'value': str(amount_msat // 1000),  # Convert to sat
                'memo': description,
                'expiry': str(expiry),
                'private': private
            }
            
            if memo:
                invoice_data['memo'] = memo
            
            # Create invoice via Lightning client
            result = self.client._make_request('invoices', method='POST', data=invoice_data)
            
            if not result:
                raise PaymentError("Failed to create invoice")
            
            # Parse response
            payment_request = result.get('payment_request', '')
            payment_hash = result.get('r_hash', '')
            add_index = result.get('add_index', 0)
            
            # Create invoice object
            invoice = Invoice(
                payment_request=payment_request,
                payment_hash=payment_hash,
                amount_msat=amount_msat,
                description=description,
                expiry=expiry,
                memo=memo,
                private=private,
                add_index=add_index
            )
            
            # Cache invoice
            self.invoice_cache[payment_hash] = invoice
            
            # Record metrics
            self.metrics.record_metric('invoice.created', 1, {
                'amount_msat': amount_msat,
                'private': private,
                'expiry': expiry
            })
            
            self.logger.info(f"Invoice created: {payment_hash}")
            return invoice
            
        except Exception as e:
            self.logger.error(f"Failed to create invoice: {e}")
            raise PaymentError(f"Invoice creation failed: {e}")
    
    def decode_payment_request(self, payment_request: str) -> Dict[str, Any]:
        """Decode a Lightning payment request"""
        try:
            result = self.client._make_request('payreq', method='POST', 
                                             data={'pay_req': payment_request})
            
            if result:
                decoded = {
                    'destination': result.get('destination'),
                    'payment_hash': result.get('payment_hash'),
                    'amount_msat': int(result.get('num_msat', 0)),
                    'timestamp': int(result.get('timestamp', 0)),
                    'expiry': int(result.get('expiry', 0)),
                    'description': result.get('description', ''),
                    'description_hash': result.get('description_hash'),
                    'fallback_addr': result.get('fallback_addr'),
                    'cltv_expiry': int(result.get('cltv_expiry', 0)),
                    'route_hints': result.get('route_hints', [])
                }
                return decoded
            else:
                raise PaymentError("Failed to decode payment request")
                
        except Exception as e:
            self.logger.error(f"Failed to decode payment request: {e}")
            raise PaymentError(f"Payment request decode failed: {e}")
    
    def send_payment(self, payment_request: Union[str, PaymentRequest]) -> PaymentResult:
        """Send a Lightning payment"""
        try:
            start_time = time.time()
            
            # Handle different input types
            if isinstance(payment_request, str):
                # Decode payment request
                decoded = self.decode_payment_request(payment_request)
                req = PaymentRequest(
                    destination=decoded['destination'],
                    amount_msat=decoded['amount_msat'],
                    payment_hash=decoded['payment_hash'],
                    payment_request=payment_request,
                    description=decoded['description']
                )
            else:
                req = payment_request
            
            payment_hash = req.payment_hash or self._generate_payment_hash()
            
            self.logger.info(f"Sending payment: {payment_hash}")
            
            # Store pending payment
            self.pending_payments[payment_hash] = req
            
            # Prepare payment data
            payment_data = {
                'payment_request': req.payment_request or '',
                'amt': str(req.amount_msat // 1000),  # Convert to sat
                'fee_limit': {'fixed': str(req.max_fee_msat // 1000)},
                'timeout_seconds': req.timeout_seconds
            }
            
            if req.destination:
                payment_data['dest'] = req.destination
            if req.payment_hash:
                payment_data['payment_hash'] = req.payment_hash
            if req.max_parts > 1:
                payment_data['max_parts'] = req.max_parts
            if req.last_hop_pubkey:
                payment_data['last_hop_pubkey'] = req.last_hop_pubkey
            
            # Send payment
            result = self.client._make_request('payments', method='POST', data=payment_data)
            
            if not result:
                raise PaymentError("Payment request failed")
            
            # Parse result
            status_str = result.get('status', 'unknown').lower()
            try:
                status = PaymentStatus(status_str)
            except ValueError:
                status = PaymentStatus.UNKNOWN
            
            # Create payment result
            payment_result = PaymentResult(
                payment_hash=payment_hash,
                status=status,
                amount_msat=req.amount_msat,
                fee_msat=int(result.get('fee_msat', 0)),
                payment_preimage=result.get('payment_preimage'),
                failure_reason=result.get('failure_reason'),
                route=result.get('route'),
                total_time_seconds=time.time() - start_time
            )
            
            if status == PaymentStatus.SUCCEEDED:
                payment_result.settled_at = datetime.now()
            
            # Store result
            self.payment_history[payment_hash] = payment_result
            
            # Clean up pending
            if payment_hash in self.pending_payments:
                del self.pending_payments[payment_hash]
            
            # Record metrics
            self.metrics.record_metric('payment.sent', 1, {
                'status': status.value,
                'amount_msat': req.amount_msat,
                'fee_msat': payment_result.fee_msat,
                'duration_seconds': payment_result.total_time_seconds
            })
            
            self.logger.info(f"Payment {status.value}: {payment_hash}")
            return payment_result
            
        except Exception as e:
            self.logger.error(f"Payment failed: {e}")
            # Clean up pending payment
            if 'payment_hash' in locals() and payment_hash in self.pending_payments:
                del self.pending_payments[payment_hash]
            
            # Create failed payment result
            failed_result = PaymentResult(
                payment_hash=payment_hash if 'payment_hash' in locals() else 'unknown',
                status=PaymentStatus.FAILED,
                amount_msat=req.amount_msat if 'req' in locals() else 0,
                failure_reason=str(e),
                total_time_seconds=time.time() - start_time if 'start_time' in locals() else 0
            )
            
            return failed_result
    
    def send_keysend(self, destination: str, amount_msat: int, 
                    custom_records: Dict[int, bytes] = None,
                    max_fee_msat: int = 10000) -> PaymentResult:
        """Send a keysend (spontaneous) payment"""
        try:
            start_time = time.time()
            
            # Generate random payment hash for keysend
            payment_hash = self._generate_payment_hash()
            preimage = secrets.token_bytes(32)
            
            self.logger.info(f"Sending keysend payment to {destination}")
            
            # Prepare keysend data
            keysend_data = {
                'dest': destination,
                'amt': str(amount_msat // 1000),
                'payment_hash': payment_hash,
                'dest_custom_records': custom_records or {},
                'fee_limit': {'fixed': str(max_fee_msat // 1000)},
                'timeout_seconds': self.payment_timeout
            }
            
            # Add preimage to custom records
            keysend_data['dest_custom_records'][5482373484] = base64.b64encode(preimage).decode()
            
            # Send keysend payment
            result = self.client._make_request('keysend', method='POST', data=keysend_data)
            
            if not result:
                raise PaymentError("Keysend payment failed")
            
            # Parse result
            status_str = result.get('status', 'unknown').lower()
            try:
                status = PaymentStatus(status_str)
            except ValueError:
                status = PaymentStatus.UNKNOWN
            
            # Create payment result
            payment_result = PaymentResult(
                payment_hash=payment_hash,
                status=status,
                amount_msat=amount_msat,
                fee_msat=int(result.get('fee_msat', 0)),
                payment_preimage=base64.b64encode(preimage).decode() if status == PaymentStatus.SUCCEEDED else None,
                failure_reason=result.get('failure_reason'),
                total_time_seconds=time.time() - start_time
            )
            
            if status == PaymentStatus.SUCCEEDED:
                payment_result.settled_at = datetime.now()
            
            # Store result
            self.payment_history[payment_hash] = payment_result
            
            # Record metrics
            self.metrics.record_metric('payment.keysend', 1, {
                'status': status.value,
                'amount_msat': amount_msat,
                'fee_msat': payment_result.fee_msat
            })
            
            return payment_result
            
        except Exception as e:
            self.logger.error(f"Keysend payment failed: {e}")
            raise PaymentError(f"Keysend failed: {e}")
    
    def get_invoice_status(self, payment_hash: str) -> Optional[Invoice]:
        """Get invoice status"""
        try:
            # Check cache first
            if payment_hash in self.invoice_cache:
                invoice = self.invoice_cache[payment_hash]
                
                # Check if we need to update status
                if invoice.status == InvoiceStatus.OPEN:
                    # Query node for current status
                    result = self.client._make_request(f'invoices/{payment_hash}')
                    if result:
                        settled = result.get('settled', False)
                        if settled:
                            invoice.status = InvoiceStatus.SETTLED
                            invoice.settled_at = datetime.now()
                            invoice.settle_index = result.get('settle_index')
                        elif datetime.now() > (invoice.created_at + timedelta(seconds=invoice.expiry)):
                            invoice.status = InvoiceStatus.EXPIRED
                
                return invoice
            
            # Not in cache, query node
            result = self.client._make_request(f'invoices/{payment_hash}')
            if result:
                # Create invoice from result
                status_str = 'settled' if result.get('settled', False) else 'open'
                status = InvoiceStatus(status_str)
                
                invoice = Invoice(
                    payment_request=result.get('payment_request', ''),
                    payment_hash=payment_hash,
                    amount_msat=int(result.get('value_msat', 0)),
                    description=result.get('memo', ''),
                    status=status,
                    add_index=result.get('add_index'),
                    settle_index=result.get('settle_index')
                )
                
                # Cache and return
                self.invoice_cache[payment_hash] = invoice
                return invoice
            
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to get invoice status for {payment_hash}: {e}")
            return None
    
    def cancel_invoice(self, payment_hash: str) -> bool:
        """Cancel an invoice"""
        try:
            result = self.client._make_request(f'invoices/{payment_hash}/cancel', method='POST')
            
            if result:
                # Update cache
                if payment_hash in self.invoice_cache:
                    self.invoice_cache[payment_hash].status = InvoiceStatus.CANCELED
                
                self.logger.info(f"Invoice canceled: {payment_hash}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to cancel invoice {payment_hash}: {e}")
            return False
    
    def get_payment_history(self, limit: int = 100, offset: int = 0) -> List[PaymentResult]:
        """Get payment history"""
        try:
            # Get from local cache first
            local_payments = list(self.payment_history.values())
            
            # Also query node for any missing payments
            result = self.client._make_request('payments', data={'max_payments': limit, 'index_offset': offset})
            
            if result and 'payments' in result:
                for payment_data in result['payments']:
                    payment_hash = payment_data.get('payment_hash', '')
                    if payment_hash and payment_hash not in self.payment_history:
                        # Convert node payment to our format
                        status_str = payment_data.get('status', 'unknown').lower()
                        try:
                            status = PaymentStatus(status_str)
                        except ValueError:
                            status = PaymentStatus.UNKNOWN
                        
                        payment = PaymentResult(
                            payment_hash=payment_hash,
                            status=status,
                            amount_msat=int(payment_data.get('value_msat', 0)),
                            fee_msat=int(payment_data.get('fee_msat', 0)),
                            payment_preimage=payment_data.get('payment_preimage'),
                            created_at=datetime.fromtimestamp(int(payment_data.get('creation_time_ns', 0)) // 1000000000) if payment_data.get('creation_time_ns') else datetime.now()
                        )
                        
                        local_payments.append(payment)
                        self.payment_history[payment_hash] = payment
            
            # Sort by creation time
            local_payments.sort(key=lambda x: x.created_at, reverse=True)
            
            return local_payments[offset:offset+limit]
            
        except Exception as e:
            self.logger.error(f"Failed to get payment history: {e}")
            return []
    
    def get_invoice_list(self, pending_only: bool = False, limit: int = 100) -> List[Invoice]:
        """Get invoice list"""
        try:
            result = self.client._make_request('invoices', data={'pending_only': pending_only, 'num_max_invoices': limit})
            
            invoices = []
            if result and 'invoices' in result:
                for invoice_data in result['invoices']:
                    payment_hash = invoice_data.get('r_hash', '')
                    
                    # Determine status
                    status = InvoiceStatus.OPEN
                    if invoice_data.get('settled', False):
                        status = InvoiceStatus.SETTLED
                    elif invoice_data.get('state') == 'CANCELED':
                        status = InvoiceStatus.CANCELED
                    
                    invoice = Invoice(
                        payment_request=invoice_data.get('payment_request', ''),
                        payment_hash=payment_hash,
                        amount_msat=int(invoice_data.get('value_msat', 0)),
                        description=invoice_data.get('memo', ''),
                        status=status,
                        expiry=int(invoice_data.get('expiry', 3600)),
                        private=invoice_data.get('private', False),
                        add_index=invoice_data.get('add_index'),
                        settle_index=invoice_data.get('settle_index')
                    )
                    
                    invoices.append(invoice)
                    # Update cache
                    self.invoice_cache[payment_hash] = invoice
            
            return invoices
            
        except Exception as e:
            self.logger.error(f"Failed to get invoice list: {e}")
            return []
    
    def estimate_fee(self, destination: str, amount_msat: int) -> Dict[str, Any]:
        """Estimate payment fee"""
        try:
            # Query for routes to destination
            result = self.client._make_request('graph/routes', data={
                'pub_key': destination,
                'amt': str(amount_msat // 1000),
                'num_routes': 10
            })
            
            if result and 'routes' in result:
                routes = result['routes']
                if routes:
                    # Analyze routes for fee estimation
                    fees = [int(route.get('total_fees_msat', 0)) for route in routes]
                    
                    return {
                        'min_fee_msat': min(fees) if fees else 0,
                        'max_fee_msat': max(fees) if fees else 0,
                        'avg_fee_msat': sum(fees) // len(fees) if fees else 0,
                        'route_count': len(routes),
                        'success_probability': self._estimate_success_probability(routes)
                    }
            
            # Fallback estimation
            return {
                'min_fee_msat': int(amount_msat * 0.001),  # 0.1%
                'max_fee_msat': int(amount_msat * 0.01),   # 1%
                'avg_fee_msat': int(amount_msat * 0.005),  # 0.5%
                'route_count': 0,
                'success_probability': 0.5
            }
            
        except Exception as e:
            self.logger.error(f"Failed to estimate fee for {destination}: {e}")
            return {'min_fee_msat': 0, 'max_fee_msat': 0, 'avg_fee_msat': 0, 'route_count': 0, 'success_probability': 0}
    
    def _generate_payment_hash(self) -> str:
        """Generate a random payment hash"""
        return hashlib.sha256(secrets.token_bytes(32)).hexdigest()
    
    def _estimate_success_probability(self, routes: List[Dict]) -> float:
        """Estimate payment success probability based on routes"""
        if not routes:
            return 0.0
        
        # Simple heuristic based on route count and hop count
        avg_hops = sum(len(route.get('hops', [])) for route in routes) / len(routes)
        
        # More routes and fewer hops = higher probability
        route_factor = min(len(routes) / 10, 1.0)
        hop_factor = max(1.0 - (avg_hops - 1) * 0.1, 0.1)
        
        return route_factor * hop_factor
    
    def get_payment_summary(self) -> Dict[str, Any]:
        """Get payment processing summary"""
        try:
            payments = list(self.payment_history.values())
            invoices = list(self.invoice_cache.values())
            
            # Payment statistics
            successful_payments = [p for p in payments if p.status == PaymentStatus.SUCCEEDED]
            failed_payments = [p for p in payments if p.status == PaymentStatus.FAILED]
            
            total_sent = sum(p.amount_msat for p in successful_payments)
            total_fees = sum(p.fee_msat for p in successful_payments)
            
            # Invoice statistics
            settled_invoices = [i for i in invoices if i.status == InvoiceStatus.SETTLED]
            open_invoices = [i for i in invoices if i.status == InvoiceStatus.OPEN]
            
            total_received = sum(i.amount_msat for i in settled_invoices)
            
            return {
                'payments': {
                    'total_count': len(payments),
                    'successful_count': len(successful_payments),
                    'failed_count': len(failed_payments),
                    'success_rate': len(successful_payments) / len(payments) if payments else 0,
                    'total_sent_msat': total_sent,
                    'total_fees_msat': total_fees,
                    'avg_fee_rate': total_fees / total_sent if total_sent > 0 else 0
                },
                'invoices': {
                    'total_count': len(invoices),
                    'settled_count': len(settled_invoices),
                    'open_count': len(open_invoices),
                    'settlement_rate': len(settled_invoices) / len(invoices) if invoices else 0,
                    'total_received_msat': total_received
                },
                'net_flow_msat': total_received - total_sent,
                'pending_payments': len(self.pending_payments)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to generate payment summary: {e}")
            return {}


def get_payment_manager(client: Optional[LightningClient] = None) -> PaymentManager:
    """Get payment manager instance"""
    if client is None:
        from .client import LightningClient
        config = get_config_manager().get_all()
        client = LightningClient(config)
    
    return PaymentManager(client)