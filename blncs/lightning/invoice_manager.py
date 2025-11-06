"""
BLNCS Lightning Invoice Manager
Practical invoice creation and management for Lightning Network
"""

import time
import json
import hashlib
import secrets
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path


@dataclass
class Invoice:
    """Lightning invoice data structure"""
    payment_hash: str
    payment_request: str  # BOLT11 invoice string
    amount_sats: int
    description: str
    expiry_seconds: int
    created_at: float
    expires_at: float
    status: str = "pending"  # pending, paid, expired, cancelled
    settled_at: Optional[float] = None
    preimage: Optional[str] = None

    def is_expired(self) -> bool:
        """Check if invoice is expired"""
        return time.time() > self.expires_at

    def time_until_expiry(self) -> float:
        """Get seconds until expiry"""
        return max(0, self.expires_at - time.time())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


class InvoiceManager:
    """Lightning invoice management system"""

    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)

        self.invoices: Dict[str, Invoice] = {}
        self.invoice_file = self.data_dir / "invoices.json"
        self.logger = logging.getLogger("BLNCS_InvoiceManager")

        self._load_invoices()

    def _load_invoices(self):
        """Load invoices from storage"""
        if self.invoice_file.exists():
            try:
                with open(self.invoice_file, 'r') as f:
                    data = json.load(f)
                    for payment_hash, invoice_data in data.items():
                        self.invoices[payment_hash] = Invoice(**invoice_data)

                self.logger.info(f"Loaded {len(self.invoices)} invoices")
            except Exception as e:
                self.logger.error(f"Failed to load invoices: {e}")

    def _save_invoices(self):
        """Save invoices to storage"""
        try:
            data = {hash: invoice.to_dict() for hash, invoice in self.invoices.items()}
            with open(self.invoice_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save invoices: {e}")

    def create_invoice(self, amount_sats: int, description: str = "",
                      expiry_seconds: int = 3600) -> Invoice:
        """Create a new Lightning invoice"""
        # Generate payment hash and preimage
        preimage = secrets.token_bytes(32)
        payment_hash = hashlib.sha256(preimage).hexdigest()

        current_time = time.time()
        expires_at = current_time + expiry_seconds

        # Create simplified BOLT11 invoice string (for demo)
        # In real implementation, this would use proper BOLT11 encoding
        payment_request = self._create_bolt11_invoice(
            payment_hash, amount_sats, description, expires_at
        )

        invoice = Invoice(
            payment_hash=payment_hash,
            payment_request=payment_request,
            amount_sats=amount_sats,
            description=description,
            expiry_seconds=expiry_seconds,
            created_at=current_time,
            expires_at=expires_at,
            preimage=preimage.hex()
        )

        self.invoices[payment_hash] = invoice
        self._save_invoices()

        self.logger.info(f"Created invoice: {payment_hash[:16]}... for {amount_sats} sats")
        return invoice

    def _create_bolt11_invoice(self, payment_hash: str, amount_sats: int,
                              description: str, expires_at: float) -> str:
        """Create simplified BOLT11 invoice string"""
        # Simplified BOLT11 format for demo
        # Real implementation would use proper BOLT11 library
        network_prefix = "lnbc"  # Bitcoin mainnet

        # Convert amount to milli-satoshis and encode
        amount_msat = amount_sats * 1000
        if amount_msat >= 1000000:  # >= 1000 sats
            amount_part = f"{amount_msat // 1000000}m"
        elif amount_msat >= 1000:  # >= 1 sat
            amount_part = f"{amount_msat // 1000}u"
        else:
            amount_part = f"{amount_msat}n"

        # Create invoice string
        invoice = f"{network_prefix}{amount_part}1{payment_hash[:16]}"
        return invoice

    def get_invoice(self, payment_hash: str) -> Optional[Invoice]:
        """Get invoice by payment hash"""
        return self.invoices.get(payment_hash)

    def pay_invoice(self, payment_hash: str) -> bool:
        """Mark invoice as paid"""
        invoice = self.invoices.get(payment_hash)
        if not invoice:
            return False

        if invoice.is_expired():
            invoice.status = "expired"
            self._save_invoices()
            return False

        invoice.status = "paid"
        invoice.settled_at = time.time()
        self._save_invoices()

        self.logger.info(f"Invoice paid: {payment_hash[:16]}...")
        return True

    def cancel_invoice(self, payment_hash: str) -> bool:
        """Cancel an invoice"""
        invoice = self.invoices.get(payment_hash)
        if not invoice or invoice.status != "pending":
            return False

        invoice.status = "cancelled"
        self._save_invoices()

        self.logger.info(f"Invoice cancelled: {payment_hash[:16]}...")
        return True

    def list_invoices(self, status: Optional[str] = None, limit: int = 100) -> List[Invoice]:
        """List invoices with optional status filter"""
        invoices = list(self.invoices.values())

        if status:
            invoices = [inv for inv in invoices if inv.status == status]

        # Sort by creation time (newest first)
        invoices.sort(key=lambda x: x.created_at, reverse=True)

        return invoices[:limit]

    def cleanup_expired_invoices(self) -> int:
        """Remove expired invoices and return count"""
        current_time = time.time()
        expired_hashes = []

        for payment_hash, invoice in self.invoices.items():
            if invoice.status == "pending" and invoice.is_expired():
                invoice.status = "expired"
                expired_hashes.append(payment_hash)

        if expired_hashes:
            self._save_invoices()
            self.logger.info(f"Marked {len(expired_hashes)} invoices as expired")

        return len(expired_hashes)

    def get_invoice_stats(self) -> Dict[str, Any]:
        """Get invoice statistics"""
        total_invoices = len(self.invoices)
        if total_invoices == 0:
            return {"total": 0}

        # Count by status
        status_counts = {}
        total_amount = 0
        paid_amount = 0

        for invoice in self.invoices.values():
            status = invoice.status
            if invoice.is_expired() and status == "pending":
                status = "expired"

            status_counts[status] = status_counts.get(status, 0) + 1
            total_amount += invoice.amount_sats

            if status == "paid":
                paid_amount += invoice.amount_sats

        return {
            "total": total_invoices,
            "status_counts": status_counts,
            "total_amount_sats": total_amount,
            "paid_amount_sats": paid_amount,
            "success_rate": paid_amount / total_amount * 100 if total_amount > 0 else 0
        }

    def decode_invoice(self, payment_request: str) -> Optional[Dict[str, Any]]:
        """Decode BOLT11 invoice (simplified)"""
        try:
            # Simplified BOLT11 decoding for demo
            if not payment_request.startswith(('lnbc', 'lntb', 'lnbcrt')):
                return None

            # Extract basic info from simplified format
            network = "mainnet" if payment_request.startswith('lnbc') else "testnet"

            # Find amount (very simplified parsing)
            amount_sats = 0
            if 'm' in payment_request:
                # milli-bitcoin
                try:
                    amount_part = payment_request.split('m')[0][4:]  # Skip 'lnbc'
                    amount_sats = int(amount_part) * 100000
                except:
                    pass

            return {
                "network": network,
                "amount_sats": amount_sats,
                "payment_request": payment_request,
                "valid": True
            }

        except Exception as e:
            self.logger.error(f"Failed to decode invoice: {e}")
            return None


def create_invoice_manager(data_dir: str = "data") -> InvoiceManager:
    """Create invoice manager instance"""
    return InvoiceManager(data_dir)


if __name__ == "__main__":
    # Test invoice manager
    print("📄 Testing Lightning Invoice Manager...")

    manager = create_invoice_manager("test_data")

    # Create test invoice
    invoice = manager.create_invoice(
        amount_sats=100000,  # 100k sats
        description="Test payment for Lightning demo",
        expiry_seconds=3600  # 1 hour
    )

    print(f"✅ Created invoice: {invoice.payment_hash[:16]}...")
    print(f"💰 Amount: {invoice.amount_sats} sats")
    print(f"📝 Description: {invoice.description}")
    print(f"⏰ Expires in: {invoice.time_until_expiry():.0f} seconds")

    # Test payment
    payment_success = manager.pay_invoice(invoice.payment_hash)
    print(f"💳 Payment: {'✅ Success' if payment_success else '❌ Failed'}")

    # Create another invoice
    manager.create_invoice(50000, "Another test payment", 1800)

    # Get statistics
    stats = manager.get_invoice_stats()
    print(f"📊 Invoice stats: {stats}")

    # List invoices
    invoices = manager.list_invoices()
    print(f"📋 Total invoices: {len(invoices)}")

    # Cleanup
    import shutil
    shutil.rmtree("test_data", ignore_errors=True)

    print("✅ Invoice manager test completed!")