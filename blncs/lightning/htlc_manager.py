"""
BLNCS HTLC Manager
Hash Time Locked Contract management for Lightning Network
"""

import time
import json
import logging
import hashlib
import secrets
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
from enum import Enum


class HTLCState(Enum):
    """HTLC states"""
    PENDING = "pending"
    OFFERED = "offered"
    RECEIVED = "received"
    FULFILLED = "fulfilled"
    FAILED = "failed"
    EXPIRED = "expired"


@dataclass
class HTLC:
    """Hash Time Locked Contract"""
    htlc_id: str
    payment_hash: str
    amount_sats: int
    cltv_expiry: int  # Block height expiry
    state: HTLCState
    channel_id: str
    direction: str  # 'outgoing' or 'incoming'
    created_at: float
    preimage: Optional[str] = None
    failure_reason: Optional[str] = None
    settled_at: Optional[float] = None

    def is_expired(self, current_block_height: int) -> bool:
        """Check if HTLC is expired"""
        return current_block_height >= self.cltv_expiry

    def time_until_expiry(self, current_block_height: int) -> int:
        """Get blocks until expiry"""
        return max(0, self.cltv_expiry - current_block_height)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['state'] = self.state.value
        return data


class HTLCManager:
    """HTLC management system"""

    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)

        self.htlcs: Dict[str, HTLC] = {}
        self.payment_hash_map: Dict[str, str] = {}  # payment_hash -> htlc_id

        self.htlc_file = self.data_dir / "htlcs.json"
        self.logger = logging.getLogger("BLNCS_HTLCManager")

        # HTLC limits
        self.max_htlc_value = 21000000 * 100000000  # 21M BTC in sats
        self.min_htlc_value = 1000  # 1000 sats minimum
        self.default_cltv_delta = 144  # ~24 hours at 10min blocks

        self._load_htlcs()

    def _load_htlcs(self):
        """Load HTLCs from storage"""
        if self.htlc_file.exists():
            try:
                with open(self.htlc_file, 'r') as f:
                    data = json.load(f)
                    for htlc_id, htlc_data in data.items():
                        htlc_data['state'] = HTLCState(htlc_data['state'])
                        htlc = HTLC(**htlc_data)
                        self.htlcs[htlc_id] = htlc
                        self.payment_hash_map[htlc.payment_hash] = htlc_id

                self.logger.info(f"Loaded {len(self.htlcs)} HTLCs")
            except Exception as e:
                self.logger.error(f"Failed to load HTLCs: {e}")

    def _save_htlcs(self):
        """Save HTLCs to storage"""
        try:
            data = {htlc_id: htlc.to_dict() for htlc_id, htlc in self.htlcs.items()}
            with open(self.htlc_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save HTLCs: {e}")

    def create_htlc(self, payment_hash: str, amount_sats: int,
                   channel_id: str, direction: str,
                   cltv_expiry: Optional[int] = None) -> Optional[HTLC]:
        """Create a new HTLC"""
        # Validate inputs
        if amount_sats < self.min_htlc_value or amount_sats > self.max_htlc_value:
            self.logger.error(f"Invalid HTLC amount: {amount_sats}")
            return None

        if len(payment_hash) != 64:  # 32 bytes hex
            self.logger.error(f"Invalid payment hash length: {len(payment_hash)}")
            return None

        if direction not in ['outgoing', 'incoming']:
            self.logger.error(f"Invalid direction: {direction}")
            return None

        # Set expiry if not provided
        if cltv_expiry is None:
            # Simulate current block height + delta
            current_block = 750000  # Simulated block height
            cltv_expiry = current_block + self.default_cltv_delta

        # Generate HTLC ID
        htlc_id = f"htlc_{int(time.time() * 1000)}_{secrets.token_hex(8)}"

        # Check for duplicate payment hash
        if payment_hash in self.payment_hash_map:
            existing_htlc_id = self.payment_hash_map[payment_hash]
            existing_htlc = self.htlcs[existing_htlc_id]
            if existing_htlc.state not in [HTLCState.FULFILLED, HTLCState.FAILED, HTLCState.EXPIRED]:
                self.logger.warning(f"HTLC already exists for payment hash: {payment_hash[:16]}...")
                return existing_htlc

        # Create HTLC
        htlc = HTLC(
            htlc_id=htlc_id,
            payment_hash=payment_hash,
            amount_sats=amount_sats,
            cltv_expiry=cltv_expiry,
            state=HTLCState.PENDING,
            channel_id=channel_id,
            direction=direction,
            created_at=time.time()
        )

        self.htlcs[htlc_id] = htlc
        self.payment_hash_map[payment_hash] = htlc_id
        self._save_htlcs()

        self.logger.info(f"Created HTLC: {htlc_id} for {amount_sats} sats")
        return htlc

    def offer_htlc(self, htlc_id: str) -> bool:
        """Mark HTLC as offered"""
        htlc = self.htlcs.get(htlc_id)
        if not htlc or htlc.state != HTLCState.PENDING:
            return False

        htlc.state = HTLCState.OFFERED
        self._save_htlcs()

        self.logger.info(f"HTLC offered: {htlc_id}")
        return True

    def receive_htlc(self, htlc_id: str) -> bool:
        """Mark HTLC as received"""
        htlc = self.htlcs.get(htlc_id)
        if not htlc or htlc.state != HTLCState.OFFERED:
            return False

        htlc.state = HTLCState.RECEIVED
        self._save_htlcs()

        self.logger.info(f"HTLC received: {htlc_id}")
        return True

    def fulfill_htlc(self, htlc_id: str, preimage: str) -> bool:
        """Fulfill HTLC with preimage"""
        htlc = self.htlcs.get(htlc_id)
        if not htlc:
            return False

        # Verify preimage
        if not self._verify_preimage(htlc.payment_hash, preimage):
            self.logger.error(f"Invalid preimage for HTLC: {htlc_id}")
            return False

        htlc.state = HTLCState.FULFILLED
        htlc.preimage = preimage
        htlc.settled_at = time.time()
        self._save_htlcs()

        self.logger.info(f"HTLC fulfilled: {htlc_id}")
        return True

    def fail_htlc(self, htlc_id: str, reason: str = "payment_failed") -> bool:
        """Fail HTLC with reason"""
        htlc = self.htlcs.get(htlc_id)
        if not htlc or htlc.state in [HTLCState.FULFILLED, HTLCState.FAILED]:
            return False

        htlc.state = HTLCState.FAILED
        htlc.failure_reason = reason
        htlc.settled_at = time.time()
        self._save_htlcs()

        self.logger.info(f"HTLC failed: {htlc_id} - {reason}")
        return True

    def expire_htlc(self, htlc_id: str) -> bool:
        """Mark HTLC as expired"""
        htlc = self.htlcs.get(htlc_id)
        if not htlc or htlc.state in [HTLCState.FULFILLED, HTLCState.FAILED, HTLCState.EXPIRED]:
            return False

        htlc.state = HTLCState.EXPIRED
        htlc.settled_at = time.time()
        self._save_htlcs()

        self.logger.info(f"HTLC expired: {htlc_id}")
        return True

    def _verify_preimage(self, payment_hash: str, preimage: str) -> bool:
        """Verify preimage produces the payment hash"""
        try:
            preimage_bytes = bytes.fromhex(preimage)
            computed_hash = hashlib.sha256(preimage_bytes).hexdigest()
            return computed_hash == payment_hash
        except Exception:
            return False

    def get_htlc(self, htlc_id: str) -> Optional[HTLC]:
        """Get HTLC by ID"""
        return self.htlcs.get(htlc_id)

    def get_htlc_by_payment_hash(self, payment_hash: str) -> Optional[HTLC]:
        """Get HTLC by payment hash"""
        htlc_id = self.payment_hash_map.get(payment_hash)
        if htlc_id:
            return self.htlcs.get(htlc_id)
        return None

    def list_htlcs(self, channel_id: str = None, state: HTLCState = None,
                  direction: str = None) -> List[HTLC]:
        """List HTLCs with optional filters"""
        htlcs = list(self.htlcs.values())

        if channel_id:
            htlcs = [h for h in htlcs if h.channel_id == channel_id]

        if state:
            htlcs = [h for h in htlcs if h.state == state]

        if direction:
            htlcs = [h for h in htlcs if h.direction == direction]

        # Sort by creation time (newest first)
        htlcs.sort(key=lambda x: x.created_at, reverse=True)

        return htlcs

    def check_expiring_htlcs(self, current_block_height: int,
                           blocks_ahead: int = 10) -> List[HTLC]:
        """Find HTLCs expiring soon"""
        expiring_htlcs = []

        for htlc in self.htlcs.values():
            if htlc.state in [HTLCState.OFFERED, HTLCState.RECEIVED]:
                blocks_until_expiry = htlc.time_until_expiry(current_block_height)
                if blocks_until_expiry <= blocks_ahead:
                    expiring_htlcs.append(htlc)

        return expiring_htlcs

    def process_block_expiry(self, current_block_height: int) -> int:
        """Process HTLC expiries for current block"""
        expired_count = 0

        for htlc in self.htlcs.values():
            if htlc.state in [HTLCState.OFFERED, HTLCState.RECEIVED]:
                if htlc.is_expired(current_block_height):
                    self.expire_htlc(htlc.htlc_id)
                    expired_count += 1

        return expired_count

    def get_htlc_stats(self) -> Dict[str, Any]:
        """Get HTLC statistics"""
        if not self.htlcs:
            return {"total_htlcs": 0}

        htlcs = list(self.htlcs.values())

        # Count by state
        state_counts = {}
        for state in HTLCState:
            state_counts[state.value] = sum(1 for h in htlcs if h.state == state)

        # Count by direction
        direction_counts = {
            "outgoing": sum(1 for h in htlcs if h.direction == "outgoing"),
            "incoming": sum(1 for h in htlcs if h.direction == "incoming")
        }

        # Value statistics
        total_value = sum(h.amount_sats for h in htlcs)
        pending_value = sum(h.amount_sats for h in htlcs
                           if h.state in [HTLCState.PENDING, HTLCState.OFFERED, HTLCState.RECEIVED])

        fulfilled_htlcs = [h for h in htlcs if h.state == HTLCState.FULFILLED]
        success_rate = (len(fulfilled_htlcs) / len(htlcs)) * 100 if htlcs else 0

        return {
            "total_htlcs": len(htlcs),
            "state_counts": state_counts,
            "direction_counts": direction_counts,
            "total_value_sats": total_value,
            "pending_value_sats": pending_value,
            "success_rate": success_rate,
            "avg_amount_sats": total_value / len(htlcs) if htlcs else 0
        }

    def cleanup_old_htlcs(self, older_than_days: int = 30) -> int:
        """Remove old settled HTLCs"""
        cutoff_time = time.time() - (older_than_days * 24 * 3600)
        old_htlcs = []

        for htlc_id, htlc in self.htlcs.items():
            if (htlc.state in [HTLCState.FULFILLED, HTLCState.FAILED, HTLCState.EXPIRED] and
                htlc.settled_at and htlc.settled_at < cutoff_time):
                old_htlcs.append(htlc_id)

        for htlc_id in old_htlcs:
            htlc = self.htlcs[htlc_id]
            del self.payment_hash_map[htlc.payment_hash]
            del self.htlcs[htlc_id]

        if old_htlcs:
            self._save_htlcs()
            self.logger.info(f"Cleaned up {len(old_htlcs)} old HTLCs")

        return len(old_htlcs)


def create_htlc_manager(data_dir: str = "data") -> HTLCManager:
    """Create HTLC manager instance"""
    return HTLCManager(data_dir)


def generate_payment_hash_and_preimage() -> Tuple[str, str]:
    """Generate payment hash and preimage pair"""
    preimage = secrets.token_bytes(32)
    payment_hash = hashlib.sha256(preimage).hexdigest()
    return payment_hash, preimage.hex()


if __name__ == "__main__":
    # Test HTLC manager
    print("🔗 Testing Lightning HTLC Manager...")

    manager = create_htlc_manager("test_data")

    # Generate test payment
    payment_hash, preimage = generate_payment_hash_and_preimage()

    # Create test HTLC
    htlc = manager.create_htlc(
        payment_hash=payment_hash,
        amount_sats=100000,  # 100k sats
        channel_id="test_channel_123",
        direction="outgoing",
        cltv_expiry=750144  # ~24 hours from now
    )

    print(f"🔗 HTLC created: {htlc.htlc_id if htlc else 'Failed'}")

    if htlc:
        # Test HTLC lifecycle
        manager.offer_htlc(htlc.htlc_id)
        manager.receive_htlc(htlc.htlc_id)
        fulfill_success = manager.fulfill_htlc(htlc.htlc_id, preimage)

        print(f"💰 HTLC fulfilled: {'✅' if fulfill_success else '❌'}")

        # Create another HTLC and fail it
        payment_hash2, _ = generate_payment_hash_and_preimage()
        htlc2 = manager.create_htlc(payment_hash2, 50000, "test_channel_123", "incoming")

        if htlc2:
            manager.offer_htlc(htlc2.htlc_id)
            manager.fail_htlc(htlc2.htlc_id, "insufficient_funds")

        # Get statistics
        stats = manager.get_htlc_stats()
        print(f"📊 Total HTLCs: {stats['total_htlcs']}")
        print(f"✅ Success rate: {stats['success_rate']:.1f}%")
        print(f"💰 Total value: {stats['total_value_sats']} sats")

        # Test expiry check
        expiring = manager.check_expiring_htlcs(750140, 10)  # Check 10 blocks ahead
        print(f"⏰ Expiring HTLCs: {len(expiring)}")

    # Cleanup
    import shutil
    shutil.rmtree("test_data", ignore_errors=True)

    print("✅ HTLC manager test completed!")