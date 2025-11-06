"""
BLNCS Multi-Path Payment Manager
Advanced MPP implementation based on 2025 research and LND best practices

Based on:
- LND 0.10+ MPP implementation
- Lightning Engineering official documentation
- 2025 best practices for payment splitting
"""

import time
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class PaymentPartStatus(Enum):
    """Status of individual payment parts"""
    PENDING = "pending"
    IN_FLIGHT = "in_flight"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass
class PaymentPart:
    """Individual part of a multi-path payment"""
    part_id: int
    amount_sats: int
    route: List[str]
    status: PaymentPartStatus = PaymentPartStatus.PENDING
    fee_sats: int = 0
    attempt: int = 1
    created_at: float = field(default_factory=time.time)
    settled_at: Optional[float] = None


@dataclass
class MultiPathPayment:
    """Multi-path payment structure"""
    payment_hash: str
    total_amount_sats: int
    parts: List[PaymentPart]
    timeout_seconds: int = 60
    status: str = "pending"
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None


class MultipathPaymentManager:
    """
    Advanced Multi-Path Payment (MPP) Manager

    Features:
    - Intelligent payment splitting across viable channels
    - Split-in-half retry strategy (LND approach)
    - Timeout management for HTLC coordination
    - Atomic settlement (all or nothing)

    Based on Lightning Network MPP protocol (TLV format)
    """

    def __init__(self, channel_manager, routing_engine=None):
        self.channel_manager = channel_manager
        self.routing_engine = routing_engine

        self.active_payments: Dict[str, MultiPathPayment] = {}
        self.payment_timeout = 60  # seconds, matching receiver wait time

        # MPP configuration
        self.min_shard_size_sats = 1000  # Minimum payment part size
        self.max_parts = 16  # Maximum number of parts

        logger.info("Multi-path payment manager initialized")

    def can_use_mpp(self, total_amount_sats: int, dest_pubkey: str) -> bool:
        """
        Check if MPP is beneficial for this payment

        MPP is useful when:
        - No single channel has sufficient capacity
        - Multiple paths available can handle smaller amounts
        - Total amount > min_shard_size
        """
        # Find channels with capacity
        channels = self.channel_manager.find_route_capacity(total_amount_sats)

        # If we have a direct channel with capacity, MPP not needed
        if len(channels) > 0:
            return False

        # Check if we can split into smaller viable parts
        viable_channels = self.channel_manager.list_channels(active_only=True)
        viable_channels = [ch for ch in viable_channels
                          if ch.available_capacity() >= self.min_shard_size_sats]

        # Need at least 2 viable paths for MPP
        return len(viable_channels) >= 2

    def split_payment(self, total_amount_sats: int, dest_pubkey: str,
                     max_fee_sats: Optional[int] = None) -> Optional[MultiPathPayment]:
        """
        Split payment into multiple parts using intelligent strategy

        Strategy:
        1. Find all viable paths (channels with available capacity)
        2. Calculate optimal split based on path capacities
        3. Use split-in-half approach for failed attempts
        4. Ensure atomic settlement (all parts must succeed)

        Args:
            total_amount_sats: Total payment amount
            dest_pubkey: Destination node public key
            max_fee_sats: Maximum acceptable fee

        Returns:
            MultiPathPayment object or None if splitting not possible
        """
        # Get viable channels
        viable_channels = self._find_viable_paths(total_amount_sats)

        if len(viable_channels) < 2:
            logger.warning(f"Not enough viable paths for MPP: {len(viable_channels)}")
            return None

        # Optimize payment split
        payment_parts = self._optimize_split(total_amount_sats, viable_channels, max_fee_sats)

        if not payment_parts:
            return None

        # Create multi-path payment
        payment_hash = self._generate_payment_hash()

        mpp = MultiPathPayment(
            payment_hash=payment_hash,
            total_amount_sats=total_amount_sats,
            parts=payment_parts,
            timeout_seconds=self.payment_timeout
        )

        self.active_payments[payment_hash] = mpp

        logger.info(f"Created MPP: {payment_hash[:16]}... with {len(payment_parts)} parts")
        return mpp

    def _find_viable_paths(self, amount_sats: int) -> List[Any]:
        """
        Find channels that can potentially route payment parts

        Returns channels with:
        - Active state
        - Sufficient capacity for minimum shard
        - Good balance ratio
        """
        channels = self.channel_manager.list_channels(active_only=True)

        viable = []
        for channel in channels:
            capacity = channel.available_capacity()

            # Must have minimum shard capacity
            if capacity >= self.min_shard_size_sats:
                # Prefer balanced channels for reliability
                balance_score = 1.0 - abs(0.5 - channel.balance_ratio())

                viable.append({
                    'channel': channel,
                    'capacity': capacity,
                    'balance_score': balance_score
                })

        # Sort by capacity * balance_score for optimal selection
        viable.sort(key=lambda x: x['capacity'] * x['balance_score'], reverse=True)

        return viable

    def _optimize_split(self, total_amount: int, viable_paths: List[Dict],
                       max_fee: Optional[int]) -> List[PaymentPart]:
        """
        Optimize payment splitting across available paths

        Algorithm:
        1. Try uniform distribution first
        2. Adjust based on path capacities
        3. Ensure each part >= min_shard_size
        4. Limit to max_parts
        """
        num_paths = min(len(viable_paths), self.max_parts)

        if num_paths == 0:
            return []

        # Calculate base amount per part
        base_amount = total_amount // num_paths
        remainder = total_amount % num_paths

        # Ensure base amount meets minimum
        if base_amount < self.min_shard_size_sats:
            # Reduce number of parts
            num_paths = total_amount // self.min_shard_size_sats
            if num_paths < 2:
                return []
            base_amount = total_amount // num_paths
            remainder = total_amount % num_paths

        parts = []
        for i in range(num_paths):
            path_info = viable_paths[i]
            channel = path_info['channel']

            # Distribute remainder across first parts
            part_amount = base_amount + (1 if i < remainder else 0)

            # Verify channel can handle this amount
            if part_amount > channel.available_capacity():
                part_amount = channel.available_capacity()

            # Create payment part
            part = PaymentPart(
                part_id=i,
                amount_sats=part_amount,
                route=[channel.channel_id],  # Simplified route
                fee_sats=self._estimate_fee(part_amount, 1)  # 1 hop estimate
            )

            parts.append(part)

        # Verify total amount
        total_split = sum(p.amount_sats for p in parts)
        if total_split < total_amount:
            logger.warning(f"Split amount {total_split} < requested {total_amount}")
            return []

        # Check fee constraint
        if max_fee:
            total_fee = sum(p.fee_sats for p in parts)
            if total_fee > max_fee:
                logger.warning(f"Total MPP fee {total_fee} > max {max_fee}")
                return []

        return parts

    def execute_mpp(self, mpp: MultiPathPayment) -> Dict[str, Any]:
        """
        Execute multi-path payment

        Process:
        1. Send all payment parts (HTLCs)
        2. Wait for all parts to arrive (timeout: 60s)
        3. If all succeed, reveal pre-image
        4. If any fail, cancel all parts

        Returns:
            Result dictionary with status and details
        """
        logger.info(f"Executing MPP {mpp.payment_hash[:16]}... with {len(mpp.parts)} parts")

        # Track execution
        start_time = time.time()
        successful_parts = []
        failed_parts = []

        # Send all parts
        for part in mpp.parts:
            try:
                part.status = PaymentPartStatus.IN_FLIGHT

                # Simulate sending HTLC
                # In real implementation, this would use Lightning client
                result = self._send_payment_part(part)

                if result['success']:
                    part.status = PaymentPartStatus.SUCCEEDED
                    part.settled_at = time.time()
                    successful_parts.append(part)
                else:
                    part.status = PaymentPartStatus.FAILED
                    failed_parts.append(part)

            except Exception as e:
                logger.error(f"Failed to send part {part.part_id}: {e}")
                part.status = PaymentPartStatus.FAILED
                failed_parts.append(part)

        # Check if all parts succeeded within timeout
        elapsed = time.time() - start_time

        if len(successful_parts) == len(mpp.parts) and elapsed < mpp.timeout_seconds:
            # All parts succeeded - atomic success
            mpp.status = "succeeded"
            mpp.completed_at = time.time()

            total_fee = sum(p.fee_sats for p in successful_parts)

            logger.info(f"MPP succeeded: {mpp.payment_hash[:16]}... "
                       f"Amount: {mpp.total_amount_sats} sats, Fee: {total_fee} sats")

            return {
                'success': True,
                'payment_hash': mpp.payment_hash,
                'amount_sats': mpp.total_amount_sats,
                'fee_sats': total_fee,
                'parts_count': len(successful_parts),
                'elapsed_seconds': elapsed
            }
        else:
            # At least one part failed - atomic failure
            mpp.status = "failed"

            # Cancel successful parts (in real impl, would release HTLCs)
            for part in successful_parts:
                self._cancel_payment_part(part)

            logger.warning(f"MPP failed: {mpp.payment_hash[:16]}... "
                          f"Succeeded: {len(successful_parts)}/{len(mpp.parts)}")

            return {
                'success': False,
                'payment_hash': mpp.payment_hash,
                'reason': 'One or more parts failed',
                'succeeded_parts': len(successful_parts),
                'failed_parts': len(failed_parts),
                'elapsed_seconds': elapsed
            }

    def retry_failed_mpp(self, payment_hash: str, use_split_strategy: bool = True) -> Dict[str, Any]:
        """
        Retry failed MPP with split-in-half strategy

        LND approach: When paths fail, split the failed parts in half
        and try alternative routes
        """
        mpp = self.active_payments.get(payment_hash)
        if not mpp:
            return {'success': False, 'reason': 'Payment not found'}

        failed_parts = [p for p in mpp.parts if p.status == PaymentPartStatus.FAILED]

        if not failed_parts:
            return {'success': False, 'reason': 'No failed parts to retry'}

        logger.info(f"Retrying MPP with {len(failed_parts)} failed parts")

        # Split failed parts in half
        new_parts = []
        for part in failed_parts:
            if use_split_strategy and part.amount_sats >= self.min_shard_size_sats * 2:
                # Split in half
                half_amount = part.amount_sats // 2

                new_parts.extend([
                    PaymentPart(
                        part_id=len(mpp.parts) + len(new_parts),
                        amount_sats=half_amount,
                        route=part.route,
                        attempt=part.attempt + 1
                    ),
                    PaymentPart(
                        part_id=len(mpp.parts) + len(new_parts) + 1,
                        amount_sats=part.amount_sats - half_amount,
                        route=part.route,
                        attempt=part.attempt + 1
                    )
                ])
            else:
                # Retry same part with different route
                part.attempt += 1
                part.status = PaymentPartStatus.PENDING
                new_parts.append(part)

        # Replace failed parts with new split
        mpp.parts = [p for p in mpp.parts if p.status == PaymentPartStatus.SUCCEEDED] + new_parts

        # Execute retry
        return self.execute_mpp(mpp)

    def _send_payment_part(self, part: PaymentPart) -> Dict[str, Any]:
        """
        Send individual payment part (HTLC)

        In real implementation, this would:
        - Create HTLC with payment hash
        - Set timeout
        - Route through specified path
        - Wait for pre-image
        """
        # Simulate sending
        # Success rate simulation: 95% for demonstration
        import random
        success = random.random() > 0.05

        return {
            'success': success,
            'part_id': part.part_id,
            'amount_sats': part.amount_sats
        }

    def _cancel_payment_part(self, part: PaymentPart):
        """Cancel/release HTLC for payment part"""
        logger.debug(f"Cancelling payment part {part.part_id}")
        # In real implementation, would release HTLC
        pass

    def _estimate_fee(self, amount_sats: int, num_hops: int) -> int:
        """Estimate routing fee for payment part"""
        # Simple fee estimation: 1000 ppm * hops
        fee_rate_ppm = 1000
        return (amount_sats * fee_rate_ppm * num_hops) // 1_000_000

    def _generate_payment_hash(self) -> str:
        """Generate unique payment hash"""
        import hashlib
        import os
        return hashlib.sha256(os.urandom(32)).hexdigest()

    def get_payment_status(self, payment_hash: str) -> Optional[Dict[str, Any]]:
        """Get status of multi-path payment"""
        mpp = self.active_payments.get(payment_hash)
        if not mpp:
            return None

        return {
            'payment_hash': payment_hash,
            'total_amount_sats': mpp.total_amount_sats,
            'status': mpp.status,
            'parts_count': len(mpp.parts),
            'succeeded_parts': len([p for p in mpp.parts if p.status == PaymentPartStatus.SUCCEEDED]),
            'failed_parts': len([p for p in mpp.parts if p.status == PaymentPartStatus.FAILED]),
            'created_at': mpp.created_at,
            'completed_at': mpp.completed_at
        }

    def cleanup_old_payments(self, max_age_hours: int = 24):
        """Remove old completed/failed payments"""
        cutoff = time.time() - (max_age_hours * 3600)

        to_remove = []
        for payment_hash, mpp in self.active_payments.items():
            if mpp.status in ['succeeded', 'failed'] and mpp.created_at < cutoff:
                to_remove.append(payment_hash)

        for payment_hash in to_remove:
            del self.active_payments[payment_hash]

        if to_remove:
            logger.info(f"Cleaned up {len(to_remove)} old MPP records")


def create_mpp_manager(channel_manager, routing_engine=None):
    """Factory function to create MPP manager"""
    return MultipathPaymentManager(channel_manager, routing_engine)


__all__ = [
    'MultipathPaymentManager',
    'MultiPathPayment',
    'PaymentPart',
    'PaymentPartStatus',
    'create_mpp_manager'
]
