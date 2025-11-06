#!/usr/bin/env python3
"""
Idempotency and Transaction Module
Ensures reliable transaction processing with idempotent guarantees
Implements patterns from 2025 best practices for distributed systems
"""

import hashlib
import logging
import uuid
from typing import Dict, Optional, Callable, Any, TypeVar, Awaitable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

logger = logging.getLogger(__name__)

T = TypeVar('T')


class TransactionStatus(Enum):
    """Status of an idempotent transaction"""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"


@dataclass
class TransactionRecord:
    """Record of an idempotent transaction"""
    transaction_id: str
    status: TransactionStatus
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    attempts: int = 0
    max_attempts: int = 3
    result: Optional[Any] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    idempotency_key: Optional[str] = None  # For deduplication


class IdempotencyManager:
    """
    Manages idempotent operations and transaction deduplication
    Follows patterns from distributed transaction best practices
    """

    def __init__(self, retention_hours: int = 24):
        """
        Initialize idempotency manager

        Args:
            retention_hours: How long to keep transaction records
        """
        self.transactions: Dict[str, TransactionRecord] = {}
        self.idempotency_keys: Dict[str, str] = {}  # Maps idempotency key to transaction ID
        self.retention_hours = retention_hours

    def generate_transaction_id(self) -> str:
        """Generate a unique transaction ID"""
        return str(uuid.uuid4())

    def generate_idempotency_key(self, *components: str) -> str:
        """
        Generate an idempotency key from components
        Ensures same operation always produces same key

        Args:
            *components: Components to hash (user ID, action, timestamp, etc.)

        Returns:
            Hex-encoded idempotency key
        """
        combined = "|".join(str(c) for c in components)
        return hashlib.sha256(combined.encode()).hexdigest()

    def create_transaction(
        self,
        transaction_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> TransactionRecord:
        """
        Create a new transaction record

        Args:
            transaction_id: Optional explicit transaction ID
            idempotency_key: Key for deduplication
            metadata: Additional transaction metadata

        Returns:
            Created TransactionRecord
        """
        # Check for duplicate based on idempotency key
        if idempotency_key and idempotency_key in self.idempotency_keys:
            existing_id = self.idempotency_keys[idempotency_key]
            logger.info(f"Found existing transaction for idempotency key: {existing_id}")
            return self.transactions[existing_id]

        # Create new transaction
        tid = transaction_id or self.generate_transaction_id()

        record = TransactionRecord(
            transaction_id=tid,
            status=TransactionStatus.PENDING,
            idempotency_key=idempotency_key,
            metadata=metadata or {}
        )

        self.transactions[tid] = record

        if idempotency_key:
            self.idempotency_keys[idempotency_key] = tid

        logger.info(f"Created transaction: {tid}")
        return record

    def start_processing(self, transaction_id: str) -> TransactionRecord:
        """Mark a transaction as processing"""
        if transaction_id not in self.transactions:
            raise ValueError(f"Unknown transaction: {transaction_id}")

        record = self.transactions[transaction_id]
        record.status = TransactionStatus.PROCESSING
        record.updated_at = datetime.utcnow()
        record.attempts += 1

        logger.info(
            f"Started processing transaction {transaction_id} "
            f"(attempt {record.attempts})"
        )

        return record

    def complete_transaction(
        self,
        transaction_id: str,
        result: Any
    ) -> TransactionRecord:
        """Mark a transaction as completed with result"""
        if transaction_id not in self.transactions:
            raise ValueError(f"Unknown transaction: {transaction_id}")

        record = self.transactions[transaction_id]
        record.status = TransactionStatus.COMPLETED
        record.result = result
        record.updated_at = datetime.utcnow()

        logger.info(f"Completed transaction: {transaction_id}")
        return record

    def fail_transaction(
        self,
        transaction_id: str,
        error: str,
        retry: bool = True
    ) -> TransactionRecord:
        """Mark a transaction as failed"""
        if transaction_id not in self.transactions:
            raise ValueError(f"Unknown transaction: {transaction_id}")

        record = self.transactions[transaction_id]
        record.error = error
        record.updated_at = datetime.utcnow()

        if retry and record.attempts < record.max_attempts:
            record.status = TransactionStatus.RETRYING
            logger.warning(
                f"Transaction {transaction_id} failed but will retry "
                f"({record.attempts}/{record.max_attempts}): {error}"
            )
        else:
            record.status = TransactionStatus.FAILED
            logger.error(
                f"Transaction {transaction_id} failed permanently: {error}"
            )

        return record

    def get_transaction(self, transaction_id: str) -> Optional[TransactionRecord]:
        """Retrieve a transaction record"""
        return self.transactions.get(transaction_id)

    def get_by_idempotency_key(self, key: str) -> Optional[TransactionRecord]:
        """Get transaction by idempotency key"""
        if key in self.idempotency_keys:
            transaction_id = self.idempotency_keys[key]
            return self.transactions.get(transaction_id)
        return None

    def cleanup_old_transactions(self) -> int:
        """Remove old transaction records beyond retention period"""
        cutoff_time = datetime.utcnow() - timedelta(hours=self.retention_hours)
        to_delete = [
            tid for tid, record in self.transactions.items()
            if record.updated_at < cutoff_time
        ]

        for tid in to_delete:
            record = self.transactions.pop(tid)
            if record.idempotency_key:
                self.idempotency_keys.pop(record.idempotency_key, None)

        logger.info(f"Cleaned up {len(to_delete)} old transactions")
        return len(to_delete)


async def idempotent_execute(
    manager: IdempotencyManager,
    operation: Callable[[], Awaitable[T]],
    transaction_id: str,
    max_retries: int = 3,
    retry_delay: float = 0.1
) -> T:
    """
    Execute an operation with idempotent guarantees

    Args:
        manager: IdempotencyManager instance
        operation: Async operation to execute
        transaction_id: Unique transaction ID
        max_retries: Maximum retry attempts
        retry_delay: Delay between retries (seconds)

    Returns:
        Result from operation

    Raises:
        Exception: If all retries exhausted
    """
    record = manager.get_transaction(transaction_id)

    # If already completed, return cached result
    if record and record.status == TransactionStatus.COMPLETED:
        logger.info(f"Returning cached result for transaction: {transaction_id}")
        return record.result

    # If already failed, don't retry
    if record and record.status == TransactionStatus.FAILED:
        raise RuntimeError(f"Transaction {transaction_id} already failed: {record.error}")

    # Create or get transaction record
    if not record:
        record = manager.create_transaction(transaction_id=transaction_id)

    for attempt in range(max_retries):
        try:
            manager.start_processing(transaction_id)

            result = await operation()

            manager.complete_transaction(transaction_id, result)
            return result

        except Exception as e:
            manager.fail_transaction(
                transaction_id,
                str(e),
                retry=attempt < max_retries - 1
            )

            if attempt < max_retries - 1:
                import asyncio
                await asyncio.sleep(retry_delay * (2 ** attempt))  # Exponential backoff
            else:
                raise

    raise RuntimeError(f"Transaction {transaction_id} exhausted all retries")


class UniqueConstraintValidator:
    """
    Validates unique constraints to prevent duplicate operations
    Implements database-level uniqueness for transactions
    """

    def __init__(self):
        self.unique_values: Dict[str, set] = {}

    def register_unique_field(self, field_name: str) -> None:
        """Register a field as unique"""
        if field_name not in self.unique_values:
            self.unique_values[field_name] = set()

    def check_unique(self, field_name: str, value: Any) -> bool:
        """Check if a value is unique for a field"""
        if field_name not in self.unique_values:
            return True

        return value not in self.unique_values[field_name]

    def add_unique_value(self, field_name: str, value: Any) -> None:
        """Add a value to unique field"""
        if field_name not in self.unique_values:
            self.unique_values[field_name] = set()

        self.unique_values[field_name].add(value)

    def remove_unique_value(self, field_name: str, value: Any) -> None:
        """Remove a value from unique field"""
        if field_name in self.unique_values:
            self.unique_values[field_name].discard(value)


class DistributedLock:
    """
    Simple distributed lock for transaction coordination
    In production, use Redis or database-backed locks
    """

    def __init__(self, lock_timeout_seconds: int = 30):
        self.locks: Dict[str, datetime] = {}
        self.lock_timeout = lock_timeout_seconds

    def acquire_lock(self, resource_id: str) -> bool:
        """Try to acquire a lock"""
        now = datetime.utcnow()

        # Check if lock exists and is still valid
        if resource_id in self.locks:
            lock_time = self.locks[resource_id]
            if (now - lock_time).seconds < self.lock_timeout:
                return False  # Lock held

        self.locks[resource_id] = now
        logger.info(f"Acquired lock for resource: {resource_id}")
        return True

    def release_lock(self, resource_id: str) -> None:
        """Release a lock"""
        self.locks.pop(resource_id, None)
        logger.info(f"Released lock for resource: {resource_id}")

    def is_locked(self, resource_id: str) -> bool:
        """Check if a resource is locked"""
        if resource_id not in self.locks:
            return False

        now = datetime.utcnow()
        lock_time = self.locks[resource_id]

        if (now - lock_time).seconds >= self.lock_timeout:
            self.release_lock(resource_id)
            return False

        return True


__all__ = [
    'TransactionStatus',
    'TransactionRecord',
    'IdempotencyManager',
    'idempotent_execute',
    'UniqueConstraintValidator',
    'DistributedLock',
]
