"""Single-use, short-lived confirmation tokens for Lightning payments.

Paying an invoice through the REST API is a two-step flow:

1. The client submits the invoice.  The API validates it, enforces the
   amount limit, and returns a confirmation token bound to
   (authenticated identity, invoice, amount).
2. The client repeats the request together with the token.  Only then
   is the payment executed.

Tokens are random, expire quickly, and are consumed on first use --
including on a failed match, so a token cannot be probed repeatedly.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple

__all__ = ["PaymentConfirmationStore"]


@dataclass
class _ConfirmationRecord:
    identity: str
    invoice_digest: str
    amount_msat: int
    expires_at: float


class PaymentConfirmationStore:
    """In-memory store for payment confirmation tokens.

    The store is process-local: a token issued by one API process can
    only be redeemed against the same process.  That is intentional --
    confirmation is an interactive, seconds-scale step.
    """

    def __init__(
        self,
        ttl_seconds: int = 120,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._ttl_seconds = int(ttl_seconds)
        self._clock = clock
        self._lock = threading.Lock()
        self._records: Dict[str, _ConfirmationRecord] = {}

    @property
    def ttl_seconds(self) -> int:
        return self._ttl_seconds

    @staticmethod
    def _digest(payment_request: str) -> str:
        return hashlib.sha256(payment_request.strip().lower().encode("utf-8")).hexdigest()

    def issue(self, identity: str, payment_request: str, amount_msat: int) -> Tuple[str, float]:
        """Create a token bound to (identity, invoice, amount).

        Returns ``(token, expires_at_epoch)``.
        """
        token = secrets.token_urlsafe(32)
        expires_at = self._clock() + self._ttl_seconds
        record = _ConfirmationRecord(
            identity=str(identity),
            invoice_digest=self._digest(payment_request),
            amount_msat=int(amount_msat),
            expires_at=expires_at,
        )
        with self._lock:
            self._prune_expired_locked()
            self._records[token] = record
        return token, expires_at

    def consume(
        self,
        token: Optional[str],
        identity: str,
        payment_request: str,
        amount_msat: int,
    ) -> bool:
        """Redeem a token.  Returns True exactly once per issued token.

        The record is removed on any consume attempt, successful or
        not, and must match the identity, invoice, and amount it was
        issued for, and must not be expired.
        """
        if not token or not isinstance(token, str):
            return False

        with self._lock:
            record = self._records.pop(token, None)

        if record is None:
            return False
        if record.expires_at < self._clock():
            return False
        if record.identity != str(identity):
            return False
        if record.amount_msat != int(amount_msat):
            return False
        if not hmac.compare_digest(record.invoice_digest, self._digest(payment_request)):
            return False
        return True

    def pending_count(self) -> int:
        with self._lock:
            self._prune_expired_locked()
            return len(self._records)

    def _prune_expired_locked(self) -> None:
        now = self._clock()
        expired = [t for t, r in self._records.items() if r.expires_at < now]
        for token in expired:
            del self._records[token]
