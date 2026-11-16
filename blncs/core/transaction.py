"""Transactional helpers for SQLite-backed components.

Provides a small transaction manager (commit on success, rollback on
error, with statistics) and a batched executor for bulk statements.
"""

import logging
import sqlite3
from contextlib import contextmanager
from typing import Any, Dict, Iterable, Iterator, List, Sequence, Tuple

logger = logging.getLogger(__name__)


class TransactionManager:
    """Run blocks of statements on a connection as one transaction."""

    def __init__(self) -> None:
        self._committed = 0
        self._rolled_back = 0

    @contextmanager
    def transaction(self, conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
        """Context manager: commit on clean exit, roll back on error."""
        try:
            yield conn
            conn.commit()
            self._committed += 1
        except Exception:
            conn.rollback()
            self._rolled_back += 1
            raise

    def get_stats(self) -> Dict[str, int]:
        """Return transaction outcome counters."""
        return {
            "committed": self._committed,
            "rolled_back": self._rolled_back,
        }


def batch_execute(
    conn: sqlite3.Connection,
    operations: Iterable[Tuple[str, Sequence[Any]]],
    batch_size: int = 20,
) -> int:
    """Execute many parameterized statements in batches.

    ``operations`` is an iterable of ``(sql, params)`` pairs. Statements
    are grouped by SQL text inside each batch and run with
    ``executemany``; each batch is committed before the next starts.
    Returns the number of statements executed.
    """
    if batch_size <= 0:
        raise ValueError("batch_size must be positive")

    ops: List[Tuple[str, Sequence[Any]]] = list(operations)
    executed = 0
    for start in range(0, len(ops), batch_size):
        chunk = ops[start : start + batch_size]
        # Group consecutive statements that share the same SQL text.
        grouped: Dict[str, List[Sequence[Any]]] = {}
        order: List[str] = []
        for sql, params in chunk:
            if sql not in grouped:
                grouped[sql] = []
                order.append(sql)
            grouped[sql].append(params)
        for sql in order:
            conn.executemany(sql, grouped[sql])
            executed += len(grouped[sql])
        conn.commit()

    logger.debug("batch_execute: %d statements in batches of %d", executed, batch_size)
    return executed
