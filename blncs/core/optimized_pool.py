"""A small thread-safe SQLite connection pool.

Connections are created lazily up to ``max_size`` (with ``min_size``
created up front), reused between borrowers, and handed out through
the :meth:`OptimizedConnectionPool.acquire` context manager, which
blocks while the pool is exhausted.
"""

import logging
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional

logger = logging.getLogger(__name__)


class OptimizedConnectionPool:
    """Thread-safe pool of SQLite connections to a single database file."""

    def __init__(self, db_path: str, min_size: int = 2, max_size: int = 5):
        if max_size <= 0:
            raise ValueError("max_size must be positive")
        if min_size < 0 or min_size > max_size:
            raise ValueError("min_size must be between 0 and max_size")
        self.db_path = db_path
        self.min_size = min_size
        self.max_size = max_size

        self._idle: List[sqlite3.Connection] = []
        self._created = 0
        self._total_requests = 0
        self._reuse_count = 0
        self._closed = False
        self._cond = threading.Condition()

        with self._cond:
            for _ in range(min_size):
                self._idle.append(self._new_connection())

    def _new_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._created += 1
        return conn

    @contextmanager
    def acquire(self) -> Iterator[sqlite3.Connection]:
        """Borrow a connection, waiting while the pool is exhausted."""
        conn = self._checkout()
        try:
            yield conn
        finally:
            self._checkin(conn)

    def _checkout(self) -> sqlite3.Connection:
        with self._cond:
            while True:
                if self._closed:
                    raise RuntimeError("connection pool is closed")
                if self._idle:
                    self._total_requests += 1
                    self._reuse_count += 1
                    return self._idle.pop()
                if self._created < self.max_size:
                    self._total_requests += 1
                    return self._new_connection()
                self._cond.wait()

    def _checkin(self, conn: sqlite3.Connection) -> None:
        with self._cond:
            if self._closed:
                try:
                    conn.close()
                except sqlite3.Error:
                    pass
                self._created -= 1
            else:
                self._idle.append(conn)
            self._cond.notify()

    def get_stats(self) -> Dict[str, Any]:
        """Return pool usage statistics."""
        with self._cond:
            total = self._total_requests
            return {
                "total_requests": total,
                "connections_created": self._created,
                "connections_idle": len(self._idle),
                "cache_hit_rate": (self._reuse_count / total) if total else 0.0,
            }

    def close_all(self) -> None:
        """Close every pooled connection and reject new borrowers."""
        with self._cond:
            self._closed = True
            idle, self._idle = self._idle, []
            self._created -= len(idle)
            self._cond.notify_all()
        for conn in idle:
            try:
                conn.close()
            except sqlite3.Error:
                pass
