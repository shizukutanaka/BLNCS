"""Small SQLite database manager driven by the BLNCS config file.

The database location is taken from the ``database`` section of the
JSON config file (``path``, or a ``sqlite:///`` ``url``). When the
config file or the setting is missing, a ``database.db`` file next to
the config file is used.
"""

import json
import logging
import os
import sqlite3
from typing import Any, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Minimal SQLite access layer bound to a config file location."""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.db_path = self._resolve_db_path(config_path)
        self._conn: Optional[sqlite3.Connection] = None

    @staticmethod
    def _resolve_db_path(config_path: Optional[str]) -> str:
        if config_path:
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    config = json.load(f)
                database = (
                    config.get("database", {}) if isinstance(config, dict) else {}
                )
                path = database.get("path")
                if path:
                    return path
                url = database.get("url")
                if isinstance(url, str) and url.startswith("sqlite:///"):
                    return url[len("sqlite:///") :]
            except (OSError, ValueError) as e:
                logger.warning(
                    f"Could not read database settings from {config_path}: {e}"
                )
            return os.path.join(
                os.path.dirname(os.path.abspath(config_path)), "database.db"
            )
        return "database.db"

    def connect(self) -> bool:
        """Open the database connection. Returns True on success."""
        try:
            directory = os.path.dirname(os.path.abspath(self.db_path))
            os.makedirs(directory, exist_ok=True)
            self._conn = sqlite3.connect(self.db_path)
            return True
        except sqlite3.Error as e:
            logger.error(f"Failed to connect to database {self.db_path}: {e}")
            self._conn = None
            return False

    def _ensure_connection(self) -> sqlite3.Connection:
        if self._conn is None:
            if not self.connect():
                raise sqlite3.Error(f"Could not connect to database {self.db_path}")
        return self._conn  # type: ignore[return-value]

    def execute(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
        """Execute a single statement and commit it."""
        conn = self._ensure_connection()
        cursor = conn.execute(sql, tuple(params))
        conn.commit()
        return cursor

    def fetch_one(
        self, sql: str, params: Sequence[Any] = ()
    ) -> Optional[Tuple[Any, ...]]:
        """Execute a query and return the first row, or None."""
        conn = self._ensure_connection()
        cursor = conn.execute(sql, tuple(params))
        return cursor.fetchone()

    def fetch_all(self, sql: str, params: Sequence[Any] = ()) -> List[Tuple[Any, ...]]:
        """Execute a query and return all rows."""
        conn = self._ensure_connection()
        cursor = conn.execute(sql, tuple(params))
        return cursor.fetchall()

    def close(self) -> None:
        """Close the database connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None
