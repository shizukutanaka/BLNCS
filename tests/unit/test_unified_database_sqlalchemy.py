#!/usr/bin/env python3
"""
Unit tests for UnifiedDatabase fetch_one()/fetch_all() and
execute()/insert()/update()/delete() on the SQLAlchemy path.

Regression coverage: when SQLAlchemy is installed, a ``sqlite://``
URL selects the SQLAlchemy backend, whose rows are SQLAlchemy 2.x
``Row`` objects. ``dict(row)`` raises TypeError/ValueError for those;
the rows must be converted through their mapping view instead. The
native sqlite3 path was unaffected (its rows are ``sqlite3.Row``).
"""

import shutil
import tempfile
import unittest
from pathlib import Path

try:
    from sqlalchemy import text

    HAS_SQLALCHEMY = True
except ImportError:  # pragma: no cover - depends on environment
    HAS_SQLALCHEMY = False

from blncs.core.unified_database import UnifiedDatabase


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy is not installed")
class TestUnifiedDatabaseSqlAlchemyFetch(unittest.TestCase):
    """fetch_one()/fetch_all() must return plain dicts via SQLAlchemy"""

    def setUp(self):
        """Set up a SQLAlchemy-backed database in a temporary directory"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test.db"
        self.db = UnifiedDatabase(database_url=f"sqlite:///{self.db_path}")
        # The fixture must really exercise the SQLAlchemy backend;
        # a silent fallback to native sqlite3 would hide the defect.
        self.assertTrue(self.db.using_sqlalchemy)
        # Seed one row through a raw session. (Seeding is fixture
        # setup only; the methods under test are the fetchers.)
        session = self.db._get_connection()
        try:
            session.execute(
                text(
                    "INSERT INTO channels (channel_id, capacity) "
                    "VALUES ('chan-1', 1000)"
                )
            )
            session.commit()
        finally:
            session.close()

    def tearDown(self):
        """Clean up temporary files"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_fetch_one_returns_dict(self):
        row = self.db.fetch_one(
            "SELECT channel_id, capacity FROM channels " "WHERE channel_id = :cid",
            {"cid": "chan-1"},
        )
        self.assertEqual(row, {"channel_id": "chan-1", "capacity": 1000})

    def test_fetch_one_scalar_query(self):
        row = self.db.fetch_one("SELECT 1 AS one")
        self.assertEqual(row, {"one": 1})

    def test_fetch_one_no_rows_returns_none(self):
        row = self.db.fetch_one(
            "SELECT channel_id FROM channels WHERE channel_id = 'missing'"
        )
        self.assertIsNone(row)

    def test_fetch_all_returns_list_of_dicts(self):
        rows = self.db.fetch_all("SELECT channel_id, capacity FROM channels")
        self.assertEqual(rows, [{"channel_id": "chan-1", "capacity": 1000}])


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy is not installed")
class TestUnifiedDatabaseSqlAlchemyExecute(unittest.TestCase):
    """execute()/insert()/update()/delete() must work via SQLAlchemy

    Regression coverage: the SQLAlchemy path fetched rows
    unconditionally after committing, so every non-SELECT statement
    (INSERT/UPDATE/DELETE) raised ResourceClosedError even though
    the statement itself had been applied. The native sqlite3 path
    branches on the statement kind and was unaffected.
    """

    def setUp(self):
        """Set up a SQLAlchemy-backed database in a temporary directory"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test.db"
        self.db = UnifiedDatabase(database_url=f"sqlite:///{self.db_path}")
        # The fixture must really exercise the SQLAlchemy backend;
        # a silent fallback to native sqlite3 would hide the defect.
        self.assertTrue(self.db.using_sqlalchemy)

    def tearDown(self):
        """Clean up temporary files"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_insert_then_select_roundtrip_via_execute(self):
        self.db.execute(
            "INSERT INTO channels (channel_id, capacity) " "VALUES (:cid, :cap)",
            {"cid": "chan-1", "cap": 1000},
        )
        rows = self.db.execute(
            "SELECT channel_id, capacity FROM channels " "WHERE channel_id = :cid",
            {"cid": "chan-1"},
        )
        self.assertEqual([tuple(row) for row in rows], [("chan-1", 1000)])

    def test_insert_helper_returns_generated_id(self):
        new_id = self.db.insert("channels", {"channel_id": "chan-1", "capacity": 1000})
        self.assertEqual(new_id, 1)
        row = self.db.fetch_one(
            "SELECT channel_id, capacity FROM channels " "WHERE channel_id = :cid",
            {"cid": "chan-1"},
        )
        self.assertEqual(row, {"channel_id": "chan-1", "capacity": 1000})

    def test_update_helper_applies_and_reports_rowcount(self):
        self.db.insert("channels", {"channel_id": "chan-1", "capacity": 1000})
        affected = self.db.update(
            "channels", {"capacity": 2000}, {"channel_id": "chan-1"}
        )
        self.assertEqual(affected, 1)
        row = self.db.fetch_one(
            "SELECT capacity FROM channels WHERE channel_id = :cid",
            {"cid": "chan-1"},
        )
        self.assertEqual(row, {"capacity": 2000})

    def test_delete_helper_applies_and_reports_rowcount(self):
        self.db.insert("channels", {"channel_id": "chan-1", "capacity": 1000})
        affected = self.db.delete("channels", {"channel_id": "chan-1"})
        self.assertEqual(affected, 1)
        row = self.db.fetch_one(
            "SELECT channel_id FROM channels WHERE channel_id = :cid",
            {"cid": "chan-1"},
        )
        self.assertIsNone(row)


if __name__ == "__main__":
    unittest.main()
