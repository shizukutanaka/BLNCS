#!/usr/bin/env python3
"""
Unit tests for UnifiedDatabase connect()/health_check()

Regression coverage for the application startup crash: the entry
point calls database.connect() during initialization (and
health_check() for status reporting), but UnifiedDatabase did not
provide either method.
"""

import tempfile
import unittest
from pathlib import Path

from blncs.core.unified_database import UnifiedDatabase


class TestUnifiedDatabaseConnect(unittest.TestCase):
    """connect()/health_check() must exist and report, never raise"""

    def setUp(self):
        """Set up a database in a temporary directory"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test.db"
        self.db = UnifiedDatabase(database_url=f"sqlite:///{self.db_path}")

    def tearDown(self):
        """Clean up temporary files"""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_connect_returns_true_for_sqlite(self):
        """A reachable database reports a successful connection"""
        self.assertTrue(self.db.connect())

    def test_health_check_returns_true_for_sqlite(self):
        """health_check() mirrors connect() for status reporting"""
        self.assertTrue(self.db.health_check())

    def test_connect_returns_false_instead_of_raising(self):
        """A broken connection factory yields False, not an exception"""

        def broken_connection():
            raise RuntimeError("connection factory exploded")

        self.db._get_connection = broken_connection
        self.assertFalse(self.db.connect())
        self.assertFalse(self.db.health_check())


if __name__ == "__main__":
    unittest.main()
