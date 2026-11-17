#!/usr/bin/env python3
"""
Unit tests for BLNCSApplication start/stop and component shutdowns

Regression coverage for the application startup path used by the
container CMD: start() awaited the synchronous initialize(), which
returns None (TypeError), and stop() called
stop_background_optimization() / stop_background_cleanup(), which
the components did not implement (AttributeError).
"""

import asyncio
import importlib
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from blncs.core.config import reset_config
from blncs.core.unified_database import reset_database
from blncs.core.unified_performance import UnifiedPerformanceOptimizer
from blncs.core.unified_security import UnifiedSecurityManager


class TestComponentStopMethods(unittest.TestCase):
    """The background-stop methods used by application shutdown"""

    def test_performance_stop_background_optimization(self):
        """stop_background_optimization() sets the shutdown event"""
        optimizer = UnifiedPerformanceOptimizer.__new__(UnifiedPerformanceOptimizer)
        optimizer.shutdown_event = threading.Event()
        optimizer._background_thread = None

        optimizer.stop_background_optimization()

        self.assertTrue(optimizer.shutdown_event.is_set())

    def test_performance_stop_joins_live_thread(self):
        """A live background thread is joined on stop"""
        optimizer = UnifiedPerformanceOptimizer.__new__(UnifiedPerformanceOptimizer)
        optimizer.shutdown_event = threading.Event()
        optimizer._background_thread = threading.Thread(
            target=optimizer.shutdown_event.wait, args=(30,), daemon=True
        )
        optimizer._background_thread.start()

        optimizer.stop_background_optimization()

        self.assertFalse(optimizer._background_thread.is_alive())

    def test_security_stop_background_cleanup(self):
        """stop_background_cleanup() sets the shutdown event"""
        manager = UnifiedSecurityManager.__new__(UnifiedSecurityManager)
        manager.shutdown_event = threading.Event()
        manager.cleanup_thread = None

        manager.stop_background_cleanup()

        self.assertTrue(manager.shutdown_event.is_set())

    def test_security_stop_joins_live_thread(self):
        """A live cleanup thread is joined on stop"""
        manager = UnifiedSecurityManager.__new__(UnifiedSecurityManager)
        manager.shutdown_event = threading.Event()
        manager.cleanup_thread = threading.Thread(
            target=manager.shutdown_event.wait, args=(30,), daemon=True
        )
        manager.cleanup_thread.start()

        manager.stop_background_cleanup()

        self.assertFalse(manager.cleanup_thread.is_alive())


class TestBLNCSApplicationStartStop(unittest.TestCase):
    """start()/stop() must complete without TypeError/AttributeError"""

    def setUp(self):
        """Run in an empty directory (first-run conditions)"""
        self.temp_dir = tempfile.mkdtemp()
        self._prev_cwd = os.getcwd()
        os.chdir(self.temp_dir)
        reset_config()
        reset_database()

    def tearDown(self):
        """Restore the working directory and clean up"""
        reset_config()
        reset_database()
        os.chdir(self._prev_cwd)
        if Path(self.temp_dir).exists():
            import shutil

            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_start_and_stop(self):
        """The application starts and shuts down cleanly"""
        blncs_main = importlib.import_module("blncs_main")

        with patch.dict(os.environ, {"BLNCS_ENV": "development"}):
            app = blncs_main.BLNCSApplication()

            asyncio.run(app.start())
            self.assertTrue(app.running)

            asyncio.run(app.stop())
            self.assertFalse(app.running)


if __name__ == "__main__":
    unittest.main()
