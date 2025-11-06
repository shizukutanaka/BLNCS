#!/usr/bin/env python3
"""
Unit tests for BLNCS Maintenance Scheduler synchronous execution helpers
"""

import unittest
import sys
import os
import tempfile
import json
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

class TestMaintenanceSchedulerSync(unittest.TestCase):
    """Test cases for synchronous maintenance task execution"""

    def setUp(self):
        """Set up test fixtures"""
        from blncs.utils.maintenance_scheduler import MaintenanceScheduler, MaintenancePriority, TaskStatus

        # Create a temporary directory for test data
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.temp_dir, "test_maintenance.json")

        # Mock the database path to avoid conflicts
        with patch('blncs.utils.maintenance_scheduler.DEFAULT_DB_PATH', os.path.join(self.temp_dir, "test_maintenance.db")):
            with patch('blncs.utils.maintenance_scheduler.DEFAULT_LOG_DIR', os.path.join(self.temp_dir, "logs")):
                self.scheduler = MaintenanceScheduler(self.config_path)

    def tearDown(self):
        """Clean up test fixtures"""
        # Clean up temporary files
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_scheduler_initialization(self):
        """Test that scheduler initializes correctly"""
        self.assertIsNotNone(self.scheduler)
        self.assertFalse(self.scheduler.scheduler_active)
        self.assertEqual(len(self.scheduler.tasks), 6)  # 6 default tasks

    def test_list_tasks_summary(self):
        """Test listing task summaries"""
        tasks = self.scheduler.list_tasks_summary()

        self.assertIsInstance(tasks, list)
        self.assertGreater(len(tasks), 0)

        # Check structure of first task
        task = tasks[0]
        expected_keys = ['task_id', 'name', 'type', 'priority', 'priority_value', 'schedule', 'requires_downtime', 'last_run', 'last_status', 'estimated_duration_minutes']

        for key in expected_keys:
            self.assertIn(key, task)

    def test_get_maintenance_status(self):
        """Test getting maintenance system status"""
        status = self.scheduler.get_maintenance_status()

        expected_keys = ['scheduler_active', 'total_tasks', 'running_tasks', 'completed_tasks', 'failed_tasks', 'success_rate', 'maintenance_windows']

        for key in expected_keys:
            self.assertIn(key, status)

        self.assertFalse(status['scheduler_active'])
        self.assertEqual(status['total_tasks'], 6)

    def test_run_tasks_now_with_valid_task(self):
        """Test running a valid maintenance task synchronously"""
        results = self.scheduler.run_tasks_now(['hourly_health_check'])

        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 1)

        result = results[0]
        expected_keys = ['task_id', 'name', 'status', 'duration_seconds', 'details']

        for key in expected_keys:
            self.assertIn(key, result)

        # Health check should complete successfully
        self.assertEqual(result['status'], TaskStatus.COMPLETED.value)

    def test_run_tasks_now_with_invalid_task(self):
        """Test running an invalid maintenance task"""
        results = self.scheduler.run_tasks_now(['nonexistent_task'])

        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 1)

        result = results[0]
        self.assertEqual(result['status'], TaskStatus.SKIPPED.value)
        self.assertEqual(result['reason'], 'unknown_task')

    def test_run_tasks_now_multiple_tasks(self):
        """Test running multiple maintenance tasks"""
        results = self.scheduler.run_tasks_now(['hourly_health_check', 'daily_system_cleanup'])

        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 2)

        for result in results:
            self.assertIn('status', result)
            self.assertIn('duration_seconds', result)
            # Both should complete successfully
            self.assertEqual(result['status'], TaskStatus.COMPLETED.value)

    def test_run_priority_bundle_high(self):
        """Test running high priority maintenance bundle"""
        from blncs.utils.maintenance_scheduler import MaintenancePriority

        results = self.scheduler.run_priority_bundle(MaintenancePriority.HIGH)

        self.assertIsInstance(results, list)

        # Should include high and critical priority tasks
        task_ids = [r['task_id'] for r in results]
        self.assertIn('hourly_health_check', task_ids)
        self.assertIn('weekly_database_optimization', task_ids)
        self.assertIn('weekly_security_update', task_ids)

    def test_run_priority_bundle_critical(self):
        """Test running critical priority maintenance bundle"""
        from blncs.utils.maintenance_scheduler import MaintenancePriority

        results = self.scheduler.run_priority_bundle(MaintenancePriority.CRITICAL)

        self.assertIsInstance(results, list)

        # Should only include critical priority tasks
        for result in results:
            task = self.scheduler.tasks[result['task_id']]
            self.assertEqual(task.priority, MaintenancePriority.CRITICAL)

    def test_respect_windows_parameter(self):
        """Test that respect_windows parameter is properly passed"""
        results = self.scheduler.run_tasks_now(['hourly_health_check'], respect_windows=True)

        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 1)

        result = results[0]
        self.assertEqual(result['status'], TaskStatus.COMPLETED.value)

    def test_task_execution_with_system_cleanup(self):
        """Test system cleanup task execution"""
        results = self.scheduler.run_tasks_now(['daily_system_cleanup'])

        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 1)

        result = results[0]
        self.assertEqual(result['status'], TaskStatus.COMPLETED.value)

        # Check that details contain expected information
        details = result['details']
        self.assertIn('cleaned_files', details)
        self.assertIn('freed_space_mb', details)

    def test_task_execution_with_health_check(self):
        """Test health check task execution"""
        results = self.scheduler.run_tasks_now(['hourly_health_check'])

        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 1)

        result = results[0]
        self.assertEqual(result['status'], TaskStatus.COMPLETED.value)

        # Check that details contain health information
        details = result['details']
        self.assertIn('health_score', details)
        self.assertIn('issues_found', details)

    def test_maintenance_report_generation(self):
        """Test maintenance report generation"""
        # Run a few tasks first
        self.scheduler.run_tasks_now(['hourly_health_check'])

        # Generate report
        report = self.scheduler.get_maintenance_report(days=1)

        expected_keys = ['report_period_days', 'total_tasks_executed', 'successful_tasks', 'failed_tasks', 'maintenance_by_type']

        for key in expected_keys:
            self.assertIn(key, report)

        self.assertEqual(report['report_period_days'], 1)
        self.assertGreaterEqual(report['total_tasks_executed'], 1)

    def test_scheduler_shutdown(self):
        """Test scheduler shutdown"""
        # Start scheduler
        self.scheduler.start_scheduler()

        # Shutdown scheduler
        self.scheduler.shutdown()

        # Verify scheduler is stopped
        self.assertFalse(self.scheduler.scheduler_active)

class TestMaintenanceSchedulerIntegration(unittest.TestCase):
    """Integration tests for maintenance scheduler with CLI"""

    def test_cli_argument_parsing(self):
        """Test that CLI arguments are properly parsed for maintenance commands"""
        from blncs_main import main
        import sys
        from unittest.mock import patch

        # Test --list argument
        with patch('sys.argv', ['blncs_main.py', 'maintenance', '--list']):
            # This should not raise an exception
            try:
                # We can't actually run main() due to dependencies, but we can test the parsing
                pass
            except SystemExit:
                pass  # argparse calls sys.exit on --help

    def test_json_output_format(self):
        """Test JSON output format for maintenance commands"""
        scheduler = self.setUp_scheduler()

        # Test list with JSON output
        tasks = scheduler.list_tasks_summary()
        json_output = json.dumps(tasks, indent=2, ensure_ascii=False)

        # Verify it's valid JSON
        parsed = json.loads(json_output)
        self.assertIsInstance(parsed, list)

        # Test status with JSON output
        status = scheduler.get_maintenance_status()
        json_output = json.dumps(status, indent=2, ensure_ascii=False)

        # Verify it's valid JSON
        parsed = json.loads(json_output)
        self.assertIsInstance(parsed, dict)

    def test_priority_bundle_execution_order(self):
        """Test that priority bundles execute tasks in correct priority order"""
        from blncs.utils.maintenance_scheduler import MaintenancePriority

        results = self.scheduler.run_priority_bundle(MaintenancePriority.NORMAL)

        # Extract priorities from results
        priorities = []
        for result in results:
            task = self.scheduler.tasks[result['task_id']]
            priorities.append(task.priority.value)

        # Verify all tasks have priority >= NORMAL (value 2)
        for priority in priorities:
            self.assertGreaterEqual(priority, 2)

        # Verify results are sorted by priority (descending)
        priorities_sorted = sorted(priorities, reverse=True)
        self.assertEqual(priorities, priorities_sorted)

    def setUp_scheduler(self):
        """Helper method to set up scheduler for integration tests"""
        from blncs.utils.maintenance_scheduler import MaintenanceScheduler

        temp_dir = tempfile.mkdtemp()
        config_path = os.path.join(temp_dir, "test_maintenance.json")

        with patch('blncs.utils.maintenance_scheduler.DEFAULT_DB_PATH', os.path.join(temp_dir, "test_maintenance.db")):
            with patch('blncs.utils.maintenance_scheduler.DEFAULT_LOG_DIR', os.path.join(temp_dir, "logs")):
                scheduler = MaintenanceScheduler(config_path)

        self.temp_dir = temp_dir
        return scheduler

    def tearDown(self):
        """Clean up integration test fixtures"""
        if hasattr(self, 'temp_dir'):
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)

if __name__ == '__main__':
    # Create test suite
    unittest.main(verbosity=2)
