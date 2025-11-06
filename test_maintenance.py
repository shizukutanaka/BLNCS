#!/usr/bin/env python3
"""
Test script for maintenance automation functionality
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_maintenance_integration():
    """Test maintenance scheduler integration"""
    try:
        from blncs.utils.maintenance_scheduler import MaintenanceScheduler
        from pathlib import Path
        import json

        print("🔧 Testing Maintenance Scheduler Integration")
        print("=" * 50)

        # Create scheduler instance
        scheduler = MaintenanceScheduler()

        # Test 1: List available tasks
        print("\n📋 Test 1: List available maintenance tasks")
        tasks = scheduler.list_tasks_summary()
        print(f"Found {len(tasks)} maintenance tasks:")

        for task in tasks[:3]:  # Show first 3 tasks
            print(f"  • {task['name']} ({task['task_id']}) - {task['priority']} priority")

        # Test 2: Get maintenance status
        print("\n📊 Test 2: Get maintenance system status")
        status = scheduler.get_maintenance_status()
        print(f"Scheduler Active: {status['scheduler_active']}")
        print(f"Total Tasks: {status['total_tasks']}")
        print(f"Success Rate: {status['success_rate']".1f"}%")

        # Test 3: Run a simple task synchronously
        print("\n⚡ Test 3: Run maintenance tasks synchronously")
        print("Running hourly health check...")

        results = scheduler.run_tasks_now(['hourly_health_check'])
        for result in results:
            print(f"  • {result['name']}: {result['status']} ({result['duration_seconds']".2f"}s)")

        # Test 4: Run priority bundle
        print("\n🎯 Test 4: Run high priority maintenance bundle")
        from blncs.utils.maintenance_scheduler import MaintenancePriority

        results = scheduler.run_priority_bundle(MaintenancePriority.HIGH)
        print(f"Executed {len(results)} high+ priority tasks")

        print("\n✅ All tests completed successfully!")
        print("🎉 Maintenance automation is ready for CLI integration")

        return True

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_maintenance_integration()
    sys.exit(0 if success else 1)
