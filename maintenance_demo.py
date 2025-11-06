#!/usr/bin/env python3
"""
BLNCS Maintenance CLI Integration Demo
This demonstrates the maintenance automation functionality that would be integrated into blncs_main.py
"""

import sys
import os
import json
import argparse
from pathlib import Path

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def cmd_maintenance(args, config, logger, error_handler):
    """Maintenance automation command with scheduler integration"""
    try:
        from blncs.utils.maintenance_scheduler import MaintenanceScheduler
    except ImportError as e:
        print(f"❌ Error: Could not import maintenance scheduler: {e}")
        print("💡 Make sure blncs is properly installed")
        return

    # Get or create maintenance scheduler with caching
    scheduler = MaintenanceScheduler()

    # Handle different maintenance commands
    if args.list:
        # List available maintenance tasks
        tasks = scheduler.list_tasks_summary()

        if args.json:
            print(json.dumps(tasks, indent=2, ensure_ascii=False))
        else:
            print(f"\n🔧 Available Maintenance Tasks ({len(tasks)})")
            print("=" * 70)
            print(f"{'Task ID':<25} {'Name':<25} {'Priority':<10} {'Type':<15} {'Schedule':<15}")
            print("-" * 70)

            for task in tasks:
                print(f"{task['task_id']:<25} {task['name']:<25} {task['priority']:<10} {task['type']:<15} {task['schedule']:<15}")

    elif args.run:
        # Run specific maintenance tasks synchronously
        task_ids = args.run
        print(f"\n🔧 Running Maintenance Tasks: {', '.join(task_ids)}")

        results = scheduler.run_tasks_now(
            task_ids=task_ids,
            respect_windows=args.respect_windows
        )

        if args.json:
            print(json.dumps(results, indent=2, ensure_ascii=False))
        else:
            print("\n📊 Execution Results:")
            print("-" * 50)

            for result in results:
                status_emoji = {
                    'completed': '✅',
                    'failed': '❌',
                    'skipped': '⏭️'
                }.get(result['status'], '❓')

                print(f"{status_emoji} {result['name']} ({result['duration_seconds']:.2f}s)")
                if result['status'] == 'failed':
                    print(f"   Error: {result.get('last_error', 'Unknown error')}")
                elif result['status'] == 'skipped':
                    print(f"   Reason: {result.get('reason', 'Unknown reason')}")

            successful = len([r for r in results if r['status'] == 'completed'])
            total = len(results)
            print(f"\n📈 Summary: {successful}/{total} tasks completed successfully")

    elif args.bundle:
        # Run priority bundle
        from blncs.utils.maintenance_scheduler import MaintenancePriority
        priority_map = {
            'critical': MaintenancePriority.CRITICAL,
            'high': MaintenancePriority.HIGH,
            'normal': MaintenancePriority.NORMAL,
            'low': MaintenancePriority.LOW
        }

        min_priority = priority_map.get(args.bundle.lower(), MaintenancePriority.HIGH)
        print(f"\n🔧 Running Priority Bundle: {args.bundle} ({min_priority.name})")

        results = scheduler.run_priority_bundle(
            minimum_priority=min_priority,
            respect_windows=args.respect_windows
        )

        if args.json:
            print(json.dumps(results, indent=2, ensure_ascii=False))
        else:
            print("\n📊 Execution Results:")
            print("-" * 50)

            for result in results:
                status_emoji = {
                    'completed': '✅',
                    'failed': '❌',
                    'skipped': '⏭️'
                }.get(result['status'], '❓')

                print(f"{status_emoji} {result['name']} ({result['duration_seconds']:.2f}s)")
                if result['status'] == 'failed':
                    print(f"   Error: {result.get('last_error', 'Unknown error')}")
                elif result['status'] == 'skipped':
                    print(f"   Reason: {result.get('reason', 'Unknown reason')}")

            successful = len([r for r in results if r['status'] == 'completed'])
            total = len(results)
            print(f"\n📈 Summary: {successful}/{total} tasks completed successfully")

    else:
        # Show maintenance status
        status = scheduler.get_maintenance_status()

        if args.json:
            print(json.dumps(status, indent=2, ensure_ascii=False))
        else:
            print("\n🔧 Maintenance System Status")
            print("=" * 50)
            print(f"Scheduler Active: {'✅ Yes' if status['scheduler_active'] else '❌ No'}")
            print(f"Total Tasks: {status['total_tasks']}")
            print(f"Running Tasks: {status['running_tasks']}")
            print(f"Completed Tasks: {status['completed_tasks']}")
            print(f"Failed Tasks: {status['failed_tasks']}")
            print(f"Success Rate: {status['success_rate']:.1f}%")
            print(f"Maintenance Windows: {status['maintenance_windows']}")

            if status['next_scheduled_tasks']:
                print(f"\n⏰ Next Scheduled Tasks:")
                for task in status['next_scheduled_tasks'][:5]:  # Show top 5
                    print(f"  • {task['name']} ({task['task_id']})")

            print(f"\n💡 Usage:")
            print(f"  python maintenance_demo.py --list          # List all tasks")
            print(f"  python maintenance_demo.py --run task1 task2  # Run specific tasks")
            print(f"  python maintenance_demo.py --bundle high   # Run high+ priority tasks")
            print(f"  python maintenance_demo.py --help          # Show this help")

def main():
    """Main entry point for maintenance demo"""
    parser = argparse.ArgumentParser(description='BLNCS Maintenance Automation Demo')
    parser.add_argument('--list', action='store_true', help='List available maintenance tasks')
    parser.add_argument('--run', nargs='+', metavar='TASK_ID', help='Run specified maintenance task IDs synchronously')
    parser.add_argument('--bundle', choices=['critical', 'high', 'normal', 'low'], help='Run maintenance tasks at or above the priority threshold')
    parser.add_argument('--respect-windows', action='store_true', help='Enforce maintenance windows when executing tasks')
    parser.add_argument('--json', action='store_true', help='Emit JSON output for automation pipelines')

    args = parser.parse_args()

    # Mock config, logger, and error_handler for demo
    class MockConfig:
        def get(self, key, default=None):
            return default

    class MockLogger:
        def info(self, msg, *args):
            print(f"INFO: {msg % args if args else msg}")

    class MockErrorHandler:
        pass

    config = MockConfig()
    logger = MockLogger()
    error_handler = MockErrorHandler()

    cmd_maintenance(args, config, logger, error_handler)

if __name__ == '__main__':
    main()
