def cmd_maintenance(args, config, logger, error_handler):
    """Maintenance automation command with scheduler integration"""
    from blncs.utils.maintenance_scheduler import MaintenanceScheduler
    from pathlib import Path
    import json

    # Get or create maintenance scheduler with caching
    global _maintenance_scheduler_cache, _maintenance_scheduler_lock

    def get_maintenance_scheduler():
        with _maintenance_scheduler_lock:
            if _maintenance_scheduler_cache is None:
                config_path = Path("config/maintenance.json") if Path("config/maintenance.json").exists() else None
                _maintenance_scheduler_cache = MaintenanceScheduler(config_path)
            return _maintenance_scheduler_cache

    scheduler = get_maintenance_scheduler()

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
            print(f"  blncs maintenance --list          # List all tasks")
            print(f"  blncs maintenance --run task1 task2  # Run specific tasks")
            print(f"  blncs maintenance --bundle high   # Run high+ priority tasks")
            print(f"  blncs maintenance --help          # Show this help")

    # Log maintenance command execution
    logger.info(f"Maintenance command executed: {' '.join(sys.argv[1:])}")
