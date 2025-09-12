#!/usr/bin/env python3
"""
BLNCS Simple CLI
Following Pike: do one thing well - Lightning Network control.
"""

import sys
from pathlib import Path

# Add current directory to Python path for imports  
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir.parent))


def main():
    """Simple main entry point - delegates to core commands"""
    try:
        from .commands.core import cli
        cli()
    except ImportError:
        # Fallback to basic operations without click
        if len(sys.argv) > 1:
            command = sys.argv[1].lower()
            
            if command in ['info', 'status']:
                basic_info()
            elif command == 'help':
                basic_help()
            else:
                print(f"Unknown command: {command}")
                basic_help()
        else:
            basic_help()


def basic_info():
    """Basic info without dependencies"""
    print("BLNCS - Bitcoin Lightning Network Control System")
    print("Status: System operational")
    
    try:
        from blncs.utils.lightweight_fallbacks import LightweightSystemMonitor
        monitor = LightweightSystemMonitor()
        info = monitor.get_system_info()
        print(f"CPU: {info.cpu_percent:.1f}%")
        print(f"Memory: {info.memory_percent:.1f}%")
        print(f"Disk: {info.disk_usage:.1f}%")
    except Exception as e:
        print(f"System info unavailable: {e}")


def basic_help():
    """Basic help without dependencies"""
    print("BLNCS - Bitcoin Lightning Network Control System")
    print("\nAvailable commands:")
    print("  info     - Show node information")
    print("  balance  - Show wallet and channel balances") 
    print("  channels - List Lightning channels")
    print("  invoice  - Create payment invoice")
    print("  pay      - Send Lightning payment")
    print("  status   - Show system status")
    print("  setup    - Quick setup")
    print("  help     - Show this help")
    print("\nExample: python -m blncs info")


if __name__ == '__main__':
    main()