#!/usr/bin/env python3
"""
BLNCS main entry point for python -m blncs execution
Simple and direct following Pike's principles.
"""

if __name__ == '__main__':
    try:
        # Try optimized CLI first
        from .cli.commands.core import main
        main()
    except ImportError:
        # Fallback to simple CLI
        from .cli.simple import main
        main()