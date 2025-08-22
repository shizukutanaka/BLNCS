#!/usr/bin/env python3
"""
BLRCS - Main Entry Point
Optimized with lazy loading and performance improvements
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Apply optimizations before heavy imports
from blrcs.optimizations import apply_all_optimizations
apply_all_optimizations()

from blrcs.core import run

if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print("\nShutting down BLRCS...")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)
