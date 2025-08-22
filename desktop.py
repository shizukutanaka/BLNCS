#!/usr/bin/env python3
"""
BLRCS Desktop Application
Unified desktop interface
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from blrcs.desktop import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
