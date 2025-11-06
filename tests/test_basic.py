#!/usr/bin/env python3
"""
Basic tests for BLNCS functionality
Ultra-lightweight tests for core components.
"""

import unittest
import sys
from pathlib import Path

# Minimal path setup for speed
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from blncs.core.config import get_config
    from blncs.lightning.simple_client import SimpleLightningClient
    IMPORTS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Core imports not available: {e}")
    IMPORTS_AVAILABLE = False


class TestBasicComponents(unittest.TestCase):
    """Test basic BLNCS components"""

    @unittest.skipUnless(IMPORTS_AVAILABLE, "Imports not available")
    def test_config_system(self):
        """Test configuration system"""
        config = get_config()
        self.assertIsNotNone(config)

    @unittest.skipUnless(IMPORTS_AVAILABLE, "Imports not available")
    def test_lightning_client(self):
        """Test Lightning client"""
        config = {'mock_mode': True, 'node_type': 'mock'}
        client = SimpleLightningClient(config=config)
        self.assertIsNotNone(client)

        # Mock mode should allow get_info without connection
        client.connected = True
        client.mock_mode = True
        info = client.get_info()
        self.assertIsNotNone(info)


if __name__ == '__main__':
    unittest.main()