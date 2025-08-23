"""
Pytest configuration and shared fixtures
"""

import pytest
import asyncio
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@pytest.fixture
def event_loop():
    """Create event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def test_config():
    """Test configuration"""
    return {
        "lnd_host": "localhost",
        "lnd_port": 10009,
        "lnd_dir": "/tmp/test_lnd",
        "auto_optimize": False,
        "test_mode": True
    }


@pytest.fixture
def mock_lnd_response():
    """Mock LND API responses"""
    return {
        "get_info": {
            "identity_pubkey": "test_pubkey_123",
            "alias": "TestNode",
            "num_active_channels": 3,
            "num_peers": 2,
            "block_height": 700000,
            "synced_to_chain": True,
            "testnet": False
        },
        "list_channels": [
            {
                "channel_id": "123456789",
                "channel_point": "abc:1",
                "remote_pubkey": "remote_node_1",
                "capacity": "1000000",
                "local_balance": "600000",
                "remote_balance": "400000",
                "active": True,
                "private": False
            },
            {
                "channel_id": "987654321",
                "channel_point": "def:2",
                "remote_pubkey": "remote_node_2",
                "capacity": "2000000",
                "local_balance": "300000",
                "remote_balance": "1700000",
                "active": True,
                "private": False
            }
        ],
        "describe_graph": {
            "nodes": [
                {"pub_key": "node_1", "alias": "Node1"},
                {"pub_key": "node_2", "alias": "Node2"},
                {"pub_key": "node_3", "alias": "Node3"}
            ],
            "edges": [
                {
                    "channel_id": "111111",
                    "node1_pub": "node_1",
                    "node2_pub": "node_2",
                    "capacity": "5000000",
                    "node1_policy": {
                        "fee_base_msat": "1000",
                        "fee_rate_milli_msat": "1",
                        "time_lock_delta": 40,
                        "min_htlc": "1000",
                        "max_htlc_msat": "4500000000",
                        "disabled": False
                    },
                    "node2_policy": {
                        "fee_base_msat": "1000",
                        "fee_rate_milli_msat": "1",
                        "time_lock_delta": 40,
                        "min_htlc": "1000",
                        "max_htlc_msat": "4500000000",
                        "disabled": False
                    },
                    "last_update": 1234567890
                }
            ]
        }
    }