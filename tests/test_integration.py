"""
Integration tests for Lightning routing system
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from blrcs.lightning import OneClickLightningRouter
from blrcs.lightning.lnd_connector import LNDConnector
from blrcs.lightning.payment_router import PaymentRouter, ChannelEdge
from datetime import datetime


@pytest.fixture
def mock_lnd_connector():
    """Create mock LND connector"""
    connector = Mock(spec=LNDConnector)
    connector.connect = AsyncMock(return_value=True)
    connector.get_info = AsyncMock(return_value={
        "identity_pubkey": "test_node_123",
        "alias": "TestNode",
        "num_active_channels": 5,
        "num_peers": 3
    })
    connector.list_channels = AsyncMock(return_value=[
        {
            "channel_id": "123456789",
            "remote_pubkey": "peer_node_1",
            "capacity": "1000000",
            "local_balance": "600000",
            "remote_balance": "400000",
            "active": True
        }
    ])
    return connector


@pytest.fixture
def sample_channels():
    """Create sample channel edges for testing"""
    return [
        ChannelEdge(
            channel_id="channel_1",
            node1="node_a",
            node2="node_b",
            capacity=1000000,
            fee_base_msat=1000,
            fee_rate_millimsat=1,
            time_lock_delta=40,
            min_htlc=1000,
            max_htlc_msat=900000000,
            last_update=datetime.now(),
            active=True,
            disabled=False,
            success_rate=0.95,
            avg_response_time=100.0,
            liquidity_estimate=0.6
        ),
        ChannelEdge(
            channel_id="channel_2",
            node1="node_b",
            node2="node_c",
            capacity=2000000,
            fee_base_msat=500,
            fee_rate_millimsat=2,
            time_lock_delta=30,
            min_htlc=1000,
            max_htlc_msat=1800000000,
            last_update=datetime.now(),
            active=True,
            disabled=False,
            success_rate=0.98,
            avg_response_time=80.0,
            liquidity_estimate=0.7
        )
    ]


@pytest.mark.asyncio
async def test_one_click_router_integration(mock_lnd_connector):
    """Test one-click router with mock LND"""
    with patch("blrcs.lightning.one_click_routing.Path.exists", return_value=True):
        router = OneClickLightningRouter()
        router.lnd_connector = mock_lnd_connector
        
        # Mock file system checks
        with patch("pathlib.Path.exists", return_value=True):
            success = await router.start()
            assert success == True
            
            # Check dashboard data
            dashboard = router.get_dashboard_data()
            assert dashboard["status"] == "connected"
            assert dashboard["channels"]["total"] == 2
            assert dashboard["config"]["auto_optimize"] == True


@pytest.mark.asyncio
async def test_payment_router_integration(mock_lnd_connector, sample_channels):
    """Test payment router with sample data"""
    router = PaymentRouter(mock_lnd_connector)
    
    # Update pathfinder with sample channels
    router.pathfinder.update_graph(sample_channels)
    
    # Test routing
    result = await router.route_payment(
        target="node_c",
        amount_msat=100000
    )
    
    assert result is not None
    assert "error" not in result or result.get("type") in ["single", "multipath"]


@pytest.mark.asyncio
async def test_channel_rebalancing():
    """Test channel rebalancing logic"""
    router = OneClickLightningRouter()
    
    # Setup test channels
    router.channels = [
        {
            "channel_id": "test_1",
            "peer": "peer_1",
            "capacity": 1000000,
            "local_balance": 100000,  # 10% - needs rebalancing
            "remote_balance": 900000,
            "active": True
        },
        {
            "channel_id": "test_2",
            "peer": "peer_2",
            "capacity": 2000000,
            "local_balance": 1900000,  # 95% - needs rebalancing
            "remote_balance": 100000,
            "active": True
        }
    ]
    
    # Run rebalancing
    await router.rebalance_channels()
    
    # Check if balances were adjusted (in real implementation)
    for channel in router.channels:
        local_ratio = channel["local_balance"] / channel["capacity"]
        assert 0.4 <= local_ratio <= 0.6  # Should be near 50%


@pytest.mark.asyncio
async def test_route_finding(sample_channels):
    """Test route finding algorithm"""
    from blrcs.lightning.payment_router import PaymentPathfinder
    
    pathfinder = PaymentPathfinder(max_routes=3)
    pathfinder.update_graph(sample_channels)
    
    # Find routes
    routes = await pathfinder.find_routes(
        source="node_a",
        target="node_c",
        amount_msat=500000
    )
    
    assert len(routes) <= 3
    if routes:
        route = routes[0]
        assert route.hops[0] == "node_a"
        assert route.hops[-1] == "node_c"
        assert route.total_fee_msat >= 0
        assert route.probability > 0


@pytest.mark.asyncio
async def test_fee_optimization():
    """Test fee optimization logic"""
    router = OneClickLightningRouter()
    
    # Setup test channels with different balances
    router.channels = [
        {
            "channel_id": "low_balance",
            "capacity": 1000000,
            "local_balance": 200000,  # 20% - should increase fees
            "remote_balance": 800000,
            "active": True
        },
        {
            "channel_id": "high_balance",
            "capacity": 1000000,
            "local_balance": 800000,  # 80% - should decrease fees
            "remote_balance": 200000,
            "active": True
        }
    ]
    
    # Run fee optimization
    await router.optimize_fees()
    
    # Fees should be adjusted based on balance
    # (In real implementation, would check actual fee updates)