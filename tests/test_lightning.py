"""
Tests for Lightning Network functionality
"""

import pytest
from blncs.lightning import (
    LightningClient,
    ChannelManager,
    LNDConnector,
    PaymentRouter,
    OneClickLightningRouter
)
from blncs.lightning.payment_router import (
    PaymentPathfinder,
    PaymentOptimizer,
    RouteMetric
)


def test_lightning_client_initialization():
    """Test Lightning client can be initialized"""
    client = LightningClient()
    assert client is not None


def test_channel_manager_initialization():
    """Test channel manager can be initialized"""
    manager = ChannelManager()
    assert manager is not None


@pytest.mark.asyncio
async def test_lnd_connector():
    """Test LND connector initialization"""
    connector = LNDConnector()
    assert connector is not None
    assert connector.host == "localhost"
    assert connector.port == 10009


@pytest.mark.asyncio
async def test_payment_router():
    """Test payment router initialization"""
    mock_connector = LNDConnector()
    router = PaymentRouter(mock_connector)
    assert router is not None
    assert router.pathfinder is not None
    assert router.optimizer is not None


@pytest.mark.asyncio
async def test_one_click_router():
    """Test one-click router initialization"""
    router = OneClickLightningRouter()
    assert router is not None
    assert router.config is not None
    assert router.config.auto_optimize == True


@pytest.mark.asyncio
async def test_pathfinder():
    """Test payment pathfinder"""
    pathfinder = PaymentPathfinder(max_routes=5)
    assert pathfinder is not None
    assert pathfinder.max_routes == 5
    assert len(pathfinder.channel_edges) == 0


@pytest.mark.asyncio
async def test_route_metrics():
    """Test routing metrics"""
    assert RouteMetric.LOWEST_FEE.value == "lowest_fee"
    assert RouteMetric.FASTEST.value == "fastest"
    assert RouteMetric.HIGHEST_SUCCESS.value == "highest_success"
    assert RouteMetric.BALANCED.value == "balanced"