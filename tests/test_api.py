"""
Tests for Lightning API endpoints
"""

import pytest
from fastapi.testclient import TestClient
from blncs.api.main import app


client = TestClient(app)


def test_health_check():
    """Test health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "lightning" in data
    assert "timestamp" in data


def test_lightning_status():
    """Test Lightning status endpoint"""
    response = client.get("/api/lightning/status")
    assert response.status_code == 200
    data = response.json()
    assert "connected" in data
    assert "channels" in data
    assert "balance" in data


def test_channels_list():
    """Test channels list endpoint"""
    response = client.get("/api/lightning/channels")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_routing_info():
    """Test routing info endpoint"""
    response = client.get("/api/lightning/routing")
    assert response.status_code == 200
    data = response.json()
    assert "nodes_count" in data
    assert "channels_count" in data
    assert "avg_success_rate" in data


@pytest.mark.asyncio
async def test_websocket_connection():
    """Test WebSocket connection"""
    from fastapi.testclient import TestClient
    
    with client.websocket_connect("/ws") as websocket:
        # Test connection established
        data = websocket.receive_json()
        assert data["type"] == "connection"
        assert data["message"] == "Connected to Lightning updates"