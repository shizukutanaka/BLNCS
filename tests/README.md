# BLNCS Test Suite

## Overview
Test suite for Bitcoin Lightning Routing Control System focusing on Lightning Network functionality.

## Test Structure

```
tests/
├── conftest.py           # Pytest configuration and shared fixtures
├── test_lightning.py     # Core Lightning module tests
├── test_api.py          # API endpoint tests
├── test_cli.py          # CLI command tests
└── test_integration.py  # Integration tests
```

## Running Tests

### Run all tests
```bash
pytest
```

### Run specific test file
```bash
pytest tests/test_lightning.py
```

### Run with coverage
```bash
pytest --cov=blrcs --cov-report=html
```

### Run with verbose output
```bash
pytest -v
```

## Test Categories

### Unit Tests
- **test_lightning.py**: Tests for core Lightning modules
  - LightningClient initialization
  - ChannelManager functionality
  - LNDConnector operations
  - PaymentRouter logic
  - OneClickLightningRouter features

### API Tests
- **test_api.py**: Tests for REST API endpoints
  - Health check endpoint
  - Lightning status endpoint
  - Channels list endpoint
  - Routing information endpoint
  - WebSocket connections

### CLI Tests
- **test_cli.py**: Tests for command-line interface
  - Help command
  - Start/stop operations
  - Status display
  - Channel management
  - Rebalancing commands

### Integration Tests
- **test_integration.py**: End-to-end tests
  - One-click router with mock LND
  - Payment routing with sample data
  - Channel rebalancing logic
  - Route finding algorithms
  - Fee optimization

## Fixtures

### conftest.py
- `event_loop`: Async event loop for tests
- `test_config`: Test configuration settings
- `mock_lnd_response`: Mock LND API responses

### test_integration.py
- `mock_lnd_connector`: Mock LND connector instance
- `sample_channels`: Sample channel data for testing

## Writing Tests

### Example Unit Test
```python
def test_lightning_client_initialization():
    """Test Lightning client can be initialized"""
    client = LightningClient()
    assert client is not None
```

### Example Async Test
```python
@pytest.mark.asyncio
async def test_payment_router():
    """Test payment router initialization"""
    mock_connector = LNDConnector()
    router = PaymentRouter(mock_connector)
    assert router is not None
```

### Example Integration Test
```python
@pytest.mark.asyncio
async def test_one_click_router_integration(mock_lnd_connector):
    """Test one-click router with mock LND"""
    router = OneClickLightningRouter()
    router.lnd_connector = mock_lnd_connector
    success = await router.start()
    assert success == True
```

## Coverage Goals

- Unit test coverage: > 80%
- Integration test coverage: > 60%
- Critical path coverage: 100%

## Continuous Integration

Tests are automatically run on:
- Pull requests
- Main branch commits
- Release tags

## Dependencies

Test dependencies are listed in `requirements-dev.txt`:
- pytest
- pytest-asyncio
- pytest-cov
- pytest-mock
- fastapi[testing]