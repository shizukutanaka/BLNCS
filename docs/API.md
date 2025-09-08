# BLNCS API Documentation

## Overview

BLNCS provides both a CLI interface and a Python API for Lightning Network management.

## Python API

### Basic Usage

```python
from blncs.lightning.client import LightningClient
from blncs.core.config import get_config

# Initialize client
client = LightningClient()

# Get node information
info = client.get_info()
print(f"Node alias: {info['alias']}")

# Check balance
balance = client.get_balance()
print(f"Total balance: {balance['total']} sats")

# List channels
channels = client.list_channels()
for channel in channels:
    print(f"Channel {channel['channel_id']}: {channel['capacity']} sats")
```

## CLI Commands

### System Commands

- `status` - Show system status
- `setup` - Initialize configuration
- `health` - Run health check
- `optimize` - Optimize system performance

### Lightning Commands

- `info` - Display node information
- `balance` - Show wallet balance
- `channels` - List all channels
- `open-channel` - Open a new channel
- `close-channel` - Close a channel
- `pay` - Pay a Lightning invoice
- `invoice` - Create a Lightning invoice

### Monitoring Commands

- `monitor` - Monitor wallet and channels
- `dashboard` - Display dashboard
- `history` - Show transaction history
- `stats` - Show statistics

## Configuration API

```python
from blncs.core.config import get_config

config = get_config()

# Get configuration value
host = config.get('lightning.host')

# Set configuration value
config.set('lightning.timeout', 5)

# Save configuration
config.save()
```

## Error Handling

```python
from blncs.core.exceptions import BLNCSError, LightningError

try:
    client.connect()
except LightningError as e:
    print(f"Lightning error: {e.message}")
    if e.recoverable:
        # Retry operation
        pass
except BLNCSError as e:
    print(f"System error: {e.message}")
```

## Health Monitoring

```python
from blncs.core.health import get_health_checker

checker = get_health_checker()

# Quick health check
status = checker.get_quick_status()
print(f"System status: {status['status']}")

# Full health check
health = checker.check_health()
for component, status in health.items():
    print(f"{component}: {status}")
```