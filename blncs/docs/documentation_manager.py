#!/usr/bin/env python3
"""
BLNCS Documentation Manager
Advanced documentation system with multi-format support and search capabilities.
"""

import os
import json
import logging
import markdown
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock
import re

logger = logging.getLogger(__name__)


@dataclass
class DocumentSection:
    """A single documentation section"""
    id: str
    title: str
    content: str
    category: str
    tags: List[str] = field(default_factory=list)
    language: str = 'en'
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())
    author: str = 'BLNCS Team'
    difficulty: str = 'beginner'  # beginner, intermediate, advanced
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'category': self.category,
            'tags': self.tags,
            'language': self.language,
            'last_updated': self.last_updated,
            'author': self.author,
            'difficulty': self.difficulty
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DocumentSection':
        """Create from dictionary"""
        return cls(**data)


class DocumentationManager:
    """Comprehensive documentation management system"""
    
    def __init__(self, docs_dir: Optional[str] = None):
        self.docs_dir = Path(docs_dir or self._get_default_docs_dir())
        self.content_dir = self.docs_dir / 'content'
        self.templates_dir = self.docs_dir / 'templates'
        self.output_dir = self.docs_dir / 'output'
        
        # Documentation storage
        self.sections: Dict[str, DocumentSection] = {}
        self.categories: Dict[str, List[str]] = {}
        self.search_index: Dict[str, List[str]] = {}
        
        self.lock = Lock()
        
        # Initialize documentation system
        self.initialize_docs()
        self.load_documentation()
    
    def _get_default_docs_dir(self) -> str:
        """Get default documentation directory"""
        return str(Path(__file__).parent / 'content')
    
    def initialize_docs(self):
        """Initialize documentation directory structure"""
        # Create directories
        for directory in [self.docs_dir, self.content_dir, self.templates_dir, self.output_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Create default documentation if it doesn't exist
        if not any(self.content_dir.glob('*.json')):
            self.create_default_documentation()
        
        logger.info(f"Documentation system initialized in {self.docs_dir}")
    
    def create_default_documentation(self):
        """Create default documentation content"""
        logger.info("Creating default documentation content")
        
        # Getting Started Guide
        getting_started = DocumentSection(
            id='getting_started',
            title='Getting Started with BLNCS',
            content='''# Getting Started with BLNCS

Welcome to the Bitcoin Lightning Network Control System (BLNCS)! This guide will help you get started quickly.

## What is BLNCS?

BLNCS is a comprehensive control system for Bitcoin Lightning Network nodes, providing:

- **Node Management**: Connect and manage Lightning Network nodes
- **Channel Management**: Open, close, and monitor Lightning channels
- **Wallet Operations**: Send and receive Bitcoin payments
- **Monitoring & Alerts**: Real-time monitoring with customizable alerts
- **Multi-language Support**: Available in English, Japanese, and Spanish
- **Production Monitoring**: Enterprise-grade monitoring and alerting

## Quick Setup

### 1. Installation

```bash
# Install BLNCS
pip install blncs

# Or run from source
python -m blncs
```

### 2. First Time Setup

1. **Launch BLNCS**: Run `blncs` or `python -m blncs`
2. **Setup Wizard**: Follow the interactive setup wizard
3. **Connect Node**: Configure your Lightning Network node connection
4. **Verify Connection**: Test the connection to ensure everything works

### 3. Basic Operations

#### Connecting to Your Node

```bash
# Using CLI
blncs connect --host localhost --port 9735

# Using GUI
# Click "Connect" button in the main interface
```

#### Checking Balance

```bash
# View wallet balance
blncs wallet balance

# View channel balances
blncs channels list
```

#### Making Payments

```bash
# Generate invoice
blncs wallet invoice 1000 "Payment description"

# Pay invoice
blncs wallet pay <invoice_string>
```

## Next Steps

- Read the [Node Configuration Guide](node_configuration)
- Learn about [Channel Management](channel_management)
- Set up [Monitoring and Alerts](monitoring_setup)
- Explore [Advanced Features](advanced_features)

## Need Help?

- Use the built-in help system: `blncs help`
- Check the troubleshooting guide: `blncs help troubleshooting`
- Visit our documentation: `blncs docs open`
''',
            category='getting_started',
            tags=['setup', 'installation', 'quickstart'],
            difficulty='beginner'
        )
        
        # Node Configuration
        node_config = DocumentSection(
            id='node_configuration',
            title='Node Configuration',
            content='''# Node Configuration

Learn how to configure BLNCS to work with your Lightning Network node.

## Supported Node Types

BLNCS supports multiple Lightning Network implementations:

- **LND (Lightning Network Daemon)**
- **Core Lightning (CLN)**
- **Eclair**
- **REST API compatible nodes**

## Configuration Methods

### 1. Interactive Setup

Use the built-in setup wizard:

```bash
blncs setup
```

The wizard will guide you through:
- Node type selection
- Connection details
- Authentication setup
- Initial testing

### 2. Configuration File

Create a configuration file at `~/.blncs/config.json`:

```json
{
  "node": {
    "type": "lnd",
    "host": "localhost",
    "port": 10009,
    "tls_cert": "/path/to/tls.cert",
    "macaroon": "/path/to/admin.macaroon"
  },
  "wallet": {
    "auto_unlock": false,
    "password_file": "/path/to/password.txt"
  },
  "monitoring": {
    "enabled": true,
    "interval": 30
  }
}
```

### 3. Environment Variables

Set environment variables for configuration:

```bash
export BLNCS_NODE_HOST="localhost"
export BLNCS_NODE_PORT="10009"
export BLNCS_TLS_CERT="/path/to/tls.cert"
export BLNCS_MACAROON="/path/to/admin.macaroon"
```

## LND Configuration

### Requirements

- LND version 0.15.0 or higher
- Admin macaroon for full functionality
- TLS certificate for secure connection

### Setup Steps

1. **Locate LND Files**:
   - TLS certificate: `~/.lnd/tls.cert`
   - Admin macaroon: `~/.lnd/data/chain/bitcoin/mainnet/admin.macaroon`

2. **Configure Connection**:
   ```bash
   blncs config set node.type lnd
   blncs config set node.host localhost
   blncs config set node.port 10009
   blncs config set node.tls_cert ~/.lnd/tls.cert
   blncs config set node.macaroon ~/.lnd/data/chain/bitcoin/mainnet/admin.macaroon
   ```

3. **Test Connection**:
   ```bash
   blncs node info
   ```

## Core Lightning Configuration

### Requirements

- Core Lightning version 0.12.0 or higher
- RPC access configured
- Proper file permissions

### Setup Steps

1. **Configure Core Lightning**:
   Add to your Core Lightning config:
   ```
   rpc-file=/tmp/lightning-rpc
   ```

2. **Configure BLNCS**:
   ```bash
   blncs config set node.type core_lightning
   blncs config set node.rpc_file /tmp/lightning-rpc
   ```

3. **Test Connection**:
   ```bash
   blncs node info
   ```

## Security Considerations

- **File Permissions**: Ensure macaroon and key files have restricted permissions (600)
- **Network Security**: Use TLS for all connections
- **Credential Storage**: Store credentials securely, avoid plaintext passwords
- **Regular Updates**: Keep BLNCS and your Lightning node updated

## Troubleshooting

### Connection Issues

1. **Check Node Status**:
   ```bash
   # For LND
   lncli getinfo
   
   # For Core Lightning
   lightning-cli getinfo
   ```

2. **Verify File Paths**:
   ```bash
   blncs config show
   ```

3. **Test Network Connectivity**:
   ```bash
   blncs connection test
   ```

### Common Errors

- **"Permission denied"**: Check file permissions on certificates/macaroons
- **"Connection refused"**: Verify node is running and accessible
- **"Invalid macaroon"**: Ensure you're using the correct macaroon file
- **"TLS handshake failed"**: Check TLS certificate validity

## Advanced Configuration

### Custom REST API

For custom node implementations:

```json
{
  "node": {
    "type": "rest_api",
    "base_url": "https://your-node.com/api",
    "auth": {
      "type": "bearer_token",
      "token": "your_api_token"
    }
  }
}
```

### Load Balancing

Configure multiple nodes for redundancy:

```json
{
  "nodes": [
    {
      "id": "primary",
      "host": "node1.example.com",
      "priority": 1
    },
    {
      "id": "backup", 
      "host": "node2.example.com",
      "priority": 2
    }
  ]
}
```
''',
            category='configuration',
            tags=['node', 'setup', 'lnd', 'core_lightning'],
            difficulty='intermediate'
        )
        
        # Channel Management
        channel_mgmt = DocumentSection(
            id='channel_management',
            title='Channel Management',
            content='''# Channel Management

Complete guide to managing Lightning Network channels with BLNCS.

## Understanding Channels

Lightning Network channels are payment channels between two nodes that enable instant, low-fee Bitcoin transactions.

### Channel States

- **Opening**: Channel is being established on the blockchain
- **Active**: Channel is ready for payments
- **Inactive**: Channel exists but peer is offline
- **Closing**: Channel is being closed cooperatively
- **Force Closing**: Unilateral channel closure
- **Closed**: Channel has been closed and settled

## Opening Channels

### Using CLI

```bash
# Open channel with specific node
blncs channels open 03abc123... 1000000

# Open channel with custom fee rate
blncs channels open 03abc123... 1000000 --fee-rate 10

# Open private channel
blncs channels open 03abc123... 1000000 --private
```

### Using GUI

1. Navigate to **Channels** tab
2. Click **Open Channel**
3. Enter node public key and amount
4. Configure channel options
5. Click **Confirm**

### Channel Opening Parameters

- **Node Public Key**: 66-character hex string identifying the peer
- **Channel Amount**: Local capacity in satoshis
- **Fee Rate**: Transaction fee rate in sat/vByte
- **Private Channel**: Whether to announce the channel publicly

## Monitoring Channels

### Channel List

```bash
# List all channels
blncs channels list

# List only active channels
blncs channels list --active

# Show detailed channel information
blncs channels info <channel_id>
```

### Channel Statistics

```bash
# Show channel statistics
blncs channels stats

# Show routing statistics
blncs routing stats
```

### Real-time Monitoring

Enable real-time channel monitoring:

```bash
# Start monitoring
blncs monitor channels

# Monitor with alerts
blncs monitor channels --alerts
```

## Channel Balancing

### Understanding Balance

Each channel has two balances:
- **Local Balance**: Amount you can send
- **Remote Balance**: Amount you can receive

### Rebalancing Strategies

1. **Circular Payments**: Send payments through multiple channels to redistribute funds
2. **Channel Splicing**: Add or remove funds from existing channels (if supported)
3. **Submarine Swaps**: Exchange on-chain Bitcoin for Lightning capacity

### Automated Rebalancing

```bash
# Enable automatic rebalancing
blncs config set rebalancing.enabled true
blncs config set rebalancing.target_ratio 0.5

# Set rebalancing limits
blncs config set rebalancing.max_fee_rate 100
blncs config set rebalancing.max_amount 100000
```

## Closing Channels

### Cooperative Close

```bash
# Close channel cooperatively
blncs channels close <channel_id>

# Close with custom fee rate
blncs channels close <channel_id> --fee-rate 20
```

### Force Close

Only use when cooperative close isn't possible:

```bash
# Force close channel (emergency only)
blncs channels force-close <channel_id>
```

⚠️ **Warning**: Force closing results in longer settlement times and higher fees.

## Channel Fees and Routing

### Setting Channel Fees

```bash
# Set fees for all channels
blncs channels set-fees --base-fee 1000 --fee-rate 0.001

# Set fees for specific channel
blncs channels set-fees <channel_id> --base-fee 500 --fee-rate 0.0005
```

### Fee Strategies

1. **Conservative**: Lower fees to attract more routing
2. **Aggressive**: Higher fees for premium routing
3. **Dynamic**: Adjust fees based on demand and balance

### Routing Management

```bash
# View routing history
blncs routing history

# Show routing statistics
blncs routing stats

# Set routing policies
blncs routing policy set --max-htlc 1000000 --time-lock-delta 40
```

## Channel Health Monitoring

### Health Metrics

BLNCS monitors several channel health indicators:

- **Uptime**: Percentage of time channel is active
- **Balance Distribution**: How evenly balanced the channel is
- **Routing Activity**: Number of payments routed
- **Fee Earnings**: Revenue generated from routing

### Automated Alerts

Set up alerts for channel issues:

```json
{
  "alerts": {
    "channel_offline": {
      "enabled": true,
      "threshold": 3600
    },
    "low_balance": {
      "enabled": true,
      "threshold": 0.1
    },
    "high_fees": {
      "enabled": true,
      "threshold": 1000
    }
  }
}
```

## Best Practices

### Channel Selection

1. **Peer Reliability**: Choose well-connected, reliable peers
2. **Capacity Planning**: Balance channel sizes based on payment patterns
3. **Geographic Distribution**: Connect to nodes in different regions
4. **Backup Channels**: Maintain redundant paths for reliability

### Maintenance

1. **Regular Monitoring**: Check channel status daily
2. **Balance Management**: Keep channels balanced for optimal routing
3. **Fee Optimization**: Adjust fees based on network conditions
4. **Backup Strategy**: Maintain channel backups for disaster recovery

### Security

1. **Node Security**: Secure your Lightning node properly
2. **Channel Backups**: Regularly backup channel state
3. **Monitoring**: Set up alerts for unusual activity
4. **Updates**: Keep your Lightning software updated

## Troubleshooting

### Common Issues

1. **Channel Won't Open**:
   - Check peer connectivity
   - Verify sufficient on-chain balance
   - Confirm minimum channel size requirements

2. **Payments Failing**:
   - Check channel balance and liquidity
   - Verify route availability
   - Confirm invoice validity

3. **High Fees**:
   - Review fee settings
   - Check network congestion
   - Consider alternative routes

### Diagnostic Commands

```bash
# Check node connectivity
blncs node ping <peer_pubkey>

# Verify channel state
blncs channels verify <channel_id>

# Test payment paths
blncs payments probe <destination> <amount>
```
''',
            category='operations',
            tags=['channels', 'payments', 'routing', 'lightning'],
            difficulty='intermediate'
        )
        
        # Save documentation sections
        self.add_section(getting_started)
        self.add_section(node_config)
        self.add_section(channel_mgmt)
        
        # Create additional sections
        self._create_monitoring_docs()
        self._create_troubleshooting_docs()
        self._create_api_docs()
        
        logger.info("Default documentation created successfully")
    
    def _create_monitoring_docs(self):
        """Create monitoring and alerting documentation"""
        monitoring_doc = DocumentSection(
            id='monitoring_setup',
            title='Monitoring and Alerting Setup',
            content='''# Monitoring and Alerting Setup

Set up comprehensive monitoring for your Lightning Network node with BLNCS.

## Overview

BLNCS provides enterprise-grade monitoring capabilities:

- **Real-time Metrics**: System, Lightning, and application metrics
- **Configurable Alerts**: Email, webhook, and console notifications
- **Visual Dashboard**: Real-time charts and status indicators
- **Health Checks**: Automated health monitoring
- **Performance Tracking**: Response time and throughput monitoring

## Quick Start

### 1. Enable Monitoring

```bash
# Enable monitoring
blncs monitoring start

# Launch dashboard
blncs monitoring dashboard
```

### 2. Basic Configuration

```bash
# Set monitoring intervals
blncs config set monitoring.system_interval 30
blncs config set monitoring.lightning_interval 60

# Enable alerts
blncs config set monitoring.alerts.enabled true
```

## Monitoring Components

### System Metrics

- **CPU Usage**: Processor utilization percentage
- **Memory Usage**: RAM consumption and availability
- **Disk Usage**: Storage space utilization
- **Network I/O**: Network traffic and connectivity
- **Process Metrics**: Application-specific performance

### Lightning Metrics

- **Channel Status**: Active, inactive, and pending channels
- **Balance Distribution**: Local and remote balances
- **Payment Activity**: Successful and failed payments
- **Routing Performance**: Forwarded payments and fees earned
- **Node Connectivity**: Peer connections and network status

### Application Metrics

- **Response Times**: API and operation latency
- **Error Rates**: Failed operations and exceptions
- **Resource Usage**: Memory, CPU, and database usage
- **User Activity**: Connection attempts and operations

## Alert Configuration

### Alert Channels

Configure multiple notification channels:

```bash
# Email alerts
blncs alerts configure email --smtp-server smtp.gmail.com \
  --username your-email@gmail.com --password your-password \
  --recipients alert@yourcompany.com

# Webhook alerts
blncs alerts configure webhook --url https://your-webhook.com/alerts \
  --method POST --headers "Content-Type: application/json"

# Slack integration
blncs alerts configure slack --webhook-url https://hooks.slack.com/... \
  --channel "#lightning-alerts"
```

### Alert Rules

Set up alert thresholds:

```bash
# CPU usage alerts
blncs alerts rule create cpu_high --metric cpu_usage \
  --threshold 80 --severity warning
blncs alerts rule create cpu_critical --metric cpu_usage \
  --threshold 95 --severity critical

# Channel alerts
blncs alerts rule create channels_offline --metric channels_offline \
  --threshold 1 --severity warning

# Balance alerts
blncs alerts rule create low_balance --metric local_balance \
  --threshold 100000 --comparison less --severity warning
```

## Dashboard Usage

### Web Dashboard

Access the monitoring dashboard:

```bash
# Start web dashboard
blncs monitoring dashboard --port 8080

# Open in browser
# Navigate to http://localhost:8080
```

### GUI Dashboard

Launch the desktop dashboard:

```bash
# GUI dashboard
blncs monitoring dashboard --gui
```

### Features

- **Real-time Charts**: Live updating metrics
- **Status Indicators**: Health status for all components
- **Alert History**: Recent alerts and notifications
- **Export Functions**: Data export for analysis

## Advanced Monitoring

### Custom Metrics

Define custom metrics for monitoring:

```python
from blncs.monitoring import MetricsCollector

collector = MetricsCollector()

# Add custom metric
collector.add_metric('custom_metric', value=42, 
                    labels={'component': 'custom'})

# Track timing
with collector.timer('operation_duration'):
    # Your code here
    pass
```

### Prometheus Integration

Export metrics to Prometheus:

```bash
# Enable Prometheus metrics
blncs config set monitoring.prometheus.enabled true
blncs config set monitoring.prometheus.port 9090

# Start Prometheus exporter
blncs monitoring prometheus
```

### Grafana Dashboards

Import pre-built Grafana dashboards:

```bash
# Export dashboard templates
blncs monitoring export-grafana-dashboard > blncs-dashboard.json

# Import into Grafana
# Use the exported JSON file in Grafana
```

## Performance Optimization

### Monitoring Overhead

Optimize monitoring performance:

```bash
# Adjust collection intervals
blncs config set monitoring.system_interval 60  # Less frequent
blncs config set monitoring.batch_size 100     # Larger batches

# Enable sampling
blncs config set monitoring.sampling.enabled true
blncs config set monitoring.sampling.rate 0.1  # 10% sampling
```

### Data Retention

Configure data retention policies:

```bash
# Set retention periods
blncs config set monitoring.retention.metrics 30d
blncs config set monitoring.retention.alerts 90d
blncs config set monitoring.retention.logs 7d

# Enable automatic cleanup
blncs config set monitoring.cleanup.enabled true
blncs config set monitoring.cleanup.interval 24h
```

## Troubleshooting

### Common Issues

1. **High CPU Usage**:
   ```bash
   # Check monitoring overhead
   blncs monitoring stats
   
   # Reduce collection frequency
   blncs config set monitoring.system_interval 120
   ```

2. **Alert Fatigue**:
   ```bash
   # Adjust thresholds
   blncs alerts rule update cpu_high --threshold 90
   
   # Enable alert grouping
   blncs config set monitoring.alerts.grouping true
   ```

3. **Storage Issues**:
   ```bash
   # Check storage usage
   blncs monitoring storage-usage
   
   # Clean old data
   blncs monitoring cleanup --older-than 30d
   ```

### Diagnostic Commands

```bash
# Check monitoring status
blncs monitoring status

# Test alert channels
blncs alerts test email
blncs alerts test webhook

# Validate configuration
blncs config validate monitoring
```
''',
            category='monitoring',
            tags=['monitoring', 'alerts', 'dashboard', 'performance'],
            difficulty='intermediate'
        )
        
        self.add_section(monitoring_doc)
    
    def _create_troubleshooting_docs(self):
        """Create troubleshooting documentation"""
        troubleshooting_doc = DocumentSection(
            id='troubleshooting',
            title='Troubleshooting Guide',
            content='''# Troubleshooting Guide

Common issues and solutions for BLNCS.

## General Troubleshooting

### Getting Help

```bash
# Show help system
blncs help

# Check system status
blncs status

# View logs
blncs logs --tail 100

# Run diagnostics
blncs diagnostics
```

### Common Commands

```bash
# Check configuration
blncs config show

# Test connections
blncs connection test

# Verify installation
blncs version --detailed
```

## Connection Issues

### Cannot Connect to Node

**Symptoms**: Connection timeout, authentication errors

**Solutions**:

1. **Check Node Status**:
   ```bash
   # For LND
   lncli getinfo
   
   # For Core Lightning
   lightning-cli getinfo
   ```

2. **Verify Configuration**:
   ```bash
   blncs config show node
   ```

3. **Test Network Connectivity**:
   ```bash
   ping your-node-host
   telnet your-node-host 10009
   ```

4. **Check Certificates**:
   ```bash
   # Verify TLS certificate
   openssl x509 -in ~/.lnd/tls.cert -text -noout
   
   # Check file permissions
   ls -la ~/.lnd/tls.cert
   ls -la ~/.lnd/data/chain/bitcoin/mainnet/admin.macaroon
   ```

### Authentication Errors

**Symptoms**: "Permission denied", "Invalid macaroon"

**Solutions**:

1. **Verify Macaroon Path**:
   ```bash
   blncs config get node.macaroon
   ls -la "$(blncs config get node.macaroon)"
   ```

2. **Check Macaroon Permissions**:
   ```bash
   # Should be 600 (readable by owner only)
   chmod 600 ~/.lnd/data/chain/bitcoin/mainnet/admin.macaroon
   ```

3. **Regenerate Macaroon** (if needed):
   ```bash
   lncli bakemacaroon uri:/lnrpc.Lightning/GetInfo
   ```

## Payment Issues

### Payments Failing

**Symptoms**: "No route found", "Insufficient balance"

**Solutions**:

1. **Check Balances**:
   ```bash
   blncs wallet balance
   blncs channels list
   ```

2. **Verify Routes**:
   ```bash
   blncs payments probe <destination> <amount>
   blncs routing find-route <destination> <amount>
   ```

3. **Channel Liquidity**:
   ```bash
   # Check channel balances
   blncs channels list --detailed
   
   # Rebalance if needed
   blncs channels rebalance
   ```

### Invoice Issues

**Symptoms**: "Invoice expired", "Invalid payment hash"

**Solutions**:

1. **Check Invoice Status**:
   ```bash
   blncs wallet invoice-status <payment_hash>
   ```

2. **Generate New Invoice**:
   ```bash
   blncs wallet invoice <amount> "New payment"
   ```

## Channel Issues

### Channels Not Opening

**Symptoms**: Channel stuck in "opening" state

**Solutions**:

1. **Check On-chain Transaction**:
   ```bash
   blncs wallet transactions
   blncs channels pending
   ```

2. **Verify Peer Connection**:
   ```bash
   blncs node peers
   blncs node connect <peer_pubkey>@<peer_host>
   ```

3. **Check Minimum Channel Size**:
   ```bash
   blncs config get channels.min_size
   ```

### Channel Force Closes

**Symptoms**: Unexpected channel closures, funds locked

**Solutions**:

1. **Check Closure Reason**:
   ```bash
   blncs channels history --closed
   ```

2. **Monitor Sweep Transactions**:
   ```bash
   blncs wallet transactions --pending
   ```

3. **Wait for Timeout**:
   Force closes require waiting for the timelock to expire (usually 144 blocks).

## Performance Issues

### Slow Response Times

**Symptoms**: Long delays, timeouts

**Solutions**:

1. **Check System Resources**:
   ```bash
   blncs monitoring status
   htop
   df -h
   ```

2. **Optimize Configuration**:
   ```bash
   # Increase timeouts
   blncs config set network.timeout 60
   
   # Reduce monitoring frequency
   blncs config set monitoring.interval 60
   ```

3. **Database Maintenance**:
   ```bash
   blncs database optimize
   blncs database vacuum
   ```

### High Memory Usage

**Symptoms**: System slowdown, out-of-memory errors

**Solutions**:

1. **Check Memory Usage**:
   ```bash
   blncs monitoring memory
   ps aux | grep blncs
   ```

2. **Optimize Settings**:
   ```bash
   # Reduce cache size
   blncs config set cache.max_size 100MB
   
   # Enable garbage collection
   blncs config set gc.enabled true
   ```

## GUI Issues

### GUI Not Starting

**Symptoms**: GUI window doesn't appear, crashes on startup

**Solutions**:

1. **Check Dependencies**:
   ```bash
   python -c "import tkinter; print('tkinter available')"
   ```

2. **Run in Debug Mode**:
   ```bash
   blncs gui --debug
   ```

3. **Check Display**:
   ```bash
   echo $DISPLAY
   xauth list
   ```

### Display Issues

**Symptoms**: Garbled text, missing elements

**Solutions**:

1. **Update Font Settings**:
   ```bash
   blncs config set gui.font.family "Arial"
   blncs config set gui.font.size 10
   ```

2. **Reset GUI Configuration**:
   ```bash
   blncs config reset gui
   ```

## Data Issues

### Database Corruption

**Symptoms**: "Database locked", data inconsistencies

**Solutions**:

1. **Backup Data**:
   ```bash
   blncs backup create --full
   ```

2. **Check Database Integrity**:
   ```bash
   blncs database check
   ```

3. **Repair Database**:
   ```bash
   blncs database repair
   ```

4. **Restore from Backup** (if needed):
   ```bash
   blncs backup restore --file backup.tar.gz
   ```

### Configuration Issues

**Symptoms**: Invalid settings, crashes on startup

**Solutions**:

1. **Validate Configuration**:
   ```bash
   blncs config validate
   ```

2. **Reset to Defaults**:
   ```bash
   blncs config reset
   ```

3. **Manual Configuration**:
   ```bash
   # Edit configuration file directly
   nano ~/.blncs/config.json
   ```

## Logging and Diagnostics

### Enable Debug Logging

```bash
# Set debug level
blncs config set logging.level DEBUG

# Enable component-specific logging
blncs config set logging.components.lightning DEBUG
blncs config set logging.components.database DEBUG
```

### Collect Diagnostic Information

```bash
# Generate diagnostic report
blncs diagnostics --full > diagnostics.txt

# Include system information
blncs diagnostics --system --network --configuration
```

### Log Locations

- **Application Logs**: `~/.blncs/logs/blncs.log`
- **Error Logs**: `~/.blncs/logs/error.log`
- **Debug Logs**: `~/.blncs/logs/debug.log`
- **Audit Logs**: `~/.blncs/logs/audit.log`

## Getting Additional Help

### Community Resources

- **Documentation**: `blncs docs open`
- **GitHub Issues**: Report bugs and feature requests
- **Community Forum**: Ask questions and share experiences

### Support Information

```bash
# Generate support bundle
blncs support bundle > support.zip

# Check system compatibility
blncs compatibility check
```

### Emergency Recovery

```bash
# Safe mode (minimal functionality)
blncs --safe-mode

# Recovery mode (repair and restore)
blncs --recovery-mode

# Factory reset (nuclear option)
blncs factory-reset --confirm
```
''',
            category='support',
            tags=['troubleshooting', 'debugging', 'support'],
            difficulty='beginner'
        )
        
        self.add_section(troubleshooting_doc)
    
    def _create_api_docs(self):
        """Create API documentation"""
        api_doc = DocumentSection(
            id='api_reference',
            title='API Reference',
            content='''# BLNCS API Reference

Complete reference for BLNCS command-line interface and Python API.

## Command Line Interface

### Global Options

```bash
blncs [GLOBAL_OPTIONS] COMMAND [COMMAND_OPTIONS]

Global Options:
  --config PATH     Configuration file path
  --verbose, -v     Verbose output
  --quiet, -q       Quiet mode
  --help           Show help message
  --version        Show version information
```

### Node Commands

```bash
# Node information and management
blncs node info                    # Get node information
blncs node connect PUBKEY@HOST     # Connect to peer
blncs node disconnect PUBKEY       # Disconnect from peer
blncs node peers                   # List connected peers
```

### Wallet Commands

```bash
# Wallet operations
blncs wallet balance              # Show wallet balance
blncs wallet address             # Generate new address
blncs wallet transactions        # List transactions
blncs wallet send ADDRESS AMOUNT # Send on-chain payment
blncs wallet invoice AMOUNT DESC # Create Lightning invoice
blncs wallet pay INVOICE         # Pay Lightning invoice
```

### Channel Commands

```bash
# Channel management
blncs channels list              # List all channels
blncs channels open PUBKEY AMOUNT # Open new channel
blncs channels close CHANNEL_ID   # Close channel
blncs channels balance            # Show channel balances
blncs channels fees              # Show fee settings
```

### Monitoring Commands

```bash
# Monitoring and alerts
blncs monitoring start           # Start monitoring
blncs monitoring stop            # Stop monitoring
blncs monitoring status          # Show monitoring status
blncs monitoring dashboard       # Launch dashboard
blncs monitoring collect         # Collect metrics
```

### Configuration Commands

```bash
# Configuration management
blncs config show               # Show all configuration
blncs config get KEY            # Get specific value
blncs config set KEY VALUE      # Set configuration value
blncs config reset              # Reset to defaults
blncs config validate           # Validate configuration
```

## Python API

### Installation

```python
pip install blncs
```

### Basic Usage

```python
from blncs import BLNCSClient

# Create client
client = BLNCSClient(config_file='~/.blncs/config.json')

# Connect to node
client.connect()

# Get node information
info = client.node.get_info()
print(f"Node ID: {info.identity_pubkey}")
print(f"Block Height: {info.block_height}")
```

### Node Operations

```python
# Node management
node = client.node

# Get node information
info = node.get_info()

# Connect to peer
node.connect_peer(pubkey='03abc123...', host='node.example.com:9735')

# List peers
peers = node.list_peers()

# Disconnect peer
node.disconnect_peer(pubkey='03abc123...')
```

### Wallet Operations

```python
# Wallet management
wallet = client.wallet

# Get balance
balance = wallet.get_balance()
print(f"Confirmed: {balance.confirmed_balance}")
print(f"Unconfirmed: {balance.unconfirmed_balance}")

# Generate address
address = wallet.new_address()
print(f"New address: {address.address}")

# Create invoice
invoice = wallet.add_invoice(
    amount=1000,
    memo="Test payment",
    expiry=3600
)
print(f"Payment request: {invoice.payment_request}")

# Pay invoice
payment = wallet.pay_invoice(payment_request="lnbc...")
if payment.status == 'SUCCEEDED':
    print(f"Payment successful: {payment.payment_hash}")
```

### Channel Management

```python
# Channel operations
channels = client.channels

# List channels
channel_list = channels.list_channels()
for channel in channel_list.channels:
    print(f"Channel ID: {channel.chan_id}")
    print(f"Peer: {channel.remote_pubkey}")
    print(f"Capacity: {channel.capacity}")
    print(f"Local Balance: {channel.local_balance}")

# Open channel
response = channels.open_channel(
    node_pubkey='03abc123...',
    local_funding_amount=1000000,
    private=False
)

# Close channel
close_response = channels.close_channel(
    channel_point=f"{response.funding_txid_str}:{response.output_index}"
)
```

### Monitoring Integration

```python
# Monitoring
monitor = client.monitoring

# Start monitoring
monitor.start()

# Get metrics
metrics = monitor.get_metrics()
print(f"CPU Usage: {metrics.system.cpu_percent}%")
print(f"Memory Usage: {metrics.system.memory_percent}%")

# Set up alerts
monitor.add_alert_rule(
    name='high_cpu',
    metric='cpu_percent',
    threshold=80,
    comparison='greater',
    severity='warning'
)
```

### Configuration Management

```python
# Configuration
config = client.config

# Get configuration value
node_host = config.get('node.host')
print(f"Node host: {node_host}")

# Set configuration value
config.set('monitoring.interval', 60)

# Save configuration
config.save()

# Validate configuration
is_valid, errors = config.validate()
if not is_valid:
    print(f"Configuration errors: {errors}")
```

### Error Handling

```python
from blncs.exceptions import BLNCSError, ConnectionError, PaymentError

try:
    # Attempt operation
    client.connect()
    balance = client.wallet.get_balance()
    
except ConnectionError as e:
    print(f"Connection failed: {e}")
    
except PaymentError as e:
    print(f"Payment error: {e}")
    
except BLNCSError as e:
    print(f"BLNCS error: {e}")
    
except Exception as e:
    print(f"Unexpected error: {e}")
```

### Async Operations

```python
import asyncio
from blncs import AsyncBLNCSClient

async def main():
    # Async client
    client = AsyncBLNCSClient()
    
    try:
        # Connect asynchronously
        await client.connect()
        
        # Get information
        info = await client.node.get_info()
        print(f"Node: {info.alias}")
        
        # List channels
        channels = await client.channels.list_channels()
        print(f"Channels: {len(channels.channels)}")
        
    finally:
        await client.close()

# Run async function
asyncio.run(main())
```

## Data Models

### NodeInfo

```python
@dataclass
class NodeInfo:
    identity_pubkey: str
    alias: str
    color: str
    num_pending_channels: int
    num_active_channels: int
    num_inactive_channels: int
    num_peers: int
    block_height: int
    block_hash: str
    best_header_timestamp: int
    synced_to_chain: bool
    synced_to_graph: bool
    chains: List[Chain]
    uris: List[str]
    features: Dict[int, Feature]
```

### WalletBalance

```python
@dataclass
class WalletBalance:
    total_balance: int
    confirmed_balance: int
    unconfirmed_balance: int
    locked_balance: int
    reserved_balance_anchor_chan: int
```

### Channel

```python
@dataclass
class Channel:
    active: bool
    remote_pubkey: str
    channel_point: str
    chan_id: int
    capacity: int
    local_balance: int
    remote_balance: int
    commit_fee: int
    commit_weight: int
    fee_per_kw: int
    unsettled_balance: int
    total_satoshis_sent: int
    total_satoshis_received: int
    num_updates: int
    pending_htlcs: List[HTLC]
    csv_delay: int
    private: bool
    initiator: bool
    chan_status_flags: str
    local_chan_reserve_sat: int
    remote_chan_reserve_sat: int
    static_remote_key: bool
    commitment_type: CommitmentType
    lifetime: int
    uptime: int
```

### Payment

```python
@dataclass
class Payment:
    payment_hash: str
    value: int
    creation_date: int
    fee: int
    payment_preimage: str
    value_sat: int
    value_msat: int
    payment_request: str
    status: PaymentStatus
    fee_sat: int
    fee_msat: int
    creation_time_ns: int
    htlcs: List[HTLCAttempt]
    payment_index: int
    failure_reason: PaymentFailureReason
```

## Response Formats

### Success Response

```json
{
    "success": true,
    "data": {
        "node_info": {
            "identity_pubkey": "03abc123...",
            "alias": "MyLightningNode",
            "num_active_channels": 5,
            "block_height": 750000
        }
    },
    "timestamp": "2025-01-15T10:30:00Z"
}
```

### Error Response

```json
{
    "success": false,
    "error": {
        "code": "CONNECTION_ERROR",
        "message": "Failed to connect to Lightning node",
        "details": {
            "host": "localhost",
            "port": 10009,
            "timeout": 30
        }
    },
    "timestamp": "2025-01-15T10:30:00Z"
}
```

## Rate Limits and Best Practices

### Rate Limits

- **Node Operations**: 100 requests/minute
- **Wallet Operations**: 60 requests/minute
- **Channel Operations**: 30 requests/minute
- **Payment Operations**: 120 requests/minute

### Best Practices

1. **Connection Management**:
   - Reuse client connections
   - Implement connection pooling
   - Handle reconnection gracefully

2. **Error Handling**:
   - Always wrap operations in try-catch blocks
   - Implement exponential backoff for retries
   - Log errors appropriately

3. **Performance**:
   - Use async operations for high-throughput scenarios
   - Batch operations when possible
   - Cache frequently accessed data

4. **Security**:
   - Store credentials securely
   - Use TLS for all connections
   - Validate all input data
   - Implement proper access controls
''',
            category='reference',
            tags=['api', 'cli', 'python', 'reference'],
            difficulty='advanced'
        )
        
        self.add_section(api_doc)
    
    def load_documentation(self):
        """Load all documentation from storage"""
        with self.lock:
            # Load from JSON files
            for doc_file in self.content_dir.glob('*.json'):
                try:
                    with open(doc_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    section = DocumentSection.from_dict(data)
                    self.sections[section.id] = section
                    
                    # Update categories
                    if section.category not in self.categories:
                        self.categories[section.category] = []
                    if section.id not in self.categories[section.category]:
                        self.categories[section.category].append(section.id)
                    
                    logger.debug(f"Loaded documentation section: {section.id}")
                    
                except Exception as e:
                    logger.error(f"Failed to load documentation file {doc_file}: {e}")
            
            # Build search index
            self.build_search_index()
            
            logger.info(f"Loaded {len(self.sections)} documentation sections")
    
    def add_section(self, section: DocumentSection):
        """Add a documentation section"""
        with self.lock:
            # Store in memory
            self.sections[section.id] = section
            
            # Update categories
            if section.category not in self.categories:
                self.categories[section.category] = []
            if section.id not in self.categories[section.category]:
                self.categories[section.category].append(section.id)
            
            # Save to file
            section_file = self.content_dir / f"{section.id}.json"
            try:
                with open(section_file, 'w', encoding='utf-8') as f:
                    json.dump(section.to_dict(), f, indent=2, ensure_ascii=False)
                
                logger.debug(f"Saved documentation section: {section.id}")
                
            except Exception as e:
                logger.error(f"Failed to save documentation section {section.id}: {e}")
        
        # Update search index
        self.update_search_index(section)
    
    def get_section(self, section_id: str) -> Optional[DocumentSection]:
        """Get a specific documentation section"""
        return self.sections.get(section_id)
    
    def get_sections_by_category(self, category: str) -> List[DocumentSection]:
        """Get all sections in a category"""
        section_ids = self.categories.get(category, [])
        return [self.sections[section_id] for section_id in section_ids if section_id in self.sections]
    
    def get_all_categories(self) -> List[str]:
        """Get all documentation categories"""
        return list(self.categories.keys())
    
    def search_documentation(self, query: str, max_results: int = 10) -> List[DocumentSection]:
        """Search documentation content"""
        query_words = query.lower().split()
        results = []
        
        for section in self.sections.values():
            score = 0
            content_lower = (section.title + ' ' + section.content).lower()
            
            # Calculate relevance score
            for word in query_words:
                # Title matches get higher score
                if word in section.title.lower():
                    score += 10
                
                # Content matches
                if word in content_lower:
                    score += content_lower.count(word)
                
                # Tag matches
                for tag in section.tags:
                    if word in tag.lower():
                        score += 5
            
            if score > 0:
                results.append((section, score))
        
        # Sort by score and return top results
        results.sort(key=lambda x: x[1], reverse=True)
        return [section for section, score in results[:max_results]]
    
    def build_search_index(self):
        """Build search index for faster searching"""
        self.search_index.clear()
        
        for section in self.sections.values():
            # Index title words
            for word in section.title.lower().split():
                if word not in self.search_index:
                    self.search_index[word] = []
                if section.id not in self.search_index[word]:
                    self.search_index[word].append(section.id)
            
            # Index content words (first 100 significant words)
            content_words = re.findall(r'\b[a-zA-Z]{3,}\b', section.content.lower())
            for word in content_words[:100]:  # Limit to avoid huge indices
                if word not in self.search_index:
                    self.search_index[word] = []
                if section.id not in self.search_index[word]:
                    self.search_index[word].append(section.id)
            
            # Index tags
            for tag in section.tags:
                for word in tag.lower().split():
                    if word not in self.search_index:
                        self.search_index[word] = []
                    if section.id not in self.search_index[word]:
                        self.search_index[word].append(section.id)
    
    def update_search_index(self, section: DocumentSection):
        """Update search index for a specific section"""
        # Remove old entries
        for word_list in self.search_index.values():
            if section.id in word_list:
                word_list.remove(section.id)
        
        # Add new entries
        for word in section.title.lower().split():
            if word not in self.search_index:
                self.search_index[word] = []
            if section.id not in self.search_index[word]:
                self.search_index[word].append(section.id)
    
    def render_section_html(self, section_id: str) -> Optional[str]:
        """Render section as HTML"""
        section = self.get_section(section_id)
        if not section:
            return None
        
        try:
            # Convert markdown to HTML
            md = markdown.Markdown(extensions=['extra', 'codehilite'])
            html_content = md.convert(section.content)
            
            # Create full HTML page
            html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{section.title} - BLNCS Documentation</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; line-height: 1.6; margin: 40px; }}
        h1, h2, h3 {{ color: #333; }}
        code {{ background: #f4f4f4; padding: 2px 4px; border-radius: 3px; }}
        pre {{ background: #f4f4f4; padding: 10px; border-radius: 5px; overflow-x: auto; }}
        .meta {{ color: #666; font-size: 0.9em; margin-bottom: 20px; }}
        .tags {{ margin-top: 20px; }}
        .tag {{ background: #007acc; color: white; padding: 2px 8px; border-radius: 12px; margin-right: 5px; font-size: 0.8em; }}
    </style>
</head>
<body>
    <div class="meta">
        Category: {section.category} | Difficulty: {section.difficulty} | Last updated: {section.last_updated}
    </div>
    <h1>{section.title}</h1>
    {html_content}
    <div class="tags">
        Tags: {' '.join(f'<span class="tag">{tag}</span>' for tag in section.tags)}
    </div>
</body>
</html>
"""
            return html
            
        except Exception as e:
            logger.error(f"Failed to render section {section_id} as HTML: {e}")
            return None
    
    def export_documentation(self, output_dir: str, format: str = 'html'):
        """Export all documentation to specified format"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        if format == 'html':
            # Export as HTML
            for section in self.sections.values():
                html_content = self.render_section_html(section.id)
                if html_content:
                    html_file = output_path / f"{section.id}.html"
                    with open(html_file, 'w', encoding='utf-8') as f:
                        f.write(html_content)
            
            # Create index page
            self._create_html_index(output_path)
            
        elif format == 'markdown':
            # Export as markdown
            for section in self.sections.values():
                md_file = output_path / f"{section.id}.md"
                with open(md_file, 'w', encoding='utf-8') as f:
                    f.write(f"# {section.title}\n\n")
                    f.write(f"**Category**: {section.category}  \n")
                    f.write(f"**Difficulty**: {section.difficulty}  \n")
                    f.write(f"**Tags**: {', '.join(section.tags)}  \n")
                    f.write(f"**Last Updated**: {section.last_updated}\n\n")
                    f.write(section.content)
        
        logger.info(f"Documentation exported to {output_path} in {format} format")
    
    def _create_html_index(self, output_path: Path):
        """Create HTML index page"""
        index_html = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>BLNCS Documentation</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 40px; }
        .category { margin-bottom: 30px; }
        .section-link { display: block; margin: 5px 0; text-decoration: none; color: #007acc; }
        .section-link:hover { text-decoration: underline; }
        .difficulty { font-size: 0.8em; color: #666; margin-left: 10px; }
    </style>
</head>
<body>
    <h1>BLNCS Documentation</h1>
    <p>Welcome to the BLNCS documentation. Choose a section to get started:</p>
"""
        
        for category, section_ids in self.categories.items():
            index_html += f'    <div class="category">\n'
            index_html += f'        <h2>{category.replace("_", " ").title()}</h2>\n'
            
            for section_id in section_ids:
                section = self.sections.get(section_id)
                if section:
                    index_html += f'        <a href="{section_id}.html" class="section-link">'
                    index_html += f'{section.title}'
                    index_html += f'<span class="difficulty">({section.difficulty})</span></a>\n'
            
            index_html += '    </div>\n'
        
        index_html += """
</body>
</html>
"""
        
        with open(output_path / 'index.html', 'w', encoding='utf-8') as f:
            f.write(index_html)


# Global documentation manager instance
_documentation_manager = None
_documentation_manager_lock = Lock()


def get_documentation_manager() -> DocumentationManager:
    """Get global documentation manager instance"""
    global _documentation_manager
    
    if _documentation_manager is None:
        with _documentation_manager_lock:
            if _documentation_manager is None:
                _documentation_manager = DocumentationManager()
    
    return _documentation_manager


if __name__ == "__main__":
    # Test documentation manager
    import tempfile
    
    with tempfile.TemporaryDirectory() as temp_dir:
        doc_manager = DocumentationManager(temp_dir)
        
        print("Documentation Manager Test")
        print("=" * 40)
        
        # Test documentation loading
        sections = list(doc_manager.sections.keys())
        print(f"Loaded sections: {len(sections)}")
        
        # Test categories
        categories = doc_manager.get_all_categories()
        print(f"Categories: {categories}")
        
        # Test search
        results = doc_manager.search_documentation("lightning channel")
        print(f"Search results for 'lightning channel': {len(results)}")
        for result in results[:3]:
            print(f"  - {result.title} ({result.category})")
        
        # Test HTML export
        export_dir = Path(temp_dir) / "export"
        doc_manager.export_documentation(str(export_dir), format='html')
        print(f"Exported documentation to {export_dir}")
        
        print("Documentation manager test completed")