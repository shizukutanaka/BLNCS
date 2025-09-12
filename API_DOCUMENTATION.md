# BLNCS API Documentation

## Overview

The Bitcoin Lightning Network Control System (BLNCS) API provides comprehensive REST endpoints for managing Lightning node backups, recovery, scheduling, and system monitoring.

## Base URL

- Development: `http://localhost:8080`
- Production: `https://api.blncs.org`

## API Version

Current version: **2.0.0**

All endpoints are prefixed with `/api/v1/` unless otherwise noted.

## Authentication

The BLNCS API uses API keys for authentication. Include your API key in requests using one of these methods:

### Recommended: Header Authentication
```bash
X-API-Key: your-api-key
```

### Alternative: Bearer Token
```bash
Authorization: Bearer your-api-key  
```

### Not Recommended: Query Parameter
```bash
?api_key=your-api-key
```

## Rate Limiting

API requests are rate limited to prevent abuse:

- **Default Limit**: 100 requests per minute
- **Headers**: Rate limit information is included in response headers:
  - `X-RateLimit-Limit`: Request limit per window
  - `X-RateLimit-Remaining`: Remaining requests in current window  
  - `X-RateLimit-Reset`: Window reset time (Unix timestamp)

When rate limits are exceeded, the API returns HTTP 429 with retry information.

## Response Format

All API responses follow a consistent JSON structure:

### Success Response
```json
{
  "success": true,
  "data": { /* response data */ },
  "message": "Operation completed successfully",
  "timestamp": "2023-01-01T00:00:00Z",
  "metadata": { /* additional information */ }
}
```

### Error Response  
```json
{
  "success": false,
  "error": {
    "message": "Error description",
    "code": "ERROR_CODE"
  },
  "timestamp": "2023-01-01T00:00:00Z"
}
```

## HTTP Status Codes

- `200 OK`: Request successful
- `201 Created`: Resource created successfully
- `202 Accepted`: Request accepted for processing
- `400 Bad Request`: Invalid request data
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `422 Unprocessable Entity`: Validation failed
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error

## API Examples

### Authentication Examples

How to authenticate with the BLNCS API

#### Using API Key Header

Authenticate using X-API-Key header

```bash
curl -H "X-API-Key: your-api-key" \
     -H "Content-Type: application/json" \
     https://api.blncs.org/api/v1/backup/items
```

#### Using Bearer Token

Authenticate using Authorization Bearer header

```bash
curl -H "Authorization: Bearer your-api-key" \
     -H "Content-Type: application/json" \
     https://api.blncs.org/api/v1/backup/items
```

#### Query Parameter

Authenticate using query parameter (not recommended for production)

```bash
curl "https://api.blncs.org/api/v1/backup/items?api_key=your-api-key" 
```

### Backup Operations

Common backup management operations

#### Create Backup Item

Configure a new item for backup

```bash
curl -X POST \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Lightning Node Data",
    "source_path": "/home/lightning/.lnd",
    "backup_type": "incremental",
    "priority": 8,
    "enabled": true,
    "encryption": true,
    "compression": true
  }' \
  https://api.blncs.org/api/v1/backup/items
```

#### Start Backup

Execute backup for specific items

```bash
curl -X POST \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "backup_name": "Daily Lightning Backup",
    "backup_type": "incremental",
    "items": ["lightning-node", "channel-db"],
    "encryption": true,
    "compression": true
  }' \
  https://api.blncs.org/api/v1/backup/create
```

#### Validate Backup

Verify backup integrity

```bash
curl -X POST \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"backup_id": "backup_20240101_120000"}' \
  https://api.blncs.org/api/v1/backup/validate
```

### Backup Scheduling

Automated backup scheduling examples

#### Daily Schedule

Schedule daily backups at 2:00 AM

```bash
curl -X POST \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Daily Lightning Backup",
    "backup_items": ["lightning-node", "channel-db"],
    "schedule_type": "daily",
    "schedule_config": {"hour": 2, "minute": 0},
    "backup_type": "incremental",
    "retention_days": 30,
    "enabled": true
  }' \
  https://api.blncs.org/api/v1/scheduler/schedules
```

#### Weekly Schedule

Schedule weekly full backups on Sundays

```bash
curl -X POST \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Weekly Full Backup",
    "backup_items": ["lightning-node", "channel-db", "wallet-data"],
    "schedule_type": "weekly",
    "schedule_config": {"day_of_week": 0, "hour": 1, "minute": 0},
    "backup_type": "full",
    "retention_days": 90,
    "enabled": true
  }' \
  https://api.blncs.org/api/v1/scheduler/schedules
```

### Recovery Operations

Data recovery and restoration examples

#### List Available Backups

Get list of backups available for recovery

```bash
curl -H "X-API-Key: your-api-key" \
  https://api.blncs.org/api/v1/recovery/backups
```

#### Execute Recovery

Restore data from backup

```bash
curl -X POST \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "backup_id": "backup_20240101_120000",
    "target_directory": "/home/lightning/recovery",
    "overwrite_existing": false,
    "verify_integrity": true
  }' \
  https://api.blncs.org/api/v1/recovery/execute
```

### System Monitoring

Monitor system health and performance

#### Get System Metrics

Retrieve comprehensive system metrics

```bash
curl -H "X-API-Key: your-api-key" \
  https://api.blncs.org/api/v1/monitoring/metrics
```

#### Health Check

Check system health status

```bash
curl -H "X-API-Key: your-api-key" \
  https://api.blncs.org/api/v1/monitoring/health
```

### Python Client Examples

Using the API with Python requests library

#### Python Client Setup

Basic Python client for BLNCS API

```bash
import requests
import json
from typing import Dict, Any, Optional

class BLNCSClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'X-API-Key': api_key,
            'Content-Type': 'application/json'
        })
    
    def _request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{endpoint}"
        response = self.session.request(method, url, json=data)
        response.raise_for_status()
        return response.json()
    
    def create_backup_item(self, name: str, source_path: str, **kwargs) -> Dict[str, Any]:
        data = {'name': name, 'source_path': source_path, **kwargs}
        return self._request('POST', '/api/v1/backup/items', data)
    
    def start_backup(self, backup_name: str, items: list, **kwargs) -> Dict[str, Any]:
        data = {'backup_name': backup_name, 'items': items, **kwargs}
        return self._request('POST', '/api/v1/backup/create', data)
    
    def get_metrics(self) -> Dict[str, Any]:
        return self._request('GET', '/api/v1/monitoring/metrics')

# Usage example
client = BLNCSClient('https://api.blncs.org', 'your-api-key')

# Create backup item
result = client.create_backup_item(
    name="Lightning Node",
    source_path="/home/lightning/.lnd",
    backup_type="incremental",
    encryption=True
)
print(f"Backup item created: {result['data']['id']}")

# Start backup
backup_result = client.start_backup(
    backup_name="Manual Backup",
    items=["lightning-node"],
    encryption=True,
    compression=True
)
print(f"Backup started: {backup_result['data']['operation_id']}")
```

## Tutorials

### Getting Started with BLNCS API

Complete guide to setting up and using the BLNCS API

#### Step 1: Generate API Key

First, generate an API key with appropriate permissions

```bash
curl -X POST \
  -H "X-API-Key: admin-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Application",
    "permissions": ["read", "write"]
  }' \
  https://api.blncs.org/api/v1/auth/generate-key
```

#### Step 2: Test Authentication

Verify your API key works

```bash
curl -H "X-API-Key: your-new-api-key" \
  https://api.blncs.org/health
```

#### Step 3: Configure Backup Item

Set up your first backup item

```bash
curl -X POST \
  -H "X-API-Key: your-new-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Lightning Node Data",
    "source_path": "/home/lightning/.lnd",
    "backup_type": "incremental",
    "enabled": true,
    "encryption": true
  }' \
  https://api.blncs.org/api/v1/backup/items
```

#### Step 4: Create Backup Schedule

Automate backups with a schedule

```bash
curl -X POST \
  -H "X-API-Key: your-new-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Daily Backup",
    "backup_items": ["your-backup-item-id"],
    "schedule_type": "daily",
    "schedule_config": {"hour": 2, "minute": 0},
    "backup_type": "incremental",
    "enabled": true
  }' \
  https://api.blncs.org/api/v1/scheduler/schedules
```

#### Step 5: Monitor System

Check system health and metrics

```bash
# Check health
curl -H "X-API-Key: your-new-api-key" \
  https://api.blncs.org/api/v1/monitoring/health

# Get metrics  
curl -H "X-API-Key: your-new-api-key" \
  https://api.blncs.org/api/v1/monitoring/metrics
```

### Disaster Recovery Setup

Set up comprehensive disaster recovery with BLNCS

#### Step 1: Configure Multiple Storage Backends

Set up redundant storage for maximum safety

```bash
# Local storage
curl -X POST -H "X-API-Key: your-api-key" \
  -d '{
    "name": "Local Storage",
    "storage_type": "local",
    "config": {"path": "/backup/local"},
    "priority": 1,
    "enabled": true
  }' \
  https://api.blncs.org/api/v1/storage/backends

# S3 storage  
curl -X POST -H "X-API-Key: your-api-key" \
  -d '{
    "name": "AWS S3",
    "storage_type": "s3",
    "config": {
      "bucket": "blncs-disaster-recovery",
      "region": "us-west-2"
    },
    "priority": 2,
    "enabled": true,
    "encryption_enabled": true
  }' \
  https://api.blncs.org/api/v1/storage/backends
```

#### Step 2: Create Critical Data Backups

Define backup items for all critical data

```bash
# Lightning node data
curl -X POST -H "X-API-Key: your-api-key" \
  -d '{
    "name": "Lightning Node",
    "source_path": "/home/lightning/.lnd",
    "backup_type": "full",
    "priority": 10,
    "encryption": true,
    "compression": true
  }' \
  https://api.blncs.org/api/v1/backup/items

# Channel database
curl -X POST -H "X-API-Key: your-api-key" \
  -d '{
    "name": "Channel Database", 
    "source_path": "/home/lightning/.lnd/data/graph/mainnet/channel.db",
    "backup_type": "full",
    "priority": 10,
    "encryption": true
  }' \
  https://api.blncs.org/api/v1/backup/items
```

#### Step 3: Set Up Frequent Backups

Create multiple backup schedules for different frequencies

```bash
# Hourly critical backups
curl -X POST -H "X-API-Key: your-api-key" \
  -d '{
    "name": "Hourly Critical",
    "backup_items": ["lightning-node-id", "channel-db-id"],
    "schedule_type": "hourly",
    "schedule_config": {"minute": 0},
    "backup_type": "incremental",
    "retention_days": 7
  }' \
  https://api.blncs.org/api/v1/scheduler/schedules

# Weekly full backups
curl -X POST -H "X-API-Key: your-api-key" \
  -d '{
    "name": "Weekly Full Backup",
    "backup_items": ["all-backup-items"],
    "schedule_type": "weekly", 
    "schedule_config": {"day_of_week": 0, "hour": 1, "minute": 0},
    "backup_type": "full",
    "retention_days": 90
  }' \
  https://api.blncs.org/api/v1/scheduler/schedules
```

## Endpoint Reference

### System Endpoints

#### GET /health
Health check endpoint (no authentication required)

#### GET /api/v1
API version and status information

### Backup Management

#### GET /api/v1/backup/items
List all backup items with pagination

#### POST /api/v1/backup/items  
Create new backup item

#### POST /api/v1/backup/create
Execute backup creation (async operation)

#### POST /api/v1/backup/validate
Validate backup integrity

#### GET /api/v1/backup/{backup_id}
Get detailed backup information

### Recovery Operations

#### GET /api/v1/recovery/backups
List available backups for recovery

#### POST /api/v1/recovery/execute
Execute recovery operation (async)

### Scheduler Management

#### GET /api/v1/scheduler/schedules
List all backup schedules

#### POST /api/v1/scheduler/schedules
Create new backup schedule

#### DELETE /api/v1/scheduler/{schedule_id}
Delete backup schedule

#### POST /api/v1/scheduler/start
Start scheduler service

#### POST /api/v1/scheduler/stop
Stop scheduler service

### Monitoring

#### GET /api/v1/monitoring/metrics
Get comprehensive system metrics

#### GET /api/v1/monitoring/health
Detailed health status of all system components

### Configuration

#### GET /api/v1/config
Get system configuration (admin only)

### Storage Management

#### GET /api/v1/storage/backends
List storage backends

#### POST /api/v1/storage/backends
Configure new storage backend

### Authentication

#### POST /api/v1/auth/generate-key
Generate new API key (admin only)

#### GET /api/v1/auth/stats
Get authentication statistics (admin only)

## Interactive Documentation

Visit `/api/v1/docs/swagger` for interactive Swagger UI documentation where you can test endpoints directly.

The OpenAPI specification is available at `/api/v1/docs`.

## Error Handling

The API provides detailed error information to help with troubleshooting:

### Validation Errors (422)
```json
{
  "success": false,
  "error": {
    "message": "Validation failed",
    "code": "VALIDATION_ERROR"
  },
  "data": {
    "validation_errors": {
      "field_name": {
        "message": "Field is required",
        "code": "REQUIRED"
      }
    }
  }
}
```

### Common Error Codes
- `UNAUTHORIZED`: Invalid or missing API key
- `FORBIDDEN`: Insufficient permissions  
- `VALIDATION_ERROR`: Request data validation failed
- `NOT_FOUND`: Requested resource not found
- `RATE_LIMIT_EXCEEDED`: Too many requests
- `INTERNAL_ERROR`: Server error

## Support

For support and questions:
- Documentation: `/api/v1/docs/swagger`
- Email: support@blncs.org
- Issues: GitHub repository

## Changelog

### Version 2.0.0
- Complete API redesign with REST principles
- Comprehensive authentication and authorization
- Rate limiting and security improvements
- Standardized response format
- Enhanced error handling and validation
- Interactive documentation with Swagger UI
- Comprehensive monitoring and metrics endpoints