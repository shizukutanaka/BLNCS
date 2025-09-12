#!/usr/bin/env python3
"""
BLNCS API Documentation Generator
Interactive documentation and examples for API endpoints.
"""

import json
from typing import Dict, Any, List
from datetime import datetime

class APIDocumentationGenerator:
    """Generate comprehensive API documentation"""
    
    def __init__(self):
        self.examples = {}
        self.tutorials = {}
        self._load_examples()
        self._load_tutorials()
    
    def _load_examples(self):
        """Load API usage examples"""
        self.examples = {
            "authentication": {
                "title": "Authentication Examples",
                "description": "How to authenticate with the BLNCS API",
                "examples": [
                    {
                        "name": "Using API Key Header",
                        "description": "Authenticate using X-API-Key header",
                        "code": """curl -H "X-API-Key: your-api-key" \\
     -H "Content-Type: application/json" \\
     https://api.blncs.org/api/v1/backup/items"""
                    },
                    {
                        "name": "Using Bearer Token",
                        "description": "Authenticate using Authorization Bearer header",
                        "code": """curl -H "Authorization: Bearer your-api-key" \\
     -H "Content-Type: application/json" \\
     https://api.blncs.org/api/v1/backup/items"""
                    },
                    {
                        "name": "Query Parameter",
                        "description": "Authenticate using query parameter (not recommended for production)",
                        "code": """curl "https://api.blncs.org/api/v1/backup/items?api_key=your-api-key" """
                    }
                ]
            },
            "backup_operations": {
                "title": "Backup Operations",
                "description": "Common backup management operations",
                "examples": [
                    {
                        "name": "Create Backup Item",
                        "description": "Configure a new item for backup",
                        "code": """curl -X POST \\
  -H "X-API-Key: your-api-key" \\
  -H "Content-Type: application/json" \\
  -d '{
    "name": "Lightning Node Data",
    "source_path": "/home/lightning/.lnd",
    "backup_type": "incremental",
    "priority": 8,
    "enabled": true,
    "encryption": true,
    "compression": true
  }' \\
  https://api.blncs.org/api/v1/backup/items"""
                    },
                    {
                        "name": "Start Backup",
                        "description": "Execute backup for specific items",
                        "code": """curl -X POST \\
  -H "X-API-Key: your-api-key" \\
  -H "Content-Type: application/json" \\
  -d '{
    "backup_name": "Daily Lightning Backup",
    "backup_type": "incremental",
    "items": ["lightning-node", "channel-db"],
    "encryption": true,
    "compression": true
  }' \\
  https://api.blncs.org/api/v1/backup/create"""
                    },
                    {
                        "name": "Validate Backup",
                        "description": "Verify backup integrity",
                        "code": """curl -X POST \\
  -H "X-API-Key: your-api-key" \\
  -H "Content-Type: application/json" \\
  -d '{"backup_id": "backup_20240101_120000"}' \\
  https://api.blncs.org/api/v1/backup/validate"""
                    }
                ]
            },
            "scheduling": {
                "title": "Backup Scheduling",
                "description": "Automated backup scheduling examples",
                "examples": [
                    {
                        "name": "Daily Schedule",
                        "description": "Schedule daily backups at 2:00 AM",
                        "code": """curl -X POST \\
  -H "X-API-Key: your-api-key" \\
  -H "Content-Type: application/json" \\
  -d '{
    "name": "Daily Lightning Backup",
    "backup_items": ["lightning-node", "channel-db"],
    "schedule_type": "daily",
    "schedule_config": {"hour": 2, "minute": 0},
    "backup_type": "incremental",
    "retention_days": 30,
    "enabled": true
  }' \\
  https://api.blncs.org/api/v1/scheduler/schedules"""
                    },
                    {
                        "name": "Weekly Schedule",
                        "description": "Schedule weekly full backups on Sundays",
                        "code": """curl -X POST \\
  -H "X-API-Key: your-api-key" \\
  -H "Content-Type: application/json" \\
  -d '{
    "name": "Weekly Full Backup",
    "backup_items": ["lightning-node", "channel-db", "wallet-data"],
    "schedule_type": "weekly",
    "schedule_config": {"day_of_week": 0, "hour": 1, "minute": 0},
    "backup_type": "full",
    "retention_days": 90,
    "enabled": true
  }' \\
  https://api.blncs.org/api/v1/scheduler/schedules"""
                    }
                ]
            },
            "recovery": {
                "title": "Recovery Operations",
                "description": "Data recovery and restoration examples",
                "examples": [
                    {
                        "name": "List Available Backups",
                        "description": "Get list of backups available for recovery",
                        "code": """curl -H "X-API-Key: your-api-key" \\
  https://api.blncs.org/api/v1/recovery/backups"""
                    },
                    {
                        "name": "Execute Recovery",
                        "description": "Restore data from backup",
                        "code": """curl -X POST \\
  -H "X-API-Key: your-api-key" \\
  -H "Content-Type: application/json" \\
  -d '{
    "backup_id": "backup_20240101_120000",
    "target_directory": "/home/lightning/recovery",
    "overwrite_existing": false,
    "verify_integrity": true
  }' \\
  https://api.blncs.org/api/v1/recovery/execute"""
                    }
                ]
            },
            "monitoring": {
                "title": "System Monitoring",
                "description": "Monitor system health and performance",
                "examples": [
                    {
                        "name": "Get System Metrics",
                        "description": "Retrieve comprehensive system metrics",
                        "code": """curl -H "X-API-Key: your-api-key" \\
  https://api.blncs.org/api/v1/monitoring/metrics"""
                    },
                    {
                        "name": "Health Check",
                        "description": "Check system health status",
                        "code": """curl -H "X-API-Key: your-api-key" \\
  https://api.blncs.org/api/v1/monitoring/health"""
                    }
                ]
            },
            "python_client": {
                "title": "Python Client Examples",
                "description": "Using the API with Python requests library",
                "examples": [
                    {
                        "name": "Python Client Setup",
                        "description": "Basic Python client for BLNCS API",
                        "code": """import requests
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
print(f"Backup started: {backup_result['data']['operation_id']}")"""
                    }
                ]
            }
        }
    
    def _load_tutorials(self):
        """Load step-by-step tutorials"""
        self.tutorials = {
            "getting_started": {
                "title": "Getting Started with BLNCS API",
                "description": "Complete guide to setting up and using the BLNCS API",
                "steps": [
                    {
                        "step": 1,
                        "title": "Generate API Key",
                        "description": "First, generate an API key with appropriate permissions",
                        "code": """curl -X POST \\
  -H "X-API-Key: admin-key" \\
  -H "Content-Type: application/json" \\
  -d '{
    "name": "My Application",
    "permissions": ["read", "write"]
  }' \\
  https://api.blncs.org/api/v1/auth/generate-key"""
                    },
                    {
                        "step": 2,
                        "title": "Test Authentication",
                        "description": "Verify your API key works",
                        "code": """curl -H "X-API-Key: your-new-api-key" \\
  https://api.blncs.org/health"""
                    },
                    {
                        "step": 3,
                        "title": "Configure Backup Item",
                        "description": "Set up your first backup item",
                        "code": """curl -X POST \\
  -H "X-API-Key: your-new-api-key" \\
  -H "Content-Type: application/json" \\
  -d '{
    "name": "Lightning Node Data",
    "source_path": "/home/lightning/.lnd",
    "backup_type": "incremental",
    "enabled": true,
    "encryption": true
  }' \\
  https://api.blncs.org/api/v1/backup/items"""
                    },
                    {
                        "step": 4,
                        "title": "Create Backup Schedule",
                        "description": "Automate backups with a schedule",
                        "code": """curl -X POST \\
  -H "X-API-Key: your-new-api-key" \\
  -H "Content-Type: application/json" \\
  -d '{
    "name": "Daily Backup",
    "backup_items": ["your-backup-item-id"],
    "schedule_type": "daily",
    "schedule_config": {"hour": 2, "minute": 0},
    "backup_type": "incremental",
    "enabled": true
  }' \\
  https://api.blncs.org/api/v1/scheduler/schedules"""
                    },
                    {
                        "step": 5,
                        "title": "Monitor System",
                        "description": "Check system health and metrics",
                        "code": """# Check health
curl -H "X-API-Key: your-new-api-key" \\
  https://api.blncs.org/api/v1/monitoring/health

# Get metrics  
curl -H "X-API-Key: your-new-api-key" \\
  https://api.blncs.org/api/v1/monitoring/metrics"""
                    }
                ]
            },
            "disaster_recovery": {
                "title": "Disaster Recovery Setup",
                "description": "Set up comprehensive disaster recovery with BLNCS",
                "steps": [
                    {
                        "step": 1,
                        "title": "Configure Multiple Storage Backends",
                        "description": "Set up redundant storage for maximum safety",
                        "code": """# Local storage
curl -X POST -H "X-API-Key: your-api-key" \\
  -d '{
    "name": "Local Storage",
    "storage_type": "local",
    "config": {"path": "/backup/local"},
    "priority": 1,
    "enabled": true
  }' \\
  https://api.blncs.org/api/v1/storage/backends

# S3 storage  
curl -X POST -H "X-API-Key: your-api-key" \\
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
  }' \\
  https://api.blncs.org/api/v1/storage/backends"""
                    },
                    {
                        "step": 2,
                        "title": "Create Critical Data Backups",
                        "description": "Define backup items for all critical data",
                        "code": """# Lightning node data
curl -X POST -H "X-API-Key: your-api-key" \\
  -d '{
    "name": "Lightning Node",
    "source_path": "/home/lightning/.lnd",
    "backup_type": "full",
    "priority": 10,
    "encryption": true,
    "compression": true
  }' \\
  https://api.blncs.org/api/v1/backup/items

# Channel database
curl -X POST -H "X-API-Key: your-api-key" \\
  -d '{
    "name": "Channel Database", 
    "source_path": "/home/lightning/.lnd/data/graph/mainnet/channel.db",
    "backup_type": "full",
    "priority": 10,
    "encryption": true
  }' \\
  https://api.blncs.org/api/v1/backup/items"""
                    },
                    {
                        "step": 3,
                        "title": "Set Up Frequent Backups",
                        "description": "Create multiple backup schedules for different frequencies",
                        "code": """# Hourly critical backups
curl -X POST -H "X-API-Key: your-api-key" \\
  -d '{
    "name": "Hourly Critical",
    "backup_items": ["lightning-node-id", "channel-db-id"],
    "schedule_type": "hourly",
    "schedule_config": {"minute": 0},
    "backup_type": "incremental",
    "retention_days": 7
  }' \\
  https://api.blncs.org/api/v1/scheduler/schedules

# Weekly full backups
curl -X POST -H "X-API-Key: your-api-key" \\
  -d '{
    "name": "Weekly Full Backup",
    "backup_items": ["all-backup-items"],
    "schedule_type": "weekly", 
    "schedule_config": {"day_of_week": 0, "hour": 1, "minute": 0},
    "backup_type": "full",
    "retention_days": 90
  }' \\
  https://api.blncs.org/api/v1/scheduler/schedules"""
                    }
                ]
            }
        }
    
    def generate_markdown_docs(self) -> str:
        """Generate complete API documentation in Markdown format"""
        
        markdown = """# BLNCS API Documentation

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

"""

        # Add examples section
        markdown += "\n## API Examples\n\n"
        
        for category_key, category in self.examples.items():
            markdown += f"### {category['title']}\n\n"
            markdown += f"{category['description']}\n\n"
            
            for example in category['examples']:
                markdown += f"#### {example['name']}\n\n"
                markdown += f"{example['description']}\n\n"
                markdown += f"```bash\n{example['code']}\n```\n\n"

        # Add tutorials section
        markdown += "\n## Tutorials\n\n"
        
        for tutorial_key, tutorial in self.tutorials.items():
            markdown += f"### {tutorial['title']}\n\n"
            markdown += f"{tutorial['description']}\n\n"
            
            for step in tutorial['steps']:
                markdown += f"#### Step {step['step']}: {step['title']}\n\n"
                markdown += f"{step['description']}\n\n"
                markdown += f"```bash\n{step['code']}\n```\n\n"

        # Add endpoint reference
        markdown += """## Endpoint Reference

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
Detailed health status of all components

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
"""

        return markdown
    
    def generate_postman_collection(self) -> Dict[str, Any]:
        """Generate Postman collection for API testing"""
        
        collection = {
            "info": {
                "name": "BLNCS API",
                "description": "Bitcoin Lightning Network Control System API",
                "version": "2.0.0",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "auth": {
                "type": "apikey",
                "apikey": [
                    {"key": "key", "value": "X-API-Key"},
                    {"key": "value", "value": "{{api_key}}"},
                    {"key": "in", "value": "header"}
                ]
            },
            "variable": [
                {"key": "base_url", "value": "https://api.blncs.org"},
                {"key": "api_key", "value": "your-api-key-here"}
            ],
            "item": [
                {
                    "name": "Authentication",
                    "item": [
                        {
                            "name": "Generate API Key",
                            "request": {
                                "method": "POST",
                                "header": [{"key": "Content-Type", "value": "application/json"}],
                                "body": {
                                    "mode": "raw",
                                    "raw": json.dumps({"name": "Test Key", "permissions": ["read", "write"]})
                                },
                                "url": "{{base_url}}/api/v1/auth/generate-key"
                            }
                        },
                        {
                            "name": "Get Auth Stats",
                            "request": {
                                "method": "GET",
                                "url": "{{base_url}}/api/v1/auth/stats"
                            }
                        }
                    ]
                },
                {
                    "name": "System",
                    "item": [
                        {
                            "name": "Health Check",
                            "request": {
                                "method": "GET",
                                "auth": {"type": "noauth"},
                                "url": "{{base_url}}/health"
                            }
                        },
                        {
                            "name": "API Info",
                            "request": {
                                "method": "GET",
                                "url": "{{base_url}}/api/v1"
                            }
                        }
                    ]
                },
                {
                    "name": "Backup Management",
                    "item": [
                        {
                            "name": "List Backup Items",
                            "request": {
                                "method": "GET",
                                "url": "{{base_url}}/api/v1/backup/items"
                            }
                        },
                        {
                            "name": "Create Backup Item",
                            "request": {
                                "method": "POST",
                                "header": [{"key": "Content-Type", "value": "application/json"}],
                                "body": {
                                    "mode": "raw",
                                    "raw": json.dumps({
                                        "name": "Lightning Node Data",
                                        "source_path": "/home/lightning/.lnd",
                                        "backup_type": "incremental",
                                        "priority": 8,
                                        "enabled": True,
                                        "encryption": True
                                    })
                                },
                                "url": "{{base_url}}/api/v1/backup/items"
                            }
                        },
                        {
                            "name": "Create Backup",
                            "request": {
                                "method": "POST",
                                "header": [{"key": "Content-Type", "value": "application/json"}],
                                "body": {
                                    "mode": "raw",
                                    "raw": json.dumps({
                                        "backup_name": "Manual Backup",
                                        "backup_type": "full",
                                        "items": ["lightning-node"],
                                        "encryption": True,
                                        "compression": True
                                    })
                                },
                                "url": "{{base_url}}/api/v1/backup/create"
                            }
                        }
                    ]
                },
                {
                    "name": "Recovery",
                    "item": [
                        {
                            "name": "List Available Backups",
                            "request": {
                                "method": "GET",
                                "url": "{{base_url}}/api/v1/recovery/backups"
                            }
                        },
                        {
                            "name": "Execute Recovery",
                            "request": {
                                "method": "POST",
                                "header": [{"key": "Content-Type", "value": "application/json"}],
                                "body": {
                                    "mode": "raw",
                                    "raw": json.dumps({
                                        "backup_id": "backup_20240101_120000",
                                        "target_directory": "/home/lightning/recovery",
                                        "verify_integrity": True
                                    })
                                },
                                "url": "{{base_url}}/api/v1/recovery/execute"
                            }
                        }
                    ]
                },
                {
                    "name": "Monitoring",
                    "item": [
                        {
                            "name": "System Metrics",
                            "request": {
                                "method": "GET",
                                "url": "{{base_url}}/api/v1/monitoring/metrics"
                            }
                        },
                        {
                            "name": "Health Status",
                            "request": {
                                "method": "GET",
                                "url": "{{base_url}}/api/v1/monitoring/health"
                            }
                        }
                    ]
                }
            ]
        }
        
        return collection
    
    def get_example_responses(self) -> Dict[str, Any]:
        """Get example API responses for documentation"""
        
        return {
            "success_response": {
                "success": True,
                "data": {"id": "backup_123", "status": "completed"},
                "message": "Backup created successfully",
                "timestamp": datetime.now().isoformat(),
                "metadata": {"duration_seconds": 45.2}
            },
            "error_response": {
                "success": False,
                "error": {
                    "message": "Backup item not found",
                    "code": "NOT_FOUND"
                },
                "timestamp": datetime.now().isoformat()
            },
            "validation_error": {
                "success": False,
                "error": {
                    "message": "Validation failed",
                    "code": "VALIDATION_ERROR"
                },
                "data": {
                    "validation_errors": {
                        "name": {
                            "message": "Name is required",
                            "code": "REQUIRED"
                        },
                        "source_path": {
                            "message": "Source path must be at least 1 character",
                            "code": "MIN_LENGTH"
                        }
                    }
                },
                "timestamp": datetime.now().isoformat()
            }
        }