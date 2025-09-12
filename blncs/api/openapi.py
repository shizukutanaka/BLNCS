#!/usr/bin/env python3
"""
BLNCS API OpenAPI Documentation Generator
Comprehensive OpenAPI/Swagger documentation for all API endpoints.
"""

from flask import Flask, jsonify
from typing import Dict, Any
import json

OPENAPI_SPEC = {
    "openapi": "3.0.3",
    "info": {
        "title": "BLNCS API",
        "description": "Bitcoin Lightning Network Control System REST API",
        "version": "2.0.0",
        "contact": {
            "name": "BLNCS Support",
            "email": "support@blncs.org"
        },
        "license": {
            "name": "MIT",
            "url": "https://opensource.org/licenses/MIT"
        }
    },
    "servers": [
        {
            "url": "http://localhost:8080",
            "description": "Development server"
        },
        {
            "url": "https://api.blncs.org",
            "description": "Production server"
        }
    ],
    "security": [
        {
            "ApiKeyAuth": []
        },
        {
            "BearerAuth": []
        }
    ],
    "components": {
        "securitySchemes": {
            "ApiKeyAuth": {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key"
            },
            "BearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT"
            }
        },
        "schemas": {
            "APIResponse": {
                "type": "object",
                "properties": {
                    "success": {
                        "type": "boolean",
                        "description": "Whether the operation was successful"
                    },
                    "data": {
                        "description": "Response data"
                    },
                    "message": {
                        "type": "string",
                        "description": "Human-readable message"
                    },
                    "timestamp": {
                        "type": "string",
                        "format": "date-time",
                        "description": "Response timestamp"
                    },
                    "error": {
                        "$ref": "#/components/schemas/ErrorObject"
                    },
                    "metadata": {
                        "type": "object",
                        "description": "Additional response metadata"
                    }
                },
                "required": ["success", "timestamp"]
            },
            "ErrorObject": {
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "Error message"
                    },
                    "code": {
                        "type": "string",
                        "description": "Error code"
                    }
                },
                "required": ["message"]
            },
            "BackupItem": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Backup item name",
                        "minLength": 1,
                        "maxLength": 100
                    },
                    "source_path": {
                        "type": "string",
                        "description": "Source path to backup"
                    },
                    "backup_type": {
                        "type": "string",
                        "enum": ["full", "incremental", "differential"],
                        "description": "Type of backup"
                    },
                    "priority": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 10,
                        "description": "Backup priority"
                    },
                    "enabled": {
                        "type": "boolean",
                        "description": "Whether backup is enabled"
                    },
                    "encryption": {
                        "type": "boolean",
                        "description": "Enable encryption"
                    },
                    "compression": {
                        "type": "boolean",
                        "description": "Enable compression"
                    }
                },
                "required": ["name", "source_path"]
            },
            "BackupSchedule": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Schedule name",
                        "minLength": 1,
                        "maxLength": 100
                    },
                    "backup_items": {
                        "type": "array",
                        "items": {
                            "type": "string"
                        },
                        "description": "List of backup item IDs"
                    },
                    "schedule_type": {
                        "type": "string",
                        "enum": ["hourly", "daily", "weekly", "monthly"],
                        "description": "Schedule frequency"
                    },
                    "schedule_config": {
                        "type": "object",
                        "description": "Schedule configuration parameters"
                    },
                    "backup_type": {
                        "type": "string",
                        "enum": ["full", "incremental", "differential"],
                        "description": "Type of backup"
                    },
                    "retention_days": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 365,
                        "description": "Retention period in days"
                    },
                    "enabled": {
                        "type": "boolean",
                        "description": "Whether schedule is enabled"
                    }
                },
                "required": ["name", "backup_items", "schedule_type", "schedule_config"]
            },
            "RecoveryRequest": {
                "type": "object",
                "properties": {
                    "backup_id": {
                        "type": "string",
                        "description": "ID of backup to recover from"
                    },
                    "target_directory": {
                        "type": "string",
                        "description": "Target directory for recovery"
                    },
                    "items": {
                        "type": "array",
                        "items": {
                            "type": "string"
                        },
                        "description": "Specific items to recover"
                    },
                    "overwrite_existing": {
                        "type": "boolean",
                        "description": "Whether to overwrite existing files"
                    },
                    "verify_integrity": {
                        "type": "boolean",
                        "description": "Verify integrity during recovery"
                    }
                },
                "required": ["backup_id"]
            },
            "StorageBackend": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Storage backend name",
                        "minLength": 1,
                        "maxLength": 100
                    },
                    "storage_type": {
                        "type": "string",
                        "enum": ["local", "s3", "sftp", "azure", "gcs"],
                        "description": "Type of storage backend"
                    },
                    "config": {
                        "type": "object",
                        "description": "Storage backend configuration"
                    },
                    "enabled": {
                        "type": "boolean",
                        "description": "Whether backend is enabled"
                    },
                    "priority": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 10,
                        "description": "Backend priority"
                    },
                    "encryption_enabled": {
                        "type": "boolean",
                        "description": "Enable encryption for this backend"
                    }
                },
                "required": ["name", "storage_type", "config"]
            },
            "SystemMetrics": {
                "type": "object",
                "properties": {
                    "system": {
                        "type": "object",
                        "properties": {
                            "cpu_percent": {"type": "number"},
                            "memory_percent": {"type": "number"},
                            "disk_usage": {"type": "number"}
                        }
                    },
                    "backup": {
                        "type": "object",
                        "properties": {
                            "total_backups": {"type": "integer"},
                            "successful_backups": {"type": "integer"},
                            "failed_backups": {"type": "integer"},
                            "last_backup": {"type": "string", "format": "date-time"}
                        }
                    },
                    "lightning": {
                        "type": "object",
                        "properties": {
                            "node_status": {"type": "string"},
                            "channel_count": {"type": "integer"},
                            "balance": {"type": "number"}
                        }
                    }
                }
            },
            "ValidationError": {
                "type": "object",
                "properties": {
                    "success": {
                        "type": "boolean",
                        "example": false
                    },
                    "error": {
                        "type": "object",
                        "properties": {
                            "message": {
                                "type": "string",
                                "example": "Validation failed"
                            },
                            "code": {
                                "type": "string",
                                "example": "VALIDATION_ERROR"
                            }
                        }
                    },
                    "data": {
                        "type": "object",
                        "properties": {
                            "validation_errors": {
                                "type": "object",
                                "additionalProperties": {
                                    "type": "object",
                                    "properties": {
                                        "message": {"type": "string"},
                                        "code": {"type": "string"}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "responses": {
            "Success": {
                "description": "Successful operation",
                "content": {
                    "application/json": {
                        "schema": {
                            "$ref": "#/components/schemas/APIResponse"
                        }
                    }
                }
            },
            "ValidationError": {
                "description": "Validation error",
                "content": {
                    "application/json": {
                        "schema": {
                            "$ref": "#/components/schemas/ValidationError"
                        }
                    }
                }
            },
            "Unauthorized": {
                "description": "Authentication required",
                "content": {
                    "application/json": {
                        "schema": {
                            "$ref": "#/components/schemas/APIResponse"
                        },
                        "example": {
                            "success": false,
                            "error": {
                                "message": "Invalid or missing API key",
                                "code": "UNAUTHORIZED"
                            },
                            "timestamp": "2023-01-01T00:00:00Z"
                        }
                    }
                }
            },
            "Forbidden": {
                "description": "Insufficient permissions",
                "content": {
                    "application/json": {
                        "schema": {
                            "$ref": "#/components/schemas/APIResponse"
                        }
                    }
                }
            },
            "NotFound": {
                "description": "Resource not found",
                "content": {
                    "application/json": {
                        "schema": {
                            "$ref": "#/components/schemas/APIResponse"
                        }
                    }
                }
            },
            "RateLimited": {
                "description": "Rate limit exceeded",
                "content": {
                    "application/json": {
                        "schema": {
                            "$ref": "#/components/schemas/APIResponse"
                        }
                    }
                },
                "headers": {
                    "X-RateLimit-Limit": {
                        "description": "Request limit per window",
                        "schema": {"type": "integer"}
                    },
                    "X-RateLimit-Remaining": {
                        "description": "Remaining requests in window",
                        "schema": {"type": "integer"}
                    },
                    "X-RateLimit-Reset": {
                        "description": "Window reset time (Unix timestamp)",
                        "schema": {"type": "integer"}
                    }
                }
            }
        }
    },
    "paths": {
        "/health": {
            "get": {
                "tags": ["System"],
                "summary": "Health check",
                "description": "Check API health status",
                "security": [],
                "responses": {
                    "200": {
                        "description": "Service is healthy",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/APIResponse"
                                },
                                "example": {
                                    "success": true,
                                    "data": {
                                        "status": "healthy",
                                        "version": "2.0.0",
                                        "checks": {
                                            "database": "ok",
                                            "storage": "ok"
                                        }
                                    },
                                    "timestamp": "2023-01-01T00:00:00Z"
                                }
                            }
                        }
                    },
                    "503": {
                        "description": "Service is unhealthy"
                    }
                }
            }
        },
        "/api/v1": {
            "get": {
                "tags": ["System"],
                "summary": "API information",
                "description": "Get API version and status information",
                "security": [],
                "responses": {
                    "200": {"$ref": "#/components/responses/Success"}
                }
            }
        },
        "/api/v1/backup/items": {
            "get": {
                "tags": ["Backup"],
                "summary": "List backup items",
                "description": "Get list of all configured backup items",
                "parameters": [
                    {
                        "name": "page",
                        "in": "query",
                        "schema": {"type": "integer", "minimum": 1, "default": 1}
                    },
                    {
                        "name": "per_page",
                        "in": "query",
                        "schema": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}
                    }
                ],
                "responses": {
                    "200": {"$ref": "#/components/responses/Success"},
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "429": {"$ref": "#/components/responses/RateLimited"}
                }
            },
            "post": {
                "tags": ["Backup"],
                "summary": "Create backup item",
                "description": "Create a new backup item configuration",
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/BackupItem"},
                            "example": {
                                "name": "Lightning Node Data",
                                "source_path": "/home/lightning/.lnd",
                                "backup_type": "full",
                                "priority": 8,
                                "enabled": true,
                                "encryption": true,
                                "compression": true
                            }
                        }
                    }
                },
                "responses": {
                    "201": {"$ref": "#/components/responses/Success"},
                    "400": {"$ref": "#/components/responses/ValidationError"},
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "403": {"$ref": "#/components/responses/Forbidden"},
                    "429": {"$ref": "#/components/responses/RateLimited"}
                }
            }
        },
        "/api/v1/backup/create": {
            "post": {
                "tags": ["Backup"],
                "summary": "Create backup",
                "description": "Execute backup creation for specified items",
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "backup_name": {"type": "string", "maxLength": 200},
                                    "backup_type": {
                                        "type": "string",
                                        "enum": ["full", "incremental", "differential"]
                                    },
                                    "items": {"type": "array", "items": {"type": "string"}},
                                    "encryption": {"type": "boolean"},
                                    "compression": {"type": "boolean"}
                                }
                            }
                        }
                    }
                },
                "responses": {
                    "202": {
                        "description": "Backup started",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/APIResponse"},
                                "example": {
                                    "success": true,
                                    "data": {
                                        "operation_id": "backup_123456",
                                        "operation": "backup creation",
                                        "status": "started",
                                        "estimated_duration_seconds": 300
                                    },
                                    "message": "Backup creation started",
                                    "timestamp": "2023-01-01T00:00:00Z"
                                }
                            }
                        }
                    },
                    "400": {"$ref": "#/components/responses/ValidationError"},
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "403": {"$ref": "#/components/responses/Forbidden"},
                    "429": {"$ref": "#/components/responses/RateLimited"}
                }
            }
        },
        "/api/v1/backup/validate": {
            "post": {
                "tags": ["Backup"],
                "summary": "Validate backup",
                "description": "Validate integrity of existing backup",
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "backup_id": {"type": "string"}
                                },
                                "required": ["backup_id"]
                            }
                        }
                    }
                },
                "responses": {
                    "200": {"$ref": "#/components/responses/Success"},
                    "400": {"$ref": "#/components/responses/ValidationError"},
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "403": {"$ref": "#/components/responses/Forbidden"},
                    "404": {"$ref": "#/components/responses/NotFound"},
                    "429": {"$ref": "#/components/responses/RateLimited"}
                }
            }
        },
        "/api/v1/backup/{backup_id}": {
            "get": {
                "tags": ["Backup"],
                "summary": "Get backup details",
                "description": "Get detailed information about a specific backup",
                "parameters": [
                    {
                        "name": "backup_id",
                        "in": "path",
                        "required": true,
                        "schema": {"type": "string"}
                    }
                ],
                "responses": {
                    "200": {"$ref": "#/components/responses/Success"},
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "404": {"$ref": "#/components/responses/NotFound"},
                    "429": {"$ref": "#/components/responses/RateLimited"}
                }
            }
        },
        "/api/v1/recovery/backups": {
            "get": {
                "tags": ["Recovery"],
                "summary": "List available backups",
                "description": "Get list of backups available for recovery",
                "responses": {
                    "200": {"$ref": "#/components/responses/Success"},
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "429": {"$ref": "#/components/responses/RateLimited"}
                }
            }
        },
        "/api/v1/recovery/execute": {
            "post": {
                "tags": ["Recovery"],
                "summary": "Execute recovery",
                "description": "Execute recovery operation from backup",
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/RecoveryRequest"},
                            "example": {
                                "backup_id": "backup_20230101_120000",
                                "target_directory": "/home/lightning/recovery",
                                "overwrite_existing": false,
                                "verify_integrity": true
                            }
                        }
                    }
                },
                "responses": {
                    "202": {
                        "description": "Recovery started",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/APIResponse"}
                            }
                        }
                    },
                    "400": {"$ref": "#/components/responses/ValidationError"},
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "403": {"$ref": "#/components/responses/Forbidden"},
                    "404": {"$ref": "#/components/responses/NotFound"},
                    "429": {"$ref": "#/components/responses/RateLimited"}
                }
            }
        },
        "/api/v1/scheduler/schedules": {
            "get": {
                "tags": ["Scheduler"],
                "summary": "List schedules",
                "description": "Get list of backup schedules",
                "responses": {
                    "200": {"$ref": "#/components/responses/Success"},
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "429": {"$ref": "#/components/responses/RateLimited"}
                }
            },
            "post": {
                "tags": ["Scheduler"],
                "summary": "Create schedule",
                "description": "Create new backup schedule",
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/BackupSchedule"},
                            "example": {
                                "name": "Daily Lightning Backup",
                                "backup_items": ["item_1", "item_2"],
                                "schedule_type": "daily",
                                "schedule_config": {"hour": 2, "minute": 0},
                                "backup_type": "incremental",
                                "retention_days": 30,
                                "enabled": true
                            }
                        }
                    }
                },
                "responses": {
                    "201": {"$ref": "#/components/responses/Success"},
                    "400": {"$ref": "#/components/responses/ValidationError"},
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "403": {"$ref": "#/components/responses/Forbidden"},
                    "429": {"$ref": "#/components/responses/RateLimited"}
                }
            }
        },
        "/api/v1/scheduler/{schedule_id}": {
            "delete": {
                "tags": ["Scheduler"],
                "summary": "Delete schedule",
                "description": "Delete backup schedule",
                "parameters": [
                    {
                        "name": "schedule_id",
                        "in": "path",
                        "required": true,
                        "schema": {"type": "string"}
                    }
                ],
                "responses": {
                    "200": {"$ref": "#/components/responses/Success"},
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "403": {"$ref": "#/components/responses/Forbidden"},
                    "404": {"$ref": "#/components/responses/NotFound"},
                    "429": {"$ref": "#/components/responses/RateLimited"}
                }
            }
        },
        "/api/v1/scheduler/start": {
            "post": {
                "tags": ["Scheduler"],
                "summary": "Start scheduler",
                "description": "Start the backup scheduler service",
                "responses": {
                    "200": {"$ref": "#/components/responses/Success"},
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "403": {"$ref": "#/components/responses/Forbidden"},
                    "429": {"$ref": "#/components/responses/RateLimited"}
                }
            }
        },
        "/api/v1/scheduler/stop": {
            "post": {
                "tags": ["Scheduler"],
                "summary": "Stop scheduler",
                "description": "Stop the backup scheduler service",
                "responses": {
                    "200": {"$ref": "#/components/responses/Success"},
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "403": {"$ref": "#/components/responses/Forbidden"},
                    "429": {"$ref": "#/components/responses/RateLimited"}
                }
            }
        },
        "/api/v1/monitoring/metrics": {
            "get": {
                "tags": ["Monitoring"],
                "summary": "System metrics",
                "description": "Get comprehensive system metrics",
                "responses": {
                    "200": {
                        "description": "System metrics data",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "allOf": [
                                        {"$ref": "#/components/schemas/APIResponse"},
                                        {
                                            "properties": {
                                                "data": {"$ref": "#/components/schemas/SystemMetrics"}
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    },
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "429": {"$ref": "#/components/responses/RateLimited"}
                }
            }
        },
        "/api/v1/monitoring/health": {
            "get": {
                "tags": ["Monitoring"],
                "summary": "Health status",
                "description": "Get detailed health status of all system components",
                "responses": {
                    "200": {"$ref": "#/components/responses/Success"},
                    "503": {
                        "description": "One or more components are unhealthy",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/APIResponse"}
                            }
                        }
                    },
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "429": {"$ref": "#/components/responses/RateLimited"}
                }
            }
        },
        "/api/v1/config": {
            "get": {
                "tags": ["Configuration"],
                "summary": "Get system configuration",
                "description": "Get current system configuration (sensitive values masked)",
                "responses": {
                    "200": {"$ref": "#/components/responses/Success"},
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "403": {"$ref": "#/components/responses/Forbidden"},
                    "429": {"$ref": "#/components/responses/RateLimited"}
                }
            }
        },
        "/api/v1/storage/backends": {
            "get": {
                "tags": ["Storage"],
                "summary": "List storage backends",
                "description": "Get list of configured storage backends",
                "responses": {
                    "200": {"$ref": "#/components/responses/Success"},
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "429": {"$ref": "#/components/responses/RateLimited"}
                }
            },
            "post": {
                "tags": ["Storage"],
                "summary": "Create storage backend",
                "description": "Configure new storage backend",
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/StorageBackend"},
                            "example": {
                                "name": "S3 Production",
                                "storage_type": "s3",
                                "config": {
                                    "bucket": "blncs-backups",
                                    "region": "us-west-2",
                                    "access_key_id": "AKIA...",
                                    "secret_access_key": "***masked***"
                                },
                                "enabled": true,
                                "priority": 5,
                                "encryption_enabled": true
                            }
                        }
                    }
                },
                "responses": {
                    "201": {"$ref": "#/components/responses/Success"},
                    "400": {"$ref": "#/components/responses/ValidationError"},
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "403": {"$ref": "#/components/responses/Forbidden"},
                    "429": {"$ref": "#/components/responses/RateLimited"}
                }
            }
        },
        "/api/v1/auth/generate-key": {
            "post": {
                "tags": ["Authentication"],
                "summary": "Generate API key",
                "description": "Generate new API key with specified permissions",
                "security": [{"ApiKeyAuth": []}, {"BearerAuth": []}],
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string", "description": "Key name"},
                                    "permissions": {
                                        "type": "array",
                                        "items": {
                                            "type": "string",
                                            "enum": ["read", "write", "admin"]
                                        },
                                        "description": "List of permissions"
                                    }
                                },
                                "required": ["name"]
                            }
                        }
                    }
                },
                "responses": {
                    "201": {
                        "description": "API key generated",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "allOf": [
                                        {"$ref": "#/components/schemas/APIResponse"},
                                        {
                                            "properties": {
                                                "data": {
                                                    "type": "object",
                                                    "properties": {
                                                        "api_key": {"type": "string"},
                                                        "name": {"type": "string"},
                                                        "permissions": {"type": "array", "items": {"type": "string"}},
                                                        "created_at": {"type": "string", "format": "date-time"}
                                                    }
                                                }
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    },
                    "400": {"$ref": "#/components/responses/ValidationError"},
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "403": {"$ref": "#/components/responses/Forbidden"},
                    "429": {"$ref": "#/components/responses/RateLimited"}
                }
            }
        },
        "/api/v1/auth/stats": {
            "get": {
                "tags": ["Authentication"],
                "summary": "Authentication statistics",
                "description": "Get authentication and API key usage statistics",
                "responses": {
                    "200": {
                        "description": "Authentication statistics",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "allOf": [
                                        {"$ref": "#/components/schemas/APIResponse"},
                                        {
                                            "properties": {
                                                "data": {
                                                    "type": "object",
                                                    "properties": {
                                                        "total_keys": {"type": "integer"},
                                                        "active_keys": {"type": "integer"},
                                                        "usage_today": {"type": "integer"}
                                                    }
                                                }
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    },
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "403": {"$ref": "#/components/responses/Forbidden"},
                    "429": {"$ref": "#/components/responses/RateLimited"}
                }
            }
        }
    },
    "tags": [
        {"name": "System", "description": "System health and information"},
        {"name": "Backup", "description": "Backup management operations"},
        {"name": "Recovery", "description": "Recovery operations"},
        {"name": "Scheduler", "description": "Backup scheduler management"},
        {"name": "Monitoring", "description": "System monitoring and metrics"},
        {"name": "Configuration", "description": "System configuration"},
        {"name": "Storage", "description": "Storage backend management"},
        {"name": "Authentication", "description": "API authentication and key management"}
    ]
}

def setup_docs_endpoints(app: Flask):
    """Setup OpenAPI documentation endpoints"""
    
    @app.route('/api/v1/docs', methods=['GET'])
    def api_docs():
        """Serve OpenAPI specification"""
        return jsonify(OPENAPI_SPEC)
    
    @app.route('/api/v1/docs/swagger', methods=['GET'])
    def swagger_ui():
        """Serve Swagger UI HTML"""
        return '''
<!DOCTYPE html>
<html>
<head>
    <title>BLNCS API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui.css" />
    <style>
        html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
        *, *:before, *:after { box-sizing: inherit; }
        body { margin: 0; background: #fafafa; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-bundle.js"></script>
    <script>
        window.onload = function() {
            SwaggerUIBundle({
                url: '/api/v1/docs',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIBundle.presets.standalone
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout"
            });
        }
    </script>
</body>
</html>
        '''

def get_openapi_spec() -> Dict[str, Any]:
    """Get the OpenAPI specification"""
    return OPENAPI_SPEC