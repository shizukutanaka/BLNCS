# BLNCS API reference (deprecated legacy content)

**Status:** Archived. The maintained REST endpoints are documented in `docs/API_REFERENCE_UNIFIED.md`.
**See also:** `docs/QUICK_START.md`, `docs/DEPLOYMENT_GUIDE_UNIFIED.md`
---

## Legacy enterprise API reference (archived)

**Version:** 2.0.0 Enterprise Edition
**Security:** Enterprise-grade with national-level compliance
**Authentication:** Multi-factor with role-based access control

## Overview

BLNCS provides a comprehensive RESTful API for enterprise Lightning Network management with government-grade security and commercial reliability.

## Base Configuration

### Enterprise Endpoints
```
Production: http://localhost:3000
Staging: http://localhost:3000
```

### Authentication

#### API Key Authentication
```bash
curl -H "Authorization: Bearer YOUR_ENTERPRISE_API_KEY" \
     -H "X-API-Version: 2.0" \
     http://localhost:3000/status
```

#### Multi-Factor Authentication
```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
     -H "X-MFA-Token: YOUR_MFA_TOKEN" \
     -H "X-Session-ID: YOUR_SESSION_ID" \
     http://localhost:3000/secure/operations
```

### Request Headers
- **Content-Type**: `application/json; charset=utf-8`
- **Accept**: `application/json`
- **X-API-Version**: `2.0`
- **Authorization**: `Bearer YOUR_API_KEY`
- **X-Request-ID**: Unique request identifier for tracking

### Response Format
```json
{
  "success": true,
  "data": {},
  "metadata": {
    "timestamp": "2025-09-23T10:00:00Z",
    "request_id": "req_123456789",
    "processing_time_ms": 45,
    "api_version": "2.0.0"
  },
  "pagination": {
    "page": 1,
    "per_page": 100,
    "total": 250,
    "total_pages": 3
  }
}
```

### Error Response Format
```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request parameters",
    "details": {
      "field": "amount",
      "reason": "Must be positive number"
    }
  },
  "metadata": {
    "timestamp": "2025-09-23T10:00:00Z",
    "request_id": "req_123456789"
  }
}
```

## System Management API

### System Status

#### GET /status
Get comprehensive system status and health information.

**Response:**
```json
{
  "success": true,
  "data": {
    "status": "operational",
    "environment": "production",
    "version": "2.0.0-enterprise",
    "uptime_seconds": 86400,
    "system_health": {
      "overall": "optimal",
      "services": {
        "lightning_manager": "operational",
        "payment_processor": "operational",
        "security_manager": "operational",
        "monitoring_service": "operational"
      }
    },
    "performance_metrics": {
      "response_time_avg_ms": 45,
      "throughput_rps": 1250,
      "error_rate_percent": 0.02,
      "uptime_percentage": 99.98
    },
    "security_status": {
      "threat_level": "low",
      "active_protections": 15,
      "incidents_24h": 0,
      "compliance_score": 100
    }
  }
}
```

#### GET /health
Basic health check endpoint for load balancers.

**Response:**
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "timestamp": "2025-09-23T10:00:00Z"
  }
}
```

### System Configuration

#### GET /config
Get system configuration (admin only).

**Authentication:** Admin role required

**Response:**
```json
{
  "success": true,
  "data": {
    "lightning": {
      "implementation": "lnd",
      "network": "mainnet",
      "max_channels": 1000,
      "auto_pilot": true
    },
    "security": {
      "encryption_enabled": true,
      "mfa_required": true,
      "session_timeout": 1800,
      "audit_logging": true
    },
    "performance": {
      "cache_enabled": true,
      "optimization_level": "enterprise",
      "monitoring_interval": 5
    }
  }
}
```

#### PUT /config
Update system configuration (super admin only).

**Authentication:** Super admin role required

**Request:**
```json
{
  "lightning": {
    "max_channels": 1500,
    "auto_pilot": false
  },
  "security": {
    "session_timeout": 3600
  }
}
```

## Lightning Network API

### Node Information

#### GET /lightning/info
Get Lightning Network node information.

**Response:**
```json
{
  "success": true,
  "data": {
    "public_key": "02a1b2c3d4e5f6...",
    "alias": "BLNCS-Enterprise-Node",
    "version": "0.17.0-beta",
    "block_height": 750000,
    "block_hash": "0000000000000000...",
    "synced_to_chain": true,
    "synced_to_graph": true,
    "num_active_channels": 25,
    "num_pending_channels": 2,
    "num_peers": 28,
    "total_balance_sat": 100000000,
    "confirmed_balance_sat": 95000000,
    "unconfirmed_balance_sat": 5000000
  }
}
```

### Channel Management

#### GET /lightning/channels
List all Lightning Network channels.

**Query Parameters:**
- `status` (optional): Filter by status (active, pending, inactive)
- `limit` (optional): Number of results (default: 100, max: 500)
- `offset` (optional): Pagination offset

**Response:**
```json
{
  "success": true,
  "data": {
    "channels": [
      {
        "channel_id": "123456789012345678",
        "remote_pubkey": "03a1b2c3d4e5f6...",
        "channel_point": "txid:0",
        "capacity": 1000000,
        "local_balance": 600000,
        "remote_balance": 400000,
        "commit_fee": 253,
        "fee_per_kw": 253,
        "unsettled_balance": 0,
        "total_satoshis_sent": 5000000,
        "total_satoshis_received": 3000000,
        "num_updates": 150,
        "pending_htlcs": [],
        "csv_delay": 144,
        "private": false,
        "initiator": true,
        "chan_status_flags": "ChanStatusDefault",
        "local_chan_reserve_sat": 10000,
        "remote_chan_reserve_sat": 10000,
        "static_remote_key": true,
        "commitment_type": "ANCHORS",
        "lifetime": 86400,
        "uptime": 86000,
        "close_address": "",
        "push_amount_sat": 0,
        "thaw_height": 0,
        "local_constraints": {
          "csv_delay": 144,
          "chan_reserve_sat": 10000,
          "dust_limit_sat": 354,
          "max_pending_amt_msat": 990000000,
          "min_htlc_msat": 1,
          "max_accepted_htlcs": 483
        },
        "remote_constraints": {
          "csv_delay": 144,
          "chan_reserve_sat": 10000,
          "dust_limit_sat": 354,
          "max_pending_amt_msat": 990000000,
          "min_htlc_msat": 1,
          "max_accepted_htlcs": 483
        }
      }
    ]
  }
}
```

#### POST /lightning/channels/open
Open a new Lightning Network channel.

**Authentication:** Operator role or higher required

**Request:**
```json
{
  "node_pubkey": "03a1b2c3d4e5f6...",
  "local_funding_amount": 1000000,
  "push_sat": 0,
  "target_conf": 6,
  "sat_per_byte": 12,
  "private": false,
  "min_htlc_msat": 1,
  "remote_csv_delay": 144,
  "min_confs": 1,
  "spend_unconfirmed": false
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "funding_txid": "a1b2c3d4e5f6...",
    "output_index": 0,
    "pending_chan_id": "123456789012345678"
  }
}
```

### Payment Operations

#### POST /lightning/payments/send
Send a Lightning Network payment.

**Authentication:** Operator role or higher required

**Request:**
```json
{
  "payment_request": "lnbc1m1p0...",
  "amount_msat": 100000000,
  "fee_limit_msat": 1000000,
  "timeout_seconds": 60,
  "allow_self_payment": false,
  "dest_features": [],
  "payment_hash": "a1b2c3d4e5f6...",
  "final_cltv_delta": 40
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "payment_hash": "a1b2c3d4e5f6...",
    "payment_preimage": "b2c3d4e5f6a1...",
    "payment_route": {
      "total_time_lock": 750144,
      "total_fees": 1000,
      "total_amt": 100001000,
      "hops": [
        {
          "chan_id": "123456789012345678",
          "chan_capacity": 1000000,
          "amt_to_forward": 100000000,
          "fee": 1000,
          "expiry": 750144,
          "amt_to_forward_msat": 100000000000,
          "fee_msat": 1000000,
          "pub_key": "03a1b2c3d4e5f6...",
          "tlv_payload": true,
          "mpp_record": null,
          "amp_record": null,
          "custom_records": {}
        }
      ]
    },
    "payment_error": "",
    "payment_request": "lnbc1m1p0...",
    "status": "SUCCEEDED",
    "fee_sat": 1,
    "fee_msat": 1000,
    "value_sat": 100000,
    "value_msat": 100000000,
    "payment_index": 1,
    "failure_reason": "FAILURE_REASON_NONE"
  }
}
```

#### GET /lightning/payments
List payment history.

**Query Parameters:**
- `include_incomplete` (optional): Include incomplete payments
- `index_offset` (optional): Pagination offset
- `max_payments` (optional): Maximum results (default: 100)
- `reversed` (optional): Reverse chronological order

**Response:**
```json
{
  "success": true,
  "data": {
    "payments": [
      {
        "payment_hash": "a1b2c3d4e5f6...",
        "value": 100000,
        "creation_date": 1693747200,
        "fee": 1,
        "payment_preimage": "b2c3d4e5f6a1...",
        "value_sat": 100000,
        "value_msat": 100000000,
        "payment_request": "lnbc1m1p0...",
        "status": "SUCCEEDED",
        "fee_sat": 1,
        "fee_msat": 1000,
        "creation_time_ns": 1693747200000000000,
        "htlcs": [
          {
            "attempt_id": 1,
            "status": "SUCCEEDED",
            "route": {
              "total_time_lock": 750144,
              "total_fees": 1,
              "total_amt": 100001,
              "hops": []
            },
            "attempt_time_ns": 1693747200000000000,
            "resolve_time_ns": 1693747201000000000,
            "failure": null,
            "preimage": "b2c3d4e5f6a1..."
          }
        ],
        "payment_index": 1,
        "failure_reason": "FAILURE_REASON_NONE"
      }
    ],
    "first_index_offset": 0,
    "last_index_offset": 1
  }
}
```

### Invoice Management

#### POST /lightning/invoices
Create a new invoice.

**Authentication:** Operator role or higher required

**Request:**
```json
{
  "memo": "Payment for services",
  "value": 100000,
  "value_msat": 100000000,
  "description_hash": "",
  "expiry": 3600,
  "fallback_addr": "",
  "cltv_expiry": 40,
  "private": false,
  "is_amp": false
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "r_hash": "a1b2c3d4e5f6...",
    "payment_request": "lnbc1m1p0...",
    "add_index": 1,
    "payment_addr": "b2c3d4e5f6a1..."
  }
}
```

#### GET /lightning/invoices
List invoices.

**Query Parameters:**
- `pending_only` (optional): Show only pending invoices
- `index_offset` (optional): Pagination offset
- `num_max_invoices` (optional): Maximum results
- `reversed` (optional): Reverse chronological order

## Security API

### Security Status

#### GET /security/status
Get comprehensive security status.

**Authentication:** Security admin role required

**Response:**
```json
{
  "success": true,
  "data": {
    "overall_status": "secure",
    "threat_level": "low",
    "active_protections": {
      "firewall": true,
      "intrusion_detection": true,
      "rate_limiting": true,
      "encryption": true,
      "audit_logging": true
    },
    "security_metrics": {
      "blocked_attacks_24h": 15,
      "failed_login_attempts": 3,
      "security_incidents": 0,
      "compliance_score": 100
    },
    "recent_events": [
      {
        "timestamp": "2025-09-23T09:45:00Z",
        "event_type": "blocked_ip",
        "severity": "medium",
        "description": "Blocked suspicious IP after multiple failed attempts"
      }
    ]
  }
}
```

### Access Control

#### GET /security/users
List system users (admin only).

**Authentication:** Admin role required

**Response:**
```json
{
  "success": true,
  "data": {
    "users": [
      {
        "user_id": "user_123",
        "username": "admin",
        "email": "admin@company.com",
        "role": "super_admin",
        "status": "active",
        "last_login": "2025-09-23T08:00:00Z",
        "created_at": "2025-01-01T00:00:00Z",
        "mfa_enabled": true,
        "permissions": [
          "system_admin",
          "security_admin",
          "user_management",
          "financial_operations"
        ]
      }
    ]
  }
}
```

## Monitoring API

### Performance Metrics

#### GET /monitoring/metrics
Get real-time performance metrics.

**Response:**
```json
{
  "success": true,
  "data": {
    "timestamp": "2025-09-23T10:00:00Z",
    "system_metrics": {
      "cpu_usage_percent": 25.5,
      "memory_usage_percent": 45.2,
      "disk_usage_percent": 68.1,
      "network_throughput_mbps": 125.8
    },
    "application_metrics": {
      "active_connections": 150,
      "requests_per_second": 1250,
      "average_response_time_ms": 45,
      "error_rate_percent": 0.02
    },
    "lightning_metrics": {
      "active_channels": 25,
      "total_capacity_sat": 25000000,
      "routing_fee_revenue_sat": 5000,
      "successful_payments_24h": 1250
    }
  }
}
```

### Alerts

#### GET /monitoring/alerts
Get active alerts.

**Response:**
```json
{
  "success": true,
  "data": {
    "active_alerts": [
      {
        "alert_id": "alert_123",
        "severity": "medium",
        "title": "High Memory Usage",
        "description": "Memory usage has exceeded 80% threshold",
        "timestamp": "2025-09-23T09:30:00Z",
        "acknowledged": false,
        "category": "system_performance"
      }
    ],
    "alert_summary": {
      "total_active": 1,
      "critical": 0,
      "high": 0,
      "medium": 1,
      "low": 0
    }
  }
}
```

## Error Codes

### Authentication Errors
- `AUTH_001`: Invalid API key
- `AUTH_002`: Expired API key
- `AUTH_003`: MFA token required
- `AUTH_004`: Invalid MFA token
- `AUTH_005`: Insufficient privileges

### Validation Errors
- `VAL_001`: Missing required parameter
- `VAL_002`: Invalid parameter format
- `VAL_003`: Parameter out of range
- `VAL_004`: Invalid payment request
- `VAL_005`: Insufficient balance

### System Errors
- `SYS_001`: Internal server error
- `SYS_002`: Service unavailable
- `SYS_003`: Database connection error
- `SYS_004`: Lightning node connection error
- `SYS_005`: Rate limit exceeded

### Business Logic Errors
- `BIZ_001`: Channel already exists
- `BIZ_002`: Insufficient channel capacity
- `BIZ_003`: Payment timeout
- `BIZ_004`: Invoice already paid
- `BIZ_005`: Channel force close required

## Rate Limits

### Standard Limits
- **General API**: 1000 requests per minute per API key
- **Payment Operations**: 100 requests per minute per API key
- **Channel Operations**: 50 requests per minute per API key
- **Admin Operations**: 200 requests per minute per API key

### Enterprise Limits
Contact enterprise support for increased rate limits based on your use case.

## API Versioning

BLNCS uses semantic versioning for the API. Breaking changes will result in a new major version.

- Current Version: `2.0.0`
- Supported Versions: `2.0.x`, `1.9.x` (deprecated)
- Deprecation Notice: 6 months advance notice for version deprecations

## SDKs and Libraries

### Official SDKs
- **Node.js**: `npm install @blncs/sdk-nodejs`
- **Python**: `pip install blncs-sdk-python`
- **Go**: `go get github.com/blncs/blncs-go-sdk`
- **Java**: Maven/Gradle dependency available

### Community SDKs
- **PHP**: Available via Packagist
- **Ruby**: Available via RubyGems
- **C#**: Available via NuGet

## Support

### Enterprise Support
- **24/7 Technical Support**: enterprise-support@blncs.org
- **Security Issues**: security@blncs.com
- **API Questions**: api-support@blncs.org

### Documentation
- **API Documentation**: Built-in interactive documentation
- **Enterprise Guide**: Comprehensive enterprise deployment guide
- **Security Guide**: Security implementation best practices

---

**Last Updated:** September 23, 2025
**API Version:** 2.0.0 Enterprise Edition