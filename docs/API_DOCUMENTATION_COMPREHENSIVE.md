# BLNCS Commercial-Grade API Documentation

## Table of Contents

1. [Overview](#overview)
2. [Authentication & Authorization](#authentication--authorization)
3. [Core Lightning APIs](#core-lightning-apis)
4. [Payment Management](#payment-management)
5. [Channel Management](#channel-management)
6. [Monitoring & Metrics](#monitoring--metrics)
7. [Security & Encryption](#security--encryption)
8. [Caching & Performance](#caching--performance)
9. [Error Handling](#error-handling)
10. [Deployment & Infrastructure](#deployment--infrastructure)
11. [SDKs & Integration](#sdks--integration)
12. [Examples & Use Cases](#examples--use-cases)

---

## Overview

BLNCS (Bitcoin Lightning Network Control System) is a comprehensive, commercial-grade Lightning Network management platform. This API documentation covers all endpoints, authentication methods, data models, and integration patterns.

### Base URL
```
Production: http://localhost:3000
Staging:    http://localhost:3000
```

### API Versioning
- Current Version: v1
- Version Header: `Accept: application/vnd.blncs.v1+json`
- Backward Compatibility: Maintained for 12 months

### Rate Limiting
- Standard: 1000 requests/hour
- Premium: 10000 requests/hour
- Enterprise: Unlimited
- Headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`

---

## Authentication & Authorization

### JWT Authentication

All API requests require authentication via JWT tokens in the Authorization header:

```http
Authorization: Bearer <jwt_token>
```

### Obtaining Access Tokens

#### POST /auth/login
Authenticate user and obtain JWT tokens.

**Request:**
```json
{
  "username": "string",
  "password": "string",
  "mfa_token": "string",
  "ip_address": "string"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 3600,
  "token_type": "Bearer",
  "scope": ["read", "write", "admin"]
}
```

#### POST /auth/refresh
Refresh expired access token using refresh token.

**Request:**
```json
{
  "refresh_token": "string"
}
```

### Authorization Levels

| Level | Permissions | Use Case |
|-------|-------------|----------|
| `public` | Read-only public data | Public APIs |
| `authenticated` | Basic user operations | Standard users |
| `verified` | Enhanced operations | KYC verified users |
| `admin` | Administrative functions | System administrators |
| `system` | Internal system operations | Service accounts |

### Security Headers

Required security headers for all requests:

```http
X-Request-ID: uuid4
X-Correlation-ID: uuid4
User-Agent: YourApp/1.0
Content-Type: application/json
```

---

## Core Lightning APIs

### Node Information

#### GET /lightning/node/info
Get Lightning node information and status.

**Authentication:** Required
**Authorization:** `authenticated`

**Response:**
```json
{
  "public_key": "02a1b2c3d4...",
  "alias": "BLNCS-Node-01",
  "color": "#ff5722",
  "num_peers": 25,
  "num_active_channels": 12,
  "num_pending_channels": 2,
  "block_height": 750000,
  "synced_to_chain": true,
  "synced_to_graph": true,
  "version": "0.15.4-beta",
  "chains": [
    {
      "chain": "bitcoin",
      "network": "mainnet"
    }
  ],
  "uris": [
    "02a1b2c3d4...@lightning.blncs.com:9735"
  ],
  "features": {
    "data_loss_protect": {
      "is_required": true,
      "is_known": true
    },
    "payment_addr": {
      "is_required": true,
      "is_known": true
    }
  }
}
```

#### GET /lightning/node/balance
Get node balance information.

**Response:**
```json
{
  "total_balance": 50000000,
  "confirmed_balance": 48000000,
  "unconfirmed_balance": 2000000,
  "channel_balance": {
    "local_balance": 30000000,
    "remote_balance": 15000000,
    "pending_open_balance": 5000000
  },
  "wallet_balance": {
    "total_balance": 50000000,
    "confirmed_balance": 48000000,
    "unconfirmed_balance": 2000000
  }
}
```

### Peer Management

#### GET /lightning/peers
List connected peers.

**Query Parameters:**
- `limit` (int): Number of results (default: 50, max: 200)
- `offset` (int): Pagination offset
- `status` (string): Filter by status (`connected`, `disconnected`)

**Response:**
```json
{
  "peers": [
    {
      "pub_key": "03a1b2c3d4...",
      "address": "192.168.1.100:9735",
      "bytes_sent": 1024000,
      "bytes_recv": 2048000,
      "sat_sent": 10000,
      "sat_recv": 15000,
      "inbound": false,
      "ping_time": 50,
      "sync_type": "ACTIVE_SYNC",
      "features": {
        "data_loss_protect": true,
        "payment_addr": true
      }
    }
  ],
  "total_count": 25,
  "pagination": {
    "limit": 50,
    "offset": 0,
    "has_more": false
  }
}
```

#### POST /lightning/peers/connect
Connect to a Lightning node.

**Request:**
```json
{
  "pub_key": "03a1b2c3d4...",
  "host": "lightning.example.com:9735",
  "perm": true
}
```

#### DELETE /lightning/peers/{pub_key}
Disconnect from a peer.

---

## Payment Management

### Invoice Management

#### POST /lightning/invoices
Create a new invoice.

**Request:**
```json
{
  "memo": "Payment for services",
  "value": 100000,
  "expiry": 3600,
  "description_hash": "sha256_hash",
  "fallback_addr": "bc1q...",
  "cltv_expiry": 144,
  "route_hints": [
    {
      "hop_hints": [
        {
          "node_id": "03a1b2c3d4...",
          "chan_id": "123456789012345678",
          "fee_base_msat": 1000,
          "fee_proportional_millionths": 1,
          "cltv_expiry_delta": 40
        }
      ]
    }
  ],
  "private": false
}
```

**Response:**
```json
{
  "r_hash": "a1b2c3d4...",
  "payment_request": "lnbc1u1p...",
  "add_index": 123,
  "payment_addr": "02a1b2c3d4..."
}
```

#### GET /lightning/invoices
List invoices with filtering options.

**Query Parameters:**
- `pending_only` (bool): Show only pending invoices
- `index_offset` (int): Starting index
- `num_max_invoices` (int): Maximum number to return
- `reversed` (bool): Reverse chronological order

#### GET /lightning/invoices/{r_hash}
Get specific invoice details.

**Response:**
```json
{
  "memo": "Payment for services",
  "r_preimage": "preimage_hex",
  "r_hash": "hash_hex",
  "value": 100000,
  "value_msat": 100000000,
  "settled": true,
  "creation_date": 1634567890,
  "settle_date": 1634567950,
  "payment_request": "lnbc1u1p...",
  "description_hash": "sha256_hash",
  "expiry": 3600,
  "fallback_addr": "bc1q...",
  "cltv_expiry": 144,
  "route_hints": [],
  "private": false,
  "add_index": 123,
  "settle_index": 456,
  "amt_paid": 100000,
  "amt_paid_sat": 100000,
  "amt_paid_msat": 100000000,
  "state": "SETTLED",
  "htlcs": [
    {
      "chan_id": "123456789012345678",
      "htlc_index": 1,
      "amt_msat": 100000000,
      "accept_height": 750000,
      "accept_time": 1634567950,
      "resolve_time": 1634567955,
      "expiry_height": 750144,
      "state": "SETTLED"
    }
  ],
  "features": {},
  "is_keysend": false,
  "payment_addr": "02a1b2c3d4..."
}
```

### Payment Sending

#### POST /lightning/payments
Send a Lightning payment.

**Request:**
```json
{
  "payment_request": "lnbc1u1p...",
  "amt": 100000,
  "fee_limit": {
    "fixed": 1000,
    "percent": 1
  },
  "outgoing_chan_id": "123456789012345678",
  "last_hop_pubkey": "03a1b2c3d4...",
  "cltv_limit": 1000,
  "dest_custom_records": {
    "5482373484": "custom_data"
  },
  "allow_self_payment": false,
  "dest_features": [9, 15, 17]
}
```

**Response:**
```json
{
  "payment_hash": "a1b2c3d4...",
  "value": 100000,
  "creation_date": 1634567890,
  "fee": 100,
  "payment_preimage": "preimage_hex",
  "value_sat": 100000,
  "value_msat": 100000000,
  "payment_request": "lnbc1u1p...",
  "status": "SUCCEEDED",
  "fee_sat": 100,
  "fee_msat": 100000,
  "creation_time_ns": 1634567890000000000,
  "htlcs": [
    {
      "attempt_time_ns": 1634567890000000000,
      "resolve_time_ns": 1634567895000000000,
      "route": {
        "total_time_lock": 750144,
        "total_fees": 100,
        "total_amt": 100100,
        "hops": [
          {
            "chan_id": "123456789012345678",
            "chan_capacity": 5000000,
            "amt_to_forward": 100000,
            "fee": 100,
            "expiry": 750144,
            "amt_to_forward_msat": 100000000,
            "fee_msat": 100000,
            "pub_key": "03a1b2c3d4...",
            "tlv_payload": true,
            "mpp_record": {
              "payment_addr": "02a1b2c3d4...",
              "total_amt_msat": 100000000
            }
          }
        ]
      },
      "attempt_id": 1,
      "status": "SUCCEEDED",
      "preimage": "preimage_hex"
    }
  ],
  "payment_index": 789,
  "failure_reason": "FAILURE_REASON_NONE"
}
```

#### GET /lightning/payments
List payment history.

**Query Parameters:**
- `include_incomplete` (bool): Include incomplete payments
- `index_offset` (int): Starting index
- `max_payments` (int): Maximum number to return
- `reversed` (bool): Reverse chronological order

### Payment Streaming

#### GET /lightning/payments/stream
Server-sent events stream for real-time payment updates.

**Headers:**
```http
Accept: text/event-stream
Cache-Control: no-cache
```

**Response Stream:**
```
event: payment_sent
data: {"payment_hash": "...", "status": "SUCCEEDED", "fee": 100}

event: payment_received
data: {"r_hash": "...", "amt_paid": 100000, "settle_date": 1634567950}

event: invoice_created
data: {"r_hash": "...", "payment_request": "lnbc1u1p..."}
```

---

## Channel Management

### Channel Operations

#### POST /lightning/channels
Open a new channel.

**Request:**
```json
{
  "node_pubkey": "03a1b2c3d4...",
  "local_funding_amount": 1000000,
  "push_sat": 100000,
  "target_conf": 6,
  "sat_per_byte": 10,
  "private": false,
  "min_htlc_msat": 1000,
  "remote_csv_delay": 144,
  "min_confs": 1,
  "spend_unconfirmed": false,
  "close_address": "bc1q...",
  "funding_shim": {
    "chan_point_shim": {
      "amt": 1000000,
      "chan_point": {
        "funding_txid_bytes": "txid_bytes",
        "output_index": 0
      },
      "local_key": {
        "key_family": 6,
        "key_index": 0
      },
      "remote_key": "02a1b2c3d4...",
      "pending_chan_id": "pending_id",
      "thaw_height": 0
    }
  }
}
```

**Response:**
```json
{
  "funding_txid_bytes": "txid_bytes",
  "funding_txid_str": "abc123...",
  "output_index": 0,
  "pending_chan_id": "pending_id"
}
```

#### GET /lightning/channels
List channels.

**Query Parameters:**
- `active_only` (bool): Show only active channels
- `inactive_only` (bool): Show only inactive channels
- `public_only` (bool): Show only public channels
- `private_only` (bool): Show only private channels
- `peer` (string): Filter by peer public key

**Response:**
```json
{
  "channels": [
    {
      "active": true,
      "remote_pubkey": "03a1b2c3d4...",
      "channel_point": "abc123...:0",
      "chan_id": "123456789012345678",
      "capacity": 5000000,
      "local_balance": 2500000,
      "remote_balance": 2400000,
      "commit_fee": 9050,
      "commit_weight": 724,
      "fee_per_kw": 12500,
      "unsettled_balance": 0,
      "total_satoshis_sent": 1000000,
      "total_satoshis_received": 800000,
      "num_updates": 100,
      "pending_htlcs": [
        {
          "incoming": false,
          "amount": 50000,
          "hash_lock": "hash_hex",
          "expiration_height": 750144,
          "htlc_index": 1,
          "forwarding_channel": 0,
          "forwarding_htlc_index": 0
        }
      ],
      "csv_delay": 144,
      "private": false,
      "initiator": true,
      "chan_status_flags": "ChanStatusDefault",
      "local_chan_reserve_sat": 50000,
      "remote_chan_reserve_sat": 50000,
      "static_remote_key": false,
      "commitment_type": "ANCHORS",
      "lifetime": 86400,
      "uptime": 85000,
      "close_address": "bc1q...",
      "push_amount_sat": 100000,
      "thaw_height": 0,
      "local_constraints": {
        "csv_delay": 144,
        "chan_reserve_sat": 50000,
        "dust_limit_sat": 546,
        "max_pending_amt_msat": 4950000000,
        "min_htlc_msat": 1,
        "max_accepted_htlcs": 483
      },
      "remote_constraints": {
        "csv_delay": 144,
        "chan_reserve_sat": 50000,
        "dust_limit_sat": 546,
        "max_pending_amt_msat": 4950000000,
        "min_htlc_msat": 1,
        "max_accepted_htlcs": 483
      }
    }
  ]
}
```

#### DELETE /lightning/channels/{channel_point}
Close a channel.

**Query Parameters:**
- `force` (bool): Force close the channel
- `target_conf` (int): Target confirmation blocks
- `sat_per_byte` (int): Fee rate

**Request:**
```json
{
  "delivery_address": "bc1q..."
}
```

### Channel Balance Management

#### POST /lightning/channels/{chan_id}/rebalance
Rebalance channel using circular payments.

**Request:**
```json
{
  "target_local_balance": 2500000,
  "max_fee_rate": 1000,
  "timeout_seconds": 60
}
```

#### GET /lightning/channels/{chan_id}/fees
Get channel fee policy.

**Response:**
```json
{
  "base_fee_msat": 1000,
  "fee_rate": 1,
  "time_lock_delta": 40,
  "min_htlc": 1000,
  "max_htlc_msat": 4950000000
}
```

#### PUT /lightning/channels/{chan_id}/fees
Update channel fee policy.

**Request:**
```json
{
  "base_fee_msat": 1000,
  "fee_rate": 1,
  "time_lock_delta": 40,
  "min_htlc_msat": 1000,
  "max_htlc_msat": 4950000000
}
```

---

## Monitoring & Metrics

### System Metrics

#### GET /monitoring/metrics
Get comprehensive system metrics.

**Response:**
```json
{
  "timestamp": "2023-10-15T10:30:00Z",
  "system": {
    "cpu_usage": 45.2,
    "memory_usage": 67.8,
    "disk_usage": 23.4,
    "network_io": {
      "bytes_sent": 1024000,
      "bytes_received": 2048000
    }
  },
  "lightning": {
    "node_uptime": 86400,
    "channel_count": 25,
    "active_channels": 23,
    "pending_channels": 2,
    "total_capacity": 50000000,
    "total_balance": 30000000,
    "routing_revenue_24h": 1000,
    "payment_success_rate": 98.5
  },
  "performance": {
    "avg_response_time": 150,
    "requests_per_minute": 120,
    "error_rate": 0.5,
    "cache_hit_rate": 85.2
  }
}
```

#### GET /monitoring/health
Health check endpoint for load balancers.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2023-10-15T10:30:00Z",
  "version": "1.0.0",
  "checks": {
    "database": "healthy",
    "lightning_node": "healthy",
    "cache": "healthy",
    "external_apis": "healthy"
  },
  "uptime_seconds": 86400
}
```

#### GET /monitoring/alerts
Get active alerts.

**Response:**
```json
{
  "active_alerts": [
    {
      "id": "alert_123",
      "name": "high_memory_usage",
      "priority": "high",
      "message": "Memory usage is 89.5%",
      "triggered_at": "2023-10-15T10:25:00Z",
      "acknowledged": false
    }
  ],
  "alert_summary": {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 0
  }
}
```

### Performance Analytics

#### GET /analytics/payments
Payment analytics and statistics.

**Query Parameters:**
- `time_range` (string): `1h`, `24h`, `7d`, `30d`
- `group_by` (string): `hour`, `day`, `week`

**Response:**
```json
{
  "time_range": "24h",
  "total_payments": {
    "sent": 150,
    "received": 200,
    "volume_sent": 15000000,
    "volume_received": 20000000
  },
  "success_rates": {
    "outgoing": 98.5,
    "incoming": 99.2
  },
  "fees": {
    "total_paid": 1500,
    "total_earned": 800,
    "average_fee_rate": 0.001
  },
  "time_series": [
    {
      "timestamp": "2023-10-15T09:00:00Z",
      "payments_sent": 12,
      "payments_received": 15,
      "volume_sent": 1200000,
      "volume_received": 1500000,
      "fees_paid": 120,
      "fees_earned": 75
    }
  ]
}
```

---

## Security & Encryption

### Encryption Services

#### POST /security/encrypt
Encrypt sensitive data.

**Request:**
```json
{
  "data": "sensitive_information",
  "key_type": "data"
}
```

**Response:**
```json
{
  "encrypted_data": "base64_encrypted_string",
  "encryption_key_id": "key_123"
}
```

#### POST /security/decrypt
Decrypt encrypted data.

**Request:**
```json
{
  "encrypted_data": "base64_encrypted_string",
  "key_type": "data"
}
```

### Security Audit

#### GET /security/audit
Get security audit log.

**Query Parameters:**
- `event_type` (string): Filter by event type
- `user_id` (string): Filter by user
- `start_time` (datetime): Start of time range
- `end_time` (datetime): End of time range

**Response:**
```json
{
  "audit_entries": [
    {
      "timestamp": "2023-10-15T10:30:00Z",
      "event_type": "authentication",
      "user_id": "user_123",
      "action": "login",
      "resource": "api",
      "result": "success",
      "ip_address": "192.168.1.100",
      "user_agent": "BLNCS-Client/1.0",
      "metadata": {
        "mfa_used": true,
        "session_duration": 3600
      }
    }
  ],
  "total_count": 1500,
  "pagination": {
    "offset": 0,
    "limit": 50,
    "has_more": true
  }
}
```

---

## Error Handling

### Error Response Format

All errors follow a consistent JSON format:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request validation failed",
    "details": [
      {
        "field": "amount",
        "message": "Amount must be greater than 0"
      }
    ],
    "correlation_id": "req_123456",
    "timestamp": "2023-10-15T10:30:00Z",
  }
}
```

### HTTP Status Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 200 | OK | Request successful |
| 201 | Created | Resource created |
| 204 | No Content | Request successful, no content |
| 400 | Bad Request | Invalid request parameters |
| 401 | Unauthorized | Authentication required |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Resource conflict |
| 422 | Unprocessable Entity | Validation error |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error |
| 502 | Bad Gateway | Upstream service error |
| 503 | Service Unavailable | Service temporarily unavailable |

### Error Codes

| Code | Description | HTTP Status |
|------|-------------|-------------|
| `AUTHENTICATION_FAILED` | Invalid credentials | 401 |
| `AUTHORIZATION_DENIED` | Insufficient permissions | 403 |
| `VALIDATION_ERROR` | Request validation failed | 422 |
| `RESOURCE_NOT_FOUND` | Requested resource not found | 404 |
| `RATE_LIMIT_EXCEEDED` | Rate limit exceeded | 429 |
| `LIGHTNING_NODE_ERROR` | Lightning node operation failed | 502 |
| `CHANNEL_NOT_FOUND` | Channel not found | 404 |
| `INSUFFICIENT_BALANCE` | Insufficient balance for operation | 422 |
| `PAYMENT_FAILED` | Payment could not be completed | 422 |
| `INTERNAL_ERROR` | Internal server error | 500 |

---

## SDKs & Integration

### Official SDKs

#### Python SDK
```bash
pip install blncs-python-sdk
```

```python
from blncs import Client

client = Client(
    api_key="your_api_key",
    base_url="http://localhost:3000"
)

# Create invoice
invoice = client.invoices.create(
    memo="Test payment",
    value=100000
)

# Send payment
payment = client.payments.send(
    payment_request="lnbc1u1p..."
)
```

#### Node.js SDK
```bash
npm install @blncs/node-sdk
```

```javascript
const { BlncsClient } = require('@blncs/node-sdk');

const client = new BlncsClient({
  apiKey: 'your_api_key',
  baseUrl: 'http://localhost:3000'
});

// Create invoice
const invoice = await client.invoices.create({
  memo: 'Test payment',
  value: 100000
});

// Send payment
const payment = await client.payments.send({
  paymentRequest: 'lnbc1u1p...'
});
```

### Webhook Integration

#### Webhook Configuration

Configure webhooks to receive real-time notifications:

```json
{
  "url": "https://your-app.com/webhooks/blncs",
  "events": [
    "payment.sent",
    "payment.received",
    "invoice.created",
    "invoice.settled",
    "channel.opened",
    "channel.closed"
  ],
  "secret": "webhook_secret_key"
}
```

#### Webhook Payload

```json
{
  "id": "evt_123456",
  "type": "payment.received",
  "timestamp": "2023-10-15T10:30:00Z",
  "data": {
    "payment_hash": "a1b2c3d4...",
    "amount": 100000,
    "memo": "Payment for services",
    "settled_at": "2023-10-15T10:30:00Z"
  },
  "signature": "sha256_signature"
}
```

---

## Examples & Use Cases

### Basic Payment Flow

```python
# 1. Create invoice
invoice = client.invoices.create(
    memo="Coffee payment",
    value=5000,  # 5000 sats
    expiry=3600  # 1 hour
)

print(f"Invoice: {invoice.payment_request}")

# 2. Check invoice status
status = client.invoices.get(invoice.r_hash)
if status.settled:
    print("Payment received!")

# 3. Send payment
payment = client.payments.send(
    payment_request="lnbc50u1p...",
    fee_limit={"fixed": 100}  # Max 100 sat fee
)

if payment.status == "SUCCEEDED":
    print(f"Payment sent! Fee: {payment.fee} sats")
```

### Channel Management

```python
# Open channel
channel = client.channels.open(
    node_pubkey="03a1b2c3d4...",
    local_funding_amount=1000000,  # 1M sats
    push_sat=100000,  # Push 100k sats
    private=False
)

# Wait for confirmation
while True:
    status = client.channels.get(channel.channel_point)
    if status.active:
        print("Channel is active!")
        break
    time.sleep(30)

# Update channel fees
client.channels.update_fees(
    chan_id=channel.chan_id,
    base_fee_msat=1000,
    fee_rate=1
)
```

### Monitoring Integration

```python
# Stream real-time events
for event in client.events.stream():
    if event.type == "payment.received":
        print(f"Received {event.data.amount} sats")
    elif event.type == "channel.opened":
        print(f"New channel: {event.data.channel_point}")

# Get metrics
metrics = client.monitoring.get_metrics()
print(f"Success rate: {metrics.lightning.payment_success_rate}%")

# Check alerts
alerts = client.monitoring.get_alerts()
for alert in alerts.active_alerts:
    if alert.priority == "critical":
        # Handle critical alert
        send_notification(alert.message)
```

### Error Handling

```python
from blncs.exceptions import (
    BlncsAPIError,
    InsufficientBalanceError,
    ChannelNotFoundError
)

try:
    payment = client.payments.send(
        payment_request="lnbc1u1p...",
        fee_limit={"percent": 1}
    )
except InsufficientBalanceError:
    print("Not enough balance for payment")
except BlncsAPIError as e:
    print(f"API Error: {e.message} (Code: {e.code})")
    if e.code == "PAYMENT_FAILED":
        # Handle payment failure
        retry_payment_later(payment_request)
```

### Advanced Routing

```python
# Custom route hints for private channels
route_hints = [
    {
        "hop_hints": [
            {
                "node_id": "03a1b2c3d4...",
                "chan_id": "123456789012345678",
                "fee_base_msat": 1000,
                "fee_proportional_millionths": 1,
                "cltv_expiry_delta": 40
            }
        ]
    }
]

invoice = client.invoices.create(
    memo="Private channel payment",
    value=50000,
    route_hints=route_hints,
    private=True
)

# Multi-path payment
payment = client.payments.send(
    payment_request="lnbc500u1p...",
    fee_limit={"fixed": 1000},
    allow_self_payment=False,
    max_parts=10  # Split into max 10 parts
)
```

---

## Support & Resources

- **Support**: support@blncs.com

### Rate Limits & Quotas

- **Free Tier**: 1,000 requests/hour
- **Starter**: 10,000 requests/hour, 100 channels
- **Professional**: 100,000 requests/hour, 1,000 channels
- **Enterprise**: Unlimited requests, unlimited channels

### SLA Guarantees

- **Professional**: 99.5% uptime
- **Enterprise**: 99.9% uptime
- **Response Time**: < 200ms (95th percentile)
- **Support Response**: < 4 hours (Enterprise), < 24 hours (Professional)

---

*Last Updated: 2023-10-15*
*API Version: v1.0.0*