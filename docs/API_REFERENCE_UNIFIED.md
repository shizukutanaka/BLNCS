# BLNCS REST API Reference｜REST API リファレンス

## Overview (English)

The BLNCS REST API is served by `blncs/api/unified_rest_api.py`. It exposes lightweight endpoints for health monitoring, cache inspection, configuration snapshots, Lightning Network helpers, and basic system automation. Responses are JSON encoded and designed for automation scripts or operator dashboards.

## 概要 (日本語)

BLNCS の REST API は `blncs/api/unified_rest_api.py` で提供され、ヘルスチェック、キャッシュ統計、設定情報、Lightning Network 操作用ヘルパー、システム自動化といった軽量な機能を JSON 形式で返します。運用スクリプトやダッシュボード連携を想定しています。

---

## Base URL｜ベース URL

```
http://<host>:<port>
```

- **Default host**: `127.0.0.1` (configurable via `config/blncs.json` key `api.host`)
- **Default port**: `8080` (configurable via `config/blncs.json` key `api.port`)
- **Content-Type**: `application/json; charset=utf-8`

---

## Authentication｜認証

- **Header**: `X-API-Key: <token>`（クエリ `?api_key=` もサポートしますが、運用時はヘッダ利用を推奨）
- **Token management**: `blncs/core/simple_auth.py` の `SimpleAuth` によるソルト付き PBKDF2 ハッシュ保存。`blncs_main.py security` サブコマンドやライブラリ API で発行・ローテーション可能です。
- **Default scopes**:
  - `read`: 情報取得系エンドポイント。`/api/info`、`/api/cache/stats`、`/api/config`、`/api/lightning/info`、`/api/lightning/balance`、`/api/lightning/decode`、`/api/system/metrics`、`/api/websocket/status` など。
  - `write`: 設定やライトニング送金など状態を変更するエンドポイント。`/api/cache/clear`、`/api/lightning/invoice`、`/api/lightning/pay`、`/api/system/backup`、`/api/system/optimize` など。
- **Error responses**:
  - `401 {"error": "Invalid or missing API key"}`: トークン未指定・無効時。
  - `403 {"error": "Insufficient permissions. Required: <scope>"}`: スコープ不足時。
  - `429 {"error": "Too many authentication failures"}`: 同一クライアントから短時間に一定回数以上の失敗が発生した場合。

### Authentication Failure Limiter｜認証失敗レート制限

- **Configuration keys** (`config/blncs.json` など)
  - `security.max_attempts`: 失敗許容回数 (default: 5)
  - `security.failure_window_seconds`: 失敗カウント対象となる時間窓 (default: 60)
- **Behaviour**
  - レート制限発動時には `AUTH_RATE_LIMIT` ログを `blncs.auth` ロガーへ出力し、HTTP 429 を返答します。
  - 許可されたリクエストが成功するとカウンタがリセットされ、正常な利用者が継続利用できるよう配慮しています。
  - 設定値は `UnifiedConfigManager` のホットリロードに追従し、運用中でも変更が反映されます。

---

## Health & Information｜ヘルス・情報系

- **Endpoint**: `GET /health`
  - **Description**: Returns current service health with subsystem checks. Uses HTTP `200` when healthy, `503` when degraded.
  - **Response**:
    ```json
    {
      "status": "healthy",
      "timestamp": 1726905600.123,
      "checks": {
        "database": "ok",
        "cache": "ok",
        "lightning": "available"
      }
    }
    ```

- **Endpoint**: `GET /api/info`
  - **Description**: Static metadata about the running build. Cached for 300 seconds.
  - **Response**:
    ```json
    {
      "name": "BLNCS",
      "version": "1.0.0",
      "description": "Bitcoin Lightning Network Control System"
    }
    ```

---

## Cache Management｜キャッシュ管理

- **Endpoint**: `GET /api/cache/stats`
  - **Description**: Returns statistics from `blncs.core.simple_cache`. Cached for five seconds.
  - **Response**:
    ```json
    {
      "size": 12,
      "max_size": 1000,
      "hits": 320,
      "misses": 45,
      "hit_rate": 87.6,
      "ttl": 300,
      "total_requests": 365
    }
    ```

- **Endpoint**: `POST /api/cache/clear`
  - **Description**: Clears the shared cache. Returns success or error information.
  - **Response**:
    ```json
    {
      "status": "success",
      "message": "Cache cleared"
    }
    ```

---

## Configuration Snapshot｜設定スナップショット

- **Endpoint**: `GET /api/config`
  - **Description**: Returns non-sensitive configuration sections (`api`, `monitoring`, `cache`). Useful for dashboards that need runtime settings without exposing credentials.
  - **Response**:
    ```json
    {
      "api": {
        "host": "127.0.0.1",
        "port": 8080,
        "enable_cors": true
      },
      "monitoring": {
        "enabled": true,
        "interval": 60
      },
      "cache": {
        "enabled": true,
        "ttl": 300,
        "max_size": 1000
      }
    }
    ```

---

## Lightning Network Helpers｜Lightning Network ヘルパー

The Lightning endpoints rely on `blncs.lightning.simple_client.SimpleLightningClient`. In mock setups the client provides simulated data; connecting to a real node requires appropriate credentials.

- **Endpoint**: `GET /api/lightning/info`
  - **Description**: Basic node metadata from the Lightning backend.
  - **Response**:
    ```json
    {
      "alias": "SampleNode",
      "network": "testnet",
      "version": "0.15.5"
    }
    ```

- **Endpoint**: `GET /api/lightning/balance`
  - **Description**: Wallet balances (total, confirmed, unconfirmed).
  - **Response**:
    ```json
    {
      "total_balance": 120000,
      "confirmed_balance": 118000,
      "unconfirmed_balance": 2000
    }
    ```

- **Endpoint**: `POST /api/lightning/invoice`
  - **Description**: Creates a new Lightning invoice.
  - **Request**:
    ```json
    {
      "amount": 5000,
      "memo": "Demo payment"
    }
    ```
  - **Response**:
    ```json
    {
      "payment_request": "lnbc50u1p...",
      "amount": 5000,
      "memo": "Demo payment"
    }
    ```

- **Endpoint**: `POST /api/lightning/pay`
  - **Description**: Attempts to pay a Bolt11 payment request.
  - **Request**:
    ```json
    {
      "payment_request": "lnbc50u1p..."
    }
    ```
  - **Response**:
    ```json
    {
      "status": "pending",
      "payment_request": "lnbc50u1p..."
    }
    ```

- **Endpoint**: `POST /api/lightning/decode`
  - **Description**: Decodes a Bolt11 invoice without executing a payment.
  - **Request**:
    ```json
    {
      "payment_request": "lnbc50u1p..."
    }
    ```
  - **Response**:
    ```json
    {
      "amount": 5000,
      "description": "Demo payment",
      "network": "testnet"
    }
    ```

---

## System Operations｜システム操作

- **Endpoint**: `POST /api/system/backup`
  - **Description**: Triggers the automatic backup helper (`blncs.utils.backup_manager.auto_backup`).
  - **Response**:
    ```json
    {
      "status": "created",
      "path": "backups/auto_20240921_120000.db"
    }
    ```

- **Endpoint**: `GET /api/system/metrics`
  - **Description**: Returns aggregate metrics from `blncs.utils.simple_metrics.get_stats()`.
  - **Response**:
    ```json
    {
      "cpu_percent": 17.5,
      "memory_mb": 128.3,
      "uptime_seconds": 3600
    }
    ```

- **Endpoint**: `POST /api/system/optimize`
  - **Description**: Invokes `blncs.core.fast_startup.PerformanceOptimizer.apply_all_optimizations()` to adjust lightweight GC thresholds, preload hot imports, and expand buffered I/O safely.
  - **Response**:
    ```json
    {
      "optimizations_applied": ["imports_preloaded", "memory_gc_0", "io_buffers"],
      "gc_objects_collected": 0,
      "optimization_time": 0.042
    }
    ```

---

## WebSocket Status｜WebSocket 状態

- **Endpoint**: `GET /api/websocket/status`
  - **Description**: Reports statistics from the WebSocket manager used by the dashboard (`blncs.api.websocket_server`).
  - **Response**:
    ```json
    {
      "clients": 3,
      "topics": ["dashboard"],
      "last_event": "2024-09-21T12:00:00Z"
    }
    ```

---

## Error Handling｜エラーハンドリング

- **404 Not Found**: `{"error": "Not found"}`
- **500 Internal Server Error**: `{"error": "Internal server error"}` for uncaught exceptions.
- Most application-level errors return a JSON payload with an `error` key and a suitable HTTP status code (`400`, `500`, etc.).

---

## Notes｜補足

- Lightning endpoints assume the optional Lightning client dependencies are installed and configured. In evaluation environments they fall back to mock implementations.
- CORS is enabled by default (`config/blncs.json` key `api.enable_cors`). Disable it if the API is exposed only to trusted backends.
- Only the endpoints listed in this reference are implemented in `blncs/api/unified_rest_api.py`. Remove or gate any downstream integrations that rely on undocumented URLs.

### 
```bash
curl -X GET "http://localhost:8080/logs/recent?limit=10&level=ERROR"
```

### Lightning
```bash
curl -X GET http://localhost:8080/lightning/info
```

## 

### 
:

#### GET /test/ping
```json
{
 "message": "pong",
 "timestamp": "2025-09-21T12:00:00Z"
}
```

### 
`debug=true`

### CORS
 `cors_enabled: true` 

---

**BLNCS API** - REST API