"""
高度なAPI管理システム for BLNCS
APIゲートウェイ強化とレート制限最適化機能を提供
"""

import time
import json
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import logging
import asyncio
import aiohttp
import uuid
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class RateLimitStrategy(Enum):
    """レート制限戦略"""
    FIXED_WINDOW = "fixed_window"      # 固定ウィンドウ
    SLIDING_WINDOW = "sliding_window"  # スライディングウィンドウ
    TOKEN_BUCKET = "token_bucket"      # トークンバケット
    LEAKY_BUCKET = "leaky_bucket"      # リーキーバケット


class APISecurityLevel(Enum):
    """APIセキュリティレベル"""
    PUBLIC = "public"
    AUTHENTICATED = "authenticated"
    AUTHORIZED = "authorized"
    ADMIN_ONLY = "admin_only"


@dataclass
class APIEndpoint:
    """APIエンドポイント情報"""
    endpoint_id: str
    path: str
    method: str
    service_name: str
    security_level: APISecurityLevel = APISecurityLevel.PUBLIC
    rate_limit_rules: List[Dict[str, Any]] = field(default_factory=list)
    caching_config: Dict[str, Any] = field(default_factory=dict)
    timeout: float = 30.0
    retries: int = 3
    is_active: bool = True
    created_at: float = field(default_factory=time.time)


@dataclass
class RateLimitRule:
    """レート制限ルール情報"""
    rule_id: str
    endpoint_pattern: str
    strategy: RateLimitStrategy
    requests_per_window: int
    window_size_seconds: int
    burst_limit: int = 0
    user_tier: str = "default"  # free, premium, enterprise
    is_active: bool = True


@dataclass
class APIRequest:
    """APIリクエスト情報"""
    request_id: str
    endpoint: str
    method: str
    user_id: Optional[str] = None
    api_key: Optional[str] = None
    user_tier: str = "default"
    ip_address: str = ""
    user_agent: str = ""
    timestamp: float = field(default_factory=time.time)
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[Any] = None


@dataclass
class RateLimitStatus:
    """レート制限ステータス情報"""
    user_id: str
    endpoint: str
    current_requests: int
    window_start: float
    window_end: float
    is_allowed: bool
    retry_after: Optional[float] = None


class EnhancedRateLimiter:
    """強化されたレート制限システム"""

    def __init__(self, db_path: str = "rate_limiting.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self._init_db()
        self.rate_limit_rules: Dict[str, RateLimitRule] = {}
        self.request_counters: Dict[str, Dict[str, Any]] = defaultdict(dict)
        self.buckets: Dict[str, Dict[str, float]] = defaultdict(dict)  # user_id -> endpoint -> tokens

    def _init_db(self):
        """データベースを初期化"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rate_limit_rules (
                    rule_id TEXT PRIMARY KEY,
                    endpoint_pattern TEXT NOT NULL,
                    strategy TEXT NOT NULL,
                    requests_per_window INTEGER NOT NULL,
                    window_size_seconds INTEGER NOT NULL,
                    burst_limit INTEGER,
                    user_tier TEXT,
                    is_active INTEGER
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS rate_limit_counters (
                    id INTEGER PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    request_count INTEGER NOT NULL,
                    window_start REAL NOT NULL,
                    window_end REAL NOT NULL,
                    last_request REAL,
                    UNIQUE(user_id, endpoint)
                )
            """)

            conn.commit()

    def add_rate_limit_rule(self, rule: RateLimitRule):
        """
        レート制限ルールを追加
        Args:
            rule: レート制限ルール
        """
        self.rate_limit_rules[rule.rule_id] = rule

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO rate_limit_rules
                    (rule_id, endpoint_pattern, strategy, requests_per_window, window_size_seconds,
                     burst_limit, user_tier, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    rule.rule_id, rule.endpoint_pattern, rule.strategy.value,
                    rule.requests_per_window, rule.window_size_seconds,
                    rule.burst_limit, rule.user_tier, 1 if rule.is_active else 0
                ))
                conn.commit()

        except Exception as e:
            logger.error(f"レート制限ルール追加エラー: {e}")

    def check_rate_limit(self, request: APIRequest) -> RateLimitStatus:
        """
        レート制限をチェック
        Args:
            request: APIリクエスト
        Returns:
            レート制限ステータス
        """
        current_time = time.time()

        # 該当するルールを取得
        applicable_rules = self._get_applicable_rules(request.endpoint, request.user_tier)

        if not applicable_rules:
            # ルールがない場合は許可
            return RateLimitStatus(
                user_id=request.user_id or "anonymous",
                endpoint=request.endpoint,
                current_requests=0,
                window_start=current_time,
                window_end=current_time + 60,
                is_allowed=True
            )

        # 最も厳しいルールを選択
        strictest_rule = min(applicable_rules, key=lambda r: r.requests_per_window)

        # 戦略に応じたチェックを実行
        if strictest_rule.strategy == RateLimitStrategy.FIXED_WINDOW:
            return self._check_fixed_window(request, strictest_rule)
        elif strictest_rule.strategy == RateLimitStrategy.SLIDING_WINDOW:
            return self._check_sliding_window(request, strictest_rule)
        elif strictest_rule.strategy == RateLimitStrategy.TOKEN_BUCKET:
            return self._check_token_bucket(request, strictest_rule)
        else:
            return self._check_fixed_window(request, strictest_rule)  # デフォルト

    def _get_applicable_rules(self, endpoint: str, user_tier: str) -> List[RateLimitRule]:
        """該当するルールを取得"""
        applicable = []

        for rule in self.rate_limit_rules.values():
            if not rule.is_active:
                continue

            # エンドポイントパターンマッチング（簡易版）
            if self._match_endpoint_pattern(endpoint, rule.endpoint_pattern):
                # ユーザーティアチェック
                if rule.user_tier == "all" or rule.user_tier == user_tier:
                    applicable.append(rule)

        return applicable

    def _match_endpoint_pattern(self, endpoint: str, pattern: str) -> bool:
        """エンドポイントパターンマッチング"""
        # 簡易的なパターンマッチング
        if pattern == "*":
            return True
        elif pattern.endswith("*"):
            return endpoint.startswith(pattern[:-1])
        else:
            return endpoint == pattern

    def _check_fixed_window(self, request: APIRequest, rule: RateLimitRule) -> RateLimitStatus:
        """固定ウィンドウ方式でチェック"""
        user_key = f"{request.user_id or 'anonymous'}_{rule.endpoint_pattern}"
        current_time = time.time()

        # ウィンドウの開始時間を計算
        window_size = rule.window_size_seconds
        window_start = current_time - (current_time % window_size)
        window_end = window_start + window_size

        # データベースから現在のカウントを取得
        counter_key = f"{user_key}_{window_start}"

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT request_count FROM rate_limit_counters
                    WHERE user_id = ? AND endpoint = ?
                """, (user_key, rule.endpoint_pattern))

                row = cursor.fetchone()
                current_count = row[0] if row else 0

        except Exception as e:
            logger.error(f"カウンター取得エラー: {e}")
            current_count = 0

        is_allowed = current_count < rule.requests_per_window

        if is_allowed:
            # カウンターを更新
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO rate_limit_counters
                        (user_id, endpoint, request_count, window_start, window_end, last_request)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (user_key, rule.endpoint_pattern, current_count + 1, window_start, window_end, current_time))
                    conn.commit()

            except Exception as e:
                logger.error(f"カウンター更新エラー: {e}")

        return RateLimitStatus(
            user_id=request.user_id or "anonymous",
            endpoint=request.endpoint,
            current_requests=current_count + 1 if is_allowed else current_count,
            window_start=window_start,
            window_end=window_end,
            is_allowed=is_allowed,
            retry_after=window_end - current_time if not is_allowed else None
        )

    def _check_sliding_window(self, request: APIRequest, rule: RateLimitRule) -> RateLimitStatus:
        """スライディングウィンドウ方式でチェック"""
        user_key = f"{request.user_id or 'anonymous'}_{rule.endpoint_pattern}"
        current_time = time.time()

        # ウィンドウ内のリクエストをカウント
        cutoff_time = current_time - rule.window_size_seconds

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT COUNT(*) FROM rate_limit_counters
                    WHERE user_id = ? AND endpoint = ? AND last_request > ?
                """, (user_key, rule.endpoint_pattern, cutoff_time))

                current_count = cursor.fetchone()[0]

        except Exception as e:
            logger.error(f"スライディングウィンドウチェックエラー: {e}")
            current_count = 0

        is_allowed = current_count < rule.requests_per_window

        if is_allowed:
            # 新しいリクエストを記録
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT INTO rate_limit_counters
                        (user_id, endpoint, request_count, window_start, window_end, last_request)
                        VALUES (?, ?, 1, ?, ?, ?)
                    """, (user_key, rule.endpoint_pattern, cutoff_time, current_time + rule.window_size_seconds, current_time))
                    conn.commit()

            except Exception as e:
                logger.error(f"スライディングウィンドウ記録エラー: {e}")

        return RateLimitStatus(
            user_id=request.user_id or "anonymous",
            endpoint=request.endpoint,
            current_requests=current_count + 1 if is_allowed else current_count,
            window_start=cutoff_time,
            window_end=current_time + rule.window_size_seconds,
            is_allowed=is_allowed,
            retry_after=rule.window_size_seconds if not is_allowed else None
        )

    def _check_token_bucket(self, request: APIRequest, rule: RateLimitRule) -> RateLimitStatus:
        """トークンバケット方式でチェック"""
        user_key = f"{request.user_id or 'anonymous'}_{rule.endpoint_pattern}"
        current_time = time.time()

        # バケットの状態を取得・更新
        if user_key not in self.buckets:
            self.buckets[user_key][rule.endpoint_pattern] = rule.requests_per_window

        tokens = self.buckets[user_key][rule.endpoint_pattern]

        # トークンが十分にあるかチェック
        if tokens >= 1:
            # トークンを消費
            self.buckets[user_key][rule.endpoint_pattern] = tokens - 1

            # トークン再充填（時間経過による）
            time_passed = current_time - getattr(self, '_last_refill', {}).get(user_key, current_time)
            tokens_to_add = (time_passed / rule.window_size_seconds) * rule.requests_per_window

            if tokens_to_add > 0:
                new_tokens = min(rule.requests_per_window, tokens + tokens_to_add)
                self.buckets[user_key][rule.endpoint_pattern] = new_tokens
                self._last_refill = {user_key: current_time}

            return RateLimitStatus(
                user_id=request.user_id or "anonymous",
                endpoint=request.endpoint,
                current_requests=rule.requests_per_window - int(tokens),
                window_start=current_time,
                window_end=current_time + rule.window_size_seconds,
                is_allowed=True
            )
        else:
            return RateLimitStatus(
                user_id=request.user_id or "anonymous",
                endpoint=request.endpoint,
                current_requests=rule.requests_per_window,
                window_start=current_time,
                window_end=current_time + rule.window_size_seconds,
                is_allowed=False,
                retry_after=rule.window_size_seconds
            )


class EnhancedAPIGateway:
    """強化されたAPIゲートウェイ"""

    def __init__(self, db_path: str = "api_gateway.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self._init_db()
        self.endpoints: Dict[str, APIEndpoint] = {}
        self.rate_limiter = EnhancedRateLimiter(db_path)
        self.request_log: List[Dict[str, Any]] = []
        self.middleware_stack: List[Callable] = []

    def _init_db(self):
        """データベースを初期化"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS api_endpoints (
                    endpoint_id TEXT PRIMARY KEY,
                    path TEXT NOT NULL,
                    method TEXT NOT NULL,
                    service_name TEXT NOT NULL,
                    security_level TEXT,
                    rate_limit_rules TEXT,
                    caching_config TEXT,
                    timeout REAL,
                    retries INTEGER,
                    is_active INTEGER,
                    created_at REAL
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS api_requests (
                    id INTEGER PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    method TEXT NOT NULL,
                    user_id TEXT,
                    api_key TEXT,
                    user_tier TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    status_code INTEGER,
                    response_time REAL,
                    timestamp REAL
                )
            """)

            conn.commit()

    def register_endpoint(self, endpoint: APIEndpoint):
        """
        APIエンドポイントを登録
        Args:
            endpoint: APIエンドポイント情報
        """
        self.endpoints[endpoint.endpoint_id] = endpoint

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO api_endpoints
                    (endpoint_id, path, method, service_name, security_level, rate_limit_rules,
                     caching_config, timeout, retries, is_active, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    endpoint.endpoint_id, endpoint.path, endpoint.method, endpoint.service_name,
                    endpoint.security_level.value, json.dumps(endpoint.rate_limit_rules),
                    json.dumps(endpoint.caching_config), endpoint.timeout, endpoint.retries,
                    1 if endpoint.is_active else 0, endpoint.created_at
                ))
                conn.commit()

        except Exception as e:
            logger.error(f"エンドポイント登録エラー: {e}")

    def add_middleware(self, middleware: Callable):
        """
        ミドルウェアを追加
        Args:
            middleware: ミドルウェア関数
        """
        self.middleware_stack.append(middleware)

    async def process_request(self, request: APIRequest) -> Dict[str, Any]:
        """
        リクエストを処理
        Args:
            request: APIリクエスト
        Returns:
            レスポンスデータ
        """
        start_time = time.time()

        try:
            # レート制限チェック
            rate_limit_status = self.rate_limiter.check_rate_limit(request)

            if not rate_limit_status.is_allowed:
                return {
                    "status_code": 429,
                    "headers": {"Retry-After": str(rate_limit_status.retry_after or 60)},
                    "body": {"error": "Rate limit exceeded"},
                    "response_time": time.time() - start_time
                }

            # セキュリティチェック
            security_check_result = await self._perform_security_check(request)
            if not security_check_result["allowed"]:
                return {
                    "status_code": 403,
                    "body": {"error": security_check_result["reason"]},
                    "response_time": time.time() - start_time
                }

            # ミドルウェア実行
            for middleware in self.middleware_stack:
                try:
                    result = await middleware(request)
                    if result:
                        break
                except Exception as e:
                    logger.error(f"ミドルウェア実行エラー: {e}")

            # 実際のサービスにリクエストを転送
            response = await self._forward_request(request)

            # リクエストログを記録
            self._log_api_request(request, response["status_code"], response["response_time"])

            return response

        except Exception as e:
            logger.error(f"リクエスト処理エラー: {e}")

            return {
                "status_code": 500,
                "body": {"error": "Internal server error"},
                "response_time": time.time() - start_time
            }

    async def _perform_security_check(self, request: APIRequest) -> Dict[str, Any]:
        """セキュリティチェックを実行"""
        # エンドポイントのセキュリティレベルを取得
        endpoint = self._find_matching_endpoint(request.endpoint)

        if not endpoint:
            return {"allowed": False, "reason": "Endpoint not found"}

        # セキュリティレベルチェック
        if endpoint.security_level == APISecurityLevel.AUTHENTICATED:
            if not request.user_id and not request.api_key:
                return {"allowed": False, "reason": "Authentication required"}

        elif endpoint.security_level == APISecurityLevel.AUTHORIZED:
            # 実際の実装では詳細な認可チェックを実行
            if not request.user_id:
                return {"allowed": False, "reason": "Authorization required"}

        return {"allowed": True, "reason": "OK"}

    def _find_matching_endpoint(self, path: str) -> Optional[APIEndpoint]:
        """マッチするエンドポイントを検索"""
        for endpoint in self.endpoints.values():
            if endpoint.is_active and self._match_path(path, endpoint.path):
                return endpoint
        return None

    def _match_path(self, request_path: str, endpoint_path: str) -> bool:
        """パスをマッチング"""
        # 簡易的なパス一致チェック
        return request_path == endpoint_path

    async def _forward_request(self, request: APIRequest) -> Dict[str, Any]:
        """リクエストを転送"""
        # マッチするエンドポイントを取得
        endpoint = self._find_matching_endpoint(request.endpoint)

        if not endpoint:
            return {"status_code": 404, "body": {"error": "Endpoint not found"}}

        # 実際の実装ではサービスにリクエストを転送
        # ここではシミュレーション
        await asyncio.sleep(0.1)  # 処理時間をシミュレーション

        return {
            "status_code": 200,
            "headers": {"Content-Type": "application/json"},
            "body": {"message": "Request processed successfully", "endpoint": request.endpoint},
            "response_time": 0.1
        }

    def _log_api_request(self, request: APIRequest, status_code: int, response_time: float):
        """APIリクエストをログ記録"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO api_requests
                    (request_id, endpoint, method, user_id, api_key, user_tier, ip_address, user_agent,
                     status_code, response_time, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    request.request_id, request.endpoint, request.method, request.user_id,
                    request.api_key, request.user_tier, request.ip_address, request.user_agent,
                    status_code, response_time, request.timestamp
                ))
                conn.commit()

        except Exception as e:
            logger.error(f"APIリクエストログエラー: {e}")

    def get_api_analytics(self, hours: int = 24) -> Dict[str, Any]:
        """API分析情報を取得"""
        cutoff_time = time.time() - (hours * 3600)

        try:
            with sqlite3.connect(self.db_path) as conn:
                # リクエスト数の集計
                cursor = conn.execute("""
                    SELECT COUNT(*) as total_requests,
                           AVG(response_time) as avg_response_time,
                           COUNT(CASE WHEN status_code >= 400 THEN 1 END) as error_count
                    FROM api_requests
                    WHERE timestamp > ?
                """, (cutoff_time,))

                row = cursor.fetchone()

                # エンドポイント別統計
                endpoint_stats = conn.execute("""
                    SELECT endpoint, COUNT(*) as requests, AVG(response_time) as avg_time
                    FROM api_requests
                    WHERE timestamp > ?
                    GROUP BY endpoint
                    ORDER BY requests DESC
                """, (cutoff_time,)).fetchall()

                return {
                    "total_requests": row[0],
                    "avg_response_time": row[1],
                    "error_rate": (row[2] / row[0] * 100) if row[0] > 0 else 0,
                    "endpoint_stats": [
                        {"endpoint": stat[0], "requests": stat[1], "avg_response_time": stat[2]}
                        for stat in endpoint_stats[:10]  # 上位10件
                    ],
                    "period_hours": hours
                }

        except Exception as e:
            logger.error(f"API分析取得エラー: {e}")
            return {}


class APIKeyManager:
    """APIキーマネージャー"""

    def __init__(self, db_path: str = "api_keys.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self._init_db()
        self.api_keys: Dict[str, Dict[str, Any]] = {}

    def _init_db(self):
        """データベースを初期化"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    key_id TEXT PRIMARY KEY,
                    api_key_hash TEXT NOT NULL,
                    user_id TEXT,
                    tier TEXT,
                    permissions TEXT,
                    rate_limits TEXT,
                    is_active INTEGER,
                    created_at REAL,
                    expires_at REAL,
                    last_used REAL
                )
            """)

            conn.commit()

    def generate_api_key(self, user_id: str, tier: str = "free", permissions: List[str] = None) -> str:
        """
        APIキーを生成
        Args:
            user_id: ユーザーID
            tier: ユーザーティア
            permissions: 権限リスト
        Returns:
            生成されたAPIキー
        """
        key_id = str(uuid.uuid4())
        api_key = f"blncs_{key_id}_{int(time.time())}"

        # APIキーをハッシュ化して保存
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        key_info = {
            "key_id": key_id,
            "api_key_hash": api_key_hash,
            "user_id": user_id,
            "tier": tier,
            "permissions": permissions or ["read"],
            "rate_limits": {"requests_per_minute": 60 if tier == "free" else 1000},
            "is_active": True,
            "created_at": time.time(),
            "expires_at": None,  # 無期限
            "last_used": None
        }

        self.api_keys[key_id] = key_info

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO api_keys
                    (key_id, api_key_hash, user_id, tier, permissions, rate_limits, is_active,
                     created_at, expires_at, last_used)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    key_id, api_key_hash, user_id, tier, json.dumps(permissions or ["read"]),
                    json.dumps(key_info["rate_limits"]), 1, time.time(), None, None
                ))
                conn.commit()

        except Exception as e:
            logger.error(f"APIキー生成エラー: {e}")

        return api_key

    def validate_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """
        APIキーを検証
        Args:
            api_key: APIキー
        Returns:
            キー情報（無効な場合はNone）
        """
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        for key_info in self.api_keys.values():
            if key_info["api_key_hash"] == api_key_hash and key_info["is_active"]:
                # 最終使用時間を更新
                key_info["last_used"] = time.time()

                return {
                    "user_id": key_info["user_id"],
                    "tier": key_info["tier"],
                    "permissions": key_info["permissions"],
                    "rate_limits": key_info["rate_limits"]
                }

        return None

    def revoke_api_key(self, key_id: str) -> bool:
        """
        APIキーを無効化
        Args:
            key_id: キーID
        Returns:
            無効化成功フラグ
        """
        if key_id in self.api_keys:
            self.api_keys[key_id]["is_active"] = False

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("UPDATE api_keys SET is_active = 0 WHERE key_id = ?", (key_id,))
                conn.commit()

            return True

        except Exception as e:
            logger.error(f"APIキー無効化エラー: {e}")
            return False


class AdvancedAPIManager:
    """高度なAPI管理システム"""

    def __init__(self, db_path: str = "advanced_api_management.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self.api_gateway = EnhancedAPIGateway(db_path)
        self.api_key_manager = APIKeyManager(db_path)

        self.is_api_active = False

    def initialize_api_system(self):
        """APIシステムを初期化"""
        # デフォルトのエンドポイントを登録
        self._register_default_endpoints()

        # デフォルトのレート制限ルールを設定
        self._setup_default_rate_limits()

    def _register_default_endpoints(self):
        """デフォルトのエンドポイントを登録"""
        endpoints = [
            APIEndpoint(
                endpoint_id="user_api",
                path="/api/v1/users",
                method="GET",
                service_name="user_service",
                security_level=APISecurityLevel.AUTHENTICATED,
                rate_limit_rules=[{"tier": "free", "requests_per_minute": 60}],
                timeout=10.0
            ),
            APIEndpoint(
                endpoint_id="payment_api",
                path="/api/v1/payments",
                method="POST",
                service_name="payment_service",
                security_level=APISecurityLevel.AUTHORIZED,
                rate_limit_rules=[{"tier": "premium", "requests_per_minute": 100}],
                timeout=15.0
            ),
            APIEndpoint(
                endpoint_id="analytics_api",
                path="/api/v1/analytics",
                method="GET",
                service_name="analytics_service",
                security_level=APISecurityLevel.ADMIN_ONLY,
                rate_limit_rules=[{"tier": "enterprise", "requests_per_minute": 1000}],
                timeout=30.0
            )
        ]

        for endpoint in endpoints:
            self.api_gateway.register_endpoint(endpoint)

    def _setup_default_rate_limits(self):
        """デフォルトのレート制限ルールを設定"""
        rules = [
            RateLimitRule(
                rule_id="free_tier_limit",
                endpoint_pattern="/api/v1/*",
                strategy=RateLimitStrategy.SLIDING_WINDOW,
                requests_per_window=60,
                window_size_seconds=60,
                user_tier="free"
            ),
            RateLimitRule(
                rule_id="premium_tier_limit",
                endpoint_pattern="/api/v1/*",
                strategy=RateLimitStrategy.TOKEN_BUCKET,
                requests_per_window=1000,
                window_size_seconds=60,
                user_tier="premium"
            ),
            RateLimitRule(
                rule_id="enterprise_tier_limit",
                endpoint_pattern="/api/v1/*",
                strategy=RateLimitStrategy.TOKEN_BUCKET,
                requests_per_window=10000,
                window_size_seconds=60,
                user_tier="enterprise"
            )
        ]

        for rule in rules:
            self.api_gateway.rate_limiter.add_rate_limit_rule(rule)

    def start_api_system(self):
        """APIシステムを開始"""
        if not self.is_api_active:
            self.is_api_active = True
            logger.info("高度なAPI管理システムを開始しました")

    def stop_api_system(self):
        """APIシステムを停止"""
        self.is_api_active = False
        logger.info("高度なAPI管理システムを停止しました")

    def generate_user_api_key(self, user_id: str, tier: str = "free") -> str:
        """
        ユーザーAPIキーを生成
        Args:
            user_id: ユーザーID
            tier: ユーザーティア
        Returns:
            生成されたAPIキー
        """
        return self.api_key_manager.generate_api_key(user_id, tier)

    async def handle_api_request(self, endpoint: str, method: str,
                               headers: Dict[str, str] = None,
                               body: Any = None, ip_address: str = "") -> Dict[str, Any]:
        """
        APIリクエストを処理
        Args:
            endpoint: エンドポイントパス
            method: HTTPメソッド
            headers: リクエストヘッダー
            body: リクエストボディ
            ip_address: クライアントIPアドレス
        Returns:
            レスポンスデータ
        """
        # APIキーを抽出
        api_key = None
        user_id = None
        user_tier = "default"

        if headers:
            api_key = headers.get("X-API-Key") or headers.get("Authorization", "").replace("Bearer ", "")

        if api_key:
            key_info = self.api_key_manager.validate_api_key(api_key)
            if key_info:
                user_id = key_info["user_id"]
                user_tier = key_info["tier"]

        # リクエストオブジェクトを作成
        request = APIRequest(
            request_id=str(uuid.uuid4()),
            endpoint=endpoint,
            method=method,
            user_id=user_id,
            api_key=api_key,
            user_tier=user_tier,
            ip_address=ip_address,
            headers=headers or {},
            body=body
        )

        return await self.api_gateway.process_request(request)

    def get_api_analytics(self, hours: int = 24) -> Dict[str, Any]:
        """API分析情報を取得"""
        return self.api_gateway.get_api_analytics(hours)

    def get_api_system_status(self) -> Dict[str, Any]:
        """APIシステムステータスを取得"""
        return {
            "is_active": self.is_api_active,
            "total_endpoints": len(self.api_gateway.endpoints),
            "active_rate_limits": len(self.api_gateway.rate_limiter.rate_limit_rules),
            "total_api_keys": len(self.api_key_manager.api_keys),
            "middleware_count": len(self.api_gateway.middleware_stack)
        }


# 使用例
async def example_usage():
    manager = AdvancedAPIManager()

    # システム初期化
    manager.initialize_api_system()

    # システム開始
    manager.start_api_system()

    # APIキー生成
    api_key = manager.generate_user_api_key("user_123", "premium")
    print(f"APIキー生成: {api_key[:20]}...")

    # APIリクエスト処理のシミュレーション
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}

    response = await manager.handle_api_request(
        "/api/v1/users",
        "GET",
        headers=headers,
        ip_address="192.168.1.100"
    )

    print(f"APIレスポンス: {response['status_code']} - {response['response_time']:.3f}s")

    # API分析取得
    analytics = manager.get_api_analytics(hours=1)
    print(f"API分析: {analytics['total_requests']}リクエスト")

    # システムステータス
    status = manager.get_api_system_status()
    print(f"APIシステムステータス: {status}")

    manager.stop_api_system()


if __name__ == "__main__":
    asyncio.run(example_usage())
