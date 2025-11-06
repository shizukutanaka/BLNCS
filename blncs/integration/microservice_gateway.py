"""
システム統合強化 for BLNCS
マイクロサービス統合とAPIゲートウェイ機能を提供
"""

import time
import json
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
import asyncio
import aiohttp
import uuid
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ServiceStatus(Enum):
    """サービスステータス"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    OFFLINE = "offline"


class RequestMethod(Enum):
    """リクエストメソッド"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"


@dataclass
class MicroService:
    """マイクロサービス情報"""
    service_id: str
    name: str
    base_url: str
    version: str
    status: ServiceStatus = ServiceStatus.HEALTHY
    health_endpoint: str = "/health"
    dependencies: List[str] = field(default_factory=list)
    last_check: float = field(default_factory=time.time)
    response_time: float = 0.0
    error_rate: float = 0.0
    load_score: float = 0.0


@dataclass
class ServiceRequest:
    """サービスリクエスト情報"""
    request_id: str
    service_id: str
    method: RequestMethod
    endpoint: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[Any] = None
    timeout: float = 30.0
    retries: int = 3
    timestamp: float = field(default_factory=time.time)


@dataclass
class ServiceResponse:
    """サービスレスポンス情報"""
    request_id: str
    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: Any = None
    response_time: float = 0.0
    timestamp: float = field(default_factory=time.time)


class ServiceRegistry:
    """サービスレジストリ"""

    def __init__(self, db_path: str = "service_registry.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self._init_db()
        self.services: Dict[str, MicroService] = {}
        self.service_discovery_cache: Dict[str, List[str]] = defaultdict(list)

    def _init_db(self):
        """データベースを初期化"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS services (
                    service_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    base_url TEXT NOT NULL,
                    version TEXT NOT NULL,
                    status TEXT,
                    health_endpoint TEXT,
                    dependencies TEXT,
                    last_check REAL,
                    response_time REAL,
                    error_rate REAL,
                    load_score REAL
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS service_requests (
                    request_id TEXT PRIMARY KEY,
                    service_id TEXT NOT NULL,
                    method TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    headers TEXT,
                    body TEXT,
                    timeout REAL,
                    retries INTEGER,
                    timestamp REAL,
                    FOREIGN KEY (service_id) REFERENCES services (service_id)
                )
            """)

            conn.commit()

    def register_service(self, service: MicroService):
        """
        サービスを登録
        Args:
            service: マイクロサービス情報
        """
        self.services[service.service_id] = service

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO services
                    (service_id, name, base_url, version, status, health_endpoint,
                     dependencies, last_check, response_time, error_rate, load_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    service.service_id, service.name, service.base_url, service.version,
                    service.status.value, service.health_endpoint,
                    json.dumps(service.dependencies), service.last_check,
                    service.response_time, service.error_rate, service.load_score
                ))
                conn.commit()

        except Exception as e:
            logger.error(f"サービス登録エラー: {e}")

    def unregister_service(self, service_id: str):
        """
        サービスを登録解除
        Args:
            service_id: サービスID
        """
        if service_id in self.services:
            del self.services[service_id]

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM services WHERE service_id = ?", (service_id,))
                conn.commit()

        except Exception as e:
            logger.error(f"サービス登録解除エラー: {e}")

    def discover_service(self, service_name: str) -> List[str]:
        """
        サービスを検出
        Args:
            service_name: サービス名
        Returns:
            サービスURLリスト
        """
        if service_name in self.service_discovery_cache:
            return self.service_discovery_cache[service_name]

        # サービス名で検索
        matching_services = [
            service for service in self.services.values()
            if service_name.lower() in service.name.lower() and service.status == ServiceStatus.HEALTHY
        ]

        urls = [service.base_url for service in matching_services]

        # キャッシュに保存
        self.service_discovery_cache[service_name] = urls

        return urls

    def get_service_by_id(self, service_id: str) -> Optional[MicroService]:
        """
        サービスIDでサービスを取得
        Args:
            service_id: サービスID
        Returns:
            マイクロサービス情報（見つからない場合はNone）
        """
        return self.services.get(service_id)

    def update_service_health(self, service_id: str, status: ServiceStatus,
                            response_time: float = 0.0, error_rate: float = 0.0):
        """
        サービスヘルスを更新
        Args:
            service_id: サービスID
            status: ステータス
            response_time: レスポンスタイム
            error_rate: エラーレート
        """
        if service_id in self.services:
            service = self.services[service_id]
            service.status = status
            service.last_check = time.time()

            if response_time > 0:
                service.response_time = response_time

            if error_rate >= 0:
                service.error_rate = error_rate

            # 負荷スコアを計算
            service.load_score = self._calculate_load_score(service)

    def _calculate_load_score(self, service: MicroService) -> float:
        """負荷スコアを計算"""
        # レスポンスタイムとエラーレートに基づく簡易計算
        time_score = min(service.response_time / 1000, 1.0)  # 1秒以上は最大スコア
        error_score = service.error_rate

        return (time_score * 0.7) + (error_score * 0.3)


class LoadBalancer:
    """ロードバランサー"""

    def __init__(self, algorithm: str = "round_robin"):
        """
        初期化
        Args:
            algorithm: バランシングアルゴリズム
        """
        self.algorithm = algorithm
        self.service_endpoints: Dict[str, List[str]] = defaultdict(list)
        self.current_index: Dict[str, int] = defaultdict(int)
        self.endpoint_health: Dict[str, Dict[str, float]] = defaultdict(dict)

    def register_endpoint(self, service_name: str, endpoint: str):
        """
        エンドポイントを登録
        Args:
            service_name: サービス名
            endpoint: エンドポイントURL
        """
        if endpoint not in self.service_endpoints[service_name]:
            self.service_endpoints[service_name].append(endpoint)

    def select_endpoint(self, service_name: str) -> Optional[str]:
        """
        エンドポイントを選択
        Args:
            service_name: サービス名
        Returns:
            選択されたエンドポイント（見つからない場合はNone）
        """
        if service_name not in self.service_endpoints:
            return None

        endpoints = self.service_endpoints[service_name]

        if not endpoints:
            return None

        if self.algorithm == "round_robin":
            return self._round_robin_select(service_name, endpoints)
        elif self.algorithm == "least_connections":
            return self._least_connections_select(service_name, endpoints)
        elif self.algorithm == "weighted_response_time":
            return self._weighted_response_time_select(service_name, endpoints)
        else:
            return endpoints[0]  # デフォルトは最初のエンドポイント

    def _round_robin_select(self, service_name: str, endpoints: List[str]) -> str:
        """ラウンドロビン選択"""
        index = self.current_index[service_name]
        endpoint = endpoints[index % len(endpoints)]
        self.current_index[service_name] = index + 1
        return endpoint

    def _least_connections_select(self, service_name: str, endpoints: List[str]) -> str:
        """最小接続数選択"""
        # 簡易実装：レスポンスタイムで代用
        best_endpoint = endpoints[0]
        best_time = float('inf')

        for endpoint in endpoints:
            response_time = self.endpoint_health.get(service_name, {}).get(endpoint, 1000)
            if response_time < best_time:
                best_time = response_time
                best_endpoint = endpoint

        return best_endpoint

    def _weighted_response_time_select(self, service_name: str, endpoints: List[str]) -> str:
        """重み付きレスポンスタイム選択"""
        total_weight = 0
        weighted_endpoints = []

        for endpoint in endpoints:
            response_time = self.endpoint_health.get(service_name, {}).get(endpoint, 1000)
            weight = max(0.1, 1.0 / (response_time / 1000 + 0.1))  # レスポンスタイムが短いほど重みが高い
            weighted_endpoints.append((endpoint, weight))
            total_weight += weight

        # 重み付きランダム選択
        import random
        random_value = random.random() * total_weight

        current_weight = 0
        for endpoint, weight in weighted_endpoints:
            current_weight += weight
            if random_value <= current_weight:
                return endpoint

        return endpoints[0]  # フォールバック

    def update_endpoint_health(self, service_name: str, endpoint: str, response_time: float):
        """
        エンドポイントヘルスを更新
        Args:
            service_name: サービス名
            endpoint: エンドポイント
            response_time: レスポンスタイム
        """
        if service_name not in self.endpoint_health:
            self.endpoint_health[service_name] = {}

        self.endpoint_health[service_name][endpoint] = response_time


class CircuitBreaker:
    """サーキットブレーカー"""

    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 60.0):
        """
        初期化
        Args:
            failure_threshold: 失敗閾値
            recovery_timeout: 回復タイムアウト（秒）
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_counts: Dict[str, int] = defaultdict(int)
        self.last_failure_times: Dict[str, float] = defaultdict(float)
        self.circuit_states: Dict[str, str] = defaultdict(lambda: "closed")  # closed, open, half-open

    def is_request_allowed(self, service_name: str) -> bool:
        """
        リクエストが許可されるかをチェック
        Args:
            service_name: サービス名
        Returns:
            リクエスト許可フラグ
        """
        state = self.circuit_states[service_name]

        if state == "closed":
            return True
        elif state == "open":
            # 回復タイムアウトをチェック
            if time.time() - self.last_failure_times[service_name] > self.recovery_timeout:
                self.circuit_states[service_name] = "half-open"
                return True
            return False
        elif state == "half-open":
            return True

        return True

    def record_success(self, service_name: str):
        """
        成功を記録
        Args:
            service_name: サービス名
        """
        if self.circuit_states[service_name] == "half-open":
            # 半開放状態で成功したら閉じる
            self.circuit_states[service_name] = "closed"

        # 失敗カウントをリセット
        self.failure_counts[service_name] = 0

    def record_failure(self, service_name: str):
        """
        失敗を記録
        Args:
            service_name: サービス名
        """
        self.failure_counts[service_name] += 1
        self.last_failure_times[service_name] = time.time()

        # 失敗閾値を超えたら回路を開く
        if self.failure_counts[service_name] >= self.failure_threshold:
            self.circuit_states[service_name] = "open"
            logger.warning(f"サーキットブレーカーが開きました: {service_name}")


class APIGateway:
    """APIゲートウェイ"""

    def __init__(self, service_registry: ServiceRegistry, load_balancer: LoadBalancer, circuit_breaker: CircuitBreaker):
        """
        初期化
        Args:
            service_registry: サービスレジストリ
            load_balancer: ロードバランサー
            circuit_breaker: サーキットブレーカー
        """
        self.service_registry = service_registry
        self.load_balancer = load_balancer
        self.circuit_breaker = circuit_breaker
        self.request_middleware: List[Callable] = []
        self.response_middleware: List[Callable] = []

    async def route_request(self, request: ServiceRequest) -> ServiceResponse:
        """
        リクエストをルーティング
        Args:
            request: サービスリクエスト
        Returns:
            サービスレスポンス
        """
        start_time = time.time()

        try:
            # リクエストミドルウェア実行
            for middleware in self.request_middleware:
                try:
                    await middleware(request)
                except Exception as e:
                    logger.error(f"リクエストミドルウェアエラー: {e}")

            # サービス検出
            service_urls = self.service_registry.discover_service(request.service_id)

            if not service_urls:
                raise ValueError(f"サービスが見つかりません: {request.service_id}")

            # ロードバランサーでエンドポイントを選択
            target_url = self.load_balancer.select_endpoint(request.service_id)

            if not target_url:
                raise ValueError(f"利用可能なエンドポイントがありません: {request.service_id}")

            # サーキットブレーカーチェック
            if not self.circuit_breaker.is_request_allowed(request.service_id):
                raise ValueError(f"サービスが利用できません（サーキットブレーカー）: {request.service_id}")

            # リクエスト実行
            response = await self._execute_request(request, target_url)

            # レスポンスミドルウェア実行
            for middleware in self.response_middleware:
                try:
                    await middleware(response)
                except Exception as e:
                    logger.error(f"レスポンスミドルウェアエラー: {e}")

            # 成功を記録
            self.circuit_breaker.record_success(request.service_id)

            # エンドポイントヘルスを更新
            response_time = time.time() - start_time
            self.load_balancer.update_endpoint_health(request.service_id, target_url, response_time)

            return response

        except Exception as e:
            # 失敗を記録
            self.circuit_breaker.record_failure(request.service_id)

            logger.error(f"リクエスト実行エラー: {e}")

            return ServiceResponse(
                request_id=request.request_id,
                status_code=500,
                body={"error": str(e)},
                response_time=time.time() - start_time
            )

    async def _execute_request(self, request: ServiceRequest, target_url: str) -> ServiceResponse:
        """リクエストを実行"""
        full_url = f"{target_url.rstrip('/')}{request.endpoint}"

        # リクエストタイムアウト設定
        timeout = aiohttp.ClientTimeout(total=request.timeout)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                start_request_time = time.time()

                # リクエスト実行
                if request.method == RequestMethod.GET:
                    async with session.get(full_url, headers=request.headers) as response:
                        response_body = await response.text()
                        response_time = time.time() - start_request_time

                        return ServiceResponse(
                            request_id=request.request_id,
                            status_code=response.status,
                            headers=dict(response.headers),
                            body=response_body,
                            response_time=response_time
                        )

                elif request.method == RequestMethod.POST:
                    async with session.post(full_url, headers=request.headers, json=request.body) as response:
                        response_body = await response.text()
                        response_time = time.time() - start_request_time

                        return ServiceResponse(
                            request_id=request.request_id,
                            status_code=response.status,
                            headers=dict(response.headers),
                            body=response_body,
                            response_time=response_time
                        )

                # 他のHTTPメソッドも同様に実装可能

        except asyncio.TimeoutError:
            raise ValueError(f"リクエストタイムアウト: {request.timeout}秒")
        except Exception as e:
            raise ValueError(f"リクエスト実行エラー: {e}")

    def add_request_middleware(self, middleware: Callable):
        """
        リクエストミドルウェアを追加
        Args:
            middleware: ミドルウェア関数
        """
        self.request_middleware.append(middleware)

    def add_response_middleware(self, middleware: Callable):
        """
        レスポンスミドルウェアを追加
        Args:
            middleware: ミドルウェア関数
        """
        self.response_middleware.append(middleware)


class SystemIntegrationManager:
    """システム統合管理システム"""

    def __init__(self, db_path: str = "system_integration.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self.service_registry = ServiceRegistry(db_path)
        self.load_balancer = LoadBalancer()
        self.circuit_breaker = CircuitBreaker()
        self.api_gateway = APIGateway(self.service_registry, self.load_balancer, self.circuit_breaker)

        self.is_integration_active = False

    def initialize_integration_system(self):
        """統合システムを初期化"""
        # デフォルトのサービスを登録
        self._register_default_services()

        # デフォルトのミドルウェアを設定
        self._setup_default_middleware()

    def _register_default_services(self):
        """デフォルトのサービスを登録"""
        services = [
            MicroService(
                service_id="user_service",
                name="ユーザーサービス",
                base_url="http://localhost:8001",
                version="1.0.0",
                health_endpoint="/health"
            ),
            MicroService(
                service_id="payment_service",
                name="決済サービス",
                base_url="http://localhost:8002",
                version="1.0.0",
                health_endpoint="/health",
                dependencies=["user_service"]
            ),
            MicroService(
                service_id="notification_service",
                name="通知サービス",
                base_url="http://localhost:8003",
                version="1.0.0",
                health_endpoint="/health"
            )
        ]

        for service in services:
            self.service_registry.register_service(service)
            self.load_balancer.register_endpoint(service.name, service.base_url)

    def _setup_default_middleware(self):
        """デフォルトのミドルウェアを設定"""
        # 認証ミドルウェア
        async def auth_middleware(request: ServiceRequest):
            # 実際の実装ではトークン検証などを実行
            if "Authorization" not in request.headers:
                request.headers["Authorization"] = "Bearer default_token"

        # ログミドルウェア
        async def logging_middleware(request: ServiceRequest):
            logger.info(f"APIリクエスト: {request.method.value} {request.endpoint}")

        # レート制限ミドルウェア
        async def rate_limit_middleware(request: ServiceRequest):
            # 実際の実装ではレート制限チェックを実行
            pass

        self.api_gateway.add_request_middleware(auth_middleware)
        self.api_gateway.add_request_middleware(logging_middleware)
        self.api_gateway.add_request_middleware(rate_limit_middleware)

        # レスポンスログミドルウェア
        async def response_logging_middleware(response: ServiceResponse):
            logger.info(f"APIレスポンス: {response.status_code} ({response.response_time:.3f}s)")

        self.api_gateway.add_response_middleware(response_logging_middleware)

    def start_integration_system(self):
        """統合システムを開始"""
        if not self.is_integration_active:
            self.is_integration_active = True
            # 定期的なヘルスチェックを開始
            asyncio.create_task(self._health_check_loop())

    def stop_integration_system(self):
        """統合システムを停止"""
        self.is_integration_active = False

    def register_service(self, service_id: str, name: str, base_url: str, version: str = "1.0.0"):
        """
        サービスを登録
        Args:
            service_id: サービスID
            name: サービス名
            base_url: ベースURL
            version: バージョン
        """
        service = MicroService(
            service_id=service_id,
            name=name,
            base_url=base_url,
            version=version
        )

        self.service_registry.register_service(service)
        self.load_balancer.register_endpoint(name, base_url)

    async def make_request(self, service_name: str, method: RequestMethod, endpoint: str,
                          headers: Dict[str, str] = None, body: Any = None,
                          timeout: float = 30.0) -> ServiceResponse:
        """
        リクエストを実行
        Args:
            service_name: サービス名
            method: HTTPメソッド
            endpoint: エンドポイント
            headers: ヘッダー
            body: リクエストボディ
            timeout: タイムアウト
        Returns:
            サービスレスポンス
        """
        request = ServiceRequest(
            request_id=str(uuid.uuid4()),
            service_id=service_name,
            method=method,
            endpoint=endpoint,
            headers=headers or {},
            body=body,
            timeout=timeout
        )

        return await self.api_gateway.route_request(request)

    def get_integration_status(self) -> Dict[str, Any]:
        """統合ステータスを取得"""
        healthy_services = len([
            service for service in self.service_registry.services.values()
            if service.status == ServiceStatus.HEALTHY
        ])

        return {
            "is_active": self.is_integration_active,
            "total_services": len(self.service_registry.services),
            "healthy_services": healthy_services,
            "unhealthy_services": len(self.service_registry.services) - healthy_services,
            "circuit_breaker_states": dict(self.circuit_breaker.circuit_states)
        }

    async def _health_check_loop(self):
        """ヘルスチェックループ"""
        while self.is_integration_active:
            try:
                await self._perform_health_checks()
                await asyncio.sleep(30.0)  # 30秒間隔
            except Exception as e:
                logger.error(f"ヘルスチェックループエラー: {e}")

    async def _perform_health_checks(self):
        """ヘルスチェックを実行"""
        for service_id, service in self.service_registry.services.items():
            try:
                # ヘルスチェックエンドポイントにリクエスト
                health_url = f"{service.base_url}{service.health_endpoint}"
                start_time = time.time()

                async with aiohttp.ClientSession() as session:
                    async with session.get(health_url, timeout=aiohttp.ClientTimeout(total=5.0)) as response:
                        response_time = time.time() - start_time

                        if response.status == 200:
                            status = ServiceStatus.HEALTHY
                            error_rate = 0.0
                        else:
                            status = ServiceStatus.DEGRADED
                            error_rate = 0.5

                        self.service_registry.update_service_health(
                            service_id, status, response_time, error_rate
                        )

            except Exception as e:
                logger.error(f"ヘルスチェックエラー: {service_id} - {e}")
                self.service_registry.update_service_health(
                    service_id, ServiceStatus.UNHEALTHY, 0.0, 1.0
                )


# 使用例
async def example_usage():
    manager = SystemIntegrationManager()

    # システム初期化
    manager.initialize_integration_system()

    # システム開始
    manager.start_integration_system()

    # 追加のサービス登録
    manager.register_service(
        "analytics_service",
        "アナリティクスサービス",
        "http://localhost:8004"
    )

    # リクエスト実行のテスト
    try:
        response = await manager.make_request(
            "ユーザーサービス",
            RequestMethod.GET,
            "/users/123"
        )

        print(f"レスポンス: {response.status_code} - {response.response_time:.3f}s")
        print(f"ボディ: {response.body}")

    except Exception as e:
        print(f"リクエストエラー: {e}")

    # 統合ステータス表示
    status = manager.get_integration_status()
    print(f"統合ステータス: {status}")

    manager.stop_integration_system()


if __name__ == "__main__":
    asyncio.run(example_usage())
