#!/usr/bin/env python3
"""BLRCS包括的テストスイート"""

import asyncio
import pytest
import time
import sqlite3
from pathlib import Path
import sys
import os

# プロジェクトルートをパスに追加
sys.path.insert(0, str(Path(__file__).parent))

from blrcs.rate_limiter import RateLimiter, RateLimitConfig
from blrcs.csrf_protection import CSRFProtection
from blrcs.input_validator import InputValidator, ValidationRule
from blrcs.password_policy import PasswordPolicy
from blrcs.security_headers import SecurityHeaders
from blrcs.database_optimizer import DatabaseOptimizer, ConnectionPool
from blrcs.cache_strategy import CacheManager, CacheStrategy
from blrcs.health_check import HealthChecker
from blrcs.secrets_manager import SecretsManager

class TestSecurityComponents:
    """セキュリティコンポーネントテスト"""
    
    def test_rate_limiter(self):
        """レート制限テスト"""
        config = RateLimitConfig(
            requests_per_second=5,
            requests_per_minute=20,
            burst_size=10
        )
        limiter = RateLimiter(config)
        
        # 正常なリクエスト
        for _ in range(5):
            allowed, msg = asyncio.run(limiter.check_rate_limit("127.0.0.1"))
            assert allowed is True
            
        # レート超過
        for _ in range(10):
            asyncio.run(limiter.check_rate_limit("127.0.0.1"))
            
        allowed, msg = asyncio.run(limiter.check_rate_limit("127.0.0.1"))
        assert allowed is False
        assert "Rate limit exceeded" in msg
        
    def test_csrf_protection(self):
        """CSRF保護テスト"""
        csrf = CSRFProtection()
        session_id = "test_session_123"
        
        # トークン生成
        token = csrf.generate_token(session_id)
        assert token is not None
        assert len(token) > 32
        
        # トークン検証
        valid, msg = csrf.validate_token(session_id, token)
        assert valid is True
        
        # 無効なトークン
        valid, msg = csrf.validate_token(session_id, "invalid_token")
        assert valid is False
        
        # 使用済みトークン（ワンタイム）
        valid, msg = csrf.validate_token(session_id, token)
        assert valid is False
        
    def test_input_validator(self):
        """入力検証テスト"""
        validator = InputValidator()
        
        # SQLインジェクション検出
        malicious_input = "'; DROP TABLE users; --"
        valid, errors = validator.validate_input(
            malicious_input,
            ValidationRule(field_name="test", data_type=str)
        )
        assert valid is False
        assert any("SQL injection" in error for error in errors)
        
        # XSS検出
        xss_input = "<script>alert('XSS')</script>"
        valid, errors = validator.validate_input(
            xss_input,
            ValidationRule(field_name="test", data_type=str)
        )
        assert valid is False
        assert any("XSS" in error for error in errors)
        
        # 正常な入力
        normal_input = "Normal text input"
        valid, errors = validator.validate_input(
            normal_input,
            ValidationRule(field_name="test", data_type=str, max_length=100)
        )
        assert valid is True
        
    def test_password_policy(self):
        """パスワードポリシーテスト"""
        policy = PasswordPolicy()
        
        # 弱いパスワード
        weak_passwords = [
            "password",
            "12345678",
            "qwerty123",
            "admin123"
        ]
        
        for pwd in weak_passwords:
            valid, errors = policy.validate_password(pwd)
            assert valid is False
            
        # 強いパスワード - 動的生成
        import secrets
        import string
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        strong_password = 'Te$t' + ''.join(secrets.choice(chars) for _ in range(12))
        valid, errors = policy.validate_password(strong_password)
        assert valid is True
        
        # パスワード生成
        generated = policy.generate_strong_password(16)
        assert len(generated) == 16
        valid, errors = policy.validate_password(generated)
        assert valid is True
        
    def test_security_headers(self):
        """セキュリティヘッダーテスト"""
        headers_manager = SecurityHeaders()
        headers = headers_manager.get_headers()
        
        # 必須ヘッダーの確認
        assert "Strict-Transport-Security" in headers
        assert "Content-Security-Policy" in headers
        assert "X-Frame-Options" in headers
        assert "X-Content-Type-Options" in headers
        assert headers["X-Content-Type-Options"] == "nosniff"

class TestPerformanceComponents:
    """パフォーマンスコンポーネントテスト"""
    
    def test_database_optimizer(self):
        """データベース最適化テスト"""
        # テスト用DB作成
        test_db = "test_optimize.db"
        conn = sqlite3.connect(test_db)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS test_table (
                id INTEGER PRIMARY KEY,
                name TEXT,
                value INTEGER
            )
        """)
        
        # テストデータ挿入
        for i in range(100):
            conn.execute(
                "INSERT INTO test_table (name, value) VALUES (?, ?)",
                (f"name_{i}", i * 10)
            )
        conn.commit()
        conn.close()
        
        # オプティマイザーテスト
        optimizer = DatabaseOptimizer(test_db)
        
        # クエリ記録
        query = "SELECT * FROM test_table WHERE value > 500"
        optimizer.record_query_execution(query, 0.05)
        
        # 統計更新
        asyncio.run(optimizer.update_statistics())
        
        # クリーンアップ
        os.remove(test_db)
        
    def test_connection_pool(self):
        """接続プールテスト"""
        pool = ConnectionPool("test_pool.db", pool_size=5)
        
        # 接続取得
        connections = []
        for _ in range(3):
            conn = pool.acquire()
            assert conn is not None
            connections.append(conn)
            
        # 接続返却
        for conn in connections:
            pool.release(conn)
            
        # 再取得
        conn = pool.acquire()
        assert conn is not None
        pool.release(conn)
        
        # クリーンアップ
        pool.close_all()
        if os.path.exists("test_pool.db"):
            os.remove("test_pool.db")
            
    def test_cache_manager(self):
        """キャッシュマネージャーテスト"""
        cache = CacheManager(max_size=1024*1024, strategy=CacheStrategy.LRU)
        
        # キャッシュ設定
        asyncio.run(cache.set("key1", "value1", ttl=60))
        asyncio.run(cache.set("key2", {"data": "complex"}, ttl=60))
        
        # キャッシュ取得
        value1 = asyncio.run(cache.get("key1"))
        assert value1 == "value1"
        
        value2 = asyncio.run(cache.get("key2"))
        assert value2["data"] == "complex"
        
        # 存在しないキー
        value3 = asyncio.run(cache.get("key3", "default"))
        assert value3 == "default"
        
        # ヒット率確認
        hit_rate = cache.get_hit_rate()
        assert hit_rate > 0
        
        # 統計情報
        stats = cache.get_stats()
        assert stats["hit_count"] == 2
        assert stats["miss_count"] == 1

class TestHealthAndMonitoring:
    """ヘルスチェックと監視テスト"""
    
    @pytest.mark.asyncio
    async def test_health_checker(self):
        """ヘルスチェッカーテスト"""
        checker = HealthChecker()
        
        # 全体チェック
        result = await checker.check_all(use_cache=False)
        
        assert "status" in result
        assert "timestamp" in result
        assert "components" in result
        
        # コンポーネント確認
        component_names = [c["name"] for c in result["components"]]
        assert "database" in component_names
        assert "cache" in component_names
        assert "disk_space" in component_names
        assert "memory" in component_names
        assert "cpu" in component_names
        
    def test_secrets_manager(self):
        """シークレットマネージャーテスト"""
        secrets = SecretsManager(master_key="test_master_key_123")
        
        # シークレット設定
        secrets.set_secret("API_KEY", "secret_api_key_123")
        secrets.set_secret("DB_PASSWORD", "secret_password")
        
        # シークレット取得
        api_key = secrets.get_secret("API_KEY")
        assert api_key == "secret_api_key_123"
        
        db_password = secrets.get_secret("DB_PASSWORD")
        assert db_password == "secret_password"
        
        # 存在しないキー
        missing = secrets.get_secret("MISSING_KEY", "default")
        assert missing == "default"

class TestIntegration:
    """統合テスト"""
    
    @pytest.mark.asyncio
    async def test_security_middleware_flow(self):
        """セキュリティミドルウェアフロー"""
        # レート制限 + CSRF + 入力検証の統合テスト
        
        limiter = RateLimiter()
        csrf = CSRFProtection()
        validator = InputValidator()
        
        # リクエストシミュレーション
        ip = "192.168.1.1"
        session_id = "session_123"
        
        # 1. レート制限チェック
        allowed, _ = await limiter.check_rate_limit(ip)
        assert allowed is True
        
        # 2. CSRFトークン生成と検証
        token = csrf.generate_token(session_id)
        valid, _ = csrf.validate_token(session_id, token)
        assert valid is True
        
        # 3. 入力検証
        user_input = "valid_username_123"
        rule = ValidationRule(
            field_name="username",
            data_type=str,
            min_length=3,
            max_length=50,
            pattern=r"^[a-zA-Z0-9_]+$"
        )
        valid, _ = validator.validate_input(user_input, rule)
        assert valid is True
        
    @pytest.mark.asyncio
    async def test_performance_optimization_flow(self):
        """パフォーマンス最適化フロー"""
        # キャッシュ + DB最適化の統合テスト
        
        cache = CacheManager()
        
        # キャッシュミス時のDB取得シミュレーション
        async def fetch_from_db(key: str):
            # 疑似的なDB取得
            await asyncio.sleep(0.01)  # DBレイテンシ
            return f"data_for_{key}"
            
        # 初回取得（キャッシュミス）
        start = time.time()
        data = await cache.get("test_key")
        if data is None:
            data = await fetch_from_db("test_key")
            await cache.set("test_key", data)
        first_time = time.time() - start
        
        # 2回目取得（キャッシュヒット）
        start = time.time()
        cached_data = await cache.get("test_key")
        second_time = time.time() - start
        
        assert cached_data == data
        assert second_time < first_time  # キャッシュの方が高速

def run_all_tests():
    """全テスト実行"""
    print("=" * 60)
    print("BLRCS 包括的テスト実行")
    print("=" * 60)
    
    # pytest実行
    exit_code = pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "--color=yes"
    ])
    
    if exit_code == 0:
        print("\n✅ 全テスト成功!")
    else:
        print("\n❌ テスト失敗")
        
    return exit_code

if __name__ == "__main__":
    sys.exit(run_all_tests())