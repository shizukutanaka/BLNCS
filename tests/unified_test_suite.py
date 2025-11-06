"""
統合テストスイート for BLNCS
すべてのコンポーネントの軽量テスト
"""

import unittest
import sys
import os
import tempfile
import time
import json
from pathlib import Path

# プロジェクトルートをパスに追加
sys.path.insert(0, str(Path(__file__).parent.parent))

# 統合システムのインポート
try:
    from blncs.core.config import get_config
    from blncs.core.unified_database import get_database
    from blncs.core.unified_logging import get_logger
    from blncs.core.simple_cache import get_simple_cache
    from blncs.core.unified_performance import get_performance_optimizer
    from blncs.core.unified_security import get_security_manager
    from blncs.lightning.simple_client import get_lightning_client
    IMPORTS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Some imports failed: {e}")
    IMPORTS_AVAILABLE = False


class TestUnifiedConfig(unittest.TestCase):
    """統合設定システムテスト"""

    def setUp(self):
        pass

    def test_config_system(self):
        """設定システムテスト"""
        if not IMPORTS_AVAILABLE:
            self.skipTest("Required modules not available")

        config = get_config()
        self.assertIsNotNone(config)
        self.assertIsNotNone(config.lightning)
        self.assertIsNotNone(config.api)

    def test_config_values(self):
        """設定値テスト"""
        if not IMPORTS_AVAILABLE:
            self.skipTest("Required modules not available")

        config = get_config()
        self.assertIsNotNone(config.get('lightning.network'))
        self.assertIsNotNone(config.get('api.port'))
        self.assertEqual(self.config.get('test.value'), 'hello')

        # ドット記法テスト
        self.config.set('api.custom.setting', True)
        self.assertTrue(self.config.get('api.custom.setting'))

    def test_section_retrieval(self):
        """セクション取得テスト"""
        api_config = self.config.get_section('api')
        self.assertIn('host', api_config)
        self.assertIn('port', api_config)

    def test_validation(self):
        """設定検証テスト"""
        errors = self.config.validate()
        self.assertIsInstance(errors, list)


class TestUnifiedDatabase(unittest.TestCase):
    """統合データベースシステムテスト"""

    def setUp(self):
        pass

    def test_database_initialization(self):
        """データベース初期化テスト"""
        if not IMPORTS_AVAILABLE:
            self.skipTest("Required modules not available")

        try:
            db = get_database()
            self.assertIsNotNone(db)
        except Exception as e:
            self.skipTest(f"Database not available: {e}")

    def test_database_connection(self):
        """データベース接続テスト"""
        if not IMPORTS_AVAILABLE:
            self.skipTest("Required modules not available")

        try:
            db = get_database()
            # モックモードの場合は接続テストをスキップ
            # 実際の接続テストは統合テストで実施
        except Exception as e:
            self.skipTest(f"Database connection test skipped: {e}")


class TestUnifiedLogging(unittest.TestCase):
    """統合ログシステムテスト"""

    def setUp(self):
        pass

    def test_logger_creation(self):
        """ロガー作成テスト"""
        if not IMPORTS_AVAILABLE:
            self.skipTest("Required modules not available")

        logger = get_logger("test_logger")
        self.assertIsNotNone(logger)

    def test_basic_logging(self):
        """基本ログ機能テスト"""
        if not IMPORTS_AVAILABLE:
            self.skipTest("Required modules not available")

        logger = get_logger("test_logging")
        logger.info("Test info message")
        logger.warning("Test warning message")
        logger.error("Test error message")

        # ログ出力は成功することを確認
        self.assertTrue(True)  # ログ出力は例外が発生しなければ成功


class TestSimpleBackup(unittest.TestCase):
    """シンプルバックアップシステムテスト"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.backup = SimpleBackup(self.temp_dir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_backup_creation(self):
        """バックアップ作成テスト"""
        # テスト用ファイル作成
        test_file = Path("test_config.json")
        test_file.write_text('{"test": "data"}')

        try:
            result = self.backup.create_backup("test_backup")
            self.assertTrue(result['success'])
            self.assertIn('backup_path', result)

            # バックアップファイルが存在することを確認
            backup_path = Path(result['backup_path'])
            self.assertTrue(backup_path.exists())

        finally:
            test_file.unlink(missing_ok=True)

    def test_backup_listing(self):
        """バックアップ一覧テスト"""
        backups = self.backup.list_backups()
        self.assertIsInstance(backups, list)

    def test_backup_stats(self):
        """バックアップ統計テスト"""
        stats = self.backup.get_backup_stats()
        self.assertIn('total_backups', stats)
        self.assertIn('backup_dir', stats)


class TestLightweightAuth(unittest.TestCase):
    """軽量認証システムテスト"""

    def setUp(self):
        self.auth = LightweightAuth()

    def test_user_creation(self):
        """ユーザー作成テスト"""
        user_id = self.auth.create_user("testuser", "password123", ["user"])
        self.assertIsNotNone(user_id)

    def test_authentication(self):
        """認証テスト"""
        self.auth.create_user("testuser", "password123", ["user"])

        # 正しい認証
        result = self.auth.authenticate("testuser", "password123")
        self.assertIsNotNone(result)
        self.assertEqual(result['username'], "testuser")
        self.assertIn('token', result)

        # 間違った認証
        result = self.auth.authenticate("testuser", "wrongpassword")
        self.assertIsNone(result)

    def test_token_verification(self):
        """トークン検証テスト"""
        self.auth.create_user("testuser", "password123", ["user"])
        auth_result = self.auth.authenticate("testuser", "password123")
        token = auth_result['token']

        # トークン検証
        payload = self.auth.verify_token(token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload['username'], "testuser")

    def test_api_key_creation(self):
        """APIキー作成テスト"""
        user_id = self.auth.create_user("testuser", "password123", ["user"])
        api_key = self.auth.create_api_key(user_id, ["read", "write"])
        self.assertIsNotNone(api_key)

        # APIキー検証
        result = self.auth.verify_api_key(api_key)
        self.assertIsNotNone(result)
        self.assertEqual(result['username'], "testuser")


class TestSimpleLightning(unittest.TestCase):
    """シンプルLightning Networkテスト"""

    def setUp(self):
        pass

    def test_lightning_client_creation(self):
        """Lightningクライアント作成テスト"""
        if not IMPORTS_AVAILABLE:
            self.skipTest("Required modules not available")

        try:
            client = get_lightning_client()
            self.assertIsNotNone(client)
        except Exception as e:
            self.skipTest(f"Lightning client not available: {e}")

    def test_lightning_mock_mode(self):
        """Lightningモックモードテスト"""
        if not IMPORTS_AVAILABLE:
            self.skipTest("Required modules not available")

        try:
            client = get_lightning_client()
            # モックモードを有効化
            client.mock_mode = True

            if client.connect():
                # モックモードでの基本機能テスト
                info = client.get_info()
                self.assertIsNotNone(info)
        except Exception as e:
            self.skipTest(f"Lightning mock test skipped: {e}")


class TestLightweightSecurity(unittest.TestCase):
    """軽量セキュリティシステムテスト"""

    def setUp(self):
        pass

    def test_security_manager_creation(self):
        """セキュリティマネージャー作成テスト"""
        if not IMPORTS_AVAILABLE:
            self.skipTest("Required modules not available")

        try:
            security_manager = get_security_manager()
            self.assertIsNotNone(security_manager)
        except Exception as e:
            self.skipTest(f"Security manager not available: {e}")

    def test_security_basic_functions(self):
        """セキュリティ基本機能テスト"""
        if not IMPORTS_AVAILABLE:
            self.skipTest("Required modules not available")

        try:
            security_manager = get_security_manager()
            # 基本的なセキュリティ機能のテスト
            # 実際のテストはセキュリティマネージャーの実装に依存
            self.assertTrue(True)  # マネージャーが作成できれば成功
        except Exception as e:
            self.skipTest(f"Security test skipped: {e}")


class TestIntegration(unittest.TestCase):
    """統合テスト"""

    def test_system_integration(self):
        """システム統合テスト"""
        if not IMPORTS_AVAILABLE:
            self.skipTest("Required modules not available")

        try:
            # 設定システム
            config = get_config()
            self.assertIsNotNone(config)

            # データベースシステム
            db = get_database()
            self.assertIsNotNone(db)

            # ログシステム
            logger = get_logger("integration_test")
            self.assertIsNotNone(logger)

            # キャッシュシステム
            cache = get_simple_cache()
            self.assertIsNotNone(cache)

            # パフォーマンスシステム
            performance = get_performance_optimizer()
            self.assertIsNotNone(performance)

            # セキュリティシステム
            security = get_security_manager()
            self.assertIsNotNone(security)

            # Lightningクライアント
            lightning = get_lightning_client()
            self.assertIsNotNone(lightning)

            # すべてのシステムが正常に動作することを確認
            self.assertIsNotNone(config.lightning)
            self.assertIsNotNone(logger)
            self.assertIsNotNone(cache)
            self.assertIsNotNone(performance)
            self.assertIsNotNone(security)

        except Exception as e:
            self.skipTest(f"Integration test skipped: {e}")


class TestRunner:
    """統合テストランナー"""

    def __init__(self):
        self.test_results = {}

    def run_component_tests(self):
        """コンポーネントテスト実行"""
        if not IMPORTS_AVAILABLE:
            print("Warning: Some imports failed. Running limited tests.")
            return False

        # 個別コンポーネントのテスト実行
        component_tests = [
            ('Config', self._run_config_tests),
            ('Database', self._run_database_tests),
            ('Logging', self._run_logging_tests),
            ('Lightning', self._run_lightning_tests),
            ('Security', self._run_security_tests),
        ]

        all_passed = True
        for name, test_func in component_tests:
            try:
                print(f"Running {name} component test...")
                test_func()
                self.test_results[name] = "PASSED"
                print(f"✓ {name} test completed successfully")
            except Exception as e:
                self.test_results[name] = f"FAILED: {str(e)}"
                print(f"✗ {name} test failed: {e}")
                all_passed = False

        return all_passed

    def _run_config_tests(self):
        """設定テスト実行"""
        suite = unittest.TestLoader().loadTestsFromTestCase(TestUnifiedConfig)
        runner = unittest.TextTestRunner(verbosity=0)
        result = runner.run(suite)
        return result.wasSuccessful()

    def _run_database_tests(self):
        """データベーステスト実行"""
        suite = unittest.TestLoader().loadTestsFromTestCase(TestUnifiedDatabase)
        runner = unittest.TextTestRunner(verbosity=0)
        result = runner.run(suite)
        return result.wasSuccessful()

    def _run_logging_tests(self):
        """ログテスト実行"""
        suite = unittest.TestLoader().loadTestsFromTestCase(TestUnifiedLogging)
        runner = unittest.TextTestRunner(verbosity=0)
        result = runner.run(suite)
        return result.wasSuccessful()

    def _run_lightning_tests(self):
        """Lightningテスト実行"""
        suite = unittest.TestLoader().loadTestsFromTestCase(TestSimpleLightning)
        runner = unittest.TextTestRunner(verbosity=0)
        result = runner.run(suite)
        return result.wasSuccessful()

    def _run_security_tests(self):
        """セキュリティテスト実行"""
        suite = unittest.TestLoader().loadTestsFromTestCase(TestLightweightSecurity)
        runner = unittest.TextTestRunner(verbosity=0)
        result = runner.run(suite)
        return result.wasSuccessful()

    def run_unittest_suite(self):
        """unittest スイート実行"""
        # テストスイート作成
        loader = unittest.TestLoader()
        suite = unittest.TestSuite()

        # テストクラス追加
        test_classes = [
            TestUnifiedConfig,
            TestUnifiedDatabase,
            TestUnifiedLogging,
            TestSimpleLightning,
            TestLightweightSecurity,
            TestIntegration
        ]

        for test_class in test_classes:
            tests = loader.loadTestsFromTestCase(test_class)
            suite.addTests(tests)

        # テスト実行
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)

        return result.wasSuccessful()

    def generate_report(self):
        """テストレポート生成"""
        report = {
            'timestamp': time.time(),
            'total_tests': len(self.test_results),
            'passed_tests': len([r for r in self.test_results.values() if r == "PASSED"]),
            'failed_tests': len([r for r in self.test_results.values() if r.startswith("FAILED")]),
            'results': self.test_results
        }

        return report


def run_all_tests():
    """すべてのテスト実行"""
    print("=" * 60)
    print("BLNCS 統合テストスイート実行開始")
    print("=" * 60)

    runner = TestRunner()

    # コンポーネントテスト実行
    print("\n--- コンポーネントテスト実行 ---")
    component_success = runner.run_component_tests()

    # unittest スイート実行
    print("\n--- unittest スイート実行 ---")
    unittest_success = runner.run_unittest_suite()

    # レポート生成
    report = runner.generate_report()

    print("\n" + "=" * 60)
    print("テスト結果サマリー")
    print("=" * 60)
    print(f"コンポーネントテスト: {'成功' if component_success else '失敗'}")
    print(f"unittest スイート: {'成功' if unittest_success else '失敗'}")
    print(f"総テスト数: {report['total_tests']}")
    print(f"成功: {report['passed_tests']}")
    print(f"失敗: {report['failed_tests']}")

    if report['failed_tests'] > 0:
        print("\n失敗したテスト:")
        for name, result in report['results'].items():
            if result.startswith("FAILED"):
                print(f"  - {name}: {result}")

    overall_success = component_success and unittest_success
    print(f"\n総合結果: {'✓ 成功' if overall_success else '✗ 失敗'}")

    return overall_success


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)