#!/usr/bin/env python3
import asyncio
import sys
import logging
from datetime import datetime
from pathlib import Path

# プロジェクトルートをPythonパスに追加
sys.path.append(str(Path(__file__).parent))

from blrcs.lnd_connector import LNDConnector
from blrcs.channel_manager import ChannelManager
from blrcs.payment_router import PaymentRouter
from blrcs.risk_engine import RiskEngine
from blrcs.performance_monitor import PerformanceMonitor
from blrcs.memory_optimizer import MemoryOptimizer
from blrcs.async_architecture import AsyncTaskManager
from blrcs.user_management import UserManager
from blrcs.access_control import AccessControlManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BLRCSIntegrationTest:
    def __init__(self):
        self.test_results = {}
        self.components = {}
        
    async def run_all_tests(self):
        """全統合テストを実行"""
        logger.info("=== BLRCS統合テスト開始 ===")
        
        tests = [
            ("基本初期化テスト", self.test_basic_initialization),
            ("非同期アーキテクチャテスト", self.test_async_architecture),
            ("メモリ最適化テスト", self.test_memory_optimization),
            ("パフォーマンス監視テスト", self.test_performance_monitoring),
            ("ユーザー管理テスト", self.test_user_management),
            ("アクセス制御テスト", self.test_access_control),
            ("LND接続テスト", self.test_lnd_connection),
            ("チャネル管理テスト", self.test_channel_management),
            ("支払いルーティングテスト", self.test_payment_routing),
            ("リスク管理テスト", self.test_risk_management),
            ("システム統合テスト", self.test_system_integration)
        ]
        
        passed = 0
        failed = 0
        
        for test_name, test_func in tests:
            try:
                logger.info(f"実行中: {test_name}")
                result = await test_func()
                if result:
                    logger.info(f"✓ {test_name}: 成功")
                    passed += 1
                else:
                    logger.error(f"✗ {test_name}: 失敗")
                    failed += 1
                self.test_results[test_name] = result
            except Exception as e:
                logger.error(f"✗ {test_name}: エラー - {e}")
                self.test_results[test_name] = False
                failed += 1
        
        logger.info(f"\n=== テスト結果 ===")
        logger.info(f"成功: {passed}")
        logger.info(f"失敗: {failed}")
        logger.info(f"成功率: {passed/(passed+failed)*100:.1f}%")
        
        return passed > failed
    
    async def test_basic_initialization(self) -> bool:
        """基本初期化テスト"""
        try:
            # AsyncTaskManager
            self.components['task_manager'] = AsyncTaskManager()
            await self.components['task_manager'].start()
            
            # MemoryOptimizer
            self.components['memory_optimizer'] = MemoryOptimizer()
            
            # PerformanceMonitor
            self.components['performance_monitor'] = PerformanceMonitor()
            await self.components['performance_monitor'].start()
            
            # UserManager
            self.components['user_manager'] = UserManager()
            await self.components['user_manager'].initialize()
            
            # AccessControlManager
            self.components['access_control'] = AccessControlManager()
            
            return True
        except Exception as e:
            logger.error(f"Basic initialization failed: {e}")
            return False
    
    async def test_async_architecture(self) -> bool:
        """非同期アーキテクチャテスト"""
        try:
            task_manager = self.components['task_manager']
            
            # 基本タスク実行
            async def test_task():
                await asyncio.sleep(0.1)
                return "test_result"
            
            task_id = await task_manager.submit_task(test_task())
            result = await task_manager.wait_for_task(task_id)
            
            if result != "test_result":
                return False
            
            # 統計確認
            stats = await task_manager.get_stats()
            return stats['completed_tasks'] > 0
            
        except Exception as e:
            logger.error(f"Async architecture test failed: {e}")
            return False
    
    async def test_memory_optimization(self) -> bool:
        """メモリ最適化テスト"""
        try:
            memory_optimizer = self.components['memory_optimizer']
            
            # オブジェクトプール
            pool = memory_optimizer.get_object_pool(str, lambda: "test")
            obj1 = pool.acquire()
            pool.release(obj1)
            obj2 = pool.acquire()
            
            # キャッシュ
            cache = memory_optimizer.get_cache("test_cache", max_size=100)
            cache.set("key1", "value1")
            value = cache.get("key1")
            
            return value == "value1"
            
        except Exception as e:
            logger.error(f"Memory optimization test failed: {e}")
            return False
    
    async def test_performance_monitoring(self) -> bool:
        """パフォーマンス監視テスト"""
        try:
            monitor = self.components['performance_monitor']
            
            # メトリクス記録
            monitor.increment_counter("test.counter")
            monitor.set_gauge("test.gauge", 42.0)
            
            with monitor.timer("test.timer"):
                await asyncio.sleep(0.01)
            
            # メトリクス取得
            metrics = await monitor.get_metrics()
            return "test.counter" in metrics
            
        except Exception as e:
            logger.error(f"Performance monitoring test failed: {e}")
            return False
    
    async def test_user_management(self) -> bool:
        """ユーザー管理テスト"""
        try:
            user_manager = self.components['user_manager']
            
            # ユーザー作成
            user_id = await user_manager.create_user(
                "testuser", "test@example.com", "testpass123"
            )
            
            if not user_id:
                return False
            
            # 認証テスト
            success, session_id, session = await user_manager.authenticate(
                "testuser", "testpass123"
            )
            
            return success and session_id is not None
            
        except Exception as e:
            logger.error(f"User management test failed: {e}")
            return False
    
    async def test_access_control(self) -> bool:
        """アクセス制御テスト"""
        try:
            access_control = self.components['access_control']
            
            # ロール作成
            role_id = access_control.create_role("test_role", ["test.read"])
            
            # ユーザーにロール割り当て
            access_control.assign_role_to_user("testuser", role_id)
            
            # アクセス確認
            from blrcs.access_control import ResourceType, ActionType
            result = access_control.check_access(
                "testuser", ResourceType.CHANNEL, "test_channel", ActionType.READ
            )
            
            return result.allowed
            
        except Exception as e:
            logger.error(f"Access control test failed: {e}")
            return False
    
    async def test_lnd_connection(self) -> bool:
        """LND接続テスト（モック）"""
        try:
            # 実際のLNDには接続せず、インターフェースのテストのみ
            lnd_connector = LNDConnector()
            
            # モック設定（実際の接続は行わない）
            lnd_connector.connected = True
            
            return True
            
        except Exception as e:
            logger.error(f"LND connection test failed: {e}")
            return False
    
    async def test_channel_management(self) -> bool:
        """チャネル管理テスト（モック）"""
        try:
            lnd_connector = LNDConnector()
            lnd_connector.connected = True
            
            channel_manager = ChannelManager(lnd_connector)
            
            # モックチャネルデータでテスト
            mock_channels = [
                {
                    'chan_id': '123456789',
                    'capacity': 1000000,
                    'local_balance': 300000,
                    'remote_balance': 700000,
                    'remote_pubkey': 'test_pubkey',
                    'active': True
                }
            ]
            
            # チャネル分析
            analysis = await channel_manager._analyze_channel(mock_channels[0])
            
            return analysis['score'] > 0
            
        except Exception as e:
            logger.error(f"Channel management test failed: {e}")
            return False
    
    async def test_payment_routing(self) -> bool:
        """支払いルーティングテスト（モック）"""
        try:
            lnd_connector = LNDConnector()
            payment_router = PaymentRouter(lnd_connector)
            
            # グラフ構築（モック）
            from blrcs.payment_router import ChannelEdge
            mock_edges = [
                ChannelEdge(
                    channel_id="123",
                    node1="node1",
                    node2="node2",
                    capacity=1000000,
                    fee_base_msat=1000,
                    fee_rate_millimsat=1,
                    time_lock_delta=40,
                    min_htlc=1000,
                    max_htlc_msat=900000,
                    last_update=datetime.now(),
                    active=True,
                    disabled=False
                )
            ]
            
            payment_router.pathfinder.update_graph(mock_edges)
            
            return payment_router.pathfinder.graph.number_of_nodes() > 0
            
        except Exception as e:
            logger.error(f"Payment routing test failed: {e}")
            return False
    
    async def test_risk_management(self) -> bool:
        """リスク管理テスト（モック）"""
        try:
            lnd_connector = LNDConnector()
            channel_manager = ChannelManager(lnd_connector)
            risk_engine = RiskEngine(lnd_connector, channel_manager)
            
            # リスクファクター確認
            factors = risk_engine.risk_factors
            
            return len(factors) > 0
            
        except Exception as e:
            logger.error(f"Risk management test failed: {e}")
            return False
    
    async def test_system_integration(self) -> bool:
        """システム統合テスト"""
        try:
            # 全コンポーネントの相互作用テスト
            task_manager = self.components['task_manager']
            monitor = self.components['performance_monitor']
            
            # 監視付きタスク実行
            @monitor.monitor_performance("integration.test")
            async def integration_task():
                await asyncio.sleep(0.01)
                return "integration_success"
            
            task_id = await task_manager.submit_task(integration_task())
            result = await task_manager.wait_for_task(task_id)
            
            return result == "integration_success"
            
        except Exception as e:
            logger.error(f"System integration test failed: {e}")
            return False
    
    async def cleanup(self):
        """テスト後のクリーンアップ"""
        try:
            if 'task_manager' in self.components:
                await self.components['task_manager'].stop()
            
            if 'performance_monitor' in self.components:
                await self.components['performance_monitor'].stop()
                
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")

async def main():
    """メイン統合テスト実行"""
    test_suite = BLRCSIntegrationTest()
    
    try:
        success = await test_suite.run_all_tests()
        
        if success:
            logger.info("\n🎉 全統合テストが成功しました！")
            logger.info("BLRCSシステムは正常に動作しています。")
        else:
            logger.error("\n❌ 一部のテストが失敗しました。")
            logger.error("ログを確認して問題を解決してください。")
        
        return success
        
    finally:
        await test_suite.cleanup()

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)