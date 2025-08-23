# BLRCS Connection Manager - 統一接続管理
# 重複排除とコード品質向上

import asyncio
from typing import Optional, Dict, Any, Callable
from dataclasses import dataclass
import logging
import time


@dataclass
class ConnectionConfig:
    """接続設定"""
    host: str
    port: int
    timeout: float = 30.0
    retry_count: int = 3
    retry_delay: float = 1.0
    

class ConnectionState:
    """接続状態管理"""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    FAILED = "failed"
    RECONNECTING = "reconnecting"


class BaseConnectionManager:
    """基本接続マネージャー - 重複コード削減"""
    
    def __init__(self, config: ConnectionConfig, logger: Optional[logging.Logger] = None):
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        self.state = ConnectionState.DISCONNECTED
        self.connection = None
        self.last_error = None
        self.retry_count = 0
        self.on_state_change: Optional[Callable] = None
    
    def _set_state(self, new_state: str):
        """状態変更"""
        old_state = self.state
        self.state = new_state
        self.logger.info(f"接続状態変更: {old_state} -> {new_state}")
        
        if self.on_state_change:
            try:
                self.on_state_change(old_state, new_state)
            except Exception as e:
                self.logger.warning(f"状態変更コールバックエラー: {e}")
    
    async def connect(self) -> bool:
        """接続実行 - サブクラスでオーバーライド"""
        raise NotImplementedError("サブクラスで実装してください")
    
    async def disconnect(self):
        """切断実行 - サブクラスでオーバーライド"""
        raise NotImplementedError("サブクラスで実装してください")
    
    async def is_connected(self) -> bool:
        """接続確認 - サブクラスでオーバーライド"""
        raise NotImplementedError("サブクラスで実装してください")
    
    async def connect_with_retry(self) -> bool:
        """リトライ付き接続"""
        self._set_state(ConnectionState.CONNECTING)
        
        for attempt in range(self.config.retry_count):
            try:
                self.retry_count = attempt
                
                if await self.connect():
                    self._set_state(ConnectionState.CONNECTED)
                    self.last_error = None
                    return True
                
            except Exception as e:
                self.last_error = str(e)
                self.logger.warning(f"接続試行 {attempt + 1} 失敗: {e}")
                
                if attempt < self.config.retry_count - 1:
                    await asyncio.sleep(self.config.retry_delay * (2 ** attempt))
        
        self._set_state(ConnectionState.FAILED)
        return False
    
    async def reconnect(self) -> bool:
        """再接続"""
        self._set_state(ConnectionState.RECONNECTING)
        
        try:
            await self.disconnect()
        except Exception as e:
            self.logger.warning(f"切断エラー: {e}")
        
        return await self.connect_with_retry()
    
    def get_status(self) -> Dict[str, Any]:
        """接続状態取得"""
        return {
            "state": self.state,
            "config": {
                "host": self.config.host,
                "port": self.config.port
            },
            "last_error": self.last_error,
            "retry_count": self.retry_count
        }


class DatabaseConnectionManager(BaseConnectionManager):
    """データベース接続管理"""
    
    async def connect(self) -> bool:
        """データベース接続"""
        try:
            # 実際のDB接続ロジック
            # データベース接続処理をここに実装
            self.connection = {"db": "connected"}  # プレースホルダー
            return True
        except Exception as e:
            self.logger.error(f"データベース接続失敗: {e}")
            return False
    
    async def disconnect(self):
        """データベース切断"""
        if self.connection:
            try:
                # 実際のDB切断処理
                self.connection = None
                self._set_state(ConnectionState.DISCONNECTED)
            except Exception as e:
                self.logger.error(f"データベース切断失敗: {e}")
    
    async def is_connected(self) -> bool:
        """データベース接続確認"""
        return self.connection is not None


class LightningConnectionManager(BaseConnectionManager):
    """Lightning Network接続管理"""
    
    async def connect(self) -> bool:
        """Lightning接続"""
        try:
            # 実際のLN接続ロジック
            self.connection = {"ln": "connected"}  # プレースホルダー
            return True
        except Exception as e:
            self.logger.error(f"Lightning接続失敗: {e}")
            return False
    
    async def disconnect(self):
        """Lightning切断"""
        if self.connection:
            try:
                self.connection = None
                self._set_state(ConnectionState.DISCONNECTED)
            except Exception as e:
                self.logger.error(f"Lightning切断失敗: {e}")
    
    async def is_connected(self) -> bool:
        """Lightning接続確認"""
        return self.connection is not None


class UnifiedConnectionManager:
    """統合接続管理 - 全接続の一元管理"""
    
    def __init__(self):
        self.managers: Dict[str, BaseConnectionManager] = {}
        self.logger = logging.getLogger(__name__)
    
    def register_manager(self, name: str, manager: BaseConnectionManager):
        """マネージャー登録"""
        self.managers[name] = manager
    
    async def connect_all(self) -> Dict[str, bool]:
        """全接続実行"""
        results = {}
        for name, manager in self.managers.items():
            results[name] = await manager.connect_with_retry()
        return results
    
    async def disconnect_all(self):
        """全切断実行"""
        for name, manager in self.managers.items():
            try:
                await manager.disconnect()
            except Exception as e:
                self.logger.warning(f"{name} 切断エラー: {e}")
    
    def get_status_all(self) -> Dict[str, Dict[str, Any]]:
        """全状態取得"""
        return {name: manager.get_status() for name, manager in self.managers.items()}