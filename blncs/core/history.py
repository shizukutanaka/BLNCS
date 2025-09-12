"""
BLNCS 履歴管理モジュール
軽量なJSONベースのトランザクション履歴記録機能（圧縮対応）。
"""

import json
import gzip
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from .logger import get_logger
from .config import get_config
from .cache_unified import get_cache


class TransactionHistory:
    """軽量なトランザクション履歴管理"""
    
    def __init__(self, history_file: Optional[str] = None):
        self.logger = get_logger(__name__)
        config = get_config()
        self.cache = get_cache()
        
        # 履歴ファイルのパスを決定
        if history_file:
            self.history_file = Path(history_file)
        else:
            data_dir = config.get('system.data_dir', './data')
            self.history_file = Path(data_dir) / 'transaction_history.json'
        
        # 圧縮ファイルのパス
        self.compressed_file = self.history_file.with_suffix('.json.gz')
        
        # ディレクトリを作成
        self.history_file.parent.mkdir(parents=True, exist_ok=True)
        
        # 最大エントリ数の設定
        self.max_entries = config.get('features.max_history_entries', 1000)
        
        # 履歴が有効かどうか
        self.enabled = config.get('features.enable_history', True)
        
        # 圧縮を使用するかどうか
        self.use_compression = config.get('features.compress_history', True)
        
        # ファイルサイズの閾値（バイト） - これを超えると圧縮を使用
        self.compression_threshold = config.get('features.compression_threshold', 10240)  # 10KB
    
    def _load_history(self) -> List[Dict[str, Any]]:
        """履歴ファイルを読み込み（圧縮対応）"""
        cache_key = "history_data"
        cached_history = self.cache.get(cache_key)
        if cached_history:
            return cached_history
        
        history = []
        
        # 圧縮ファイルを優先して読み込み
        if self.compressed_file.exists():
            try:
                with gzip.open(self.compressed_file, 'rt', encoding='utf-8') as f:
                    history = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                self.logger.warning(f"圧縮履歴ファイルの読み込みエラー: {e}")
        
        # 通常のファイルから読み込み（圧縮ファイルがない場合）
        elif self.history_file.exists():
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    history = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                self.logger.warning(f"履歴ファイルの読み込みエラー: {e}")
        
        # キャッシュに保存（30秒間）
        self.cache.set(cache_key, history, 30)
        return history
    
    def _save_history(self, history: List[Dict[str, Any]]):
        """履歴ファイルに保存（圧縮対応）"""
        try:
            # データのサイズを推定
            data_str = json.dumps(history, ensure_ascii=False, separators=(',', ':'))
            data_size = len(data_str.encode('utf-8'))
            
            if self.use_compression and data_size > self.compression_threshold:
                # 圧縮して保存
                with gzip.open(self.compressed_file, 'wt', encoding='utf-8') as f:
                    json.dump(history, f, ensure_ascii=False, separators=(',', ':'))
                
                # 通常のファイルが存在する場合は削除
                if self.history_file.exists():
                    self.history_file.unlink()
                
                self.logger.debug(f"履歴を圧縮保存 ({data_size} bytes → compressed)")
            else:
                # 通常のファイルとして保存
                with open(self.history_file, 'w', encoding='utf-8') as f:
                    json.dump(history, f, ensure_ascii=False, indent=2)
                
                # 圧縮ファイルが存在する場合は削除
                if self.compressed_file.exists():
                    self.compressed_file.unlink()
            
            # キャッシュを更新
            self.cache.set("history_data", history, 30)
            
        except OSError as e:
            self.logger.error(f"履歴ファイルの保存エラー: {e}")
    
    def add_transaction(self, tx_type: str, tx_data: Dict[str, Any]):
        """トランザクションを履歴に追加"""
        if not self.enabled:
            return
        
        # タイムスタンプを追加
        entry = {
            'timestamp': datetime.now().isoformat(),
            'type': tx_type,
            'data': tx_data
        }
        
        # 履歴を読み込み
        history = self._load_history()
        
        # 新しいエントリを先頭に追加
        history.insert(0, entry)
        
        # 最大エントリ数を超える場合は古いものを削除
        if len(history) > self.max_entries:
            history = history[:self.max_entries]
            self.logger.debug(f"履歴を {self.max_entries} エントリに制限しました")
        
        # 保存
        self._save_history(history)
        
        self.logger.info(f"履歴に記録: {tx_type}")
    
    def get_recent_transactions(self, limit: int = 10) -> List[Dict[str, Any]]:
        """最近のトランザクションを取得"""
        history = self._load_history()
        return history[:limit]
    
    def get_transactions_by_type(self, tx_type: str, limit: int = 10) -> List[Dict[str, Any]]:
        """指定タイプのトランザクションを取得"""
        history = self._load_history()
        filtered = [entry for entry in history if entry.get('type') == tx_type]
        return filtered[:limit]
    
    def get_statistics(self) -> Dict[str, Any]:
        """履歴の統計情報を取得"""
        history = self._load_history()
        
        if not history:
            return {
                'total_transactions': 0,
                'types': {},
                'oldest_entry': None,
                'newest_entry': None,
                'file_size_bytes': 0,
                'compressed': False
            }
        
        # タイプ別の集計
        type_counts = {}
        for entry in history:
            tx_type = entry.get('type', 'unknown')
            type_counts[tx_type] = type_counts.get(tx_type, 0) + 1
        
        # ファイルサイズと圧縮状態を確認
        file_size = 0
        compressed = False
        
        if self.compressed_file.exists():
            try:
                file_size = self.compressed_file.stat().st_size
                compressed = True
            except:
                file_size = 0
        elif self.history_file.exists():
            try:
                file_size = self.history_file.stat().st_size
            except:
                file_size = 0
        
        return {
            'total_transactions': len(history),
            'types': type_counts,
            'oldest_entry': history[-1].get('timestamp') if history else None,
            'newest_entry': history[0].get('timestamp') if history else None,
            'file_size_bytes': file_size,
            'compressed': compressed
        }
    
    def clear_history(self):
        """履歴をクリア"""
        try:
            if self.history_file.exists():
                self.history_file.unlink()
                self.logger.info("履歴をクリアしました")
        except OSError as e:
            self.logger.error(f"履歴クリアエラー: {e}")
    
    def export_history(self, export_file: str) -> bool:
        """履歴をエクスポート"""
        try:
            history = self._load_history()
            export_path = Path(export_file)
            export_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(history, f, ensure_ascii=False, indent=2)
            
            self.logger.info(f"履歴をエクスポート: {export_path}")
            return True
        except Exception as e:
            self.logger.error(f"履歴エクスポートエラー: {e}")
            return False
    
    def optimize_storage(self):
        """ストレージを最適化（古いエントリを削除）"""
        history = self._load_history()
        original_count = len(history)
        
        if original_count <= self.max_entries:
            return 0
        
        # 最大エントリ数まで削減
        optimized_history = history[:self.max_entries]
        self._save_history(optimized_history)
        
        removed_count = original_count - len(optimized_history)
        self.logger.info(f"履歴を最適化: {removed_count}件のエントリを削除")
        return removed_count


# グローバルインスタンス
_global_history = None

def get_history() -> TransactionHistory:
    """グローバル履歴インスタンスを取得"""
    global _global_history
    if _global_history is None:
        _global_history = TransactionHistory()
    return _global_history


def record_transaction(tx_type: str, **kwargs):
    """トランザクションを記録（簡易インターフェース）"""
    history = get_history()
    history.add_transaction(tx_type, kwargs)