"""
Lightweight backup system for BLNCS
Essential backup functionality without enterprise complexity.
"""

import os
import json
import shutil
import tarfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from .logger import get_logger
from .config import get_config


class SimpleBackup:
    """Lightweight backup system"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config()
        
        # Backup settings
        self.backup_dir = Path(self.config.get('system.backup_dir', './backups'))
        self.data_dir = Path(self.config.get('system.data_dir', './data'))
        self.config_dir = Path('./config')
        
        # Create backup directory
        self.backup_dir.mkdir(exist_ok=True)
        
        # Retention settings
        self.max_backups = self.config.get('backup.max_backups', 10)
        self.backup_retention_days = self.config.get('backup.retention_days', 30)
    
    def create_backup(self, backup_name: Optional[str] = None) -> str:
        """Create backup"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        if backup_name:
            backup_name = f"{backup_name}_{timestamp}"
        else:
            backup_name = f"blncs_backup_{timestamp}"
        
        backup_path = self.backup_dir / f"{backup_name}.tar.gz"
        
        try:
            self.logger.info(f"Starting backup: {backup_path}")
            
            # Backup information
            backup_info = {
                'created': timestamp,
                'version': '1.0.0',
                'system': {
                    'hostname': os.uname().nodename if hasattr(os, 'uname') else 'unknown',
                    'python_version': f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}"
                },
                'included_files': []
            }
            
            with tarfile.open(backup_path, 'w:gz') as tar:
                # 設定ファイル
                if self.config_dir.exists():
                    tar.add(self.config_dir, arcname='config')
                    backup_info['included_files'].append('config/')
                
                # データディレクトリ
                if self.data_dir.exists():
                    tar.add(self.data_dir, arcname='data')
                    backup_info['included_files'].append('data/')
                
                # セキュリティファイル（存在する場合）
                security_dir = Path('./security')
                if security_dir.exists():
                    tar.add(security_dir, arcname='security')
                    backup_info['included_files'].append('security/')
                
                # ログファイル（最新のみ）
                logs_dir = Path('./logs')
                if logs_dir.exists():
                    log_files = list(logs_dir.glob('*.log'))
                    if log_files:
                        # 最新のログファイルのみ
                        latest_log = max(log_files, key=lambda x: x.stat().st_mtime)
                        tar.add(latest_log, arcname=f'logs/{latest_log.name}')
                        backup_info['included_files'].append(f'logs/{latest_log.name}')
                
                # バックアップ情報ファイル
                info_path = self.backup_dir / 'backup_info.json'
                with open(info_path, 'w') as f:
                    json.dump(backup_info, f, indent=2)
                tar.add(info_path, arcname='backup_info.json')
                os.remove(info_path)
            
            # 古いバックアップ削除
            self._cleanup_old_backups()
            
            self.logger.info(f"バックアップ作成完了: {backup_path}")
            return str(backup_path)
            
        except Exception as e:
            self.logger.error(f"バックアップ作成エラー: {e}")
            if backup_path.exists():
                backup_path.unlink()
            raise
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """バックアップ一覧取得"""
        backups = []
        
        for backup_file in self.backup_dir.glob('*.tar.gz'):
            try:
                stat = backup_file.stat()
                backups.append({
                    'name': backup_file.name,
                    'path': str(backup_file),
                    'size_mb': round(stat.st_size / (1024 * 1024), 2),
                    'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    'age_days': (datetime.now().timestamp() - stat.st_ctime) / 86400
                })
            except Exception as e:
                self.logger.warning(f"バックアップファイル情報取得エラー: {backup_file.name}: {e}")
        
        # 作成日時でソート（新しい順）
        backups.sort(key=lambda x: x['created'], reverse=True)
        return backups
    
    def restore_backup(self, backup_path: str, restore_dir: Optional[str] = None) -> bool:
        """バックアップ復元"""
        backup_file = Path(backup_path)
        if not backup_file.exists():
            self.logger.error(f"バックアップファイルが見つかりません: {backup_path}")
            return False
        
        if restore_dir is None:
            restore_dir = '.'
        
        restore_path = Path(restore_dir)
        
        try:
            self.logger.info(f"バックアップ復元開始: {backup_path} -> {restore_path}")
            
            # 確認プロンプト（危険な操作のため）
            if restore_path.resolve() == Path('.').resolve():
                self.logger.warning("現在のディレクトリに復元します。既存ファイルが上書きされる可能性があります")
            
            with tarfile.open(backup_file, 'r:gz') as tar:
                tar.extractall(restore_path)
            
            self.logger.info("バックアップ復元完了")
            return True
            
        except Exception as e:
            self.logger.error(f"バックアップ復元エラー: {e}")
            return False
    
    def delete_backup(self, backup_name: str) -> bool:
        """バックアップ削除"""
        if not backup_name.endswith('.tar.gz'):
            backup_name += '.tar.gz'
        
        backup_path = self.backup_dir / backup_name
        
        if not backup_path.exists():
            self.logger.error(f"バックアップファイルが見つかりません: {backup_name}")
            return False
        
        try:
            backup_path.unlink()
            self.logger.info(f"バックアップを削除しました: {backup_name}")
            return True
        except Exception as e:
            self.logger.error(f"バックアップ削除エラー: {e}")
            return False
    
    def _cleanup_old_backups(self) -> None:
        """古いバックアップの削除"""
        backups = self.list_backups()
        
        # 数制限による削除
        if len(backups) > self.max_backups:
            for backup in backups[self.max_backups:]:
                self.logger.info(f"保持数制限による削除: {backup['name']}")
                Path(backup['path']).unlink()
        
        # 期間制限による削除
        for backup in backups:
            if backup['age_days'] > self.backup_retention_days:
                self.logger.info(f"保持期間制限による削除: {backup['name']}")
                Path(backup['path']).unlink()
    
    def get_backup_status(self) -> Dict[str, Any]:
        """バックアップ状況取得"""
        backups = self.list_backups()
        
        total_size = sum(b['size_mb'] for b in backups)
        
        return {
            'backup_count': len(backups),
            'total_size_mb': round(total_size, 2),
            'latest_backup': backups[0] if backups else None,
            'backup_dir': str(self.backup_dir),
            'retention_days': self.backup_retention_days,
            'max_backups': self.max_backups
        }


# Global instance
_backup_instance = None

def get_backup_manager() -> SimpleBackup:
    """グローバルバックアップマネージャー取得"""
    global _backup_instance
    if _backup_instance is None:
        _backup_instance = SimpleBackup()
    return _backup_instance