"""
BLNCS セキュリティモジュール
軽量な認証とアクセス制御機能。
"""

import hashlib
import hmac
import secrets
import time
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from .logger import get_logger
from .config import get_config


class SecurityManager:
    """軽量セキュリティ管理"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config()
        
        # セキュリティ設定
        self.enable_auth = self.config.get('security.enable_api_auth', False)
        self.session_timeout = self.config.get('security.session_timeout', 3600)  # 1時間
        self.max_failed_attempts = self.config.get('security.max_failed_attempts', 5)
        
        # セッション管理
        self.active_sessions = {}
        self.failed_attempts = {}
        
        # セキュリティファイル
        security_dir = Path('./security')
        security_dir.mkdir(exist_ok=True)
        self.auth_file = security_dir / 'auth.json'
        
        # デフォルト認証情報の初期化
        self._init_default_auth()
    
    def _init_default_auth(self):
        """セキュリティ認証の初期化"""
        if not self.auth_file.exists():
            # セキュア初期設定 - デフォルトパスワードは生成しない
            auth_data = {
                'users': {},
                'sessions': {},
                'security_log': [],
                'macaroon_path': None,
                'tls_cert_path': None,
                'initialized': False
            }
            
            with open(self.auth_file, 'w') as f:
                json.dump(auth_data, f, indent=2)
            
            # 適切な権限設定
            self.auth_file.chmod(0o600)
            
            self.logger.info("認証ファイルを初期化しました。setup コマンドで設定を行ってください。")
    
    def _hash_password(self, password: str, salt: Optional[str] = None) -> Dict[str, str]:
        """パスワードをハッシュ化"""
        if salt is None:
            salt = secrets.token_hex(32)
        
        # PBKDF2を使用
        password_hash = hashlib.pbkdf2_hmac('sha256', 
                                          password.encode('utf-8'), 
                                          salt.encode('utf-8'), 
                                          100000)  # 100,000 iterations
        
        return {
            'hash': password_hash.hex(),
            'salt': salt,
            'iterations': 100000,
            'algorithm': 'pbkdf2_hmac_sha256'
        }
    
    def verify_macaroon_security(self, macaroon_path: str) -> Dict[str, Any]:
        """Macaroonセキュリティ検証"""
        macaroon_file = Path(macaroon_path).expanduser()
        
        if not macaroon_file.exists():
            return {
                'valid': False,
                'error': 'Macaroon file not found',
                'recommendation': 'Ensure Lightning node is running and macaroon path is correct'
            }
        
        try:
            # ファイル権限チェック
            file_stat = macaroon_file.stat()
            file_mode = oct(file_stat.st_mode)[-3:]
            
            security_issues = []
            
            # 権限が777や666など危険でないかチェック
            if file_mode in ['777', '666', '644']:
                security_issues.append(f"Insecure file permissions: {file_mode}")
            
            # ファイルサイズチェック（空または異常に小さいファイル）
            if file_stat.st_size < 50:
                security_issues.append("Macaroon file appears to be empty or corrupted")
            
            return {
                'valid': len(security_issues) == 0,
                'file_size': file_stat.st_size,
                'permissions': file_mode,
                'issues': security_issues,
                'recommendation': 'chmod 600 for optimal security' if security_issues else 'Macaroon security OK'
            }
            
        except Exception as e:
            return {
                'valid': False,
                'error': f"Security check failed: {e}",
                'recommendation': 'Check file permissions and Lightning node status'
            }
    
    def verify_tls_security(self, cert_path: str) -> Dict[str, Any]:
        """TLS証明書セキュリティ検証"""
        cert_file = Path(cert_path).expanduser()
        
        if not cert_file.exists():
            return {
                'valid': False,
                'error': 'TLS certificate file not found',
                'recommendation': 'Ensure Lightning node is running and certificate path is correct'
            }
        
        try:
            # 証明書ファイルの基本チェック
            file_stat = cert_file.stat()
            
            # PEM形式かチェック
            with open(cert_file, 'r') as f:
                content = f.read()
                if not content.startswith('-----BEGIN CERTIFICATE-----'):
                    return {
                        'valid': False,
                        'error': 'Invalid certificate format',
                        'recommendation': 'Ensure certificate is in PEM format'
                    }
            
            return {
                'valid': True,
                'file_size': file_stat.st_size,
                'format': 'PEM',
                'recommendation': 'TLS certificate OK'
            }
            
        except Exception as e:
            return {
                'valid': False,
                'error': f"Certificate check failed: {e}",
                'recommendation': 'Check certificate file and Lightning node status'
            }
    
    def get_security_status(self) -> Dict[str, Any]:
        """セキュリティ状況取得"""
        config = get_config()
        
        try:
            # Macaroon確認
            macaroon_path = config.get('lightning.macaroon_path', '')
            macaroon_status = self.verify_macaroon_security(macaroon_path) if macaroon_path else None
            
            # TLS証明書確認  
            cert_path = config.get('lightning.cert_path', '')
            tls_status = self.verify_tls_security(cert_path) if cert_path else None
            
            return {
                'authentication_enabled': self.enable_auth,
                'session_timeout_seconds': self.session_timeout,
                'max_failed_attempts': self.max_failed_attempts,
                'active_sessions': len(self.active_sessions),
                'macaroon_security': macaroon_status,
                'tls_security': tls_status,
                'security_recommendations': self._get_security_recommendations()
            }
        
        except Exception as e:
            self.logger.error(f"セキュリティ状態取得エラー: {e}")
            return {'error': str(e)}
    
    def _get_security_recommendations(self) -> List[str]:
        """セキュリティ推奨事項取得"""
        recommendations = []
        
        if not self.enable_auth:
            recommendations.append("認証機能の有効化を検討してください")
        
        if self.session_timeout > 7200:  # 2時間
            recommendations.append("セッションタイムアウトを短縮することを検討してください")
        
        # システム固有の推奨事項
        recommendations.extend([
            "定期的なバックアップの実行",
            "Macaroonファイルの権限確認 (chmod 600 推奨)",
            "Lightning ノードの定期的な更新",
            "ファイアウォール設定の確認"
        ])
        
        return recommendations


# Global instance
_security_manager_instance = None

def get_security_manager() -> SecurityManager:
    """グローバルセキュリティマネージャー取得"""
    global _security_manager_instance
    if _security_manager_instance is None:
        _security_manager_instance = SecurityManager()
    return _security_manager_instance

def require_auth(func):
    """認証デコレータ（将来の拡張用）"""
    def wrapper(*args, **kwargs):
        # 現在は認証チェックをスキップ
        return func(*args, **kwargs)
    return wrapper