#!/usr/bin/env python3
"""
BLNCS Security Manager - セキュリティ管理
Advanced security features for Lightning Network operations.
"""

import os
import json
import hashlib
import hmac
import secrets
import base64
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
import threading
import time
import logging

try:
    from .config_manager import get_config_manager
    from ..lightning.client_simple import get_lightning_client
except ImportError:
    import sys
    sys.path.append(str(Path(__file__).parent.parent))
    from config_manager import get_config_manager
    from lightning.client_simple import get_lightning_client


class SecurityManager:
    """セキュリティ管理クラス"""
    
    def __init__(self, config_manager=None):
        self.config = config_manager or get_config_manager()
        self.lightning_client = get_lightning_client()
        
        # セキュリティ設定
        self.max_login_attempts = 5
        self.lockout_duration = 300  # 5分
        self.session_timeout = 3600  # 1時間
        self.password_min_length = 8
        self.require_2fa = False
        
        # データディレクトリ
        self.security_dir = Path(self.config.get_data_dir()) / "security"
        self.security_dir.mkdir(exist_ok=True, parents=True)
        
        # ログ設定
        self.setup_logging()
        
        # データベース初期化
        self.init_security_database()
        
        # セキュリティ監視開始
        self.monitoring_active = False
        self.start_security_monitoring()
    
    def setup_logging(self):
        """セキュリティログ設定"""
        log_dir = self.security_dir / "logs"
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / f"security_{datetime.now().strftime('%Y%m%d')}.log"
        
        self.logger = logging.getLogger('blncs_security')
        self.logger.setLevel(logging.INFO)
        
        # ファイルハンドラー
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        
        # フォーマッター
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
    
    def init_security_database(self):
        """セキュリティデータベース初期化"""
        db_path = self.security_dir / "security.db"
        
        with sqlite3.connect(str(db_path)) as conn:
            cursor = conn.cursor()
            
            # ユーザーテーブル
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    failed_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP,
                    two_factor_secret TEXT,
                    permissions TEXT DEFAULT '{}',
                    is_active BOOLEAN DEFAULT 1
                )
            ''')
            
            # セッションテーブル
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    user_id INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    ip_address TEXT,
                    user_agent TEXT,
                    is_active BOOLEAN DEFAULT 1,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # セキュリティイベントテーブル
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    user_id INTEGER,
                    ip_address TEXT,
                    details TEXT,
                    severity TEXT DEFAULT 'INFO',
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # APIキーテーブル
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_id TEXT UNIQUE NOT NULL,
                    key_hash TEXT NOT NULL,
                    user_id INTEGER,
                    permissions TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    last_used TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # 暗号化キーテーブル
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS encryption_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_name TEXT UNIQUE NOT NULL,
                    encrypted_key TEXT NOT NULL,
                    key_type TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )
            ''')
            
            conn.commit()
    
    # ユーザー認証機能
    def create_user(self, username, password, permissions=None):
        """ユーザーを作成"""
        try:
            if len(password) < self.password_min_length:
                raise ValueError(f"パスワードは{self.password_min_length}文字以上である必要があります")
            
            # パスワードハッシュ化
            salt = secrets.token_hex(32)
            password_hash = self.hash_password(password, salt)
            
            permissions = permissions or {}
            permissions_json = json.dumps(permissions)
            
            db_path = self.security_dir / "security.db"
            with sqlite3.connect(str(db_path)) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO users (username, password_hash, salt, permissions)
                    VALUES (?, ?, ?, ?)
                ''', (username, password_hash, salt, permissions_json))
                
                user_id = cursor.lastrowid
                conn.commit()
            
            self.log_security_event("USER_CREATED", user_id=user_id, details=f"User '{username}' created")
            
            return {
                'success': True,
                'user_id': user_id,
                'username': username
            }
            
        except sqlite3.IntegrityError:
            return {'success': False, 'error': 'ユーザー名が既に存在します'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def authenticate_user(self, username, password, ip_address=None):
        """ユーザー認証"""
        try:
            db_path = self.security_dir / "security.db"
            with sqlite3.connect(str(db_path)) as conn:
                cursor = conn.cursor()
                
                # ユーザー情報取得
                cursor.execute('''
                    SELECT id, username, password_hash, salt, failed_attempts, 
                           locked_until, is_active
                    FROM users WHERE username = ?
                ''', (username,))
                
                user = cursor.fetchone()
                if not user:
                    self.log_security_event("LOGIN_FAILED", details=f"User '{username}' not found", ip_address=ip_address)
                    return {'success': False, 'error': 'ユーザー名またはパスワードが間違っています'}
                
                user_id, username, password_hash, salt, failed_attempts, locked_until, is_active = user
                
                # アカウント有効性確認
                if not is_active:
                    self.log_security_event("LOGIN_FAILED", user_id=user_id, details="Account inactive", ip_address=ip_address)
                    return {'success': False, 'error': 'アカウントが無効です'}
                
                # ロック状態確認
                if locked_until:
                    lock_time = datetime.fromisoformat(locked_until)
                    if datetime.now() < lock_time:
                        remaining = int((lock_time - datetime.now()).total_seconds())
                        self.log_security_event("LOGIN_FAILED", user_id=user_id, details="Account locked", ip_address=ip_address)
                        return {'success': False, 'error': f'アカウントがロックされています（残り{remaining}秒）'}
                    else:
                        # ロック期間終了 - リセット
                        cursor.execute('''
                            UPDATE users SET failed_attempts = 0, locked_until = NULL
                            WHERE id = ?
                        ''', (user_id,))
                
                # パスワード検証
                if not self.verify_password(password, password_hash, salt):
                    # 失敗回数を増やす
                    failed_attempts += 1
                    
                    if failed_attempts >= self.max_login_attempts:
                        # アカウントロック
                        lock_until = datetime.now() + timedelta(seconds=self.lockout_duration)
                        cursor.execute('''
                            UPDATE users SET failed_attempts = ?, locked_until = ?
                            WHERE id = ?
                        ''', (failed_attempts, lock_until.isoformat(), user_id))
                        
                        self.log_security_event("ACCOUNT_LOCKED", user_id=user_id, 
                                               details=f"Account locked after {failed_attempts} failed attempts",
                                               ip_address=ip_address, severity="WARNING")
                    else:
                        cursor.execute('''
                            UPDATE users SET failed_attempts = ?
                            WHERE id = ?
                        ''', (failed_attempts, user_id))
                    
                    conn.commit()
                    self.log_security_event("LOGIN_FAILED", user_id=user_id, 
                                          details=f"Password incorrect (attempt {failed_attempts})",
                                          ip_address=ip_address)
                    return {'success': False, 'error': 'ユーザー名またはパスワードが間違っています'}
                
                # 認証成功 - 失敗回数リセット、最終ログイン更新
                cursor.execute('''
                    UPDATE users SET failed_attempts = 0, locked_until = NULL, 
                                     last_login = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (user_id,))
                
                conn.commit()
                
                # セッション作成
                session_result = self.create_session(user_id, ip_address)
                if not session_result['success']:
                    return session_result
                
                self.log_security_event("LOGIN_SUCCESS", user_id=user_id, 
                                       details="User logged in", ip_address=ip_address)
                
                return {
                    'success': True,
                    'user_id': user_id,
                    'username': username,
                    'session_id': session_result['session_id']
                }
                
        except Exception as e:
            self.log_security_event("LOGIN_ERROR", details=str(e), ip_address=ip_address, severity="ERROR")
            return {'success': False, 'error': '認証エラーが発生しました'}
    
    def create_session(self, user_id, ip_address=None, user_agent=None):
        """セッション作成"""
        try:
            session_id = secrets.token_urlsafe(32)
            expires_at = datetime.now() + timedelta(seconds=self.session_timeout)
            
            db_path = self.security_dir / "security.db"
            with sqlite3.connect(str(db_path)) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO sessions (session_id, user_id, expires_at, ip_address, user_agent)
                    VALUES (?, ?, ?, ?, ?)
                ''', (session_id, user_id, expires_at.isoformat(), ip_address, user_agent))
                
                conn.commit()
            
            return {
                'success': True,
                'session_id': session_id,
                'expires_at': expires_at
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def validate_session(self, session_id):
        """セッション検証"""
        try:
            db_path = self.security_dir / "security.db"
            with sqlite3.connect(str(db_path)) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT s.user_id, s.expires_at, u.username, u.permissions
                    FROM sessions s
                    JOIN users u ON s.user_id = u.id
                    WHERE s.session_id = ? AND s.is_active = 1 AND u.is_active = 1
                ''', (session_id,))
                
                session = cursor.fetchone()
                if not session:
                    return {'valid': False, 'error': 'セッションが見つかりません'}
                
                user_id, expires_at, username, permissions = session
                expires_time = datetime.fromisoformat(expires_at)
                
                if datetime.now() > expires_time:
                    # セッション無効化
                    cursor.execute('''
                        UPDATE sessions SET is_active = 0 WHERE session_id = ?
                    ''', (session_id,))
                    conn.commit()
                    
                    return {'valid': False, 'error': 'セッションの有効期限が切れました'}
                
                return {
                    'valid': True,
                    'user_id': user_id,
                    'username': username,
                    'permissions': json.loads(permissions) if permissions else {}
                }
                
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    def logout_user(self, session_id):
        """ユーザーログアウト"""
        try:
            db_path = self.security_dir / "security.db"
            with sqlite3.connect(str(db_path)) as conn:
                cursor = conn.cursor()
                
                # セッション情報取得
                cursor.execute('''
                    SELECT user_id FROM sessions WHERE session_id = ?
                ''', (session_id,))
                
                session = cursor.fetchone()
                if session:
                    user_id = session[0]
                    
                    # セッション無効化
                    cursor.execute('''
                        UPDATE sessions SET is_active = 0 WHERE session_id = ?
                    ''', (session_id,))
                    
                    conn.commit()
                    
                    self.log_security_event("LOGOUT", user_id=user_id, details="User logged out")
                    
                    return {'success': True}
                else:
                    return {'success': False, 'error': 'セッションが見つかりません'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # パスワード管理
    def hash_password(self, password, salt):
        """パスワードハッシュ化"""
        return hashlib.pbkdf2_hex(password.encode('utf-8'), salt.encode('utf-8'), 100000)
    
    def verify_password(self, password, password_hash, salt):
        """パスワード検証"""
        return hmac.compare_digest(self.hash_password(password, salt), password_hash)
    
    def change_password(self, user_id, old_password, new_password):
        """パスワード変更"""
        try:
            if len(new_password) < self.password_min_length:
                raise ValueError(f"新しいパスワードは{self.password_min_length}文字以上である必要があります")
            
            db_path = self.security_dir / "security.db"
            with sqlite3.connect(str(db_path)) as conn:
                cursor = conn.cursor()
                
                # 現在のパスワード確認
                cursor.execute('''
                    SELECT password_hash, salt FROM users WHERE id = ?
                ''', (user_id,))
                
                user = cursor.fetchone()
                if not user:
                    return {'success': False, 'error': 'ユーザーが見つかりません'}
                
                password_hash, salt = user
                if not self.verify_password(old_password, password_hash, salt):
                    self.log_security_event("PASSWORD_CHANGE_FAILED", user_id=user_id,
                                          details="Incorrect old password")
                    return {'success': False, 'error': '現在のパスワードが間違っています'}
                
                # 新しいパスワードでハッシュ化
                new_salt = secrets.token_hex(32)
                new_password_hash = self.hash_password(new_password, new_salt)
                
                cursor.execute('''
                    UPDATE users SET password_hash = ?, salt = ?
                    WHERE id = ?
                ''', (new_password_hash, new_salt, user_id))
                
                conn.commit()
                
                self.log_security_event("PASSWORD_CHANGED", user_id=user_id,
                                       details="Password changed successfully")
                
                return {'success': True}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # APIキー管理
    def create_api_key(self, user_id, permissions=None, expires_days=None):
        """APIキー作成"""
        try:
            key_id = secrets.token_urlsafe(16)
            api_key = secrets.token_urlsafe(32)
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            
            permissions = permissions or {}
            permissions_json = json.dumps(permissions)
            
            expires_at = None
            if expires_days:
                expires_at = datetime.now() + timedelta(days=expires_days)
            
            db_path = self.security_dir / "security.db"
            with sqlite3.connect(str(db_path)) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO api_keys (key_id, key_hash, user_id, permissions, expires_at)
                    VALUES (?, ?, ?, ?, ?)
                ''', (key_id, key_hash, user_id, permissions_json, 
                      expires_at.isoformat() if expires_at else None))
                
                conn.commit()
            
            self.log_security_event("API_KEY_CREATED", user_id=user_id,
                                   details=f"API key created: {key_id}")
            
            return {
                'success': True,
                'key_id': key_id,
                'api_key': api_key
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def validate_api_key(self, api_key):
        """APIキー検証"""
        try:
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            
            db_path = self.security_dir / "security.db"
            with sqlite3.connect(str(db_path)) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT ak.key_id, ak.user_id, ak.permissions, ak.expires_at,
                           u.username, u.is_active
                    FROM api_keys ak
                    JOIN users u ON ak.user_id = u.id
                    WHERE ak.key_hash = ? AND ak.is_active = 1
                ''', (key_hash,))
                
                key_info = cursor.fetchone()
                if not key_info:
                    return {'valid': False, 'error': 'APIキーが無効です'}
                
                key_id, user_id, permissions, expires_at, username, user_active = key_info
                
                if not user_active:
                    return {'valid': False, 'error': 'ユーザーアカウントが無効です'}
                
                if expires_at:
                    expires_time = datetime.fromisoformat(expires_at)
                    if datetime.now() > expires_time:
                        return {'valid': False, 'error': 'APIキーの有効期限が切れました'}
                
                # 最終使用時刻更新
                cursor.execute('''
                    UPDATE api_keys SET last_used = CURRENT_TIMESTAMP
                    WHERE key_id = ?
                ''', (key_id,))
                
                conn.commit()
                
                return {
                    'valid': True,
                    'key_id': key_id,
                    'user_id': user_id,
                    'username': username,
                    'permissions': json.loads(permissions) if permissions else {}
                }
                
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    # 暗号化・復号化
    def encrypt_data(self, data, key_name="default"):
        """データ暗号化"""
        try:
            from cryptography.fernet import Fernet
            
            # 暗号化キー取得または作成
            encryption_key = self.get_or_create_encryption_key(key_name)
            if not encryption_key:
                raise ValueError("暗号化キーの取得に失敗しました")
            
            fernet = Fernet(encryption_key)
            
            if isinstance(data, str):
                data = data.encode('utf-8')
            elif isinstance(data, dict):
                data = json.dumps(data).encode('utf-8')
            
            encrypted_data = fernet.encrypt(data)
            return base64.b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            self.logger.error(f"暗号化エラー: {e}")
            return None
    
    def decrypt_data(self, encrypted_data, key_name="default"):
        """データ復号化"""
        try:
            from cryptography.fernet import Fernet
            
            encryption_key = self.get_or_create_encryption_key(key_name)
            if not encryption_key:
                raise ValueError("暗号化キーの取得に失敗しました")
            
            fernet = Fernet(encryption_key)
            
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
            decrypted_data = fernet.decrypt(encrypted_bytes)
            
            return decrypted_data.decode('utf-8')
            
        except Exception as e:
            self.logger.error(f"復号化エラー: {e}")
            return None
    
    def get_or_create_encryption_key(self, key_name):
        """暗号化キー取得または作成"""
        try:
            from cryptography.fernet import Fernet
            
            db_path = self.security_dir / "security.db"
            with sqlite3.connect(str(db_path)) as conn:
                cursor = conn.cursor()
                
                # 既存キー確認
                cursor.execute('''
                    SELECT encrypted_key FROM encryption_keys 
                    WHERE key_name = ? AND is_active = 1
                ''', (key_name,))
                
                result = cursor.fetchone()
                if result:
                    # 既存キーを復号化して返す
                    encrypted_key = result[0]
                    # ここでは簡易的にそのまま返す（実際の実装では適切な復号化が必要）
                    return encrypted_key
                
                # 新しいキーを作成
                new_key = Fernet.generate_key()
                key_b64 = base64.b64encode(new_key).decode('utf-8')
                
                cursor.execute('''
                    INSERT INTO encryption_keys (key_name, encrypted_key, key_type)
                    VALUES (?, ?, ?)
                ''', (key_name, key_b64, 'fernet'))
                
                conn.commit()
                
                return new_key
                
        except Exception as e:
            self.logger.error(f"暗号化キー取得/作成エラー: {e}")
            return None
    
    # セキュリティ監視
    def start_security_monitoring(self):
        """セキュリティ監視開始"""
        if not self.monitoring_active:
            self.monitoring_active = True
            self.monitor_thread = threading.Thread(target=self._security_monitor_loop, daemon=True)
            self.monitor_thread.start()
    
    def stop_security_monitoring(self):
        """セキュリティ監視停止"""
        self.monitoring_active = False
    
    def _security_monitor_loop(self):
        """セキュリティ監視ループ"""
        while self.monitoring_active:
            try:
                # 期限切れセッションをクリーンアップ
                self.cleanup_expired_sessions()
                
                # 不審なアクティビティをチェック
                self.check_suspicious_activity()
                
                # セキュリティレポート生成（毎時）
                current_time = datetime.now()
                if current_time.minute == 0:  # 毎時0分
                    self.generate_security_report()
                
                # 60秒待機
                time.sleep(60)
                
            except Exception as e:
                self.logger.error(f"セキュリティ監視エラー: {e}")
                time.sleep(60)
    
    def cleanup_expired_sessions(self):
        """期限切れセッションをクリーンアップ"""
        try:
            db_path = self.security_dir / "security.db"
            with sqlite3.connect(str(db_path)) as conn:
                cursor = conn.cursor()
                
                # 期限切れセッションを無効化
                cursor.execute('''
                    UPDATE sessions SET is_active = 0 
                    WHERE expires_at < CURRENT_TIMESTAMP AND is_active = 1
                ''')
                
                cleaned_count = cursor.rowcount
                if cleaned_count > 0:
                    self.logger.info(f"期限切れセッション {cleaned_count} 件をクリーンアップしました")
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"セッションクリーンアップエラー: {e}")
    
    def check_suspicious_activity(self):
        """不審なアクティビティをチェック"""
        try:
            db_path = self.security_dir / "security.db"
            with sqlite3.connect(str(db_path)) as conn:
                cursor = conn.cursor()
                
                # 過去1時間の失敗ログイン試行をチェック
                one_hour_ago = datetime.now() - timedelta(hours=1)
                cursor.execute('''
                    SELECT ip_address, COUNT(*) as attempt_count
                    FROM security_events
                    WHERE event_type = 'LOGIN_FAILED' 
                      AND timestamp > ?
                    GROUP BY ip_address
                    HAVING attempt_count >= 10
                ''', (one_hour_ago.isoformat(),))
                
                suspicious_ips = cursor.fetchall()
                for ip, count in suspicious_ips:
                    self.log_security_event("SUSPICIOUS_ACTIVITY", 
                                           details=f"Excessive login failures from IP {ip}: {count} attempts",
                                           ip_address=ip, severity="WARNING")
                
        except Exception as e:
            self.logger.error(f"不審アクティビティチェックエラー: {e}")
    
    def generate_security_report(self):
        """セキュリティレポート生成"""
        try:
            db_path = self.security_dir / "security.db"
            with sqlite3.connect(str(db_path)) as conn:
                cursor = conn.cursor()
                
                # 過去24時間の統計
                yesterday = datetime.now() - timedelta(days=1)
                
                # ログイン成功/失敗
                cursor.execute('''
                    SELECT event_type, COUNT(*)
                    FROM security_events
                    WHERE timestamp > ? AND event_type IN ('LOGIN_SUCCESS', 'LOGIN_FAILED')
                    GROUP BY event_type
                ''', (yesterday.isoformat(),))
                
                login_stats = dict(cursor.fetchall())
                
                # アクティブセッション数
                cursor.execute('''
                    SELECT COUNT(*) FROM sessions WHERE is_active = 1
                ''')
                active_sessions = cursor.fetchone()[0]
                
                # 警告レベルイベント
                cursor.execute('''
                    SELECT COUNT(*) FROM security_events
                    WHERE timestamp > ? AND severity IN ('WARNING', 'ERROR')
                ''', (yesterday.isoformat(),))
                
                warning_events = cursor.fetchone()[0]
                
                report = {
                    'timestamp': datetime.now().isoformat(),
                    'login_success': login_stats.get('LOGIN_SUCCESS', 0),
                    'login_failed': login_stats.get('LOGIN_FAILED', 0),
                    'active_sessions': active_sessions,
                    'warning_events': warning_events
                }
                
                self.logger.info(f"セキュリティレポート: {json.dumps(report)}")
                
        except Exception as e:
            self.logger.error(f"セキュリティレポート生成エラー: {e}")
    
    def log_security_event(self, event_type, user_id=None, ip_address=None, 
                          details=None, severity="INFO"):
        """セキュリティイベントをログ"""
        try:
            db_path = self.security_dir / "security.db"
            with sqlite3.connect(str(db_path)) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO security_events (event_type, user_id, ip_address, details, severity)
                    VALUES (?, ?, ?, ?, ?)
                ''', (event_type, user_id, ip_address, details, severity))
                
                conn.commit()
            
            # ログファイルにも記録
            log_message = f"{event_type}"
            if user_id:
                log_message += f" (User ID: {user_id})"
            if ip_address:
                log_message += f" (IP: {ip_address})"
            if details:
                log_message += f" - {details}"
            
            if severity == "ERROR":
                self.logger.error(log_message)
            elif severity == "WARNING":
                self.logger.warning(log_message)
            else:
                self.logger.info(log_message)
            
        except Exception as e:
            print(f"セキュリティイベントログエラー: {e}")
    
    # ユーティリティメソッド
    def get_security_statistics(self):
        """セキュリティ統計を取得"""
        try:
            db_path = self.security_dir / "security.db"
            with sqlite3.connect(str(db_path)) as conn:
                cursor = conn.cursor()
                
                # 総ユーザー数
                cursor.execute('SELECT COUNT(*) FROM users WHERE is_active = 1')
                total_users = cursor.fetchone()[0]
                
                # アクティブセッション数
                cursor.execute('SELECT COUNT(*) FROM sessions WHERE is_active = 1')
                active_sessions = cursor.fetchone()[0]
                
                # 過去24時間のログイン試行
                yesterday = datetime.now() - timedelta(days=1)
                cursor.execute('''
                    SELECT COUNT(*) FROM security_events
                    WHERE event_type = 'LOGIN_SUCCESS' AND timestamp > ?
                ''', (yesterday.isoformat(),))
                successful_logins = cursor.fetchone()[0]
                
                cursor.execute('''
                    SELECT COUNT(*) FROM security_events
                    WHERE event_type = 'LOGIN_FAILED' AND timestamp > ?
                ''', (yesterday.isoformat(),))
                failed_logins = cursor.fetchone()[0]
                
                # APIキー数
                cursor.execute('SELECT COUNT(*) FROM api_keys WHERE is_active = 1')
                active_api_keys = cursor.fetchone()[0]
                
                return {
                    'total_users': total_users,
                    'active_sessions': active_sessions,
                    'successful_logins_24h': successful_logins,
                    'failed_logins_24h': failed_logins,
                    'active_api_keys': active_api_keys
                }
                
        except Exception as e:
            self.logger.error(f"セキュリティ統計取得エラー: {e}")
            return {}
    
    def get_recent_security_events(self, limit=50):
        """最近のセキュリティイベントを取得"""
        try:
            db_path = self.security_dir / "security.db"
            with sqlite3.connect(str(db_path)) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT se.event_type, se.timestamp, se.ip_address, 
                           se.details, se.severity, u.username
                    FROM security_events se
                    LEFT JOIN users u ON se.user_id = u.id
                    ORDER BY se.timestamp DESC
                    LIMIT ?
                ''', (limit,))
                
                events = []
                for row in cursor.fetchall():
                    events.append({
                        'event_type': row[0],
                        'timestamp': row[1],
                        'ip_address': row[2],
                        'details': row[3],
                        'severity': row[4],
                        'username': row[5]
                    })
                
                return events
                
        except Exception as e:
            self.logger.error(f"セキュリティイベント取得エラー: {e}")
            return []


def get_security_manager():
    """セキュリティマネージャーのシングルトンインスタンスを取得"""
    if not hasattr(get_security_manager, '_instance'):
        get_security_manager._instance = SecurityManager()
    return get_security_manager._instance


def main():
    """テスト用メイン関数"""
    security_manager = SecurityManager()
    
    print("=== BLNCS セキュリティマネージャー テスト ===")
    
    # ユーザー作成テスト
    print("\n1. ユーザー作成テスト")
    result = security_manager.create_user("test_user", "test_password123", 
                                        {"admin": True, "api_access": True})
    print(f"結果: {result}")
    
    if result['success']:
        # 認証テスト
        print("\n2. 認証テスト")
        auth_result = security_manager.authenticate_user("test_user", "test_password123")
        print(f"認証結果: {auth_result}")
        
        if auth_result['success']:
            # セッション検証テスト
            print("\n3. セッション検証テスト")
            session_result = security_manager.validate_session(auth_result['session_id'])
            print(f"セッション検証結果: {session_result}")
    
    # 統計情報表示
    print("\n4. セキュリティ統計")
    stats = security_manager.get_security_statistics()
    print(f"統計: {stats}")
    
    # 最近のイベント表示
    print("\n5. 最近のセキュリティイベント")
    events = security_manager.get_recent_security_events(10)
    for event in events:
        print(f"  - {event['timestamp']} {event['event_type']} {event.get('details', '')}")


if __name__ == "__main__":
    main()