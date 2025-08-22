import os
import json
import base64
import secrets
from typing import Any, Dict, Optional
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import logging

logger = logging.getLogger(__name__)

class SecretsManager:
    """環境変数とシークレットの安全な管理"""
    
    def __init__(self, master_key: Optional[str] = None):
        self.master_key = master_key or os.getenv("BLRCS_MASTER_KEY")
        if not self.master_key:
            self.master_key = self._generate_master_key()
            logger.warning("Generated new master key. Store it safely!")
            
        # Generate random salt for PBKDF2
        self.salt = self._get_or_generate_salt()
        self.cipher = self._init_cipher()
        self.secrets_file = Path(".secrets.encrypted")
        self.secrets_cache = {}
        
    def _generate_master_key(self) -> str:
        """マスターキー生成"""
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
        
    def _get_or_generate_salt(self) -> bytes:
        """ソルトの取得または生成"""
        salt_file = Path(".secrets.salt")
        
        if salt_file.exists():
            # 既存のソルトを読み込み
            try:
                with open(salt_file, 'rb') as f:
                    salt = f.read()
                if len(salt) == 32:
                    return salt
            except Exception as e:
                logger.warning(f"Failed to read salt file: {e}")
        
        # 新しいソルトを生成
        salt = secrets.token_bytes(32)
        try:
            with open(salt_file, 'wb') as f:
                f.write(salt)
            # ソルトファイルの権限を厳しく設定
            salt_file.chmod(0o600)
        except Exception as e:
            logger.error(f"Failed to save salt file: {e}")
            
        return salt
        
    def _init_cipher(self) -> Fernet:
        """暗号化オブジェクト初期化"""
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(
            kdf.derive(self.master_key.encode())
        )
        return Fernet(key)
        
    def set_secret(self, key: str, value: Any):
        """シークレット設定"""
        self.secrets_cache[key] = value
        self._save_secrets()
        
    def get_secret(self, key: str, default: Any = None) -> Any:
        """シークレット取得"""
        if not self.secrets_cache:
            self._load_secrets()
        return self.secrets_cache.get(key, default)
        
    def _save_secrets(self):
        """シークレットをファイルに保存"""
        try:
            data = json.dumps(self.secrets_cache)
            encrypted = self.cipher.encrypt(data.encode())
            self.secrets_file.write_bytes(encrypted)
            logger.info("Secrets saved successfully")
        except Exception as e:
            logger.error(f"Failed to save secrets: {e}")
            
    def _load_secrets(self):
        """シークレットをファイルから読み込み"""
        try:
            if self.secrets_file.exists():
                encrypted = self.secrets_file.read_bytes()
                decrypted = self.cipher.decrypt(encrypted)
                self.secrets_cache = json.loads(decrypted.decode())
                logger.info("Secrets loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load secrets: {e}")
            self.secrets_cache = {}
            
    def rotate_master_key(self, new_master_key: str):
        """マスターキーローテーション"""
        # 現在のシークレットを読み込み
        self._load_secrets()
        
        # 新しい暗号化オブジェクトを作成
        old_cipher = self.cipher
        self.master_key = new_master_key
        self.cipher = self._init_cipher()
        
        # 再暗号化して保存
        self._save_secrets()
        logger.info("Master key rotated successfully")
        
    def get_database_url(self) -> str:
        """データベースURL取得（機密情報を含む）"""
        db_config = {
            "host": self.get_secret("DB_HOST", "localhost"),
            "port": self.get_secret("DB_PORT", 5432),
            "user": self.get_secret("DB_USER", "blrcs"),
            "password": self.get_secret("DB_PASSWORD", ""),
            "database": self.get_secret("DB_NAME", "blrcs")
        }
        
        return f"postgresql://{db_config['user']}:{db_config['password']}@{db_config['host']}:{db_config['port']}/{db_config['database']}"
        
    def get_api_keys(self) -> Dict[str, str]:
        """API キー取得"""
        return {
            "lightning": self.get_secret("LND_API_KEY", ""),
            "blockchain": self.get_secret("BLOCKCHAIN_API_KEY", ""),
            "exchange": self.get_secret("EXCHANGE_API_KEY", ""),
            "monitoring": self.get_secret("MONITORING_API_KEY", "")
        }
        
    def validate_environment(self) -> bool:
        """環境変数検証"""
        required_vars = [
            "BLRCS_ENV",
            "BLRCS_SECRET_KEY",
            "BLRCS_DATABASE_URL"
        ]
        
        missing = []
        for var in required_vars:
            if not os.getenv(var) and not self.get_secret(var):
                missing.append(var)
                
        if missing:
            logger.error(f"Missing required environment variables: {missing}")
            return False
            
        return True

# グローバルインスタンス
secrets_manager = SecretsManager()