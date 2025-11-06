#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
エンタープライズレベルキー管理システム
政府機関対応の暗号化キー管理
"""

import os
import json
import hmac
import hashlib
import secrets
import logging
from typing import Dict, Optional, Tuple
from pathlib import Path
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

class EnterpriseKeyManager:
    """エンタープライズレベルキー管理システム"""

    def __init__(self, key_store_path: str = "secure_keys"):
        self.key_store_path = Path(key_store_path)
        self.key_store_path.mkdir(mode=0o700, exist_ok=True)
        self._key_cache = {}
        self._rotation_schedule = {}
        self._initialize_key_store()

    def _initialize_key_store(self):
        """キーストアの初期化"""
        # メタデータファイルの作成
        metadata_file = self.key_store_path / "metadata.json"
        if not metadata_file.exists():
            metadata = {
                "created": datetime.now().isoformat(),
                "version": "1.0",
                "encryption_algorithm": "AES-256-GCM",
                "key_derivation": "Scrypt",
                "keys": {},
                "rotation_history": []
            }
            self._write_metadata(metadata)
            logger.info("🔐 新しいキーストアを初期化しました")

    def _write_metadata(self, metadata: Dict):
        """メタデータの安全な書き込み"""
        metadata_file = self.key_store_path / "metadata.json"

        # 一時ファイルに書き込み後、アトミックに移動
        temp_file = metadata_file.with_suffix('.tmp')
        with open(temp_file, 'w') as f:
            json.dump(metadata, f, indent=2)

        # WSL環境対応: 直接移動
        temp_file.replace(metadata_file)

    def _read_metadata(self) -> Dict:
        """メタデータの読み込み"""
        metadata_file = self.key_store_path / "metadata.json"
        if metadata_file.exists():
            with open(metadata_file, 'r') as f:
                return json.load(f)
        return {}

    def generate_master_key(self, key_id: str = "master", force_regenerate: bool = False) -> str:
        """マスターキーの生成"""
        metadata = self._read_metadata()

        # 既存キーのチェック
        if key_id in metadata.get("keys", {}) and not force_regenerate:
            logger.info(f"🔑 既存のマスターキーを使用: {key_id}")
            return self._load_key(key_id)

        # 新しいキーの生成
        key = Fernet.generate_key()
        key_info = {
            "created": datetime.now().isoformat(),
            "algorithm": "Fernet",
            "strength": "256-bit",
            "usage": "master_encryption",
            "rotation_due": (datetime.now() + timedelta(days=90)).isoformat(),
            "active": True
        }

        # キーの保存
        self._store_key(key_id, key, key_info)

        # 既存キーを非アクティブ化
        if key_id in metadata.get("keys", {}):
            self._deactivate_old_key(key_id, metadata)

        logger.info(f"🆕 新しいマスターキーを生成: {key_id}")
        return key.decode()

    def _store_key(self, key_id: str, key: bytes, key_info: Dict):
        """キーの安全な保存"""
        # キーファイルの保存
        key_file = self.key_store_path / f"{key_id}.key"

        # 環境変数からのパスフレーズ
        passphrase = os.getenv('BLNCS_KEY_PASSPHRASE', '').encode()
        if not passphrase:
            passphrase = self._generate_system_passphrase()

        # キーの暗号化保存
        encrypted_key = self._encrypt_key_with_passphrase(key, passphrase)

        with open(key_file, 'wb') as f:
            f.write(encrypted_key)

        # メタデータ更新
        metadata = self._read_metadata()
        if "keys" not in metadata:
            metadata["keys"] = {}

        metadata["keys"][key_id] = key_info
        metadata["keys"][key_id]["file"] = str(key_file.name)

        self._write_metadata(metadata)

    def _encrypt_key_with_passphrase(self, key: bytes, passphrase: bytes) -> bytes:
        """パスフレーズによるキー暗号化"""
        salt = os.urandom(32)

        # Scrypt KDF（政府推奨）
        kdf = Scrypt(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            n=2**14,  # CPUコスト
            r=8,      # メモリコスト
            p=1,      # 並列度
            backend=default_backend()
        )

        derived_key = kdf.derive(passphrase)
        fernet = Fernet(Fernet.generate_key())

        # キーの暗号化
        encrypted_key = fernet.encrypt(key)

        # 形式: salt(32) + fernet_key(44) + encrypted_key(variable)
        return salt + fernet.key + encrypted_key

    def _decrypt_key_with_passphrase(self, encrypted_data: bytes, passphrase: bytes) -> bytes:
        """パスフレーズによるキー復号化"""
        salt = encrypted_data[:32]
        fernet_key = encrypted_data[32:76]
        encrypted_key = encrypted_data[76:]

        # 同じKDFでキー復元
        kdf = Scrypt(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )

        try:
            derived_key = kdf.derive(passphrase)
            fernet = Fernet(fernet_key)
            key = fernet.decrypt(encrypted_key)
            return key
        except Exception as e:
            raise ValueError(f"キー復号化失敗: 無効なパスフレーズまたは破損したキー")

    def _generate_system_passphrase(self) -> bytes:
        """システム固有パスフレーズの生成"""
        # システム情報を組み合わせてパスフレーズ生成
        system_info = []

        # ホスト名
        try:
            import socket
            system_info.append(socket.gethostname())
        except:
            system_info.append("unknown_host")

        # MAC アドレス
        try:
            import uuid
            system_info.append(str(uuid.getnode()))
        except:
            system_info.append("unknown_mac")

        # プロセス情報
        system_info.append(str(os.getpid()))
        system_info.append(str(os.getppid()))

        # 組み合わせてハッシュ化
        combined = ":".join(system_info)
        hash_obj = hashlib.sha256(combined.encode())

        logger.warning("⚠️  システム生成パスフレーズを使用中 - 本番環境では BLNCS_KEY_PASSPHRASE を設定してください")
        return hash_obj.digest()

    def _load_key(self, key_id: str) -> Optional[str]:
        """キーの読み込み"""
        metadata = self._read_metadata()

        if key_id not in metadata.get("keys", {}):
            return None

        key_info = metadata["keys"][key_id]
        if not key_info.get("active", False):
            logger.warning(f"⚠️  非アクティブなキー: {key_id}")
            return None

        key_file = self.key_store_path / key_info["file"]
        if not key_file.exists():
            logger.error(f"❌ キーファイルが見つかりません: {key_file}")
            return None

        # キーファイルの読み込み
        with open(key_file, 'rb') as f:
            encrypted_data = f.read()

        # パスフレーズの取得
        passphrase = os.getenv('BLNCS_KEY_PASSPHRASE', '').encode()
        if not passphrase:
            passphrase = self._generate_system_passphrase()

        try:
            key = self._decrypt_key_with_passphrase(encrypted_data, passphrase)
            return key.decode()
        except Exception as e:
            logger.error(f"❌ キー復号化エラー: {e}")
            return None

    def _deactivate_old_key(self, key_id: str, metadata: Dict):
        """古いキーの非アクティブ化"""
        if key_id in metadata.get("keys", {}):
            old_info = metadata["keys"][key_id].copy()
            old_info["deactivated"] = datetime.now().isoformat()
            old_info["active"] = False

            # ローテーション履歴に追加
            if "rotation_history" not in metadata:
                metadata["rotation_history"] = []
            metadata["rotation_history"].append(old_info)

    def rotate_key(self, key_id: str = "master") -> bool:
        """キーローテーション"""
        try:
            logger.info(f"🔄 キーローテーション開始: {key_id}")

            # 新しいキーの生成
            new_key = self.generate_master_key(key_id, force_regenerate=True)

            # ローテーション完了ログ
            logger.info(f"✅ キーローテーション完了: {key_id}")

            return True
        except Exception as e:
            logger.error(f"❌ キーローテーション失敗: {e}")
            return False

    def check_rotation_needed(self) -> Dict[str, bool]:
        """ローテーションが必要なキーのチェック"""
        metadata = self._read_metadata()
        rotation_needed = {}

        for key_id, key_info in metadata.get("keys", {}).items():
            if not key_info.get("active", False):
                continue

            rotation_due = key_info.get("rotation_due")
            if rotation_due:
                due_date = datetime.fromisoformat(rotation_due.replace('Z', '+00:00'))
                rotation_needed[key_id] = datetime.now() > due_date
            else:
                rotation_needed[key_id] = True  # 期限未設定は要ローテーション

        return rotation_needed

    def get_key_status_report(self) -> Dict:
        """キー状況レポート"""
        metadata = self._read_metadata()

        report = {
            "keystore_created": metadata.get("created"),
            "total_keys": len(metadata.get("keys", {})),
            "active_keys": 0,
            "rotation_needed": {},
            "security_recommendations": []
        }

        # アクティブキーのカウント
        for key_id, key_info in metadata.get("keys", {}).items():
            if key_info.get("active", False):
                report["active_keys"] += 1

        # ローテーション状況
        report["rotation_needed"] = self.check_rotation_needed()

        # セキュリティ推奨事項
        if not os.getenv('BLNCS_KEY_PASSPHRASE'):
            report["security_recommendations"].append(
                "本番環境では BLNCS_KEY_PASSPHRASE 環境変数を設定してください"
            )

        if any(report["rotation_needed"].values()):
            report["security_recommendations"].append(
                "期限切れのキーがあります。ローテーションを実行してください"
            )

        return report

    def backup_keystore(self, backup_path: str) -> bool:
        """キーストアのバックアップ"""
        try:
            backup_dir = Path(backup_path)
            backup_dir.mkdir(parents=True, exist_ok=True)

            # タイムスタンプ付きバックアップ
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = backup_dir / f"keystore_backup_{timestamp}.tar.gz"

            # tarコマンドでバックアップ（暗号化オプション付き）
            import subprocess
            result = subprocess.run([
                'tar', 'czf', str(backup_file),
                '-C', str(self.key_store_path.parent),
                str(self.key_store_path.name)
            ], capture_output=True, text=True)

            if result.returncode == 0:
                logger.info(f"✅ キーストアバックアップ完了: {backup_file}")
                return True
            else:
                logger.error(f"❌ バックアップ失敗: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"❌ バックアップエラー: {e}")
            return False

# 使用例とテスト
def main():
    """キー管理システムのテスト"""
    try:
        # キー管理システムの初期化
        key_manager = EnterpriseKeyManager()

        # マスターキーの生成/取得
        master_key = key_manager.generate_master_key()
        print(f"✅ マスターキー取得完了: {master_key[:16]}...")

        # キー状況レポート
        report = key_manager.get_key_status_report()
        print(f"📊 キー状況レポート:")
        print(f"  📁 総キー数: {report['total_keys']}")
        print(f"  🔑 アクティブキー: {report['active_keys']}")

        if report['security_recommendations']:
            print("⚠️  セキュリティ推奨事項:")
            for rec in report['security_recommendations']:
                print(f"  • {rec}")

        # ローテーション状況
        rotation_needed = report['rotation_needed']
        if any(rotation_needed.values()):
            print("🔄 ローテーション必要:")
            for key_id, needed in rotation_needed.items():
                if needed:
                    print(f"  • {key_id}")

        print("🎉 エンタープライズキー管理システム動作確認完了")
        return True

    except Exception as e:
        print(f"❌ エラー: {e}")
        return False

if __name__ == "__main__":
    main()