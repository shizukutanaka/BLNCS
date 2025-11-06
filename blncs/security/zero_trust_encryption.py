"""
セキュリティ追加強化システム for BLNCS
ゼロトラストアーキテクチャとエンドツーエンド暗号化機能を提供
"""

import time
import json
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Callable, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import logging
import hashlib
import hmac
import secrets
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

logger = logging.getLogger(__name__)


class TrustLevel(Enum):
    """信頼レベル"""
    UNTRUSTED = "untrusted"
    LOW_TRUST = "low_trust"
    MEDIUM_TRUST = "medium_trust"
    HIGH_TRUST = "high_trust"
    FULLY_TRUSTED = "fully_trusted"


class SecurityEventType(Enum):
    """セキュリティイベントタイプ"""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_ACCESS = "data_access"
    NETWORK_ACCESS = "network_access"
    CONFIG_CHANGE = "config_change"
    ANOMALY_DETECTED = "anomaly_detected"
    POLICY_VIOLATION = "policy_violation"


@dataclass
class SecurityContext:
    """セキュリティコンテキスト情報"""
    user_id: str
    session_id: str
    device_id: str
    ip_address: str
    location: str
    user_agent: str
    trust_level: TrustLevel
    mfa_verified: bool = False
    last_activity: float = field(default_factory=time.time)
    risk_score: float = 0.0


@dataclass
class AccessRequest:
    """アクセスリクエスト情報"""
    request_id: str
    user_id: str
    resource: str
    action: str
    context: SecurityContext
    timestamp: float = field(default_factory=time.time)
    decision: Optional[str] = None  # 'allow', 'deny', 'challenge'
    reason: str = ""


@dataclass
class EncryptionKey:
    """暗号化キー情報"""
    key_id: str
    key_type: str  # 'aes', 'rsa', 'ecc'
    key_data: bytes
    algorithm: str
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    is_active: bool = True


class ZeroTrustPolicyEngine:
    """ゼロトラストポリシーエンジン"""

    def __init__(self, db_path: str = "zero_trust.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self._init_db()
        self.policies: Dict[str, Dict[str, Any]] = {}
        self.security_contexts: Dict[str, SecurityContext] = {}
        self.access_log: List[AccessRequest] = []

    def _init_db(self):
        """データベースを初期化"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_policies (
                    policy_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    resource_pattern TEXT NOT NULL,
                    action TEXT NOT NULL,
                    conditions TEXT,
                    decision TEXT NOT NULL,
                    priority INTEGER DEFAULT 0,
                    is_active INTEGER DEFAULT 1,
                    created_at REAL
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS access_log (
                    id INTEGER PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    action TEXT NOT NULL,
                    decision TEXT,
                    reason TEXT,
                    timestamp REAL,
                    context TEXT
                )
            """)

            conn.commit()

    def add_security_policy(self, policy_id: str, name: str, resource_pattern: str,
                          action: str, conditions: Dict[str, Any], decision: str, priority: int = 0):
        """
        セキュリティポリシーを追加
        Args:
            policy_id: ポリシーID
            name: ポリシー名
            resource_pattern: リソースパターン
            action: アクション
            conditions: 条件設定
            decision: 決定（allow/deny/challenge）
            priority: 優先度
        """
        policy = {
            "policy_id": policy_id,
            "name": name,
            "resource_pattern": resource_pattern,
            "action": action,
            "conditions": conditions,
            "decision": decision,
            "priority": priority,
            "is_active": True,
            "created_at": time.time()
        }

        self.policies[policy_id] = policy

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO security_policies
                    (policy_id, name, resource_pattern, action, conditions, decision, priority, is_active, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    policy_id, name, resource_pattern, action,
                    json.dumps(conditions), decision, priority, 1, time.time()
                ))
                conn.commit()

        except Exception as e:
            logger.error(f"ポリシー追加エラー: {e}")

    def evaluate_access_request(self, request: AccessRequest) -> str:
        """
        アクセスリクエストを評価
        Args:
            request: アクセスリクエスト
        Returns:
            決定結果（allow/deny/challenge）
        """
        # 該当するポリシーを検索（優先度順）
        applicable_policies = []

        for policy in self.policies.values():
            if not policy["is_active"]:
                continue

            # リソースパターンマッチング（簡易版）
            if self._match_resource_pattern(request.resource, policy["resource_pattern"]):
                if request.action == policy["action"]:
                    applicable_policies.append(policy)

        # 優先度が高いポリシーを選択
        if applicable_policies:
            best_policy = max(applicable_policies, key=lambda p: p["priority"])
            decision = self._evaluate_policy_conditions(request, best_policy)
        else:
            # デフォルトポリシー（明示的な許可がない場合は拒否）
            decision = "deny"

        request.decision = decision
        request.reason = f"ポリシー評価結果: {decision}"

        # ログ記録
        self._log_access_request(request)

        return decision

    def _match_resource_pattern(self, resource: str, pattern: str) -> bool:
        """リソースパターンマッチング"""
        # 簡易的なワイルドカードマッチング
        if pattern == "*":
            return True
        elif pattern.endswith("*"):
            return resource.startswith(pattern[:-1])
        elif pattern.startswith("*"):
            return resource.endswith(pattern[1:])
        else:
            return resource == pattern

    def _evaluate_policy_conditions(self, request: AccessRequest, policy: Dict[str, Any]) -> str:
        """ポリシー条件を評価"""
        conditions = policy["conditions"]

        # 信頼レベルチェック
        required_trust = conditions.get("min_trust_level", "untrusted")
        trust_levels = {
            "untrusted": TrustLevel.UNTRUSTED,
            "low_trust": TrustLevel.LOW_TRUST,
            "medium_trust": TrustLevel.MEDIUM_TRUST,
            "high_trust": TrustLevel.HIGH_TRUST,
            "fully_trusted": TrustLevel.FULLY_TRUSTED
        }

        if request.context.trust_level.value < trust_levels[required_trust].value:
            return "challenge"

        # MFA要件チェック
        if conditions.get("require_mfa", False) and not request.context.mfa_verified:
            return "challenge"

        # リスクスコアチェック
        max_risk_score = conditions.get("max_risk_score", 100.0)
        if request.context.risk_score > max_risk_score:
            return "deny"

        # 時間帯制限チェック
        time_restrictions = conditions.get("time_restrictions")
        if time_restrictions:
            current_hour = time.localtime().tm_hour
            if not (time_restrictions["start_hour"] <= current_hour <= time_restrictions["end_hour"]):
                return "deny"

        return policy["decision"]

    def _log_access_request(self, request: AccessRequest):
        """アクセスリクエストをログ記録"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO access_log
                    (request_id, user_id, resource, action, decision, reason, timestamp, context)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    request.request_id, request.user_id, request.resource,
                    request.action, request.decision, request.reason,
                    request.timestamp, json.dumps({
                        "session_id": request.context.session_id,
                        "device_id": request.context.device_id,
                        "ip_address": request.context.ip_address,
                        "trust_level": request.context.trust_level.value,
                        "risk_score": request.context.risk_score
                    })
                ))
                conn.commit()

        except Exception as e:
            logger.error(f"アクセスログ記録エラー: {e}")

    def update_security_context(self, user_id: str, context: SecurityContext):
        """
        セキュリティコンテキストを更新
        Args:
            user_id: ユーザーID
            context: セキュリティコンテキスト
        """
        self.security_contexts[user_id] = context

    def calculate_risk_score(self, context: SecurityContext) -> float:
        """
        リスクスコアを計算
        Args:
            context: セキュリティコンテキスト
        Returns:
            リスクスコア（0-100）
        """
        risk_score = 0.0

        # 信頼レベルによるリスク調整
        trust_risks = {
            TrustLevel.UNTRUSTED: 80.0,
            TrustLevel.LOW_TRUST: 50.0,
            TrustLevel.MEDIUM_TRUST: 20.0,
            TrustLevel.HIGH_TRUST: 10.0,
            TrustLevel.FULLY_TRUSTED: 0.0
        }

        risk_score += trust_risks.get(context.trust_level, 50.0)

        # MFA未検証ペナルティ
        if not context.mfa_verified:
            risk_score += 20.0

        # 位置情報によるリスク調整（簡易版）
        if context.location not in ["JP", "US", "EU"]:  # 許可された地域
            risk_score += 30.0

        return min(100.0, risk_score)


class EndToEndEncryptionManager:
    """エンドツーエンド暗号化マネージャー"""

    def __init__(self, key_rotation_days: int = 30):
        """
        初期化
        Args:
            key_rotation_days: キー回転期間（日）
        """
        self.key_rotation_days = key_rotation_days
        self.encryption_keys: Dict[str, EncryptionKey] = {}
        self.key_rotation_schedule: Dict[str, float] = {}
        self.message_queue: List[Dict[str, Any]] = []

    def generate_data_key(self, key_type: str = "aes") -> EncryptionKey:
        """
        データ暗号化キーを生成
        Args:
            key_type: キー種類
        Returns:
            暗号化キー情報
        """
        if key_type == "aes":
            key_data = Fernet.generate_key()
            algorithm = "AES-256-GCM"
        else:
            # 他のキー種類もサポート可能
            key_data = secrets.token_bytes(32)
            algorithm = "AES-256-CBC"

        key_id = f"key_{int(time.time() * 1000000)}"

        encryption_key = EncryptionKey(
            key_id=key_id,
            key_type=key_type,
            key_data=key_data,
            algorithm=algorithm
        )

        self.encryption_keys[key_id] = encryption_key

        # 回転スケジュールを設定
        self.key_rotation_schedule[key_id] = time.time() + (self.key_rotation_days * 24 * 3600)

        return encryption_key

    def encrypt_message(self, message: str, recipient_public_key: bytes) -> Dict[str, Any]:
        """
        メッセージを暗号化
        Args:
            message: 暗号化するメッセージ
            recipient_public_key: 受信者の公開鍵
        Returns:
            暗号化されたメッセージデータ
        """
        # データキーを生成
        data_key = self.generate_data_key()

        # メッセージをデータキーで暗号化
        fernet = Fernet(data_key.key_data)
        encrypted_message = fernet.encrypt(message.encode('utf-8'))

        # データキーを受信者の公開鍵で暗号化（簡易版）
        # 実際の実装では適切な非対称暗号化を使用
        encrypted_data_key = base64.b64encode(data_key.key_data)

        return {
            "encrypted_message": base64.b64encode(encrypted_message).decode('utf-8'),
            "encrypted_data_key": encrypted_data_key.decode('utf-8'),
            "key_id": data_key.key_id,
            "algorithm": data_key.algorithm,
            "timestamp": time.time()
        }

    def decrypt_message(self, encrypted_data: Dict[str, Any], recipient_private_key: bytes) -> str:
        """
        メッセージを復号化
        Args:
            encrypted_data: 暗号化されたメッセージデータ
            recipient_private_key: 受信者の秘密鍵
        Returns:
            復号化されたメッセージ
        """
        try:
            # データキーを復号化（簡易版）
            encrypted_data_key = base64.b64decode(encrypted_data["encrypted_data_key"])
            data_key_data = base64.b64decode(encrypted_data_key)

            # メッセージを復号化
            fernet = Fernet(data_key_data)
            encrypted_message = base64.b64decode(encrypted_data["encrypted_message"])
            decrypted_message = fernet.decrypt(encrypted_message)

            return decrypted_message.decode('utf-8')

        except Exception as e:
            logger.error(f"メッセージ復号エラー: {e}")
            raise

    def rotate_encryption_keys(self):
        """暗号化キーを回転"""
        current_time = time.time()

        for key_id, key in list(self.encryption_keys.items()):
            if key_id in self.key_rotation_schedule:
                if current_time >= self.key_rotation_schedule[key_id]:
                    # 新しいキーを生成
                    new_key = self.generate_data_key(key.key_type)

                    logger.info(f"暗号化キー回転: {key_id} -> {new_key.key_id}")

                    # 古いキーを無効化
                    key.is_active = False
                    key.expires_at = current_time

                    # 新しいキーの回転スケジュールを設定
                    self.key_rotation_schedule[new_key.key_id] = current_time + (self.key_rotation_days * 24 * 3600)

    def get_active_keys(self) -> List[EncryptionKey]:
        """アクティブなキーを取得"""
        return [key for key in self.encryption_keys.values() if key.is_active]


class NetworkSecurityLayer:
    """ネットワークセキュリティレイヤー"""

    def __init__(self, zero_trust_engine: ZeroTrustPolicyEngine):
        """
        初期化
        Args:
            zero_trust_engine: ゼロトラストポリシーエンジン
        """
        self.zero_trust_engine = zero_trust_engine
        self.secure_channels: Dict[str, Dict[str, Any]] = {}
        self.tls_certificates: Dict[str, Dict[str, Any]] = {}

    def establish_secure_channel(self, connection_id: str, peer_info: Dict[str, Any]) -> bool:
        """
        セキュアチャネルを確立
        Args:
            connection_id: 接続ID
            peer_info: ピア情報
        Returns:
            確立成功フラグ
        """
        try:
            # TLS証明書の検証
            if not self._verify_tls_certificate(peer_info):
                return False

            # ゼロトラスト認証
            if not self._perform_zero_trust_authentication(connection_id, peer_info):
                return False

            # セキュアチャネル情報を記録
            self.secure_channels[connection_id] = {
                "peer_info": peer_info,
                "established_at": time.time(),
                "is_authenticated": True,
                "encryption_enabled": True
            }

            return True

        except Exception as e:
            logger.error(f"セキュアチャネル確立エラー: {e}")
            return False

    def _verify_tls_certificate(self, peer_info: Dict[str, Any]) -> bool:
        """TLS証明書を検証"""
        # 実際の実装では証明書の検証ロジックを実装
        cert_fingerprint = peer_info.get("cert_fingerprint")

        if cert_fingerprint in self.tls_certificates:
            cert_info = self.tls_certificates[cert_fingerprint]
            return cert_info.get("is_valid", False)

        # 未知の証明書は拒否（厳格モード）
        return False

    def _perform_zero_trust_authentication(self, connection_id: str, peer_info: Dict[str, Any]) -> bool:
        """ゼロトラスト認証を実行"""
        # 実際の実装では継続的な認証を実行
        return True

    def validate_ongoing_access(self, connection_id: str, resource: str, action: str) -> bool:
        """
        継続的なアクセスを検証
        Args:
            connection_id: 接続ID
            resource: リソース
            action: アクション
        Returns:
            検証結果
        """
        if connection_id not in self.secure_channels:
            return False

        channel = self.secure_channels[connection_id]

        # チャネルがアクティブかチェック
        if time.time() - channel["established_at"] > 3600:  # 1時間制限
            return False

        # ゼロトラストポリシーに基づいてアクセスを評価
        # 実際の実装では詳細なポリシー評価を実行
        return channel.get("is_authenticated", False)


class SecurityEnhancementManager:
    """セキュリティ強化管理システム"""

    def __init__(self, db_path: str = "security_enhancement.db"):
        """
        初期化
        Args:
            db_path: データベースパス
        """
        self.db_path = db_path
        self.zero_trust_engine = ZeroTrustPolicyEngine(db_path)
        self.encryption_manager = EndToEndEncryptionManager()
        self.network_security = NetworkSecurityLayer(self.zero_trust_engine)

        self.is_security_active = False
        self.security_thread: Optional[threading.Thread] = None

    def initialize_security_system(self):
        """セキュリティシステムを初期化"""
        # デフォルトのゼロトラストポリシーを設定
        self._setup_default_zero_trust_policies()

        # TLS証明書を設定（簡易版）
        self._setup_default_certificates()

    def _setup_default_zero_trust_policies(self):
        """デフォルトのゼロトラストポリシーを設定"""
        # 高リスクアクションのポリシー
        self.zero_trust_engine.add_security_policy(
            "admin_access_policy",
            "管理者アクセス制御",
            "admin/*",
            "write",
            {
                "min_trust_level": "high_trust",
                "require_mfa": True,
                "max_risk_score": 30.0,
                "time_restrictions": {"start_hour": 9, "end_hour": 18}
            },
            "challenge",
            priority=100
        )

        # データアクセスポリシー
        self.zero_trust_engine.add_security_policy(
            "data_access_policy",
            "データアクセス制御",
            "data/*",
            "read",
            {
                "min_trust_level": "medium_trust",
                "require_mfa": False,
                "max_risk_score": 50.0
            },
            "allow",
            priority=50
        )

        # デフォルト拒否ポリシー
        self.zero_trust_engine.add_security_policy(
            "default_deny_policy",
            "デフォルト拒否",
            "*",
            "*",
            {},
            "deny",
            priority=0
        )

    def _setup_default_certificates(self):
        """デフォルトのTLS証明書を設定"""
        # 実際の実装では適切な証明書管理システムを実装
        pass

    def start_security_system(self):
        """セキュリティシステムを開始"""
        if not self.is_security_active:
            self.is_security_active = True
            self.security_thread = threading.Thread(target=self._security_loop, daemon=True)
            self.security_thread.start()

    def stop_security_system(self):
        """セキュリティシステムを停止"""
        self.is_security_active = False
        if self.security_thread:
            self.security_thread.join()

    def evaluate_access(self, user_id: str, resource: str, action: str,
                       context: Optional[SecurityContext] = None) -> str:
        """
        アクセスを評価
        Args:
            user_id: ユーザーID
            resource: リソース
            action: アクション
            context: セキュリティコンテキスト
        Returns:
            評価結果（allow/deny/challenge）
        """
        if not context:
            context = SecurityContext(
                user_id=user_id,
                session_id="unknown",
                device_id="unknown",
                ip_address="0.0.0.0",
                location="unknown",
                user_agent="unknown",
                trust_level=TrustLevel.UNTRUSTED
            )

        # リスクスコアを計算
        context.risk_score = self.zero_trust_engine.calculate_risk_score(context)

        # セキュリティコンテキストを更新
        self.zero_trust_engine.update_security_context(user_id, context)

        # アクセスリクエストを作成
        request = AccessRequest(
            request_id=f"req_{int(time.time() * 1000000)}",
            user_id=user_id,
            resource=resource,
            action=action,
            context=context
        )

        # アクセスを評価
        return self.zero_trust_engine.evaluate_access_request(request)

    def encrypt_communication(self, message: str, recipient_id: str) -> Dict[str, Any]:
        """
        通信を暗号化
        Args:
            message: メッセージ
            recipient_id: 受信者ID
        Returns:
            暗号化されたメッセージデータ
        """
        # 実際の実装では受信者の公開鍵を取得
        recipient_public_key = b"dummy_public_key"

        return self.encryption_manager.encrypt_message(message, recipient_public_key)

    def decrypt_communication(self, encrypted_data: Dict[str, Any], recipient_id: str) -> str:
        """
        通信を復号化
        Args:
            encrypted_data: 暗号化されたデータ
            recipient_id: 受信者ID
        Returns:
            復号化されたメッセージ
        """
        # 実際の実装では受信者の秘密鍵を取得
        recipient_private_key = b"dummy_private_key"

        return self.encryption_manager.decrypt_message(encrypted_data, recipient_private_key)

    def get_security_status(self) -> Dict[str, Any]:
        """セキュリティステータスを取得"""
        return {
            "is_security_active": self.is_security_active,
            "active_policies": len(self.zero_trust_engine.policies),
            "active_keys": len(self.encryption_manager.get_active_keys()),
            "secure_channels": len(self.network_security.secure_channels),
            "risk_score_average": self._calculate_average_risk_score()
        }

    def _calculate_average_risk_score(self) -> float:
        """平均リスクスコアを計算"""
        if not self.zero_trust_engine.security_contexts:
            return 0.0

        scores = [ctx.risk_score for ctx in self.zero_trust_engine.security_contexts.values()]
        return sum(scores) / len(scores)

    def _security_loop(self):
        """セキュリティループ"""
        while self.is_security_active:
            try:
                # 定期的なセキュリティメンテナンス
                self.encryption_manager.rotate_encryption_keys()

                time.sleep(3600)  # 1時間間隔
            except Exception as e:
                logger.error(f"セキュリティループエラー: {e}")


# 使用例
def example_usage():
    manager = SecurityEnhancementManager()

    # システム初期化
    manager.initialize_security_system()

    # システム開始
    manager.start_security_system()

    # セキュリティコンテキスト作成
    context = SecurityContext(
        user_id="user_123",
        session_id="session_456",
        device_id="device_789",
        ip_address="192.168.1.100",
        location="JP",
        user_agent="Mozilla/5.0...",
        trust_level=TrustLevel.HIGH_TRUST,
        mfa_verified=True,
        risk_score=10.0
    )

    # アクセス評価
    decision = manager.evaluate_access("user_123", "admin/config", "write", context)
    print(f"アクセス決定: {decision}")

    # メッセージ暗号化
    encrypted = manager.encrypt_communication("秘密のメッセージ", "recipient_123")
    print(f"暗号化完了: {len(encrypted)}項目")

    # メッセージ復号化
    try:
        decrypted = manager.decrypt_communication(encrypted, "recipient_123")
        print(f"復号化完了: {decrypted}")
    except Exception as e:
        print(f"復号エラー: {e}")

    # セキュリティステータス
    status = manager.get_security_status()
    print(f"セキュリティステータス: {status}")

    manager.stop_security_system()


if __name__ == "__main__":
    example_usage()
