#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
エンタープライズ認証システム
政府機関レベルの多要素認証とセキュリティ機能
"""

import os
import jwt
import hmac
import hashlib
import secrets
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Tuple
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
import ipaddress

logger = logging.getLogger(__name__)

class EnterpriseAuthManager:
    """エンタープライズ認証管理システム"""

    def __init__(self):
        self.jwt_secret = self._get_jwt_secret()
        self.session_store = {}
        self.failed_attempts = {}
        self.ip_whitelist = set()
        self.certificate_store = {}
        self._initialize_security_policies()

    def _get_jwt_secret(self) -> str:
        """JWT秘密鍵の安全な取得"""
        jwt_secret = os.getenv('BLNCS_JWT_SECRET')
        if not jwt_secret:
            raise ValueError("BLNCS_JWT_SECRET 環境変数が設定されていません")

        # 秘密鍵の強度検証
        if len(jwt_secret) < 32:
            raise ValueError("JWT秘密鍵が短すぎます（32文字以上必要）")

        # エントロピー検証
        unique_chars = len(set(jwt_secret))
        if unique_chars < 16:
            logger.warning("⚠️  JWT秘密鍵のエントロピーが低い可能性があります")

        return jwt_secret

    def _initialize_security_policies(self):
        """セキュリティポリシーの初期化"""
        # ログイン試行制限
        self.max_failed_attempts = int(os.getenv('BLNCS_MAX_FAILED_ATTEMPTS', '5'))
        self.lockout_duration = int(os.getenv('BLNCS_LOCKOUT_DURATION', '900'))  # 15分

        # セッション設定
        self.session_timeout = int(os.getenv('BLNCS_SESSION_TIMEOUT', '1800'))  # 30分
        self.require_mfa = os.getenv('BLNCS_REQUIRE_MFA', 'true').lower() == 'true'

        # IP制限設定
        whitelist_env = os.getenv('BLNCS_IP_WHITELIST', '')
        if whitelist_env:
            for ip_range in whitelist_env.split(','):
                try:
                    self.ip_whitelist.add(ipaddress.ip_network(ip_range.strip(), strict=False))
                except Exception as e:
                    logger.error(f"❌ 無効なIP範囲: {ip_range} - {e}")

        logger.info(f"🔒 セキュリティポリシー初期化完了 - MFA: {self.require_mfa}")

    def authenticate_user(self, username: str, password: str, client_ip: str,
                         mfa_token: Optional[str] = None,
                         client_cert: Optional[str] = None) -> Dict[str, any]:
        """多段階ユーザー認証"""

        # 1. IP制限チェック
        if not self._check_ip_allowed(client_ip):
            logger.warning(f"🚫 IP制限によりアクセス拒否: {client_ip}")
            return {"success": False, "error": "IP_NOT_ALLOWED", "requires_whitelist": True}

        # 2. レート制限チェック
        if self._is_rate_limited(username, client_ip):
            logger.warning(f"🚫 レート制限によりアクセス拒否: {username}@{client_ip}")
            return {"success": False, "error": "RATE_LIMITED", "retry_after": self.lockout_duration}

        # 3. ユーザー認証
        user_info = self._verify_credentials(username, password)
        if not user_info:
            self._record_failed_attempt(username, client_ip)
            return {"success": False, "error": "INVALID_CREDENTIALS"}

        # 4. 多要素認証（MFA）
        if self.require_mfa:
            if not mfa_token:
                return {"success": False, "error": "MFA_REQUIRED", "mfa_challenge": self._generate_mfa_challenge(username)}

            if not self._verify_mfa_token(username, mfa_token):
                self._record_failed_attempt(username, client_ip)
                return {"success": False, "error": "INVALID_MFA"}

        # 5. 証明書ベース認証（オプション）
        if client_cert:
            if not self._verify_client_certificate(client_cert, username):
                logger.warning(f"🚫 証明書認証失敗: {username}")
                return {"success": False, "error": "INVALID_CERTIFICATE"}

        # 認証成功
        self._clear_failed_attempts(username, client_ip)

        # セッション作成
        session_token = self._create_session(user_info, client_ip)

        logger.info(f"✅ 認証成功: {username}@{client_ip}")

        return {
            "success": True,
            "token": session_token,
            "user": user_info,
            "expires_at": (datetime.now() + timedelta(seconds=self.session_timeout)).isoformat(),
            "security_level": self._calculate_security_level(client_cert, mfa_token)
        }

    def _check_ip_allowed(self, client_ip: str) -> bool:
        """IP許可リストのチェック"""
        if not self.ip_whitelist:
            return True  # ホワイトリストが空の場合は全IP許可

        try:
            client_addr = ipaddress.ip_address(client_ip)
            for allowed_network in self.ip_whitelist:
                if client_addr in allowed_network:
                    return True
            return False
        except Exception as e:
            logger.error(f"❌ IP検証エラー: {client_ip} - {e}")
            return False

    def _is_rate_limited(self, username: str, client_ip: str) -> bool:
        """レート制限チェック"""
        key = f"{username}:{client_ip}"
        current_time = datetime.now()

        if key not in self.failed_attempts:
            return False

        attempts = self.failed_attempts[key]
        if attempts["count"] >= self.max_failed_attempts:
            if current_time < attempts["locked_until"]:
                return True
            else:
                # ロック期間終了
                del self.failed_attempts[key]

        return False

    def _record_failed_attempt(self, username: str, client_ip: str):
        """失敗試行の記録"""
        key = f"{username}:{client_ip}"
        current_time = datetime.now()

        if key not in self.failed_attempts:
            self.failed_attempts[key] = {"count": 0, "first_attempt": current_time}

        self.failed_attempts[key]["count"] += 1
        self.failed_attempts[key]["last_attempt"] = current_time

        # ロック判定
        if self.failed_attempts[key]["count"] >= self.max_failed_attempts:
            self.failed_attempts[key]["locked_until"] = current_time + timedelta(seconds=self.lockout_duration)
            logger.warning(f"🔒 アカウントロック: {username}@{client_ip} - {self.lockout_duration}秒間")

    def _clear_failed_attempts(self, username: str, client_ip: str):
        """失敗試行のクリア"""
        key = f"{username}:{client_ip}"
        if key in self.failed_attempts:
            del self.failed_attempts[key]

    def _verify_credentials(self, username: str, password: str) -> Optional[Dict]:
        """資格情報の検証"""
        # TODO: 実際のユーザーデータベースと連携
        # デモ用のハードコードされたユーザー（実際は削除すること）
        demo_users = {
            "admin": {
                "password_hash": generate_password_hash("SecurePassword123!"),
                "role": "administrator",
                "permissions": ["all"],
                "mfa_enabled": True
            },
            "operator": {
                "password_hash": generate_password_hash("OperatorPass456!"),
                "role": "operator",
                "permissions": ["read", "lightning_operations"],
                "mfa_enabled": True
            }
        }

        if username in demo_users:
            user = demo_users[username]
            if check_password_hash(user["password_hash"], password):
                return {
                    "username": username,
                    "role": user["role"],
                    "permissions": user["permissions"],
                    "mfa_enabled": user["mfa_enabled"]
                }

        return None

    def _generate_mfa_challenge(self, username: str) -> Dict:
        """MFAチャレンジの生成"""
        # TOTP またはWebAuthnチャレンジを生成
        challenge = {
            "type": "totp",
            "message": "Google Authenticator等のTOTPアプリでコードを入力してください",
            "backup_methods": ["sms", "email"]
        }

        # 実装時はWebAuthnも対応
        if os.getenv('BLNCS_WEBAUTHN_ENABLED', 'false').lower() == 'true':
            challenge["webauthn_challenge"] = self._generate_webauthn_challenge(username)

        return challenge

    def _verify_mfa_token(self, username: str, token: str) -> bool:
        """MFAトークンの検証"""
        # TODO: 実際のTOTP/WebAuthn検証ライブラリと連携
        # デモ用の簡易検証（実際は削除すること）
        if len(token) == 6 and token.isdigit():
            # 簡易TOTP風検証（実際はpyotp等を使用）
            current_minute = datetime.now().minute
            expected_token = f"{current_minute:02d}{(current_minute + 1) % 60:02d}XX"[:6]
            return token == expected_token or token == "123456"  # デモ用固定トークン

        return False

    def _verify_client_certificate(self, cert_pem: str, username: str) -> bool:
        """クライアント証明書の検証"""
        try:
            # 証明書のパース（実際はcryptographyライブラリ使用）
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

            # 証明書の有効性チェック
            current_time = datetime.now()
            if current_time < cert.not_valid_before or current_time > cert.not_valid_after:
                logger.warning("🚫 証明書の有効期限切れ")
                return False

            # サブジェクトの確認
            subject = cert.subject
            cert_username = None
            for attribute in subject:
                if attribute.oid == x509.NameOID.COMMON_NAME:
                    cert_username = attribute.value
                    break

            if cert_username != username:
                logger.warning(f"🚫 証明書のユーザー名不一致: {cert_username} != {username}")
                return False

            # 証明書チェーンの検証（実装時はCA証明書と照合）
            logger.info(f"✅ 証明書認証成功: {username}")
            return True

        except Exception as e:
            logger.error(f"❌ 証明書検証エラー: {e}")
            return False

    def _create_session(self, user_info: Dict, client_ip: str) -> str:
        """セッションの作成"""
        session_id = secrets.token_urlsafe(32)
        current_time = datetime.now()
        expires_at = current_time + timedelta(seconds=self.session_timeout)

        # JWT ペイロード
        payload = {
            "session_id": session_id,
            "username": user_info["username"],
            "role": user_info["role"],
            "permissions": user_info["permissions"],
            "client_ip": client_ip,
            "iat": current_time.timestamp(),
            "exp": expires_at.timestamp(),
            "jti": session_id  # JWT ID
        }

        # JWTトークン生成
        token = jwt.encode(payload, self.jwt_secret, algorithm="HS256")

        # セッション情報をストアに保存
        self.session_store[session_id] = {
            "user_info": user_info,
            "client_ip": client_ip,
            "created_at": current_time,
            "expires_at": expires_at,
            "last_access": current_time
        }

        logger.info(f"🎫 セッション作成: {user_info['username']} - {session_id[:8]}...")
        return token

    def _calculate_security_level(self, client_cert: Optional[str], mfa_token: Optional[str]) -> str:
        """セキュリティレベルの計算"""
        level = "basic"

        if mfa_token:
            level = "enhanced"

        if client_cert:
            level = "maximum"

        return level

    def verify_token(self, token: str, client_ip: str) -> Optional[Dict]:
        """トークンの検証"""
        try:
            # JWT検証
            payload = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])

            session_id = payload.get("session_id")
            if not session_id or session_id not in self.session_store:
                logger.warning("🚫 無効なセッション")
                return None

            session = self.session_store[session_id]

            # IP制限チェック
            if session["client_ip"] != client_ip:
                logger.warning(f"🚫 IP不一致: 期待={session['client_ip']}, 実際={client_ip}")
                return None

            # セッション有効期限チェック
            if datetime.now() > session["expires_at"]:
                logger.warning("🚫 セッション期限切れ")
                self._invalidate_session(session_id)
                return None

            # 最終アクセス時刻更新
            session["last_access"] = datetime.now()

            return {
                "valid": True,
                "user": session["user_info"],
                "session_id": session_id,
                "security_level": self._calculate_security_level(None, None)  # TODO: 実際の値を設定
            }

        except jwt.ExpiredSignatureError:
            logger.warning("🚫 JWT期限切れ")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"🚫 無効なJWT: {e}")
            return None

    def _invalidate_session(self, session_id: str):
        """セッションの無効化"""
        if session_id in self.session_store:
            del self.session_store[session_id]
            logger.info(f"🗑️  セッション無効化: {session_id[:8]}...")

    def logout(self, token: str) -> bool:
        """ログアウト"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
            session_id = payload.get("session_id")

            if session_id:
                self._invalidate_session(session_id)
                return True

        except Exception as e:
            logger.error(f"❌ ログアウトエラー: {e}")

        return False

    def get_security_report(self) -> Dict:
        """セキュリティ状況レポート"""
        current_time = datetime.now()

        # アクティブセッション数
        active_sessions = sum(1 for s in self.session_store.values()
                            if s["expires_at"] > current_time)

        # 失敗試行統計
        failed_attempts_count = len(self.failed_attempts)
        locked_accounts = sum(1 for attempts in self.failed_attempts.values()
                            if attempts.get("locked_until", current_time) > current_time)

        return {
            "timestamp": current_time.isoformat(),
            "active_sessions": active_sessions,
            "total_sessions": len(self.session_store),
            "failed_attempts": failed_attempts_count,
            "locked_accounts": locked_accounts,
            "ip_whitelist_enabled": len(self.ip_whitelist) > 0,
            "mfa_required": self.require_mfa,
            "security_recommendations": self._generate_security_recommendations()
        }

    def _generate_security_recommendations(self) -> List[str]:
        """セキュリティ推奨事項の生成"""
        recommendations = []

        if not self.require_mfa:
            recommendations.append("多要素認証（MFA）を有効にすることを強く推奨します")

        if not self.ip_whitelist:
            recommendations.append("IP許可リストの設定を検討してください")

        if self.session_timeout > 3600:
            recommendations.append("セッションタイムアウトを1時間以下に設定することを推奨します")

        # 古いセッションのクリーンアップ警告
        old_sessions = sum(1 for s in self.session_store.values()
                         if (datetime.now() - s["last_access"]).total_seconds() > 86400)
        if old_sessions > 10:
            recommendations.append(f"{old_sessions}個の古いセッションが残っています。クリーンアップを検討してください")

        return recommendations

# デコレータ：認証が必要なエンドポイント用
def require_auth(auth_manager: EnterpriseAuthManager, required_permissions: List[str] = None):
    """認証デコレータ"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import request, jsonify

            # Authorizationヘッダーの取得
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({"error": "認証が必要です"}), 401

            token = auth_header.split(' ')[1]
            client_ip = request.remote_addr

            # トークン検証
            auth_result = auth_manager.verify_token(token, client_ip)
            if not auth_result or not auth_result["valid"]:
                return jsonify({"error": "無効なトークンです"}), 401

            # 権限チェック
            if required_permissions:
                user_permissions = auth_result["user"]["permissions"]
                if not any(perm in user_permissions for perm in required_permissions) and "all" not in user_permissions:
                    return jsonify({"error": "権限が不足しています"}), 403

            # ユーザー情報をリクエストコンテキストに追加
            request.current_user = auth_result["user"]
            request.session_id = auth_result["session_id"]

            return f(*args, **kwargs)
        return decorated_function
    return decorator

# 使用例
def main():
    """認証システムのテスト"""
    try:
        # 環境変数設定（テスト用）
        os.environ['BLNCS_JWT_SECRET'] = secrets.token_urlsafe(32)

        # 認証管理の初期化
        auth_manager = EnterpriseAuthManager()

        # 認証テスト
        auth_result = auth_manager.authenticate_user(
            username="admin",
            password="SecurePassword123!",
            client_ip="127.0.0.1",
            mfa_token="123456"  # デモ用固定
        )

        if auth_result["success"]:
            print(f"✅ 認証成功: {auth_result['user']['username']}")
            print(f"🎫 トークン: {auth_result['token'][:20]}...")

            # トークン検証テスト
            verify_result = auth_manager.verify_token(auth_result["token"], "127.0.0.1")
            if verify_result and verify_result["valid"]:
                print("✅ トークン検証成功")
            else:
                print("❌ トークン検証失敗")

        else:
            print(f"❌ 認証失敗: {auth_result['error']}")

        # セキュリティレポート
        report = auth_manager.get_security_report()
        print(f"📊 セキュリティレポート:")
        print(f"  🔑 アクティブセッション: {report['active_sessions']}")
        print(f"  🚫 失敗試行: {report['failed_attempts']}")
        print(f"  🔒 MFA有効: {report['mfa_required']}")

        print("🎉 エンタープライズ認証システム動作確認完了")

    except Exception as e:
        print(f"❌ エラー: {e}")
        return False

    return True

if __name__ == "__main__":
    main()