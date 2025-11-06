"""
Lightweight API key authentication manager for BLNCS.
Provides secure key storage, validation, and Flask integration helpers.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

try:  # Optional dependency used for configuration fallbacks
    from .config_manager import UnifiedConfigManager  # type: ignore
except Exception:  # pragma: no cover - fallback when config manager is unavailable
    UnifiedConfigManager = None  # type: ignore

try:
    from .rate_limiter import RateLimiter
except Exception:  # pragma: no cover - very small fallback to keep module usable
    class RateLimiter:  # type: ignore
        def __init__(self, max_requests: int = 5, window_seconds: int = 3600) -> None:
            self.max_requests = max_requests
            self.window_seconds = window_seconds
            self._timestamps: Dict[str, list[float]] = {}
            self._lock = threading.Lock()

        def is_allowed(self, identifier: str) -> bool:
            now = time.time()
            with self._lock:
                timestamps = self._timestamps.setdefault(identifier, [])
                self._timestamps[identifier] = [ts for ts in timestamps if ts > now - self.window_seconds]
                if len(self._timestamps[identifier]) < self.max_requests:
                    self._timestamps[identifier].append(now)
                    return True
                return False

        def remaining_requests(self, identifier: str) -> int:
            now = time.time()
            with self._lock:
                timestamps = self._timestamps.get(identifier, [])
                timestamps = [ts for ts in timestamps if ts > now - self.window_seconds]
                return max(0, self.max_requests - len(timestamps))

        def reset_time(self, identifier: str) -> float:
            now = time.time()
            with self._lock:
                timestamps = self._timestamps.get(identifier, [])
                timestamps = [ts for ts in timestamps if ts > now - self.window_seconds]
                return timestamps[0] + self.window_seconds - now if timestamps else 0.0

        def set_limit(self, max_requests: int, window_seconds: int) -> None:
            with self._lock:
                self.max_requests = max_requests
                self.window_seconds = window_seconds

        def clear(self, identifier: Optional[str] = None) -> None:
            with self._lock:
                if identifier is None:
                    self._timestamps.clear()
                else:
                    self._timestamps.pop(identifier, None)

        def get_statistics(self) -> Dict[str, Any]:
            with self._lock:
                return {
                    "total_identifiers": len(self._timestamps),
                    "max_requests_per_window": self.max_requests,
                    "window_seconds": self.window_seconds,
                }

DEFAULT_STORAGE_PATH = Path("config/auth.json")
DEFAULT_ITERATIONS = 240_000
DEFAULT_PERMISSIONS = {"read": True, "write": False, "admin": False}
AUTH_LOGGER_NAME = "blncs.auth"


@dataclass
class AuthToken:
    """Represents a stored authentication token descriptor."""

    token_id: str
    api_key_hash: str
    salt: str
    iterations: int
    permissions: Dict[str, bool]
    created_at: float
    updated_at: float
    expires_at: Optional[float] = None
    usage_count: int = 0
    last_used_at: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    api_key: Optional[str] = None

    def has_permission(self, permission: str) -> bool:
        return bool(self.permissions.get(permission, False))

    @property
    def is_expired(self) -> bool:
        return self.expires_at is not None and self.expires_at < time.time()

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "token_id": self.token_id,
            "api_key_hash": self.api_key_hash,
            "salt": self.salt,
            "iterations": self.iterations,
            "permissions": self.permissions,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "expires_at": self.expires_at,
            "usage_count": self.usage_count,
            "last_used_at": self.last_used_at,
            "metadata": self.metadata,
        }
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthToken":
        return cls(
            token_id=data["token_id"],
            api_key_hash=data["api_key_hash"],
            salt=data["salt"],
            iterations=data.get("iterations", DEFAULT_ITERATIONS),
            permissions=dict(data.get("permissions", DEFAULT_PERMISSIONS)),
            created_at=float(data.get("created_at", time.time())),
            updated_at=float(data.get("updated_at", time.time())),
            expires_at=data.get("expires_at"),
            usage_count=int(data.get("usage_count", 0)),
            last_used_at=data.get("last_used_at"),
            metadata=dict(data.get("metadata", {})),
        )


class SimpleAuth:
    """File-backed API key authentication manager."""

    def __init__(
        self,
        storage_path: Optional[str] = None,
        iterations: int = DEFAULT_ITERATIONS,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.storage_path = Path(storage_path) if storage_path else DEFAULT_STORAGE_PATH
        self.iterations = max(iterations, 200_000)
        self.logger = logger or logging.getLogger(AUTH_LOGGER_NAME)
        self.logger.addHandler(logging.NullHandler())

        self._lock = threading.RLock()
        self._tokens: Dict[str, AuthToken] = {}
        self._sessions: Dict[str, Dict[str, Any]] = {}

        self.config_manager = self._load_config_manager()
        self.failure_config = self._load_failure_config()
        self.failure_limiter = RateLimiter(
            max_requests=self.failure_config["max_attempts"],
            window_seconds=self.failure_config["window_seconds"],
        )

        self._load_storage()
        self._load_env_tokens()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def generate_api_key(
        self,
        token_id: str,
        permissions: Optional[Dict[str, bool]] = None,
        expires_in: Optional[int] = None,
        expires_at: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Create or replace an API key identified by *token_id*."""

        token_id = str(token_id)
        normalized_permissions = self._normalize_permissions(permissions)
        expiration = self._determine_expiration(expires_in, expires_at)
        api_key = self._generate_api_key_value()
        salt, api_key_hash = self._hash_api_key(api_key)
        now = time.time()

        with self._lock:
            existing = self._tokens.get(token_id)
            usage_count = existing.usage_count if existing else 0
            token = AuthToken(
                token_id=token_id,
                api_key_hash=api_key_hash,
                salt=salt,
                iterations=self.iterations,
                permissions=normalized_permissions,
                created_at=existing.created_at if existing else now,
                updated_at=now,
                expires_at=expiration,
                usage_count=usage_count,
                metadata=metadata or (existing.metadata if existing else {}),
            )
            token.api_key = None
            self._tokens[token_id] = token
            self._persist_tokens()

        self.logger.info(
            "AUTH_KEY_CREATED token_id=%s replaced=%s permissions=%s expires_at=%s",
            token_id,
            existing is not None,
            sorted(k for k, v in normalized_permissions.items() if v),
            int(expiration) if isinstance(expiration, (int, float)) else expiration,
        )

        return api_key

    def rotate_api_key(
        self,
        api_key: str,
        permissions: Optional[Dict[str, bool]] = None,
        expires_in: Optional[int] = None,
        expires_at: Optional[float] = None,
    ) -> str:
        """Rotate an existing API key, invalidating the previous secret."""

        with self._lock:
            stored = self._find_token_by_key(api_key)
            if stored is None:
                raise ValueError("API key not found")

            return self.rotate_api_key_by_id(
                stored.token_id,
                permissions=permissions or stored.permissions,
                expires_in=expires_in,
                expires_at=expires_at if expires_at is not None else stored.expires_at,
                metadata=stored.metadata,
            )

    def rotate_api_key_by_id(
        self,
        token_id: str,
        permissions: Optional[Dict[str, bool]] = None,
        expires_in: Optional[int] = None,
        expires_at: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Rotate an existing API key identified by *token_id*."""

        token_id = str(token_id)

        with self._lock:
            stored = self._tokens.get(token_id)
            if stored is None:
                raise ValueError("Token ID not found")

            normalized_permissions = self._normalize_permissions(permissions or stored.permissions)
            expiration = self._determine_expiration(
                expires_in,
                expires_at if expires_at is not None else stored.expires_at,
            )

            self._tokens.pop(token_id, None)
            new_key = self.generate_api_key(
                token_id=token_id,
                permissions=normalized_permissions,
                expires_in=None,
                expires_at=expiration,
                metadata=metadata or stored.metadata,
            )

            self.logger.info(
                "AUTH_KEY_ROTATED token_id=%s permissions=%s expires_at=%s",
                token_id,
                sorted(k for k, v in normalized_permissions.items() if v),
                int(expiration) if isinstance(expiration, (int, float)) else expiration,
            )

            return new_key

    def validate_api_key(self, api_key: Optional[str]) -> Optional[AuthToken]:
        """Validate *api_key* returning an ``AuthToken`` snapshot or ``None``."""

        if not api_key:
            return None

        now = time.time()
        with self._lock:
            for stored in self._tokens.values():
                if stored.is_expired:
                    continue
                if self._compare_api_key(api_key, stored):
                    stored.usage_count += 1
                    stored.last_used_at = now
                    stored.updated_at = now
                    self._persist_tokens()

                    return AuthToken(
                        token_id=stored.token_id,
                        api_key_hash=stored.api_key_hash,
                        salt=stored.salt,
                        iterations=stored.iterations,
                        permissions=dict(stored.permissions),
                        created_at=stored.created_at,
                        updated_at=stored.updated_at,
                        expires_at=stored.expires_at,
                        usage_count=stored.usage_count,
                        last_used_at=stored.last_used_at,
                        metadata=dict(stored.metadata),
                    )

        return None

    def revoke_api_key(self, api_key_or_id: str) -> bool:
        """Remove an API key using either its plaintext value or token identifier."""

        with self._lock:
            stored = self._tokens.get(api_key_or_id)
            if stored is None:
                stored = self._find_token_by_key(api_key_or_id)

            if stored is None:
                return False

            self._tokens.pop(stored.token_id, None)
            self._invalidate_sessions(stored.token_id)
            self._persist_tokens()
            self.logger.info(
                "AUTH_KEY_REVOKED token_id=%s remaining_tokens=%d",
                stored.token_id,
                len(self._tokens),
            )
            return True

    def list_tokens(self) -> list[Dict[str, Any]]:
        """Return sanitized summaries for all stored tokens."""

        with self._lock:
            summaries = []
            for token in self._tokens.values():
                summaries.append(
                    {
                        "token_id": token.token_id,
                        "permissions": dict(token.permissions),
                        "created_at": token.created_at,
                        "updated_at": token.updated_at,
                        "expires_at": token.expires_at,
                        "usage_count": token.usage_count,
                        "last_used_at": token.last_used_at,
                        "metadata": dict(token.metadata),
                    }
                )

        return sorted(summaries, key=lambda entry: entry["token_id"])

    def get_token(self, token_id: str) -> Optional[Dict[str, Any]]:
        """Return a sanitized summary for *token_id*, or ``None`` if missing."""

        token_id = str(token_id)
        with self._lock:
            token = self._tokens.get(token_id)
            if token is None:
                return None

            return {
                "token_id": token.token_id,
                "permissions": dict(token.permissions),
                "created_at": token.created_at,
                "updated_at": token.updated_at,
                "expires_at": token.expires_at,
                "usage_count": token.usage_count,
                "last_used_at": token.last_used_at,
                "metadata": dict(token.metadata),
            }

    def export_statistics(self, window_seconds: int = 86_400) -> Dict[str, Any]:
        """Summarize token inventory and risk indicators."""

        window = max(0, int(window_seconds))
        with self._lock:
            now = time.time()
            total_tokens = len(self._tokens)
            expired_tokens = 0
            active_tokens = 0
            expiring_soon: List[str] = []
            never_used = 0
            last_updated_at: Optional[float] = None
            max_usage_count = 0

            for token in self._tokens.values():
                if token.is_expired:
                    expired_tokens += 1
                else:
                    active_tokens += 1
                    if (
                        token.expires_at is not None
                        and (token.expires_at - now) <= window
                    ):
                        expiring_soon.append(token.token_id)

                if token.usage_count == 0:
                    never_used += 1

                if last_updated_at is None or token.updated_at > last_updated_at:
                    last_updated_at = token.updated_at

                if token.usage_count > max_usage_count:
                    max_usage_count = token.usage_count

            return {
                "storage_path": str(self.storage_path),
                "total_tokens": total_tokens,
                "active_tokens": active_tokens,
                "expired_tokens": expired_tokens,
                "expiring_within_seconds": window,
                "expiring_soon": sorted(expiring_soon),
                "never_used_tokens": never_used,
                "max_usage_count": max_usage_count,
                "last_updated_at": last_updated_at,
                "failure_limits": self.export_failure_limits(),
            }

    def prune_tokens(
        self,
        *,
        include_expired: bool = True,
        idle_seconds: Optional[float] = None,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """Remove tokens matching the provided criteria."""

        idle_window: Optional[float] = None
        if idle_seconds is not None:
            idle_window = max(0.0, float(idle_seconds))

        with self._lock:
            now = time.time()
            matched: List[Dict[str, Any]] = []

            for token in self._tokens.values():
                reasons: List[str] = []

                if include_expired and token.is_expired:
                    reasons.append("expired")

                if idle_window is not None:
                    last_activity = token.last_used_at or token.updated_at or token.created_at
                    if last_activity <= now - idle_window:
                        reasons.append("inactive")

                if reasons:
                    matched.append({
                        "token_id": token.token_id,
                        "reasons": sorted(set(reasons)),
                        "expires_at": token.expires_at,
                        "last_used_at": token.last_used_at,
                        "usage_count": token.usage_count,
                    })

            if dry_run or not matched:
                return {
                    "dry_run": dry_run,
                    "criteria": {
                        "include_expired": include_expired,
                        "idle_seconds": idle_window,
                    },
                    "matched": matched,
                    "pruned": [],
                    "remaining_tokens": len(self._tokens),
                }

            pruned_ids: List[str] = []
            for entry in matched:
                token_id = entry["token_id"]
                removed = self._tokens.pop(token_id, None)
                if removed is None:
                    continue

                self._invalidate_sessions(token_id)
                pruned_ids.append(token_id)
                reason_str = ",".join(entry["reasons"])
                self.logger.info(
                    "AUTH_KEY_PRUNED token_id=%s reason=%s",
                    token_id,
                    reason_str,
                )

            if pruned_ids:
                self._persist_tokens()

            return {
                "dry_run": dry_run,
                "criteria": {
                    "include_expired": include_expired,
                    "idle_seconds": idle_window,
                },
                "matched": matched,
                "pruned": pruned_ids,
                "remaining_tokens": len(self._tokens),
            }

    def create_session(self, token: AuthToken, ttl: int = 3600) -> str:
        """Create a transient session linked to *token* with a configurable TTL."""

        session_id = secrets.token_hex(16)
        expires_at = time.time() + max(ttl, 1)
        with self._lock:
            self._sessions[session_id] = {
                "token_id": token.token_id,
                "expires_at": expires_at,
            }
        return session_id

    def validate_session(self, session_id: str) -> Optional[AuthToken]:
        """Validate a previously issued session identifier."""

        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None
            if session["expires_at"] < time.time():
                self._sessions.pop(session_id, None)
                return None

            stored = self._tokens.get(session["token_id"])
            if stored is None:
                self._sessions.pop(session_id, None)
                return None

            return AuthToken(
                token_id=stored.token_id,
                api_key_hash=stored.api_key_hash,
                salt=stored.salt,
                iterations=stored.iterations,
                permissions=dict(stored.permissions),
                created_at=stored.created_at,
                updated_at=stored.updated_at,
                expires_at=stored.expires_at,
                usage_count=stored.usage_count,
                last_used_at=stored.last_used_at,
                metadata=dict(stored.metadata),
            )

    def require_auth(self, permission: str) -> Callable:
        """Decorator enforcing the presence of a valid API key with *permission*."""

        def decorator(func: Callable) -> Callable:
            from functools import wraps

            @wraps(func)
            def wrapper(*args, **kwargs):
                api_key = kwargs.pop("api_key", None)
                metadata = self._collect_request_metadata()
                if api_key is None:
                    extracted = self._extract_api_key_from_request()
                    if extracted is not None:
                        api_key = extracted

                fail_identifier = f"auth_fail:{metadata.get('client_ip') or 'unknown'}"

                def auth_failure(message: str, status: int = 401):
                    allowed = self.failure_limiter.is_allowed(fail_identifier)
                    if not allowed:
                        self.logger.error(
                            "AUTH_RATE_LIMIT identifier=%s correlation=%s",
                            fail_identifier,
                            metadata.get("correlation_id"),
                        )
                        return {"error": "Too many authentication failures"}, 429

                    self.logger.warning(
                        "AUTH_DENIED reason=%s correlation=%s",
                        message,
                        metadata.get("correlation_id"),
                    )
                    return {"error": message.replace("_", " ")}, status

                if not api_key:
                    return auth_failure("invalid_or_missing_token", status=401)

                token = self.validate_api_key(api_key)
                if token is None:
                    return auth_failure("invalid_or_missing_token", status=401)

                if not token.has_permission(permission):
                    return auth_failure("insufficient_permissions", status=403)

                # Successful authentication, clear failure counter
                self.failure_limiter.clear(fail_identifier)
                self.logger.info(
                    "AUTH_GRANTED permission=%s token_id=%s correlation=%s endpoint=%s client_ip=%s",
                    permission,
                    token.token_id,
                    metadata.get("correlation_id"),
                    metadata.get("endpoint"),
                    metadata.get("client_ip"),
                )

                kwargs["auth_token"] = token
                result = func(*args, **kwargs)

                # Preserve Flask response objects and explicit tuple responses
                if hasattr(result, "status_code"):
                    return result
                if isinstance(result, tuple):
                    return result

                return result, 200

            return wrapper

        return decorator

    # ------------------------------------------------------------------
    # Failure limiter helpers
    # ------------------------------------------------------------------
    def export_failure_limits(self) -> Dict[str, int]:
        return dict(self.failure_config)

    def clear_all_failures(self) -> None:
        self.failure_limiter.clear()

    def update_failure_limits(self, *, max_attempts: Optional[int] = None, window_seconds: Optional[int] = None) -> None:
        with self._lock:
            if max_attempts is not None:
                self.failure_config["max_attempts"] = int(max(1, max_attempts))
            if window_seconds is not None:
                self.failure_config["window_seconds"] = int(max(1, window_seconds))

            self.failure_limiter.set_limit(
                self.failure_config["max_attempts"],
                self.failure_config["window_seconds"],
            )

            if self.config_manager is not None:
                try:
                    self.config_manager.set("security.max_attempts", self.failure_config["max_attempts"])
                    self.config_manager.set("security.failure_window_seconds", self.failure_config["window_seconds"])
                    self.config_manager.save()
                except Exception:
                    self.logger.exception("Failed to persist authentication failure limits")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _load_config_manager(self):
        # defer heavy imports to avoid recursion
        try:
            from blncs.core import get_config  # type: ignore

            return get_config()
        except Exception:
            if UnifiedConfigManager is None:
                return None
            try:
                return UnifiedConfigManager()
            except Exception:
                return None

    def _load_failure_config(self) -> Dict[str, int]:
        defaults = {"max_attempts": 5, "window_seconds": 3600}
        if self.config_manager is None:
            return defaults

        try:
            max_attempts = int(self.config_manager.get("security.max_attempts", defaults["max_attempts"]))
            window_seconds = int(self.config_manager.get("security.failure_window_seconds", defaults["window_seconds"]))
            return {
                "max_attempts": max(1, max_attempts),
                "window_seconds": max(1, window_seconds),
            }
        except Exception:
            return defaults

    def _load_storage(self) -> None:
        if not self.storage_path.exists():
            return

        try:
            with self.storage_path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except Exception:
            self.logger.exception("Failed to read auth storage: %s", self.storage_path)
            return

        tokens = payload.get("tokens", []) if isinstance(payload, dict) else []
        with self._lock:
            self._tokens.clear()
            for entry in tokens:
                try:
                    token = AuthToken.from_dict(entry)
                    self._tokens[token.token_id] = token
                except Exception:
                    self.logger.exception("Discarding malformed token entry: %s", entry)

    def _persist_tokens(self) -> None:
        with self._lock:
            payload = {
                "version": 1,
                "updated_at": time.time(),
                "tokens": [token.to_dict() for token in self._tokens.values()],
            }
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self.storage_path.with_suffix(".tmp")
            with tmp_path.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            tmp_path.replace(self.storage_path)

    def _generate_api_key_value(self) -> str:
        return "blncs_" + secrets.token_urlsafe(24)

    def _hash_api_key(self, api_key: str) -> Tuple[str, str]:
        salt = os.urandom(16)
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            api_key.encode("utf-8"),
            salt,
            self.iterations,
        )
        return base64.b64encode(salt).decode("ascii"), base64.b64encode(digest).decode("ascii")

    def _rehash_api_key(self, api_key: str, salt: bytes, iterations: int) -> str:
        digest = hashlib.pbkdf2_hmac("sha256", api_key.encode("utf-8"), salt, iterations)
        return base64.b64encode(digest).decode("ascii")

    def _compare_api_key(self, api_key: str, token: AuthToken) -> bool:
        try:
            salt = base64.b64decode(token.salt)
        except Exception:
            return False
        computed = self._rehash_api_key(api_key, salt, token.iterations)
        return hmac.compare_digest(computed, token.api_key_hash)

    def _find_token_by_key(self, api_key: str) -> Optional[AuthToken]:
        for token in self._tokens.values():
            if token.is_expired:
                continue
            if self._compare_api_key(api_key, token):
                return token
        return None

    def _normalize_permissions(self, permissions: Optional[Dict[str, bool]]) -> Dict[str, bool]:
        normalized = dict(DEFAULT_PERMISSIONS)
        if permissions:
            for key in normalized.keys():
                if key in permissions:
                    normalized[key] = bool(permissions[key])
        return normalized

    def _determine_expiration(
        self,
        expires_in: Optional[int],
        expires_at: Optional[float],
    ) -> Optional[float]:
        now = time.time()
        if expires_at is not None:
            return float(expires_at)
        if expires_in is not None:
            return now + max(1, float(expires_in))
        return None

    def _invalidate_sessions(self, token_id: str) -> None:
        self._sessions = {
            sid: session
            for sid, session in self._sessions.items()
            if session.get("token_id") != token_id
        }

    # ------------------------------------------------------------------
    # Environment loading
    # ------------------------------------------------------------------
    def _load_env_tokens(self) -> None:
        for prefix, default_id in (
            ("BLNCS_API_TOKEN", "api"),
            ("BLNCS_CLI_TOKEN", "cli"),
        ):
            self._apply_env_token(prefix, default_id)

        if self._tokens:
            self._persist_tokens()

    def _apply_env_token(self, prefix: str, default_id: str) -> None:
        token_value = os.getenv(prefix)
        if not token_value:
            return

        token_id = os.getenv(f"{prefix}_ID", default_id)
        permissions = self._parse_permissions(os.getenv(f"{prefix}_PERMISSIONS"))
        ttl_str = os.getenv(f"{prefix}_TTL")
        expires_at_str = os.getenv(f"{prefix}_EXPIRES_AT")
        expiration = self._parse_expiration(ttl_str, expires_at_str)

        salt, api_key_hash = self._hash_api_key(token_value)
        now = time.time()

        with self._lock:
            existing = self._tokens.get(token_id)
            token = AuthToken(
                token_id=token_id,
                api_key_hash=api_key_hash,
                salt=salt,
                iterations=self.iterations,
                permissions=permissions,
                created_at=existing.created_at if existing else now,
                updated_at=now,
                expires_at=expiration,
                usage_count=existing.usage_count if existing else 0,
                metadata=existing.metadata if existing else {"managed_by": "env"},
            )
            token.api_key = None
            self._tokens[token_id] = token

    def _parse_permissions(self, raw: Optional[str]) -> Dict[str, bool]:
        if not raw:
            return dict(DEFAULT_PERMISSIONS)
        normalized = dict(DEFAULT_PERMISSIONS)
        tokens = [item.strip().lower() for item in raw.split(",") if item.strip()]
        for key in normalized.keys():
            normalized[key] = key in tokens
        return normalized

    def _parse_expiration(self, ttl: Optional[str], explicit: Optional[str]) -> Optional[float]:
        if explicit:
            explicit = explicit.strip()
            if explicit.isdigit():
                return float(explicit)
            try:
                dt = datetime.fromisoformat(explicit)
            except ValueError:
                pass
            else:
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.timestamp()

        if ttl:
            try:
                ttl_seconds = float(ttl)
                return time.time() + max(1.0, ttl_seconds)
            except ValueError:
                return None
        return None

    # ------------------------------------------------------------------
    # Request helpers
    # ------------------------------------------------------------------
    def _extract_api_key_from_request(self) -> Optional[str]:
        try:
            from flask import request  # type: ignore
        except Exception:
            return None

        try:
            headers = request.headers
            api_key = headers.get("X-API-Key")
            if api_key:
                return api_key

            auth_header = headers.get("Authorization")
            if auth_header and auth_header.lower().startswith("bearer "):
                return auth_header.split(" ", 1)[1].strip()

            return request.args.get("api_key")
        except RuntimeError:
            return None

    def _collect_request_metadata(self) -> Dict[str, Any]:
        metadata: Dict[str, Any] = {
            "timestamp": time.time(),
            "correlation_id": secrets.token_hex(16),
            "client_ip": None,
            "endpoint": None,
            "method": None,
        }

        try:
            from flask import request  # type: ignore
        except Exception:
            return metadata

        try:
            metadata["endpoint"] = getattr(request, "path", None)
            metadata["method"] = getattr(request, "method", None)
            forwarded = request.headers.get("X-Forwarded-For")
            if forwarded:
                metadata["client_ip"] = forwarded.split(",")[0].strip()
            else:
                metadata["client_ip"] = getattr(request, "remote_addr", None)

            correlation = (
                request.headers.get("X-Request-ID")
                or request.headers.get("X-Correlation-ID")
                or request.environ.get("REQUEST_ID")
            )
            if correlation:
                metadata["correlation_id"] = correlation
        except RuntimeError:
            pass
        return metadata


# ----------------------------------------------------------------------
# Module-level helpers
# ----------------------------------------------------------------------
_auth_instance: Optional[SimpleAuth] = None
_auth_lock = threading.Lock()


def get_auth(storage_path: Optional[str] = None) -> SimpleAuth:
    global _auth_instance
    if _auth_instance is not None:
        return _auth_instance

    with _auth_lock:
        if _auth_instance is None:
            _auth_instance = SimpleAuth(storage_path=storage_path)
    return _auth_instance


def set_auth_instance(instance: Optional[SimpleAuth]) -> None:
    global _auth_instance
    with _auth_lock:
        _auth_instance = instance


def generate_api_key(token_id: str, **kwargs) -> str:
    return get_auth().generate_api_key(token_id, **kwargs)


__all__ = [
    "AuthToken",
    "SimpleAuth",
    "get_auth",
    "set_auth_instance",
    "generate_api_key",
]
