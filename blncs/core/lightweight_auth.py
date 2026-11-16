"""Lightweight in-memory authentication for tests and small tools.

Passwords are stored only as PBKDF2-HMAC-SHA256 digests with per-user
salts. Session tokens and API keys are opaque random values; API keys
are stored as SHA-256 digests. Nothing is persisted to disk.
"""

import hashlib
import hmac
import logging
import secrets
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_PBKDF2_ITERATIONS = 100_000
_TOKEN_TTL_SECONDS = 3600


class LightweightAuth:
    """Minimal user, token, and API-key management held in memory."""

    def __init__(self):
        self._users: Dict[str, Dict[str, Any]] = {}
        self._tokens: Dict[str, Dict[str, Any]] = {}
        self._api_keys: Dict[str, str] = {}  # sha256(api_key) -> username
        self._next_user_id = 1

    @staticmethod
    def _hash_password(password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS
        )

    def create_user(
        self, username: str, password: str, roles: Optional[List[str]] = None
    ) -> int:
        """Create a user and return its numeric user id."""
        if username in self._users:
            raise ValueError(f"User already exists: {username}")
        salt = secrets.token_bytes(16)
        user_id = self._next_user_id
        self._next_user_id += 1
        self._users[username] = {
            "user_id": user_id,
            "salt": salt,
            "password_hash": self._hash_password(password, salt),
            "roles": list(roles or []),
        }
        return user_id

    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Verify credentials; return {'username', 'token'} or None."""
        user = self._users.get(username)
        if user is None:
            return None
        candidate = self._hash_password(password, user["salt"])
        if not hmac.compare_digest(candidate, user["password_hash"]):
            return None
        token = secrets.token_urlsafe(32)
        self._tokens[token] = {
            "username": username,
            "expires_at": time.time() + _TOKEN_TTL_SECONDS,
        }
        return {"username": username, "token": token}

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Return the token payload for a valid, unexpired token."""
        session = self._tokens.get(token)
        if session is None:
            return None
        if time.time() > session["expires_at"]:
            del self._tokens[token]
            return None
        return {"username": session["username"]}

    def create_api_key(self, user_id: int) -> Optional[str]:
        """Create an API key for the user with the given id."""
        username = None
        for name, user in self._users.items():
            if user["user_id"] == user_id:
                username = name
                break
        if username is None:
            return None
        api_key = secrets.token_urlsafe(32)
        digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        self._api_keys[digest] = username
        return api_key

    def verify_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Return {'username'} when the API key is known, else None."""
        digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        username = self._api_keys.get(digest)
        if username is None:
            return None
        return {"username": username}
