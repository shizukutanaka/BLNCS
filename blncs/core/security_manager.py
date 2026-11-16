"""Symmetric encryption helper for application-level secrets.

Uses Fernet (AES-128-CBC + HMAC) from the ``cryptography`` package —
no home-grown cryptography. Each instance generates its own key unless
one is supplied, so data encrypted by one instance can only be
decrypted by an instance holding the same key.
"""

import logging
from typing import Optional, Union

from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)


class SecurityManager:
    """Encrypt and decrypt short strings with a Fernet key."""

    def __init__(self, key: Optional[Union[str, bytes]] = None):
        if key is None:
            key = Fernet.generate_key()
        elif isinstance(key, str):
            key = key.encode("utf-8")
        self._key = key
        self._fernet = Fernet(key)

    @property
    def key(self) -> str:
        """The instance's Fernet key, base64-encoded."""
        return self._key.decode("utf-8")

    def encrypt(self, data: str) -> str:
        """Encrypt a string, returning a base64 token string."""
        if not isinstance(data, str):
            raise TypeError("encrypt() expects a str")
        return self._fernet.encrypt(data.encode("utf-8")).decode("utf-8")

    def decrypt(self, token: str) -> str:
        """Decrypt a token produced by :meth:`encrypt`."""
        if not isinstance(token, str):
            raise TypeError("decrypt() expects a str")
        return self._fernet.decrypt(token.encode("utf-8")).decode("utf-8")
