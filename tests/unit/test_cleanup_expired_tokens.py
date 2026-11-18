"""Regression tests for the security background cleanup loop.

The cleanup loop in ``UnifiedSecurityManager.start_background_cleanup``
does ``expired_count = self.jwt_manager.cleanup_expired_tokens()`` and
then ``if expired_count > 0``. ``cleanup_expired_tokens`` used to return
``None`` (no return statement), so every loop iteration died with
``TypeError: '>' not supported between instances of 'NoneType' and
'int'`` -- logged as "Security cleanup failed" -- before it could sweep
expired account locks. These tests pin the contract the loop relies on:
the cleanup reports how many tokens it removed, as an ``int``.
"""

import logging
import time

from blncs.core.unified_security import JWTManager, UnifiedSecurityManager


def test_cleanup_expired_tokens_returns_zero_when_nothing_to_clean():
    manager = JWTManager("test-secret")

    assert manager.cleanup_expired_tokens() == 0


def test_cleanup_expired_tokens_returns_removed_count():
    manager = JWTManager("test-secret")
    manager.create_token("alice", expires_in=-10)  # already expired
    manager.create_token("bob", expires_in=3600)  # still valid

    removed = manager.cleanup_expired_tokens()

    assert removed == 1
    assert manager.get_active_token_count() == 1
    # A second sweep finds nothing left to remove.
    assert manager.cleanup_expired_tokens() == 0


def test_background_cleanup_loop_does_not_fail(caplog):
    manager = UnifiedSecurityManager(jwt_secret="test-secret")
    try:
        with caplog.at_level(logging.DEBUG, logger="blncs.core.unified_security"):
            # The first loop iteration runs immediately at thread start;
            # with the bug its failure was logged within milliseconds.
            deadline = time.time() + 2
            while time.time() < deadline:
                if any("Security cleanup failed" in r.message for r in caplog.records):
                    break
                time.sleep(0.05)

        failures = [
            r.message for r in caplog.records if "Security cleanup failed" in r.message
        ]
        assert failures == []
    finally:
        manager.stop_background_cleanup()
