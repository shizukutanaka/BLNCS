"""
Graceful Shutdown Handler for BLNCS
Simple and reliable shutdown management
"""

import signal
import sys
import threading
import time
import atexit
from typing import Callable, List, Any
import logging

logger = logging.getLogger(__name__)

class ShutdownHandler:
    """Manages graceful shutdown of the system"""

    def __init__(self):
        self.shutdown_hooks: List[Callable] = []
        self.shutdown_in_progress = False
        self._lock = threading.Lock()
        self._original_handlers = {}

        # Register signal handlers
        self._register_signals()

        # Register atexit handler
        atexit.register(self._cleanup)

    def _register_signals(self):
        """Register signal handlers for graceful shutdown"""
        for sig in [signal.SIGINT, signal.SIGTERM]:
            self._original_handlers[sig] = signal.signal(sig, self._signal_handler)

    def _signal_handler(self, signum: int, frame: Any) -> None:
        """Handle shutdown signals"""
        signal_name = signal.Signals(signum).name
        logger.info(f"Received signal: {signal_name}")
        self.shutdown()

    def register_hook(self, hook: Callable[[], None]) -> None:
        """Register a cleanup hook to be called on shutdown"""
        with self._lock:
            if hook not in self.shutdown_hooks:
                self.shutdown_hooks.append(hook)
                logger.debug(f"Registered shutdown hook: {hook.__name__}")

    def unregister_hook(self, hook: Callable[[], None]) -> None:
        """Unregister a cleanup hook"""
        with self._lock:
            if hook in self.shutdown_hooks:
                self.shutdown_hooks.remove(hook)
                logger.debug(f"Unregistered shutdown hook: {hook.__name__}")

    def _cleanup(self):
        """Execute all cleanup hooks"""
        with self._lock:
            if self.shutdown_in_progress:
                return

            self.shutdown_in_progress = True
            logger.info("Starting graceful shutdown...")

            # Execute hooks in reverse order (LIFO)
            for hook in reversed(self.shutdown_hooks):
                try:
                    logger.debug(f"Executing shutdown hook: {hook.__name__}")
                    hook()
                except Exception as e:
                    logger.error(f"Error in shutdown hook {hook.__name__}: {e}")

            logger.info("Graceful shutdown completed")

    def shutdown(self, exit_code: int = 0) -> None:
        """Initiate system shutdown"""
        self._cleanup()

        # Restore original signal handlers
        for sig, handler in self._original_handlers.items():
            signal.signal(sig, handler)

        # Exit
        sys.exit(exit_code)

    def wait_for_shutdown(self, timeout: float = None) -> bool:
        """Wait for shutdown to complete"""
        start_time = time.time()
        while not self.shutdown_in_progress:
            if timeout and (time.time() - start_time) > timeout:
                return False
            time.sleep(0.1)
        return True

# Global instance
_shutdown_handler = None

def get_shutdown_handler() -> ShutdownHandler:
    """Get global shutdown handler instance"""
    global _shutdown_handler
    if _shutdown_handler is None:
        _shutdown_handler = ShutdownHandler()
    return _shutdown_handler

def register_shutdown_hook(hook: Callable[[], None]) -> None:
    """Convenience function to register a shutdown hook"""
    get_shutdown_handler().register_hook(hook)

def graceful_shutdown(exit_code: int = 0) -> None:
    """Convenience function to initiate graceful shutdown"""
    get_shutdown_handler().shutdown(exit_code)

__all__ = ['ShutdownHandler', 'get_shutdown_handler', 'register_shutdown_hook', 'graceful_shutdown']