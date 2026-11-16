"""UnifiedCore: a small facade tying together BLNCS core services.

Historically the pasted-in integration tests (and older examples)
refer to a single ``UnifiedCore`` object that exposes the shared
cache and a clean shutdown. This class provides exactly that surface
on top of the existing components.
"""

import logging
from typing import Optional

from blncs.core.simple_cache import SimpleCache

logger = logging.getLogger(__name__)


class UnifiedCore:
    """Facade over the core services used across BLNCS components."""

    def __init__(self, cache: Optional[SimpleCache] = None):
        self.cache = cache or SimpleCache()
        self._shutdown = False

    @property
    def is_shutdown(self) -> bool:
        """Whether shutdown() has been called."""
        return self._shutdown

    def shutdown(self) -> None:
        """Shut the core down, clearing shared in-memory state."""
        if self._shutdown:
            return
        try:
            self.cache.clear()
        except Exception as e:  # pragma: no cover - defensive
            logger.warning(f"Error while clearing cache on shutdown: {e}")
        self._shutdown = True
        logger.info("UnifiedCore shut down")
