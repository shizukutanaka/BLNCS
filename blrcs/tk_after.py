"""
Tkinter after() guard and tracking mixin for clean shutdown.
Provides:
- _init_after_guard(): initialize tracking set and flags
- _safe_after(ms, func): schedule guarded callbacks tracked for cancellation
- _cancel_after(after_id): cancel a specific callback and untrack
- _cancel_all_afters(): bulk-cancel all tracked callbacks

Assumptions:
- self.root is a tkinter root
- self.logger is optional and may provide .debug/.exception
- self._is_shutting_down flag indicates shutdown in progress
"""
from __future__ import annotations
from typing import Callable, Optional

class TkAfterGuardMixin:
    def _init_after_guard(self) -> None:
        if not hasattr(self, "_is_shutting_down"):
            setattr(self, "_is_shutting_down", False)
        if not hasattr(self, "_tracked_after_ids"):
            setattr(self, "_tracked_after_ids", set())

    def _safe_after(self, ms: int, func: Callable[[], None]) -> Optional[str]:
        try:
            if getattr(self, "_is_shutting_down", False) or not getattr(self, "root", None):
                return None
        except Exception:
            return None

        holder = {"id": None}

        def wrapped():
            # Remove id from tracking when firing
            try:
                aid = holder.get("id")
                if aid is not None:
                    getattr(self, "_tracked_after_ids", set()).discard(aid)
            except Exception:
                pass
            # Do not execute during shutdown
            if getattr(self, "_is_shutting_down", False):
                return
            try:
                func()
            except Exception:
                try:
                    logger = getattr(self, "logger", None)
                    if logger:
                        logger.exception("GUI after() callback raised")
                except Exception:
                    pass

        try:
            aid = self.root.after(ms, wrapped)
            try:
                self._tracked_after_ids.add(aid)
            except Exception:
                pass
            holder["id"] = aid
            return aid
        except Exception:
            return None

    def _cancel_after(self, after_id) -> None:
        try:
            if after_id:
                self.root.after_cancel(after_id)
                # Remove from tracking set
                try:
                    getattr(self, "_tracked_after_ids", set()).discard(after_id)
                except Exception:
                    pass
        except Exception:
            pass

    def _cancel_all_afters(self) -> None:
        try:
            ids = list(getattr(self, "_tracked_after_ids", set()))
        except Exception:
            ids = []
        for aid in ids:
            try:
                self.root.after_cancel(aid)
                try:
                    logger = getattr(self, "logger", None)
                    if logger:
                        logger.debug("Shutdown: bulk-cancelled after() id=%s", str(aid))
                except Exception:
                    pass
            except Exception:
                pass
        try:
            getattr(self, "_tracked_after_ids", set()).clear()
        except Exception:
            pass
