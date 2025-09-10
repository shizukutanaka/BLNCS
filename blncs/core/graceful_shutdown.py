"""
Graceful Shutdown System for BLNCS
Ensures all resources are properly cleaned up during shutdown.
"""

import time
import signal
import threading
import atexit
from typing import List, Callable, Optional, Dict, Any
from dataclasses import dataclass
from enum import Enum
from contextlib import contextmanager

from .logger import get_logger
from .resource_manager import get_resource_manager


class ShutdownPhase(Enum):
    """Phases of graceful shutdown"""
    NORMAL = "normal"
    STOP_ACCEPTING_NEW_WORK = "stop_accepting_new_work"
    FINISH_CURRENT_WORK = "finish_current_work"
    CLEANUP_RESOURCES = "cleanup_resources"
    FORCE_SHUTDOWN = "force_shutdown"
    COMPLETED = "completed"


@dataclass
class ShutdownHook:
    """Shutdown hook configuration"""
    name: str
    handler: Callable
    priority: int = 100  # Lower numbers run first
    timeout: float = 30.0  # Timeout for this hook
    phase: ShutdownPhase = ShutdownPhase.CLEANUP_RESOURCES


class GracefulShutdownManager:
    """Manages graceful shutdown process"""
    
    def __init__(self, total_timeout: float = 60.0):
        self.logger = get_logger(__name__)
        self.total_timeout = total_timeout
        self.resource_manager = get_resource_manager()
        
        # Shutdown state
        self._shutdown_requested = threading.Event()
        self._shutdown_completed = threading.Event()
        self._current_phase = ShutdownPhase.NORMAL
        self._shutdown_start_time: Optional[float] = None
        
        # Shutdown hooks by phase
        self._hooks: Dict[ShutdownPhase, List[ShutdownHook]] = {
            phase: [] for phase in ShutdownPhase
        }
        self._hooks_lock = threading.RLock()
        
        # Active work tracking
        self._active_work_count = 0
        self._work_lock = threading.RLock()
        
        # Register signal handlers
        self._register_signal_handlers()
        
        # Register with atexit
        atexit.register(self.shutdown)
    
    def _register_signal_handlers(self):
        """Register signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            signal_name = signal.Signals(signum).name
            self.logger.info(f"Received {signal_name} signal, initiating graceful shutdown")
            self.shutdown()
        
        # Register handlers for common shutdown signals
        for sig in [signal.SIGTERM, signal.SIGINT]:
            try:
                signal.signal(sig, signal_handler)
            except (OSError, ValueError) as e:
                self.logger.warning(f"Could not register handler for signal {sig}: {e}")
    
    def register_shutdown_hook(self, name: str, handler: Callable, 
                              priority: int = 100, timeout: float = 30.0,
                              phase: ShutdownPhase = ShutdownPhase.CLEANUP_RESOURCES) -> None:
        """Register a shutdown hook"""
        hook = ShutdownHook(
            name=name,
            handler=handler,
            priority=priority,
            timeout=timeout,
            phase=phase
        )
        
        with self._hooks_lock:
            self._hooks[phase].append(hook)
            # Sort by priority (lower numbers first)
            self._hooks[phase].sort(key=lambda h: h.priority)
        
        self.logger.debug(f"Registered shutdown hook: {name} (phase: {phase.value}, priority: {priority})")
    
    def unregister_shutdown_hook(self, name: str, phase: ShutdownPhase = None) -> bool:
        """Unregister a shutdown hook"""
        with self._hooks_lock:
            phases_to_check = [phase] if phase else list(ShutdownPhase)
            
            for check_phase in phases_to_check:
                hooks = self._hooks.get(check_phase, [])
                for i, hook in enumerate(hooks):
                    if hook.name == name:
                        del hooks[i]
                        self.logger.debug(f"Unregistered shutdown hook: {name} from phase {check_phase.value}")
                        return True
        
        return False
    
    @contextmanager
    def work_context(self, work_name: str = "unknown"):
        """Context manager for tracking active work"""
        if self._shutdown_requested.is_set():
            raise RuntimeError("Cannot start new work: shutdown in progress")
        
        with self._work_lock:
            self._active_work_count += 1
        
        self.logger.debug(f"Started work: {work_name} (active: {self._active_work_count})")
        
        try:
            yield
        finally:
            with self._work_lock:
                self._active_work_count -= 1
            
            self.logger.debug(f"Finished work: {work_name} (active: {self._active_work_count})")
    
    def is_shutdown_requested(self) -> bool:
        """Check if shutdown has been requested"""
        return self._shutdown_requested.is_set()
    
    def is_accepting_new_work(self) -> bool:
        """Check if system is still accepting new work"""
        return (not self._shutdown_requested.is_set() or 
                self._current_phase == ShutdownPhase.NORMAL)
    
    def get_active_work_count(self) -> int:
        """Get count of active work items"""
        with self._work_lock:
            return self._active_work_count
    
    def _execute_hooks(self, phase: ShutdownPhase) -> bool:
        """Execute shutdown hooks for a specific phase"""
        self._current_phase = phase
        hooks = self._hooks.get(phase, [])
        
        if not hooks:
            return True
        
        self.logger.info(f"Executing {len(hooks)} shutdown hooks for phase: {phase.value}")
        
        success = True
        for hook in hooks:
            hook_start_time = time.time()
            
            try:
                self.logger.debug(f"Executing shutdown hook: {hook.name}")
                
                # Execute hook with timeout
                hook_thread = threading.Thread(
                    target=hook.handler,
                    name=f"ShutdownHook-{hook.name}",
                    daemon=True
                )
                hook_thread.start()
                hook_thread.join(timeout=hook.timeout)
                
                if hook_thread.is_alive():
                    self.logger.warning(f"Shutdown hook '{hook.name}' timed out after {hook.timeout}s")
                    success = False
                else:
                    execution_time = time.time() - hook_start_time
                    self.logger.debug(f"Shutdown hook '{hook.name}' completed in {execution_time:.3f}s")
            
            except Exception as e:
                self.logger.error(f"Error executing shutdown hook '{hook.name}': {e}")
                success = False
        
        return success
    
    def _wait_for_work_completion(self, timeout: float) -> bool:
        """Wait for all active work to complete"""
        start_time = time.time()
        
        while self._active_work_count > 0 and (time.time() - start_time) < timeout:
            self.logger.info(f"Waiting for {self._active_work_count} active work items to complete")
            time.sleep(0.5)
        
        if self._active_work_count > 0:
            self.logger.warning(f"Timeout waiting for work completion. {self._active_work_count} items still active")
            return False
        
        return True
    
    def shutdown(self, force: bool = False) -> None:
        """Perform graceful shutdown"""
        if self._shutdown_completed.is_set():
            self.logger.debug("Shutdown already completed")
            return
        
        if not self._shutdown_requested.is_set():
            self._shutdown_requested.set()
            self._shutdown_start_time = time.time()
            self.logger.info("Graceful shutdown initiated")
        
        try:
            remaining_time = self.total_timeout
            
            if not force:
                # Phase 1: Stop accepting new work
                self.logger.info("Phase 1: Stopping acceptance of new work")
                phase_start = time.time()
                self._execute_hooks(ShutdownPhase.STOP_ACCEPTING_NEW_WORK)
                remaining_time -= (time.time() - phase_start)
                
                # Phase 2: Finish current work
                if remaining_time > 0:
                    self.logger.info("Phase 2: Waiting for current work to finish")
                    phase_start = time.time()
                    work_timeout = min(remaining_time * 0.6, 30.0)  # Use 60% of remaining time, max 30s
                    
                    self._execute_hooks(ShutdownPhase.FINISH_CURRENT_WORK)
                    self._wait_for_work_completion(work_timeout)
                    
                    remaining_time -= (time.time() - phase_start)
            
            # Phase 3: Cleanup resources
            if remaining_time > 0:
                self.logger.info("Phase 3: Cleaning up resources")
                phase_start = time.time()
                self._execute_hooks(ShutdownPhase.CLEANUP_RESOURCES)
                
                # Also cleanup resources via resource manager
                self.resource_manager.shutdown_all()
                
                remaining_time -= (time.time() - phase_start)
            
            # Phase 4: Force shutdown if needed
            if remaining_time <= 0 or force:
                self.logger.warning("Phase 4: Force shutdown due to timeout or force flag")
                self._execute_hooks(ShutdownPhase.FORCE_SHUTDOWN)
            
            # Phase 5: Completion
            self._current_phase = ShutdownPhase.COMPLETED
            self._shutdown_completed.set()
            
            total_time = time.time() - (self._shutdown_start_time or time.time())
            self.logger.info(f"Graceful shutdown completed in {total_time:.3f}s")
        
        except Exception as e:
            self.logger.error(f"Error during graceful shutdown: {e}")
            self._shutdown_completed.set()
    
    def wait_for_shutdown(self, timeout: Optional[float] = None) -> bool:
        """Wait for shutdown to complete"""
        return self._shutdown_completed.wait(timeout)
    
    def get_shutdown_status(self) -> Dict[str, Any]:
        """Get current shutdown status"""
        return {
            'shutdown_requested': self._shutdown_requested.is_set(),
            'shutdown_completed': self._shutdown_completed.is_set(),
            'current_phase': self._current_phase.value,
            'active_work_count': self._active_work_count,
            'accepting_new_work': self.is_accepting_new_work(),
            'shutdown_duration': (
                time.time() - self._shutdown_start_time
                if self._shutdown_start_time else 0
            ),
            'registered_hooks': {
                phase.value: len(hooks) 
                for phase, hooks in self._hooks.items()
            }
        }


# Global shutdown manager
_shutdown_manager: Optional[GracefulShutdownManager] = None
_shutdown_lock = threading.Lock()


def get_shutdown_manager() -> GracefulShutdownManager:
    """Get global shutdown manager"""
    global _shutdown_manager
    if _shutdown_manager is None:
        with _shutdown_lock:
            if _shutdown_manager is None:
                _shutdown_manager = GracefulShutdownManager()
    return _shutdown_manager


# Convenience functions
def register_shutdown_hook(name: str, handler: Callable, 
                          priority: int = 100, timeout: float = 30.0,
                          phase: ShutdownPhase = ShutdownPhase.CLEANUP_RESOURCES) -> None:
    """Register a shutdown hook"""
    manager = get_shutdown_manager()
    manager.register_shutdown_hook(name, handler, priority, timeout, phase)


def unregister_shutdown_hook(name: str, phase: ShutdownPhase = None) -> bool:
    """Unregister a shutdown hook"""
    manager = get_shutdown_manager()
    return manager.unregister_shutdown_hook(name, phase)


def work_context(work_name: str = "unknown"):
    """Context manager for tracking active work"""
    manager = get_shutdown_manager()
    return manager.work_context(work_name)


def is_shutdown_requested() -> bool:
    """Check if shutdown has been requested"""
    manager = get_shutdown_manager()
    return manager.is_shutdown_requested()


def is_accepting_new_work() -> bool:
    """Check if system is accepting new work"""
    manager = get_shutdown_manager()
    return manager.is_accepting_new_work()


def shutdown(force: bool = False) -> None:
    """Initiate graceful shutdown"""
    manager = get_shutdown_manager()
    manager.shutdown(force)