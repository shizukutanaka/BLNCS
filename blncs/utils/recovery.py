# BLNCS Recovery Module
# Lightweight error recovery following Carmack's fail-fast principle
import asyncio
import time
import traceback
from typing import Optional, Callable, Any, Dict
from collections import deque
from dataclasses import dataclass
from datetime import datetime

@dataclass
class RecoveryState:
    """Track recovery state for a component"""
    component: str
    last_failure: Optional[float] = None
    failure_count: int = 0
    recovery_count: int = 0
    is_healthy: bool = True

class RecoveryManager:
    """
    Lightweight recovery manager.
    Simple, effective, and fast.
    """
    
    def __init__(self, max_retries: int = 3, backoff_base: float = 1.0):
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.states: Dict[str, RecoveryState] = {}
        self.recovery_handlers: Dict[str, Callable] = {}
        self.failure_log = deque(maxlen=100)
    
    def register_component(self, name: str, recovery_handler: Optional[Callable] = None):
        """Register component for recovery tracking"""
        self.states[name] = RecoveryState(component=name)
        if recovery_handler:
            self.recovery_handlers[name] = recovery_handler
    
    async def execute_with_recovery(self, component: str, func: Callable, *args, **kwargs) -> Any:
        """Execute function with automatic recovery"""
        if component not in self.states:
            self.register_component(component)
        
        state = self.states[component]
        retry_count = 0
        last_error = None
        
        while retry_count <= self.max_retries:
            try:
                # Execute function
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)
                
                # Success - reset state
                state.is_healthy = True
                state.failure_count = 0
                return result
                
            except Exception as e:
                last_error = e
                retry_count += 1
                state.failure_count += 1
                state.last_failure = time.time()
                state.is_healthy = False
                
                # Log failure
                self._log_failure(component, e)
                
                # If we have retries left, wait and try again
                if retry_count <= self.max_retries:
                    wait_time = self.backoff_base * (2 ** (retry_count - 1))
                    await asyncio.sleep(wait_time)
                    
                    # Try recovery handler if available
                    if component in self.recovery_handlers:
                        try:
                            await self._run_recovery_handler(component)
                            state.recovery_count += 1
                        except:
                            pass  # Recovery failed, continue with retry
        
        # All retries exhausted
        raise last_error
    
    async def _run_recovery_handler(self, component: str):
        """Run recovery handler for component"""
        handler = self.recovery_handlers.get(component)
        if handler:
            if asyncio.iscoroutinefunction(handler):
                await handler()
            else:
                handler()
    
    def _log_failure(self, component: str, error: Exception):
        """Log failure for analysis"""
        self.failure_log.append({
            'timestamp': datetime.now().isoformat(),
            'component': component,
            'error': str(error),
            'traceback': traceback.format_exc()
        })
    
    def get_component_health(self, component: str) -> bool:
        """Check if component is healthy"""
        state = self.states.get(component)
        return state.is_healthy if state else True
    
    def get_system_health(self) -> Dict[str, Any]:
        """Get overall system health"""
        total = len(self.states)
        healthy = sum(1 for s in self.states.values() if s.is_healthy)
        
        return {
            'healthy_components': healthy,
            'total_components': total,
            'health_percentage': (healthy / total * 100) if total > 0 else 100,
            'recent_failures': len(self.failure_log),
            'components': {
                name: {
                    'healthy': state.is_healthy,
                    'failures': state.failure_count,
                    'recoveries': state.recovery_count
                }
                for name, state in self.states.items()
            }
        }
    
    def reset_component(self, component: str):
        """Reset component state"""
        if component in self.states:
            self.states[component] = RecoveryState(component=component)
    
    def clear_failure_log(self):
        """Clear failure log"""
        self.failure_log.clear()

class AutoRecover:
    """
    Decorator for automatic recovery.
    Following Martin's clean code principles.
    """
    
    def __init__(self, component: str, max_retries: int = 3, backoff: float = 1.0):
        self.component = component
        self.max_retries = max_retries
        self.backoff = backoff
    
    def __call__(self, func):
        async def async_wrapper(*args, **kwargs):
            recovery_mgr = get_recovery_manager()
            return await recovery_mgr.execute_with_recovery(
                self.component, func, *args, **kwargs
            )
        
        def sync_wrapper(*args, **kwargs):
            recovery_mgr = get_recovery_manager()
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(
                recovery_mgr.execute_with_recovery(
                    self.component, func, *args, **kwargs
                )
            )
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

# Global recovery manager
_recovery_manager: Optional[RecoveryManager] = None

def get_recovery_manager() -> RecoveryManager:
    """Get global recovery manager instance"""
    global _recovery_manager
    if _recovery_manager is None:
        _recovery_manager = RecoveryManager()
    return _recovery_manager

# Common recovery handlers
async def restart_database_connection():
    """Recovery handler for database"""
    from blncs.database import Database
    # Reconnect logic here
    pass

async def clear_cache():
    """Recovery handler for cache"""
    from blncs.cache import Cache
    # Clear cache logic here
    pass

async def reset_network_connection():
    """Recovery handler for network"""
    # Reset network logic here
    pass

# Register common components
def initialize_recovery():
    """Initialize recovery system with common components"""
    mgr = get_recovery_manager()
    
    mgr.register_component("database", restart_database_connection)
    mgr.register_component("cache", clear_cache)
    mgr.register_component("network", reset_network_connection)
    mgr.register_component("api", None)
    mgr.register_component("gui", None)