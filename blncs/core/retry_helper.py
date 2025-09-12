"""
Lightweight Retry Helper for BLNCS
Simple retry logic for improved connection stability.
"""

import time
import logging
import functools
from typing import Callable, Any, Optional, Type, Union, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class RetryConfig:
    """Configuration for retry behavior"""
    max_attempts: int = 3
    initial_delay: float = 1.0
    backoff_multiplier: float = 2.0
    max_delay: float = 60.0
    jitter: bool = True

def exponential_backoff(attempt: int, config: RetryConfig) -> float:
    """Calculate exponential backoff delay"""
    delay = config.initial_delay * (config.backoff_multiplier ** (attempt - 1))
    delay = min(delay, config.max_delay)
    
    if config.jitter:
        import random
        delay *= (0.5 + random.random() * 0.5)  # Add 0-50% jitter
    
    return delay

def retry_on_exception(
    exceptions: Union[Type[Exception], Tuple[Type[Exception], ...]] = Exception,
    config: Optional[RetryConfig] = None,
    on_retry: Optional[Callable[[Exception, int], None]] = None
):
    """
    Decorator for retrying function calls on exceptions
    
    Args:
        exceptions: Exception types to retry on
        config: Retry configuration
        on_retry: Callback called on each retry attempt
    """
    if config is None:
        config = RetryConfig()
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(1, config.max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    
                    if attempt == config.max_attempts:
                        logger.error(f"Function {func.__name__} failed after {config.max_attempts} attempts")
                        raise e
                    
                    delay = exponential_backoff(attempt, config)
                    logger.warning(f"Attempt {attempt} failed for {func.__name__}: {e}. Retrying in {delay:.1f}s")
                    
                    if on_retry:
                        on_retry(e, attempt)
                    
                    time.sleep(delay)
            
            # Should never reach here, but just in case
            raise last_exception
        
        return wrapper
    return decorator

class RetryableClient:
    """Base class for clients with retry capability"""
    
    def __init__(self, retry_config: Optional[RetryConfig] = None):
        self.retry_config = retry_config or RetryConfig()
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def with_retry(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with retry logic"""
        last_exception = None
        
        for attempt in range(1, self.retry_config.max_attempts + 1):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                
                if attempt == self.retry_config.max_attempts:
                    self.logger.error(f"Function failed after {self.retry_config.max_attempts} attempts")
                    raise e
                
                delay = exponential_backoff(attempt, self.retry_config)
                self.logger.warning(f"Attempt {attempt} failed: {e}. Retrying in {delay:.1f}s")
                time.sleep(delay)
        
        raise last_exception

# Common retry configurations
FAST_RETRY = RetryConfig(max_attempts=3, initial_delay=0.5, max_delay=5.0)
STANDARD_RETRY = RetryConfig(max_attempts=3, initial_delay=1.0, max_delay=30.0)
PERSISTENT_RETRY = RetryConfig(max_attempts=5, initial_delay=2.0, max_delay=60.0)

# Convenience decorators
fast_retry = lambda: retry_on_exception(config=FAST_RETRY)
standard_retry = lambda: retry_on_exception(config=STANDARD_RETRY)
persistent_retry = lambda: retry_on_exception(config=PERSISTENT_RETRY)

__all__ = [
    'RetryConfig', 'RetryableClient', 'retry_on_exception', 'exponential_backoff',
    'FAST_RETRY', 'STANDARD_RETRY', 'PERSISTENT_RETRY',
    'fast_retry', 'standard_retry', 'persistent_retry'
]