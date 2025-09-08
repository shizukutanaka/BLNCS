"""
BLNCS Error Recovery System
Backward compatibility wrapper for enhanced recovery system.
"""

from .recovery_enhanced import (
    EnhancedErrorRecovery,
    EnhancedAutoRecoveryDecorator,
    get_enhanced_error_recovery,
    enhanced_auto_recover,
    lightning_auto_recover,
    network_auto_recover,
    RecoveryStrategy,
    RecoveryPriority,
    RecoveryAction,
    RecoveryResult
)

# Backward compatibility aliases
ErrorRecovery = EnhancedErrorRecovery
AutoRecoveryDecorator = EnhancedAutoRecoveryDecorator
get_error_recovery = get_enhanced_error_recovery
auto_recover = enhanced_auto_recover

# Export all public interfaces
__all__ = [
    'ErrorRecovery',
    'AutoRecoveryDecorator', 
    'get_error_recovery',
    'auto_recover',
    'enhanced_auto_recover',
    'lightning_auto_recover',
    'network_auto_recover',
    'RecoveryStrategy',
    'RecoveryPriority',
    'RecoveryAction',
    'RecoveryResult',
    'EnhancedErrorRecovery',
    'get_enhanced_error_recovery'
]