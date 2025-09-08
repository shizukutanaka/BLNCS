"""
BLNCS Validation Module
High-quality validation system with clear separation of concerns.
"""

from .config_validator import ConfigValidator
from .validation_rules import ValidationRules
from .field_validators import FieldValidator

__all__ = ['ConfigValidator', 'ValidationRules', 'FieldValidator']


def get_validator() -> ConfigValidator:
    """Get configuration validator instance"""
    return ConfigValidator()


def get_config_validator() -> ConfigValidator:
    """Alias for get_validator() for backward compatibility"""
    return get_validator()