"""
Validation compatibility wrapper
Provides backward compatibility for modules using old validation module.
"""

from .enhanced_validator import get_enhanced_validator

def get_validator():
    """Get validator instance for backward compatibility"""
    return get_enhanced_validator()

# For direct imports
validator = get_validator()