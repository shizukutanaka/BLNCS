"""
Field Validation Logic
Single-responsibility field validation functions.
"""

import re
from typing import Any, List, Dict, Tuple, Optional
from pathlib import Path


class FieldValidator:
    """Individual field validation logic"""
    
    @staticmethod
    def validate_required_field(
        field_name: str, 
        value: Any, 
        rule: Dict[str, Any]
    ) -> Tuple[bool, Optional[str], Any]:
        """Validate required field"""
        if rule.get('required', False) and value is None:
            error = f"{field_name}: Required field is missing"
            default_value = rule.get('default')
            return False, error, default_value
        return True, None, value
    
    @staticmethod
    def validate_type(
        field_name: str, 
        value: Any, 
        expected_type: type
    ) -> Tuple[bool, Optional[str]]:
        """Validate field type"""
        if value is not None and not isinstance(value, expected_type):
            error = (f"{field_name}: Invalid type "
                    f"(expected: {expected_type.__name__}, "
                    f"got: {type(value).__name__})")
            return False, error
        return True, None
    
    @staticmethod
    def validate_integer_range(
        field_name: str, 
        value: int, 
        rule: Dict[str, Any]
    ) -> Tuple[bool, Optional[str], int]:
        """Validate integer range constraints"""
        original_value = value
        
        if 'min' in rule and value < rule['min']:
            error = f"{field_name}: Value too small (minimum: {rule['min']})"
            return False, error, rule['min']
        
        if 'max' in rule and value > rule['max']:
            error = f"{field_name}: Value too large (maximum: {rule['max']})"
            return False, error, rule['max']
        
        return True, None, original_value
    
    @staticmethod
    def validate_float_range(
        field_name: str, 
        value: float, 
        rule: Dict[str, Any]
    ) -> Tuple[bool, Optional[str], float]:
        """Validate float range constraints"""
        original_value = value
        
        if 'min' in rule and value < rule['min']:
            error = f"{field_name}: Value too small (minimum: {rule['min']})"
            return False, error, rule['min']
        
        if 'max' in rule and value > rule['max']:
            error = f"{field_name}: Value too large (maximum: {rule['max']})"
            return False, error, rule['max']
        
        return True, None, original_value
    
    @staticmethod
    def validate_string_constraints(
        field_name: str, 
        value: str, 
        rule: Dict[str, Any]
    ) -> Tuple[bool, Optional[str], str]:
        """Validate string constraints"""
        original_value = value
        
        # Length validation
        if 'max_length' in rule and len(value) > rule['max_length']:
            error = f"{field_name}: String too long (maximum: {rule['max_length']})"
            return False, error, value[:rule['max_length']]
        
        # Pattern validation
        if 'pattern' in rule:
            pattern = rule['pattern']
            if not re.match(pattern, value):
                error = f"{field_name}: Invalid format (pattern: {pattern})"
                return False, error, original_value
        
        return True, None, original_value
    
    @staticmethod
    def validate_allowed_values(
        field_name: str, 
        value: Any, 
        allowed_values: List[Any]
    ) -> Tuple[bool, Optional[str], Any]:
        """Validate value against allowed list"""
        if value not in allowed_values:
            error = (f"{field_name}: Invalid value '{value}' "
                    f"(allowed: {', '.join(map(str, allowed_values))})")
            # Return first allowed value as default
            return False, error, allowed_values[0] if allowed_values else value
        return True, None, value
    
    @staticmethod
    def validate_file_path(
        field_name: str, 
        value: str, 
        should_exist: bool = False
    ) -> Tuple[bool, Optional[str]]:
        """Validate file path"""
        try:
            path = Path(value).expanduser()
            
            if should_exist and not path.exists():
                error = f"{field_name}: File does not exist: {value}"
                return False, error
            
            # Check if parent directory exists (for file creation)
            if not should_exist and path.parent.exists() and not path.parent.is_dir():
                error = f"{field_name}: Parent path is not a directory: {value}"
                return False, error
            
            return True, None
            
        except Exception as e:
            error = f"{field_name}: Invalid path '{value}': {str(e)}"
            return False, error