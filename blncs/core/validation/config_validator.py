"""
Configuration Validator
Clean, maintainable configuration validation with low complexity.
"""

import yaml
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional

from ..logger import get_logger
from .validation_rules import ValidationRules
from .field_validators import FieldValidator


class ValidationResult:
    """Encapsulates validation result with clear interface"""
    
    def __init__(self, is_valid: bool, errors: List[str], fixed_config: Dict[str, Any]):
        self.is_valid = is_valid
        self.errors = errors
        self.fixed_config = fixed_config
        self.error_count = len(errors)
    
    def has_errors(self) -> bool:
        """Check if validation has errors"""
        return not self.is_valid
    
    def get_summary(self) -> str:
        """Get validation summary"""
        if self.is_valid:
            return "Configuration validation successful"
        return f"Configuration has {self.error_count} errors"


class ConfigValidator:
    """Configuration validator with single responsibility design"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.validation_rules = ValidationRules.get_all_rules()
        self.field_validator = FieldValidator()
    
    def validate_config(self, config_path: str) -> ValidationResult:
        """Validate configuration file"""
        try:
            config = self._load_config_file(config_path)
            if config is None:
                return self._handle_missing_config(config_path)
            
            return self._validate_loaded_config(config)
            
        except yaml.YAMLError as e:
            return ValidationResult(
                is_valid=False,
                errors=[f"YAML format error: {e}"],
                fixed_config=self._create_default_config()
            )
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                errors=[f"Validation error: {e}"],
                fixed_config=self._create_default_config()
            )
    
    def _load_config_file(self, config_path: str) -> Optional[Dict[str, Any]]:
        """Load configuration file safely"""
        path = Path(config_path)
        if not path.exists():
            return None
        
        with open(path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}
    
    def _handle_missing_config(self, config_path: str) -> ValidationResult:
        """Handle missing configuration file"""
        return ValidationResult(
            is_valid=False,
            errors=[f"Configuration file not found: {config_path}"],
            fixed_config=self._create_default_config()
        )
    
    def _validate_loaded_config(self, config: Dict[str, Any]) -> ValidationResult:
        """Validate loaded configuration"""
        errors = []
        fixed_config = {}
        
        # Validate each section
        for section_name, rules in self.validation_rules.items():
            section_config = config.get(section_name, {})
            fixed_section, section_errors = self._validate_section(
                section_name, section_config, rules
            )
            
            errors.extend(section_errors)
            fixed_config[section_name] = fixed_section
        
        # Warn about unknown sections
        self._warn_unknown_sections(config)
        
        # Log result
        self._log_validation_result(errors)
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            fixed_config=fixed_config
        )
    
    def _validate_section(
        self, 
        section_name: str, 
        section_config: Dict[str, Any], 
        rules: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], List[str]]:
        """Validate a single configuration section"""
        fixed_section = {}
        errors = []
        
        for field_name, rule in rules.items():
            value = section_config.get(field_name)
            full_field_name = f"{section_name}.{field_name}"
            
            # Validate field
            fixed_value, field_errors = self._validate_field(
                full_field_name, value, rule
            )
            
            errors.extend(field_errors)
            if fixed_value is not None:
                fixed_section[field_name] = fixed_value
        
        return fixed_section, errors
    
    def _validate_field(
        self, 
        field_name: str, 
        value: Any, 
        rule: Dict[str, Any]
    ) -> Tuple[Any, List[str]]:
        """Validate a single field"""
        errors = []
        
        # Check required field
        is_valid, error, value = self.field_validator.validate_required_field(
            field_name, value, rule
        )
        if not is_valid and error:
            errors.append(error)
        
        # Apply default if value is None
        if value is None and 'default' in rule:
            return rule['default'], errors
        
        # Skip validation if value is None and not required
        if value is None:
            return None, errors
        
        # Validate type
        expected_type = rule['type']
        is_valid, error = self.field_validator.validate_type(
            field_name, value, expected_type
        )
        if not is_valid:
            errors.append(error)
            return rule.get('default'), errors
        
        # Type-specific validations
        if expected_type == int:
            value, int_errors = self._validate_integer_field(field_name, value, rule)
            errors.extend(int_errors)
        
        elif expected_type == float:
            value, float_errors = self._validate_float_field(field_name, value, rule)
            errors.extend(float_errors)
        
        elif expected_type == str:
            value, str_errors = self._validate_string_field(field_name, value, rule)
            errors.extend(str_errors)
        
        # Validate allowed values
        if 'allowed' in rule:
            is_valid, error, value = self.field_validator.validate_allowed_values(
                field_name, value, rule['allowed']
            )
            if not is_valid:
                errors.append(error)
        
        return value, errors
    
    def _validate_integer_field(
        self, 
        field_name: str, 
        value: int, 
        rule: Dict[str, Any]
    ) -> Tuple[int, List[str]]:
        """Validate integer field constraints"""
        is_valid, error, fixed_value = self.field_validator.validate_integer_range(
            field_name, value, rule
        )
        
        errors = [error] if not is_valid and error else []
        return fixed_value, errors
    
    def _validate_float_field(
        self, 
        field_name: str, 
        value: float, 
        rule: Dict[str, Any]
    ) -> Tuple[float, List[str]]:
        """Validate float field constraints"""
        is_valid, error, fixed_value = self.field_validator.validate_float_range(
            field_name, value, rule
        )
        
        errors = [error] if not is_valid and error else []
        return fixed_value, errors
    
    def _validate_string_field(
        self, 
        field_name: str, 
        value: str, 
        rule: Dict[str, Any]
    ) -> Tuple[str, List[str]]:
        """Validate string field constraints"""
        is_valid, error, fixed_value = self.field_validator.validate_string_constraints(
            field_name, value, rule
        )
        
        errors = [error] if not is_valid and error else []
        return fixed_value, errors
    
    def _warn_unknown_sections(self, config: Dict[str, Any]) -> None:
        """Warn about unknown configuration sections"""
        for section in config:
            if section not in self.validation_rules:
                self.logger.warning(f"Unknown configuration section: {section}")
    
    def _log_validation_result(self, errors: List[str]) -> None:
        """Log validation result"""
        if not errors:
            self.logger.info("Configuration validation successful")
        else:
            self.logger.warning(f"Configuration has {len(errors)} issues")
    
    def _create_default_config(self) -> Dict[str, Any]:
        """Create default configuration"""
        default_config = {}
        
        for section_name, rules in self.validation_rules.items():
            section_defaults = {}
            for field_name, rule in rules.items():
                if 'default' in rule:
                    section_defaults[field_name] = rule['default']
            
            if section_defaults:
                default_config[section_name] = section_defaults
        
        return default_config
    
    def repair_config(self, config_path: str) -> bool:
        """Repair configuration file with fixed values"""
        validation_result = self.validate_config(config_path)
        
        if validation_result.is_valid:
            self.logger.info("Configuration is valid, no repair needed")
            return True
        
        try:
            # Write repaired configuration
            with open(config_path, 'w', encoding='utf-8') as f:
                yaml.dump(
                    validation_result.fixed_config, 
                    f, 
                    default_flow_style=False, 
                    indent=2
                )
            
            self.logger.info(f"Configuration repaired with {len(validation_result.errors)} fixes")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to repair configuration: {e}")
            return False


def validate_basic_config(config: Dict[str, Any]) -> Tuple[bool, List[str], Dict[str, Any]]:
    """Validate basic configuration and return results"""
    validator = ConfigValidator()
    
    # Validate config
    result = validator._validate_loaded_config(config)
    return result.is_valid, result.errors, result.fixed_config


def format_validation_results(is_valid: bool, errors: List[str]) -> str:
    """Format validation results for display"""
    if is_valid:
        return "✅ Configuration is valid"
    
    if not errors:
        return "⚠️ No specific errors found but validation failed"
    
    error_msg = "❌ Configuration errors found:\n"
    for i, error in enumerate(errors, 1):
        error_msg += f"  {i}. {error}\n"
    return error_msg