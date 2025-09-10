"""
Enhanced Input Validation Module
Provides comprehensive input validation with fallback support for missing dependencies.
"""

import re
import ipaddress
from typing import Any, Optional, Union, List, Dict, Callable
from urllib.parse import urlparse
import logging

# Try to import validators, with fallback implementation
try:
    import validators as _validators
    VALIDATORS_AVAILABLE = True
except ImportError:
    VALIDATORS_AVAILABLE = False

logger = logging.getLogger(__name__)


class ValidationError(Exception):
    """Custom validation error"""
    def __init__(self, message: str, field: Optional[str] = None, value: Any = None):
        super().__init__(message)
        self.field = field
        self.value = value


class EnhancedValidator:
    """
    Enhanced validation class with fallback implementations
    Provides comprehensive validation capabilities even when external libraries aren't available
    """
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        
    def validate_email(self, email: str) -> bool:
        """Validate email address with fallback implementation"""
        if VALIDATORS_AVAILABLE:
            try:
                return _validators.email(email) == True
            except Exception:
                pass
        
        # Fallback regex validation
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(email_pattern, email))
    
    def validate_url(self, url: str) -> bool:
        """Validate URL with fallback implementation"""
        if VALIDATORS_AVAILABLE:
            try:
                return _validators.url(url) == True
            except Exception:
                pass
        
        # Fallback validation
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def validate_ip_address(self, ip: str) -> bool:
        """Validate IP address (IPv4 or IPv6)"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def validate_port(self, port: Union[str, int]) -> bool:
        """Validate network port number"""
        try:
            port_int = int(port)
            return 1 <= port_int <= 65535
        except (ValueError, TypeError):
            return False
    
    def validate_bitcoin_address(self, address: str) -> bool:
        """
        Validate Bitcoin address (simplified validation)
        Supports Legacy, SegWit, and Bech32 formats
        """
        if not isinstance(address, str):
            return False
            
        # Legacy addresses (P2PKH and P2SH)
        if address.startswith(('1', '3')):
            return self._validate_base58_address(address)
        
        # Bech32 addresses (native SegWit)
        if address.startswith(('bc1', 'tb1')):
            return self._validate_bech32_address(address)
        
        return False
    
    def _validate_base58_address(self, address: str) -> bool:
        """Validate Base58 Bitcoin address"""
        base58_pattern = r'^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$'
        return bool(re.match(base58_pattern, address)) and 25 <= len(address) <= 34
    
    def _validate_bech32_address(self, address: str) -> bool:
        """Validate Bech32 Bitcoin address"""
        bech32_pattern = r'^(bc1|tb1)[a-z0-9]{39,59}$'
        return bool(re.match(bech32_pattern, address.lower()))
    
    def validate_lightning_node_pubkey(self, pubkey: str) -> bool:
        """Validate Lightning Network node public key"""
        if not isinstance(pubkey, str):
            return False
        
        # Lightning node pubkeys are 66 character hex strings
        hex_pattern = r'^[0-9a-fA-F]{66}$'
        return bool(re.match(hex_pattern, pubkey))
    
    def validate_lightning_invoice(self, invoice: str) -> bool:
        """Validate Lightning Network invoice (basic validation)"""
        if not isinstance(invoice, str):
            return False
        
        # Lightning invoices start with 'ln' followed by network prefix
        return invoice.lower().startswith(('lnbc', 'lntb', 'lnbcrt'))
    
    def validate_amount(self, amount: Union[str, int, float], min_value: Optional[float] = None, max_value: Optional[float] = None) -> bool:
        """Validate monetary amount"""
        try:
            amount_float = float(amount)
            
            # Check for negative values
            if amount_float < 0:
                return False
            
            # Check minimum value
            if min_value is not None and amount_float < min_value:
                return False
            
            # Check maximum value  
            if max_value is not None and amount_float > max_value:
                return False
            
            return True
        except (ValueError, TypeError):
            return False
    
    def validate_channel_id(self, channel_id: str) -> bool:
        """Validate Lightning Network channel ID"""
        if not isinstance(channel_id, str):
            return False
        
        # Channel IDs can be in format: block:tx:output or just a number
        if ':' in channel_id:
            parts = channel_id.split(':')
            if len(parts) != 3:
                return False
            try:
                # Validate block height, tx index, output index
                block_height = int(parts[0])
                tx_index = int(parts[1])  
                output_index = int(parts[2])
                return all(x >= 0 for x in [block_height, tx_index, output_index])
            except ValueError:
                return False
        else:
            # Numeric channel ID
            try:
                int(channel_id)
                return True
            except ValueError:
                return False
    
    def validate_fee_rate(self, fee_rate: Union[str, int, float]) -> bool:
        """Validate fee rate (in sats/vbyte or ppm)"""
        try:
            rate = float(fee_rate)
            return 0 <= rate <= 1000000  # Reasonable range for fee rates
        except (ValueError, TypeError):
            return False
    
    def validate_hex_string(self, hex_str: str, expected_length: Optional[int] = None) -> bool:
        """Validate hexadecimal string"""
        if not isinstance(hex_str, str):
            return False
        
        hex_pattern = r'^[0-9a-fA-F]+$'
        if not re.match(hex_pattern, hex_str):
            return False
        
        if expected_length is not None and len(hex_str) != expected_length:
            return False
        
        return True
    
    def validate_json_string(self, json_str: str) -> bool:
        """Validate JSON string"""
        try:
            import json
            json.loads(json_str)
            return True
        except (ValueError, TypeError):
            return False
    
    def validate_config_key(self, key: str) -> bool:
        """Validate configuration key format"""
        if not isinstance(key, str):
            return False
        
        # Config keys should be alphanumeric with dots and underscores
        config_pattern = r'^[a-zA-Z0-9_.]+$'
        return bool(re.match(config_pattern, key)) and len(key) <= 100
    
    def validate_file_path(self, path: str) -> bool:
        """Validate file path (basic validation)"""
        if not isinstance(path, str):
            return False
        
        # Check for dangerous characters and patterns
        dangerous_patterns = ['../', '..\\', '/etc/', '/proc/', '/sys/']
        return not any(pattern in path for pattern in dangerous_patterns)
    
    def sanitize_string(self, input_str: str, max_length: int = 1000, allowed_chars: Optional[str] = None) -> str:
        """Sanitize string input"""
        if not isinstance(input_str, str):
            return ""
        
        # Truncate to max length
        sanitized = input_str[:max_length]
        
        # Remove control characters
        sanitized = ''.join(char for char in sanitized if ord(char) >= 32 or char in '\t\n\r')
        
        # Filter to allowed characters if specified
        if allowed_chars:
            sanitized = ''.join(char for char in sanitized if char in allowed_chars)
        
        return sanitized
    
    def validate_batch(self, validations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate multiple inputs in batch
        
        Args:
            validations: List of dicts with keys: 'type', 'value', 'field_name'
        
        Returns:
            Dict with validation results
        """
        results = {
            'valid': True,
            'errors': [],
            'details': {}
        }
        
        validation_methods = {
            'email': self.validate_email,
            'url': self.validate_url,
            'ip': self.validate_ip_address,
            'port': self.validate_port,
            'bitcoin_address': self.validate_bitcoin_address,
            'lightning_pubkey': self.validate_lightning_node_pubkey,
            'lightning_invoice': self.validate_lightning_invoice,
            'amount': self.validate_amount,
            'channel_id': self.validate_channel_id,
            'fee_rate': self.validate_fee_rate,
            'hex': self.validate_hex_string,
            'json': self.validate_json_string,
            'config_key': self.validate_config_key,
            'file_path': self.validate_file_path
        }
        
        for validation in validations:
            validation_type = validation.get('type')
            value = validation.get('value')
            field_name = validation.get('field_name', 'unknown')
            
            if validation_type not in validation_methods:
                results['errors'].append(f"Unknown validation type: {validation_type}")
                results['valid'] = False
                continue
            
            try:
                is_valid = validation_methods[validation_type](value)
                results['details'][field_name] = is_valid
                
                if not is_valid:
                    results['errors'].append(f"Validation failed for {field_name}: {value}")
                    results['valid'] = False
                    
            except Exception as e:
                results['errors'].append(f"Validation error for {field_name}: {str(e)}")
                results['valid'] = False
        
        return results


# Global validator instance
_validator = None

def get_enhanced_validator() -> EnhancedValidator:
    """Get global enhanced validator instance"""
    global _validator
    if _validator is None:
        _validator = EnhancedValidator()
    return _validator


# Convenience functions
def validate_email(email: str) -> bool:
    """Convenience function for email validation"""
    return get_enhanced_validator().validate_email(email)

def validate_url(url: str) -> bool:
    """Convenience function for URL validation"""
    return get_enhanced_validator().validate_url(url)

def validate_bitcoin_address(address: str) -> bool:
    """Convenience function for Bitcoin address validation"""
    return get_enhanced_validator().validate_bitcoin_address(address)

def validate_lightning_invoice(invoice: str) -> bool:
    """Convenience function for Lightning invoice validation"""
    return get_enhanced_validator().validate_lightning_invoice(invoice)

def sanitize_input(input_str: str, max_length: int = 1000) -> str:
    """Convenience function for input sanitization"""
    return get_enhanced_validator().sanitize_string(input_str, max_length)


# Export commonly used functions
__all__ = [
    'EnhancedValidator',
    'ValidationError',
    'get_enhanced_validator',
    'validate_email',
    'validate_url', 
    'validate_bitcoin_address',
    'validate_lightning_invoice',
    'sanitize_input',
    'VALIDATORS_AVAILABLE'
]