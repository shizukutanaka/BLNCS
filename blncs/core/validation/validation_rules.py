"""
Validation Rules Definition
Clean, maintainable validation rule definitions.
"""

from typing import Dict, Any


class ValidationRules:
    """Centralized validation rules definition"""
    
    @staticmethod
    def get_system_rules() -> Dict[str, Dict[str, Any]]:
        """System configuration validation rules"""
        return {
            'name': {
                'type': str, 
                'required': True, 
                'max_length': 50
            },
            'environment': {
                'type': str, 
                'allowed': ['development', 'production', 'testing'],
                'default': 'production'
            },
            'log_level': {
                'type': str, 
                'allowed': ['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                'default': 'WARNING'
            },
            'debug': {
                'type': bool, 
                'default': False
            },
            'enable_file_logging': {
                'type': bool, 
                'default': True
            }
        }
    
    @staticmethod
    def get_lightning_rules() -> Dict[str, Dict[str, Any]]:
        """Lightning Network configuration validation rules"""
        return {
            'host': {
                'type': str, 
                'required': True, 
                'pattern': r'^[a-zA-Z0-9.-]+$'
            },
            'port': {
                'type': int, 
                'min': 1, 
                'max': 65535, 
                'required': True
            },
            'network': {
                'type': str, 
                'allowed': ['mainnet', 'testnet', 'regtest'], 
                'required': True
            },
            'timeout': {
                'type': int, 
                'min': 5, 
                'max': 300, 
                'default': 15
            },
            'connect_timeout': {
                'type': int, 
                'min': 1, 
                'max': 60, 
                'default': 5
            },
            'max_retries': {
                'type': int, 
                'min': 1, 
                'max': 10, 
                'default': 5
            },
            'retry_delay': {
                'type': int, 
                'min': 1, 
                'max': 60, 
                'default': 2
            },
            'macaroon_path': {
                'type': str, 
                'default': '~/.lnd/data/chain/bitcoin/testnet/readonly.macaroon'
            }
        }
    
    @staticmethod
    def get_performance_rules() -> Dict[str, Dict[str, Any]]:
        """Performance monitoring validation rules"""
        return {
            'monitoring_enabled': {
                'type': bool, 
                'default': True
            },
            'collection_interval': {
                'type': int, 
                'min': 10, 
                'max': 3600, 
                'default': 60
            },
            'max_history': {
                'type': int, 
                'min': 100, 
                'max': 10000, 
                'default': 500
            },
            'auto_tune': {
                'type': bool, 
                'default': False
            }
        }
    
    @staticmethod
    def get_monitor_rules() -> Dict[str, Dict[str, Any]]:
        """Monitor configuration validation rules"""
        return {
            'enabled': {
                'type': bool, 
                'default': True
            },
            'interval': {
                'type': int, 
                'min': 30, 
                'max': 3600, 
                'default': 120
            },
            'alert_threshold': {
                'type': int, 
                'min': 1000, 
                'max': 1000000, 
                'default': 50000
            }
        }
    
    @staticmethod
    def get_security_rules() -> Dict[str, Dict[str, Any]]:
        """Security configuration validation rules"""
        return {
            'enable_auth': {
                'type': bool, 
                'default': False
            },
            'session_timeout': {
                'type': int, 
                'min': 300, 
                'max': 86400, 
                'default': 1800
            },
            'max_failed_attempts': {
                'type': int, 
                'min': 3, 
                'max': 10, 
                'default': 3
            }
        }
    
    @staticmethod
    def get_fees_rules() -> Dict[str, Dict[str, Any]]:
        """Fee configuration validation rules"""
        return {
            'target_confirmation': {
                'type': int, 
                'min': 1, 
                'max': 144, 
                'default': 3
            },
            'max_fee_rate': {
                'type': int, 
                'min': 1, 
                'max': 1000, 
                'default': 50
            },
            'min_fee_rate': {
                'type': int, 
                'min': 1, 
                'max': 100, 
                'default': 2
            },
            'lightning_fee_ppm': {
                'type': int, 
                'min': 0, 
                'max': 10000, 
                'default': 500
            },
            'max_lightning_fee_ppm': {
                'type': int, 
                'min': 100, 
                'max': 50000, 
                'default': 2000
            }
        }
    
    @staticmethod
    def get_channel_rules() -> Dict[str, Dict[str, Any]]:
        """Channel configuration validation rules"""
        return {
            'min_size': {
                'type': int, 
                'min': 10000, 
                'max': 16777215, 
                'default': 20000
            },
            'max_size': {
                'type': int, 
                'min': 100000, 
                'max': 16777215, 
                'default': 5000000
            },
            'target_count': {
                'type': int, 
                'min': 1, 
                'max': 50, 
                'default': 3
            },
            'min_balance_ratio': {
                'type': float, 
                'min': 0.0, 
                'max': 1.0, 
                'default': 0.2
            },
            'max_balance_ratio': {
                'type': float, 
                'min': 0.0, 
                'max': 1.0, 
                'default': 0.8
            },
            'auto_rebalance': {
                'type': bool, 
                'default': False
            },
            'auto_close_inactive': {
                'type': bool, 
                'default': False
            }
        }
    
    @staticmethod
    def get_features_rules() -> Dict[str, Dict[str, Any]]:
        """Features configuration validation rules"""
        return {
            'enable_cache': {'type': bool, 'default': True},
            'cache_ttl': {'type': int, 'min': 60, 'default': 300},
            'enable_history': {'type': bool, 'default': True},
            'max_history_entries': {'type': int, 'min': 100, 'default': 1000},
            'enable_monitoring': {'type': bool, 'default': True},
            'monitoring_interval': {'type': int, 'min': 30, 'default': 60}
        }
    
    @staticmethod
    def get_logging_rules() -> Dict[str, Dict[str, Any]]:
        """Logging configuration validation rules"""
        return {
            'file_logging': {'type': bool, 'default': True},
            'log_file': {'type': str, 'default': 'logs/blncs.log'},
            'max_log_size': {'type': str, 'default': '10MB'},
            'backup_count': {'type': int, 'min': 1, 'default': 3},
            'components': {'type': dict, 'required': False}
        }
    
    @staticmethod 
    def get_development_rules() -> Dict[str, Dict[str, Any]]:
        """Development configuration validation rules"""
        return {
            'debug_mode': {'type': bool, 'default': True},
            'mock_lightning_node': {'type': bool, 'default': True},
            'enable_test_endpoints': {'type': bool, 'default': True}
        }

    @staticmethod
    def get_all_rules() -> Dict[str, Dict[str, Any]]:
        """Get all validation rules"""
        return {
            'system': ValidationRules.get_system_rules(),
            'lightning': ValidationRules.get_lightning_rules(),
            'features': ValidationRules.get_features_rules(),
            'logging': ValidationRules.get_logging_rules(),
            'development': ValidationRules.get_development_rules(),
            'performance': ValidationRules.get_performance_rules(),
            'monitor': ValidationRules.get_monitor_rules(),
            'security': ValidationRules.get_security_rules(),
            'fees': ValidationRules.get_fees_rules(),
            'channel': ValidationRules.get_channel_rules()
        }