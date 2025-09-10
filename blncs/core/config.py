"""
Configuration compatibility wrapper
Provides backward compatibility for modules using old config module.
"""

import os
from .config_manager import get_config_manager

def get_config():
    """Get configuration instance for backward compatibility"""
    return get_config_manager()

def get_database_url():
    """Get database URL from configuration or environment"""
    # Try environment first
    db_url = os.getenv('DATABASE_URL')
    if db_url:
        return db_url
    
    # Try configuration
    config = get_config_manager()
    db_config = config.get_section('database', {})
    
    if 'url' in db_config:
        return db_config['url']
    
    # Build URL from components
    host = db_config.get('host', 'localhost')
    port = db_config.get('port', 5432)
    database = db_config.get('database', 'blncs')
    username = db_config.get('username', 'blncs')
    password = db_config.get('password', '')
    
    if password:
        return f"postgresql://{username}:{password}@{host}:{port}/{database}"
    else:
        return f"postgresql://{username}@{host}:{port}/{database}"