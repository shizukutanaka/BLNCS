"""
Database System for BLNCS - Wrapper for lightweight implementation
Maintains compatibility while using optimized lightweight database.
"""

from .database_lightweight import LightweightDatabase, get_database as get_lightweight_database

# Re-export for compatibility
DatabaseManager = LightweightDatabase

def get_database(db_path: str = "blncs.db"):
    """Get database instance (compatibility wrapper)"""
    return get_lightweight_database(db_path)

__all__ = ['DatabaseManager', 'LightweightDatabase', 'get_database']