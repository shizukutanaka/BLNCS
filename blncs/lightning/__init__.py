"""
BLNCS Lightning Module
Interface to Lightning Network nodes
"""

from .simple_client import SimpleLightningClient, get_lightning_client

__all__ = ['SimpleLightningClient', 'get_lightning_client']