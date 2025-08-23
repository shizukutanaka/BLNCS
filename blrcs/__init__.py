"""
BLRCS - Bitcoin Lightning Routing Control System

One-click Lightning Network routing optimization
"""

__version__ = "0.0.1"
__author__ = "BLRCS Team"
__license__ = "MIT"

import logging

# Lightning-specific imports
try:
    from .lightning import (
        LightningClient,
        LNDConnector,
        ChannelManager,
        PaymentRouter,
        OneClickLightningRouter
    )
except ImportError as e:
    logging.warning(f"Lightning module import failed: {e}")
    LightningClient = LNDConnector = ChannelManager = PaymentRouter = OneClickLightningRouter = None

try:
    from .api import APIServer
    from .cli import cli_main
except ImportError as e:
    logging.warning(f"Interface module import failed: {e}")
    APIServer = cli_main = None

# Main Lightning Router class
class LightningRouter:
    """Main class for Lightning Network routing optimization"""
    
    def __init__(self, lnd_dir: str = None):
        self.lnd_connector = LNDConnector(lnd_dir) if LNDConnector else None
        self.channel_manager = ChannelManager() if ChannelManager else None
        self.payment_router = PaymentRouter() if PaymentRouter else None
        self.connected = False
        
    def connect(self):
        """Connect to LND node"""
        if self.lnd_connector:
            self.connected = self.lnd_connector.connect()
            return self.connected
        return False
    
    def find_best_route(self, source: str, destination: str, amount_sat: int):
        """Find optimal payment route"""
        if not self.connected:
            self.connect()
        if self.payment_router:
            return self.payment_router.find_route(source, destination, amount_sat)
        return None
    
    def rebalance_channels(self, threshold: float = 0.2):
        """Rebalance channels automatically"""
        if not self.connected:
            self.connect()
        if self.channel_manager:
            return self.channel_manager.rebalance(threshold)
        return False
    
    def optimize_fees(self):
        """Optimize routing fees"""
        if not self.connected:
            self.connect()
        if self.channel_manager:
            return self.channel_manager.optimize_fees()
        return False
    
    def get_status(self):
        """Get current routing status"""
        return {
            "connected": self.connected,
            "channels": self.channel_manager.get_channels() if self.channel_manager else [],
            "routing_stats": self.payment_router.get_stats() if self.payment_router else {}
        }

# Module availability
AVAILABLE_MODULES = {
    'lightning_client': LightningClient is not None,
    'lnd_connector': LNDConnector is not None,
    'channel_manager': ChannelManager is not None,
    'payment_router': PaymentRouter is not None,
    'one_click_router': OneClickLightningRouter is not None,
    'api': APIServer is not None,
    'cli': cli_main is not None,
}

def get_module_status():
    """Get status of Lightning modules"""
    return AVAILABLE_MODULES

# Export main classes
__all__ = [
    "LightningRouter",
    "LightningClient",
    "LNDConnector", 
    "ChannelManager",
    "PaymentRouter",
    "OneClickLightningRouter",
    "APIServer",
    "cli_main",
    "get_module_status",
    "AVAILABLE_MODULES"
]