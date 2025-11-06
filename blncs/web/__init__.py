"""
BLNCS Web Module
軽量Web機能
"""

try:
    from .simple_dashboard import SimpleDashboard, run_dashboard
    DASHBOARD_AVAILABLE = True
except ImportError:
    DASHBOARD_AVAILABLE = False

    class SimpleDashboard:
        def __init__(self, *args, **kwargs): pass
        def start(self): pass
        def stop(self): pass

    def run_dashboard(*args, **kwargs):
        print("Dashboard not available")

__all__ = ['SimpleDashboard', 'run_dashboard', 'DASHBOARD_AVAILABLE']