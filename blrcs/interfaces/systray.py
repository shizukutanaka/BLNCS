# BLRCS System Tray Integration
# Lightweight tray icon implementation
import sys
import threading
from typing import Optional, Callable, Dict, Any
from pathlib import Path

try:
    from pystray import Icon, MenuItem, Menu
    from PIL import Image, ImageDraw
    TRAY_AVAILABLE = True
except ImportError:
    TRAY_AVAILABLE = False

class SystemTray:
    """
    System tray integration for BLRCS.
    Simple and effective following Pike's principles.
    """
    
    def __init__(self, app_name: str = "BLRCS"):
        self.app_name = app_name
        self.icon: Optional[Any] = None
        self.menu_items: Dict[str, Callable] = {}
        self.running = False
        self.thread: Optional[threading.Thread] = None
        
        if not TRAY_AVAILABLE:
            self.enabled = False
        else:
            self.enabled = True
    
    def create_icon(self, size: int = 64) -> Image:
        """Create simple icon for tray"""
        if not TRAY_AVAILABLE:
            return None
        
        # Create simple icon with letter 'B'
        image = Image.new('RGB', (size, size), color='#2E3440')
        draw = ImageDraw.Draw(image)
        
        # Draw border
        draw.rectangle([0, 0, size-1, size-1], outline='#88C0D0', width=2)
        
        # Draw 'B' in center
        text_size = size // 2
        draw.text((size//4, size//4), 'B', fill='#88C0D0')
        
        return image
    
    def add_menu_item(self, label: str, action: Callable):
        """Add menu item to tray"""
        self.menu_items[label] = action
    
    def build_menu(self) -> Menu:
        """Build tray menu"""
        if not TRAY_AVAILABLE:
            return None
        
        items = []
        
        # Add custom menu items
        for label, action in self.menu_items.items():
            items.append(MenuItem(label, action))
        
        # Add separator if there are custom items
        if items:
            items.append(MenuItem('-', None))
        
        # Add default items
        items.extend([
            MenuItem('Show', self.on_show),
            MenuItem('Settings', self.on_settings),
            MenuItem('-', None),
            MenuItem('Exit', self.on_exit)
        ])
        
        return Menu(*items)
    
    def on_show(self, icon, item):
        """Show main window"""
        if 'show' in self.menu_items:
            self.menu_items['show']()
    
    def on_settings(self, icon, item):
        """Open settings"""
        if 'settings' in self.menu_items:
            self.menu_items['settings']()
    
    def on_exit(self, icon, item):
        """Exit application"""
        self.stop()
        if 'exit' in self.menu_items:
            self.menu_items['exit']()
        else:
            sys.exit(0)
    
    def start(self):
        """Start system tray icon"""
        if not self.enabled or self.running:
            return
        
        def run():
            self.icon = Icon(
                self.app_name,
                self.create_icon(),
                menu=self.build_menu()
            )
            self.icon.run()
        
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        self.running = True
    
    def stop(self):
        """Stop system tray icon"""
        if self.icon:
            self.icon.stop()
        self.running = False
    
    def update_tooltip(self, text: str):
        """Update tray icon tooltip"""
        if self.icon:
            self.icon.title = text
    
    def notify(self, title: str, message: str):
        """Show system notification"""
        if self.icon and hasattr(self.icon, 'notify'):
            self.icon.notify(title, message)

class SimpleTray:
    """
    Even simpler tray implementation for basic needs.
    No dependencies except tkinter.
    """
    
    def __init__(self, root):
        self.root = root
        self.minimized = False
        
        # Bind minimize event
        self.root.bind('<Unmap>', self.on_minimize)
        self.root.protocol('WM_DELETE_WINDOW', self.on_close)
    
    def on_minimize(self, event):
        """Handle minimize to tray"""
        if not self.minimized:
            self.root.withdraw()
            self.minimized = True
            self.show_tray_message()
    
    def on_close(self):
        """Handle window close"""
        if self.minimize_to_tray_enabled():
            self.on_minimize(None)
        else:
            self.root.quit()
    
    def minimize_to_tray_enabled(self) -> bool:
        """Check if minimize to tray is enabled"""
        # Check config or return default
        return True
    
    def show_tray_message(self):
        """Show message that app is in tray"""
        # This would show a balloon tip on Windows
        pass
    
    def restore_window(self):
        """Restore window from tray"""
        self.root.deiconify()
        self.minimized = False

# Global tray instance
_system_tray: Optional[SystemTray] = None

def get_system_tray() -> SystemTray:
    """Get global system tray instance"""
    global _system_tray
    if _system_tray is None:
        _system_tray = SystemTray()
    return _system_tray

def setup_tray(app_name: str = "BLRCS", 
               show_callback: Optional[Callable] = None,
               exit_callback: Optional[Callable] = None) -> SystemTray:
    """Quick setup for system tray"""
    tray = get_system_tray()
    tray.app_name = app_name
    
    if show_callback:
        tray.add_menu_item('show', show_callback)
    if exit_callback:
        tray.add_menu_item('exit', exit_callback)
    
    return tray