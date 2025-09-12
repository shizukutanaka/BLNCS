#!/usr/bin/env python3
"""
BLNCS System Tray Integration
Provides system tray functionality for background operation.
"""

import tkinter as tk
from tkinter import messagebox
import threading
import time
from datetime import datetime
from typing import Optional, Callable

# Mock system tray implementation for cross-platform compatibility
class SystemTrayIcon:
    """System tray icon with Lightning Network status"""
    
    def __init__(self, parent_window=None, lightning_client=None):
        self.parent_window = parent_window
        self.client = lightning_client
        self.is_visible = True
        self.last_update = None
        
        # Status tracking
        self.connection_status = "disconnected"
        self.balance = 0
        self.channels_count = 0
        
        # Initialize tray
        self.create_tray_menu()
        
    def create_tray_menu(self):
        """Create the system tray menu"""
        # Since we don't have access to system tray libraries,
        # we'll create a simplified popup menu for demonstration
        self.tray_menu = tk.Menu(None, tearoff=0)
        
        # Menu items
        self.tray_menu.add_command(label="⚡ BLNCS - Lightning Control", 
                                  state='disabled')
        self.tray_menu.add_separator()
        
        self.status_item = self.tray_menu.add_command(label="🔴 Disconnected", 
                                                     state='disabled')
        self.balance_item = self.tray_menu.add_command(label="💰 Balance: 0 sats", 
                                                      state='disabled')
        self.channels_item = self.tray_menu.add_command(label="⚡ Channels: 0", 
                                                       state='disabled')
        
        self.tray_menu.add_separator()
        
        # Action items
        self.tray_menu.add_command(label="📊 Show Dashboard", 
                                  command=self.show_main_window)
        self.tray_menu.add_command(label="🔄 Refresh Status", 
                                  command=self.update_status)
        self.tray_menu.add_command(label="⚙️ Settings", 
                                  command=self.show_settings)
        
        self.tray_menu.add_separator()
        self.tray_menu.add_command(label="🚪 Exit", 
                                  command=self.exit_application)
    
    def update_menu_items(self):
        """Update tray menu items with current status"""
        try:
            # Update status item
            status_text = f"🟢 Connected" if self.connection_status == "connected" else "🔴 Disconnected"
            self.tray_menu.entryconfig(2, label=status_text)
            
            # Update balance
            balance_text = f"💰 Balance: {self.balance:,} sats"
            self.tray_menu.entryconfig(3, label=balance_text)
            
            # Update channels
            channels_text = f"⚡ Channels: {self.channels_count}"
            self.tray_menu.entryconfig(4, label=channels_text)
            
        except Exception as e:
            print(f"Error updating tray menu: {e}")
    
    def update_status(self):
        """Update system tray status from Lightning client"""
        if not self.client:
            return
            
        try:
            # Get node info for connection status
            info = self.client.get_info()
            if info:
                self.connection_status = "connected"
            else:
                self.connection_status = "disconnected"
            
            # Get balance
            balance_data = self.client.get_balance()
            if balance_data:
                self.balance = balance_data.get('total', 0)
            
            # Get channels count
            channels = self.client.list_channels()
            if channels:
                self.channels_count = len(channels)
            
            # Update last update time
            self.last_update = datetime.now()
            
            # Update menu items
            self.update_menu_items()
            
        except Exception as e:
            print(f"Error updating tray status: {e}")
            self.connection_status = "disconnected"
            self.balance = 0
            self.channels_count = 0
    
    def show_main_window(self):
        """Show the main application window"""
        if self.parent_window:
            self.parent_window.deiconify()  # Restore from minimized
            self.parent_window.lift()       # Bring to front
            self.parent_window.focus_set()  # Give focus
    
    def show_settings(self):
        """Show settings dialog"""
        if self.parent_window:
            self.show_main_window()
            # Switch to settings tab if possible
            try:
                if hasattr(self.parent_window, 'notebook'):
                    # Switch to settings tab (index 3)
                    self.parent_window.notebook.select(3)
            except:
                pass
    
    def exit_application(self):
        """Exit the entire application"""
        result = messagebox.askyesno("Exit BLNCS", 
                                   "Are you sure you want to exit BLNCS?")
        if result and self.parent_window:
            self.parent_window.quit()
    
    def minimize_to_tray(self):
        """Minimize main window to system tray"""
        if self.parent_window:
            self.parent_window.withdraw()  # Hide window
        
        # Show tray notification
        self.show_notification("BLNCS minimized to system tray")
    
    def show_notification(self, message: str, title: str = "BLNCS"):
        """Show system notification"""
        # Since we don't have access to system notification libraries,
        # we'll use a simple message box for demonstration
        print(f"🔔 Notification: {title} - {message}")
    
    def start_background_updates(self):
        """Start background status updates"""
        def update_loop():
            while self.is_visible:
                try:
                    self.update_status()
                    time.sleep(60)  # Update every minute for tray
                except Exception as e:
                    print(f"Tray update error: {e}")
                    time.sleep(60)
        
        # Run in background thread
        thread = threading.Thread(target=update_loop, daemon=True)
        thread.start()


class TrayIntegration:
    """Integration helper for system tray functionality"""
    
    def __init__(self, main_window, lightning_client):
        self.main_window = main_window
        self.client = lightning_client
        self.tray_icon = None
        
    def setup_tray(self):
        """Setup system tray integration"""
        try:
            self.tray_icon = SystemTrayIcon(
                parent_window=self.main_window.root,
                lightning_client=self.client
            )
            
            # Start background updates
            self.tray_icon.start_background_updates()
            
            # Bind window minimize event
            self.main_window.root.protocol("WM_DELETE_WINDOW", self.on_window_close)
            
            return True
            
        except Exception as e:
            print(f"Error setting up system tray: {e}")
            return False
    
    def on_window_close(self):
        """Handle main window close event"""
        # Check if minimize to tray is enabled
        try:
            config = self.main_window.config_manager
            minimize_to_tray = config.get('app.minimize_to_tray', True)
            
            if minimize_to_tray and self.tray_icon:
                # Minimize to tray instead of closing
                self.tray_icon.minimize_to_tray()
            else:
                # Normal application exit
                self.main_window.root.quit()
                
        except Exception as e:
            print(f"Error handling window close: {e}")
            self.main_window.root.quit()
    
    def show_tray_menu(self, x, y):
        """Show tray context menu at coordinates"""
        if self.tray_icon and self.tray_icon.tray_menu:
            try:
                self.tray_icon.tray_menu.post(x, y)
            except Exception as e:
                print(f"Error showing tray menu: {e}")


def create_tray_integration(main_window, lightning_client):
    """Factory function to create tray integration"""
    tray_integration = TrayIntegration(main_window, lightning_client)
    
    if tray_integration.setup_tray():
        print("✅ System tray integration enabled")
        return tray_integration
    else:
        print("⚠️ System tray integration not available")
        return None


# Example usage and testing
if __name__ == "__main__":
    # Create a simple test window
    root = tk.Tk()
    root.title("BLNCS Tray Test")
    root.geometry("400x300")
    
    # Mock Lightning client for testing
    class MockLightningClient:
        def get_info(self):
            return {"alias": "Test Node", "version": "0.15.0"}
        
        def get_balance(self):
            return {"total": 850000}
        
        def list_channels(self):
            return [{"active": True}, {"active": True}, {"active": False}]
    
    # Create mock main window class
    class MockMainWindow:
        def __init__(self):
            self.root = root
            self.config_manager = None
    
    # Test tray integration
    mock_client = MockLightningClient()
    mock_window = MockMainWindow()
    
    tray = create_tray_integration(mock_window, mock_client)
    
    # Add test button to show tray menu
    def show_tray_test():
        if tray and tray.tray_icon:
            tray.show_tray_menu(400, 300)
    
    tk.Button(root, text="Show Tray Menu", command=show_tray_test).pack(pady=20)
    tk.Label(root, text="System Tray Integration Test").pack(pady=10)
    
    root.mainloop()