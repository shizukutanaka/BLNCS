# BLRCS UI Components Module
# Enhanced UI components with progress indicators and modern design
import tkinter as tk
from tkinter import ttk
import threading
import time
from typing import Optional, Callable, Any, Dict
from dataclasses import dataclass
from enum import Enum

class ThemeMode(Enum):
    """UI Theme modes"""
    LIGHT = "light"
    DARK = "dark"
    AUTO = "auto"

@dataclass
class ProgressState:
    """Progress tracking state"""
    current: int = 0
    total: int = 100
    message: str = ""
    percentage: float = 0.0
    is_indeterminate: bool = False

class ProgressDialog:
    """
    Modern progress dialog with cancellation support
    """
    
    def __init__(self, parent, title: str = "Processing...", 
                 cancelable: bool = True, theme: ThemeMode = ThemeMode.LIGHT):
        self.parent = parent
        self.title = title
        self.cancelable = cancelable
        self.theme = theme
        self.cancelled = False
        self.dialog = None
        self.progress_var = None
        self.message_var = None
        self.progress_bar = None
        self.cancel_callback: Optional[Callable] = None
        
    def show(self, on_cancel: Optional[Callable] = None):
        """Show progress dialog"""
        self.cancel_callback = on_cancel
        
        # Create dialog window
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title(self.title)
        self.dialog.geometry("400x150")
        self.dialog.resizable(False, False)
        
        # Center on parent
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # Apply theme
        self._apply_theme()
        
        # Create UI elements
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Message label
        self.message_var = tk.StringVar(value="Initializing...")
        message_label = ttk.Label(main_frame, textvariable=self.message_var, 
                                font=("Segoe UI", 10))
        message_label.pack(pady=(0, 10))
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            main_frame, 
            variable=self.progress_var,
            maximum=100,
            length=360,
            mode='determinate'
        )
        self.progress_bar.pack(pady=(0, 10))
        
        # Percentage label
        self.percentage_var = tk.StringVar(value="0%")
        percentage_label = ttk.Label(main_frame, textvariable=self.percentage_var,
                                   font=("Segoe UI", 9))
        percentage_label.pack()
        
        # Cancel button
        if self.cancelable:
            button_frame = ttk.Frame(main_frame)
            button_frame.pack(pady=(10, 0))
            
            cancel_btn = ttk.Button(button_frame, text="Cancel", 
                                  command=self._on_cancel)
            cancel_btn.pack()
        
        # Handle window close
        self.dialog.protocol("WM_DELETE_WINDOW", self._on_cancel)
        
        # Center dialog
        self._center_dialog()
    
    def update_progress(self, current: int, total: int, message: str = ""):
        """Update progress display"""
        if self.dialog and not self.cancelled:
            percentage = (current / total * 100) if total > 0 else 0
            
            self.progress_var.set(percentage)
            self.percentage_var.set(f"{percentage:.1f}%")
            
            if message:
                self.message_var.set(message)
            
            self.dialog.update_idletasks()
    
    def set_indeterminate(self, indeterminate: bool = True):
        """Set progress bar to indeterminate mode"""
        if self.progress_bar:
            if indeterminate:
                self.progress_bar.config(mode='indeterminate')
                self.progress_bar.start(10)
                self.percentage_var.set("Working...")
            else:
                self.progress_bar.stop()
                self.progress_bar.config(mode='determinate')
    
    def close(self):
        """Close progress dialog"""
        if self.dialog:
            self.dialog.destroy()
            self.dialog = None
    
    def _on_cancel(self):
        """Handle cancel button click"""
        self.cancelled = True
        if self.cancel_callback:
            self.cancel_callback()
        self.close()
    
    def _apply_theme(self):
        """Apply theme to dialog"""
        if self.theme == ThemeMode.DARK:
            self.dialog.configure(bg='#2b2b2b')
            
            # Configure ttk styles for dark theme
            style = ttk.Style()
            style.theme_use('clam')
            
            # Dark theme colors
            style.configure('TFrame', background='#2b2b2b')
            style.configure('TLabel', background='#2b2b2b', foreground='#ffffff')
            style.configure('TButton', background='#404040', foreground='#ffffff')
            style.map('TButton', 
                     background=[('active', '#505050')])
    
    def _center_dialog(self):
        """Center dialog on parent window"""
        self.dialog.update_idletasks()
        
        # Get parent window position and size
        parent_x = self.parent.winfo_rootx()
        parent_y = self.parent.winfo_rooty()
        parent_width = self.parent.winfo_width()
        parent_height = self.parent.winfo_height()
        
        # Calculate center position
        dialog_width = self.dialog.winfo_reqwidth()
        dialog_height = self.dialog.winfo_reqheight()
        
        x = parent_x + (parent_width - dialog_width) // 2
        y = parent_y + (parent_height - dialog_height) // 2
        
        self.dialog.geometry(f"+{x}+{y}")

class LoadingSpinner:
    """
    Animated loading spinner widget
    """
    
    def __init__(self, parent, size: int = 32, color: str = "#007ACC"):
        self.parent = parent
        self.size = size
        self.color = color
        self.canvas = None
        self.animation_id = None
        self.angle = 0
        self.running = False
        
    def create(self) -> tk.Canvas:
        """Create spinner canvas"""
        self.canvas = tk.Canvas(self.parent, width=self.size, height=self.size,
                               highlightthickness=0, bg=self.parent.cget('bg'))
        return self.canvas
    
    def start(self):
        """Start spinner animation"""
        if not self.running and self.canvas:
            self.running = True
            self._animate()
    
    def stop(self):
        """Stop spinner animation"""
        self.running = False
        if self.animation_id:
            self.canvas.after_cancel(self.animation_id)
            self.animation_id = None
        if self.canvas:
            self.canvas.delete("all")
    
    def _animate(self):
        """Animate spinner rotation"""
        if not self.running or not self.canvas:
            return
        
        self.canvas.delete("all")
        
        # Draw spinner arcs
        center = self.size // 2
        radius = center - 4
        
        for i in range(8):
            start_angle = self.angle + (i * 45)
            alpha = 1.0 - (i * 0.1)
            
            # Calculate arc color with alpha
            color = self._adjust_color_alpha(self.color, alpha)
            
            self.canvas.create_arc(
                center - radius, center - radius,
                center + radius, center + radius,
                start=start_angle, extent=20,
                outline=color, width=3, style='arc'
            )
        
        self.angle = (self.angle + 22.5) % 360
        self.animation_id = self.canvas.after(80, self._animate)
    
    def _adjust_color_alpha(self, color: str, alpha: float) -> str:
        """Adjust color transparency (simplified)"""
        if color.startswith('#'):
            # Convert hex to RGB and adjust brightness
            hex_color = color[1:]
            rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
            
            # Simulate alpha by blending with background
            bg_color = (255, 255, 255)  # Assume white background
            
            new_rgb = tuple(
                int(rgb[i] * alpha + bg_color[i] * (1 - alpha))
                for i in range(3)
            )
            
            return f"#{new_rgb[0]:02x}{new_rgb[1]:02x}{new_rgb[2]:02x}"
        
        return color

class StatusBar:
    """
    Enhanced status bar with multiple sections and animations
    """
    
    def __init__(self, parent):
        self.parent = parent
        self.frame = None
        self.status_var = None
        self.progress_var = None
        self.progress_bar = None
        self.spinner = None
        self.sections = {}
        
    def create(self) -> ttk.Frame:
        """Create status bar"""
        self.frame = ttk.Frame(self.parent, relief=tk.SUNKEN)
        
        # Main status section
        status_frame = ttk.Frame(self.frame)
        status_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(status_frame, textvariable=self.status_var)
        status_label.pack(side=tk.LEFT, padx=5)
        
        # Progress section
        progress_frame = ttk.Frame(self.frame)
        progress_frame.pack(side=tk.RIGHT, padx=2)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            variable=self.progress_var,
            length=100,
            height=16,
            mode='determinate'
        )
        
        # Spinner section
        spinner_frame = ttk.Frame(self.frame)
        spinner_frame.pack(side=tk.RIGHT, padx=2)
        
        self.spinner = LoadingSpinner(spinner_frame, size=16)
        spinner_canvas = self.spinner.create()
        spinner_canvas.pack()
        
        return self.frame
    
    def set_status(self, message: str):
        """Set status message"""
        if self.status_var:
            self.status_var.set(message)
    
    def show_progress(self, show: bool = True):
        """Show/hide progress bar"""
        if self.progress_bar:
            if show:
                self.progress_bar.pack(side=tk.RIGHT, padx=5)
            else:
                self.progress_bar.pack_forget()
    
    def update_progress(self, value: float):
        """Update progress bar value (0-100)"""
        if self.progress_var:
            self.progress_var.set(value)
    
    def show_spinner(self, show: bool = True):
        """Show/hide loading spinner"""
        if self.spinner:
            if show:
                self.spinner.start()
            else:
                self.spinner.stop()
    
    def add_section(self, name: str, text: str = "", width: int = 100):
        """Add custom section to status bar"""
        if self.frame and name not in self.sections:
            section_frame = ttk.Frame(self.frame, width=width)
            section_frame.pack(side=tk.RIGHT, padx=2)
            section_frame.pack_propagate(False)
            
            section_var = tk.StringVar(value=text)
            section_label = ttk.Label(section_frame, textvariable=section_var)
            section_label.pack(expand=True)
            
            self.sections[name] = {
                'frame': section_frame,
                'var': section_var,
                'label': section_label
            }
    
    def update_section(self, name: str, text: str):
        """Update custom section text"""
        if name in self.sections:
            self.sections[name]['var'].set(text)

class TooltipManager:
    """
    Enhanced tooltip manager with formatting support
    """
    
    def __init__(self):
        self.tooltips = {}
        
    def add_tooltip(self, widget, text: str, delay: int = 500, 
                   wraplength: int = 250, theme: ThemeMode = ThemeMode.LIGHT):
        """Add tooltip to widget"""
        tooltip = EnhancedTooltip(widget, text, delay, wraplength, theme)
        self.tooltips[widget] = tooltip
        return tooltip
    
    def remove_tooltip(self, widget):
        """Remove tooltip from widget"""
        if widget in self.tooltips:
            self.tooltips[widget].destroy()
            del self.tooltips[widget]
    
    def update_tooltip(self, widget, text: str):
        """Update tooltip text"""
        if widget in self.tooltips:
            self.tooltips[widget].text = text

class EnhancedTooltip:
    """
    Enhanced tooltip with modern styling
    """
    
    def __init__(self, widget, text: str, delay: int = 500, 
                 wraplength: int = 250, theme: ThemeMode = ThemeMode.LIGHT):
        self.widget = widget
        self.text = text
        self.delay = delay
        self.wraplength = wraplength
        self.theme = theme
        self.tooltip_window = None
        self.after_id = None
        
        # Bind events
        self.widget.bind("<Enter>", self._on_enter)
        self.widget.bind("<Leave>", self._on_leave)
        self.widget.bind("<Motion>", self._on_motion)
    
    def _on_enter(self, event=None):
        """Mouse enter event"""
        self._schedule_show()
    
    def _on_leave(self, event=None):
        """Mouse leave event"""
        self._cancel_show()
        self._hide()
    
    def _on_motion(self, event=None):
        """Mouse motion event"""
        self._cancel_show()
        self._schedule_show()
    
    def _schedule_show(self):
        """Schedule tooltip display"""
        self._cancel_show()
        self.after_id = self.widget.after(self.delay, self._show)
    
    def _cancel_show(self):
        """Cancel scheduled tooltip display"""
        if self.after_id:
            self.widget.after_cancel(self.after_id)
            self.after_id = None
    
    def _show(self):
        """Show tooltip"""
        if self.tooltip_window or not self.text:
            return
        
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        
        self.tooltip_window = tk.Toplevel(self.widget)
        self.tooltip_window.wm_overrideredirect(True)
        
        # Apply theme styling
        if self.theme == ThemeMode.DARK:
            bg_color = "#2b2b2b"
            fg_color = "#ffffff"
            border_color = "#555555"
        else:
            bg_color = "#ffffe0"
            fg_color = "#000000"
            border_color = "#808080"
        
        label = tk.Label(
            self.tooltip_window,
            text=self.text,
            background=bg_color,
            foreground=fg_color,
            relief=tk.SOLID,
            borderwidth=1,
            font=("Segoe UI", 9),
            wraplength=self.wraplength,
            justify=tk.LEFT,
            padx=8,
            pady=4
        )
        label.pack()
        
        # Position tooltip
        self.tooltip_window.geometry(f"+{x}+{y}")
        
        # Ensure tooltip stays on screen
        self.tooltip_window.update_idletasks()
        tooltip_width = self.tooltip_window.winfo_reqwidth()
        tooltip_height = self.tooltip_window.winfo_reqheight()
        screen_width = self.tooltip_window.winfo_screenwidth()
        screen_height = self.tooltip_window.winfo_screenheight()
        
        if x + tooltip_width > screen_width:
            x = screen_width - tooltip_width - 10
        if y + tooltip_height > screen_height:
            y = self.widget.winfo_rooty() - tooltip_height - 5
        
        self.tooltip_window.geometry(f"+{x}+{y}")
    
    def _hide(self):
        """Hide tooltip"""
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None
    
    def destroy(self):
        """Destroy tooltip"""
        self._cancel_show()
        self._hide()
        
        # Unbind events
        self.widget.unbind("<Enter>")
        self.widget.unbind("<Leave>")
        self.widget.unbind("<Motion>")

class NotificationManager:
    """
    In-app notification system with different types and animations
    """
    
    def __init__(self, parent):
        self.parent = parent
        self.notifications = []
        self.container = None
        
    def create_container(self):
        """Create notification container"""
        self.container = tk.Frame(self.parent)
        self.container.place(relx=1.0, rely=0.0, anchor='ne', x=-10, y=10)
        return self.container
    
    def show_notification(self, message: str, type_: str = "info", 
                         duration: int = 3000, clickable: bool = True):
        """Show notification"""
        if not self.container:
            self.create_container()
        
        notification = Notification(
            self.container, message, type_, duration, 
            clickable, self._remove_notification
        )
        
        self.notifications.append(notification)
        notification.show()
        
        # Auto-position notifications
        self._reposition_notifications()
        
        return notification
    
    def _remove_notification(self, notification):
        """Remove notification from list"""
        if notification in self.notifications:
            self.notifications.remove(notification)
            self._reposition_notifications()
    
    def _reposition_notifications(self):
        """Reposition all notifications"""
        for i, notification in enumerate(self.notifications):
            y_offset = i * 60
            notification.update_position(y_offset)

class Notification:
    """
    Individual notification widget
    """
    
    def __init__(self, parent, message: str, type_: str, duration: int,
                 clickable: bool, remove_callback: Callable):
        self.parent = parent
        self.message = message
        self.type = type_
        self.duration = duration
        self.clickable = clickable
        self.remove_callback = remove_callback
        self.frame = None
        self.auto_hide_id = None
        
        # Type-specific styling
        self.styles = {
            "info": {"bg": "#d1ecf1", "fg": "#0c5460", "border": "#bee5eb"},
            "success": {"bg": "#d4edda", "fg": "#155724", "border": "#c3e6cb"},
            "warning": {"bg": "#fff3cd", "fg": "#856404", "border": "#ffeaa7"},
            "error": {"bg": "#f8d7da", "fg": "#721c24", "border": "#f5c6cb"}
        }
    
    def show(self):
        """Show notification"""
        style = self.styles.get(self.type, self.styles["info"])
        
        self.frame = tk.Frame(
            self.parent,
            bg=style["border"],
            relief=tk.RAISED,
            borderwidth=1
        )
        
        # Inner frame for padding
        inner_frame = tk.Frame(self.frame, bg=style["bg"])
        inner_frame.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        
        # Message label
        message_label = tk.Label(
            inner_frame,
            text=self.message,
            bg=style["bg"],
            fg=style["fg"],
            font=("Segoe UI", 9),
            wraplength=300,
            justify=tk.LEFT
        )
        message_label.pack(side=tk.LEFT, padx=10, pady=8)
        
        # Close button
        if self.clickable:
            close_btn = tk.Label(
                inner_frame,
                text="×",
                bg=style["bg"],
                fg=style["fg"],
                font=("Segoe UI", 12, "bold"),
                cursor="hand2"
            )
            close_btn.pack(side=tk.RIGHT, padx=5, pady=8)
            close_btn.bind("<Button-1>", lambda e: self.hide())
        
        # Auto-hide
        if self.duration > 0:
            self.auto_hide_id = self.parent.after(self.duration, self.hide)
        
        # Show with animation
        self._animate_in()
    
    def hide(self):
        """Hide notification"""
        if self.auto_hide_id:
            self.parent.after_cancel(self.auto_hide_id)
        
        self._animate_out()
    
    def update_position(self, y_offset: int):
        """Update notification position"""
        if self.frame:
            self.frame.place(x=0, y=y_offset, width=320)
    
    def _animate_in(self):
        """Animate notification appearance"""
        if self.frame:
            self.frame.place(x=0, y=0, width=320, height=50)
    
    def _animate_out(self):
        """Animate notification disappearance"""
        if self.frame:
            self.frame.destroy()
            self.frame = None
            self.remove_callback(self)

# Global instances
_tooltip_manager: Optional[TooltipManager] = None

def get_tooltip_manager() -> TooltipManager:
    """Get global tooltip manager instance"""
    global _tooltip_manager
    if _tooltip_manager is None:
        _tooltip_manager = TooltipManager()
    return _tooltip_manager