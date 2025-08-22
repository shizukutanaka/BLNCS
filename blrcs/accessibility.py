# BLRCS Accessibility Module
# Comprehensive accessibility features for inclusive design
import tkinter as tk
from tkinter import ttk
from typing import Dict, List, Optional, Callable, Any, Union
from dataclasses import dataclass
from enum import Enum
import platform
import threading
import time

class AccessibilityLevel(Enum):
    """Accessibility compliance levels"""
    BASIC = "basic"          # Basic accessibility
    AA = "aa"               # WCAG 2.1 AA compliance
    AAA = "aaa"             # WCAG 2.1 AAA compliance

class ColorBlindnessType(Enum):
    """Types of color blindness"""
    NONE = "none"
    PROTANOPIA = "protanopia"      # Red-blind
    DEUTERANOPIA = "deuteranopia"  # Green-blind
    TRITANOPIA = "tritanopia"      # Blue-blind
    MONOCHROMACY = "monochromacy"  # Complete color blindness

@dataclass
class AccessibilitySettings:
    """User accessibility preferences"""
    high_contrast: bool = False
    large_text: bool = False
    reduced_motion: bool = False
    screen_reader: bool = False
    keyboard_navigation: bool = True
    color_blindness_type: ColorBlindnessType = ColorBlindnessType.NONE
    focus_indicators: bool = True
    audio_cues: bool = False
    text_to_speech: bool = False

class FocusManager:
    """
    Keyboard navigation and focus management
    """
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.focusable_widgets = []
        self.current_focus_index = 0
        self.focus_indicators = True
        
        # Bind keyboard navigation
        self.root.bind('<Tab>', self._tab_forward)
        self.root.bind('<Shift-Tab>', self._tab_backward)
        self.root.bind('<Return>', self._activate_focused)
        self.root.bind('<space>', self._activate_focused)
        self.root.bind('<Escape>', self._escape_focus)
        
        # Focus visual indicators
        self.focus_style = {
            'highlightbackground': '#007acc',
            'highlightcolor': '#007acc',
            'highlightthickness': 2
        }
    
    def register_widget(self, widget: tk.Widget, activate_callback: Optional[Callable] = None):
        """Register widget for keyboard navigation"""
        widget_info = {
            'widget': widget,
            'callback': activate_callback,
            'original_style': {}
        }
        
        # Store original focus style
        try:
            for prop in self.focus_style:
                if hasattr(widget, 'cget'):
                    widget_info['original_style'][prop] = widget.cget(prop)
        except:
            pass
        
        self.focusable_widgets.append(widget_info)
        
        # Bind focus events
        widget.bind('<FocusIn>', lambda e: self._on_focus_in(widget))
        widget.bind('<FocusOut>', lambda e: self._on_focus_out(widget))
    
    def _tab_forward(self, event):
        """Move focus forward"""
        if not self.focusable_widgets:
            return
        
        self.current_focus_index = (self.current_focus_index + 1) % len(self.focusable_widgets)
        self._set_focus()
        return 'break'
    
    def _tab_backward(self, event):
        """Move focus backward"""
        if not self.focusable_widgets:
            return
        
        self.current_focus_index = (self.current_focus_index - 1) % len(self.focusable_widgets)
        self._set_focus()
        return 'break'
    
    def _set_focus(self):
        """Set focus to current widget"""
        if 0 <= self.current_focus_index < len(self.focusable_widgets):
            widget_info = self.focusable_widgets[self.current_focus_index]
            widget = widget_info['widget']
            
            try:
                widget.focus_set()
                # Ensure widget is visible
                self._ensure_visible(widget)
            except:
                # Widget might be destroyed, remove from list
                self.focusable_widgets.remove(widget_info)
                if self.current_focus_index >= len(self.focusable_widgets):
                    self.current_focus_index = 0
    
    def _activate_focused(self, event):
        """Activate currently focused widget"""
        if 0 <= self.current_focus_index < len(self.focusable_widgets):
            widget_info = self.focusable_widgets[self.current_focus_index]
            
            if widget_info['callback']:
                widget_info['callback']()
            else:
                # Default activation
                widget = widget_info['widget']
                if hasattr(widget, 'invoke'):
                    widget.invoke()
                elif hasattr(widget, 'toggle'):
                    widget.toggle()
        
        return 'break'
    
    def _escape_focus(self, event):
        """Handle escape key"""
        self.root.focus_set()
        return 'break'
    
    def _on_focus_in(self, widget):
        """Handle widget gaining focus"""
        if self.focus_indicators:
            try:
                widget.configure(**self.focus_style)
            except:
                pass
    
    def _on_focus_out(self, widget):
        """Handle widget losing focus"""
        if self.focus_indicators:
            # Restore original style
            for widget_info in self.focusable_widgets:
                if widget_info['widget'] == widget:
                    try:
                        widget.configure(**widget_info['original_style'])
                    except:
                        pass
                    break
    
    def _ensure_visible(self, widget):
        """Ensure focused widget is visible"""
        try:
            # If widget is in a scrollable area, scroll to it
            parent = widget.master
            while parent:
                if isinstance(parent, (tk.Canvas, tk.Text)):
                    # Scroll to show widget
                    parent.see(widget)
                    break
                parent = parent.master
        except:
            pass

class ScreenReaderSupport:
    """
    Screen reader compatibility and announcements
    """
    
    def __init__(self):
        self.enabled = False
        self.announcements = []
        self.current_announcement = ""
        
        # Try to detect screen reader
        self._detect_screen_reader()
    
    def _detect_screen_reader(self):
        """Detect if screen reader is active"""
        try:
            if platform.system() == "Windows":
                import winreg
                try:
                    # Check for NVDA, JAWS, or Windows Narrator
                    registry = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
                    key = winreg.OpenKey(registry, r"SOFTWARE\Microsoft\Narrator")
                    self.enabled = True
                    winreg.CloseKey(key)
                except:
                    pass
            
            elif platform.system() == "Darwin":  # macOS
                import subprocess
                try:
                    # Check for VoiceOver
                    result = subprocess.run([
                        'defaults', 'read', 'com.apple.universalaccess', 'voiceOverOnOffKey'
                    ], capture_output=True, text=True)
                    self.enabled = len(result.stdout.strip()) > 0
                except:
                    pass
            
            elif platform.system() == "Linux":
                import subprocess
                try:
                    # Check for Orca
                    result = subprocess.run(['pgrep', 'orca'], capture_output=True)
                    self.enabled = result.returncode == 0
                except:
                    pass
        except:
            pass
    
    def announce(self, message: str, priority: str = "normal"):
        """Announce message to screen reader"""
        if not self.enabled:
            return
        
        self.announcements.append({
            'message': message,
            'priority': priority,
            'timestamp': time.time()
        })
        
        self._process_announcements()
    
    def _process_announcements(self):
        """Process announcement queue"""
        if not self.announcements:
            return
        
        # Get highest priority announcement
        announcement = max(self.announcements, 
                         key=lambda x: {'low': 0, 'normal': 1, 'high': 2}[x['priority']])
        
        self.current_announcement = announcement['message']
        self.announcements.remove(announcement)
        
        # In a real implementation, this would interface with screen reader APIs
        # For now, we'll just store the message for accessibility tools to read
    
    def describe_widget(self, widget: tk.Widget) -> str:
        """Generate description for widget"""
        widget_type = widget.__class__.__name__
        
        # Get widget text/label
        text = ""
        try:
            if hasattr(widget, 'cget'):
                text = widget.cget('text') or ""
        except:
            pass
        
        # Build description
        description = f"{widget_type}"
        if text:
            description += f": {text}"
        
        # Add state information
        try:
            if hasattr(widget, 'cget'):
                state = widget.cget('state')
                if state == 'disabled':
                    description += ", disabled"
        except:
            pass
        
        return description

class ColorAccessibility:
    """
    Color accessibility features including color blindness support
    """
    
    def __init__(self):
        self.color_blindness_type = ColorBlindnessType.NONE
        self.high_contrast = False
        
    def set_color_blindness_type(self, cb_type: ColorBlindnessType):
        """Set color blindness simulation"""
        self.color_blindness_type = cb_type
    
    def adjust_color(self, color: str) -> str:
        """Adjust color for color blindness"""
        if self.color_blindness_type == ColorBlindnessType.NONE:
            return color
        
        # Convert hex to RGB
        if color.startswith('#'):
            try:
                r = int(color[1:3], 16)
                g = int(color[3:5], 16)
                b = int(color[5:7], 16)
                
                # Apply color blindness simulation
                if self.color_blindness_type == ColorBlindnessType.PROTANOPIA:
                    r, g, b = self._protanopia_transform(r, g, b)
                elif self.color_blindness_type == ColorBlindnessType.DEUTERANOPIA:
                    r, g, b = self._deuteranopia_transform(r, g, b)
                elif self.color_blindness_type == ColorBlindnessType.TRITANOPIA:
                    r, g, b = self._tritanopia_transform(r, g, b)
                elif self.color_blindness_type == ColorBlindnessType.MONOCHROMACY:
                    gray = int(0.299 * r + 0.587 * g + 0.114 * b)
                    r = g = b = gray
                
                # Convert back to hex
                return f"#{r:02x}{g:02x}{b:02x}"
            except:
                pass
        
        return color
    
    def _protanopia_transform(self, r: int, g: int, b: int) -> tuple:
        """Transform colors for protanopia (red-blind)"""
        # Simplified protanopia simulation
        new_r = int(0.567 * r + 0.433 * g)
        new_g = int(0.558 * r + 0.442 * g)
        new_b = int(0.242 * g + 0.758 * b)
        return (new_r, new_g, new_b)
    
    def _deuteranopia_transform(self, r: int, g: int, b: int) -> tuple:
        """Transform colors for deuteranopia (green-blind)"""
        # Simplified deuteranopia simulation
        new_r = int(0.625 * r + 0.375 * g)
        new_g = int(0.7 * r + 0.3 * g)
        new_b = int(0.3 * g + 0.7 * b)
        return (new_r, new_g, new_b)
    
    def _tritanopia_transform(self, r: int, g: int, b: int) -> tuple:
        """Transform colors for tritanopia (blue-blind)"""
        # Simplified tritanopia simulation
        new_r = int(0.95 * r + 0.05 * g)
        new_g = int(0.433 * g + 0.567 * b)
        new_b = int(0.475 * g + 0.525 * b)
        return (new_r, new_g, new_b)
    
    def get_high_contrast_colors(self) -> Dict[str, str]:
        """Get high contrast color scheme"""
        if self.high_contrast:
            return {
                'bg': '#000000',
                'fg': '#ffffff',
                'select_bg': '#ffffff',
                'select_fg': '#000000',
                'button_bg': '#ffffff',
                'button_fg': '#000000',
                'entry_bg': '#000000',
                'entry_fg': '#ffffff',
                'border': '#ffffff'
            }
        else:
            return {}

class AccessibilityManager:
    """
    Central accessibility management system
    """
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.settings = AccessibilitySettings()
        
        # Initialize subsystems
        self.focus_manager = FocusManager(root)
        self.screen_reader = ScreenReaderSupport()
        self.color_accessibility = ColorAccessibility()
        
        # Accessibility state
        self.enabled_features = set()
    
    def enable_feature(self, feature: str):
        """Enable accessibility feature"""
        self.enabled_features.add(feature)
        
        if feature == "high_contrast":
            self.settings.high_contrast = True
            self.color_accessibility.high_contrast = True
            self._apply_high_contrast()
        
        elif feature == "large_text":
            self.settings.large_text = True
            self._apply_large_text()
        
        elif feature == "reduced_motion":
            self.settings.reduced_motion = True
            self._apply_reduced_motion()
        
        elif feature == "keyboard_navigation":
            self.settings.keyboard_navigation = True
            # Already enabled by default
        
        elif feature == "screen_reader":
            self.settings.screen_reader = True
            self.screen_reader.enabled = True
    
    def disable_feature(self, feature: str):
        """Disable accessibility feature"""
        self.enabled_features.discard(feature)
        
        if feature == "high_contrast":
            self.settings.high_contrast = False
            self.color_accessibility.high_contrast = False
        
        elif feature == "large_text":
            self.settings.large_text = False
        
        # Apply changes
        self._update_accessibility()
    
    def set_color_blindness_type(self, cb_type: ColorBlindnessType):
        """Set color blindness type"""
        self.settings.color_blindness_type = cb_type
        self.color_accessibility.set_color_blindness_type(cb_type)
    
    def register_widget(self, widget: tk.Widget, 
                       description: str = "",
                       role: str = "",
                       activate_callback: Optional[Callable] = None):
        """Register widget for accessibility"""
        # Add to focus management
        if self.settings.keyboard_navigation:
            self.focus_manager.register_widget(widget, activate_callback)
        
        # Add accessibility attributes
        if description:
            widget.accessibility_description = description
        if role:
            widget.accessibility_role = role
        
        # Apply current accessibility settings
        self._apply_widget_accessibility(widget)
    
    def announce(self, message: str, priority: str = "normal"):
        """Announce message for screen readers"""
        if self.settings.screen_reader:
            self.screen_reader.announce(message, priority)
    
    def _apply_high_contrast(self):
        """Apply high contrast theme"""
        colors = self.color_accessibility.get_high_contrast_colors()
        if colors:
            # Apply to root window
            self.root.configure(bg=colors['bg'])
            
            # Apply to all child widgets
            self._apply_colors_recursive(self.root, colors)
    
    def _apply_large_text(self):
        """Apply large text settings"""
        def scale_font(widget):
            try:
                if hasattr(widget, 'cget'):
                    current_font = widget.cget('font')
                    if isinstance(current_font, tuple) and len(current_font) >= 2:
                        family, size = current_font[0], current_font[1]
                        new_size = int(size * 1.25)  # 25% larger
                        widget.configure(font=(family, new_size) + current_font[2:])
            except:
                pass
        
        self._apply_to_all_widgets(scale_font)
    
    def _apply_reduced_motion(self):
        """Apply reduced motion settings"""
        # Disable animations and transitions
        # This would need to be implemented in animation systems
        pass
    
    def _apply_widget_accessibility(self, widget: tk.Widget):
        """Apply accessibility settings to widget"""
        if self.settings.high_contrast:
            colors = self.color_accessibility.get_high_contrast_colors()
            if colors:
                try:
                    widget.configure(
                        bg=colors['bg'],
                        fg=colors['fg']
                    )
                except:
                    pass
        
        if self.settings.large_text:
            try:
                if hasattr(widget, 'cget'):
                    current_font = widget.cget('font')
                    if isinstance(current_font, tuple) and len(current_font) >= 2:
                        family, size = current_font[0], current_font[1]
                        new_size = int(size * 1.25)
                        widget.configure(font=(family, new_size) + current_font[2:])
            except:
                pass
    
    def _apply_colors_recursive(self, widget: tk.Widget, colors: Dict[str, str]):
        """Apply colors to widget and children"""
        try:
            widget.configure(
                bg=colors.get('bg', widget.cget('bg')),
                fg=colors.get('fg', widget.cget('fg'))
            )
        except:
            pass
        
        for child in widget.winfo_children():
            self._apply_colors_recursive(child, colors)
    
    def _apply_to_all_widgets(self, func: Callable[[tk.Widget], None]):
        """Apply function to all widgets"""
        def apply_recursive(widget):
            func(widget)
            for child in widget.winfo_children():
                apply_recursive(child)
        
        apply_recursive(self.root)
    
    def _update_accessibility(self):
        """Update all accessibility features"""
        if self.settings.high_contrast:
            self._apply_high_contrast()
        
        if self.settings.large_text:
            self._apply_large_text()
        
        if self.settings.reduced_motion:
            self._apply_reduced_motion()
    
    def create_accessibility_menu(self, parent: tk.Widget) -> tk.Menu:
        """Create accessibility options menu"""
        menu = tk.Menu(parent, tearoff=0)
        
        # High contrast
        menu.add_checkbutton(
            label="High Contrast",
            variable=tk.BooleanVar(value=self.settings.high_contrast),
            command=lambda: self._toggle_feature("high_contrast")
        )
        
        # Large text
        menu.add_checkbutton(
            label="Large Text",
            variable=tk.BooleanVar(value=self.settings.large_text),
            command=lambda: self._toggle_feature("large_text")
        )
        
        # Reduced motion
        menu.add_checkbutton(
            label="Reduced Motion",
            variable=tk.BooleanVar(value=self.settings.reduced_motion),
            command=lambda: self._toggle_feature("reduced_motion")
        )
        
        # Color blindness submenu
        cb_menu = tk.Menu(menu, tearoff=0)
        for cb_type in ColorBlindnessType:
            cb_menu.add_radiobutton(
                label=cb_type.value.replace('_', ' ').title(),
                value=cb_type.value,
                command=lambda t=cb_type: self.set_color_blindness_type(t)
            )
        menu.add_cascade(label="Color Blindness", menu=cb_menu)
        
        return menu
    
    def _toggle_feature(self, feature: str):
        """Toggle accessibility feature"""
        if feature in self.enabled_features:
            self.disable_feature(feature)
        else:
            self.enable_feature(feature)
    
    def get_accessibility_info(self) -> Dict[str, Any]:
        """Get current accessibility information"""
        return {
            'enabled_features': list(self.enabled_features),
            'settings': self.settings.__dict__,
            'screen_reader_detected': self.screen_reader.enabled,
            'color_blindness_type': self.settings.color_blindness_type.value
        }

# Global accessibility manager
_accessibility_manager: Optional[AccessibilityManager] = None

def get_accessibility_manager() -> Optional[AccessibilityManager]:
    """Get global accessibility manager"""
    return _accessibility_manager

def init_accessibility(root: tk.Tk) -> AccessibilityManager:
    """Initialize accessibility for root window"""
    global _accessibility_manager
    _accessibility_manager = AccessibilityManager(root)
    return _accessibility_manager