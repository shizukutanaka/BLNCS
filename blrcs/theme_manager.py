# BLRCS Theme Manager Module
# Dark mode and theme management system
import tkinter as tk
from tkinter import ttk
import json
from pathlib import Path
from typing import Dict, Optional, Callable, Any
from dataclasses import dataclass
from enum import Enum
import platform

class ThemeType(Enum):
    """Available theme types"""
    LIGHT = "light"
    DARK = "dark"
    HIGH_CONTRAST = "high_contrast"
    AUTO = "auto"

@dataclass
class ColorScheme:
    """Color scheme definition"""
    # Background colors
    bg_primary: str
    bg_secondary: str
    bg_tertiary: str
    
    # Foreground colors
    fg_primary: str
    fg_secondary: str
    fg_tertiary: str
    
    # Accent colors
    accent_primary: str
    accent_secondary: str
    
    # State colors
    success: str
    warning: str
    error: str
    info: str
    
    # Border and separator colors
    border: str
    separator: str
    
    # Interactive element colors
    button_bg: str
    button_fg: str
    button_hover: str
    button_active: str
    
    # Input field colors
    entry_bg: str
    entry_fg: str
    entry_border: str
    entry_focus: str
    
    # Selection colors
    select_bg: str
    select_fg: str

class ThemeManager:
    """
    Comprehensive theme management system with:
    - Multiple built-in themes
    - Custom theme support
    - Automatic OS theme detection
    - Dynamic theme switching
    - Component-specific styling
    """
    
    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or Path("themes.json")
        self.current_theme = ThemeType.LIGHT
        self.color_schemes = {}
        self.style = None
        self.callbacks = []
        
        # Initialize built-in themes
        self._init_builtin_themes()
        
        # Load custom themes
        self._load_themes()
        
        # Setup ttk style
        self._setup_style()
    
    def _init_builtin_themes(self):
        """Initialize built-in color schemes"""
        
        # Light theme (default)
        self.color_schemes[ThemeType.LIGHT] = ColorScheme(
            # Backgrounds
            bg_primary="#ffffff",
            bg_secondary="#f8f9fa",
            bg_tertiary="#e9ecef",
            
            # Foregrounds
            fg_primary="#212529",
            fg_secondary="#495057",
            fg_tertiary="#6c757d",
            
            # Accents
            accent_primary="#007bff",
            accent_secondary="#6c757d",
            
            # States
            success="#28a745",
            warning="#ffc107",
            error="#dc3545",
            info="#17a2b8",
            
            # Borders
            border="#dee2e6",
            separator="#e9ecef",
            
            # Buttons
            button_bg="#007bff",
            button_fg="#ffffff",
            button_hover="#0056b3",
            button_active="#004085",
            
            # Inputs
            entry_bg="#ffffff",
            entry_fg="#495057",
            entry_border="#ced4da",
            entry_focus="#80bdff",
            
            # Selection
            select_bg="#007bff",
            select_fg="#ffffff"
        )
        
        # Dark theme
        self.color_schemes[ThemeType.DARK] = ColorScheme(
            # Backgrounds
            bg_primary="#1e1e1e",
            bg_secondary="#252526",
            bg_tertiary="#2d2d30",
            
            # Foregrounds
            fg_primary="#cccccc",
            fg_secondary="#969696",
            fg_tertiary="#6a6a6a",
            
            # Accents
            accent_primary="#0e639c",
            accent_secondary="#007acc",
            
            # States
            success="#4ec9b0",
            warning="#ffcc02",
            error="#f48771",
            info="#9cdcfe",
            
            # Borders
            border="#3e3e42",
            separator="#2d2d30",
            
            # Buttons
            button_bg="#0e639c",
            button_fg="#ffffff",
            button_hover="#1177bb",
            button_active="#094771",
            
            # Inputs
            entry_bg="#3c3c3c",
            entry_fg="#cccccc",
            entry_border="#5a5a5a",
            entry_focus="#007acc",
            
            # Selection
            select_bg="#094771",
            select_fg="#ffffff"
        )
        
        # High contrast theme
        self.color_schemes[ThemeType.HIGH_CONTRAST] = ColorScheme(
            # Backgrounds
            bg_primary="#000000",
            bg_secondary="#0f0f0f",
            bg_tertiary="#1a1a1a",
            
            # Foregrounds
            fg_primary="#ffffff",
            fg_secondary="#e0e0e0",
            fg_tertiary="#c0c0c0",
            
            # Accents
            accent_primary="#ffffff",
            accent_secondary="#ffff00",
            
            # States
            success="#00ff00",
            warning="#ffff00",
            error="#ff0000",
            info="#00ffff",
            
            # Borders
            border="#ffffff",
            separator="#808080",
            
            # Buttons
            button_bg="#ffffff",
            button_fg="#000000",
            button_hover="#e0e0e0",
            button_active="#c0c0c0",
            
            # Inputs
            entry_bg="#000000",
            entry_fg="#ffffff",
            entry_border="#ffffff",
            entry_focus="#ffff00",
            
            # Selection
            select_bg="#ffffff",
            select_fg="#000000"
        )
    
    def _setup_style(self):
        """Setup ttk style with current theme"""
        self.style = ttk.Style()
        self._apply_theme()
    
    def _apply_theme(self):
        """Apply current theme to all UI elements"""
        if not self.style:
            return
        
        scheme = self.color_schemes[self.current_theme]
        
        # Configure ttk styles
        self.style.theme_use('clam')
        
        # Frame styles
        self.style.configure(
            'TFrame',
            background=scheme.bg_primary,
            borderwidth=0
        )
        
        self.style.configure(
            'Card.TFrame',
            background=scheme.bg_secondary,
            relief='solid',
            borderwidth=1,
            bordercolor=scheme.border
        )
        
        # Label styles
        self.style.configure(
            'TLabel',
            background=scheme.bg_primary,
            foreground=scheme.fg_primary,
            font=('Segoe UI', 9)
        )
        
        self.style.configure(
            'Heading.TLabel',
            background=scheme.bg_primary,
            foreground=scheme.fg_primary,
            font=('Segoe UI', 12, 'bold')
        )
        
        self.style.configure(
            'Subtitle.TLabel',
            background=scheme.bg_primary,
            foreground=scheme.fg_secondary,
            font=('Segoe UI', 9)
        )
        
        # Button styles
        self.style.configure(
            'TButton',
            background=scheme.button_bg,
            foreground=scheme.button_fg,
            borderwidth=1,
            focuscolor='none',
            font=('Segoe UI', 9)
        )
        
        self.style.map(
            'TButton',
            background=[
                ('active', scheme.button_hover),
                ('pressed', scheme.button_active),
                ('disabled', scheme.bg_tertiary)
            ],
            foreground=[
                ('disabled', scheme.fg_tertiary)
            ]
        )
        
        # Entry styles
        self.style.configure(
            'TEntry',
            fieldbackground=scheme.entry_bg,
            foreground=scheme.entry_fg,
            bordercolor=scheme.entry_border,
            lightcolor=scheme.entry_focus,
            darkcolor=scheme.entry_focus,
            focuscolor=scheme.entry_focus,
            font=('Segoe UI', 9)
        )
        
        # Text widget styles
        self.style.configure(
            'TText',
            background=scheme.entry_bg,
            foreground=scheme.entry_fg,
            selectbackground=scheme.select_bg,
            selectforeground=scheme.select_fg,
            insertbackground=scheme.fg_primary,
            font=('Consolas', 9)
        )
        
        # Notebook styles
        self.style.configure(
            'TNotebook',
            background=scheme.bg_primary,
            borderwidth=0
        )
        
        self.style.configure(
            'TNotebook.Tab',
            background=scheme.bg_secondary,
            foreground=scheme.fg_primary,
            padding=[12, 8],
            font=('Segoe UI', 9)
        )
        
        self.style.map(
            'TNotebook.Tab',
            background=[
                ('selected', scheme.bg_primary),
                ('active', scheme.bg_tertiary)
            ],
            foreground=[
                ('selected', scheme.fg_primary),
                ('active', scheme.fg_primary)
            ]
        )
        
        # Progressbar styles
        self.style.configure(
            'TProgressbar',
            background=scheme.accent_primary,
            troughcolor=scheme.bg_tertiary,
            borderwidth=0,
            lightcolor=scheme.accent_primary,
            darkcolor=scheme.accent_primary
        )
        
        # Treeview styles
        self.style.configure(
            'Treeview',
            background=scheme.bg_primary,
            foreground=scheme.fg_primary,
            fieldbackground=scheme.bg_primary,
            selectbackground=scheme.select_bg,
            selectforeground=scheme.select_fg,
            font=('Segoe UI', 9)
        )
        
        self.style.configure(
            'Treeview.Heading',
            background=scheme.bg_secondary,
            foreground=scheme.fg_primary,
            font=('Segoe UI', 9, 'bold')
        )
        
        # Scrollbar styles
        self.style.configure(
            'TScrollbar',
            background=scheme.bg_secondary,
            troughcolor=scheme.bg_tertiary,
            bordercolor=scheme.border,
            arrowcolor=scheme.fg_secondary,
            darkcolor=scheme.bg_secondary,
            lightcolor=scheme.bg_secondary
        )
        
        # Menu styles (for context menus)
        self.style.configure(
            'TMenu',
            background=scheme.bg_primary,
            foreground=scheme.fg_primary,
            selectcolor=scheme.accent_primary,
            font=('Segoe UI', 9)
        )
        
        # Separator styles
        self.style.configure(
            'TSeparator',
            background=scheme.separator
        )
        
        # Custom status styles
        self.style.configure(
            'Success.TLabel',
            background=scheme.bg_primary,
            foreground=scheme.success,
            font=('Segoe UI', 9)
        )
        
        self.style.configure(
            'Warning.TLabel',
            background=scheme.bg_primary,
            foreground=scheme.warning,
            font=('Segoe UI', 9)
        )
        
        self.style.configure(
            'Error.TLabel',
            background=scheme.bg_primary,
            foreground=scheme.error,
            font=('Segoe UI', 9)
        )
        
        self.style.configure(
            'Info.TLabel',
            background=scheme.bg_primary,
            foreground=scheme.info,
            font=('Segoe UI', 9)
        )
        
        # Notify callbacks
        self._notify_theme_changed()
    
    def set_theme(self, theme: ThemeType):
        """Set active theme"""
        if theme in self.color_schemes:
            self.current_theme = theme
            self._apply_theme()
            self._save_theme_preference()
    
    def get_theme(self) -> ThemeType:
        """Get current theme"""
        return self.current_theme
    
    def get_color_scheme(self, theme: Optional[ThemeType] = None) -> ColorScheme:
        """Get color scheme for theme"""
        theme = theme or self.current_theme
        return self.color_schemes.get(theme, self.color_schemes[ThemeType.LIGHT])
    
    def toggle_theme(self):
        """Toggle between light and dark themes"""
        if self.current_theme == ThemeType.LIGHT:
            self.set_theme(ThemeType.DARK)
        else:
            self.set_theme(ThemeType.LIGHT)
    
    def detect_system_theme(self) -> ThemeType:
        """Detect system theme preference"""
        try:
            if platform.system() == "Windows":
                import winreg
                try:
                    registry = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
                    key = winreg.OpenKey(
                        registry,
                        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
                    )
                    value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
                    winreg.CloseKey(key)
                    return ThemeType.LIGHT if value else ThemeType.DARK
                except:
                    pass
            
            elif platform.system() == "Darwin":  # macOS
                import subprocess
                try:
                    result = subprocess.run([
                        'defaults', 'read', '-g', 'AppleInterfaceStyle'
                    ], capture_output=True, text=True)
                    return ThemeType.DARK if 'Dark' in result.stdout else ThemeType.LIGHT
                except:
                    pass
            
            elif platform.system() == "Linux":
                import subprocess
                try:
                    # Try GNOME settings
                    result = subprocess.run([
                        'gsettings', 'get', 'org.gnome.desktop.interface', 'gtk-theme'
                    ], capture_output=True, text=True)
                    return ThemeType.DARK if 'dark' in result.stdout.lower() else ThemeType.LIGHT
                except:
                    pass
        except:
            pass
        
        return ThemeType.LIGHT  # Default fallback
    
    def apply_auto_theme(self):
        """Apply theme based on system preference"""
        system_theme = self.detect_system_theme()
        self.set_theme(system_theme)
    
    def add_theme_callback(self, callback: Callable[[ThemeType], None]):
        """Add callback for theme changes"""
        self.callbacks.append(callback)
    
    def remove_theme_callback(self, callback: Callable[[ThemeType], None]):
        """Remove theme change callback"""
        if callback in self.callbacks:
            self.callbacks.remove(callback)
    
    def _notify_theme_changed(self):
        """Notify all callbacks of theme change"""
        for callback in self.callbacks:
            try:
                callback(self.current_theme)
            except Exception:
                pass
    
    def create_custom_theme(self, name: str, color_scheme: ColorScheme):
        """Create custom theme"""
        theme_type = ThemeType(name)
        self.color_schemes[theme_type] = color_scheme
        self._save_themes()
    
    def _load_themes(self):
        """Load custom themes from file"""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    data = json.load(f)
                    
                    # Load custom themes
                    for name, scheme_data in data.get('custom_themes', {}).items():
                        theme_type = ThemeType(name)
                        self.color_schemes[theme_type] = ColorScheme(**scheme_data)
                    
                    # Load current theme preference
                    current = data.get('current_theme')
                    if current:
                        try:
                            self.current_theme = ThemeType(current)
                        except ValueError:
                            pass
            except Exception:
                pass
    
    def _save_themes(self):
        """Save custom themes to file"""
        try:
            data = {
                'current_theme': self.current_theme.value,
                'custom_themes': {}
            }
            
            # Save custom themes only
            builtin_themes = {ThemeType.LIGHT, ThemeType.DARK, ThemeType.HIGH_CONTRAST}
            for theme_type, scheme in self.color_schemes.items():
                if theme_type not in builtin_themes:
                    data['custom_themes'][theme_type.value] = scheme.__dict__
            
            with open(self.config_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass
    
    def _save_theme_preference(self):
        """Save current theme preference"""
        self._save_themes()
    
    def apply_to_widget(self, widget: tk.Widget, style_name: Optional[str] = None):
        """Apply theme to specific widget"""
        scheme = self.get_color_scheme()
        
        if isinstance(widget, tk.Text):
            widget.configure(
                bg=scheme.entry_bg,
                fg=scheme.entry_fg,
                selectbackground=scheme.select_bg,
                selectforeground=scheme.select_fg,
                insertbackground=scheme.fg_primary
            )
        elif isinstance(widget, (tk.Label, tk.Button, tk.Frame)):
            widget.configure(
                bg=scheme.bg_primary,
                fg=scheme.fg_primary
            )
        elif isinstance(widget, tk.Entry):
            widget.configure(
                bg=scheme.entry_bg,
                fg=scheme.entry_fg,
                selectbackground=scheme.select_bg,
                selectforeground=scheme.select_fg,
                insertbackground=scheme.fg_primary
            )
        elif isinstance(widget, tk.Listbox):
            widget.configure(
                bg=scheme.bg_primary,
                fg=scheme.fg_primary,
                selectbackground=scheme.select_bg,
                selectforeground=scheme.select_fg
            )

# Global theme manager instance
_theme_manager: Optional[ThemeManager] = None

def get_theme_manager() -> ThemeManager:
    """Get global theme manager instance"""
    global _theme_manager
    if _theme_manager is None:
        _theme_manager = ThemeManager()
    return _theme_manager

def apply_theme_to_root(root: tk.Tk):
    """Apply current theme to root window"""
    theme_manager = get_theme_manager()
    scheme = theme_manager.get_color_scheme()
    
    root.configure(bg=scheme.bg_primary)
    
    # Apply to all children recursively
    def apply_recursive(widget):
        theme_manager.apply_to_widget(widget)
        for child in widget.winfo_children():
            apply_recursive(child)
    
    apply_recursive(root)