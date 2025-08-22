# BLRCS Responsive UI Module
# Responsive design system for adaptive layouts
import tkinter as tk
from tkinter import ttk
from typing import Dict, List, Callable, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import math

class BreakPoint(Enum):
    """Responsive breakpoints"""
    SMALL = "small"      # < 768px
    MEDIUM = "medium"    # 768px - 1024px
    LARGE = "large"      # 1024px - 1440px
    XLARGE = "xlarge"    # > 1440px

class LayoutMode(Enum):
    """Layout modes for different screen sizes"""
    MOBILE = "mobile"
    TABLET = "tablet"
    DESKTOP = "desktop"
    WIDESCREEN = "widescreen"

@dataclass
class ResponsiveConfig:
    """Configuration for responsive behavior"""
    min_width: int = 320
    max_width: int = 2560
    breakpoints: Dict[BreakPoint, int] = None
    
    def __post_init__(self):
        if self.breakpoints is None:
            self.breakpoints = {
                BreakPoint.SMALL: 768,
                BreakPoint.MEDIUM: 1024,
                BreakPoint.LARGE: 1440,
                BreakPoint.XLARGE: 2560
            }

class ResponsiveContainer:
    """
    Container that adapts its layout based on screen size
    """
    
    def __init__(self, parent: tk.Widget, config: ResponsiveConfig = None):
        self.parent = parent
        self.config = config or ResponsiveConfig()
        self.current_breakpoint = BreakPoint.LARGE
        self.current_mode = LayoutMode.DESKTOP
        
        # Layout configurations for different breakpoints
        self.layouts = {
            BreakPoint.SMALL: self._mobile_layout,
            BreakPoint.MEDIUM: self._tablet_layout,
            BreakPoint.LARGE: self._desktop_layout,
            BreakPoint.XLARGE: self._widescreen_layout
        }
        
        # Child widgets and their responsive configurations
        self.children = []
        self.resize_callbacks = []
        
        # Create main container
        self.container = ttk.Frame(parent)
        
        # Bind resize events
        self.container.bind('<Configure>', self._on_resize)
        parent.bind('<Configure>', self._on_parent_resize)
    
    def _on_resize(self, event):
        """Handle container resize"""
        if event.widget == self.container:
            self._update_layout()
    
    def _on_parent_resize(self, event):
        """Handle parent window resize"""
        if event.widget == self.parent:
            self._update_layout()
    
    def _update_layout(self):
        """Update layout based on current size"""
        width = self.parent.winfo_width()
        new_breakpoint = self._get_breakpoint(width)
        
        if new_breakpoint != self.current_breakpoint:
            self.current_breakpoint = new_breakpoint
            self.current_mode = self._get_layout_mode(new_breakpoint)
            self._apply_layout()
            self._notify_resize_callbacks()
    
    def _get_breakpoint(self, width: int) -> BreakPoint:
        """Determine breakpoint for given width"""
        if width < self.config.breakpoints[BreakPoint.SMALL]:
            return BreakPoint.SMALL
        elif width < self.config.breakpoints[BreakPoint.MEDIUM]:
            return BreakPoint.MEDIUM
        elif width < self.config.breakpoints[BreakPoint.LARGE]:
            return BreakPoint.LARGE
        else:
            return BreakPoint.XLARGE
    
    def _get_layout_mode(self, breakpoint: BreakPoint) -> LayoutMode:
        """Get layout mode for breakpoint"""
        mapping = {
            BreakPoint.SMALL: LayoutMode.MOBILE,
            BreakPoint.MEDIUM: LayoutMode.TABLET,
            BreakPoint.LARGE: LayoutMode.DESKTOP,
            BreakPoint.XLARGE: LayoutMode.WIDESCREEN
        }
        return mapping.get(breakpoint, LayoutMode.DESKTOP)
    
    def _apply_layout(self):
        """Apply layout for current breakpoint"""
        layout_func = self.layouts.get(self.current_breakpoint)
        if layout_func:
            layout_func()
    
    def _mobile_layout(self):
        """Apply mobile layout (single column, stacked)"""
        # Hide or collapse less important elements
        # Stack everything vertically
        # Use smaller fonts and padding
        pass
    
    def _tablet_layout(self):
        """Apply tablet layout (2 columns, some sidebar)"""
        # Show main content and essential sidebar
        # Use medium-sized fonts
        pass
    
    def _desktop_layout(self):
        """Apply desktop layout (full layout)"""
        # Show all panels and toolbars
        # Use standard fonts and spacing
        pass
    
    def _widescreen_layout(self):
        """Apply widescreen layout (expanded view)"""
        # Utilize extra space with wider panels
        # Show additional information panels
        pass
    
    def add_resize_callback(self, callback: Callable[[LayoutMode], None]):
        """Add callback for layout changes"""
        self.resize_callbacks.append(callback)
    
    def _notify_resize_callbacks(self):
        """Notify all resize callbacks"""
        for callback in self.resize_callbacks:
            try:
                callback(self.current_mode)
            except Exception:
                pass
    
    def pack(self, **kwargs):
        """Pack the container"""
        return self.container.pack(**kwargs)
    
    def grid(self, **kwargs):
        """Grid the container"""
        return self.container.grid(**kwargs)

class ResponsiveGrid:
    """
    Grid system with responsive columns
    """
    
    def __init__(self, parent: tk.Widget, columns: int = 12):
        self.parent = parent
        self.max_columns = columns
        self.rows = []
        self.current_row = None
        
        # Column width calculations
        self.column_configs = {
            BreakPoint.SMALL: {"columns": 1, "padding": 5},
            BreakPoint.MEDIUM: {"columns": 2, "padding": 8},
            BreakPoint.LARGE: {"columns": 3, "padding": 10},
            BreakPoint.XLARGE: {"columns": 4, "padding": 12}
        }
    
    def add_row(self) -> 'ResponsiveRow':
        """Add new row to grid"""
        row = ResponsiveRow(self.parent, self.max_columns)
        self.rows.append(row)
        self.current_row = row
        return row
    
    def add_column(self, widget: tk.Widget, span: int = 1, 
                  responsive_spans: Optional[Dict[BreakPoint, int]] = None):
        """Add column to current row"""
        if not self.current_row:
            self.add_row()
        
        return self.current_row.add_column(widget, span, responsive_spans)

class ResponsiveRow:
    """
    Single row in responsive grid
    """
    
    def __init__(self, parent: tk.Widget, max_columns: int):
        self.parent = parent
        self.max_columns = max_columns
        self.columns = []
        
        self.frame = ttk.Frame(parent)
        self.frame.pack(fill=tk.X, pady=2)
    
    def add_column(self, widget: tk.Widget, span: int = 1,
                  responsive_spans: Optional[Dict[BreakPoint, int]] = None):
        """Add column to row"""
        column = ResponsiveColumn(self.frame, widget, span, responsive_spans)
        self.columns.append(column)
        
        # Calculate grid position
        total_span = sum(col.current_span for col in self.columns[:-1])
        column.grid(row=0, column=total_span, columnspan=span, sticky="ew")
        
        return column

class ResponsiveColumn:
    """
    Single column in responsive grid
    """
    
    def __init__(self, parent: tk.Widget, widget: tk.Widget, default_span: int,
                 responsive_spans: Optional[Dict[BreakPoint, int]] = None):
        self.parent = parent
        self.widget = widget
        self.default_span = default_span
        self.responsive_spans = responsive_spans or {}
        self.current_span = default_span
        
        # Place widget in frame
        self.frame = ttk.Frame(parent)
        widget.pack(in_=self.frame, fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def update_span(self, breakpoint: BreakPoint):
        """Update column span for breakpoint"""
        new_span = self.responsive_spans.get(breakpoint, self.default_span)
        if new_span != self.current_span:
            self.current_span = new_span
            self.frame.grid_configure(columnspan=new_span)
    
    def grid(self, **kwargs):
        """Grid the column frame"""
        return self.frame.grid(**kwargs)

class AdaptiveWidget:
    """
    Widget that adapts its properties based on screen size
    """
    
    def __init__(self, widget: tk.Widget):
        self.widget = widget
        self.properties = {
            BreakPoint.SMALL: {},
            BreakPoint.MEDIUM: {},
            BreakPoint.LARGE: {},
            BreakPoint.XLARGE: {}
        }
        self.current_breakpoint = BreakPoint.LARGE
    
    def set_responsive_property(self, breakpoint: BreakPoint, 
                              property_name: str, value: Any):
        """Set property value for specific breakpoint"""
        self.properties[breakpoint][property_name] = value
    
    def set_responsive_font(self, small: tuple, medium: tuple, 
                          large: tuple, xlarge: tuple):
        """Set responsive font sizes"""
        self.set_responsive_property(BreakPoint.SMALL, 'font', small)
        self.set_responsive_property(BreakPoint.MEDIUM, 'font', medium)
        self.set_responsive_property(BreakPoint.LARGE, 'font', large)
        self.set_responsive_property(BreakPoint.XLARGE, 'font', xlarge)
    
    def set_responsive_padding(self, small: int, medium: int, 
                             large: int, xlarge: int):
        """Set responsive padding"""
        self.set_responsive_property(BreakPoint.SMALL, 'padx', small)
        self.set_responsive_property(BreakPoint.SMALL, 'pady', small)
        self.set_responsive_property(BreakPoint.MEDIUM, 'padx', medium)
        self.set_responsive_property(BreakPoint.MEDIUM, 'pady', medium)
        self.set_responsive_property(BreakPoint.LARGE, 'padx', large)
        self.set_responsive_property(BreakPoint.LARGE, 'pady', large)
        self.set_responsive_property(BreakPoint.XLARGE, 'padx', xlarge)
        self.set_responsive_property(BreakPoint.XLARGE, 'pady', xlarge)
    
    def apply_breakpoint(self, breakpoint: BreakPoint):
        """Apply properties for specific breakpoint"""
        if breakpoint != self.current_breakpoint:
            self.current_breakpoint = breakpoint
            properties = self.properties[breakpoint]
            
            for prop, value in properties.items():
                try:
                    if hasattr(self.widget, 'configure'):
                        self.widget.configure(**{prop: value})
                    elif hasattr(self.widget, prop):
                        setattr(self.widget, prop, value)
                except Exception:
                    pass

class ResponsiveNavigation:
    """
    Navigation that adapts between desktop menu and mobile hamburger
    """
    
    def __init__(self, parent: tk.Widget):
        self.parent = parent
        self.items = []
        self.current_mode = LayoutMode.DESKTOP
        
        # Desktop navigation frame
        self.desktop_nav = ttk.Frame(parent)
        
        # Mobile navigation
        self.mobile_nav = ttk.Frame(parent)
        self.hamburger_btn = ttk.Button(
            self.mobile_nav,
            text="☰",
            command=self._toggle_mobile_menu
        )
        self.hamburger_btn.pack(side=tk.LEFT)
        
        # Mobile menu (hidden by default)
        self.mobile_menu = ttk.Frame(parent)
        self.mobile_menu_visible = False
    
    def add_item(self, text: str, command: Callable, icon: str = ""):
        """Add navigation item"""
        item = {
            'text': text,
            'command': command,
            'icon': icon
        }
        self.items.append(item)
        self._rebuild_navigation()
    
    def set_mode(self, mode: LayoutMode):
        """Set navigation mode"""
        if mode != self.current_mode:
            self.current_mode = mode
            self._update_display()
    
    def _rebuild_navigation(self):
        """Rebuild navigation for current mode"""
        if self.current_mode in [LayoutMode.MOBILE, LayoutMode.TABLET]:
            self._build_mobile_nav()
        else:
            self._build_desktop_nav()
    
    def _build_desktop_nav(self):
        """Build desktop navigation"""
        # Clear existing
        for widget in self.desktop_nav.winfo_children():
            widget.destroy()
        
        # Add items as buttons
        for item in self.items:
            btn = ttk.Button(
                self.desktop_nav,
                text=f"{item['icon']} {item['text']}" if item['icon'] else item['text'],
                command=item['command']
            )
            btn.pack(side=tk.LEFT, padx=5)
    
    def _build_mobile_nav(self):
        """Build mobile navigation"""
        # Clear existing mobile menu
        for widget in self.mobile_menu.winfo_children():
            widget.destroy()
        
        # Add items vertically
        for item in self.items:
            btn = ttk.Button(
                self.mobile_menu,
                text=f"{item['icon']} {item['text']}" if item['icon'] else item['text'],
                command=item['command']
            )
            btn.pack(fill=tk.X, pady=2)
    
    def _update_display(self):
        """Update which navigation is displayed"""
        if self.current_mode in [LayoutMode.MOBILE, LayoutMode.TABLET]:
            self.desktop_nav.pack_forget()
            self.mobile_nav.pack(fill=tk.X)
            if self.mobile_menu_visible:
                self.mobile_menu.pack(fill=tk.X)
        else:
            self.mobile_nav.pack_forget()
            self.mobile_menu.pack_forget()
            self.mobile_menu_visible = False
            self.desktop_nav.pack(fill=tk.X)
        
        self._rebuild_navigation()
    
    def _toggle_mobile_menu(self):
        """Toggle mobile menu visibility"""
        if self.mobile_menu_visible:
            self.mobile_menu.pack_forget()
            self.mobile_menu_visible = False
        else:
            self.mobile_menu.pack(fill=tk.X, after=self.mobile_nav)
            self.mobile_menu_visible = True
    
    def pack(self, **kwargs):
        """Pack the navigation"""
        if self.current_mode in [LayoutMode.MOBILE, LayoutMode.TABLET]:
            return self.mobile_nav.pack(**kwargs)
        else:
            return self.desktop_nav.pack(**kwargs)

class ResponsiveManager:
    """
    Global manager for responsive design
    """
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.config = ResponsiveConfig()
        self.current_breakpoint = BreakPoint.LARGE
        self.current_mode = LayoutMode.DESKTOP
        
        # Registered responsive components
        self.components = []
        self.widgets = []
        
        # Bind window resize
        self.root.bind('<Configure>', self._on_window_resize)
        
        # Initial update
        self.root.after(100, self._initial_update)
    
    def _on_window_resize(self, event):
        """Handle window resize events"""
        if event.widget == self.root:
            self._update_responsive_design()
    
    def _initial_update(self):
        """Initial responsive design update"""
        self._update_responsive_design()
    
    def _update_responsive_design(self):
        """Update all responsive components"""
        width = self.root.winfo_width()
        new_breakpoint = self._get_breakpoint(width)
        
        if new_breakpoint != self.current_breakpoint:
            self.current_breakpoint = new_breakpoint
            self.current_mode = self._get_layout_mode(new_breakpoint)
            
            # Update all registered components
            for component in self.components:
                if hasattr(component, 'set_mode'):
                    component.set_mode(self.current_mode)
                elif hasattr(component, 'apply_breakpoint'):
                    component.apply_breakpoint(self.current_breakpoint)
    
    def _get_breakpoint(self, width: int) -> BreakPoint:
        """Get breakpoint for width"""
        if width < self.config.breakpoints[BreakPoint.SMALL]:
            return BreakPoint.SMALL
        elif width < self.config.breakpoints[BreakPoint.MEDIUM]:
            return BreakPoint.MEDIUM
        elif width < self.config.breakpoints[BreakPoint.LARGE]:
            return BreakPoint.LARGE
        else:
            return BreakPoint.XLARGE
    
    def _get_layout_mode(self, breakpoint: BreakPoint) -> LayoutMode:
        """Get layout mode for breakpoint"""
        mapping = {
            BreakPoint.SMALL: LayoutMode.MOBILE,
            BreakPoint.MEDIUM: LayoutMode.TABLET,
            BreakPoint.LARGE: LayoutMode.DESKTOP,
            BreakPoint.XLARGE: LayoutMode.WIDESCREEN
        }
        return mapping.get(breakpoint, LayoutMode.DESKTOP)
    
    def register_component(self, component):
        """Register responsive component"""
        self.components.append(component)
    
    def register_widget(self, widget: AdaptiveWidget):
        """Register adaptive widget"""
        self.widgets.append(widget)
    
    def get_current_breakpoint(self) -> BreakPoint:
        """Get current breakpoint"""
        return self.current_breakpoint
    
    def get_current_mode(self) -> LayoutMode:
        """Get current layout mode"""
        return self.current_mode

# Global responsive manager
_responsive_manager: Optional[ResponsiveManager] = None

def get_responsive_manager() -> Optional[ResponsiveManager]:
    """Get global responsive manager"""
    return _responsive_manager

def init_responsive_design(root: tk.Tk) -> ResponsiveManager:
    """Initialize responsive design for root window"""
    global _responsive_manager
    _responsive_manager = ResponsiveManager(root)
    return _responsive_manager