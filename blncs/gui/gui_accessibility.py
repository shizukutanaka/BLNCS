"""
Modern BLNCS GUI Accessibility Features.

This module provides accessibility management and keyboard navigation
for the BLNCS dashboard GUI.
"""

import tkinter as tk
from tkinter import ttk
from typing import Dict, List, Optional, Any
from .gui_theme import AtlassianTheme

class AccessibilityManager:
    """
    Accessibility manager for keyboard navigation and screen reader support.

    Provides centralized management of keyboard shortcuts, focus management,
    and accessibility features following WCAG guidelines and Atlassian standards.
    """

    def __init__(self, root):
        self.root = root
        self.focus_history = []
        self.shortcuts = {}
        self.focusable_widgets = []

        # Initialize accessibility features
        self._setup_global_shortcuts()
        self._setup_focus_management()

    def _setup_global_shortcuts(self):
        """Set up global keyboard shortcuts."""
        self.shortcuts = {
            '<Control-n>': ('New connection', None),
            '<Control-r>': ('Refresh data', lambda: self._refresh_data()),
            '<Control-,>': ('Open settings', self._show_settings),
            '<F1>': ('Show help', self._show_help),
            '<Control-q>': ('Quit application', lambda: self.root.quit()),
            '<Control-Tab>': ('Next section', self._focus_next_section),
            '<Control-Shift-Tab>': ('Previous section', self._focus_prev_section),
            '<Alt-h>': ('Go to system overview', lambda: self._navigate_to_section("System Overview", self._show_system_overview)),
            '<Alt-l>': ('Go to lightning network', lambda: self._navigate_to_section("Lightning Network", self._show_lightning_network)),
            '<Alt-p>': ('Go to performance', lambda: self._navigate_to_section("Performance", self._show_performance)),
            '<Alt-s>': ('Go to security', lambda: self._navigate_to_section("Security", self._show_security)),
            '<Alt-g>': ('Go to logs', lambda: self._navigate_to_section("Logs", self._show_logs)),
            '<Alt-d>': ('Go to diagnostics', lambda: self._navigate_to_section("Diagnostics", self._show_diagnostics)),
        }

        # Bind global shortcuts
        for shortcut, (description, callback) in self.shortcuts.items():
            if callback:
                self.root.bind(shortcut, callback)

    def _setup_focus_management(self):
        """Set up focus management and indicators."""
        # Configure focus styling
        style = ttk.Style()

        # Focus indicator for buttons
        style.map('TButton',
            relief=[('focus', 'solid')],
            borderwidth=[('focus', 2)]
        )

        # Focus indicator for entries
        style.configure('TEntry',
            borderwidth=1,
            relief='solid'
        )
        style.map('TEntry',
            borderwidth=[('focus', 2)],
            relief=[('focus', 'solid')]
        )

    def _focus_next_section(self, event=None):
        """Move focus to next major section."""
        # This will be implemented when dashboard sections are accessible
        return "break"

    def _focus_prev_section(self, event=None):
        """Move focus to previous major section."""
        # This will be implemented when dashboard sections are accessible
        return "break"

    def register_widget(self, widget, accessible_name=None, description=None):
        """Register a widget for accessibility management."""
        self.focusable_widgets.append(widget)

        # Set accessibility attributes (Tkinter limited support)
        if accessible_name:
            try:
                widget.configure(text=accessible_name)  # For labels/buttons
            except:
                pass  # Widget may not support text attribute

        # Add to focus history when focused
        widget.bind('<FocusIn>', lambda e: self._on_widget_focus(widget))

    def _on_widget_focus(self, widget):
        """Handle widget focus events."""
        if widget not in self.focus_history:
            self.focus_history.append(widget)

        # Keep only last 10 items in history
        if len(self.focus_history) > 10:
            self.focus_history.pop(0)

    def get_focus_history(self):
        """Get the focus history for debugging."""
        return self.focus_history

    def announce_to_screen_reader(self, message, priority='polite'):
        """
        Announce message to screen readers and voice assistants.

        Note: Tkinter has limited screen reader support. In a real application,
        you might use platform-specific APIs or accessibility libraries.
        """
        # For now, we'll use a visual indicator as Tkinter doesn't have
        # built-in screen reader support
        print(f"Screen reader announcement ({priority}): {message}")

        # Try to use platform-specific accessibility features if available
        try:
            if hasattr(self, '_voice_engine'):
                self._voice_engine.say(message)
        except:
            pass

    def setup_voice_support(self):
        """Set up voice support for accessibility."""
        try:
            # Try to initialize voice support (e.g., pyttsx3 or similar)
            import pyttsx3
            self._voice_engine = pyttsx3.init()
            self._voice_engine.setProperty('rate', 150)  # Speaking rate
            self._voice_engine.setProperty('volume', 0.9)  # Volume
            logger.info("Voice support initialized for accessibility")
        except ImportError:
            logger.warning("Voice support not available (pyttsx3 not installed)")
        except Exception as e:
            logger.warning(f"Failed to initialize voice support: {e}")

    def _setup_focus_management(self):
        """Set up enhanced focus management and indicators."""
        # Configure focus styling
        style = ttk.Style()

        # Focus indicator for buttons
        style.map('TButton',
            relief=[('focus', 'solid')],
            borderwidth=[('focus', 2)]
        )

        # Focus indicator for entries
        style.configure('TEntry',
            borderwidth=1,
            relief='solid'
        )
        style.map('TEntry',
            borderwidth=[('focus', 2)],
            relief=[('focus', 'solid')]
        )

        # Enhanced focus ring for better visibility
        self._focus_ring_color = '#FFD700'  # Gold color for focus rings


class FocusRing(tk.Frame):
    """
    Focus ring component for better keyboard navigation visibility.

    Provides a visible focus indicator around interactive elements.
    """

    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)

        self.focused = False
        self.configure(bg=parent.cget('bg'), relief='flat', borderwidth=0)

        # Bind focus events
        self.bind('<FocusIn>', self._on_focus_in)
        self.bind('<FocusOut>', self._on_focus_out)

    def _on_focus_in(self, event):
        """Handle focus in event."""
        self.focused = True
        self.configure(relief='solid', borderwidth=2,
                      highlightbackground=AtlassianTheme.COLORS['primary'],
                      highlightcolor=AtlassianTheme.COLORS['primary'])
        self._redraw_focus_ring()

    def _on_focus_out(self, event):
        """Handle focus out event."""
        self.focused = False
        self.configure(relief='flat', borderwidth=0)
        self._redraw_focus_ring()

    def _redraw_focus_ring(self):
        """Redraw the focus ring."""
        # Force redraw of the widget
        self.update_idletasks()


class AccessibleButton(tk.Button):
    """
    Accessible button with proper labeling and keyboard support.
    """

    def __init__(self, parent, accessible_name=None, shortcut=None, **kwargs):
        super().__init__(parent, **kwargs)

        self.accessible_name = accessible_name or self.cget('text')
        self.shortcut = shortcut

        # Set accessibility attributes
        self.configure(takefocus=True)

        # Bind keyboard activation
        self.bind('<Return>', lambda e: self.invoke())
        self.bind('<space>', lambda e: self.invoke())

        # Add shortcut hint if provided
        if shortcut and self.cget('text'):
            # Could add visual shortcut hint here
            pass


class AccessibleLabel(tk.Label):
    """
    Accessible label with proper labeling support.
    """

    def __init__(self, parent, accessible_name=None, **kwargs):
        super().__init__(parent, **kwargs)

        self.accessible_name = accessible_name or self.cget('text')

        # Labels are typically not focusable but should be associated with controls
        self.configure(takefocus=False)


class AccessibleEntry(tk.Entry):
    """
    Accessible entry field with proper labeling and validation feedback.
    """

    def __init__(self, parent, label=None, help_text=None, **kwargs):
        super().__init__(parent, **kwargs)

        self.label = label
        self.help_text = help_text

        # Configure accessibility
        self.configure(takefocus=True)

        # Bind keyboard navigation
        self.bind('<Tab>', self._on_tab)
        self.bind('<Shift-Tab>', self._on_shift_tab)

    def _on_tab(self, event):
        """Handle Tab key navigation."""
        # Allow default tab behavior
        return None

    def _on_shift_tab(self, event):
        """Handle Shift+Tab navigation."""
        # Allow default shift+tab behavior
        return None


class KeyboardNavigationMixin:
    """
    Mixin class to add keyboard navigation support to widgets.
    """

    def setup_keyboard_navigation(self):
        """Set up keyboard navigation for the widget."""
        # Bind arrow key navigation
        self.bind('<Up>', self._navigate_up)
        self.bind('<Down>', self._navigate_down)
        self.bind('<Left>', self._navigate_left)
        self.bind('<Right>', self._navigate_right)

        # Bind home/end navigation
        self.bind('<Home>', self._navigate_home)
        self.bind('<End>', self._navigate_end)

    def _navigate_up(self, event):
        """Navigate up (to be overridden by subclasses)."""
        return "break"

    def _navigate_down(self, event):
        """Navigate down (to be overridden by subclasses)."""
        return "break"

    def _navigate_left(self, event):
        """Navigate left (to be overridden by subclasses)."""
        return "break"

    def _navigate_right(self, event):
        """Navigate right (to be overridden by subclasses)."""
        return "break"

    def _navigate_home(self, event):
        """Navigate to beginning (to be overridden by subclasses)."""
        return "break"

    def _navigate_end(self, event):
        """Navigate to end (to be overridden by subclasses)."""
        return "break"


class AccessibleSidebar(tk.Frame, KeyboardNavigationMixin):
    """
    Accessible sidebar with keyboard navigation support.
    """

    def __init__(self, parent, nav_buttons=None, **kwargs):
        super().__init__(parent, **kwargs)

        self.nav_buttons = nav_buttons or []
        self.current_focus_index = 0

        # Set up keyboard navigation
        self.setup_keyboard_navigation()
        self.configure(takefocus=True)

    def setup_keyboard_navigation(self):
        """Set up keyboard navigation for sidebar."""
        super().setup_keyboard_navigation()

        # Bind additional navigation keys
        self.bind('<Return>', self._activate_current)
        self.bind('<space>', self._activate_current)

    def _navigate_down(self, event):
        """Navigate to next navigation item."""
        if self.nav_buttons:
            self.current_focus_index = (self.current_focus_index + 1) % len(self.nav_buttons)
            self._focus_current_button()
        return "break"

    def _navigate_up(self, event):
        """Navigate to previous navigation item."""
        if self.nav_buttons:
            self.current_focus_index = (self.current_focus_index - 1) % len(self.nav_buttons)
            self._focus_current_button()
        return "break"

    def _navigate_home(self, event):
        """Navigate to first item."""
        if self.nav_buttons:
            self.current_focus_index = 0
            self._focus_current_button()
        return "break"

    def _navigate_end(self, event):
        """Navigate to last item."""
        if self.nav_buttons:
            self.current_focus_index = len(self.nav_buttons) - 1
            self._focus_current_button()
        return "break"

    def _activate_current(self, event):
        """Activate the currently focused button."""
        if self.nav_buttons and 0 <= self.current_focus_index < len(self.nav_buttons):
            button = self.nav_buttons[self.current_focus_index]
            button.invoke()
        return "break"

    def _focus_current_button(self):
        """Focus the current button."""
        if self.nav_buttons and 0 <= self.current_focus_index < len(self.nav_buttons):
            button = self.nav_buttons[self.current_focus_index]
            button.focus_set()

    def update_nav_buttons(self, buttons):
        """Update the navigation buttons list."""
        self.nav_buttons = buttons
        self.current_focus_index = 0
