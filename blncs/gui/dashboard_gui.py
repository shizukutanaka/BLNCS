"""
Modern BLNCS Dashboard GUI with Atlassian-inspired design.

This module provides a professional, native desktop interface for monitoring
Bitcoin Lightning Network infrastructure with modern UX patterns.
"""

import json
import logging
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, font
import tkinter.font as tkFont
from typing import Dict, List, Optional, Any, Tuple
import queue
import random

# Third-party imports (with fallbacks)
try:
    import requests
except ImportError:
    requests = None

try:
    import websocket
except ImportError:
    websocket = None

# Local imports
# Import from new modular files
from .gui_theme import AtlassianTheme, ModernFrame, apply_atlassian_theme
from .gui_components import (Lozenge, Tag, Banner, StatusIndicator, Flag,
                              MetricCard, Skeleton, LoadingSpinner,
                              ProgressIndicator, ModernTable)
from .gui_accessibility import (AccessibilityManager, FocusRing,
                               AccessibleButton, AccessibleLabel,
                               AccessibleEntry, KeyboardNavigationMixin,
                               AccessibleSidebar)
from .net_utils import network_utils

# Configure logger
logger = logging.getLogger(__name__)


class AtlassianTheme:
    """
    Atlassian Design System inspired color scheme and styling.

    Provides consistent colors, fonts, and spacing following modern
    design principles used in Atlassian products.
    """

    # Color palette (Atlassian-inspired)
    COLORS = {
        # Primary colors
        'primary': '#0052CC',      # Atlassian blue
        'primary_hover': '#0747A6',
        'primary_light': '#DEEBFF',

        # Status colors
        'success': '#36B37E',      # Green
        'success_light': '#E3FCEF',
        'warning': '#FFAB00',      # Yellow
        'warning_light': '#FFFAE6',
        'error': '#DE350B',        # Red
        'error_light': '#FFEBE6',

        # Neutral colors
        'neutral_900': '#091E42',  # Darkest
        'neutral_700': '#253858',
        'neutral_500': '#5E6C84',
        'neutral_300': '#8993A4',
        'neutral_100': '#DFE1E6',  # Light gray
        'neutral_50': '#FAFBFC',   # Off-white
        'neutral_0': '#FFFFFF',    # Pure white

        # Text colors
        'text_primary': '#091E42',
        'text_secondary': '#5E6C84',
        'text_subtle': '#8993A4',
        'text_inverse': '#FFFFFF',

        # Background colors
        'bg_primary': '#FAFBFC',
        'bg_secondary': '#F4F5F7',
        'bg_tertiary': '#DFE1E6',
        'bg_elevated': '#FFFFFF',
    }

    # Typography (Atlassian-inspired font sizes)
    FONTS = {
        'heading_xl': ('Segoe UI', 24, 'bold'),
        'heading_lg': ('Segoe UI', 20, 'bold'),
        'heading_md': ('Segoe UI', 16, 'bold'),
        'heading_sm': ('Segoe UI', 14, 'bold'),
        'body_lg': ('Segoe UI', 16, 'normal'),
        'body_md': ('Segoe UI', 14, 'normal'),
        'body_sm': ('Segoe UI', 12, 'normal'),
        'caption': ('Segoe UI', 11, 'normal'),
        'code': ('Consolas', 12, 'normal'),
        'code_bold': ('Consolas', 12, 'bold'),
        'table_header': ('Segoe UI', 12, 'bold'),
        'table_body': ('Segoe UI', 12, 'normal'),
    }

    # Spacing (8px base unit, Atlassian pattern)
    SPACING = {
        'xs': 4,    # 4px
        'sm': 8,    # 8px
        'md': 16,   # 16px
        'lg': 24,   # 24px
        'xl': 32,   # 32px
        'xxl': 48,  # 48px
    }


class ModernFrame(ttk.Frame):
    """Base frame with Atlassian styling."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.configure(style='Modern.TFrame')

    def create_padded_frame(self, **kwargs):
        """Create a frame with consistent padding."""
        frame = ModernFrame(self, **kwargs)
        frame.pack_configure(padx=AtlassianTheme.SPACING['md'],
                           pady=AtlassianTheme.SPACING['md'])
        return frame


class Lozenge(tk.Frame):
    """
    Atlassian-style lozenge component for status indication and labeling.

    Lozenges are small, rounded containers that highlight status, category,
    or other metadata with consistent styling and color coding.
    """

    def __init__(self, parent, text: str, appearance: str = 'default', **kwargs):
        super().__init__(parent, **kwargs)

        # Configure appearance
        self.appearance = appearance
        self._configure_styling()

        # Create rounded rectangle background
        self.canvas = tk.Canvas(
            self, width=1, height=1,
            highlightthickness=0, bg=self.cget('bg')
        )
        self.canvas.pack(fill='both', expand=True)

        # Text label
        self.text_label = tk.Label(
            self.canvas, text=text,
            font=AtlassianTheme.FONTS['caption'],
            bg=self.bg_color, fg=self.fg_color
        )

        # Bind resize event
        self.bind('<Configure>', self._on_resize)

    def _configure_styling(self):
        """Configure colors and styling based on appearance."""
        color_map = {
            'default': {
                'bg': AtlassianTheme.COLORS['neutral_100'],
                'fg': AtlassianTheme.COLORS['text_secondary']
            },
            'success': {
                'bg': AtlassianTheme.COLORS['success_light'],
                'fg': AtlassianTheme.COLORS['success']
            },
            'warning': {
                'bg': AtlassianTheme.COLORS['warning_light'],
                'fg': AtlassianTheme.COLORS['warning']
            },
            'error': {
                'bg': AtlassianTheme.COLORS['error_light'],
                'fg': AtlassianTheme.COLORS['error']
            },
            'info': {
                'bg': AtlassianTheme.COLORS['primary_light'],
                'fg': AtlassianTheme.COLORS['primary']
            },
            'new': {
                'bg': AtlassianTheme.COLORS['neutral_50'],
                'fg': AtlassianTheme.COLORS['text_secondary']
            }
        }

        colors = color_map.get(self.appearance, color_map['default'])
        self.bg_color = colors['bg']
        self.fg_color = colors['fg']

    def _on_resize(self, event):
        """Handle resize to redraw the rounded background."""
        width = event.width
        height = event.height

        if width <= 1 or height <= 1:
            return

        # Clear canvas
        self.canvas.delete('all')

        # Draw rounded rectangle background
        radius = min(4, height // 2)  # Corner radius

        # Create rounded rectangle
        self.canvas.create_oval(0, 0, radius*2, radius*2,
                               fill=self.bg_color, outline='')
        self.canvas.create_oval(width-radius*2, 0, width, radius*2,
                               fill=self.bg_color, outline='')
        self.canvas.create_oval(0, height-radius*2, radius*2, height,
                               fill=self.bg_color, outline='')
        self.canvas.create_oval(width-radius*2, height-radius*2, width, height,
                               fill=self.bg_color, outline='')

        # Fill center
        self.canvas.create_rectangle(radius, 0, width-radius, height,
                                   fill=self.bg_color, outline='')
        self.canvas.create_rectangle(0, radius, width, height-radius,
                                   fill=self.bg_color, outline='')

        # Position text label
        self.canvas.create_window(width//2, height//2, window=self.text_label)

    def set_text(self, text: str):
        """Update lozenge text."""
        self.text_label.config(text=text)

    def set_appearance(self, appearance: str):
        """Update lozenge appearance."""
        self.appearance = appearance
        self._configure_styling()
        self.text_label.config(bg=self.bg_color, fg=self.fg_color)
        self._on_resize(type('Event', (), {'width': self.winfo_width(), 'height': self.winfo_height()})())


class Tag(tk.Frame):
    """
    Tag component for labeling and categorization.

    Similar to lozenge but with optional remove functionality and
    more flexible styling for content organization.
    """

    def __init__(self, parent, text: str, appearance: str = 'default',
                 removable: bool = False, on_remove=None, **kwargs):
        super().__init__(parent, **kwargs)

        self.appearance = appearance
        self.removable = removable
        self.on_remove = on_remove

        # Configure styling
        self._configure_styling()

        # Main container
        self.configure(bg=self.bg_color)

        # Text label
        self.text_label = tk.Label(
            self, text=text,
            font=AtlassianTheme.FONTS['caption'],
            bg=self.bg_color, fg=self.fg_color,
            padx=AtlassianTheme.SPACING['xs']
        )
        self.text_label.pack(side='left')

        # Remove button if removable
        if removable:
            self.remove_btn = tk.Button(
                self, text='×',
                font=('Arial', 10, 'bold'),
                bg=self.bg_color, fg=self.fg_color,
                relief='flat', borderwidth=0,
                padx=2, pady=0,
                command=self._on_remove_click
            )
            self.remove_btn.pack(side='right')
            self.remove_btn.bind('<Enter>', lambda e: self.remove_btn.config(fg=AtlassianTheme.COLORS['error']))
            self.remove_btn.bind('<Leave>', lambda e: self.remove_btn.config(fg=self.fg_color))

    def _configure_styling(self):
        """Configure tag styling."""
        color_map = {
            'default': {
                'bg': AtlassianTheme.COLORS['neutral_100'],
                'fg': AtlassianTheme.COLORS['text_secondary']
            },
            'success': {
                'bg': AtlassianTheme.COLORS['success_light'],
                'fg': AtlassianTheme.COLORS['success']
            },
            'warning': {
                'bg': AtlassianTheme.COLORS['warning_light'],
                'fg': AtlassianTheme.COLORS['warning']
            },
            'error': {
                'bg': AtlassianTheme.COLORS['error_light'],
                'fg': AtlassianTheme.COLORS['error']
            },
            'info': {
                'bg': AtlassianTheme.COLORS['primary_light'],
                'fg': AtlassianTheme.COLORS['primary']
            }
        }

        colors = color_map.get(self.appearance, color_map['default'])
        self.bg_color = colors['bg']
        self.fg_color = colors['fg']

    def _on_remove_click(self):
        """Handle remove button click."""
        if self.on_remove:
            self.on_remove()
        else:
            self.destroy()

    def set_text(self, text: str):
        """Update tag text."""
        self.text_label.config(text=text)

    def set_appearance(self, appearance: str):
        """Update tag appearance."""
        self.appearance = appearance
        self._configure_styling()
        self.configure(bg=self.bg_color)
        self.text_label.config(bg=self.bg_color, fg=self.fg_color)
        if self.removable:
            self.remove_btn.config(bg=self.bg_color, fg=self.fg_color)


class Banner(tk.Frame):
    """
    Banner component for displaying prominent messages at the top of the screen.

    Banners are used for system-wide announcements, warnings, or important notifications
    that require user attention.
    """

    def __init__(self, parent, message: str, appearance: str = 'info',
                 dismissible: bool = True, on_dismiss=None, **kwargs):
        super().__init__(parent, **kwargs)

        self.appearance = appearance
        self.dismissible = dismissible
        self.on_dismiss = on_dismiss

        # Configure styling
        self._configure_styling()

        # Configure banner background
        self.configure(bg=self.bg_color)

        # Icon based on appearance
        self.icon_label = tk.Label(
            self, text=self._get_icon(),
            font=('Arial', 14, 'bold'),
            bg=self.bg_color, fg=self.icon_color,
            padx=AtlassianTheme.SPACING['sm']
        )
        self.icon_label.pack(side='left')

        # Message text
        self.message_label = tk.Label(
            self, text=message,
            font=AtlassianTheme.FONTS['body_md'],
            bg=self.bg_color, fg=self.fg_color,
            wraplength=600, justify='left'
        )
        self.message_label.pack(side='left', fill='x', expand=True)

        # Dismiss button if dismissible
        if dismissible:
            self.dismiss_btn = tk.Button(
                self, text='×',
                font=('Arial', 16, 'bold'),
                bg=self.bg_color, fg=self.fg_color,
                relief='flat', borderwidth=0,
                padx=AtlassianTheme.SPACING['sm'],
                command=self._on_dismiss
            )
            self.dismiss_btn.pack(side='right')
            self.dismiss_btn.bind('<Enter>', lambda e: self.dismiss_btn.config(bg=self.hover_color))
            self.dismiss_btn.bind('<Leave>', lambda e: self.dismiss_btn.config(bg=self.bg_color))

    def _configure_styling(self):
        """Configure banner styling based on appearance."""
        color_map = {
            'info': {
                'bg': AtlassianTheme.COLORS['primary_light'],
                'fg': AtlassianTheme.COLORS['primary'],
                'icon': AtlassianTheme.COLORS['primary'],
                'hover': '#DEEBFF'
            },
            'success': {
                'bg': AtlassianTheme.COLORS['success_light'],
                'fg': AtlassianTheme.COLORS['success'],
                'icon': AtlassianTheme.COLORS['success'],
                'hover': '#E3FCEF'
            },
            'warning': {
                'bg': AtlassianTheme.COLORS['warning_light'],
                'fg': AtlassianTheme.COLORS['warning'],
                'icon': AtlassianTheme.COLORS['warning'],
                'hover': '#FFFAE6'
            },
            'error': {
                'bg': AtlassianTheme.COLORS['error_light'],
                'fg': AtlassianTheme.COLORS['error'],
                'icon': AtlassianTheme.COLORS['error'],
                'hover': '#FFEBE6'
            }
        }

        colors = color_map.get(self.appearance, color_map['info'])
        self.bg_color = colors['bg']
        self.fg_color = colors['fg']
        self.icon_color = colors['icon']
        self.hover_color = colors['hover']

    def _get_icon(self):
        """Get appropriate icon based on appearance."""
        icons = {
            'info': 'ℹ',
            'success': '✓',
            'warning': '⚠',
            'error': '✗'
        }
        return icons.get(self.appearance, 'ℹ')

    def _on_dismiss(self):
        """Handle dismiss button click."""
        if self.on_dismiss:
            self.on_dismiss()
        self.destroy()

    def set_message(self, message: str):
        """Update banner message."""
        self.message_label.config(text=message)


class StatusIndicator(tk.Frame):
    """A small visual indicator for status (e.g., connected, disconnected)."""
    def __init__(self, parent, size=12, **kwargs):
        super().__init__(parent, **kwargs)
        self.size = size
        self.status = 'unknown'
        self.configure(bg=parent.cget('bg'))
        self.canvas = tk.Canvas(self, width=size, height=size, bg=parent.cget('bg'), highlightthickness=0)
        self.canvas.pack()
        self._draw_indicator()

    def set_status(self, status: str):
        """Update the status and redraw the indicator."""
        self.status = status
        self._draw_indicator()

    def _draw_indicator(self):
        """Draw the indicator circle based on the current status."""
        self.canvas.delete("all")
        color_map = {
            'success': AtlassianTheme.COLORS['success'],
            'warning': AtlassianTheme.COLORS['warning'],
            'error': AtlassianTheme.COLORS['error'],
            'unknown': AtlassianTheme.COLORS['neutral_300']
        }
        color = color_map.get(self.status, AtlassianTheme.COLORS['neutral_300'])
        self.canvas.create_oval(2, 2, self.size-2, self.size-2, fill=color, outline="")


class Flag(tk.Frame):
    """
    Flag component for confirmations, alerts, and acknowledgments.

    Flags are used for notifications that require minimal user interaction
    and are typically displayed using a flag group.
    """

    def __init__(self, parent, title: str, description: str = '',
                 appearance: str = 'info', actions=None, **kwargs):
        super().__init__(parent, **kwargs)

        self.appearance = appearance
        self.actions = actions or []

        # Configure styling
        self._configure_styling()

        # Configure flag background and border
        self.configure(bg=self.bg_color, relief='solid', borderwidth=1)

        # Icon
        self.icon_label = tk.Label(
            self, text=self._get_icon(),
            font=('Arial', 16, 'bold'),
            bg=self.bg_color, fg=self.icon_color
        )
        self.icon_label.pack(side='left', padx=AtlassianTheme.SPACING['md'], pady=AtlassianTheme.SPACING['md'])

        # Content area
        content_frame = tk.Frame(self, bg=self.bg_color)
        content_frame.pack(side='left', fill='both', expand=True, pady=AtlassianTheme.SPACING['md'])

        # Title
        self.title_label = tk.Label(
            content_frame, text=title,
            font=AtlassianTheme.FONTS['body_md'],
            bg=self.bg_color, fg=self.fg_color,
            anchor='w'
        )
        self.title_label.pack(fill='x')

        # Description (if provided)
        if description:
            self.desc_label = tk.Label(
                content_frame, text=description,
                font=AtlassianTheme.FONTS['body_sm'],
                bg=self.bg_color, fg=AtlassianTheme.COLORS['text_secondary'],
                anchor='w', wraplength=400, justify='left'
            )
            self.desc_label.pack(fill='x', pady=(AtlassianTheme.SPACING['xs'], 0))

        # Actions (if provided)
        if self.actions:
            actions_frame = tk.Frame(content_frame, bg=self.bg_color)
            actions_frame.pack(fill='x', pady=(AtlassianTheme.SPACING['sm'], 0))

            for action_text, action_command in self.actions:
                action_btn = tk.Button(
                    actions_frame, text=action_text,
                    font=AtlassianTheme.FONTS['body_sm'],
                    bg=self.bg_color, fg=self.fg_color,
                    relief='flat', borderwidth=0,
                    padx=AtlassianTheme.SPACING['sm'],
                    command=action_command
                )
                action_btn.pack(side='left', padx=(0, AtlassianTheme.SPACING['sm']))

    def _configure_styling(self):
        """Configure flag styling based on appearance."""
        color_map = {
            'info': {
                'bg': AtlassianTheme.COLORS['bg_elevated'],
                'fg': AtlassianTheme.COLORS['text_primary'],
                'icon': AtlassianTheme.COLORS['primary']
            },
            'success': {
                'bg': AtlassianTheme.COLORS['success_light'],
                'fg': AtlassianTheme.COLORS['text_primary'],
                'icon': AtlassianTheme.COLORS['success']
            },
            'warning': {
                'bg': AtlassianTheme.COLORS['warning_light'],
                'fg': AtlassianTheme.COLORS['text_primary'],
                'icon': AtlassianTheme.COLORS['warning']
            },
            'error': {
                'bg': AtlassianTheme.COLORS['error_light'],
                'fg': AtlassianTheme.COLORS['text_primary'],
                'icon': AtlassianTheme.COLORS['error']
            }
        }

        colors = color_map.get(self.appearance, color_map['info'])
        self.bg_color = colors['bg']
        self.fg_color = colors['fg']
        self.icon_color = colors['icon']

    def _get_icon(self):
        """Get appropriate icon based on appearance."""
        icons = {
            'info': 'ℹ',
            'success': '✓',
            'warning': '⚠',
            'error': '✗'
        }
        return icons.get(self.appearance, 'ℹ')


class MetricCard(ModernFrame):
    """
    Modern metric display card with Atlassian styling and sparkline.
    """

    def __init__(self, parent, title: str, **kwargs):
        super().__init__(parent, **kwargs)
        self.configure(padding=AtlassianTheme.SPACING['md'])
        self.history = []
        self.max_history = 50

        # Header
        header_frame = tk.Frame(self, bg=self.cget('background'))
        header_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['sm']))
        title_label = tk.Label(header_frame, text=title, font=AtlassianTheme.FONTS['heading_sm'], fg=AtlassianTheme.COLORS['text_secondary'], bg=self.cget('background'))
        title_label.pack(side='left')
        self.status_lozenge = Lozenge(header_frame, "Unknown", 'default')
        self.status_lozenge.pack(side='right')

        # Value
        self.value_var = tk.StringVar(value='--')
        self.value_label = tk.Label(self, textvariable=self.value_var, font=AtlassianTheme.FONTS['heading_lg'], fg=AtlassianTheme.COLORS['text_primary'], bg=self.cget('background'))
        self.value_label.pack(anchor='w')

        # Sparkline
        self.sparkline_canvas = tk.Canvas(self, height=40, bg=self.cget('background'), highlightthickness=0)
        self.sparkline_canvas.pack(fill='x', pady=(AtlassianTheme.SPACING['sm'], 0))

        # Info area
        self.info_frame = tk.Frame(self, bg=self.cget('background'))
        self.info_frame.pack(fill='x', pady=(AtlassianTheme.SPACING['xs'], 0))

    def update_value(self, value: str, status: str = 'unknown', history_value: Optional[float] = None):
        """Update displayed value, status, and sparkline."""
        self.value_var.set(value)
        self._update_status(status)
        if history_value is not None:
            self.history.append(history_value)
            if len(self.history) > self.max_history:
                self.history.pop(0)
            self._draw_sparkline()

    def _draw_sparkline(self):
        """Draw the sparkline graph based on historical data."""
        self.sparkline_canvas.delete("all")
        if len(self.history) < 2:
            return

        w = self.sparkline_canvas.winfo_width()
        h = self.sparkline_canvas.winfo_height()
        if w <= 1 or h <= 1: # Not visible yet
            self.sparkline_canvas.after(100, self._draw_sparkline)
            return

        max_val = max(self.history) if self.history else 1
        min_val = min(self.history) if self.history else 0
        range_val = max_val - min_val if max_val > min_val else 1

        points = []
        for i, val in enumerate(self.history):
            x = (i / (len(self.history) - 1)) * w
            y = h - ((val - min_val) / range_val) * (h - 4) - 2 # Padding
            points.extend([x, y])

        self.sparkline_canvas.create_line(points, fill=AtlassianTheme.COLORS['primary'], width=2)

    def _update_status(self, status: str):
        """Update status lozenge based on status."""
        status_map = {
            'success': ('Healthy', 'success'),
            'warning': ('Warning', 'warning'),
            'error': ('Error', 'error'),
            'unknown': ('Unknown', 'default'),
            'info': ('Info', 'info')
        }

        text, appearance = status_map.get(status, ('Unknown', 'default'))
        self.status_lozenge.set_text(text)
        self.status_lozenge.set_appearance(appearance)

    def add_tag(self, text: str, appearance: str = 'default'):
        """Add a tag to the card."""
        tag = Tag(self.info_frame, text, appearance)
        tag.pack(side='left', padx=(0, AtlassianTheme.SPACING['xs']))
        return tag


class Skeleton(tk.Frame):
    """
    Skeleton loading component for better perceived performance.

    Shows placeholder content while data is loading, following Atlassian
    design patterns for loading states.
    """

    def __init__(self, parent, width: int = None, height: int = None,
                 shape: str = 'rectangle', **kwargs):
        super().__init__(parent, **kwargs)

        self.shape = shape
        self.width = width or 200
        self.height = height or 20

        # Configure styling
        self.bg_color = AtlassianTheme.COLORS['neutral_100']

        # Create canvas for drawing
        self.canvas = tk.Canvas(
            self, width=self.width, height=self.height,
            highlightthickness=0, bg=self.cget('bg')
        )
        self.canvas.pack(fill='both', expand=True)

        # Start animation
        self._animate()

    def _animate(self):
        """Animate the skeleton loading effect."""
        self.canvas.delete('skeleton')

        # Create gradient effect by drawing multiple rectangles
        for i in range(10):
            alpha = 0.1 + (i * 0.08)  # Gradient from light to darker
            color = self._adjust_brightness(self.bg_color, alpha)

            x1 = (self.width // 10) * i
            x2 = (self.width // 10) * (i + 1)

            if self.shape == 'circle':
                # Draw circular skeleton
                center_x, center_y = self.width // 2, self.height // 2
                radius = min(self.width, self.height) // 2
                self.canvas.create_oval(
                    center_x - radius, center_y - radius,
                    center_x + radius, center_y + radius,
                    fill=color, outline='', tags='skeleton'
                )
            else:
                # Draw rectangular skeleton
                self.canvas.create_rectangle(
                    x1, 0, x2, self.height,
                    fill=color, outline='', tags='skeleton'
                )

        # Schedule next animation frame
        self.after(100, self._animate)

    def _adjust_brightness(self, color: str, factor: float) -> str:
        """Adjust color brightness for gradient effect."""
        # Simple color adjustment - in practice you'd use a proper color library
        if color.startswith('#'):
            try:
                r = int(color[1:3], 16)
                g = int(color[3:5], 16)
                b = int(color[5:7], 16)

                r = min(255, int(r + (255 - r) * factor))
                g = min(255, int(g + (255 - g) * factor))
                b = min(255, int(b + (255 - b) * factor))

                return f'#{r:02x}{g:02x}{b:02x}'
            except ValueError:
                pass

        return color


class LoadingSpinner(tk.Canvas):
    """
    Modern loading spinner component.

    Displays a smooth rotating spinner for loading states.
    """

    def __init__(self, parent, size: int = 32, **kwargs):
        super().__init__(parent, width=size, height=size,
                         highlightthickness=0, **kwargs)

        self.size = size
        self.angle = 0

        # Start animation
        self._animate()

    def _animate(self):
        """Animate the loading spinner."""
        self.delete('spinner')

        center_x, center_y = self.size // 2, self.size // 2
        radius = (self.size - 8) // 2

        # Draw arc segments
        for i in range(8):
            start_angle = self.angle + (i * 45)
            extent = 30  # Arc length

            # Vary opacity based on position
            intensity = 0.3 + (i / 8) * 0.7
            color = self._get_spinner_color(intensity)

            self.create_arc(
                center_x - radius, center_y - radius,
                center_x + radius, center_y + radius,
                start=start_angle, extent=extent,
                fill=color, outline='', tags='spinner'
            )

        # Update angle for next frame
        self.angle = (self.angle + 10) % 360

        # Schedule next animation frame
        self.after(50, self._animate)

    def _get_spinner_color(self, intensity: float) -> str:
        """Get spinner color with varying intensity."""
        base_color = AtlassianTheme.COLORS['primary']
        if base_color.startswith('#'):
            try:
                r = int(base_color[1:3], 16)
                g = int(base_color[3:5], 16)
                b = int(base_color[5:7], 16)

                r = int(r * intensity)
                g = int(g * intensity)
                b = int(b * intensity)

                return f'#{r:02x}{g:02x}{b:02x}'
            except ValueError:
                pass

        return base_color


class ProgressIndicator(tk.Frame):
    """
    Progress indicator component with multiple display modes.

    Shows progress as a bar, circle, or step indicator.
    """

    def __init__(self, parent, mode: str = 'bar', size: int = None, **kwargs):
        super().__init__(parent, **kwargs)

        self.mode = mode  # 'bar', 'circle', 'steps'
        self.size = size or (200 if mode == 'bar' else 60)
        self.progress = 0.0
        self.max_value = 100.0

        if mode == 'circle':
            self._create_circular_indicator()
        elif mode == 'steps':
            self._create_step_indicator()
        else:
            self._create_bar_indicator()

    def _create_bar_indicator(self):
        """Create progress bar indicator."""
        self.canvas = tk.Canvas(
            self, width=self.size, height=8,
            highlightthickness=0, bg=self.cget('bg')
        )
        self.canvas.pack(fill='x', expand=True)

        # Background bar
        self.canvas.create_rectangle(
            0, 0, self.size, 8,
            fill=AtlassianTheme.COLORS['neutral_100'],
            outline='', tags='background'
        )

        # Progress bar
        self.progress_rect = self.canvas.create_rectangle(
            0, 0, 0, 8,
            fill=AtlassianTheme.COLORS['primary'],
            outline='', tags='progress'
        )

    def _create_circular_indicator(self):
        """Create circular progress indicator."""
        self.canvas = tk.Canvas(
            self, width=self.size, height=self.size,
            highlightthickness=0, bg=self.cget('bg')
        )
        self.canvas.pack()

        center_x, center_y = self.size // 2, self.size // 2
        radius = (self.size - 8) // 2

        # Background circle
        self.canvas.create_oval(
            center_x - radius, center_y - radius,
            center_x + radius, center_y + radius,
            outline=AtlassianTheme.COLORS['neutral_100'],
            width=3, tags='background'
        )

        # Progress arc
        self.progress_arc = self.canvas.create_arc(
            center_x - radius, center_y - radius,
            center_x + radius, center_y + radius,
            start=90, extent=0,
            outline=AtlassianTheme.COLORS['primary'],
            width=3, style='arc', tags='progress'
        )

    def _create_step_indicator(self):
        """Create step-based progress indicator."""
        # This would show numbered steps - simplified for now
        self.label = tk.Label(
            self, text="0/0",
            font=AtlassianTheme.FONTS['body_sm'],
            fg=AtlassianTheme.COLORS['text_secondary'],
            bg=self.cget('bg')
        )
        self.label.pack()

    def set_progress(self, value: float, max_value: float = None):
        """Set progress value."""
        if max_value:
            self.max_value = max_value

        self.progress = max(0, min(value, self.max_value))
        percentage = self.progress / self.max_value

        if self.mode == 'bar':
            self._update_bar_progress(percentage)
        elif self.mode == 'circle':
            self._update_circle_progress(percentage)
        elif self.mode == 'steps':
            self._update_step_progress()

    def _update_bar_progress(self, percentage: float):
        """Update progress bar."""
        progress_width = int(self.size * percentage)
        self.canvas.coords(
            self.progress_rect,
            0, 0, progress_width, 8
        )

    def _update_circle_progress(self, percentage: float):
        """Update circular progress."""
        extent = percentage * 360
        self.canvas.itemconfig(self.progress_arc, extent=extent)

    def _update_step_progress(self):
        """Update step progress display."""
        self.label.config(text=f"{int(self.progress)}/{int(self.max_value)}")


class SecurityMonitor(tk.Frame):
    """
    Security monitoring component for risk detection and watchtower functionality.
    """

    def __init__(self, parent, http_session, **kwargs):
        super().__init__(parent, **kwargs)
        self.http_session = http_session
        self.risk_alerts = []
        self.watchtower_status = "Unknown"
        self.configure(bg=parent.cget('bg'))

        # Create security monitoring UI
        self._create_security_ui()

    def _create_security_ui(self):
        """Create the security monitoring interface."""
        # Risk Detection Section
        risk_frame = ModernFrame(self)
        risk_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['md']))

        risk_title = AccessibleLabel(
            risk_frame, text="Risk Detection & Monitoring",
            font=AtlassianTheme.FONTS['heading_md'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=risk_frame.cget('background'),
            accessible_name="Risk Detection Section"
        )
        risk_title.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['sm']))

        # Risk status indicator
        self.risk_status_var = tk.StringVar(value="No active risks")
        self.risk_status_label = tk.Label(
            risk_frame, textvariable=self.risk_status_var,
            font=AtlassianTheme.FONTS['body_sm'],
            fg=AtlassianTheme.COLORS['text_secondary'],
            bg=risk_frame.cget('background')
        )
        self.risk_status_label.pack(anchor='w')

        # Risk alerts list
        self.risk_listbox = tk.Listbox(
            risk_frame,
            height=5,
            font=AtlassianTheme.FONTS['body_sm'],
            bg=AtlassianTheme.COLORS['bg_elevated'],
            fg=AtlassianTheme.COLORS['text_primary'],
            relief='flat',
            borderwidth=1
        )
        self.risk_listbox.pack(fill='x', pady=AtlassianTheme.SPACING['sm'])

        # Risk controls
        risk_btn_frame = tk.Frame(risk_frame, bg=risk_frame.cget('background'))
        risk_btn_frame.pack(fill='x')

        def scan_for_risks():
            """Scan for potential security risks."""
            try:
                response = self.http_session.post(
                    f"{self.parent.base_url}/api/security/scan-risks",
                    timeout=30
                )
                response.raise_for_status()
                risks = response.json().get('risks', [])
                self._update_risk_alerts(risks)
                self._show_alert("Risk scan completed", 'success')
            except Exception as e:
                self._show_alert(f"Risk scan failed: {str(e)}", 'error')

        def clear_risks():
            """Clear all risk alerts."""
            self.risk_alerts = []
            self._update_risk_display()
            self.risk_status_var.set("No active risks")

        scan_btn = AccessibleButton(
            risk_btn_frame, text="Scan for Risks",
            command=scan_for_risks,
            accessible_name="Scan for Security Risks"
        )
        scan_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['warning'],
            relief='flat'
        )
        scan_btn.pack(side='left', padx=(0, AtlassianTheme.SPACING['sm']))

        clear_btn = AccessibleButton(
            risk_btn_frame, text="Clear Alerts",
            command=clear_risks,
            accessible_name="Clear Risk Alerts"
        )
        clear_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=risk_frame.cget('background'),
            relief='flat'
        )
        clear_btn.pack(side='left')

        # Watchtower Section
        wt_frame = ModernFrame(self)
        wt_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['md']))

        wt_title = AccessibleLabel(
            wt_frame, text="Watchtower Protection",
            font=AtlassianTheme.FONTS['heading_md'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=wt_frame.cget('background'),
            accessible_name="Watchtower Section"
        )
        wt_title.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['sm']))

        # Watchtower status
        self.watchtower_status_var = tk.StringVar(value="Checking watchtower status...")
        wt_status_label = tk.Label(
            wt_frame, textvariable=self.watchtower_status_var,
            font=AtlassianTheme.FONTS['body_sm'],
            fg=AtlassianTheme.COLORS['text_secondary'],
            bg=wt_frame.cget('background')
        )
        wt_status_label.pack(anchor='w')

        # Watchtower controls
        wt_btn_frame = tk.Frame(wt_frame, bg=wt_frame.cget('background'))
        wt_btn_frame.pack(fill='x')

        def enable_watchtower():
            """Enable watchtower protection."""
            try:
                response = self.http_session.post(
                    f"{self.parent.base_url}/api/security/watchtower/enable",
                    timeout=30
                )
                response.raise_for_status()
                self.watchtower_status_var.set("Watchtower Enabled")
                self._show_alert("Watchtower enabled successfully", 'success')
            except Exception as e:
                self._show_alert(f"Failed to enable watchtower: {str(e)}", 'error')

        def disable_watchtower():
            """Disable watchtower protection."""
            try:
                response = self.http_session.post(
                    f"{self.parent.base_url}/api/security/watchtower/disable",
                    timeout=30
                )
                response.raise_for_status()
                self.watchtower_status_var.set("Watchtower Disabled")
                self._show_alert("Watchtower disabled successfully", 'success')
            except Exception as e:
                self._show_alert(f"Failed to disable watchtower: {str(e)}", 'error')

        enable_wt_btn = AccessibleButton(
            wt_btn_frame, text="Enable Watchtower",
            command=enable_watchtower,
            accessible_name="Enable Watchtower Protection"
        )
        enable_wt_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['success'],
            relief='flat'
        )
        enable_wt_btn.pack(side='left', padx=(0, AtlassianTheme.SPACING['sm']))

        disable_wt_btn = AccessibleButton(
            wt_btn_frame, text="Disable Watchtower",
            command=disable_watchtower,
            accessible_name="Disable Watchtower Protection"
        )
        disable_wt_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['error'],
            relief='flat'
        )
        disable_wt_btn.pack(side='left')

        # Security Status Overview
        status_frame = ModernFrame(self)
        status_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['md']))

        status_title = AccessibleLabel(
            status_frame, text="Security Status Overview",
            font=AtlassianTheme.FONTS['heading_md'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=status_frame.cget('background'),
            accessible_name="Security Status Section"
        )
        status_title.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['sm']))

        # Status cards in a grid
        status_cards_frame = ModernFrame(status_frame)
        status_cards_frame.pack(fill='x')
        status_cards_frame.columnconfigure(0, weight=1)
        status_cards_frame.columnconfigure(1, weight=1)

        self.security_cards = {}

        # Risk Level Card
        self.security_cards['risk_level'] = MetricCard(status_cards_frame, "Risk Level")
        self.security_cards['risk_level'].grid(row=0, column=0, sticky="ew", padx=(0, AtlassianTheme.SPACING['sm']))
        self.security_cards['risk_level'].update_value("Low", "success")
        self.security_cards['risk_level'].add_tag("PTLCs", 'success')
        self.security_cards['risk_level'].add_tag("Taproot", 'info')

        # Watchtower Status Card
        self.security_cards['watchtower'] = MetricCard(status_cards_frame, "Watchtower")
        self.security_cards['watchtower'].grid(row=0, column=1, sticky="ew")
        self.security_cards['watchtower'].update_value("Active", "success")
        self.security_cards['watchtower'].add_tag("Protection", 'success')
        self.security_cards['watchtower'].add_tag("24/7", 'info')

        # HTLC Monitoring Card
        self.security_cards['htlc_monitor'] = MetricCard(status_cards_frame, "HTLC Monitor")
        self.security_cards['htlc_monitor'].grid(row=1, column=0, sticky="ew", padx=(0, AtlassianTheme.SPACING['sm']))
        self.security_cards['htlc_monitor'].update_value("Active", "success")
        self.security_cards['htlc_monitor'].add_tag("Contracts", 'info')
        self.security_cards['htlc_monitor'].add_tag("Secure", 'success')

        # Mitigation Status Card
        self.security_cards['mitigation'] = MetricCard(status_cards_frame, "Mitigation")
        self.security_cards['mitigation'].grid(row=1, column=1, sticky="ew")
        self.security_cards['mitigation'].update_value("Ready", "success")
        self.security_cards['mitigation'].add_tag("Automated", 'success')
        self.security_cards['mitigation'].add_tag("BOLT 12", 'info')

        # BOLT 12 Privacy Status Card
        self.security_cards['bolt12_privacy'] = MetricCard(status_cards_frame, "BOLT 12 Privacy")
        self.security_cards['bolt12_privacy'].grid(row=2, column=0, sticky="ew", padx=(0, AtlassianTheme.SPACING['sm']))
        self.security_cards['bolt12_privacy'].update_value("Enabled", "success")
        self.security_cards['bolt12_privacy'].add_tag("Privacy", 'success')
        self.security_cards['bolt12_privacy'].add_tag("Enhanced", 'info')

        # Route Privacy Card
        self.security_cards['route_privacy'] = MetricCard(status_cards_frame, "Route Privacy")
        self.security_cards['route_privacy'].grid(row=2, column=1, sticky="ew")
        self.security_cards['route_privacy'].update_value("Protected", "success")
        self.security_cards['route_privacy'].add_tag("PTLCs", 'success')
        self.security_cards['route_privacy'].add_tag("Anonymous", 'info')

    def _update_risk_alerts(self, risks: List[Dict]):
        """Update risk alerts display."""
        self.risk_alerts = risks
        self._update_risk_display()

    def _update_risk_display(self):
        """Update the risk display with current alerts."""
        self.risk_listbox.delete(0, 'end')
        if not self.risk_alerts:
            self.risk_listbox.insert('end', "No risks detected")
            self.risk_status_var.set("No active risks")
        else:
            risk_count = len(self.risk_alerts)
            self.risk_status_var.set(f"{risk_count} active risk{'s' if risk_count != 1 else ''}")
            for risk in self.risk_alerts:
                severity = risk.get('severity', 'medium')
                description = risk.get('description', 'Unknown risk')
                self.risk_listbox.insert('end', f"[{severity.upper()}] {description}")

                # Color code by severity
                if severity == 'high':
                    self.risk_listbox.itemconfig('end', {'fg': AtlassianTheme.COLORS['error']})
                elif severity == 'medium':
                    self.risk_listbox.itemconfig('end', {'fg': AtlassianTheme.COLORS['warning']})
                else:
                    self.risk_listbox.itemconfig('end', {'fg': AtlassianTheme.COLORS['text_secondary']})

    def _show_alert(self, message: str, alert_type: str = 'info'):
        """Show an alert message."""
        # Use the parent dashboard's alert system
        if hasattr(self.parent, '_show_alert'):
            self.parent._show_alert(message, alert_type)
        else:
            print(f"Alert: {message}")


class ModernTable(ttk.Treeview):
    def __init__(self, parent, columns, **kwargs):
        super().__init__(parent, columns=columns, show='headings', **kwargs)

        for col in columns:
            self.heading(col, text=col, anchor='w')
            self.column(col, anchor='w')

    def insert_row(self, values, tags=()):
        """Insert a new row into the table."""
        self.insert('', 'end', values=values, tags=tags)

    def clear_rows(self):
        """Remove all rows from the table."""
        for item in self.get_children():
            self.delete(item)


class TextField(tk.Frame):
    """
    Enhanced text input field with Atlassian-inspired design.

    Provides proper labeling, validation states, and help text.
    """

    def __init__(self, parent, label_text: str, placeholder: str = '',
                 help_text: str = '', required: bool = False,
                 validation_func=None, **kwargs):
        super().__init__(parent, **kwargs)

        self.validation_func = validation_func
        self.is_valid = True

        # Configure styling
        self.configure(bg=parent.cget('bg'))

        # Label with required indicator
        label_frame = tk.Frame(self, bg=self.cget('bg'))
        label_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['xs']))

        self.label = tk.Label(
            label_frame, text=f"{label_text}{' *' if required else ''}",
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=self.cget('bg'), anchor='w'
        )
        self.label.pack(side='left')

        # Input container
        input_frame = tk.Frame(self, bg=self.cget('bg'))
        input_frame.pack(fill='x')

        # Entry field
        self.entry = tk.Entry(
            input_frame,
            font=AtlassianTheme.FONTS['body_md'],
            bg=AtlassianTheme.COLORS['bg_elevated'],
            fg=AtlassianTheme.COLORS['text_primary'],
            relief='solid', borderwidth=1,
            insertbackground=AtlassianTheme.COLORS['text_primary']
        )
        self.entry.pack(fill='x')

        # Placeholder text
        if placeholder:
            self._set_placeholder(placeholder)

        # Validation message
        self.validation_label = tk.Label(
            self, text='',
            font=AtlassianTheme.FONTS['caption'],
            fg=AtlassianTheme.COLORS['error'],
            bg=self.cget('bg'), anchor='w'
        )

        # Help text
        if help_text:
            self.help_label = tk.Label(
                self, text=help_text,
                font=AtlassianTheme.FONTS['caption'],
                fg=AtlassianTheme.COLORS['text_secondary'],
                bg=self.cget('bg'), anchor='w'
            )
            self.help_label.pack(fill='x', pady=(AtlassianTheme.SPACING['xs'], 0))

        # Bind events
        self.entry.bind('<FocusIn>', self._on_focus_in)
        self.entry.bind('<FocusOut>', self._on_focus_out)
        self.entry.bind('<KeyRelease>', self._on_key_release)

    def _set_placeholder(self, placeholder: str):
        """Set placeholder text."""
        self.placeholder = placeholder
        self.placeholder_active = True

        def on_focus_in(event):
            if self.placeholder_active:
                self.entry.delete(0, 'end')
                self.entry.config(fg=AtlassianTheme.COLORS['text_primary'])
                self.placeholder_active = False

        def on_focus_out(event):
            if not self.entry.get().strip():
                self.entry.insert(0, placeholder)
                self.entry.config(fg=AtlassianTheme.COLORS['text_secondary'])
                self.placeholder_active = True

        self.entry.insert(0, placeholder)
        self.entry.config(fg=AtlassianTheme.COLORS['text_secondary'])
        self.entry.bind('<FocusIn>', on_focus_in)
        self.entry.bind('<FocusOut>', on_focus_out)

    def _on_focus_in(self, event):
        """Handle focus in."""
        self._update_border_color('focus')

    def _on_focus_out(self, event):
        """Handle focus out."""
        self._validate()
        self._update_border_color('normal')

    def _on_key_release(self, event):
        """Handle key release for real-time validation."""
        self._validate()

    def _validate(self):
        """Validate input and update UI."""
        if self.validation_func:
            value = self.get_value()
            is_valid, message = self.validation_func(value)

            if is_valid != self.is_valid:
                self.is_valid = is_valid
                self._update_validation_state(message)

    def _update_validation_state(self, message: str = ''):
        """Update validation state and UI."""
        if not self.is_valid:
            self._update_border_color('error')
            self.validation_label.config(text=message)
            self.validation_label.pack(fill='x', pady=(AtlassianTheme.SPACING['xs'], 0))
        else:
            self.validation_label.pack_forget()

    def _update_border_color(self, state: str):
        """Update entry border color based on state."""
        if state == 'error':
            color = AtlassianTheme.COLORS['error']
        elif state == 'focus':
            color = AtlassianTheme.COLORS['primary']
        else:
            color = AtlassianTheme.COLORS['neutral_300']

        # Note: Tkinter Entry doesn't easily support border color changes
        # In a real implementation, you might use a custom widget or styling
        pass

    def get_value(self) -> str:
        """Get the current value."""
        value = self.entry.get()
        if hasattr(self, 'placeholder_active') and self.placeholder_active:
            return ''
        return value

    def set_value(self, value: str):
        """Set the field value."""
        if hasattr(self, 'placeholder_active'):
            if value.strip():
                self.entry.config(fg=AtlassianTheme.COLORS['text_primary'])
                self.placeholder_active = False
            else:
                value = self.placeholder
                self.entry.config(fg=AtlassianTheme.COLORS['text_secondary'])
                self.placeholder_active = True

        self.entry.delete(0, 'end')
        self.entry.insert(0, value)

    def is_field_valid(self) -> bool:
        """Check if field is valid."""
        return self.is_valid


class Form(tk.Frame):
    """
    Form container with validation and submission handling.
    """

    def __init__(self, parent, on_submit=None, on_cancel=None, **kwargs):
        super().__init__(parent, **kwargs)

        self.fields = {}
        self.on_submit = on_submit
        self.on_cancel = on_cancel

        # Form content area
        self.content_frame = tk.Frame(self, bg=self.cget('bg'))
        self.content_frame.pack(fill='both', expand=True, padx=AtlassianTheme.SPACING['md'],
                               pady=AtlassianTheme.SPACING['md'])

        # Button area
        self.button_frame = tk.Frame(self, bg=self.cget('bg'))
        self.button_frame.pack(fill='x', padx=AtlassianTheme.SPACING['md'],
                              pady=(0, AtlassianTheme.SPACING['md']))

        # Submit button
        self.submit_btn = tk.Button(
            self.button_frame, text="Apply",
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['primary'],
            relief='flat', borderwidth=0,
            padx=AtlassianTheme.SPACING['lg'],
            pady=AtlassianTheme.SPACING['sm'],
            command=self._on_submit_click
        )
        self.submit_btn.pack(side='right', padx=(AtlassianTheme.SPACING['sm'], 0))

        # Cancel button
        self.cancel_btn = tk.Button(
            self.button_frame, text="Cancel",
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=self.cget('bg'),
            relief='flat', borderwidth=0,
            padx=AtlassianTheme.SPACING['lg'],
            pady=AtlassianTheme.SPACING['sm'],
            command=self._on_cancel_click
        )
        self.cancel_btn.pack(side='right')

    def add_field(self, name: str, field):
        """Add a field to the form."""
        self.fields[name] = field
        field.pack(fill='x', pady=(0, AtlassianTheme.SPACING['lg']))

    def _on_submit_click(self):
        """Handle submit button click."""
        if self._validate_all_fields():
            if self.on_submit:
                # Collect form data
                data = {name: field.get_value() for name, field in self.fields.items()}
                self.on_submit(data)

    def _on_cancel_click(self):
        """Handle cancel button click."""
        if self.on_cancel:
            self.on_cancel()

    def _validate_all_fields(self) -> bool:
        """Validate all fields and return overall validity."""
        all_valid = True
        for field in self.fields.values():
            if hasattr(field, 'is_field_valid') and not field.is_field_valid():
                all_valid = False
        return all_valid

    def set_submit_enabled(self, enabled: bool):
        """Enable or disable submit button."""
        state = 'normal' if enabled else 'disabled'
        self.submit_btn.config(state=state)


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
        Announce message to screen readers.

        Note: Tkinter has limited screen reader support. In a real application,
        you might use platform-specific APIs or accessibility libraries.
        """
        # For now, we'll use a visual indicator as Tkinter doesn't have
        # built-in screen reader support
        print(f"Screen reader announcement ({priority}): {message}")

    def set_shortcut_callback(self, shortcut, callback):
        """Set callback for a keyboard shortcut."""
        if shortcut in self.shortcuts:
            description, _ = self.shortcuts[shortcut]
            self.shortcuts[shortcut] = (description, callback)
            self.root.bind(shortcut, callback)


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


class EmptyState(tk.Frame):
    """
    Empty state component for when no data is available.

    Provides helpful guidance and actions when content areas are empty,
    following Atlassian design patterns for empty states.
    """

    def __init__(self, parent, title: str, description: str,
                 icon: str = None, actions=None, **kwargs):
        super().__init__(parent, **kwargs)

        self.configure(bg=parent.cget('bg'))

        # Main content container
        content_frame = tk.Frame(self, bg=self.cget('bg'))
        content_frame.pack(expand=True, padx=AtlassianTheme.SPACING['xl'],
                          pady=AtlassianTheme.SPACING['xl'])

        # Icon (optional)
        if icon:
            icon_label = tk.Label(
                content_frame, text=icon,
                font=('Arial', 48),
                fg=AtlassianTheme.COLORS['text_secondary'],
                bg=self.cget('bg')
            )
            icon_label.pack(pady=(0, AtlassianTheme.SPACING['md']))

        # Title
        title_label = tk.Label(
            content_frame, text=title,
            font=AtlassianTheme.FONTS['heading_lg'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=self.cget('bg')
        )
        title_label.pack(pady=(0, AtlassianTheme.SPACING['sm']))

        # Description
        desc_label = tk.Label(
            content_frame, text=description,
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_secondary'],
            bg=self.cget('bg'),
            wraplength=400, justify='center'
        )
        desc_label.pack(pady=(0, AtlassianTheme.SPACING['lg']))

        # Actions (optional)
        if actions:
            actions_frame = tk.Frame(content_frame, bg=self.cget('bg'))
            actions_frame.pack()

            for action_text, action_command in actions:
                action_btn = tk.Button(
                    actions_frame, text=action_text,
                    font=AtlassianTheme.FONTS['body_md'],
                    fg=AtlassianTheme.COLORS['text_inverse'],
                    bg=AtlassianTheme.COLORS['primary'],
                    relief='flat', borderwidth=0,
                    padx=AtlassianTheme.SPACING['lg'],
                    pady=AtlassianTheme.SPACING['sm'],
                    command=action_command
                )
                action_btn.pack(side='left', padx=(0, AtlassianTheme.SPACING['sm']))


class DashboardGUI:
    """
    Modern BLNCS Dashboard with Atlassian-inspired design.

    Provides a professional desktop interface for monitoring Lightning
    infrastructure with real-time updates and intuitive navigation.
    """

    def __init__(self, root: tk.Tk, base_url: str = 'http://localhost:5000'):
        """
        Initialize the dashboard GUI.

        Args:
            root: Tkinter root window
            base_url: Base URL for BLNCS API server
        """
        self.root = root
        self.base_url = base_url.rstrip('/')
        self.poll_interval = 30  # seconds
        self.websocket_thread = None
        self.api_worker_thread = None
        self.websocket_connection = None
        self.http_session = None

        # Data storage
        self.system_data = {}
        self.last_update = 0

        # Queue for thread communication
        self.update_queue = queue.Queue()

        # Banner storage for notifications
        self.active_banners = []

        # Initialize accessibility manager
        self.accessibility = AccessibilityManager(self.root)

        # Configure root window
        self._configure_root()

        # Apply modern styling
        self._apply_atlassian_theme()

        # Create main layout
        self._create_layout()

        # Initialize networking
        self._init_networking()

        # Start background workers
        self._start_workers()

        # Initial data load
        self._load_initial_data()

        logger.info("BLNCS Dashboard GUI initialized with Atlassian design")

    def _configure_root(self):
        """Configure the main window with modern settings."""
        self.root.title("BLNCS Dashboard")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)

        # Modern window styling
        self.root.configure(bg=AtlassianTheme.COLORS['bg_primary'])

        # Configure for high DPI displays
        try:
            self.root.tk.call('tk', 'scaling', 1.2)
        except tk.TclError:
            pass  # Older Tkinter versions

    def _apply_atlassian_theme(self):
        """Apply Atlassian-inspired styling to all widgets."""
        style = ttk.Style()

        # Configure modern frame styling
        style.configure('Modern.TFrame', background=AtlassianTheme.COLORS['bg_elevated'])

        # Configure button styling
        style.configure(
            'Modern.TButton',
            font=AtlassianTheme.FONTS['body_md'],
            padding=(AtlassianTheme.SPACING['md'], AtlassianTheme.SPACING['sm']),
            relief='flat',
            borderwidth=0
        )

        style.map(
            'Modern.TButton',
            background=[('active', AtlassianTheme.COLORS['primary_hover'])],
            relief=[('pressed', 'sunken')]
        )

        # Configure label styling
        style.configure(
            'Modern.TLabel',
            font=AtlassianTheme.FONTS['body_md'],
            background=AtlassianTheme.COLORS['bg_elevated'],
            foreground=AtlassianTheme.COLORS['text_primary']
        )

        # Configure modern scrollbar
        style.configure(
            'Modern.Vertical.TScrollbar',
            background=AtlassianTheme.COLORS['neutral_100'],
            troughcolor=AtlassianTheme.COLORS['bg_secondary'],
            borderwidth=0,
            arrowcolor=AtlassianTheme.COLORS['text_secondary'],
            width=16
        )

        # Configure Treeview (ModernTable) styling
        style.configure("Treeview",
                        background=AtlassianTheme.COLORS['bg_elevated'],
                        foreground=AtlassianTheme.COLORS['text_primary'],
                        fieldbackground=AtlassianTheme.COLORS['bg_elevated'],
                        font=AtlassianTheme.FONTS['table_body'],
                        rowheight=35,
                        borderwidth=0, relief='flat')
        style.configure("Treeview.Heading",
                        background=AtlassianTheme.COLORS['bg_secondary'],
                        foreground=AtlassianTheme.COLORS['text_secondary'],
                        font=AtlassianTheme.FONTS['table_header'],
                        padding=(AtlassianTheme.SPACING['sm'], AtlassianTheme.SPACING['sm']),
                        borderwidth=0, relief='flat')
        style.map("Treeview", background=[('selected', AtlassianTheme.COLORS['primary_light'])])
        style.map("Treeview.Heading", relief=[('active', 'flat')])

    def _create_layout(self):
        """Create the main dashboard layout."""
        # Main container
        self.main_frame = ModernFrame(self.root)
        self.main_frame.pack(fill='both', expand=True, padx=AtlassianTheme.SPACING['md'])

        # Banner area for notifications
        self.banner_frame = tk.Frame(self.main_frame, bg=self.main_frame.cget('background'))
        self.banner_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['sm']))

        # Header bar
        self._create_header()

        # Content area with sidebar and main content
        self._create_content_area()

    def _create_header(self):
        """Create the modern header bar."""
        header_frame = ModernFrame(self.main_frame, height=60)
        header_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['md']))
        header_frame.pack_propagate(False)

        # Left side - Logo and title
        left_frame = tk.Frame(header_frame, bg=header_frame.cget('background'))
        left_frame.pack(side='left', fill='y')

        # Logo/Brand
        brand_label = tk.Label(
            left_frame, text="BLNCS",
            font=AtlassianTheme.FONTS['heading_lg'],
            fg=AtlassianTheme.COLORS['primary'],
            bg=header_frame.cget('background')
        )
        brand_label.pack(side='left', padx=(0, AtlassianTheme.SPACING['md']))

        # Subtitle
        subtitle_label = tk.Label(
            left_frame, text="Bitcoin Lightning Network Control System",
            font=AtlassianTheme.FONTS['body_sm'],
            fg=AtlassianTheme.COLORS['text_secondary'],
            bg=header_frame.cget('background')
        )
        subtitle_label.pack(side='left', anchor='w')

        # Register header elements for accessibility
        self.accessibility.register_widget(brand_label, "BLNCS Dashboard Application")
        self.accessibility.register_widget(subtitle_label, "Bitcoin Lightning Network Control System")

        # Right side - Status and controls
        right_frame = tk.Frame(header_frame, bg=header_frame.cget('background'))
        right_frame.pack(side='right', fill='y')

        # Connection status
        self.connection_indicator = StatusIndicator(right_frame, size=16)
        self.connection_indicator.pack(side='right', padx=(0, AtlassianTheme.SPACING['md']))

        # Connection status text
        self.connection_status = tk.StringVar(value='Disconnected')
        status_label = tk.Label(
            right_frame, textvariable=self.connection_status,
            font=AtlassianTheme.FONTS['body_sm'],
            fg=AtlassianTheme.COLORS['text_secondary'],
            bg=header_frame.cget('background')
        )
        status_label.pack(side='right', padx=(0, AtlassianTheme.SPACING['md']))

        # Settings button
        settings_btn = AccessibleButton(
            right_frame, text='⚙',
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_secondary'],
            bg=header_frame.cget('background'),
            relief='flat', borderwidth=0,
            command=self._show_settings,
            accessible_name="Open Dashboard Settings",
            shortcut="Control-,"
        )
        settings_btn.pack(side='right', padx=(0, AtlassianTheme.SPACING['sm']))

        # Register header controls for accessibility
        self.accessibility.register_widget(self.connection_indicator, "Connection Status Indicator")
        self.accessibility.register_widget(status_label, "Connection Status Text")
        self.accessibility.register_widget(settings_btn, "Open Dashboard Settings")

        # Set up settings shortcut
        self.accessibility.set_shortcut_callback('<Control-,>', self._show_settings)

    def _create_content_area(self):
        """Create the main content area with sidebar and dashboard."""
        # Paned window for resizable layout
        self.paned = ttk.PanedWindow(self.main_frame, orient='horizontal')
        self.paned.pack(fill='both', expand=True)

        # Sidebar
        self.sidebar = self._create_sidebar()
        self.paned.add(self.sidebar, weight=0)

        # Main content area
        self.main_content = self._create_main_content()
        self.paned.add(self.main_content, weight=1)

    def _create_sidebar(self):
        """Create the modern sidebar with navigation."""
        # Use accessible sidebar
        sidebar_frame = AccessibleSidebar(self.paned, width=280)
        sidebar_frame.pack_propagate(False)

        # Sidebar title
        title_label = tk.Label(
            sidebar_frame, text="Dashboard",
            font=AtlassianTheme.FONTS['heading_md'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=sidebar_frame.cget('background')
        )
        title_label.pack(anchor='w', padx=AtlassianTheme.SPACING['md'],
                       pady=(AtlassianTheme.SPACING['lg'], AtlassianTheme.SPACING['md']))

        # Register title for accessibility
        self.accessibility.register_widget(title_label, "Dashboard Navigation")

        # Navigation sections
        self._create_sidebar_sections(sidebar_frame)

        return sidebar_frame

    def _create_sidebar_sections(self, parent):
        """Create sidebar navigation sections with active state management."""
        # Track current active section
        self.active_section = "System Overview"

        sections = [
            ("System Overview", self._show_system_overview, "Alt+H"),
            ("Lightning Network", self._show_lightning_network, "Alt+L"),
            ("Performance", self._show_performance, "Alt+P"),
            ("Security", self._show_security, "Alt+S"),
            ("Logs", self._show_logs, "Alt+G"),
            ("Diagnostics", self._show_diagnostics, "Alt+D"),
        ]

        self.nav_buttons = {}  # Store button references

        for section_name, command, shortcut in sections:
            # Section button container
            btn_frame = tk.Frame(parent, bg=parent.cget('background'))
            btn_frame.pack(fill='x', padx=AtlassianTheme.SPACING['sm'],
                          pady=(0, AtlassianTheme.SPACING['xs']))

            # Create accessible button
            btn = AccessibleButton(
                btn_frame, text=section_name,
                font=AtlassianTheme.FONTS['body_md'],
                fg=AtlassianTheme.COLORS['text_primary'],
                bg=parent.cget('background'),
                relief='flat', borderwidth=0,
                anchor='w', padx=AtlassianTheme.SPACING['md'],
                pady=AtlassianTheme.SPACING['sm'],
                command=lambda s=section_name, c=command: self._navigate_to_section(s, c),
                accessible_name=f"Navigate to {section_name}",
                shortcut=shortcut
            )

            # Bind hover events
            btn.bind('<Enter>', lambda e, b=btn: self._on_nav_hover(b, True))
            btn.bind('<Leave>', lambda e, b=btn: self._on_nav_hover(b, False))

            btn.pack(fill='x')
            self.nav_buttons[section_name] = btn

            # Register button with accessibility manager
            self.accessibility.register_widget(btn, f"Navigate to {section_name}")

            # Set initial active state
            if section_name == self.active_section:
                self._set_active_nav_button(btn, section_name)

        # Update sidebar navigation buttons
        if hasattr(parent, 'update_nav_buttons'):
            parent.update_nav_buttons(list(self.nav_buttons.values()))

        # Set up keyboard shortcuts for navigation
        for section_name, _, shortcut in sections:
            if shortcut:
                self.accessibility.set_shortcut_callback(
                    f'<{shortcut}>',
                    lambda s=section_name, c=command: self._navigate_to_section(s, c)
                )

    def _navigate_to_section(self, section_name: str, command):
        """Navigate to a section and update active state."""
        # Update active section
        old_active = self.active_section
        self.active_section = section_name
        
        # Update button states
        if old_active in self.nav_buttons:
            self._set_inactive_nav_button(self.nav_buttons[old_active])
        if section_name in self.nav_buttons:
            self._set_active_nav_button(self.nav_buttons[section_name], section_name)
        
        # Execute navigation command
        command()

    def _on_nav_hover(self, button, is_hover: bool):
        """Handle navigation button hover effects."""
        if button == self.nav_buttons.get(self.active_section):
            return  # Don't override active state
            
        if is_hover:
            button.configure(
                bg=AtlassianTheme.COLORS['bg_secondary'],
                fg=AtlassianTheme.COLORS['primary']
            )
        else:
            button.configure(
                bg=button.master.cget('background'),
                fg=AtlassianTheme.COLORS['text_primary']
            )

    def _set_active_nav_button(self, button, section_name: str):
        """Set a navigation button as active."""
        button.configure(
            bg=AtlassianTheme.COLORS['primary_light'],
            fg=AtlassianTheme.COLORS['primary']
        )
        
        # Add active indicator (small bar on left)
        if hasattr(button, 'active_indicator'):
            button.active_indicator.destroy()
            
        indicator = tk.Frame(
            button.master,
            bg=AtlassianTheme.COLORS['primary'],
            width=3
        )
        indicator.pack(side='left', fill='y')
        button.active_indicator = indicator
        
        # Move indicator to front
        indicator.lift()

    def _set_inactive_nav_button(self, button):
        """Set a navigation button as inactive."""
        button.configure(
            bg=button.master.cget('background'),
            fg=AtlassianTheme.COLORS['text_primary']
        )
        
        # Remove active indicator
        if hasattr(button, 'active_indicator'):
            button.active_indicator.destroy()
            delattr(button, 'active_indicator')

    def _create_main_content(self):
        """Create the main content area for dashboard views."""
        content_frame = ModernFrame(self.paned)

        # Content container with scrollbar
        self.content_canvas = tk.Canvas(
            content_frame,
            bg=AtlassianTheme.COLORS['bg_secondary'],
            highlightthickness=0
        )
        scrollbar = ttk.Scrollbar(content_frame, orient='vertical',
                                command=self.content_canvas.yview, style='Modern.Vertical.TScrollbar')

        self.content_frame = ModernFrame(self.content_canvas)
        self.content_frame.bind(
            '<Configure>',
            lambda e: self.content_canvas.configure(scrollregion=self.content_canvas.bbox('all'))
        )

        self.content_canvas.create_window((0, 0), window=self.content_frame, anchor='nw')
        self.content_canvas.configure(yscrollcommand=scrollbar.set)

        # Pack scrollable content
        self.content_canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        # Mouse wheel scrolling
        self.content_canvas.bind_all('<MouseWheel>', self._on_mousewheel)

        # Initial view
        self._show_system_overview()

    def _show_security(self):
        """Display the security settings section."""
        self._navigate_to_section("Security", self._show_security_content)

    def _show_security_content(self):
        """Display security settings content."""
        self._clear_content()

        header_label = AccessibleLabel(
            self.content_frame, text="Security Settings",
            font=AtlassianTheme.FONTS['heading_lg'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=self.content_frame.cget('background'),
            accessible_name="Security Settings Section"
        )
        header_label.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['lg']))

        # VLS Settings
        vls_frame = ModernFrame(self.content_frame)
        vls_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['md']))

        vls_title = AccessibleLabel(
            vls_frame, text="Validating Lightning Signer (VLS)",
            font=AtlassianTheme.FONTS['heading_md'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=vls_frame.cget('background'),
            accessible_name="VLS Settings Section"
        )
        vls_title.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['sm']))

        # VLS status
        self.vls_status_var = tk.StringVar(value="Checking...")
        vls_status_label = tk.Label(
            vls_frame, textvariable=self.vls_status_var,
            font=AtlassianTheme.FONTS['body_sm'],
            fg=AtlassianTheme.COLORS['text_secondary'],
            bg=vls_frame.cget('background')
        )
        vls_status_label.pack(anchor='w')

        # VLS controls
        vls_btn_frame = tk.Frame(vls_frame, bg=vls_frame.cget('background'))
        vls_btn_frame.pack(fill='x', pady=AtlassianTheme.SPACING['sm'])

        def enable_vls():
            """Enable VLS for enhanced security."""
            try:
                response = self.http_session.post(
                    f"{self.base_url}/api/security/vls/enable",
                    timeout=30
                )
                response.raise_for_status()
                self.vls_status_var.set("VLS Enabled")
                self._show_alert("VLS enabled successfully", 'success')
            except Exception as e:
                self._show_alert(f"Failed to enable VLS: {str(e)}", 'error')

        def disable_vls():
            """Disable VLS."""
            try:
                response = self.http_session.post(
                    f"{self.base_url}/api/security/vls/disable",
                    timeout=30
                )
                response.raise_for_status()
                self.vls_status_var.set("VLS Disabled")
                self._show_alert("VLS disabled successfully", 'success')
            except Exception as e:
                self._show_alert(f"Failed to disable VLS: {str(e)}", 'error')

        enable_btn = AccessibleButton(
            vls_btn_frame, text="Enable VLS",
            command=enable_vls,
            accessible_name="Enable Validating Lightning Signer"
        )
        enable_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['success'],
            relief='flat'
        )
        enable_btn.pack(side='left', padx=(0, AtlassianTheme.SPACING['sm']))

        disable_btn = AccessibleButton(
            vls_btn_frame, text="Disable VLS",
            command=disable_vls,
            accessible_name="Disable Validating Lightning Signer"
        )
        disable_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['warning'],
            relief='flat'
        )
        disable_btn.pack(side='left')

        # Interoperability Testing
        interop_frame = ModernFrame(tools_frame)
        interop_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['md']))

        interop_title = AccessibleLabel(
            interop_frame, text="Interoperability Testing",
            font=AtlassianTheme.FONTS['heading_md'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=interop_frame.cget('background'),
            accessible_name="Interoperability Testing Section"
        )
        interop_title.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['sm']))

        def run_interop_test():
            """Run interoperability test across different Lightning implementations."""
            try:
                response = self.http_session.post(
                    f"{self.base_url}/api/testing/interoperability",
                    timeout=60
                )
                response.raise_for_status()
                result = response.json()
                self._show_alert(f"Interoperability test completed: {result.get('status', 'Unknown')}", 'success')
            except Exception as e:
                self._show_alert(f"Interoperability test failed: {str(e)}", 'error')

        interop_btn = AccessibleButton(
            interop_frame, text="Run Interop Test",
            command=run_interop_test,
            accessible_name="Run Interoperability Test"
        )
        interop_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['primary'],
            relief='flat'
        )
        # Performance Optimization
        perf_frame = ModernFrame(self.content_frame)
        perf_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['md']))

        perf_title = AccessibleLabel(
            perf_frame, text="Performance Optimization",
            font=AtlassianTheme.FONTS['heading_md'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=perf_frame.cget('background'),
            accessible_name="Performance Optimization Section"
        )
        perf_title.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['sm']))

        perf_btn_frame = tk.Frame(perf_frame, bg=perf_frame.cget('background'))
        perf_btn_frame.pack(fill='x')

        def optimize_performance():
            """Run performance optimization."""
            try:
                response = self.http_session.post(
                    f"{self.base_url}/api/performance/optimize",
                    timeout=30
                )
                response.raise_for_status()
                self._show_alert("Performance optimization completed", 'success')
            except Exception as e:
                self._show_alert(f"Optimization failed: {str(e)}", 'error')

        def clear_cache():
            """Clear system cache."""
            try:
                response = self.http_session.post(
                    f"{self.base_url}/api/performance/clear-cache",
                    timeout=30
                )
                response.raise_for_status()
                self._show_alert("Cache cleared successfully", 'success')
            except Exception as e:
                self._show_alert(f"Cache clear failed: {str(e)}", 'error')

        optimize_btn = AccessibleButton(
            perf_btn_frame, text="Optimize Performance",
            command=optimize_performance,
            accessible_name="Run Performance Optimization"
        )
        optimize_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['primary'],
            relief='flat'
        )
        optimize_btn.pack(side='left', padx=(0, AtlassianTheme.SPACING['sm']))

        cache_btn = AccessibleButton(
            perf_btn_frame, text="Clear Cache",
            command=clear_cache,
            accessible_name="Clear System Cache"
        )
        cache_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['warning'],
            relief='flat'
        )
        cache_btn.pack(side='left')

        # Security Monitoring Section - 新しく追加
        self.security_monitor = SecurityMonitor(self.content_frame, self.http_session)
        self.security_monitor.pack(fill='x', pady=(0, AtlassianTheme.SPACING['md']))

    def _show_system_overview(self):
        """Display the system overview dashboard."""
        self._navigate_to_section("System Overview", self._show_system_overview_content)

    def _show_system_overview_content(self):
        """Display the system overview dashboard content."""
        self._clear_content()

        # Overview header
        header_label = AccessibleLabel(
            self.content_frame, text="System Overview",
            font=AtlassianTheme.FONTS['heading_lg'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=self.content_frame.cget('background'),
            accessible_name="System Overview Section"
        )
        header_label.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['lg']))

        # Empty state (initially hidden)
        self.empty_state_widget = EmptyState(
            self.content_frame,
            title="No data to display",
            description="System metrics are not available yet. Please wait for the connection to be established.",
            icon="📊"
        )
        self.empty_state_widget.pack(fill='both', expand=True)
        self.empty_state_widget.pack_forget() # Hide it initially

        # Metrics cards container
        self.system_cards_frame = ModernFrame(self.content_frame)
        self.system_cards_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['md']))

        # Create grid for metric cards
        self._create_metric_cards_grid(self.system_cards_frame)

        # Initially, show skeleton loaders
        self._show_skeleton_loaders(True)

        # Lightning status section
        lightning_frame = ModernFrame(self.content_frame)
        lightning_frame.pack(fill='x', pady=AtlassianTheme.SPACING['lg'])

        lightning_title = AccessibleLabel(
            lightning_frame, text="Lightning Network Status",
            font=AtlassianTheme.FONTS['heading_md'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=lightning_frame.cget('background'),
            accessible_name="Lightning Network Status Section"
        )
        lightning_title.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['md']))

        # Lightning status cards in a grid
        self.ln_cards_frame = ModernFrame(lightning_frame)
        self.ln_cards_frame.pack(fill='x')
        self.ln_cards_frame.columnconfigure(0, weight=1)
        self.ln_cards_frame.columnconfigure(1, weight=1)

        self.ln_cards = {}

        # Node Status
        self.ln_cards['node_status'] = MetricCard(self.ln_cards_frame, "Node Status")
        self.ln_cards['node_status'].grid(row=0, column=0, sticky="ew", padx=(0, AtlassianTheme.SPACING['sm']))
        self.ln_cards['node_status'].add_tag("Lightning", 'warning')
        self.ln_cards['node_status'].add_tag("Mainnet", 'info')

        # Sustainability Card
        self.ln_cards['sustainability'] = MetricCard(self.ln_cards_frame, "Sustainability")
        self.ln_cards['sustainability'].grid(row=2, column=0, sticky="ew", padx=(0, AtlassianTheme.SPACING['sm']))
        self.ln_cards['sustainability'].add_tag("Green", 'success')
        self.ln_cards['sustainability'].add_tag("Eco", 'info')

        # Predictive Analytics Card
        self.ln_cards['predictive'] = MetricCard(self.ln_cards_frame, "AI Predictions")
        self.ln_cards['predictive'].grid(row=3, column=0, sticky="ew", padx=(0, AtlassianTheme.SPACING['sm']))
        self.ln_cards['predictive'].add_tag("AI", 'primary')
        self.ln_cards['predictive'].add_tag("ML", 'info')

    def _create_metric_cards_grid(self, parent):
        """Create a responsive grid for metric cards."""
        parent.columnconfigure(0, weight=1)
        parent.columnconfigure(1, weight=1)
        parent.columnconfigure(2, weight=1)

        self.system_cards = {}
        self.skeleton_cards = {}

        # Card definitions
        card_defs = {
            'cpu': {"title": "CPU Usage", "tags": [("System", 'info'), ("Real-time", 'success')]},
            'memory': {"title": "Memory Usage", "tags": [("RAM", 'info'), ("Physical", 'default')]},
            'disk': {"title": "Disk Usage", "tags": [("Storage", 'info'), ("SSD", 'success')]},
        }

        # Create MetricCards and Skeletons
        for i, (key, a) in enumerate(card_defs.items()):
            # Create the actual metric card (initially hidden)
            card = MetricCard(parent, a['title'])
            for tag_text, tag_appearance in a['tags']:
                card.add_tag(tag_text, tag_appearance)
            card.grid(row=0, column=i, sticky="ew", padx=(0, AtlassianTheme.SPACING['sm']))
            card.grid_remove()  # Hide it initially
            self.system_cards[key] = card

            # Create the skeleton loader (initially visible)
            skeleton = Skeleton(parent, height=120)
            skeleton.grid(row=0, column=i, sticky="ew", padx=(0, AtlassianTheme.SPACING['sm']))
            self.skeleton_cards[key] = skeleton

    def _show_skeleton_loaders(self, show: bool):
        """Show or hide skeleton loaders for metric cards."""
        for key in self.system_cards:
            if show:
                self.system_cards[key].grid_remove()
                self.skeleton_cards[key].grid()
            else:
                self.skeleton_cards[key].grid_remove()
                self.system_cards[key].grid()

    def _show_diagnostics_content(self):
        """Display diagnostics content."""
        self._clear_content()

        header_label = tk.Label(
            self.content_frame, text="System Diagnostics",
            font=AtlassianTheme.FONTS['heading_lg'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=self.content_frame.cget('background')
        )
        header_label.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['lg']))

        # Diagnostics tools container
        tools_frame = ModernFrame(self.content_frame)
        tools_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['lg']))

        # Network Diagnostics
        network_frame = ModernFrame(tools_frame)
        network_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['md']))

        network_title = AccessibleLabel(
            network_frame, text="Network Diagnostics",
            font=AtlassianTheme.FONTS['heading_md'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=network_frame.cget('background'),
            accessible_name="Network Diagnostics Section"
        )
        network_title.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['sm']))

        # Network test buttons
        network_btn_frame = tk.Frame(network_frame, bg=network_frame.cget('background'))
        network_btn_frame.pack(fill='x')

        def test_api_connection():
            """Test API server connection."""
            try:
                if not self.http_session:
                    raise Exception("HTTP session not initialized")

                response = self.http_session.get(f"{self.base_url}/health", timeout=5)
                if response.status_code == 200:
                    messagebox.showinfo("API Connection Test", "✓ API server connection successful")
                else:
                    messagebox.showwarning("API Connection Test", f"⚠ API server responded with status {response.status_code}")
            except Exception as e:
                messagebox.showerror("API Connection Test", f"✗ API connection failed: {str(e)}")

        def test_websocket_connection():
            """Test WebSocket connection."""
            try:
                if not websocket:
                    raise Exception("WebSocket library not available")

                # Test WebSocket URL construction
                ws_url = network_utils.build_ws_url(self.base_url)
                self._show_alert(f"WebSocket URL: {ws_url}", "info")

                # Note: Actual connection test would require async handling
                messagebox.showinfo("WebSocket Test", f"✓ WebSocket URL constructed: {ws_url}")

            except Exception as e:
                messagebox.showerror("WebSocket Test", f"✗ WebSocket test failed: {str(e)}")

        api_test_btn = AccessibleButton(
            network_btn_frame, text="Test API Connection",
            command=test_api_connection,
            accessible_name="Test API Server Connection"
        )
        api_test_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['primary'],
            relief='flat', borderwidth=0
        )
        api_test_btn.pack(side='left', padx=(0, AtlassianTheme.SPACING['sm']))

        ws_test_btn = AccessibleButton(
            network_btn_frame, text="Test WebSocket",
            command=test_websocket_connection,
            accessible_name="Test WebSocket Connection"
        )
        ws_test_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['primary'],
            relief='flat', borderwidth=0
        )
        ws_test_btn.pack(side='left')

        # Configuration Validation
        config_frame = ModernFrame(tools_frame)
        config_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['md']))

        config_title = AccessibleLabel(
            config_frame, text="Configuration Validation",
            font=AtlassianTheme.FONTS['heading_md'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=config_frame.cget('background'),
            accessible_name="Configuration Validation Section"
        )
        config_title.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['sm']))

        def validate_config():
            """Validate current configuration."""
            try:
                # Import config validation
                from blncs.core.config import get_config

                config = get_config()
                validation_result = config.validate()

                if validation_result['valid']:
                    messagebox.showinfo("Configuration Validation", "✓ All configuration settings are valid")
                else:
                    errors = "\n".join(validation_result.get('errors', []))
                    messagebox.showwarning("Configuration Validation", f"⚠ Configuration issues found:\n{errors}")

            except Exception as e:
                messagebox.showerror("Configuration Validation", f"✗ Validation failed: {str(e)}")

        config_test_btn = AccessibleButton(
            config_frame, text="Validate Configuration",
            command=validate_config,
            accessible_name="Validate Current Configuration"
        )
        config_test_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['success'],
            relief='flat', borderwidth=0
        )
        config_test_btn.pack(anchor='w')

        # System Health Check
        health_frame = ModernFrame(tools_frame)
        health_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['md']))

        health_title = AccessibleLabel(
            health_frame, text="System Health Check",
            font=AtlassianTheme.FONTS['heading_md'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=health_frame.cget('background'),
            accessible_name="System Health Check Section"
        )
        health_title.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['sm']))

        def run_health_check():
            """Run comprehensive health check."""
            try:
                health_results = []

                # Check API health
                try:
                    response = self.http_session.get(f"{self.base_url}/health", timeout=5)
                    if response.status_code == 200:
                        health_results.append("✓ API server is healthy")
                    else:
                        health_results.append(f"⚠ API server responded with status {response.status_code}")
                except Exception as e:
                    health_results.append(f"✗ API server health check failed: {str(e)}")

                # Check database connectivity (if available)
                try:
                    from blncs.core.unified_database import get_database
                    db = get_database()
                    if db.connect():
                        health_results.append("✓ Database connection is healthy")
                        db.disconnect()
                    else:
                        health_results.append("⚠ Database connection failed")
                except Exception as e:
                    health_results.append(f"✗ Database health check failed: {str(e)}")

                # Check memory usage
                try:
                    import psutil
                    memory = psutil.virtual_memory()
                    if memory.percent < 90:
                        health_results.append(f"✓ Memory usage is healthy ({memory.percent:.1f}%)")
                    else:
                        health_results.append(f"⚠ High memory usage ({memory.percent:.1f}%)")
                except ImportError:
                    health_results.append("⚠ Memory monitoring not available (psutil not installed)")
                except Exception as e:
                    health_results.append(f"✗ Memory health check failed: {str(e)}")

                # Display results
                result_text = "\n".join(health_results)
                self._show_health_results(result_text)

            except Exception as e:
                messagebox.showerror("Health Check", f"✗ Health check failed: {str(e)}")

        health_check_btn = AccessibleButton(
            health_frame, text="Run Health Check",
            command=run_health_check,
            accessible_name="Run System Health Check"
        )
        health_check_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['warning'],
            relief='flat', borderwidth=0
        )
        health_check_btn.pack(anchor='w')

        # Results display area
        self.diagnostics_results = tk.Text(
            tools_frame,
            height=10,
            font=AtlassianTheme.FONTS['code'],
            bg=AtlassianTheme.COLORS['neutral_50'],
            fg=AtlassianTheme.COLORS['text_primary'],
            wrap='word',
            state='disabled'
        )

        results_scrollbar = ttk.Scrollbar(tools_frame, command=self.diagnostics_results.yview)
        self.diagnostics_results.configure(yscrollcommand=results_scrollbar.set)

        self.diagnostics_results.pack(fill='x', pady=AtlassianTheme.SPACING['md'])
        results_scrollbar.pack(fill='y')

    def _show_lightning_network(self):
        """Display the Lightning Network channels view."""
        self._clear_content()

        header_label = AccessibleLabel(
            self.content_frame, text="Lightning Network Channels",
            font=AtlassianTheme.FONTS['heading_lg'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=self.content_frame.cget('background'),
            accessible_name="Lightning Network Channels Section"
        )
        header_label.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['lg']))

        table_frame = ModernFrame(self.content_frame)
        table_frame.pack(fill='both', expand=True)

        columns = ('Channel ID', 'Peer', 'Capacity', 'Local Balance', 'Status', 'Commitment Type', 'Taproot', 'Actions')
        self.channel_table = ModernTable(table_frame, columns=columns)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(table_frame, orient='vertical', command=self.channel_table.yview, style='Modern.Vertical.TScrollbar')
        self.channel_table.configure(yscrollcommand=scrollbar.set)

        self.channel_table.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        # Initial data load (will be empty)
        self._update_lightning_channels([])

    def _update_lightning_channels(self, channels: List[Dict[str, Any]]):
        """Update the channels table with new data."""
        if not hasattr(self, 'channel_table') or not self.channel_table.winfo_exists():
            return

        self.channel_table.clear_rows()
        for channel in channels:
            status = channel.get('status', 'unknown').capitalize()
            tags = ()
            if status == 'Active':
                tags = ('success',)
            elif status == 'Inactive':
                tags = ('error',)

    def _update_lightning_metrics(self, ln_info: Dict[str, Any]):
        """Update Lightning Network metric cards."""
        try:
            # Update Node Status
            node_status = "Connected" if ln_info.get('synced_to_chain', False) else "Syncing"
            self.ln_cards['node_status'].update_value(node_status, 'success' if node_status == "Connected" else 'warning')

            # Update Sustainability Metrics
            if 'sustainability' in self.ln_cards:
                energy_consumption = ln_info.get('energy_consumption', {})
                monthly_kwh = energy_consumption.get('monthly_kwh', 0)
                carbon_kg = energy_consumption.get('carbon_footprint_kg', 0)
                sustainability_text = f"{monthly_kwh:.0f} kWh | {carbon_kg:.1f} kg CO2"
                self.ln_cards['sustainability'].update_value(sustainability_text, 'success')

            # Update Predictive Analytics
            if 'predictive' in self.ln_cards:
                predictions = ln_info.get('predictions', {})
                transaction_volume = predictions.get('transaction_volume', {})
                expected = transaction_volume.get('expected', 0)
                confidence = transaction_volume.get('confidence', 0)
                predictive_text = f"{expected:,} tx | {confidence:.0f}% conf"
                self.ln_cards['predictive'].update_value(predictive_text, 'primary')

        except Exception as e:
            logger.error(f"Failed to update Lightning metrics: {e}")

    def _update_channels_table(self, channels: List[Dict[str, Any]]):
        """Update channels table with new data."""
        if not hasattr(self, 'channel_table') or not self.channel_table.winfo_exists():
            return

        self.channel_table.clear_rows()
        for channel in channels:
            status = channel.get('active', False) and "Active" or "Inactive"
            tags = ()
            if status == 'Active':
                tags = ('success',)
            elif status == 'Inactive':
                tags = ('error',)

            # Create splice button
            splice_btn = self._create_splice_button(channel)

            self.channel_table.insert_row([
                channel.get('channel_id', 'N/A'),
                channel.get('peer_alias', 'N/A'),
                f"{channel.get('capacity', 0):,} sats",
                f"{channel.get('local_balance', 0):,} sats",
                status,
                channel.get('commitment_type', 'STATIC_REMOTE_KEY'),
                '✓' if channel.get('is_taproot', False) else '✗',
                splice_btn
            ], tags=tags)

    def _create_splice_button(self, channel: Dict[str, Any]) -> tk.Button:
        """Create a Splice button for the given channel."""
        button = tk.Button(
            self.channel_table,
            text="Splice",
            font=AtlassianTheme.FONTS['body_sm'],
            bg=AtlassianTheme.COLORS['primary'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            relief='flat',
            command=lambda: self._show_splice_dialog(channel)
        )
        button.config(
            activebackground=AtlassianTheme.COLORS['primary_hover'],
            activeforeground=AtlassianTheme.COLORS['text_inverse']
        )
        return button

    def _show_splice_dialog(self, channel: Dict[str, Any]):
        """Show splice dialog for adjusting channel capacity."""
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Splice Channel {channel.get('channel_id', 'N/A')}")
        dialog.geometry("400x300")
        dialog.transient(self.root)

        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() - dialog.winfo_width()) // 2
        y = (dialog.winfo_screenheight() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")

        # Dialog content
        content_frame = ModernFrame(dialog)
        content_frame.pack(fill='both', expand=True, padx=AtlassianTheme.SPACING['md'], pady=AtlassianTheme.SPACING['md'])

        # Current capacity display
        capacity_label = AccessibleLabel(
            content_frame,
            text=f"Current Capacity: {channel.get('capacity', 0):,} sats",
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=content_frame.cget('background')
        )
        capacity_label.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['sm']))

        # New capacity input
        input_frame = ModernFrame(content_frame)
        input_frame.pack(fill='x', pady=AtlassianTheme.SPACING['sm'])

        tk.Label(
            input_frame,
            text="New Capacity (sats):",
            font=AtlassianTheme.FONTS['body_sm'],
            fg=AtlassianTheme.COLORS['text_secondary'],
            bg=input_frame.cget('background')
        ).pack(anchor='w')

        capacity_var = tk.StringVar(value=str(channel.get('capacity', 0)))
        capacity_entry = AccessibleEntry(
            input_frame,
            textvariable=capacity_var,
            font=AtlassianTheme.FONTS['body_md'],
            accessible_name="New channel capacity"
        )
        capacity_entry.pack(fill='x', pady=(AtlassianTheme.SPACING['xs'], 0))

        # Buttons
        button_frame = ModernFrame(content_frame)
        button_frame.pack(fill='x', pady=AtlassianTheme.SPACING['md'])

        def perform_splice():
            """Perform the splice operation."""
            try:
                new_capacity = int(capacity_var.get())
                if new_capacity <= 0:
                    raise ValueError("Capacity must be positive")

                channel_id = channel.get('channel_id')
                if not channel_id:
                    raise ValueError("Invalid channel ID")

                # Call API to perform splice
                self._splice_channel(channel_id, new_capacity)
                dialog.destroy()

            except ValueError as e:
                messagebox.showerror("Invalid Input", str(e))
            except Exception as e:
                messagebox.showerror("Splice Failed", f"Failed to splice channel: {str(e)}")

        splice_btn = AccessibleButton(
            button_frame,
            text="Splice",
            command=perform_splice,
            accessible_name="Perform channel splice operation"
        )
        splice_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['primary'],
            relief='flat'
        )
        splice_btn.pack(side='left')

        cancel_btn = AccessibleButton(
            button_frame,
            text="Cancel",
            command=dialog.destroy,
            accessible_name="Cancel splice operation"
        )
        cancel_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=AtlassianTheme.COLORS['neutral_100'],
            relief='flat'
        )
        cancel_btn.pack(side='right')

        # Focus management
        dialog.focus_set()
        capacity_entry.focus()

    def _splice_channel(self, channel_id: str, new_capacity: int):
        """Perform splice operation via API."""
        try:
            splice_data = {
                'channel_id': channel_id,
                'new_capacity': new_capacity
            }

            response = self.http_session.post(
                f"{self.base_url}/api/lightning/channels/{channel_id}/splice",
                json=splice_data,
                timeout=30
            )
            response.raise_for_status()

            result = response.json()
            if result.get('success'):
                self._show_alert(f"Channel spliced successfully to {new_capacity:,} sats", 'success')
                self._refresh_data()  # Refresh to show updated capacity
            else:
                raise Exception(result.get('error', 'Unknown error'))

        except Exception as e:
            logger.error(f"Splice failed: {e}")
            self._show_alert(f"Splice failed: {str(e)}", 'error')

    def _show_performance(self):
        """Display the performance dashboard content."""
        self._clear_content()

        header_label = AccessibleLabel(
            self.content_frame, text="Performance",
            font=AtlassianTheme.FONTS['heading_lg'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=self.content_frame.cget('background'),
            accessible_name="Performance Section"
        )
        header_label.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['lg']))

        # Diagnostics tools container
        tools_frame = ModernFrame(self.content_frame)
        tools_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['lg']))

        # Network Diagnostics
        network_frame = ModernFrame(tools_frame)
        network_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['md']))

        network_title = AccessibleLabel(
            network_frame, text="Network Diagnostics",
            font=AtlassianTheme.FONTS['heading_md'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=network_frame.cget('background'),
            accessible_name="Network Diagnostics Section"
        )
        network_title.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['sm']))

        # Network test buttons
        network_btn_frame = tk.Frame(network_frame, bg=network_frame.cget('background'))
        network_btn_frame.pack(fill='x')

        def test_api_connection():
            """Test API server connection."""
            try:
                if not self.http_session:
                    raise Exception("HTTP session not initialized")

                response = self.http_session.get(f"{self.base_url}/health", timeout=5)
                if response.status_code == 200:
                    messagebox.showinfo("API Connection Test", "✓ API server connection successful")
                else:
                    messagebox.showwarning("API Connection Test", f"⚠ API server responded with status {response.status_code}")
            except Exception as e:
                messagebox.showerror("API Connection Test", f"✗ API connection failed: {str(e)}")

        def test_websocket_connection():
            """Test WebSocket connection."""
            try:
                if not websocket:
                    raise Exception("WebSocket library not available")

                # Test WebSocket URL construction
                ws_url = network_utils.build_ws_url(self.base_url)
                self._show_alert(f"WebSocket URL: {ws_url}", "info")

                # Note: Actual connection test would require async handling
                messagebox.showinfo("WebSocket Test", f"✓ WebSocket URL constructed: {ws_url}")

            except Exception as e:
                messagebox.showerror("WebSocket Test", f"✗ WebSocket test failed: {str(e)}")

        api_test_btn = AccessibleButton(
            network_btn_frame, text="Test API Connection",
            command=test_api_connection,
            accessible_name="Test API Server Connection"
        )
        api_test_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['primary'],
            relief='flat', borderwidth=0
        )
        api_test_btn.pack(side='left', padx=(0, AtlassianTheme.SPACING['sm']))

        ws_test_btn = AccessibleButton(
            network_btn_frame, text="Test WebSocket",
            command=test_websocket_connection,
            accessible_name="Test WebSocket Connection"
        )
        ws_test_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['primary'],
            relief='flat', borderwidth=0
        )
        ws_test_btn.pack(side='left')

        # Configuration Validation
        config_frame = ModernFrame(tools_frame)
        config_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['md']))

        config_title = AccessibleLabel(
            config_frame, text="Configuration Validation",
            font=AtlassianTheme.FONTS['heading_md'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=config_frame.cget('background'),
            accessible_name="Configuration Validation Section"
        )
        config_title.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['sm']))

        def validate_config():
            """Validate current configuration."""
            try:
                # Import config validation
                from blncs.core.config import get_config

                config = get_config()
                validation_result = config.validate()

                if validation_result['valid']:
                    messagebox.showinfo("Configuration Validation", "✓ All configuration settings are valid")
                else:
                    errors = "\n".join(validation_result.get('errors', []))
                    messagebox.showwarning("Configuration Validation", f"⚠ Configuration issues found:\n{errors}")

            except Exception as e:
                messagebox.showerror("Configuration Validation", f"✗ Validation failed: {str(e)}")

        config_test_btn = AccessibleButton(
            config_frame, text="Validate Configuration",
            command=validate_config,
            accessible_name="Validate Current Configuration"
        )
        config_test_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['success'],
            relief='flat', borderwidth=0
        )
        config_test_btn.pack(anchor='w')

        # System Health Check
        health_frame = ModernFrame(tools_frame)
        health_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['md']))

        health_title = AccessibleLabel(
            health_frame, text="System Health Check",
            font=AtlassianTheme.FONTS['heading_md'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=health_frame.cget('background'),
            accessible_name="System Health Check Section"
        )
        health_title.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['sm']))

        def run_health_check():
            """Run comprehensive health check."""
            try:
                health_results = []

                # Check API health
                try:
                    response = self.http_session.get(f"{self.base_url}/health", timeout=5)
                    if response.status_code == 200:
                        health_results.append("✓ API server is healthy")
                    else:
                        health_results.append(f"⚠ API server responded with status {response.status_code}")
                except Exception as e:
                    health_results.append(f"✗ API server health check failed: {str(e)}")

                # Check database connectivity (if available)
                try:
                    from blncs.core.unified_database import get_database
                    db = get_database()
                    if db.connect():
                        health_results.append("✓ Database connection is healthy")
                        db.disconnect()
                    else:
                        health_results.append("⚠ Database connection failed")
                except Exception as e:
                    health_results.append(f"✗ Database health check failed: {str(e)}")

                # Check memory usage
                try:
                    import psutil
                    memory = psutil.virtual_memory()
                    if memory.percent < 90:
                        health_results.append(f"✓ Memory usage is healthy ({memory.percent:.1f}%)")
                    else:
                        health_results.append(f"⚠ High memory usage ({memory.percent:.1f}%)")
                except ImportError:
                    health_results.append("⚠ Memory monitoring not available (psutil not installed)")
                except Exception as e:
                    health_results.append(f"✗ Memory health check failed: {str(e)}")

                # Display results
                result_text = "\n".join(health_results)
                self._show_health_results(result_text)

            except Exception as e:
                messagebox.showerror("Health Check", f"✗ Health check failed: {str(e)}")

        health_check_btn = AccessibleButton(
            health_frame, text="Run Health Check",
            command=run_health_check,
            accessible_name="Run System Health Check"
        )
        health_check_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['warning'],
            relief='flat', borderwidth=0
        )
        health_check_btn.pack(anchor='w')

        # Results display area
        self.diagnostics_results = tk.Text(
            tools_frame,
            height=10,
            font=AtlassianTheme.FONTS['code'],
            bg=AtlassianTheme.COLORS['neutral_50'],
            fg=AtlassianTheme.COLORS['text_primary'],
            wrap='word',
            state='disabled'
        )

        results_scrollbar = ttk.Scrollbar(tools_frame, command=self.diagnostics_results.yview)
        self.diagnostics_results.configure(yscrollcommand=results_scrollbar.set)

        self.diagnostics_results.pack(fill='x', pady=AtlassianTheme.SPACING['md'])
        results_scrollbar.pack(fill='y')

        # Performance Benchmarking Section - 新しく追加
        benchmark_frame = ModernFrame(tools_frame)
        benchmark_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['md']))

        benchmark_title = AccessibleLabel(
            benchmark_frame, text="Performance Benchmarking",
            font=AtlassianTheme.FONTS['heading_md'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=benchmark_frame.cget('background'),
            accessible_name="Performance Benchmarking Section"
        )
        benchmark_title.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['sm']))

        # Benchmark controls
        benchmark_btn_frame = tk.Frame(benchmark_frame, bg=benchmark_frame.cget('background'))
        benchmark_btn_frame.pack(fill='x')

        def run_cpu_benchmark():
            """Run CPU performance benchmark."""
            try:
                response = self.http_session.post(
                    f"{self.base_url}/api/benchmark/cpu",
                    timeout=60
                )
                response.raise_for_status()
                result = response.json()
                score = result.get('score', 0)
                self._show_alert(f"CPU Benchmark Score: {score}", 'success')
            except Exception as e:
                self._show_alert(f"CPU benchmark failed: {str(e)}", 'error')

        def run_memory_benchmark():
            """Run memory performance benchmark."""
            try:
                response = self.http_session.post(
                    f"{self.base_url}/api/benchmark/memory",
                    timeout=60
                )
                response.raise_for_status()
                result = response.json()
                bandwidth = result.get('bandwidth_mbps', 0)
                self._show_alert(f"Memory Bandwidth: {bandwidth} MB/s", 'success')
            except Exception as e:
                self._show_alert(f"Memory benchmark failed: {str(e)}", 'error')

        def run_io_benchmark():
            """Run I/O performance benchmark."""
            try:
                response = self.http_session.post(
                    f"{self.base_url}/api/benchmark/io",
                    timeout=60
                )
                response.raise_for_status()
                result = response.json()
                read_speed = result.get('read_mbps', 0)
                write_speed = result.get('write_mbps', 0)
                self._show_alert(f"I/O - Read: {read_speed} MB/s, Write: {write_speed} MB/s", 'success')
            except Exception as e:
                self._show_alert(f"I/O benchmark failed: {str(e)}", 'error')

        def run_concurrent_benchmark():
            """Run concurrent processing benchmark."""
            try:
                response = self.http_session.post(
                    f"{self.base_url}/api/benchmark/concurrent",
                    timeout=120
                )
                response.raise_for_status()
                result = response.json()
                throughput = result.get('throughput_tps', 0)
                self._show_alert(f"Concurrent Throughput: {throughput} TPS", 'success')
            except Exception as e:
                self._show_alert(f"Concurrent benchmark failed: {str(e)}", 'error')

        cpu_btn = AccessibleButton(
            benchmark_btn_frame, text="CPU Benchmark",
            command=run_cpu_benchmark,
            accessible_name="Run CPU Performance Benchmark"
        )
        cpu_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['primary'],
            relief='flat'
        )
        cpu_btn.pack(side='left', padx=(0, AtlassianTheme.SPACING['sm']))

        memory_btn = AccessibleButton(
            benchmark_btn_frame, text="Memory Benchmark",
            command=run_memory_benchmark,
            accessible_name="Run Memory Performance Benchmark"
        )
        memory_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['primary'],
            relief='flat'
        )
        memory_btn.pack(side='left', padx=(0, AtlassianTheme.SPACING['sm']))

        io_btn = AccessibleButton(
            benchmark_btn_frame, text="I/O Benchmark",
            command=run_io_benchmark,
            accessible_name="Run I/O Performance Benchmark"
        )
        io_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['primary'],
            relief='flat'
        )
        io_btn.pack(side='left', padx=(0, AtlassianTheme.SPACING['sm']))

        concurrent_btn = AccessibleButton(
            benchmark_btn_frame, text="Concurrent Benchmark",
            command=run_concurrent_benchmark,
            accessible_name="Run Concurrent Processing Benchmark"
        )
        concurrent_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['primary'],
            relief='flat'
        )
        concurrent_btn.pack(side='left')

        # Network Centrality Analysis Section - 新しく追加
        centrality_frame = ModernFrame(tools_frame)
        centrality_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['md']))

        centrality_title = AccessibleLabel(
            centrality_frame, text="Network Centrality Analysis",
            font=AtlassianTheme.FONTS['heading_md'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=centrality_frame.cget('background'),
            accessible_name="Network Centrality Analysis Section"
        )
        centrality_title.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['sm']))

        # Centrality metrics display
        self.centrality_results = tk.Text(
            centrality_frame,
            height=8,
            font=AtlassianTheme.FONTS['code'],
            bg=AtlassianTheme.COLORS['neutral_50'],
            fg=AtlassianTheme.COLORS['text_primary'],
            wrap='word',
            state='disabled'
        )

        centrality_scrollbar = ttk.Scrollbar(centrality_frame, command=self.centrality_results.yview)
        self.centrality_results.configure(yscrollcommand=centrality_scrollbar.set)

        self.centrality_results.pack(fill='x', pady=AtlassianTheme.SPACING['sm'])
        centrality_scrollbar.pack(fill='y')

        # Centrality controls
        centrality_btn_frame = tk.Frame(centrality_frame, bg=centrality_frame.cget('background'))
        centrality_btn_frame.pack(fill='x')

        def analyze_centrality():
            """Analyze Lightning Network centrality metrics."""
            try:
                response = self.http_session.post(
                    f"{self.base_url}/api/analytics/centrality",
                    timeout=60
                )
                response.raise_for_status()
                result = response.json()

                # Display centrality metrics
                self._display_centrality_results(result)
                self._show_alert("Centrality analysis completed", 'success')

            except Exception as e:
                self._show_alert(f"Centrality analysis failed: {str(e)}", 'error')

        def run_decentralization_check():
            """Check network decentralization metrics."""
            try:
                response = self.http_session.post(
                    f"{self.base_url}/api/analytics/decentralization",
                    timeout=60
                )
                response.raise_for_status()
                result = response.json()

                # Update display with decentralization metrics
                self._display_decentralization_results(result)
                self._show_alert("Decentralization check completed", 'success')

            except Exception as e:
                self._show_alert(f"Decentralization check failed: {str(e)}", 'error')

        centrality_btn = AccessibleButton(
            centrality_btn_frame, text="Analyze Centrality",
            command=analyze_centrality,
            accessible_name="Analyze Network Centrality"
        )
        centrality_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['primary'],
            relief='flat'
        )
        centrality_btn.pack(side='left', padx=(0, AtlassianTheme.SPACING['sm']))

        decentralization_btn = AccessibleButton(
            centrality_btn_frame, text="Check Decentralization",
            command=run_decentralization_check,
            accessible_name="Check Network Decentralization"
        )
        decentralization_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['primary'],
            relief='flat'
        )
        decentralization_btn.pack(side='left')

        # GNN Prediction Section - 新しく追加
        gnn_frame = ModernFrame(tools_frame)
        gnn_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['md']))

        gnn_title = AccessibleLabel(
            gnn_frame, text="GNN-Based Predictions",
            font=AtlassianTheme.FONTS['heading_md'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=gnn_frame.cget('background'),
            accessible_name="GNN Prediction Section"
        )
        gnn_title.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['sm']))

        # GNN prediction results display
        self.gnn_results = tk.Text(
            gnn_frame,
            height=6,
            font=AtlassianTheme.FONTS['code'],
            bg=AtlassianTheme.COLORS['neutral_50'],
            fg=AtlassianTheme.COLORS['text_primary'],
            wrap='word',
            state='disabled'
        )

        gnn_scrollbar = ttk.Scrollbar(gnn_frame, command=self.gnn_results.yview)
        self.gnn_results.configure(yscrollcommand=gnn_scrollbar.set)

        self.gnn_results.pack(fill='x', pady=AtlassianTheme.SPACING['sm'])
        gnn_scrollbar.pack(fill='y')

        # GNN controls
        gnn_btn_frame = tk.Frame(gnn_frame, bg=gnn_frame.cget('background'))
        gnn_btn_frame.pack(fill='x')

        def run_tor_prediction():
            """Run Tor node prediction using GNN."""
            try:
                response = self.http_session.post(
                    f"{self.base_url}/api/analytics/gnn/tor-prediction",
                    timeout=120
                )
                response.raise_for_status()
                result = response.json()

                # Display Tor prediction results
                self._display_gnn_tor_results(result)
                self._show_alert("Tor prediction completed", 'success')

            except Exception as e:
                self._show_alert(f"Tor prediction failed: {str(e)}", 'error')

        def run_capacity_prediction():
            """Run channel capacity prediction using GNN."""
            try:
                response = self.http_session.post(
                    f"{self.base_url}/api/analytics/gnn/capacity-prediction",
                    timeout=120
                )
                response.raise_for_status()
                result = response.json()

                # Display capacity prediction results
                self._display_gnn_capacity_results(result)
                self._show_alert("Capacity prediction completed", 'success')

            except Exception as e:
                self._show_alert(f"Capacity prediction failed: {str(e)}", 'error')

        def run_fee_prediction():
            """Run fee prediction using GNN."""
            try:
                response = self.http_session.post(
                    f"{self.base_url}/api/analytics/gnn/fee-prediction",
                    timeout=120
                )
                response.raise_for_status()
                result = response.json()

                # Display fee prediction results
                self._display_gnn_fee_results(result)
                self._show_alert("Fee prediction completed", 'success')

            except Exception as e:
                self._show_alert(f"Fee prediction failed: {str(e)}", 'error')

        tor_btn = AccessibleButton(
            gnn_btn_frame, text="Tor Prediction",
            command=run_tor_prediction,
            accessible_name="Run Tor Node Prediction"
        )
        tor_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['primary'],
            relief='flat'
        )
        tor_btn.pack(side='left', padx=(0, AtlassianTheme.SPACING['sm']))

        capacity_btn = AccessibleButton(
            gnn_btn_frame, text="Capacity Prediction",
            command=run_capacity_prediction,
            accessible_name="Run Channel Capacity Prediction"
        )
        capacity_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['primary'],
            relief='flat'
        )
        capacity_btn.pack(side='left', padx=(0, AtlassianTheme.SPACING['sm']))

        fee_btn = AccessibleButton(
            gnn_btn_frame, text="Fee Prediction",
            command=run_fee_prediction,
            accessible_name="Run Fee Prediction"
        )
        fee_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['primary'],
            relief='flat'
        )
        fee_btn.pack(side='left')
        """Start background worker threads."""
        # API polling thread
        self.api_worker_thread = threading.Thread(
            target=self._api_worker,
            daemon=True,
            name="API-Worker"
        )
        self.api_worker_thread.start()

        # WebSocket thread
        if websocket:
            self.websocket_thread = threading.Thread(
                target=self._websocket_worker,
                daemon=True,
                name="WebSocket-Worker"
            )
            self.websocket_thread.start()

    def _api_worker(self):
        """Background worker for API polling with jittered exponential backoff."""
        backoff_delay = 1
        max_backoff = 60

        while True:
            try:
                self._poll_api_data()

                # Reset backoff on success
                backoff_delay = 1

                # Wait for next poll
                time.sleep(self.poll_interval)

            except Exception as e:
                logger.error(f"API polling error: {e}")

                # Exponential backoff with jitter
                jitter = random.uniform(0.5, 1.5)
                delay = min(backoff_delay * 2 * jitter, max_backoff)
                backoff_delay = delay

                logger.info(f"Retrying API poll in {delay:.1f} seconds")
                time.sleep(delay)

    def _poll_api_data(self):
        """Poll API for current data."""
        if not self.http_session:
            return

        try:
            # Fetch system metrics
            metrics_url = f"{self.base_url}/api/system/metrics"
            metrics_response = self.http_session.get(metrics_url, timeout=10)
            metrics_response.raise_for_status()
            metrics_data = metrics_response.json()

            # Fetch lightning data
            ln_url = f"{self.base_url}/api/lightning/info"
            ln_response = self.http_session.get(ln_url, timeout=10)
            ln_response.raise_for_status()
            ln_info = ln_response.json()

            # Fetch sustainability analytics
            sustainability_url = f"{self.base_url}/api/analytics/sustainability"
            sustainability_response = self.http_session.get(sustainability_url, timeout=10)
            sustainability_response.raise_for_status()
            sustainability_data = sustainability_response.json()

            # Fetch predictive analytics
            predictive_url = f"{self.base_url}/api/analytics/predictive?horizon=24h"
            predictive_response = self.http_session.get(predictive_url, timeout=10)
            predictive_response.raise_for_status()
            predictive_data = predictive_response.json()

            # Fetch blockchain interop analytics
            interop_url = f"{self.base_url}/api/analytics/interop"
            interop_response = self.http_session.get(interop_url, timeout=10)
            interop_response.raise_for_status()
            interop_data = interop_response.json()

            # Queue updates
            if not metrics_data and not ln_info and not channels_data.get('channels', []):
                self.update_queue.put(('show_empty_state', True))
            else:
                self.update_queue.put(('system_metrics', metrics_data))
                self.update_queue.put(('lightning_info', ln_info))
                self.update_queue.put(('lightning_channels', channels_data.get('channels', [])))
                self.update_queue.put(('sustainability_analytics', sustainability_data))
                self.update_queue.put(('predictive_analytics', predictive_data))
                self.update_queue.put(('interop_analytics', interop_data))
                self.last_update = time.time()

            self.update_queue.put(('connection_status', 'Connected'))
            self.update_queue.put(('api_error', None))

        except requests.exceptions.RequestException as e:
            logger.error(f"API poll failed: {e}")
            message, guidance, severity = self._diagnose_api_exception(e)
            self.update_queue.put(('connection_status', 'Disconnected'))
            self.update_queue.put(('api_error', (message, severity)))
            self.update_queue.put(('operator_guidance', (guidance, severity)))
        except Exception as e:
            logger.error(f"An unexpected error occurred during API poll: {e}")
            message, guidance, severity = self._diagnose_api_exception(e)
            self.update_queue.put(('connection_status', 'Error'))
            self.update_queue.put(('api_error', (message, severity)))
            self.update_queue.put(('operator_guidance', (guidance, severity)))

    def _websocket_worker(self):
        """Background worker for WebSocket connection with reconnection logic."""
        if not websocket:
            logger.warning("WebSocket not available, skipping WebSocket worker")
            return

        backoff_delay = 1
        max_backoff = 30

        while True:
            try:
                # Create WebSocket connection
                self.websocket_connection = network_utils.create_websocket_connection(
                    self.websocket_url,
                    enable_trace=False
                )

                # Connect and listen
                self.websocket_connection.connect(self.websocket_url)

                # Reset backoff on successful connection
                backoff_delay = 1

                # Listen for messages
                while True:
                    try:
                        message = self.websocket_connection.recv()
                        if message:
                            data = json.loads(message)
                            self.update_queue.put(('websocket_data', data))

                    except websocket.WebSocketTimeoutException:
                        # Send ping to keep connection alive
                        self.websocket_connection.ping()

                    except websocket.WebSocketConnectionClosedException:
                        logger.info("WebSocket connection closed")
                        break

            except Exception as e:
                logger.error(f"WebSocket error: {e}")

                # Exponential backoff with jitter
                jitter = random.uniform(0.5, 1.5)
                delay = min(backoff_delay * 2 * jitter, max_backoff)
                backoff_delay = delay

                message, guidance, severity = self._diagnose_websocket_exception(e)
                logger.info(f"Reconnecting WebSocket in {delay:.1f} seconds")
                self.update_queue.put(('connection_status', 'Warning'))
                self.update_queue.put(('websocket_banner', (message, severity)))
                self.update_queue.put(('operator_guidance', (guidance, severity)))
                time.sleep(delay)

    def _reconnect_api(self):
        """Reconnect to API with new URL."""
        try:
            # Close existing connections
            if self.websocket_connection and not self.websocket_connection.closed:
                self.websocket_connection.close()

            # Reinitialize networking
            self._init_networking()

            # Restart WebSocket if available
            if websocket and self.websocket_thread and not self.websocket_thread.is_alive():
                self.websocket_thread = threading.Thread(
                    target=self._websocket_worker,
                    daemon=True,
                    name="WebSocket-Worker"
                )
                self.websocket_thread.start()

            logger.info(f"Reconnected to API at: {self.base_url}")

        except Exception as e:
            logger.error(f"Failed to reconnect: {e}")
            self._show_connection_error("Reconnection failed", str(e))

    def _load_initial_data(self):
        """Load initial dashboard data."""
        # Set initial connection status
        self.update_queue.put(('connection_status', 'Connecting'))

        # Show skeletons while loading
        self.root.after(100, lambda: self._show_skeleton_loaders(True))

    def _update_system_metrics(self, data: Dict[str, Any]):
        """Update system metrics display."""
        try:
            self._show_skeleton_loaders(False)

            # Update CPU
            cpu_usage = data.get('cpu_percent')
            if cpu_usage is not None:
                self.system_cards['cpu'].update_value(f"{cpu_usage:.1f}%", 'success' if cpu_usage < 80 else 'warning', history_value=cpu_usage)
            else:
                self.system_cards['cpu'].update_value("--", 'unknown')

            # Update Memory
            memory_info = data.get('memory', {})
            memory_percent = memory_info.get('percent')
            if memory_percent is not None:
                memory_used = memory_info.get('used', 0) / (1024**3)
                memory_total = memory_info.get('total', 0) / (1024**3)
                memory_text = f"{memory_used:.1f}/{memory_total:.1f} GB ({memory_percent:.1f}%)"
                self.system_cards['memory'].update_value(memory_text, 'success' if memory_percent < 85 else 'warning', history_value=memory_percent)
            else:
                self.system_cards['memory'].update_value("--", 'unknown')

            # Update Disk
            disk_info = data.get('disk', {})
            disk_percent = disk_info.get('percent')
            if disk_percent is not None:
                disk_used = disk_info.get('used', 0) / (1024**3)
                disk_total = disk_info.get('total', 0) / (1024**3)
                disk_text = f"{disk_used:.1f}/{disk_total:.1f} GB ({disk_percent:.1f}%)"
                self.system_cards['disk'].update_value(disk_text, 'success' if disk_percent < 90 else 'warning', history_value=disk_percent)
            else:
                self.system_cards['disk'].update_value("--", 'unknown')

        except Exception as e:
            logger.error(f"Failed to update system metrics: {e}")
            self._show_skeleton_loaders(True)

    def _sanitize_input(self, input_string: str) -> str:
        """Sanitize input to prevent XSS and injection attacks."""
        if not input_string:
            return ""

        # Basic sanitization - remove potentially dangerous characters
        import re
        sanitized = re.sub(r'[<>\"\'&]', '', input_string)

        # Limit length to prevent buffer overflow
        return sanitized[:1000]

    def _validate_url(self, url: str) -> bool:
        """Validate URL format and safety."""
        if not url:
            return False

        # Basic URL validation
        import re
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)

        return url_pattern.match(url) is not None

    def _secure_data_handling(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Securely handle sensitive data."""
        if not data:
            return {}

        # Remove or mask sensitive fields
        sensitive_fields = ['password', 'token', 'secret', 'key', 'auth']

        secured_data = {}
        for key, value in data.items():
            if any(sensitive in key.lower() for sensitive in sensitive_fields):
                secured_data[key] = '***MASKED***'
            else:
                secured_data[key] = value

        return secured_data

    def _validate_api_response(self, response_data: Dict[str, Any]) -> bool:
        """Validate API response structure and content."""
        if not response_data:
            return False

        # Basic structure validation
        if not isinstance(response_data, dict):
            logger.warning("API response is not a dictionary")
            return False

        # Check for required fields if needed
        # Add more specific validation as required

        return True

    def _handle_websocket_data(self, data: Dict[str, Any]):
        """Handle real-time data from WebSocket."""
        try:
            message_type = data.get('type')

            if message_type == 'system_update':
                self._update_system_metrics(data.get('data', {}))
            elif message_type == 'sustainability_analytics':
                self._update_sustainability_analytics(data)
            elif message_type == 'predictive_analytics':
                self._update_predictive_analytics(data)
            elif message_type == 'interop_analytics':
                self._update_interop_analytics(data)

        except Exception as e:
            logger.error(f"Failed to handle WebSocket data: {e}")

    def show_banner(self, message: str, appearance: str = 'info', duration: int = None):
        """
        Show a banner notification.

        Args:
            message: Banner message text
            appearance: Banner appearance ('info', 'success', 'warning', 'error')
            duration: Auto-dismiss duration in seconds (None for persistent)
        """
        banner = Banner(
            self.banner_frame, message=message, appearance=appearance,
            on_dismiss=lambda: self._remove_banner(banner)
        )
        banner.pack(fill='x', pady=(0, AtlassianTheme.SPACING['xs']))

        self.active_banners.append(banner)

        # Announce to screen readers
        priority = 'assertive' if appearance in ['error', 'warning'] else 'polite'
        self.accessibility.announce_to_screen_reader(message, priority)

        # Auto-dismiss if duration specified
        if duration:
            self.root.after(duration * 1000, lambda: self._remove_banner(banner))

        return banner

    def _handle_operator_guidance(self, guidance: Optional[str], severity: str):
        if not guidance:
            return
        self.show_flag("Operator guidance required", guidance, appearance=severity)

    def _diagnose_api_exception(self, error: Exception) -> Tuple[str, Optional[str], str]:
        """
        Enhanced API error diagnosis with detailed guidance and logging.
        """
        message = "API request failed"
        guidance = f"Confirm the BLNCS API is reachable at {self.base_url}."
        severity = 'error'
        
        # Log the full error for debugging
        logger.error(f"API exception details: {type(error).__name__}: {str(error)}")
        
        if requests is None:
            logger.error("Requests library not available")
            return message, guidance, severity
        if isinstance(error, requests.exceptions.ConnectTimeout):
            message = "API connection timed out"
            guidance = f"Check connectivity to {self.base_url} and review firewall or proxy rules."
            return message, guidance, severity
        if isinstance(error, requests.exceptions.ReadTimeout):
            message = "API response timed out"
            guidance = "Inspect server load and network path latency, then retry." 
            return message, guidance, severity
        if isinstance(error, requests.exceptions.ConnectionError):
            message = "Unable to reach the API endpoint"
            guidance = f"Ensure the BLNCS API service is running at {self.base_url} and that DNS, routing, and TLS configuration are correct."
            return message, guidance, severity
        if isinstance(error, requests.exceptions.SSLError):
            message = "TLS negotiation with the API failed"
            guidance = "Verify certificate trust stores and confirm the API is presenting the expected certificate chain."
            return message, guidance, severity
        if isinstance(error, requests.exceptions.ProxyError):
            message = "Proxy rejected the API request"
            guidance = "Review the dashboard proxy configuration and NO_PROXY settings."
            return message, guidance, severity
        if isinstance(error, requests.exceptions.HTTPError):
            status_code = error.response.status_code if getattr(error, 'response', None) else 'unknown'
            message = f"API responded with HTTP {status_code}"
            if isinstance(status_code, int) and 500 <= status_code:
                guidance = "Inspect API server logs for faults and restart the service if required."
                severity = 'error'
            elif isinstance(status_code, int) and status_code in (401, 403):
                guidance = "Verify authentication credentials or tokens configured for the dashboard."
                severity = 'error'
            elif isinstance(status_code, int) and 400 <= status_code < 500:
                guidance = "Review API parameters and confirm the requested endpoints are enabled."
                severity = 'warning'
            else:
                guidance = "Review API server telemetry and retry once the service stabilises."
            return message, guidance, severity
        if hasattr(error, 'response') and getattr(error.response, 'status_code', None):
            status_code = error.response.status_code
            message = f"API responded with HTTP {status_code}"
            guidance = "Review API server telemetry and retry once the service stabilises."
            if isinstance(status_code, int) and status_code in (401, 403):
                severity = 'error'
                guidance = "Verify authentication credentials or tokens configured for the dashboard."
            elif isinstance(status_code, int) and status_code >= 500:
                severity = 'error'
                guidance = "Inspect API server logs for faults and restart the service if required."
            elif isinstance(status_code, int) and 400 <= status_code < 500:
                severity = 'warning'
                guidance = "Review API parameters and confirm the requested endpoints are enabled."
            return message, guidance, severity
        fallback = str(error).strip()
        if fallback:
            message = fallback
        return message, guidance, severity

    def _diagnose_websocket_exception(self, error: Exception) -> Tuple[str, Optional[str], str]:
        message = "WebSocket connection failure"
        guidance = f"Confirm the streaming endpoint {self.websocket_url} is reachable."
        severity = 'warning'
        if websocket:
            if isinstance(error, websocket.WebSocketTimeoutException):
                message = "WebSocket heartbeat timed out"
                guidance = "Check network latency and ensure the streaming service is responsive."
                return message, guidance, severity
            if isinstance(error, websocket.WebSocketConnectionClosedException):
                message = "WebSocket connection closed by server"
                guidance = "Inspect API streaming logs and confirm the dashboard channel remains enabled."
                return message, guidance, severity
            if hasattr(websocket, 'WebSocketBadStatusException') and isinstance(error, websocket.WebSocketBadStatusException):
                status_code = getattr(error, 'status_code', 'unknown')
                message = f"WebSocket handshake failed with HTTP {status_code}"
                if isinstance(status_code, int) and status_code in (401, 403):
                    guidance = "Verify authentication headers and proxy forwarding rules for the WebSocket endpoint."
                    severity = 'error'
                elif isinstance(status_code, int) and status_code >= 500:
                    guidance = "Inspect the API streaming service logs and restart if necessary."
                    severity = 'error'
                return message, guidance, severity
        fallback = str(error).strip()
        if fallback:
            message = fallback
        return message, guidance, severity

    def _refresh_data(self):
        """Refresh dashboard data manually."""
        # Trigger immediate data polling
        self._poll_api_data()

        # Announce refresh to screen readers
        self.accessibility.announce_to_screen_reader("Refreshing dashboard data", "polite")

        # Show temporary feedback
        self.show_banner("Refreshing data...", appearance='info', duration=2)

    def _remove_banner(self, banner):
        """Remove a banner from the active banners list."""
        if banner in self.active_banners:
            self.active_banners.remove(banner)
            banner.destroy()

    def show_flag(self, title: str, description: str = '', appearance: str = 'info',
                  actions=None, duration: int = None):
        """
        Show a flag notification.

        Args:
            title: Flag title
            description: Flag description text
            appearance: Flag appearance ('info', 'success', 'warning', 'error')
            actions: List of (text, command) tuples for action buttons
            duration: Auto-dismiss duration in seconds (None for persistent)
        """
        # Create flag window
        flag_window = tk.Toplevel(self.root)
        flag_window.title("BLNCS Notification")
        flag_window.geometry("450x120")
        flag_window.transient(self.root)

        # Center the window
        flag_window.update_idletasks()
        x = (flag_window.winfo_screenwidth() - flag_window.winfo_width()) // 2
        y = (flag_window.winfo_screenheight() - flag_window.winfo_height()) // 2
        flag_window.geometry(f"+{x}+{y}")

        # Create flag component
        flag = Flag(flag_window, title=title, description=description,
                   appearance=appearance, actions=actions)
        flag.pack(fill='both', expand=True, padx=AtlassianTheme.SPACING['md'],
                 pady=AtlassianTheme.SPACING['md'])

        # Auto-close if duration specified
        if duration:
            flag_window.after(duration * 1000, flag_window.destroy)

        return flag_window

    def _show_alert(self, message: str, severity: str = 'info'):
        """Show alert notification using banner component."""
        # Map severity to banner appearance
        appearance_map = {
            'info': 'info',
            'warning': 'warning',
            'error': 'error',
            'success': 'success'
        }
        appearance = appearance_map.get(severity, 'info')

        # Show banner for 10 seconds
        self.show_banner(message, appearance=appearance, duration=10)

    def _add_log_entry(self, log_data: Dict[str, Any]):
        """Add a log entry to the logs view, with color-coding."""
        if not hasattr(self, 'log_text_area') or not self.log_text_area.winfo_exists():
            return

        message = log_data.get('message', '')
        level = log_data.get('level', 'INFO').upper()

        self.log_text_area.configure(state='normal')
        self.log_text_area.insert('end', f"[{level}] {message}\n", level)
        self.log_text_area.configure(state='disabled')
        self.log_text_area.see('end') # Scroll to the bottom

    def _handle_api_error(self, error_message: Optional[str]):
        """Display or clear the API error banner."""
        # Find and remove any existing error banner first
        for banner in self.active_banners[:]:
            if getattr(banner, 'is_api_error', False):
                self._remove_banner(banner)

        if error_message:
            banner = self.show_banner(
                f"API Error: {error_message}",
                appearance='error',
                dismissible=False  # Persistent until cleared
            )
            banner.is_api_error = True # Mark it as a persistent API error banner

    def _show_empty_state(self, show: bool):
        """Show or hide the empty state message."""
        if show:
            # Hide metric cards and show empty state
            if hasattr(self, 'system_cards_frame'):
                self.system_cards_frame.pack_forget()
            if hasattr(self, 'ln_cards_frame'):
                self.ln_cards_frame.pack_forget()
            self.empty_state_widget.pack(fill='both', expand=True)
        else:
            # Show metric cards and hide empty state
            self.empty_state_widget.pack_forget()
            if hasattr(self, 'system_cards_frame'):
                self.system_cards_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['md']))
            if hasattr(self, 'ln_cards_frame'):
                self.ln_cards_frame.pack(fill='x', pady=AtlassianTheme.SPACING['lg'])

    def _show_connection_error(self, title: str, message: str):
        """Show connection error dialog."""
        messagebox.showerror(title, message)

    def _show_settings(self):
        """Display the settings dialog."""
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Settings")
        settings_window.transient(self.root)
        settings_window.grab_set()
        settings_window.geometry("500x250")

        # Center window
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (500 // 2)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (250 // 2)
        settings_window.geometry(f"+<x>+<y>")

        settings_window.configure(bg=AtlassianTheme.COLORS['bg_elevated'])

        form_frame = Form(settings_window, on_submit=lambda data: self._apply_settings(data, settings_window), on_cancel=settings_window.destroy)
        form_frame.pack(fill="both", expand=True)

        # User Preferences
        prefs_frame = ModernFrame(settings_window)
        prefs_frame.pack(fill='x', pady=AtlassianTheme.SPACING['md'])

        prefs_title = AccessibleLabel(
            prefs_frame, text="User Preferences",
            font=AtlassianTheme.FONTS['heading_md'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=prefs_frame.cget('background'),
            accessible_name="User Preferences Section"
        )
        prefs_title.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['sm']))

        # Theme selection
        theme_var = tk.StringVar(value="Atlassian")
        theme_frame = ModernFrame(prefs_frame)
        theme_frame.pack(fill='x', pady=AtlassianTheme.SPACING['sm'])

        tk.Label(
            theme_frame,
            text="Theme:",
            font=AtlassianTheme.FONTS['body_sm'],
            fg=AtlassianTheme.COLORS['text_secondary'],
            bg=theme_frame.cget('background')
        ).pack(anchor='w')

        theme_combo = ttk.Combobox(
            theme_frame,
            textvariable=theme_var,
            values=["Atlassian", "Dark", "Light"],
            state="readonly",
            font=AtlassianTheme.FONTS['body_md']
        )
        theme_combo.pack(fill='x')

        # Language selection
        lang_var = tk.StringVar(value="English")
        lang_frame = ModernFrame(prefs_frame)
        lang_frame.pack(fill='x', pady=AtlassianTheme.SPACING['sm'])

        tk.Label(
            lang_frame,
            text="Language:",
            font=AtlassianTheme.FONTS['body_sm'],
            fg=AtlassianTheme.COLORS['text_secondary'],
            bg=lang_frame.cget('background')
        ).pack(anchor='w')

        lang_combo = ttk.Combobox(
            lang_frame,
            textvariable=lang_var,
            values=["English", "Japanese", "Spanish"],
            state="readonly",
            font=AtlassianTheme.FONTS['body_md']
        )
        lang_combo.pack(fill='x')

        form_frame.add_field("theme", theme_var)
        form_frame.add_field("language", lang_var)

        # Help button for user guide
        help_btn = AccessibleButton(
            prefs_frame, text="User Guide",
            command=self._show_user_guide,
            accessible_name="Show User Guide"
        )
        help_btn.config(
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['primary'],
            relief='flat'
        )
        help_btn.pack(anchor='w', pady=AtlassianTheme.SPACING['md'])

    def _apply_settings(self, data, window):
        """Apply new settings and reconnect."""
        new_base_url = data.get('base_url', '').rstrip('/')
        if new_base_url and new_base_url != self.base_url:
            self.base_url = new_base_url
            logger.info(f"API base URL changed to: {self.base_url}")
            self._reconnect_api()
            self.show_banner("Settings updated. Reconnecting to new API URL...", 'info', duration=5)

        # Apply theme settings
        new_theme = data.get('theme')
        if new_theme:
            self._apply_theme(new_theme)

        # Apply language settings
        new_language = data.get('language')
        if new_language:
            self._apply_language(new_language)

        window.destroy()

    def _apply_theme(self, theme_name: str):
        """Apply the selected theme."""
        if theme_name == "Dark":
            self._apply_dark_theme()
        elif theme_name == "Light":
            self._apply_light_theme()
        else:
            self._apply_atlassian_theme()  # Default

        self.show_banner(f"Theme changed to {theme_name}", 'success', duration=3)

    def _apply_language(self, language: str):
        """Apply the selected language."""
        # Store language preference (for future i18n implementation)
        self.current_language = language
        self.show_banner(f"Language changed to {language}", 'success', duration=3)

    def _apply_dark_theme(self):
        """Apply dark theme colors."""
        AtlassianTheme.COLORS.update({
            'bg_primary': '#1a1a1a',
            'bg_secondary': '#2d2d2d',
            'bg_tertiary': '#404040',
            'bg_elevated': '#1f1f1f',
            'text_primary': '#ffffff',
            'text_secondary': '#cccccc',
            'neutral_100': '#333333',
            'neutral_50': '#1a1a1a',
        })
        self._refresh_ui()

    def _apply_light_theme(self):
        """Apply light theme colors."""
        AtlassianTheme.COLORS.update({
            'bg_primary': '#ffffff',
            'bg_secondary': '#f7f8f9',
            'bg_tertiary': '#dfe1e6',
            'bg_elevated': '#ffffff',
            'text_primary': '#172b4d',
            'text_secondary': '#5e6c84',
            'neutral_100': '#f4f5f7',
            'neutral_50': '#fa fb fc',
        })
        self._refresh_ui()

    def _refresh_ui(self):
        """Refresh the UI with new theme colors."""
        self._apply_atlassian_theme()
        self.root.update_idletasks()

    def _show_help(self):
        """Show keyboard shortcuts and help dialog."""
        help_window = tk.Toplevel(self.root)
        help_window.title("BLNCS Dashboard Help")
        help_window.geometry("600x400")
        help_window.transient(self.root)

        # Center the window
        help_window.update_idletasks()
        x = (help_window.winfo_screenwidth() - help_window.winfo_width()) // 2
        y = (help_window.winfo_screenheight() - help_window.winfo_height()) // 2
        help_window.geometry(f"+{x}+{y}")

        # Create scrollable content
        main_frame = tk.Frame(help_window)
        main_frame.pack(fill='both', expand=True, padx=AtlassianTheme.SPACING['md'],
                       pady=AtlassianTheme.SPACING['md'])

        # Title
        title_label = tk.Label(
            main_frame, text="Keyboard Shortcuts & Help",
            font=AtlassianTheme.FONTS['heading_lg'],
            fg=AtlassianTheme.COLORS['text_primary']
        )
        title_label.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['lg']))

        # Create canvas with scrollbar for content
        canvas = tk.Canvas(main_frame, bg=main_frame.cget('bg'),
                          highlightthickness=0)
        scrollbar = ttk.Scrollbar(main_frame, orient='vertical',
                                command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=main_frame.cget('bg'))

        scrollable_frame.bind(
            '<Configure>',
            lambda e: canvas.configure(scrollregion=canvas.bbox('all'))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor='nw')
        canvas.configure(yscrollcommand=scrollbar.set)

        # Pack scrollable content
        canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        # Mouse wheel scrolling
        canvas.bind_all('<MouseWheel>', lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))

        # Navigation shortcuts section
        nav_frame = tk.Frame(scrollable_frame, bg=scrollable_frame.cget('bg'))
        nav_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['lg']))

        nav_title = tk.Label(
            nav_frame, text="Navigation",
            font=AtlassianTheme.FONTS['heading_md'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=nav_frame.cget('bg')
        )
        nav_title.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['md']))

        navigation_shortcuts = [
            ("Alt+H", "Go to System Overview"),
            ("Alt+L", "Go to Lightning Network"),
            ("Alt+P", "Go to Performance"),
            ("Alt+S", "Go to Security"),
            ("Alt+G", "Go to Logs"),
            ("Alt+D", "Go to Diagnostics"),
            ("Ctrl+Tab", "Next section"),
            ("Ctrl+Shift+Tab", "Previous section"),
        ]

        for shortcut, description in navigation_shortcuts:
            shortcut_frame = tk.Frame(nav_frame, bg=nav_frame.cget('bg'))
            shortcut_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['xs']))

            key_label = tk.Label(
                shortcut_frame, text=shortcut,
                font=AtlassianTheme.FONTS['body_md'],
                fg=AtlassianTheme.COLORS['primary'],
                bg=shortcut_frame.cget('bg')
            )
            key_label.pack(side='left')

            desc_label = tk.Label(
                shortcut_frame, text=description,
                font=AtlassianTheme.FONTS['body_md'],
                fg=AtlassianTheme.COLORS['text_primary'],
                bg=shortcut_frame.cget('bg')
            )
            desc_label.pack(side='left', padx=(AtlassianTheme.SPACING['md'], 0))

        # Accessibility section
        accessibility_frame = tk.Frame(scrollable_frame, bg=scrollable_frame.cget('bg'))
        accessibility_frame.pack(fill='x')

        accessibility_title = tk.Label(
            accessibility_frame, text="Accessibility",
            font=AtlassianTheme.FONTS['heading_md'],
            fg=AtlassianTheme.COLORS['text_primary'],
            bg=accessibility_frame.cget('bg')
        )
        accessibility_title.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['md']))

        accessibility_info = tk.Label(
            accessibility_frame,
            text="This application supports keyboard navigation and screen reader accessibility. " +
                 "Use Tab to navigate between interactive elements, Space or Enter to activate buttons, " +
                 "and arrow keys for navigation within lists and menus.",
            font=AtlassianTheme.FONTS['body_sm'],
            fg=AtlassianTheme.COLORS['text_secondary'],
            bg=accessibility_frame.cget('bg'),
            wraplength=550, justify='left'
        )
        accessibility_info.pack(anchor='w')

        # Close button
        close_btn = tk.Button(
            main_frame, text="Close",
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['primary'],
            relief='flat', borderwidth=0,
            command=help_window.destroy
        )
        close_btn.pack(pady=(AtlassianTheme.SPACING['lg'], 0))

        # Set up help shortcut
        self.accessibility.set_shortcut_callback('<F1>', lambda: self._show_help() if not help_window.winfo_exists() else None)

    def _show_user_guide(self):
        """Show comprehensive user guide."""
        guide_window = tk.Toplevel(self.root)
        guide_window.title("BLNCS User Guide")
        guide_window.geometry("700x500")
        guide_window.transient(self.root)

        # Center the window
        guide_window.update_idletasks()
        x = (guide_window.winfo_screenwidth() - guide_window.winfo_width()) // 2
        y = (guide_window.winfo_screenheight() - guide_window.winfo_height()) // 2
        guide_window.geometry(f"+{x}+{y}")

        # Create scrollable content
        main_frame = tk.Frame(guide_window)
        main_frame.pack(fill='both', expand=True, padx=AtlassianTheme.SPACING['md'],
                       pady=AtlassianTheme.SPACING['md'])

        # Title
        title_label = tk.Label(
            main_frame, text="BLNCS User Guide",
            font=AtlassianTheme.FONTS['heading_lg'],
            fg=AtlassianTheme.COLORS['text_primary']
        )
        title_label.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['lg']))

        # Create canvas with scrollbar for content
        canvas = tk.Canvas(main_frame, bg=main_frame.cget('bg'),
                          highlightthickness=0)
        scrollbar = ttk.Scrollbar(main_frame, orient='vertical',
                                command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=main_frame.cget('bg'))

        scrollable_frame.bind(
            '<Configure>',
            lambda e: canvas.configure(scrollregion=canvas.bbox('all'))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor='nw')
        canvas.configure(yscrollcommand=scrollbar.set)

        # Pack scrollable content
        canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        # Mouse wheel scrolling
        canvas.bind_all('<MouseWheel>', lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))

        # Guide sections
        sections = [
            ("Getting Started", [
                "1. Ensure the BLNCS API server is running on the configured URL.",
                "2. Launch the dashboard GUI using the provided launcher script.",
                "3. The dashboard will automatically connect and display system metrics.",
                "4. Use the sidebar to navigate between different sections."
            ]),
            ("Security Features", [
                "• Risk Detection: Use 'Scan for Risks' to identify potential security issues.",
                "• Watchtower Protection: Enable/disable watchtower for enhanced security.",
                "• BOLT 12 Privacy: Advanced privacy features for Lightning transactions.",
                "• PTLCs & Taproot: Modern security protocols for improved privacy."
            ]),
            ("Performance Monitoring", [
                "• CPU, Memory, I/O Benchmarks: Run performance tests to evaluate system efficiency.",
                "• Concurrent Processing: Test throughput under load conditions.",
                "• Real-time Metrics: Monitor system resources in real-time with sparklines."
            ]),
            ("Lightning Network Management", [
                "• Channel Monitoring: View and manage Lightning Network channels.",
                "• Splicing: Dynamically adjust channel capacity using the Splice button.",
                "• Taproot Support: Monitor channels with Taproot commitment types."
            ]),
            ("Troubleshooting", [
                "• Connection Issues: Check API URL and network connectivity in Settings.",
                "• Performance Problems: Use the Performance section to run benchmarks.",
                "• Security Alerts: Review risk alerts and enable watchtower protection.",
                "• Accessibility: Use keyboard navigation and F1 for help."
            ])
        ]

        for section_title, items in sections:
            section_frame = tk.Frame(scrollable_frame, bg=scrollable_frame.cget('bg'))
            section_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['md']))

            section_label = tk.Label(
                section_frame, text=section_title,
                font=AtlassianTheme.FONTS['heading_md'],
                fg=AtlassianTheme.COLORS['text_primary'],
                bg=section_frame.cget('bg')
            )
            section_label.pack(anchor='w', pady=(0, AtlassianTheme.SPACING['sm']))

            for item in items:
                if item.startswith("•"):
                    # Bullet point
                    item_label = tk.Label(
                        section_frame, text=item,
                        font=AtlassianTheme.FONTS['body_sm'],
                        fg=AtlassianTheme.COLORS['text_secondary'],
                        bg=section_frame.cget('bg'),
                        justify='left'
                    )
                else:
                    # Numbered item
                    item_label = tk.Label(
                        section_frame, text=item,
                        font=AtlassianTheme.FONTS['body_sm'],
                        fg=AtlassianTheme.COLORS['text_secondary'],
                        bg=section_frame.cget('bg'),
                        justify='left'
                    )
                item_label.pack(anchor='w', padx=(AtlassianTheme.SPACING['sm'], 0))

        # Close button
        close_btn = tk.Button(
            main_frame, text="Close",
            font=AtlassianTheme.FONTS['body_md'],
            fg=AtlassianTheme.COLORS['text_inverse'],
            bg=AtlassianTheme.COLORS['primary'],
            relief='flat', borderwidth=0,
            command=guide_window.destroy
        )
        close_btn.pack(pady=(AtlassianTheme.SPACING['lg'], 0))

    def _apply_settings(self, data):
        """Apply settings from the enhanced form."""
        try:
            new_url = data["api_url"].strip()
            new_interval = int(data["poll_interval"])

            # Apply changes
            if new_url != self.base_url:
                self.base_url = new_url
                self._reconnect_api()

            if new_interval != self.poll_interval:
                self.poll_interval = new_interval

            # Show success banner
            self.show_banner(
                "Settings applied successfully",
                appearance='success',
                duration=3
            )

            # Close settings window (will be handled by form)

        except Exception as e:
            self.show_banner(
                f"Failed to apply settings: {str(e)}",
                appearance='error',
                duration=5
            )

    def _on_mousewheel(self, event):
        """Handle mouse wheel scrolling."""
        self.content_canvas.yview_scroll(int(-1*(event.delta/120)), "units")

    def start(self):
        """Start the dashboard GUI main loop."""
        # Start update processing
        self.root.after(100, self._process_updates)

        # Start main loop
        self.root.mainloop()


def create_dashboard_gui(base_url: str = 'http://localhost:5000') -> DashboardGUI:
    """
    Create and return a configured dashboard GUI instance.

    Args:
        base_url: Base URL for the BLNCS API server

    Returns:
        Configured DashboardGUI instance
    """
    root = tk.Tk()
    return DashboardGUI(root, base_url)
