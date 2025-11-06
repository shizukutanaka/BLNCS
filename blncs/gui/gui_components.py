"""
Modern BLNCS GUI Components.

This module provides reusable UI components with Atlassian-inspired design
for the BLNCS dashboard GUI.
"""

import tkinter as tk
from tkinter import ttk
from typing import Dict, List, Optional, Any, Tuple
from .gui_theme import AtlassianTheme, ModernFrame

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


class LogManager:
    """
    Enhanced logging manager with levels and filtering.
    """

    LOG_LEVELS = {
        'DEBUG': 0,
        'INFO': 1,
        'WARNING': 2,
        'ERROR': 3,
        'CRITICAL': 4
    }

    def __init__(self, max_lines: int = 1000):
        self.max_lines = max_lines
        self.log_entries = []
        self.filters = {
            'level': None,
            'source': None,
            'message_contains': None
        }

    def log(self, level: str, message: str, source: str = None):
        """Log a message with level and source."""
        if level not in self.LOG_LEVELS:
            level = 'INFO'

        entry = {
            'timestamp': time.time(),
            'level': level,
            'message': message,
            'source': source or 'system'
        }

        self.log_entries.append(entry)

        # Trim old entries
        if len(self.log_entries) > self.max_lines:
            self.log_entries = self.log_entries[-self.max_lines:]

    def set_filter(self, level: str = None, source: str = None, message_contains: str = None):
        """Set log filters."""
        self.filters = {
            'level': level,
            'source': source,
            'message_contains': message_contains
        }

    def get_filtered_logs(self) -> List[Dict[str, Any]]:
        """Get filtered log entries."""
        filtered = self.log_entries

        if self.filters['level']:
            min_level = self.LOG_LEVELS.get(self.filters['level'], 0)
            filtered = [entry for entry in filtered if self.LOG_LEVELS.get(entry['level'], 0) >= min_level]

        if self.filters['source']:
            filtered = [entry for entry in filtered if self.filters['source'].lower() in entry['source'].lower()]

        if self.filters['message_contains']:
            filtered = [entry for entry in filtered if self.filters['message_contains'].lower() in entry['message'].lower()]

        return filtered

    def clear_logs(self):
        """Clear all log entries."""
        self.log_entries.clear()

    def export_logs(self, filename: str):
        """Export logs to a file."""
        try:
            with open(filename, 'w') as f:
                for entry in self.log_entries:
                    f.write(f"[{entry['level']}] {entry['source']}: {entry['message']}\n")
        except Exception as e:
            print(f"Failed to export logs: {e}")


class EnhancedLogViewer(tk.Frame):
    """
    Enhanced log viewer with filtering and search capabilities.
    """

    def __init__(self, parent, log_manager: LogManager, **kwargs):
        super().__init__(parent, **kwargs)
        self.log_manager = log_manager

        # Filter controls
        filter_frame = tk.Frame(self, bg=self.cget('bg'))
        filter_frame.pack(fill='x', pady=(0, AtlassianTheme.SPACING['sm']))

        # Level filter
        level_label = tk.Label(filter_frame, text="Level:", font=AtlassianTheme.FONTS['body_sm'],
                              bg=self.cget('bg'), fg=AtlassianTheme.COLORS['text_secondary'])
        level_label.pack(side='left')

        self.level_var = tk.StringVar(value='All')
        level_combo = ttk.Combobox(filter_frame, textvariable=self.level_var,
                                 values=['All', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                                 state='readonly', width=10)
        level_combo.pack(side='left', padx=(AtlassianTheme.SPACING['xs'], AtlassianTheme.SPACING['sm']))
        level_combo.bind('<<ComboboxSelected>>', self._apply_filters)

        # Source filter
        source_label = tk.Label(filter_frame, text="Source:", font=AtlassianTheme.FONTS['body_sm'],
                               bg=self.cget('bg'), fg=AtlassianTheme.COLORS['text_secondary'])
        source_label.pack(side='left')

        self.source_var = tk.StringVar()
        source_entry = tk.Entry(filter_frame, textvariable=self.source_var, width=15,
                               font=AtlassianTheme.FONTS['body_sm'])
        source_entry.pack(side='left', padx=(AtlassianTheme.SPACING['xs'], AtlassianTheme.SPACING['sm']))
        source_entry.bind('<KeyRelease>', self._apply_filters)

        # Search filter
        search_label = tk.Label(filter_frame, text="Search:", font=AtlassianTheme.FONTS['body_sm'],
                               bg=self.cget('bg'), fg=AtlassianTheme.COLORS['text_secondary'])
        search_label.pack(side='left')

        self.search_var = tk.StringVar()
        search_entry = tk.Entry(filter_frame, textvariable=self.search_var, width=20,
                               font=AtlassianTheme.FONTS['body_sm'])
        search_entry.pack(side='left', padx=(AtlassianTheme.SPACING['xs'], AtlassianTheme.SPACING['sm']))
        search_entry.bind('<KeyRelease>', self._apply_filters)

        # Clear button
        clear_btn = tk.Button(filter_frame, text="Clear", font=AtlassianTheme.FONTS['body_sm'],
                             fg=AtlassianTheme.COLORS['text_inverse'], bg=AtlassianTheme.COLORS['warning'],
                             relief='flat', borderwidth=0, command=self._clear_logs)
        clear_btn.pack(side='right')

        # Log text area
        self.log_text = tk.Text(self, height=15, font=AtlassianTheme.FONTS['code'],
                               bg=AtlassianTheme.COLORS['neutral_50'], fg=AtlassianTheme.COLORS['text_primary'],
                               wrap='word', state='disabled')
        scrollbar = ttk.Scrollbar(self, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)

        self.log_text.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        # Color coding for log levels
        self.log_text.tag_configure('DEBUG', foreground='#2196F3')
        self.log_text.tag_configure('INFO', foreground='#4CAF50')
        self.log_text.tag_configure('WARNING', foreground='#FF9800')
        self.log_text.tag_configure('ERROR', foreground='#F44336')
        self.log_text.tag_configure('CRITICAL', foreground='#9C27B0', font=AtlassianTheme.FONTS['code_bold'])

        # Initial load
        self._refresh_logs()

    def _apply_filters(self, event=None):
        """Apply current filters and refresh display."""
        level = self.level_var.get() if self.level_var.get() != 'All' else None
        source = self.source_var.get().strip() if self.source_var.get() else None
        search = self.search_var.get().strip() if self.search_var.get() else None

        self.log_manager.set_filter(level=level, source=source, message_contains=search)
        self._refresh_logs()

    def _refresh_logs(self):
        """Refresh the log display."""
        self.log_text.configure(state='normal')
        self.log_text.delete('1.0', 'end')

        for entry in self.log_manager.get_filtered_logs():
            level = entry['level']
            message = entry['message']
            source = entry['source']

            self.log_text.insert('end', f"[{level}] {source}: {message}\n", level)

        self.log_text.configure(state='disabled')
        self.log_text.see('end')

    def _clear_logs(self):
        """Clear all logs."""
        self.log_manager.clear_logs()
        self._refresh_logs()

    def add_log_entry(self, level: str, message: str, source: str = None):
        """Add a log entry and refresh display."""
        self.log_manager.log(level, message, source)
        self._refresh_logs()
