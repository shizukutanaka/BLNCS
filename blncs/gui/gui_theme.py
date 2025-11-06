"""
Modern BLNCS GUI Theme and Styling.

This module provides Atlassian-inspired design system components
for consistent styling across the BLNCS dashboard GUI.
"""

import tkinter as tk
from tkinter import ttk

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


class ThemeManager:
    """
    Theme manager for customizable themes and dark mode support.
    """

    THEMES = {
        'light': {
            'name': 'Light Theme',
            'colors': AtlassianTheme.COLORS.copy(),
        },
        'dark': {
            'name': 'Dark Theme',
            'colors': {
                # Primary colors
                'primary': '#4A90E2',
                'primary_hover': '#357ABD',
                'primary_light': '#E3F2FD',

                # Status colors
                'success': '#4CAF50',
                'success_light': '#E8F5E8',
                'warning': '#FF9800',
                'warning_light': '#FFF3E0',
                'error': '#F44336',
                'error_light': '#FFEBEE',

                # Neutral colors (dark theme)
                'neutral_900': '#212121',
                'neutral_700': '#424242',
                'neutral_500': '#757575',
                'neutral_300': '#BDBDBD',
                'neutral_100': '#E0E0E0',
                'neutral_50': '#FAFAFA',
                'neutral_0': '#FFFFFF',

                # Text colors (dark theme)
                'text_primary': '#FFFFFF',
                'text_secondary': '#BDBDBD',
                'text_subtle': '#757575',
                'text_inverse': '#000000',

                # Background colors (dark theme)
                'bg_primary': '#121212',
                'bg_secondary': '#1E1E1E',
                'bg_tertiary': '#2A2A2A',
                'bg_elevated': '#1E1E1E',
            }
        }
    }

    def __init__(self):
        self.current_theme = 'light'
        self.custom_themes = {}

    def get_current_theme(self):
        """Get the current theme."""
        return self.current_theme

    def set_theme(self, theme_name: str):
        """Set the current theme."""
        if theme_name in self.THEMES or theme_name in self.custom_themes:
            self.current_theme = theme_name
            self._apply_theme()
        else:
            raise ValueError(f"Theme '{theme_name}' not found")

    def create_custom_theme(self, name: str, colors: Dict[str, str]):
        """Create a custom theme."""
        self.custom_themes[name] = {
            'name': name,
            'colors': colors
        }

    def _apply_theme(self):
        """Apply the current theme to all widgets."""
        theme_data = self.THEMES.get(self.current_theme, self.custom_themes.get(self.current_theme))
        if not theme_data:
            return

        # Update AtlassianTheme colors
        AtlassianTheme.COLORS.update(theme_data['colors'])

        # Re-apply styling
        apply_atlassian_theme()

    def toggle_dark_mode(self):
        """Toggle between light and dark mode."""
        if self.current_theme == 'light':
            self.set_theme('dark')
        else:
            self.set_theme('light')

    def get_available_themes(self):
        """Get list of available themes."""
        themes = list(self.THEMES.keys())
        themes.extend(self.custom_themes.keys())
        return themes
