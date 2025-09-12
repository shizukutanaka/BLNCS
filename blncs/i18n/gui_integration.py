#!/usr/bin/env python3
"""
BLNCS GUI Internationalization Integration
Multi-language support for tkinter GUI components.
"""

import tkinter as tk
from tkinter import ttk
import logging
from typing import Dict, Any, List, Callable, Optional, Union
from dataclasses import dataclass, field

try:
    from .translator import get_translator
    from .language_manager import get_language_manager
    from .locale_utils import get_formatter
except ImportError:
    # For standalone testing
    import sys
    from pathlib import Path
    sys.path.append(str(Path(__file__).parent))
    from translator import get_translator
    from language_manager import get_language_manager
    from locale_utils import get_formatter

logger = logging.getLogger(__name__)


@dataclass
class TranslatableWidget:
    """Widget with translatable text properties"""
    widget: tk.Widget
    translation_key: str
    text_property: str = 'text'
    format_args: Dict[str, Any] = field(default_factory=dict)


class I18nMixin:
    """Mixin class to add internationalization support to widgets"""
    
    def __init__(self):
        self.translatable_widgets: List[TranslatableWidget] = []
        self.language_manager = get_language_manager()
        self.translator = get_translator()
        
        # Register for language change notifications
        self.language_manager.add_language_change_callback(self._on_language_changed)
    
    def add_translatable_widget(self, widget: tk.Widget, translation_key: str, 
                               text_property: str = 'text', **format_args):
        """Add a widget to be automatically translated"""
        translatable = TranslatableWidget(
            widget=widget,
            translation_key=translation_key,
            text_property=text_property,
            format_args=format_args
        )
        
        self.translatable_widgets.append(translatable)
        
        # Apply initial translation
        self._update_widget_text(translatable)
    
    def remove_translatable_widget(self, widget: tk.Widget):
        """Remove widget from translation updates"""
        self.translatable_widgets = [
            tw for tw in self.translatable_widgets 
            if tw.widget != widget
        ]
    
    def translate_text(self, key: str, **kwargs) -> str:
        """Convenience method for text translation"""
        return self.translator.translate(key, **kwargs)
    
    def _update_widget_text(self, translatable: TranslatableWidget):
        """Update text for a single translatable widget"""
        try:
            translated_text = self.translator.translate(
                translatable.translation_key,
                **translatable.format_args
            )
            
            # Set the text property on the widget
            if hasattr(translatable.widget, translatable.text_property):
                setattr(translatable.widget, translatable.text_property, translated_text)
            elif hasattr(translatable.widget, 'config'):
                translatable.widget.config({translatable.text_property: translated_text})
            
        except Exception as e:
            logger.error(f"Failed to update widget text: {e}")
    
    def _on_language_changed(self, old_language: str, new_language: str):
        """Handle language change events"""
        logger.debug(f"Updating GUI texts for language change: {old_language} -> {new_language}")
        
        # Update all translatable widgets
        for translatable in self.translatable_widgets:
            self._update_widget_text(translatable)
        
        # Call custom language change handler if implemented
        if hasattr(self, 'on_language_changed'):
            self.on_language_changed(old_language, new_language)
    
    def cleanup_i18n(self):
        """Clean up i18n resources"""
        try:
            self.language_manager.remove_language_change_callback(self._on_language_changed)
        except Exception as e:
            logger.error(f"Failed to cleanup i18n resources: {e}")


class I18nWindow(tk.Tk, I18nMixin):
    """Internationalized Tkinter window"""
    
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        I18nMixin.__init__(self)
        
        # Set window title with translation
        self.title(self.translate_text('app.title'))
    
    def destroy(self):
        """Override destroy to cleanup i18n resources"""
        self.cleanup_i18n()
        super().destroy()


class I18nFrame(ttk.Frame, I18nMixin):
    """Internationalized Tkinter frame"""
    
    def __init__(self, parent, *args, **kwargs):
        ttk.Frame.__init__(self, parent, *args, **kwargs)
        I18nMixin.__init__(self)
    
    def destroy(self):
        """Override destroy to cleanup i18n resources"""
        self.cleanup_i18n()
        super().destroy()


class LanguageSelector:
    """Language selector widget with preview"""
    
    def __init__(self, parent, on_language_changed: Optional[Callable[[str], None]] = None):
        self.parent = parent
        self.on_language_changed = on_language_changed
        self.language_manager = get_language_manager()
        self.translator = get_translator()
        
        self.setup_ui()
        self.update_language_list()
    
    def setup_ui(self):
        """Setup language selector UI"""
        # Main frame
        self.frame = ttk.LabelFrame(self.parent, text="Language / 言語 / Idioma", padding="10")
        self.frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Language selection
        selection_frame = ttk.Frame(self.frame)
        selection_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(selection_frame, text="Select Language:").pack(side=tk.LEFT)
        
        self.language_var = tk.StringVar()
        self.language_combo = ttk.Combobox(
            selection_frame,
            textvariable=self.language_var,
            state="readonly",
            width=20
        )
        self.language_combo.pack(side=tk.LEFT, padx=(10, 0))
        self.language_combo.bind('<<ComboboxSelected>>', self._on_language_selected)
        
        # Language info
        info_frame = ttk.Frame(self.frame)
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.info_label = ttk.Label(info_frame, text="", font=("Arial", 9))
        self.info_label.pack(side=tk.LEFT)
        
        # Preview text
        preview_frame = ttk.LabelFrame(self.frame, text="Preview", padding="5")
        preview_frame.pack(fill=tk.X)
        
        self.preview_text = tk.Text(
            preview_frame,
            height=4,
            width=50,
            wrap=tk.WORD,
            state=tk.DISABLED,
            font=("Arial", 9)
        )
        self.preview_text.pack(fill=tk.BOTH, expand=True)
    
    def update_language_list(self):
        """Update the language selection list"""
        selector_data = self.language_manager.create_language_selector_data()
        
        # Create display strings
        language_options = []
        language_codes = []
        
        for lang_data in selector_data:
            display_name = f"{lang_data['name']} ({lang_data['code']})"
            if lang_data['completion'] < 100:
                display_name += f" - {lang_data['completion']:.0f}%"
            if lang_data['is_current']:
                display_name += " ✓"
            
            language_options.append(display_name)
            language_codes.append(lang_data['code'])
        
        # Update combobox
        self.language_combo['values'] = language_options
        self.language_codes = language_codes
        
        # Set current selection
        current_language = self.language_manager.get_current_language()
        try:
            current_index = language_codes.index(current_language)
            self.language_combo.current(current_index)
        except ValueError:
            self.language_combo.current(0)
        
        self.update_preview()
    
    def _on_language_selected(self, event):
        """Handle language selection"""
        selection_index = self.language_combo.current()
        if selection_index >= 0 and selection_index < len(self.language_codes):
            selected_language = self.language_codes[selection_index]
            
            # Set language
            success = self.language_manager.set_language(selected_language)
            if success:
                self.update_preview()
                
                # Notify callback
                if self.on_language_changed:
                    self.on_language_changed(selected_language)
            else:
                logger.error(f"Failed to set language to {selected_language}")
    
    def update_preview(self):
        """Update the preview text"""
        current_language = self.language_manager.get_current_language()
        
        # Update info label
        completion = self.language_manager.get_language_completion_percentage(current_language)
        info_text = f"Translation completeness: {completion:.1f}%"
        if completion < 100:
            missing_count = len(self.language_manager.get_missing_translations(current_language))
            info_text += f" ({missing_count} missing)"
        self.info_label.config(text=info_text)
        
        # Update preview text
        preview_keys = [
            'app.title',
            'lightning.balance',
            'action.connect', 
            'monitoring.cpu',
            'success.connected'
        ]
        
        preview_lines = []
        for key in preview_keys:
            translated = self.translator.translate(key)
            preview_lines.append(f"{key}: {translated}")
        
        preview_text = "\n".join(preview_lines)
        
        # Update text widget
        self.preview_text.config(state=tk.NORMAL)
        self.preview_text.delete(1.0, tk.END)
        self.preview_text.insert(1.0, preview_text)
        self.preview_text.config(state=tk.DISABLED)


class I18nMessageBox:
    """Internationalized message boxes"""
    
    @staticmethod
    def show_info(title_key: str, message_key: str, **format_args):
        """Show info message box with translation"""
        translator = get_translator()
        title = translator.translate(title_key, **format_args)
        message = translator.translate(message_key, **format_args)
        
        from tkinter import messagebox
        messagebox.showinfo(title, message)
    
    @staticmethod
    def show_warning(title_key: str, message_key: str, **format_args):
        """Show warning message box with translation"""
        translator = get_translator()
        title = translator.translate(title_key, **format_args)
        message = translator.translate(message_key, **format_args)
        
        from tkinter import messagebox
        messagebox.showwarning(title, message)
    
    @staticmethod
    def show_error(title_key: str, message_key: str, **format_args):
        """Show error message box with translation"""
        translator = get_translator()
        title = translator.translate(title_key, **format_args)
        message = translator.translate(message_key, **format_args)
        
        from tkinter import messagebox
        messagebox.showerror(title, message)
    
    @staticmethod
    def ask_yes_no(title_key: str, message_key: str, **format_args) -> bool:
        """Ask yes/no question with translation"""
        translator = get_translator()
        title = translator.translate(title_key, **format_args)
        message = translator.translate(message_key, **format_args)
        
        from tkinter import messagebox
        return messagebox.askyesno(title, message)


class LocalizedStatusBar(ttk.Frame):
    """Status bar with localized messages"""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.translator = get_translator()
        self.formatter = get_formatter()
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup status bar UI"""
        # Status message
        self.status_var = tk.StringVar()
        self.status_label = ttk.Label(
            self,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(2, 0))
        
        # Language indicator
        self.language_var = tk.StringVar()
        self.language_label = ttk.Label(
            self,
            textvariable=self.language_var,
            relief=tk.SUNKEN,
            width=8,
            anchor=tk.CENTER
        )
        self.language_label.pack(side=tk.RIGHT, padx=2)
        
        # Initialize
        self.update_language_indicator()
        self.set_status('app.loading')
    
    def set_status(self, message_key: str, **format_args):
        """Set status message with translation"""
        try:
            message = self.translator.translate(message_key, **format_args)
            self.status_var.set(message)
        except Exception as e:
            logger.error(f"Failed to set status: {e}")
            self.status_var.set(message_key)  # Fallback to key
    
    def set_status_direct(self, message: str):
        """Set status message directly (no translation)"""
        self.status_var.set(message)
    
    def update_language_indicator(self):
        """Update language indicator"""
        current_language = get_language_manager().get_current_language()
        self.language_var.set(current_language.upper())


def create_i18n_menu(parent, language_changed_callback: Optional[Callable[[str], None]] = None) -> tk.Menu:
    """Create internationalized menu"""
    translator = get_translator()
    language_manager = get_language_manager()
    
    # Main menubar
    menubar = tk.Menu(parent)
    
    # Language menu
    language_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label=translator.translate('settings.language'), menu=language_menu)
    
    # Add language options
    available_languages = language_manager.get_available_languages()
    current_language = language_manager.get_current_language()
    
    for code, name in available_languages.items():
        def set_lang(lang_code=code):
            success = language_manager.set_language(lang_code)
            if success and language_changed_callback:
                language_changed_callback(lang_code)
        
        menu_label = f"{name} ({code})"
        if code == current_language:
            menu_label += " ✓"
        
        language_menu.add_command(label=menu_label, command=set_lang)
    
    return menubar


if __name__ == "__main__":
    # Test GUI integration
    class TestI18nApp(I18nWindow):
        def __init__(self):
            super().__init__()
            
            self.title("BLNCS i18n Test")
            self.geometry("600x400")
            
            self.setup_ui()
        
        def setup_ui(self):
            """Setup test UI"""
            # Menu
            menubar = create_i18n_menu(self, self._on_menu_language_changed)
            self.config(menu=menubar)
            
            # Main content
            main_frame = ttk.Frame(self, padding="10")
            main_frame.pack(fill=tk.BOTH, expand=True)
            
            # Test translatable widgets
            test_label = ttk.Label(main_frame, text="")
            test_label.pack(pady=5)
            self.add_translatable_widget(test_label, 'app.title')
            
            test_button = ttk.Button(main_frame, text="")
            test_button.pack(pady=5)
            self.add_translatable_widget(test_button, 'action.connect')
            
            # Language selector
            self.language_selector = LanguageSelector(
                main_frame, 
                self._on_language_changed
            )
            
            # Status bar
            self.status_bar = LocalizedStatusBar(self)
            self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
            self.status_bar.set_status('success.connected')
        
        def _on_language_changed(self, language_code: str):
            """Handle language change from selector"""
            logger.info(f"Language changed to: {language_code}")
            self.status_bar.update_language_indicator()
        
        def _on_menu_language_changed(self, language_code: str):
            """Handle language change from menu"""
            logger.info(f"Language changed from menu to: {language_code}")
            self.language_selector.update_language_list()
            self.status_bar.update_language_indicator()
    
    # Run test
    logging.basicConfig(level=logging.INFO)
    
    app = TestI18nApp()
    app.mainloop()