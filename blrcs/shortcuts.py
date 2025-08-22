# BLRCS Keyboard Shortcuts Module
# Simple keyboard shortcut handling
from typing import Dict, Callable, Optional, Set
import tkinter as tk

class ShortcutManager:
    """
    Keyboard shortcut management.
    Clean and simple following Martin's principles.
    """
    
    def __init__(self, root: Optional[tk.Tk] = None):
        self.root = root
        self.shortcuts: Dict[str, Callable] = {}
        self.enabled = True
        
        # Common modifier mappings
        self.modifiers = {
            'ctrl': 'Control',
            'alt': 'Alt',
            'shift': 'Shift',
            'cmd': 'Command',
            'win': 'Win'
        }
        
        # Context-aware shortcuts
        self.contexts = {}
        self.active_context = "global"
        
        # Command palette shortcuts
        self.command_palette_shortcuts = {}
        
        # Register default shortcuts
        self._register_defaults()
    
    def _register_defaults(self):
        """Register enhanced default shortcuts"""
        defaults = {
            # File operations
            'ctrl+n': 'new_file',
            'ctrl+shift+n': 'new_window',
            'ctrl+o': 'open_file',
            'ctrl+shift+o': 'open_folder',
            'ctrl+s': 'save_file',
            'ctrl+shift+s': 'save_as',
            'ctrl+w': 'close_tab',
            'ctrl+shift+w': 'close_window',
            'ctrl+q': 'quit_application',
            
            # Edit operations
            'ctrl+z': 'undo',
            'ctrl+y': 'redo',
            'ctrl+shift+z': 'redo_alt',
            'ctrl+x': 'cut',
            'ctrl+c': 'copy',
            'ctrl+v': 'paste',
            'ctrl+shift+v': 'paste_special',
            'ctrl+a': 'select_all',
            'ctrl+d': 'duplicate_line',
            'ctrl+l': 'select_line',
            
            # Search and navigation
            'ctrl+f': 'find',
            'ctrl+h': 'find_replace',
            'ctrl+g': 'goto_line',
            'ctrl+shift+f': 'find_in_files',
            'ctrl+shift+h': 'replace_in_files',
            'f3': 'find_next',
            'shift+f3': 'find_previous',
            
            # View and display
            'f5': 'refresh',
            'ctrl+r': 'refresh_alt',
            'f11': 'fullscreen',
            'ctrl+0': 'reset_zoom',
            'ctrl+plus': 'zoom_in',
            'ctrl+equal': 'zoom_in_alt',
            'ctrl+minus': 'zoom_out',
            'ctrl+shift+i': 'toggle_dev_tools',
            
            # Tab and window management
            'ctrl+tab': 'next_tab',
            'ctrl+shift+tab': 'previous_tab',
            'ctrl+1': 'tab_1',
            'ctrl+2': 'tab_2',
            'ctrl+3': 'tab_3',
            'ctrl+4': 'tab_4',
            'ctrl+5': 'tab_5',
            'ctrl+6': 'tab_6',
            'ctrl+7': 'tab_7',
            'ctrl+8': 'tab_8',
            'ctrl+9': 'tab_9',
            
            # Tool shortcuts
            'ctrl+shift+p': 'command_palette',
            'ctrl+shift+e': 'explorer',
            'ctrl+shift+g': 'source_control',
            'ctrl+shift+d': 'debug',
            'ctrl+shift+x': 'extensions',
            'ctrl+comma': 'settings',
            'f1': 'help',
            'f12': 'developer_tools',
            
            # Quick actions
            'escape': 'escape_action',
            'enter': 'confirm_action',
            'space': 'space_action',
            'delete': 'delete_action',
            'backspace': 'backspace_action',
            
            # Custom BLRCS shortcuts
            'ctrl+shift+l': 'toggle_log_panel',
            'ctrl+shift+m': 'toggle_monitor_panel',
            'ctrl+shift+t': 'new_terminal',
            'ctrl+shift+c': 'copy_path',
            'ctrl+k+ctrl+s': 'keyboard_shortcuts',
            'ctrl+shift+r': 'reload_window'
        }
        
        for shortcut, action in defaults.items():
            self.shortcuts[shortcut] = action
    
    def parse_shortcut(self, shortcut: str) -> str:
        """Parse shortcut string to tkinter format"""
        parts = shortcut.lower().split('+')
        result = []
        
        for part in parts:
            if part in self.modifiers:
                result.append(f'<{self.modifiers[part]}-')
            else:
                # Handle special keys
                if part == 'space':
                    result.append('space>')
                elif part == 'enter' or part == 'return':
                    result.append('Return>')
                elif part == 'tab':
                    result.append('Tab>')
                elif part == 'escape' or part == 'esc':
                    result.append('Escape>')
                elif part.startswith('f') and part[1:].isdigit():
                    result.append(f'{part.upper()}>')
                else:
                    # Regular key
                    result.append(f'{part}>')
        
        return ''.join(result)
    
    def bind(self, shortcut: str, callback: Callable):
        """Bind shortcut to callback"""
        if not self.root:
            return
        
        tk_shortcut = self.parse_shortcut(shortcut)
        
        def wrapper(event):
            if self.enabled:
                return callback()
        
        self.root.bind(tk_shortcut, wrapper)
        self.shortcuts[shortcut] = callback
    
    def unbind(self, shortcut: str):
        """Unbind shortcut"""
        if not self.root:
            return
        
        tk_shortcut = self.parse_shortcut(shortcut)
        self.root.unbind(tk_shortcut)
        
        if shortcut in self.shortcuts:
            del self.shortcuts[shortcut]
    
    def enable(self):
        """Enable all shortcuts"""
        self.enabled = True
    
    def disable(self):
        """Disable all shortcuts"""
        self.enabled = False
    
    def get_shortcut_for_action(self, action: str) -> Optional[str]:
        """Get shortcut for action"""
        for shortcut, act in self.shortcuts.items():
            if act == action or (callable(act) and act.__name__ == action):
                return shortcut
        return None
    
    def set_context(self, context: str):
        """Set active shortcut context"""
        self.active_context = context
    
    def add_context_shortcut(self, context: str, shortcut: str, callback: Callable):
        """Add shortcut specific to context"""
        if context not in self.contexts:
            self.contexts[context] = {}
        self.contexts[context][shortcut] = callback
    
    def get_context_shortcuts(self, context: str) -> Dict[str, Callable]:
        """Get shortcuts for specific context"""
        return self.contexts.get(context, {})
    
    def execute_shortcut(self, shortcut: str) -> bool:
        """Execute shortcut in current context"""
        # Check context-specific shortcuts first
        if self.active_context in self.contexts:
            if shortcut in self.contexts[self.active_context]:
                callback = self.contexts[self.active_context][shortcut]
                if callable(callback):
                    callback()
                    return True
        
        # Check global shortcuts
        if shortcut in self.shortcuts:
            action = self.shortcuts[shortcut]
            if callable(action):
                action()
                return True
        
        return False
    
    def bind_chord(self, chord_sequence: str, callback: Callable):
        """Bind chord sequence (e.g., 'ctrl+k ctrl+s')"""
        parts = chord_sequence.split(' ')
        if len(parts) == 2:
            first_chord, second_chord = parts
            
            def chord_handler():
                # Wait for second chord within timeout
                self.root.after(1000, lambda: None)  # 1 second timeout
                
                def second_handler(event):
                    if self.parse_shortcut(second_chord) == event.keysym:
                        callback()
                    self.root.unbind('<Key>')
                
                self.root.bind('<Key>', second_handler)
            
            self.bind(first_chord, chord_handler)
    
    def create_shortcut_help(self) -> str:
        """Create formatted shortcut help text"""
        help_text = []
        
        categories = {
            "File Operations": [
                ('ctrl+n', 'New File'),
                ('ctrl+o', 'Open File'),
                ('ctrl+s', 'Save File'),
                ('ctrl+shift+s', 'Save As'),
                ('ctrl+w', 'Close Tab'),
                ('ctrl+q', 'Quit Application')
            ],
            "Edit Operations": [
                ('ctrl+z', 'Undo'),
                ('ctrl+y', 'Redo'),
                ('ctrl+x', 'Cut'),
                ('ctrl+c', 'Copy'),
                ('ctrl+v', 'Paste'),
                ('ctrl+a', 'Select All'),
                ('ctrl+f', 'Find'),
                ('ctrl+h', 'Find & Replace')
            ],
            "View & Navigation": [
                ('f5', 'Refresh'),
                ('f11', 'Fullscreen'),
                ('ctrl+tab', 'Next Tab'),
                ('ctrl+shift+tab', 'Previous Tab'),
                ('ctrl+1-9', 'Switch to Tab'),
                ('ctrl+0', 'Reset Zoom'),
                ('ctrl+plus', 'Zoom In'),
                ('ctrl+minus', 'Zoom Out')
            ],
            "Tools & Panels": [
                ('ctrl+shift+p', 'Command Palette'),
                ('ctrl+shift+l', 'Toggle Log Panel'),
                ('ctrl+shift+m', 'Toggle Monitor Panel'),
                ('ctrl+comma', 'Settings'),
                ('f1', 'Help'),
                ('f12', 'Developer Tools')
            ]
        }
        
        for category, shortcuts in categories.items():
            help_text.append(f"\n{category}:")
            help_text.append("-" * len(category))
            for shortcut, description in shortcuts:
                formatted_shortcut = format_shortcut_display(shortcut)
                help_text.append(f"  {formatted_shortcut:<20} {description}")
        
        return "\n".join(help_text)
    
    def list_shortcuts(self) -> Dict[str, str]:
        """List all registered shortcuts"""
        result = {}
        for shortcut, action in self.shortcuts.items():
            if isinstance(action, str):
                result[shortcut] = action
            elif callable(action):
                result[shortcut] = action.__name__
        return result

class GlobalShortcuts:
    """
    Global keyboard shortcuts (system-wide).
    Uses keyboard library for cross-platform support.
    """
    
    def __init__(self):
        self.shortcuts: Dict[str, Callable] = {}
        self.enabled = False
        
        try:
            import keyboard
            self.keyboard = keyboard
            self.available = True
        except ImportError:
            self.keyboard = None
            self.available = False
    
    def register(self, hotkey: str, callback: Callable):
        """Register global hotkey"""
        if not self.available:
            return False
        
        try:
            self.keyboard.add_hotkey(hotkey, callback)
            self.shortcuts[hotkey] = callback
            return True
        except:
            return False
    
    def unregister(self, hotkey: str):
        """Unregister global hotkey"""
        if not self.available:
            return
        
        try:
            self.keyboard.remove_hotkey(hotkey)
            if hotkey in self.shortcuts:
                del self.shortcuts[hotkey]
        except:
            pass
    
    def unregister_all(self):
        """Unregister all global hotkeys"""
        if not self.available:
            return
        
        for hotkey in list(self.shortcuts.keys()):
            self.unregister(hotkey)

# Shortcut definitions for easy reference
SHORTCUTS = {
    'file': {
        'new': 'Ctrl+N',
        'open': 'Ctrl+O',
        'save': 'Ctrl+S',
        'save_as': 'Ctrl+Shift+S',
        'close': 'Ctrl+W',
        'quit': 'Ctrl+Q'
    },
    'edit': {
        'undo': 'Ctrl+Z',
        'redo': 'Ctrl+Y',
        'cut': 'Ctrl+X',
        'copy': 'Ctrl+C',
        'paste': 'Ctrl+V',
        'select_all': 'Ctrl+A',
        'find': 'Ctrl+F',
        'replace': 'Ctrl+H'
    },
    'view': {
        'refresh': 'F5',
        'fullscreen': 'F11',
        'zoom_in': 'Ctrl+Plus',
        'zoom_out': 'Ctrl+Minus',
        'reset_zoom': 'Ctrl+0'
    },
    'navigation': {
        'next': 'Ctrl+Tab',
        'previous': 'Ctrl+Shift+Tab',
        'home': 'Home',
        'end': 'End',
        'page_up': 'Page_Up',
        'page_down': 'Page_Down'
    },
    'tools': {
        'settings': 'Ctrl+Comma',
        'help': 'F1',
        'console': 'F12',
        'command_palette': 'Ctrl+Shift+P'
    }
}

def format_shortcut_display(shortcut: str) -> str:
    """Format shortcut for display (e.g., in menus)"""
    parts = shortcut.split('+')
    formatted = []
    
    for part in parts:
        if part.lower() == 'ctrl':
            formatted.append('Ctrl')
        elif part.lower() == 'alt':
            formatted.append('Alt')
        elif part.lower() == 'shift':
            formatted.append('Shift')
        elif part.lower() in ['cmd', 'command']:
            formatted.append('Cmd')
        else:
            formatted.append(part.capitalize())
    
    return '+'.join(formatted)