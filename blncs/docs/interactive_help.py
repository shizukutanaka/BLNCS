#!/usr/bin/env python3
"""
BLNCS Interactive Help Interface
GUI and CLI interactive help components with tutorials and wizards.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
import webbrowser
import subprocess
import threading

try:
    from .help_system import get_help_system, HelpContext, HelpTopic
    from .documentation_manager import get_documentation_manager
    from ..i18n import get_translator
except ImportError:
    # For standalone testing
    import sys
    sys.path.append(str(Path(__file__).parent))
    from help_system import get_help_system, HelpContext, HelpTopic
    from documentation_manager import get_documentation_manager
    try:
        from i18n import get_translator
    except ImportError:
        # Mock translator for testing
        class MockTranslator:
            def translate(self, key, **kwargs):
                return key.replace('_', ' ').title()
        def get_translator():
            return MockTranslator()

logger = logging.getLogger(__name__)


class InteractiveHelpGUI:
    """GUI interface for interactive help system"""
    
    def __init__(self, parent=None):
        self.parent = parent
        self.help_system = get_help_system()
        self.doc_manager = get_documentation_manager()
        self.translator = get_translator()
        
        # Current state
        self.current_topic = None
        self.help_history = []
        self.search_results = []
        
        # Create GUI
        self.setup_gui()
        self.load_initial_help()
    
    def setup_gui(self):
        """Setup the help GUI interface"""
        # Main window or frame
        if self.parent is None:
            self.root = tk.Tk()
            self.root.title("BLNCS Help System")
            self.root.geometry("1000x700")
            container = self.root
        else:
            self.root = self.parent
            container = ttk.Frame(self.parent)
            container.pack(fill=tk.BOTH, expand=True)
        
        # Create main layout
        self.setup_main_layout(container)
        self.setup_toolbar()
        self.setup_content_area()
        self.setup_navigation_panel()
        self.setup_search_panel()
    
    def setup_main_layout(self, container):
        """Setup main layout with paned window"""
        # Main paned window
        self.paned_window = ttk.PanedWindow(container, orient=tk.HORIZONTAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left panel for navigation
        self.left_frame = ttk.Frame(self.paned_window, width=300)
        self.paned_window.add(self.left_frame, weight=1)
        
        # Right panel for content
        self.right_frame = ttk.Frame(self.paned_window)
        self.paned_window.add(self.right_frame, weight=3)
    
    def setup_toolbar(self):
        """Setup toolbar with navigation buttons"""
        toolbar = ttk.Frame(self.right_frame)
        toolbar.pack(fill=tk.X, pady=(0, 5))
        
        # Navigation buttons
        self.back_button = ttk.Button(
            toolbar, 
            text="← Back", 
            command=self.go_back,
            state=tk.DISABLED
        )
        self.back_button.pack(side=tk.LEFT, padx=(0, 5))
        
        self.forward_button = ttk.Button(
            toolbar,
            text="Forward →",
            command=self.go_forward,
            state=tk.DISABLED
        )
        self.forward_button.pack(side=tk.LEFT, padx=(0, 5))
        
        # Separator
        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)
        
        # Action buttons
        ttk.Button(
            toolbar,
            text="🏠 Home",
            command=self.go_home
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(
            toolbar,
            text="🔍 Search",
            command=self.focus_search
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(
            toolbar,
            text="📖 Docs",
            command=self.open_documentation
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        # Context label
        self.context_label = ttk.Label(toolbar, text="", font=("Arial", 9))
        self.context_label.pack(side=tk.RIGHT)
    
    def setup_content_area(self):
        """Setup main content display area"""
        # Content frame
        content_frame = ttk.Frame(self.right_frame)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        self.title_label = ttk.Label(
            content_frame,
            text="Welcome to BLNCS Help",
            font=("Arial", 16, "bold")
        )
        self.title_label.pack(pady=(0, 10))
        
        # Content text with scrollbar
        text_frame = ttk.Frame(content_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        self.content_text = scrolledtext.ScrolledText(
            text_frame,
            wrap=tk.WORD,
            font=("Arial", 11),
            state=tk.DISABLED
        )
        self.content_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure text tags for formatting
        self.setup_text_tags()
        
        # Action buttons frame
        self.actions_frame = ttk.Frame(content_frame)
        self.actions_frame.pack(fill=tk.X, pady=(10, 0))
    
    def setup_text_tags(self):
        """Configure text widget tags for formatting"""
        self.content_text.tag_configure("heading1", font=("Arial", 14, "bold"), spacing1=10, spacing3=5)
        self.content_text.tag_configure("heading2", font=("Arial", 12, "bold"), spacing1=8, spacing3=3)
        self.content_text.tag_configure("heading3", font=("Arial", 11, "bold"), spacing1=5, spacing3=2)
        self.content_text.tag_configure("code", font=("Consolas", 10), background="#f0f0f0")
        self.content_text.tag_configure("link", foreground="blue", underline=True)
        self.content_text.tag_configure("emphasis", font=("Arial", 11, "italic"))
        self.content_text.tag_configure("bold", font=("Arial", 11, "bold"))
    
    def setup_navigation_panel(self):
        """Setup navigation panel with categories and topics"""
        # Navigation notebook
        nav_notebook = ttk.Notebook(self.left_frame)
        nav_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Categories tab
        categories_frame = ttk.Frame(nav_notebook)
        nav_notebook.add(categories_frame, text="Categories")
        
        # Categories tree
        self.categories_tree = ttk.Treeview(categories_frame, show="tree")
        self.categories_tree.pack(fill=tk.BOTH, expand=True)
        self.categories_tree.bind("<<TreeviewSelect>>", self.on_category_select)
        
        # Topics tab
        topics_frame = ttk.Frame(nav_notebook)
        nav_notebook.add(topics_frame, text="All Topics")
        
        # Topics listbox
        self.topics_listbox = tk.Listbox(topics_frame)
        self.topics_listbox.pack(fill=tk.BOTH, expand=True)
        self.topics_listbox.bind("<<ListboxSelect>>", self.on_topic_select)
        
        # Favorites tab
        favorites_frame = ttk.Frame(nav_notebook)
        nav_notebook.add(favorites_frame, text="Favorites")
        
        self.favorites_listbox = tk.Listbox(favorites_frame)
        self.favorites_listbox.pack(fill=tk.BOTH, expand=True)
        
        # Populate navigation
        self.populate_navigation()
    
    def setup_search_panel(self):
        """Setup search functionality"""
        search_frame = ttk.LabelFrame(self.left_frame, text="Search Help", padding="5")
        search_frame.pack(fill=tk.X, pady=(10, 0))
        
        # Search entry
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        self.search_entry.pack(fill=tk.X, pady=(0, 5))
        self.search_entry.bind("<Return>", self.perform_search)
        
        # Search button
        ttk.Button(
            search_frame,
            text="Search",
            command=self.perform_search
        ).pack(fill=tk.X)
        
        # Quick access buttons
        quick_frame = ttk.LabelFrame(self.left_frame, text="Quick Access", padding="5")
        quick_frame.pack(fill=tk.X, pady=(10, 0))
        
        quick_buttons = [
            ("Getting Started", "getting_started"),
            ("Troubleshooting", "troubleshooting_assistant"),
            ("Commands", "command_helper"),
            ("API Reference", "api_reference")
        ]
        
        for text, topic_id in quick_buttons:
            ttk.Button(
                quick_frame,
                text=text,
                command=lambda t=topic_id: self.show_help_topic(t)
            ).pack(fill=tk.X, pady=1)
    
    def populate_navigation(self):
        """Populate navigation with categories and topics"""
        # Clear existing items
        for item in self.categories_tree.get_children():
            self.categories_tree.delete(item)
        self.topics_listbox.delete(0, tk.END)
        
        # Add categories to tree
        categories = self.help_system.get_all_categories()
        for category in categories:
            category_item = self.categories_tree.insert("", tk.END, text=category.replace('_', ' ').title())
            
            # Add topics under category
            topics = self.help_system.get_help_by_category(category)
            for topic in topics:
                self.categories_tree.insert(category_item, tk.END, text=topic.title, values=(topic.id,))
        
        # Add all topics to listbox
        all_topics = list(self.help_system.help_topics.values())
        all_topics.sort(key=lambda t: t.title)
        
        for topic in all_topics:
            self.topics_listbox.insert(tk.END, topic.title)
            self.topics_listbox.insert(tk.END, topic.id)  # Store ID as hidden item
    
    def load_initial_help(self):
        """Load initial help content"""
        # Show quick start wizard by default
        self.show_help_topic('quick_start_wizard')
    
    def show_help_topic(self, topic_id: str):
        """Display a help topic"""
        topic = self.help_system.get_help_topic(topic_id)
        if not topic:
            self.show_error(f"Help topic '{topic_id}' not found")
            return
        
        # Update navigation history
        if self.current_topic != topic_id:
            self.help_history.append(topic_id)
            if len(self.help_history) > 50:  # Limit history size
                self.help_history.pop(0)
        
        self.current_topic = topic_id
        self.update_navigation_buttons()
        
        # Display topic content
        self.title_label.config(text=topic.title)
        self.display_content(topic)
        self.update_context_label(topic)
        self.setup_topic_actions(topic)
    
    def display_content(self, topic: HelpTopic):
        """Display topic content with formatting"""
        self.content_text.config(state=tk.NORMAL)
        self.content_text.delete(1.0, tk.END)
        
        # Parse and format markdown-like content
        self.format_content(topic.content)
        
        self.content_text.config(state=tk.DISABLED)
    
    def format_content(self, content: str):
        """Format content with simple markdown-like formatting"""
        lines = content.split('\n')
        current_pos = 1.0
        
        for line in lines:
            line_start = self.content_text.index(tk.INSERT)
            
            # Headers
            if line.startswith('# '):
                self.content_text.insert(tk.INSERT, line[2:] + '\n')
                self.content_text.tag_add("heading1", line_start, f"{line_start} lineend")
            elif line.startswith('## '):
                self.content_text.insert(tk.INSERT, line[3:] + '\n')
                self.content_text.tag_add("heading2", line_start, f"{line_start} lineend")
            elif line.startswith('### '):
                self.content_text.insert(tk.INSERT, line[4:] + '\n')
                self.content_text.tag_add("heading3", line_start, f"{line_start} lineend")
            
            # Code blocks
            elif line.startswith('```'):
                # Skip code block markers, handle in code detection
                continue
            
            # Bold and italic (simple detection)
            elif '**' in line or '*' in line or '`' in line:
                self.format_styled_line(line + '\n', line_start)
            
            # Links [text](id)
            elif '[' in line and '](' in line:
                self.format_links_line(line + '\n', line_start)
            
            # Regular line
            else:
                self.content_text.insert(tk.INSERT, line + '\n')
    
    def format_styled_line(self, line: str, start_pos: str):
        """Format line with bold, italic, and code styling"""
        # This is a simplified formatter - a full implementation would use regex
        parts = []
        current_part = ""
        i = 0
        
        while i < len(line):
            if line[i:i+2] == '**' and i+2 < len(line):
                # Bold text
                if current_part:
                    parts.append(('normal', current_part))
                    current_part = ""
                
                # Find closing **
                end = line.find('**', i+2)
                if end != -1:
                    bold_text = line[i+2:end]
                    parts.append(('bold', bold_text))
                    i = end + 2
                else:
                    current_part += line[i]
                    i += 1
            
            elif line[i] == '`' and i+1 < len(line):
                # Code text
                if current_part:
                    parts.append(('normal', current_part))
                    current_part = ""
                
                # Find closing `
                end = line.find('`', i+1)
                if end != -1:
                    code_text = line[i+1:end]
                    parts.append(('code', code_text))
                    i = end + 1
                else:
                    current_part += line[i]
                    i += 1
            
            else:
                current_part += line[i]
                i += 1
        
        if current_part:
            parts.append(('normal', current_part))
        
        # Insert formatted parts
        for style, text in parts:
            part_start = self.content_text.index(tk.INSERT)
            self.content_text.insert(tk.INSERT, text)
            if style != 'normal':
                part_end = self.content_text.index(tk.INSERT)
                self.content_text.tag_add(style, part_start, part_end)
    
    def format_links_line(self, line: str, start_pos: str):
        """Format line with clickable links"""
        # Simple link detection [text](topic_id)
        import re
        
        parts = []
        last_end = 0
        
        for match in re.finditer(r'\[([^\]]+)\]\(([^)]+)\)', line):
            # Add text before link
            if match.start() > last_end:
                parts.append(('normal', line[last_end:match.start()]))
            
            # Add link
            link_text = match.group(1)
            link_target = match.group(2)
            parts.append(('link', link_text, link_target))
            
            last_end = match.end()
        
        # Add remaining text
        if last_end < len(line):
            parts.append(('normal', line[last_end:]))
        
        # Insert formatted parts
        for part in parts:
            part_start = self.content_text.index(tk.INSERT)
            if part[0] == 'link':
                self.content_text.insert(tk.INSERT, part[1])
                part_end = self.content_text.index(tk.INSERT)
                self.content_text.tag_add("link", part_start, part_end)
                
                # Bind click event to link
                def link_click(event, target=part[2]):
                    self.show_help_topic(target)
                
                self.content_text.tag_bind("link", "<Button-1>", link_click)
            else:
                self.content_text.insert(tk.INSERT, part[1])
    
    def setup_topic_actions(self, topic: HelpTopic):
        """Setup action buttons for the current topic"""
        # Clear existing buttons
        for widget in self.actions_frame.winfo_children():
            widget.destroy()
        
        # Add favorite button
        ttk.Button(
            self.actions_frame,
            text="⭐ Add to Favorites",
            command=lambda: self.add_to_favorites(topic)
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        # Copy link button
        ttk.Button(
            self.actions_frame,
            text="🔗 Copy Link",
            command=lambda: self.copy_topic_link(topic)
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        # Interactive features for certain topics
        if topic.interactive:
            ttk.Button(
                self.actions_frame,
                text="🚀 Start Interactive",
                command=lambda: self.start_interactive_help(topic)
            ).pack(side=tk.LEFT, padx=(0, 5))
        
        # Related topics button
        if topic.related_topics:
            ttk.Button(
                self.actions_frame,
                text="📑 Related Topics",
                command=lambda: self.show_related_topics(topic)
            ).pack(side=tk.LEFT, padx=(0, 5))
    
    def perform_search(self, event=None):
        """Perform help search"""
        query = self.search_var.get().strip()
        if not query:
            return
        
        results = self.help_system.search_help(query, max_results=10)
        self.show_search_results(query, results)
    
    def show_search_results(self, query: str, results: List[HelpTopic]):
        """Display search results"""
        self.title_label.config(text=f"Search Results for '{query}'")
        
        self.content_text.config(state=tk.NORMAL)
        self.content_text.delete(1.0, tk.END)
        
        if not results:
            self.content_text.insert(tk.INSERT, f"No results found for '{query}'.\n\n")
            self.content_text.insert(tk.INSERT, "Try:\n")
            self.content_text.insert(tk.INSERT, "• Different keywords\n")
            self.content_text.insert(tk.INSERT, "• Broader search terms\n")
            self.content_text.insert(tk.INSERT, "• Browse categories in the navigation panel\n")
        else:
            self.content_text.insert(tk.INSERT, f"Found {len(results)} results:\n\n")
            
            for i, result in enumerate(results, 1):
                # Result title (clickable)
                title_start = self.content_text.index(tk.INSERT)
                self.content_text.insert(tk.INSERT, f"{i}. {result.title}\n")
                title_end = self.content_text.index(tk.INSERT)
                self.content_text.tag_add("link", title_start, title_end)
                
                # Bind click event
                def result_click(event, topic_id=result.id):
                    self.show_help_topic(topic_id)
                
                self.content_text.tag_bind("link", "<Button-1>", result_click)
                
                # Result description
                self.content_text.insert(tk.INSERT, f"   {result.description}\n")
                self.content_text.insert(tk.INSERT, f"   Category: {result.category} | Difficulty: {result.difficulty}\n\n")
        
        self.content_text.config(state=tk.DISABLED)
        
        # Clear action buttons for search results
        for widget in self.actions_frame.winfo_children():
            widget.destroy()
    
    def show_error(self, message: str):
        """Display error message"""
        self.title_label.config(text="Error")
        self.content_text.config(state=tk.NORMAL)
        self.content_text.delete(1.0, tk.END)
        self.content_text.insert(tk.INSERT, f"Error: {message}")
        self.content_text.config(state=tk.DISABLED)
    
    def on_category_select(self, event):
        """Handle category selection"""
        selection = self.categories_tree.selection()
        if selection:
            item = selection[0]
            values = self.categories_tree.item(item, "values")
            if values:  # This is a topic
                topic_id = values[0]
                self.show_help_topic(topic_id)
    
    def on_topic_select(self, event):
        """Handle topic selection from listbox"""
        selection = self.topics_listbox.curselection()
        if selection:
            index = selection[0]
            if index % 2 == 1:  # ID entries are at odd indices
                topic_id = self.topics_listbox.get(index)
                self.show_help_topic(topic_id)
    
    def go_back(self):
        """Go back in help history"""
        if len(self.help_history) > 1:
            self.help_history.pop()  # Remove current
            previous_topic = self.help_history[-1]
            self.show_help_topic(previous_topic)
    
    def go_forward(self):
        """Go forward in help history (placeholder)"""
        # This would require a separate forward history
        pass
    
    def go_home(self):
        """Go to help home page"""
        self.show_help_topic('quick_start_wizard')
    
    def focus_search(self):
        """Focus search entry"""
        self.search_entry.focus_set()
    
    def open_documentation(self):
        """Open full documentation"""
        # Export documentation to temp directory and open
        try:
            import tempfile
            with tempfile.TemporaryDirectory() as temp_dir:
                self.doc_manager.export_documentation(temp_dir, format='html')
                index_file = Path(temp_dir) / 'index.html'
                if index_file.exists():
                    webbrowser.open(f'file://{index_file}')
        except Exception as e:
            self.show_error(f"Failed to open documentation: {e}")
    
    def update_navigation_buttons(self):
        """Update navigation button states"""
        self.back_button.config(state=tk.NORMAL if len(self.help_history) > 1 else tk.DISABLED)
    
    def update_context_label(self, topic: HelpTopic):
        """Update context label"""
        context = f"Category: {topic.category} | Difficulty: {topic.difficulty}"
        if topic.interactive:
            context += " | Interactive"
        self.context_label.config(text=context)
    
    def add_to_favorites(self, topic: HelpTopic):
        """Add topic to favorites"""
        # Simple implementation - in real app would persist favorites
        current_items = [self.favorites_listbox.get(i) for i in range(self.favorites_listbox.size())]
        if topic.title not in current_items:
            self.favorites_listbox.insert(tk.END, topic.title)
            self.favorites_listbox.insert(tk.END, topic.id)  # Hidden ID
    
    def copy_topic_link(self, topic: HelpTopic):
        """Copy topic link to clipboard"""
        link = f"blncs://help/{topic.id}"
        self.root.clipboard_clear()
        self.root.clipboard_append(link)
    
    def start_interactive_help(self, topic: HelpTopic):
        """Start interactive help session"""
        # This would launch interactive tutorials or wizards
        # For now, just show a message
        from tkinter import messagebox
        messagebox.showinfo("Interactive Help", f"Starting interactive help for: {topic.title}")
    
    def show_related_topics(self, topic: HelpTopic):
        """Show related topics dialog"""
        # Create a simple dialog showing related topics
        related_window = tk.Toplevel(self.root)
        related_window.title(f"Related to: {topic.title}")
        related_window.geometry("400x300")
        
        ttk.Label(related_window, text="Related Topics:", font=("Arial", 12, "bold")).pack(pady=10)
        
        topics_frame = ttk.Frame(related_window)
        topics_frame.pack(fill=tk.BOTH, expand=True, padx=10)
        
        for related_id in topic.related_topics:
            related_topic = self.help_system.get_help_topic(related_id)
            if related_topic:
                btn = ttk.Button(
                    topics_frame,
                    text=related_topic.title,
                    command=lambda t=related_id: [self.show_help_topic(t), related_window.destroy()]
                )
                btn.pack(fill=tk.X, pady=2)
    
    def run(self):
        """Run the help GUI"""
        if hasattr(self, 'root') and self.root.winfo_class() == 'Tk':
            self.root.mainloop()


class InteractiveHelp:
    """Main interactive help interface"""
    
    def __init__(self):
        self.help_system = get_help_system()
        self.gui = None
    
    def show_gui_help(self, parent=None, topic_id: str = None):
        """Show GUI help interface"""
        try:
            self.gui = InteractiveHelpGUI(parent)
            
            if topic_id:
                self.gui.show_help_topic(topic_id)
            
            if parent is None:
                self.gui.run()
            
            return self.gui
            
        except Exception as e:
            logger.error(f"Failed to show GUI help: {e}")
            return None
    
    def show_cli_help(self, topic: str = None, search: str = None):
        """Show CLI help"""
        if search:
            results = self.help_system.search_help(search, max_results=5)
            if results:
                return self.help_system.show_help_topic(results[0].id)
            else:
                return f"No help found for '{search}'"
        
        elif topic:
            return self.help_system.show_help_topic(topic)
        
        else:
            # Show main help menu
            return self._show_main_help_menu()
    
    def _show_main_help_menu(self) -> str:
        """Show main help menu for CLI"""
        categories = self.help_system.get_all_categories()
        
        menu = ["BLNCS Help System", "=" * 20, ""]
        menu.append("Available categories:")
        
        for category in categories:
            topics = self.help_system.get_help_by_category(category)
            menu.append(f"  {category.replace('_', ' ').title()} ({len(topics)} topics)")
        
        menu.extend([
            "",
            "Usage:",
            "  blncs help <topic>          Show specific help topic",
            "  blncs help search <query>   Search help content", 
            "  blncs help topics           List all topics",
            "  blncs help gui              Launch GUI help system",
            "",
            "Quick start: blncs help getting_started"
        ])
        
        return '\n'.join(menu)


# Global interactive help instance
_interactive_help = None


def show_help(topic: str = None, search: str = None, gui: bool = False, parent=None) -> str:
    """Show interactive help"""
    global _interactive_help
    
    if _interactive_help is None:
        _interactive_help = InteractiveHelp()
    
    if gui:
        _interactive_help.show_gui_help(parent, topic)
        return "GUI help launched"
    else:
        return _interactive_help.show_cli_help(topic, search)


if __name__ == "__main__":
    # Test interactive help
    logging.basicConfig(level=logging.INFO)
    
    print("Interactive Help Test")
    print("=" * 25)
    
    # Test CLI help
    help_interface = InteractiveHelp()
    
    # Test main menu
    main_menu = help_interface.show_cli_help()
    print("Main menu length:", len(main_menu))
    
    # Test topic help
    topic_help = help_interface.show_cli_help(topic='getting_started')
    print("Topic help length:", len(topic_help))
    
    # Test search
    search_help = help_interface.show_cli_help(search='lightning')
    print("Search help length:", len(search_help))
    
    # Test GUI (if available)
    try:
        print("\nLaunching GUI help...")
        gui_help = help_interface.show_gui_help()
        if gui_help:
            print("GUI help created successfully")
        
    except Exception as e:
        print(f"GUI help not available: {e}")
    
    print("Interactive help test completed")