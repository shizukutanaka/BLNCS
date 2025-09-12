#!/usr/bin/env python3
"""
BLNCS Help and Documentation CLI Commands
Command-line interface for accessing help system and documentation.
"""

import click
import sys
import webbrowser
from pathlib import Path
from typing import Optional

try:
    from ...docs import (
        get_documentation_manager, get_help_system, 
        show_help, generate_documentation
    )
    from ...docs.interactive_help import InteractiveHelp
except ImportError:
    # For standalone testing
    sys.path.append(str(Path(__file__).parent.parent.parent))
    from docs import (
        get_documentation_manager, get_help_system,
        show_help, generate_documentation  
    )
    from docs.interactive_help import InteractiveHelp


@click.group()
def help_cmd():
    """Help system and documentation commands"""
    pass


@help_cmd.command('show')
@click.argument('topic', required=False)
@click.option('--search', '-s', help='Search help content')
@click.option('--format', 'output_format', default='text', type=click.Choice(['text', 'markdown']))
def show_help_topic(topic: Optional[str], search: Optional[str], output_format: str):
    """Show help for a specific topic or search help content"""
    help_system = get_help_system()
    
    try:
        if search:
            # Search help content
            results = help_system.search_help(search, max_results=5)
            if results:
                click.echo(f"Found {len(results)} results for '{search}':\n")
                for i, result in enumerate(results, 1):
                    click.echo(f"{i}. {result.title} ({result.category})")
                    click.echo(f"   {result.description}\n")
                
                # Show first result
                first_result = results[0]
                click.echo(f"Showing: {first_result.title}")
                click.echo("=" * 50)
                content = help_system.show_help_topic(first_result.id)
                click.echo(content)
            else:
                click.echo(f"No help found for '{search}'")
                click.echo("\nTry:")
                click.echo("  blncs help topics    - List all available topics")
                click.echo("  blncs help categories - List help categories")
        
        elif topic:
            # Show specific topic
            content = help_system.show_help_topic(topic)
            click.echo(content)
        
        else:
            # Show main help
            content = show_help()
            click.echo(content)
    
    except Exception as e:
        click.echo(f"❌ Error showing help: {e}", err=True)
        return 1


@help_cmd.command('topics')
@click.option('--category', '-c', help='Filter by category')
@click.option('--difficulty', '-d', type=click.Choice(['beginner', 'intermediate', 'advanced']), 
              help='Filter by difficulty')
@click.option('--format', 'output_format', default='table', type=click.Choice(['table', 'list', 'json']))
def list_topics(category: Optional[str], difficulty: Optional[str], output_format: str):
    """List available help topics"""
    help_system = get_help_system()
    
    try:
        # Get all topics
        all_topics = list(help_system.help_topics.values())
        
        # Apply filters
        filtered_topics = all_topics
        
        if category:
            filtered_topics = [t for t in filtered_topics if t.category == category]
        
        if difficulty:
            filtered_topics = [t for t in filtered_topics if t.difficulty == difficulty]
        
        # Sort by category, then title
        filtered_topics.sort(key=lambda t: (t.category, t.title))
        
        if output_format == 'json':
            import json
            topics_data = [
                {
                    'id': topic.id,
                    'title': topic.title,
                    'category': topic.category,
                    'difficulty': topic.difficulty,
                    'description': topic.description,
                    'interactive': topic.interactive
                }
                for topic in filtered_topics
            ]
            click.echo(json.dumps(topics_data, indent=2))
        
        elif output_format == 'list':
            for topic in filtered_topics:
                interactive = " (interactive)" if topic.interactive else ""
                click.echo(f"{topic.id}: {topic.title}{interactive}")
        
        else:  # table format
            click.echo(f"Help Topics ({len(filtered_topics)} found)")
            click.echo("=" * 60)
            click.echo(f"{'ID':<25} {'Title':<25} {'Category':<15} {'Level'}")
            click.echo("-" * 60)
            
            for topic in filtered_topics:
                interactive = "*" if topic.interactive else " "
                click.echo(f"{interactive}{topic.id:<24} {topic.title[:24]:<25} {topic.category:<15} {topic.difficulty}")
            
            click.echo("\n* = Interactive help available")
            click.echo(f"\nUse 'blncs help show <topic_id>' to view a specific topic")
    
    except Exception as e:
        click.echo(f"❌ Error listing topics: {e}", err=True)
        return 1


@help_cmd.command('categories')
@click.option('--format', 'output_format', default='table', type=click.Choice(['table', 'list']))
def list_categories(output_format: str):
    """List help categories"""
    help_system = get_help_system()
    
    try:
        categories = help_system.get_all_categories()
        
        if output_format == 'list':
            for category in categories:
                topics = help_system.get_help_by_category(category)
                click.echo(f"{category}: {len(topics)} topics")
        else:
            click.echo("Help Categories")
            click.echo("=" * 40)
            click.echo(f"{'Category':<20} {'Topics':<10} {'Description'}")
            click.echo("-" * 40)
            
            category_descriptions = {
                'getting_started': 'Initial setup and basic usage',
                'configuration': 'System and node configuration',
                'operations': 'Day-to-day operations',
                'monitoring': 'Monitoring and alerting',
                'troubleshooting': 'Problem solving and fixes',
                'reference': 'API and command reference',
                'support': 'Support and debugging'
            }
            
            for category in categories:
                topics = help_system.get_help_by_category(category)
                description = category_descriptions.get(category, 'No description')
                click.echo(f"{category.replace('_', ' ').title():<20} {len(topics):<10} {description}")
            
            click.echo(f"\nUse 'blncs help topics --category <name>' to see topics in a category")
    
    except Exception as e:
        click.echo(f"❌ Error listing categories: {e}", err=True)
        return 1


@help_cmd.command('search')
@click.argument('query')
@click.option('--max-results', '-n', default=10, help='Maximum number of results')
@click.option('--category', '-c', help='Search within specific category')
def search_help(query: str, max_results: int, category: Optional[str]):
    """Search help content"""
    help_system = get_help_system()
    
    try:
        # Perform search
        results = help_system.search_help(query, max_results=max_results)
        
        if category:
            # Filter by category
            results = [r for r in results if r.category == category]
        
        if not results:
            click.echo(f"No results found for '{query}'")
            if category:
                click.echo(f"in category '{category}'")
            click.echo("\nSuggestions:")
            click.echo("• Try different keywords")
            click.echo("• Use broader search terms") 
            click.echo("• Check available categories with 'blncs help categories'")
            return 0
        
        click.echo(f"Found {len(results)} results for '{query}':")
        click.echo("=" * 50)
        
        for i, result in enumerate(results, 1):
            interactive = " [Interactive]" if result.interactive else ""
            click.echo(f"\n{i}. {result.title}{interactive}")
            click.echo(f"   ID: {result.id}")
            click.echo(f"   Category: {result.category} | Difficulty: {result.difficulty}")
            click.echo(f"   {result.description}")
        
        click.echo(f"\nUse 'blncs help show <topic_id>' to view a specific topic")
    
    except Exception as e:
        click.echo(f"❌ Error searching help: {e}", err=True)
        return 1


@help_cmd.command('gui')
@click.option('--topic', '-t', help='Open GUI help to specific topic')
def launch_gui_help(topic: Optional[str]):
    """Launch interactive GUI help system"""
    try:
        interactive_help = InteractiveHelp()
        
        click.echo("Launching GUI help system...")
        
        gui = interactive_help.show_gui_help(topic_id=topic)
        if gui:
            click.echo("✅ GUI help launched successfully")
        else:
            click.echo("❌ Failed to launch GUI help")
            return 1
    
    except ImportError:
        click.echo("❌ GUI help not available (tkinter not installed)")
        return 1
    except Exception as e:
        click.echo(f"❌ Error launching GUI help: {e}", err=True)
        return 1


@help_cmd.command('context')
@click.option('--command', '-c', help='Command context')
@click.option('--module', '-m', help='Module context')
@click.option('--operation', '-o', help='Operation context') 
@click.option('--error', '-e', help='Error context')
def contextual_help(command: Optional[str], module: Optional[str], 
                   operation: Optional[str], error: Optional[str]):
    """Get contextual help based on current situation"""
    help_system = get_help_system()
    
    try:
        from ...docs.help_system import HelpContext
        
        # Create context
        context = HelpContext(
            command=command,
            module=module,
            operation=operation,
            error_type=error
        )
        
        # Get contextual help
        relevant_topics = help_system.get_contextual_help(context)
        
        if not relevant_topics:
            click.echo("No contextual help found for the provided context")
            click.echo("\nTry:")
            click.echo("• 'blncs help show getting_started' for general help")
            click.echo("• 'blncs help search <your_question>' to search help")
            return 0
        
        click.echo("Contextual Help Suggestions:")
        click.echo("=" * 40)
        
        for i, topic in enumerate(relevant_topics[:5], 1):  # Show top 5
            interactive = " [Interactive]" if topic.interactive else ""
            click.echo(f"\n{i}. {topic.title}{interactive}")
            click.echo(f"   {topic.description}")
            click.echo(f"   Use: blncs help show {topic.id}")
        
        if len(relevant_topics) > 5:
            click.echo(f"\n... and {len(relevant_topics) - 5} more topics")
    
    except Exception as e:
        click.echo(f"❌ Error getting contextual help: {e}", err=True)
        return 1


@click.group()
def docs():
    """Documentation management commands"""
    pass


@docs.command('open')
@click.option('--format', 'doc_format', default='html', 
              type=click.Choice(['html', 'markdown']))
@click.option('--output', '-o', help='Output directory (default: temporary)')
def open_docs(doc_format: str, output: Optional[str]):
    """Open full documentation in browser"""
    doc_manager = get_documentation_manager()
    
    try:
        if output:
            export_path = Path(output)
        else:
            import tempfile
            temp_dir = tempfile.mkdtemp(prefix='blncs_docs_')
            export_path = Path(temp_dir)
        
        click.echo(f"Generating documentation in {doc_format} format...")
        doc_manager.export_documentation(str(export_path), format=doc_format)
        
        if doc_format == 'html':
            index_file = export_path / 'index.html'
            if index_file.exists():
                click.echo(f"Opening documentation: {index_file}")
                webbrowser.open(f'file://{index_file}')
                click.echo("✅ Documentation opened in browser")
            else:
                click.echo("❌ Failed to generate HTML documentation")
                return 1
        else:
            click.echo(f"✅ Markdown documentation generated in: {export_path}")
    
    except Exception as e:
        click.echo(f"❌ Error opening documentation: {e}", err=True)
        return 1


@docs.command('generate')
@click.option('--output', '-o', required=True, help='Output directory')
@click.option('--format', 'doc_format', default='html', 
              type=click.Choice(['html', 'markdown', 'both']))
@click.option('--include-api', is_flag=True, help='Include API documentation')
def generate_docs(output: str, doc_format: str, include_api: bool):
    """Generate documentation from code and templates"""
    try:
        click.echo("Generating documentation from code analysis...")
        
        # Generate documentation
        sections = generate_documentation(output_dir=output if doc_format != 'both' else None)
        
        click.echo(f"✅ Generated {len(sections)} documentation sections")
        
        # Export in requested format(s)
        doc_manager = get_documentation_manager()
        
        if doc_format == 'both':
            doc_manager.export_documentation(output, format='html')
            doc_manager.export_documentation(output, format='markdown')
            click.echo(f"✅ Documentation exported in both formats to: {output}")
        else:
            doc_manager.export_documentation(output, format=doc_format)
            click.echo(f"✅ Documentation exported in {doc_format} format to: {output}")
    
    except Exception as e:
        click.echo(f"❌ Error generating documentation: {e}", err=True)
        return 1


@docs.command('status')
def docs_status():
    """Show documentation system status"""
    try:
        doc_manager = get_documentation_manager()
        help_system = get_help_system()
        
        click.echo("📚 Documentation System Status")
        click.echo("=" * 40)
        
        # Documentation sections
        sections = len(doc_manager.sections)
        categories = len(doc_manager.categories)
        click.echo(f"Documentation sections: {sections}")
        click.echo(f"Categories: {categories}")
        
        # Help topics
        help_topics = len(help_system.help_topics)
        help_categories = len(help_system.topic_categories)
        interactive_topics = len([t for t in help_system.help_topics.values() if t.interactive])
        
        click.echo(f"Help topics: {help_topics}")
        click.echo(f"Help categories: {help_categories}")
        click.echo(f"Interactive topics: {interactive_topics}")
        
        # Recent help usage
        help_stats = help_system.get_help_statistics()
        click.echo(f"Help history entries: {help_stats['help_history_length']}")
        
        # System capabilities
        click.echo(f"\n🔧 System Capabilities:")
        click.echo(f"• Search functionality: ✅")
        click.echo(f"• HTML export: ✅")
        click.echo(f"• Markdown export: ✅")
        click.echo(f"• Interactive help: ✅")
        
        try:
            import tkinter
            click.echo(f"• GUI help system: ✅")
        except ImportError:
            click.echo(f"• GUI help system: ❌ (tkinter not available)")
        
        click.echo(f"\n📊 Documentation by Category:")
        for category, section_ids in doc_manager.categories.items():
            count = len(section_ids)
            click.echo(f"  {category.replace('_', ' ').title()}: {count}")
    
    except Exception as e:
        click.echo(f"❌ Error getting documentation status: {e}", err=True)
        return 1


@docs.command('search')
@click.argument('query')
@click.option('--max-results', '-n', default=5, help='Maximum results to show')
def search_docs(query: str, max_results: int):
    """Search documentation content"""
    doc_manager = get_documentation_manager()
    
    try:
        results = doc_manager.search_documentation(query, max_results=max_results)
        
        if not results:
            click.echo(f"No documentation found for '{query}'")
            return 0
        
        click.echo(f"Found {len(results)} documentation results for '{query}':")
        click.echo("=" * 60)
        
        for i, section in enumerate(results, 1):
            click.echo(f"\n{i}. {section.title}")
            click.echo(f"   ID: {section.id}")
            click.echo(f"   Category: {section.category}")
            click.echo(f"   Tags: {', '.join(section.tags)}")
            
            # Show first few lines of content
            content_lines = section.content.split('\n')[:3]
            preview = '\n'.join(content_lines)
            if len(section.content.split('\n')) > 3:
                preview += '\n...'
            click.echo(f"   Preview: {preview}")
        
        click.echo(f"\nUse 'blncs docs open' to view full documentation")
    
    except Exception as e:
        click.echo(f"❌ Error searching documentation: {e}", err=True)
        return 1


# Main help command (without subcommand)
@click.command()
@click.argument('topic', required=False)
@click.option('--search', '-s', help='Search help content')
@click.option('--gui', '-g', is_flag=True, help='Launch GUI help')
@click.option('--topics', is_flag=True, help='List all topics')
@click.option('--categories', is_flag=True, help='List categories')
def help_main(topic: Optional[str], search: Optional[str], gui: bool, 
              topics: bool, categories: bool):
    """BLNCS help system - show help topics and documentation"""
    
    if gui:
        # Launch GUI
        try:
            interactive_help = InteractiveHelp()
            interactive_help.show_gui_help(topic_id=topic)
            return 0
        except Exception as e:
            click.echo(f"❌ Cannot launch GUI help: {e}", err=True)
            return 1
    
    elif topics:
        # List topics
        from click.testing import CliRunner
        runner = CliRunner()
        result = runner.invoke(list_topics)
        click.echo(result.output)
        return result.exit_code
    
    elif categories:
        # List categories
        from click.testing import CliRunner
        runner = CliRunner()
        result = runner.invoke(list_categories)
        click.echo(result.output) 
        return result.exit_code
    
    elif search:
        # Search help
        from click.testing import CliRunner
        runner = CliRunner()
        result = runner.invoke(search_help, [search])
        click.echo(result.output)
        return result.exit_code
    
    elif topic:
        # Show specific topic
        from click.testing import CliRunner
        runner = CliRunner()
        result = runner.invoke(show_help_topic, [topic])
        click.echo(result.output)
        return result.exit_code
    
    else:
        # Show main help
        content = show_help()
        click.echo(content)
        return 0


if __name__ == '__main__':
    # Register commands for testing
    help_cmd.add_command(help_main)
    help_cmd()