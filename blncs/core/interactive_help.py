#!/usr/bin/env python3
"""
BLNCS Interactive Help System
Provides interactive assistance and command exploration
"""

import os
import re
import json
import logging
from typing import Dict, Any, List, Optional, Callable, Union
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
import threading
import readline
import cmd
import shlex

logger = logging.getLogger(__name__)


@dataclass
class HelpTopic:
    """Help topic structure"""
    name: str
    title: str
    description: str
    category: str
    content: str
    examples: List[str] = field(default_factory=list)
    related_topics: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class CommandSuggestion:
    """Command suggestion structure"""
    command: str
    description: str
    confidence: float
    category: str
    examples: List[str] = field(default_factory=list)


class InteractiveHelp:
    """Interactive help and command assistance system"""

    def __init__(self, help_data_path: Optional[str] = None):
        self.help_data_path = help_data_path or os.path.join(os.path.dirname(__file__), 'help_data.json')
        self.topics: Dict[str, HelpTopic] = {}
        self.command_patterns: Dict[str, List[str]] = {}
        self.context_suggestions: Dict[str, List[CommandSuggestion]] = {}
        self.session_history: List[str] = []
        self.user_preferences = {
            'detail_level': 'normal',  # brief, normal, detailed
            'show_examples': True,
            'auto_suggest': True,
            'language': 'en'
        }

        # Initialize help system
        self._load_help_data()
        self._initialize_command_patterns()
        self._initialize_context_suggestions()

    def _load_help_data(self):
        """Load help topics from data file"""
        try:
            if os.path.exists(self.help_data_path):
                with open(self.help_data_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                for topic_data in data.get('topics', []):
                    topic = HelpTopic(**topic_data)
                    self.topics[topic.name] = topic

                logger.info(f"Loaded {len(self.topics)} help topics")
            else:
                self._create_default_help_topics()
        except Exception as e:
            logger.error(f"Failed to load help data: {e}")
            self._create_default_help_topics()

    def _create_default_help_topics(self):
        """Create default help topics for BLNCS"""
        default_topics = [
            HelpTopic(
                name="getting_started",
                title="Getting Started with BLNCS",
                description="Basic introduction to BLNCS and initial setup",
                category="basics",
                content="""
BLNCS (Bitcoin Lightning Network Control System) is a comprehensive management platform for Lightning Network operations.

Key Features:
• Channel management and optimization
• Payment routing and fee management
• Real-time monitoring and analytics
• Automated rebalancing
• Security and backup management

Quick Start:
1. Configure your Lightning Network connection
2. Set up database and security settings
3. Start the API server
4. Access the web interface
                """,
                examples=[
                    "blncs config init --network testnet",
                    "blncs server start --port 3000",
                    "blncs status"
                ],
                tags=["basics", "setup", "introduction"]
            ),
            HelpTopic(
                name="channel_management",
                title="Channel Management",
                description="Managing Lightning Network channels effectively",
                category="channels",
                content="""
Channel management involves creating, monitoring, and optimizing payment channels.

Key Concepts:
• Channel capacity and liquidity
• Fee rates and routing policies
• Channel rebalancing
• Channel health monitoring

Best Practices:
• Maintain balanced channels for optimal routing
• Monitor channel fees regularly
• Use automated rebalancing when possible
• Close underperforming channels
                """,
                examples=[
                    "blncs channels list --format table",
                    "blncs channels open --peer <pubkey> --amount 1000000",
                    "blncs channels rebalance --channel <chan_id>",
                    "blncs channels close --channel <chan_id> --force"
                ],
                tags=["channels", "liquidity", "routing", "fees"]
            ),
            HelpTopic(
                name="security",
                title="Security and Authentication",
                description="Security features and authentication methods",
                category="security",
                content="""
BLNCS provides multiple layers of security:

Authentication Methods:
• Password-based authentication
• Multi-factor authentication (MFA/TOTP)
• Zero-knowledge proof authentication
• API key authentication

Security Features:
• Encrypted configuration storage
• Dynamic firewall rules
• Rate limiting and DDoS protection
• Audit logging and monitoring

Recommendations:
• Enable MFA for all admin accounts
• Use strong, unique passwords
• Regularly rotate API keys
• Monitor security events
                """,
                examples=[
                    "blncs auth setup-mfa",
                    "blncs security enable-firewall",
                    "blncs audit logs --severity high",
                    "blncs config encrypt-secrets"
                ],
                tags=["security", "authentication", "mfa", "encryption"]
            ),
            HelpTopic(
                name="performance",
                title="Performance Monitoring and Optimization",
                description="Monitoring system performance and optimization techniques",
                category="performance",
                content="""
BLNCS includes comprehensive performance monitoring:

Monitoring Features:
• CPU and memory usage tracking
• GPU utilization (if available)
• Network I/O statistics
• Memory leak detection
• Connection pool monitoring

Optimization Techniques:
• Asynchronous processing
• Connection pooling
• Caching strategies
• Background cleanup tasks

Performance Tips:
• Monitor resource usage regularly
• Enable GPU acceleration when available
• Configure appropriate connection limits
• Use caching for frequently accessed data
                """,
                examples=[
                    "blncs performance monitor --real-time",
                    "blncs performance optimize --target memory",
                    "blncs cache stats",
                    "blncs connections pool-status"
                ],
                tags=["performance", "monitoring", "optimization", "caching"]
            ),
            HelpTopic(
                name="api_usage",
                title="API Usage and Integration",
                description="Using BLNCS API for integration and automation",
                category="api",
                content="""
BLNCS provides a RESTful API for programmatic access:

API Endpoints:
• /api/v1/channels - Channel management
• /api/v1/payments - Payment operations
• /api/v1/peers - Peer management
• /api/v1/info - System information

Authentication:
• Use JWT tokens for API access
• Include token in Authorization header
• API keys for service accounts

Integration Examples:
• Web dashboard integration
• Mobile app connectivity
• Trading bot integration
• Monitoring and alerting systems
                """,
                examples=[
                    "curl -H 'Authorization: Bearer <token>' http://localhost:3000/api/v1/info",
                    "curl -X POST -H 'Authorization: Bearer <token>' -d '{\"amount\": 10000}' http://localhost:3000/api/v1/payments/send",
                    "python -c \"import requests; requests.get('http://localhost:3000/api/v1/channels', headers={'Authorization': 'Bearer <token>'})\""
                ],
                tags=["api", "integration", "rest", "automation"]
            ),
            HelpTopic(
                name="troubleshooting",
                title="Troubleshooting Common Issues",
                description="Solutions for common problems and error conditions",
                category="troubleshooting",
                content="""
Common Issues and Solutions:

Connection Problems:
• Check Lightning Network daemon status
• Verify network connectivity
• Check firewall settings
• Review TLS certificates

Performance Issues:
• Monitor resource usage
• Check database connections
• Review cache configuration
• Enable performance profiling

Security Issues:
• Verify authentication settings
• Check firewall rules
• Review audit logs
• Update security policies

Configuration Issues:
• Validate configuration files
• Check environment variables
• Review service dependencies
• Use auto-detection features
                """,
                examples=[
                    "blncs diagnose connection",
                    "blncs logs tail --filter error",
                    "blncs config validate",
                    "blncs performance profile --duration 60"
                ],
                tags=["troubleshooting", "debugging", "logs", "diagnostics"]
            )
        ]

        for topic in default_topics:
            self.topics[topic.name] = topic

        # Save default topics
        self._save_help_data()

    def _save_help_data(self):
        """Save help topics to data file"""
        try:
            data = {
                'topics': [topic.__dict__ for topic in self.topics.values()],
                'last_updated': datetime.now().isoformat()
            }

            os.makedirs(os.path.dirname(self.help_data_path), exist_ok=True)
            with open(self.help_data_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

        except Exception as e:
            logger.error(f"Failed to save help data: {e}")

    def _initialize_command_patterns(self):
        """Initialize command pattern matching"""
        self.command_patterns = {
            'channel': [
                r'channel.*list',
                r'channel.*open',
                r'channel.*close',
                r'channel.*rebalance',
                r'channel.*info'
            ],
            'payment': [
                r'payment.*send',
                r'payment.*receive',
                r'payment.*invoice',
                r'payment.*decode'
            ],
            'peer': [
                r'peer.*list',
                r'peer.*connect',
                r'peer.*disconnect',
                r'peer.*info'
            ],
            'config': [
                r'config.*get',
                r'config.*set',
                r'config.*validate',
                r'config.*auto-detect'
            ],
            'security': [
                r'security.*enable',
                r'security.*disable',
                r'auth.*setup',
                r'firewall.*add'
            ],
            'performance': [
                r'performance.*monitor',
                r'performance.*optimize',
                r'cache.*stats',
                r'memory.*usage'
            ],
            'help': [
                r'help.*\w+',
                r'\?.*',
                r'man.*\w+'
            ]
        }

    def _initialize_context_suggestions(self):
        """Initialize context-aware command suggestions"""
        self.context_suggestions = {
            'new_user': [
                CommandSuggestion(
                    command="blncs config init",
                    description="Initialize BLNCS configuration",
                    confidence=0.9,
                    category="setup",
                    examples=["blncs config init --network testnet"]
                ),
                CommandSuggestion(
                    command="blncs help getting_started",
                    description="Read getting started guide",
                    confidence=0.8,
                    category="help",
                    examples=["blncs help getting_started"]
                ),
                CommandSuggestion(
                    command="blncs server start",
                    description="Start the BLNCS server",
                    confidence=0.7,
                    category="server",
                    examples=["blncs server start --port 3000"]
                )
            ],
            'channel_management': [
                CommandSuggestion(
                    command="blncs channels list",
                    description="List all channels",
                    confidence=0.9,
                    category="channels",
                    examples=["blncs channels list --format table"]
                ),
                CommandSuggestion(
                    command="blncs channels rebalance",
                    description="Rebalance channel liquidity",
                    confidence=0.8,
                    category="channels",
                    examples=["blncs channels rebalance --channel <id>"]
                ),
                CommandSuggestion(
                    command="blncs channels optimize",
                    description="Optimize channel fees and policies",
                    confidence=0.7,
                    category="channels",
                    examples=["blncs channels optimize --strategy balanced"]
                )
            ],
            'troubleshooting': [
                CommandSuggestion(
                    command="blncs diagnose all",
                    description="Run full system diagnosis",
                    confidence=0.9,
                    category="diagnostics",
                    examples=["blncs diagnose all --verbose"]
                ),
                CommandSuggestion(
                    command="blncs logs tail",
                    description="View recent logs",
                    confidence=0.8,
                    category="logs",
                    examples=["blncs logs tail --filter error"]
                ),
                CommandSuggestion(
                    command="blncs performance monitor",
                    description="Monitor system performance",
                    confidence=0.7,
                    category="performance",
                    examples=["blncs performance monitor --real-time"]
                )
            ]
        }

    def get_topic(self, topic_name: str) -> Optional[HelpTopic]:
        """Get a specific help topic"""
        return self.topics.get(topic_name)

    def search_topics(self, query: str, category: Optional[str] = None) -> List[HelpTopic]:
        """Search help topics by query"""
        query_lower = query.lower()
        results = []

        for topic in self.topics.values():
            if category and topic.category != category:
                continue

            # Search in title, description, content, and tags
            searchable_text = f"{topic.title} {topic.description} {topic.content} {' '.join(topic.tags)}".lower()

            if query_lower in searchable_text:
                results.append(topic)

        return results

    def get_related_topics(self, topic_name: str) -> List[HelpTopic]:
        """Get related topics for a given topic"""
        if topic_name not in self.topics:
            return []

        topic = self.topics[topic_name]
        related = []

        for related_name in topic.related_topics:
            if related_name in self.topics:
                related.append(self.topics[related_name])

        return related

    def suggest_commands(self, context: str = "", partial_command: str = "") -> List[CommandSuggestion]:
        """Suggest commands based on context and partial input"""
        suggestions = []

        # Context-based suggestions
        if context in self.context_suggestions:
            suggestions.extend(self.context_suggestions[context])

        # Pattern-based suggestions
        if partial_command:
            for category, patterns in self.command_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, partial_command, re.IGNORECASE):
                        # Add relevant suggestions for this category
                        if category == 'channel':
                            suggestions.extend([
                                CommandSuggestion("blncs channels list", "List all channels", 0.8, "channels"),
                                CommandSuggestion("blncs channels info <id>", "Get channel information", 0.7, "channels")
                            ])
                        elif category == 'help':
                            suggestions.extend([
                                CommandSuggestion("blncs help topics", "List all help topics", 0.9, "help"),
                                CommandSuggestion("blncs help search <query>", "Search help topics", 0.8, "help")
                            ])

        # Remove duplicates and sort by confidence
        seen = set()
        unique_suggestions = []
        for suggestion in suggestions:
            if suggestion.command not in seen:
                unique_suggestions.append(suggestion)
                seen.add(suggestion.command)

        return sorted(unique_suggestions, key=lambda x: x.confidence, reverse=True)[:10]

    def get_command_help(self, command: str) -> Optional[str]:
        """Get help for a specific command"""
        # Try to match command to help topics
        command_lower = command.lower()

        # Direct topic matches
        if command_lower in self.topics:
            return self._format_topic_help(self.topics[command_lower])

        # Search for command in examples
        for topic in self.topics.values():
            for example in topic.examples:
                if command in example:
                    return self._format_topic_help(topic)

        return None

    def _format_topic_help(self, topic: HelpTopic) -> str:
        """Format a help topic for display"""
        output = []
        output.append(f"# {topic.title}")
        output.append(f"**Category:** {topic.category}")
        output.append(f"**Tags:** {', '.join(topic.tags)}")
        output.append("")
        output.append(topic.description)
        output.append("")
        output.append("## Content")
        output.append(topic.content.strip())

        if topic.examples:
            output.append("")
            output.append("## Examples")
            for example in topic.examples:
                output.append(f"```bash\n{example}\n```")

        if topic.related_topics:
            output.append("")
            output.append("## Related Topics")
            for related in topic.related_topics:
                if related in self.topics:
                    output.append(f"- **{self.topics[related].title}** (`{related}`)")

        return "\n".join(output)

    def get_topics_by_category(self, category: str) -> List[HelpTopic]:
        """Get all topics in a category"""
        return [topic for topic in self.topics.values() if topic.category == category]

    def get_all_categories(self) -> List[str]:
        """Get all available categories"""
        return list(set(topic.category for topic in self.topics.values()))

    def add_topic(self, topic: HelpTopic):
        """Add a new help topic"""
        self.topics[topic.name] = topic
        self._save_help_data()

    def update_topic(self, topic_name: str, updates: Dict[str, Any]):
        """Update an existing help topic"""
        if topic_name in self.topics:
            topic = self.topics[topic_name]
            for key, value in updates.items():
                if hasattr(topic, key):
                    setattr(topic, key, value)
            topic.last_updated = datetime.now().isoformat()
            self._save_help_data()

    def export_help(self, format_type: str = 'markdown') -> str:
        """Export all help topics"""
        if format_type == 'markdown':
            output = ["# BLNCS Help Documentation\n"]

            for category in self.get_all_categories():
                output.append(f"## {category.title()}\n")

                for topic in self.get_topics_by_category(category):
                    output.append(f"### {topic.title}")
                    output.append(f"**{topic.description}**")
                    output.append("")
                    output.append(topic.content)
                    output.append("")

                    if topic.examples:
                        output.append("**Examples:**")
                        for example in topic.examples:
                            output.append(f"- `{example}`")
                        output.append("")

            return "\n".join(output)

        return "Unsupported format"


class InteractiveHelpShell(cmd.Cmd):
    """Interactive help shell"""

    intro = """
BLNCS Interactive Help System
Type 'help' or '?' to list commands.
Type 'quit' or 'exit' to exit.
"""
    prompt = "blncs-help> "

    def __init__(self, help_system: InteractiveHelp):
        super().__init__()
        self.help_system = help_system

    def do_topics(self, arg):
        """List all help topics: topics [category]"""
        if arg:
            topics = self.help_system.get_topics_by_category(arg)
        else:
            topics = list(self.help_system.topics.values())

        if not topics:
            print(f"No topics found for category: {arg}")
            return

        print(f"\nAvailable topics ({len(topics)}):\n")
        current_category = None

        for topic in sorted(topics, key=lambda x: (x.category, x.title)):
            if topic.category != current_category:
                print(f"[{topic.category.upper()}]")
                current_category = topic.category

            print(f"  {topic.name:20} - {topic.title}")

    def do_search(self, arg):
        """Search help topics: search <query> [category]"""
        if not arg:
            print("Usage: search <query> [category]")
            return

        args = shlex.split(arg)
        query = args[0]
        category = args[1] if len(args) > 1 else None

        results = self.help_system.search_topics(query, category)

        if not results:
            print(f"No topics found for query: {query}")
            return

        print(f"\nSearch results for '{query}' ({len(results)} found):\n")

        for topic in results:
            print(f"  {topic.name:20} [{topic.category}] {topic.title}")
            print(f"    {topic.description[:100]}{'...' if len(topic.description) > 100 else ''}")
            print()

    def do_show(self, arg):
        """Show detailed help for a topic: show <topic_name>"""
        if not arg:
            print("Usage: show <topic_name>")
            return

        topic = self.help_system.get_topic(arg)
        if not topic:
            print(f"Topic not found: {arg}")
            # Try searching
            results = self.help_system.search_topics(arg)
            if results:
                print("Did you mean:")
                for result in results[:3]:
                    print(f"  {result.name} - {result.title}")
            return

        print(self.help_system._format_topic_help(topic))

    def do_suggest(self, arg):
        """Get command suggestions: suggest [context] [partial_command]"""
        context = "general"
        partial = ""

        if arg:
            args = shlex.split(arg)
            if len(args) >= 1:
                context = args[0]
            if len(args) >= 2:
                partial = args[1]

        suggestions = self.help_system.suggest_commands(context, partial)

        if not suggestions:
            print(f"No suggestions found for context: {context}")
            return

        print(f"\nCommand suggestions for '{context}':\n")

        for suggestion in suggestions:
            print(f"  {suggestion.command}")
            print(f"    {suggestion.description}")
            if suggestion.examples:
                print(f"    Example: {suggestion.examples[0]}")
            print()

    def do_categories(self, arg):
        """List all help categories"""
        categories = self.help_system.get_all_categories()
        print(f"\nAvailable categories ({len(categories)}):\n")
        for category in sorted(categories):
            topic_count = len(self.help_system.get_topics_by_category(category))
            print(f"  {category:15} ({topic_count} topics)")

    def do_help(self, arg):
        """Show help for commands or topics"""
        if arg:
            # Try to show topic help first
            topic = self.help_system.get_topic(arg)
            if topic:
                print(self.help_system._format_topic_help(topic))
            else:
                # Show command help
                print(self.default(f"help {arg}"))
        else:
            print("""
BLNCS Interactive Help Commands:

Navigation:
  topics [category]     - List help topics
  categories           - List all categories
  search <query>       - Search help topics
  show <topic>         - Show detailed topic help

Assistance:
  suggest [context]    - Get command suggestions
  help [command]       - Show command help

System:
  quit/exit           - Exit help system
  history             - Show command history
            """)

    def do_quit(self, arg):
        """Exit the help system"""
        print("Goodbye!")
        return True

    def do_exit(self, arg):
        """Exit the help system"""
        return self.do_quit(arg)

    def do_history(self, arg):
        """Show command history"""
        if not self.help_system.session_history:
            print("No commands in history.")
            return

        print("\nCommand history:\n")
        for i, cmd in enumerate(self.help_system.session_history[-10:], 1):
            print(f"  {i:2d}. {cmd}")

    def default(self, line):
        """Handle unknown commands"""
        # Try to interpret as topic name
        topic = self.help_system.get_topic(line.strip())
        if topic:
            print(self.help_system._format_topic_help(topic))
            return

        # Try command help
        cmd_help = self.help_system.get_command_help(line.strip())
        if cmd_help:
            print(cmd_help)
            return

        print(f"Unknown command or topic: {line}")
        print("Type 'help' for available commands or 'topics' for help topics.")

    def precmd(self, line):
        """Hook executed before command processing"""
        if line.strip():
            self.help_system.session_history.append(line.strip())
        return line


# Global help system instance
_help_system: Optional[InteractiveHelp] = None


def get_help_system() -> InteractiveHelp:
    """Get or create global help system instance"""
    global _help_system
    if _help_system is None:
        _help_system = InteractiveHelp()
    return _help_system


def start_interactive_help():
    """Start the interactive help shell"""
    help_system = get_help_system()
    shell = InteractiveHelpShell(help_system)

    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        print("\nGoodbye!")
    except Exception as e:
        logger.error(f"Help system error: {e}")


if __name__ == "__main__":
    start_interactive_help()
