"""
Enhanced CLI usability improvements for BLNCS
Implements better help system, auto-completion, user-friendly error messages,
and interactive command assistance based on competitive analysis
"""

import argparse
import cmd
import readline
import shlex
import textwrap
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass
from enum import Enum
from ..search.search_config_manager import get_search_config_manager
from ..search.advanced_search_engine import SearchManager, SearchType, SearchProvider, Language
import sys
import os


class CommandCategory(Enum):
    """CLI command categories for better organization"""
    LIGHTNING = "lightning"
    WALLET = "wallet"
    CHANNEL = "channel"
    PAYMENT = "payment"
    MONITORING = "monitoring"
    SECURITY = "security"
    SEARCH = "search"


class UserExperienceLevel(Enum):
    """User experience levels for adaptive help"""
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"


@dataclass
class CommandHelp:
    """Enhanced command help information"""
    name: str
    category: CommandCategory
    short_description: str
    long_description: str
    usage: str
    examples: List[str]
    aliases: List[str] = None
    related_commands: List[str] = None
    experience_level: UserExperienceLevel = UserExperienceLevel.INTERMEDIATE
    common_mistakes: List[str] = None
    tips: List[str] = None


class EnhancedCLI(cmd.Cmd):
    """Enhanced command-line interface with improved usability"""

    intro = textwrap.dedent("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                    BLNCS Lightning Network CLI                  ║
    ║                                                                      ║
    ║  Type 'help' or '?' for command assistance                        ║
    ║  Type 'tutorial' for interactive guidance                         ║
    ║  Type 'examples' to see common usage patterns                     ║
    ║  Type 'search "lightning network" --provider all --limit 10'      ║
    ╚══════════════════════════════════════════════════════════════╝
    """).strip()

    prompt = "blncs> "

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logger = logging.getLogger(__name__)

        # Initialize command help system
        self.command_help = self._initialize_command_help()

        # User experience tracking
        self.user_experience_level = UserExperienceLevel.INTERMEDIATE
        self.command_history = []
        self.session_commands_used = set()

        # Auto-completion setup
        self._setup_autocomplete()

        # Interactive tutorial mode
        self.tutorial_mode = False
        self.tutorial_step = 0

    def _initialize_command_help(self) -> Dict[str, CommandHelp]:
        """Initialize comprehensive command help system"""
        return {
            'connect': CommandHelp(
                name='connect',
                category=CommandCategory.LIGHTNING,
                short_description='Connect to Lightning Network node',
                long_description=textwrap.dedent("""
                Establish connection to a Lightning Network peer node.
                This command initiates a secure connection for channel operations
                and payment routing.
                """).strip(),
                usage='connect <node_uri> [--timeout SECONDS]',
                examples=[
                    'connect 03abcd...@192.168.1.1:9735',
                    'connect lightning.example.com:9735 --timeout 30'
                ],
                aliases=['c'],
                related_commands=['disconnect', 'list_peers'],
                experience_level=UserExperienceLevel.BEGINNER,
                common_mistakes=[
                    'Forgetting the port number (default is 9735)',
                    'Using incorrect node URI format'
                ],
                tips=[
                    'search "blockchain" --provider google_scholar --lang ja',
                    'Check connection status with "status" command'
                ]
            ),

            'wallet': CommandHelp(
                name='wallet',
                category=CommandCategory.WALLET,
                short_description='Wallet management commands',
                long_description='Manage wallet operations including balance, addresses, and keys',
                usage='wallet <subcommand> [options]',
                examples=[
                    'wallet balance',
                    'wallet new_address',
                    'wallet unlock --password-file /path/to/pass'
                ],
                aliases=['w'],
                related_commands=['balance', 'address'],
                experience_level=UserExperienceLevel.BEGINNER
            ),

            'channel': CommandHelp(
                name='channel',
                category=CommandCategory.CHANNEL,
                short_description='Lightning channel operations',
                long_description=textwrap.dedent("""
                Manage Lightning Network payment channels including opening,
                closing, and monitoring channel states.
                """).strip(),
                usage='channel <operation> [channel_id] [options]',
                examples=[
                    'channel open 03abcd... 1000000 --fee-rate 1000',
                    'channel close channel_123 --force',
                    'channel list --active'
                ],
                aliases=['ch'],
                related_commands=['connect', 'balance'],
                experience_level=UserExperienceLevel.INTERMEDIATE,
                tips=[
                    'Always check channel fees before opening',
                    'Use --dry-run for safe testing'
                ]
            ),

            'pay': CommandHelp(
                name='pay',
                category=CommandCategory.PAYMENT,
                short_description='Send Lightning payments',
                long_description=textwrap.dedent("""
                Send Bitcoin payments through the Lightning Network with
                automatic routing and fee optimization.
                """).strip(),
                usage='pay <invoice> [--amount SATOSHI] [--timeout SECONDS]',
                examples=[
                    'pay lnbc10n1p3...',
                    'pay invoice.txt --timeout 60',
                    'pay 03abcd... 50000 --message "Payment for service"'
                ],
                aliases=['send', 'p'],
                related_commands=['invoice', 'decode'],
                experience_level=UserExperienceLevel.BEGINNER,
                common_mistakes=[
                    'Using expired invoices',
                    'Insufficient channel balance'
                ],
                tips=[
                    'search "python tutorial" --provider github',
                    'Verify invoice amount before paying',
                    'Use --dry-run to check routing without sending'
                ]
            ),

            'invoice': CommandHelp(
                name='invoice',
                category=CommandCategory.PAYMENT,
                short_description='Create Lightning payment invoices',
                long_description='Generate payment requests for receiving Lightning payments',
                usage='invoice <amount> [--description TEXT] [--expiry SECONDS]',
                examples=[
                    'invoice 10000 --description "Coffee payment"',
                    'invoice 500000 --expiry 3600 --description "Service fee"'
                ],
                aliases=['inv', 'receive'],
                related_commands=['pay', 'decode'],
                experience_level=UserExperienceLevel.BEGINNER
            ),

            'status': CommandHelp(
                name='status',
                category=CommandCategory.MONITORING,
                short_description='Show system and network status',
                long_description=textwrap.dedent("""
                Display comprehensive status information including node health,
                channel states, wallet balance, and network connectivity.
                """).strip(),
                usage='status [--detailed] [--json]',
                examples=[
                    'status',
                    'status --detailed',
                    'status --json > status_backup.json'
                ],
                aliases=['info', 's'],
                related_commands=['monitor', 'log'],
                experience_level=UserExperienceLevel.BEGINNER
            ),

            'monitor': CommandHelp(
                name='monitor',
                category=CommandCategory.MONITORING,
                short_description='Real-time monitoring interface',
                long_description='Launch interactive real-time monitoring dashboard',
                usage='monitor [--filter PATTERN] [--interval SECONDS]',
                examples=[
                    'monitor',
                    'monitor --filter "payment|channel"',
                    'monitor --interval 5'
                ],
                aliases=['watch', 'm'],
                related_commands=['status', 'log'],
                experience_level=UserExperienceLevel.INTERMEDIATE
            ),

            'search': CommandHelp(
                name='search',
                category=CommandCategory.SEARCH,
                short_description='Multi-source intelligent search',
                long_description='Search web content, GitHub repositories, and Stack Overflow. Supports multilingual queries and intelligent result ranking.',
                usage='search <query> [--provider PROVIDER] [--lang LANGUAGE] [--limit LIMIT]',
                examples=[
                    'search "lightning network" --provider all --limit 10',
                    'search "blockchain" --provider google_scholar --lang ja'
                ],
                aliases=['s'],
                related_commands=['help'],
                experience_level=UserExperienceLevel.BEGINNER
            )
        }

    def _setup_autocomplete(self):
        """Setup enhanced auto-completion"""
        # Enable tab completion
        readline.set_completer(self.complete)
        readline.parse_and_bind('tab: complete')

        # Custom completion function
        self.completions = {
            'connect': self._complete_node_uris,
            'channel': self._complete_channel_ids,
            'pay': self._complete_invoices,
            'help': self._complete_commands,
            'search': self._complete_search_queries
        }

    def _complete_node_uris(self, text: str) -> List[str]:
        """Complete node URIs from known peers"""
        # Mock completion - in real implementation, query known peers
        known_nodes = [
            '03abcd1234567890abcdef@192.168.1.1:9735',
            'lightning.example.com:9735',
            'testnet-node.lightning.network:9735'
        ]
        return [node for node in known_nodes if node.startswith(text)]

    def _complete_channel_ids(self, text: str) -> List[str]:
        """Complete channel IDs from active channels"""
        # Mock completion - in real implementation, query active channels
        active_channels = ['channel_123', 'channel_456', 'channel_789']
        return [ch for ch in active_channels if ch.startswith(text)]

    def _complete_invoices(self, text: str) -> List[str]:
        """Complete invoice references"""
        # Mock completion
        recent_invoices = ['lnbc10n1p3...', 'lnbc50n1p4...', 'invoice_001.txt']
        return [inv for inv in recent_invoices if inv.startswith(text)]

    def _complete_commands(self, text: str) -> List[str]:
        """Complete command names"""
        commands = list(self.command_help.keys())
        return [cmd for cmd in commands if cmd.startswith(text)]

    def _complete_search_queries(self, text: str) -> List[str]:
        """Complete search queries"""
        # Mock completion
        recent_queries = ['lightning network', 'blockchain', 'bitcoin']
        return [query for query in recent_queries if query.startswith(text)]

    def complete(self, text: str, state: int) -> Optional[str]:
        """Enhanced tab completion"""
        line = readline.get_line_buffer()
        args = shlex.split(line)

        if not args:
            completions = list(self.command_help.keys())
        else:
            cmd = args[0]
            if cmd in self.completions:
                completions = self.completions[cmd](text)
            else:
                completions = [cmd for cmd in self.command_help.keys()
                             if cmd.startswith(text)]

        try:
            return completions[state]
        except IndexError:
            return None

    def default(self, line: str):
        """Handle unknown commands with helpful suggestions"""
        args = shlex.split(line)
        if not args:
            return

        cmd = args[0].lower()

        # Find similar commands
        similar = self._find_similar_commands(cmd)

        if similar:
            print(f"Command '{cmd}' not found. Did you mean:")
            for suggestion in similar[:3]:
                help_info = self.command_help.get(suggestion)
                if help_info:
                    print(f"  {suggestion}: {help_info.short_description}")
        else:
            print(f"Command '{cmd}' not found.")
            print("Type 'help' for available commands.")

    def _find_similar_commands(self, cmd: str) -> List[str]:
        """Find commands similar to the input"""
        import difflib
        commands = list(self.command_help.keys())
        return difflib.get_close_matches(cmd, commands, n=3, cutoff=0.6)

    def do_help(self, arg: str):
        """Enhanced help command"""
        if not arg:
            self._show_general_help()
        elif arg.startswith('--category'):
            # Category-based help
            category_name = arg.split('--category')[1].strip()
            try:
                category = CommandCategory[category_name.upper()]
                self._show_category_help(category)
            except KeyError:
                print(f"Unknown category: {category_name}")
        else:
            # Specific command help
            self._show_command_help(arg)

    def _show_general_help(self):
        """Show general help with categorized commands"""
        print("\nBLNCS Lightning Network CLI - Available Commands:")
        print("=" * 55)

        # Group commands by category
        by_category = {}
        for cmd_name, help_info in self.command_help.items():
            category = help_info.category.value
            if category not in by_category:
                by_category[category] = []
            by_category[category].append((cmd_name, help_info))

        for category_name, commands in by_category.items():
            print(f"\n{category_name.title()} Commands:")
            print("-" * (len(category_name) + 10))

            for cmd_name, help_info in sorted(commands):
                aliases = f" ({', '.join(help_info.aliases)})" if help_info.aliases else ""
                level_indicator = self._get_experience_indicator(help_info.experience_level)
                print(f"  {cmd_name}{aliases}{level_indicator}: {help_info.short_description}")

        print(f"\n{self._get_experience_indicator(UserExperienceLevel.BEGINNER)} Beginner")
        print(f"{self._get_experience_indicator(UserExperienceLevel.INTERMEDIATE)} Intermediate")
        print(f"{self._get_experience_indicator(UserExperienceLevel.ADVANCED)} Advanced")

        print("\nType 'help <command>' for detailed help.")
        print("Type 'examples' for common usage patterns.")
        print("Type 'tutorial' for interactive guidance.")

    def _get_experience_indicator(self, level: UserExperienceLevel) -> str:
        """Get indicator for experience level"""
        indicators = {
            UserExperienceLevel.BEGINNER: "🌱",
            UserExperienceLevel.INTERMEDIATE: "⚡",
            UserExperienceLevel.ADVANCED: "🔧"
        }
        return indicators[level]

    def _show_category_help(self, category: CommandCategory):
        """Show help for a specific category"""
        print(f"\n{category.value.title()} Commands:")
        print("=" * (len(category.value) + 10))

        commands = [cmd for cmd in self.command_help.values()
                   if cmd.category == category]

        for cmd in sorted(commands, key=lambda x: x.name):
            print(f"\n{cmd.name}:")
            print(f"  {cmd.short_description}")
            if cmd.usage:
                print(f"  Usage: {cmd.usage}")
            if cmd.examples:
                print("  Examples:")
                for example in cmd.examples[:2]:  # Show first 2 examples
                    print(f"    {example}")

    def _show_command_help(self, cmd_name: str):
        """Show detailed help for a specific command"""
        help_info = self.command_help.get(cmd_name.lower())
        if not help_info:
            print(f"No help available for command: {cmd_name}")
            similar = self._find_similar_commands(cmd_name)
            if similar:
                print("Did you mean:")
                for suggestion in similar:
                    print(f"  {suggestion}")
            return

        print(f"\nCommand: {help_info.name}")
        print("=" * (9 + len(help_info.name)))
        print(f"Category: {help_info.category.value.title()}")
        print(f"Description: {help_info.long_description}")

        if help_info.usage:
            print(f"\nUsage:\n  {help_info.usage}")

        if help_info.examples:
            print("\nExamples:")
            for example in help_info.examples:
                print(f"  {example}")

        if help_info.aliases:
            print(f"\nAliases: {', '.join(help_info.aliases)}")

        if help_info.related_commands:
            print(f"\nRelated Commands: {', '.join(help_info.related_commands)}")

        level_indicator = self._get_experience_indicator(help_info.experience_level)
        print(f"\nExperience Level: {help_info.experience_level.value.title()} {level_indicator}")

        if help_info.common_mistakes:
            print("\nCommon Mistakes to Avoid:")
            for mistake in help_info.common_mistakes:
                print(f"  • {mistake}")

        if help_info.tips:
            print("\nTips:")
            for tip in help_info.tips:
                print(f"  • {tip}")

    def do_examples(self, arg: str):
        """Show common usage examples"""
        print("\nBLNCS CLI - Common Usage Examples:")
        print("=" * 40)

        examples = [
            ("Getting Started", [
                "status  # Check system status",
                "wallet balance  # View wallet balance",
                "connect 03abcd...@node.example.com:9735  # Connect to peer"
            ]),
            ("Channel Management", [
                "channel list --active  # List active channels",
                "channel open 03abcd... 1000000  # Open channel with 1M sats",
                "channel close channel_123  # Close specific channel"
            ]),
            ("Payments", [
                "invoice 50000 --description 'Coffee'  # Create invoice",
                "pay lnbc50n1p3...  # Pay Lightning invoice",
                "pay --decode lnbc50n1p3...  # Decode invoice first"
            ]),
            ("Monitoring", [
                "monitor  # Start real-time monitoring",
                "status --detailed --json  # Export detailed status",
                "log --level DEBUG --tail 50  # View recent logs"
            ])
        ]

        for category, cmds in examples:
            print(f"\n{category}:")
            print("-" * (len(category) + 1))
            for cmd in cmds:
                print(f"  {cmd}")

        print("\nTip: Use 'tutorial' command for interactive guidance!")

    def do_tutorial(self, arg: str):
        """Interactive tutorial mode"""
        if arg.lower() in ['start', 'begin', 'yes', 'y']:
            self.tutorial_mode = True
            self.tutorial_step = 0
            self._run_tutorial_step()
        elif arg.lower() in ['stop', 'end', 'no', 'n']:
            self.tutorial_mode = False
            print("Tutorial stopped.")
        else:
            print("Interactive BLNCS Tutorial")
            print("=" * 25)
            print("This tutorial will guide you through basic BLNCS operations.")
            print("Type 'tutorial start' to begin, or 'tutorial stop' to end.")

    def _run_tutorial_step(self):
        """Run the current tutorial step"""
        steps = [
            {
                'title': 'Welcome to BLNCS',
                'content': 'BLNCS is a Lightning Network Control System. Let\'s start with checking your system status.',
                'command': 'status',
                'explanation': 'The "status" command shows your node\'s current state, including wallet balance and network connections.'
            },
            {
                'title': 'Checking Your Wallet',
                'content': 'Now let\'s check your wallet balance.',
                'command': 'wallet balance',
                'explanation': 'This shows your current Bitcoin balance available for Lightning transactions.'
            },
            {
                'title': 'Creating an Invoice',
                'content': 'Let\'s create a payment request to receive funds.',
                'command': 'invoice 10000 --description "Tutorial payment"',
                'explanation': 'This creates a Lightning invoice for 10,000 sats with a description.'
            },
            {
                'title': 'Viewing Help',
                'content': 'BLNCS has extensive help. Let\'s look at available commands.',
                'command': 'help',
                'explanation': 'The help system provides detailed information about all available commands.'
            }
        ]

        if self.tutorial_step >= len(steps):
            print("Tutorial completed! You now know the basics of BLNCS.")
            print("Type 'help' anytime for more information.")
            self.tutorial_mode = False
            return

        step = steps[self.tutorial_step]
        print(f"\nTutorial Step {self.tutorial_step + 1}: {step['title']}")
        print("-" * (17 + len(step['title'])))
        print(step['content'])
        print(f"\nTry this command: {step['command']}")
        print(f"Explanation: {step['explanation']}")
        print("\nAfter running the command, type 'next' to continue.")

    def do_next(self, arg: str):
        """Advance tutorial to next step"""
        if self.tutorial_mode:
            self.tutorial_step += 1
            self._run_tutorial_step()
        else:
            print("Tutorial not active. Type 'tutorial start' to begin.")

    def do_clear(self, arg: str):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def do_exit(self, arg: str):
        """Exit the CLI"""
        print("Thank you for using BLNCS CLI!")
        return True

    def do_quit(self, arg: str):
        """Exit the CLI (alias for exit)"""
        return self.do_exit(arg)

    # Command aliases
    do_q = do_quit
    do_EOF = do_quit  # Handle Ctrl+D

    def precmd(self, line: str):
        """Pre-command processing"""
        # Track command usage
        if line.strip():
            cmd = line.split()[0].lower()
            self.command_history.append((cmd, time.time()))
            self.session_commands_used.add(cmd)

        return line

    def postcmd(self, stop: bool, line: str):
        """Post-command processing"""
        # Auto-advance tutorial if active
        if self.tutorial_mode and not stop:
            print("\nType 'next' to continue tutorial, or enter commands normally.")

        return stop


def create_enhanced_cli_parser() -> argparse.ArgumentParser:
    """Create argument parser for enhanced CLI"""
    parser = argparse.ArgumentParser(
        description="BLNCS Enhanced Lightning Network CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          %(prog)s                          # Start interactive mode
          %(prog)s status                   # Show status and exit
          %(prog)s pay invoice.txt          # Pay invoice from file
          %(prog)s --tutorial               # Start with tutorial

        For more help, use 'help' command in interactive mode.
        """)
    )

    parser.add_argument(
        'command',
        nargs='?',
        help='Command to execute (if not provided, starts interactive mode)'
    )

    parser.add_argument(
        'args',
        nargs='*',
        help='Arguments for the command'
    )

    parser.add_argument(
        '--tutorial', '-t',
        action='store_true',
        help='Start in tutorial mode'
    )

    parser.add_argument(
        '--experience-level',
        choices=['beginner', 'intermediate', 'advanced'],
        default='intermediate',
        help='Set user experience level for help system'
    )

    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )

    return parser


def main():
    """Main CLI entry point"""
    parser = create_enhanced_cli_parser()
    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Create CLI instance
    cli = EnhancedCLI()

    # Set experience level
    cli.user_experience_level = UserExperienceLevel(args.experience_level)

    if args.tutorial:
        cli.tutorial_mode = True
        cli.tutorial_step = 0

    if args.command:
        # Execute single command
        line = f"{args.command} {' '.join(args.args)}"
        cli.onecmd(line)
    else:
        # Start interactive mode
        try:
            cli.cmdloop()
        except KeyboardInterrupt:
            print("\nInterrupted by user. Exiting...")
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)


if __name__ == '__main__':
    main()
