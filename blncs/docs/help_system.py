#!/usr/bin/env python3
"""
BLNCS Interactive Help System
Context-aware help and guidance system with interactive tutorials.
"""

import os
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from threading import Lock
import re

try:
    from .documentation_manager import get_documentation_manager, DocumentSection
except ImportError:
    # For standalone testing
    import sys
    sys.path.append(str(Path(__file__).parent))
    from documentation_manager import get_documentation_manager, DocumentSection

logger = logging.getLogger(__name__)


@dataclass
class HelpTopic:
    """A help topic with contextual information"""
    id: str
    title: str
    description: str
    content: str
    category: str
    keywords: List[str] = field(default_factory=list)
    related_topics: List[str] = field(default_factory=list)
    difficulty: str = 'beginner'
    interactive: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'content': self.content,
            'category': self.category,
            'keywords': self.keywords,
            'related_topics': self.related_topics,
            'difficulty': self.difficulty,
            'interactive': self.interactive
        }


@dataclass
class HelpContext:
    """Context information for contextual help"""
    command: Optional[str] = None
    module: Optional[str] = None
    operation: Optional[str] = None
    error_type: Optional[str] = None
    user_level: str = 'beginner'
    recent_commands: List[str] = field(default_factory=list)
    
    def matches(self, topic: HelpTopic) -> int:
        """Calculate how well this context matches a help topic (0-100)"""
        score = 0
        
        # Command matching
        if self.command and self.command in topic.keywords:
            score += 30
        
        # Module matching
        if self.module and self.module in topic.keywords:
            score += 20
        
        # Operation matching  
        if self.operation and self.operation in topic.keywords:
            score += 25
        
        # Error type matching
        if self.error_type and self.error_type in topic.keywords:
            score += 40
        
        # Difficulty matching
        if topic.difficulty == self.user_level:
            score += 10
        elif topic.difficulty == 'beginner' and self.user_level != 'advanced':
            score += 5
        
        # Recent command relevance
        for recent_cmd in self.recent_commands[-3:]:  # Last 3 commands
            if recent_cmd in topic.keywords:
                score += 5
        
        return min(score, 100)


class HelpSystem:
    """Interactive help system with context awareness"""
    
    def __init__(self):
        self.documentation_manager = get_documentation_manager()
        self.help_topics: Dict[str, HelpTopic] = {}
        self.topic_categories: Dict[str, List[str]] = {}
        self.current_context = HelpContext()
        self.help_history: List[str] = []
        self.lock = Lock()
        
        # Initialize help system
        self.initialize_help_topics()
    
    def initialize_help_topics(self):
        """Initialize help topics from documentation and add interactive elements"""
        logger.info("Initializing help system")
        
        # Load from documentation
        self.load_from_documentation()
        
        # Add interactive help topics
        self.create_interactive_topics()
        
        # Build topic relationships
        self.build_topic_relationships()
        
        logger.info(f"Help system initialized with {len(self.help_topics)} topics")
    
    def load_from_documentation(self):
        """Load help topics from documentation manager"""
        for section_id, section in self.documentation_manager.sections.items():
            # Convert documentation section to help topic
            topic = HelpTopic(
                id=section.id,
                title=section.title,
                description=self.extract_description(section.content),
                content=section.content,
                category=section.category,
                keywords=section.tags + [section.title.lower()],
                difficulty=section.difficulty
            )
            
            self.add_help_topic(topic)
    
    def extract_description(self, content: str) -> str:
        """Extract description from content"""
        # Find first paragraph or first few sentences
        lines = content.split('\n')
        description_lines = []
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                # Remove markdown formatting
                clean_line = re.sub(r'[*_`#]+', '', line)
                description_lines.append(clean_line)
                
                # Stop at first paragraph or after 2 sentences
                if len(description_lines) >= 2 or line.endswith('.'):
                    break
        
        description = ' '.join(description_lines)
        return description[:200] + ('...' if len(description) > 200 else '')
    
    def create_interactive_topics(self):
        """Create interactive help topics for common tasks"""
        
        # Quick Start Wizard
        quick_start = HelpTopic(
            id='quick_start_wizard',
            title='Quick Start Wizard',
            description='Interactive wizard to get you started with BLNCS quickly',
            content='''# Quick Start Wizard

This interactive wizard will help you set up BLNCS step by step.

## Step 1: Check System Requirements

Let me check if your system meets the requirements...

**System Requirements:**
- Python 3.8 or higher ✓
- 4GB RAM minimum ✓ 
- 10GB disk space ✓
- Network connectivity ✓

## Step 2: Lightning Node Setup

Do you have a Lightning Network node running?

**Options:**
1. **I have LND running** → [Configure LND Connection](lnd_setup)
2. **I have Core Lightning running** → [Configure CLN Connection](cln_setup)  
3. **I don't have a node** → [Install Lightning Node](node_installation)
4. **I want to use testnet** → [Testnet Setup](testnet_setup)

## Step 3: Basic Configuration

Let's configure BLNCS for your environment...

```bash
# Run the setup wizard
blncs setup --interactive

# Or configure manually
blncs config set node.host localhost
blncs config set node.port 10009
```

## Step 4: First Connection

Now let's test the connection...

```bash
# Test connection
blncs node info

# If successful, you should see your node information
```

## Step 5: Explore Features

You're ready to explore BLNCS features:

- **Wallet Operations**: [Wallet Guide](wallet_operations)
- **Channel Management**: [Channel Guide](channel_management)  
- **Monitoring Setup**: [Monitoring Guide](monitoring_setup)

**Need help?** Type `blncs help` anytime for assistance!
''',
            category='getting_started',
            keywords=['setup', 'wizard', 'start', 'begin', 'install'],
            interactive=True,
            difficulty='beginner'
        )
        
        # Command Helper
        command_helper = HelpTopic(
            id='command_helper',
            title='Command Helper',
            description='Get help with specific BLNCS commands',
            content='''# Command Helper

Get detailed help for any BLNCS command.

## Usage

```bash
# Get help for any command
blncs help <command>

# Examples:
blncs help wallet
blncs help channels open
blncs help monitoring start
```

## Common Commands

### Node Commands
- `blncs node info` - Show node information
- `blncs node connect` - Connect to a peer
- `blncs node peers` - List connected peers

### Wallet Commands  
- `blncs wallet balance` - Show wallet balance
- `blncs wallet invoice` - Create an invoice
- `blncs wallet pay` - Pay an invoice

### Channel Commands
- `blncs channels list` - List all channels
- `blncs channels open` - Open a new channel
- `blncs channels close` - Close a channel

### Monitoring Commands
- `blncs monitoring start` - Start monitoring
- `blncs monitoring dashboard` - Launch dashboard
- `blncs monitoring status` - Check status

## Interactive Help

For interactive help with commands:

```bash
# Interactive command builder
blncs help interactive

# Command examples and templates
blncs help examples <command>

# Step-by-step tutorials
blncs help tutorial <topic>
```

## Get More Help

- Type `blncs help topics` for all available help topics
- Type `blncs help search <query>` to search help content
- Type `blncs help context` for context-aware help
''',
            category='reference',
            keywords=['command', 'help', 'usage', 'cli'],
            interactive=True,
            difficulty='beginner'
        )
        
        # Troubleshooting Assistant
        troubleshooting_assistant = HelpTopic(
            id='troubleshooting_assistant',
            title='Troubleshooting Assistant',
            description='Interactive troubleshooting for common problems',
            content='''# Troubleshooting Assistant

Let me help you diagnose and fix common issues.

## Quick Diagnosis

**What problem are you experiencing?**

1. **Can't connect to Lightning node** → [Connection Issues](connection_troubleshooting)
2. **Payments are failing** → [Payment Issues](payment_troubleshooting)  
3. **Channels won't open** → [Channel Issues](channel_troubleshooting)
4. **GUI not working** → [GUI Issues](gui_troubleshooting)
5. **Performance problems** → [Performance Issues](performance_troubleshooting)
6. **Other issues** → [General Diagnostics](general_diagnostics)

## Diagnostic Tools

```bash
# Run comprehensive diagnostics
blncs diagnostics --full

# Check system status
blncs status

# Test connections
blncs connection test

# View recent logs
blncs logs --tail 50
```

## Step-by-Step Diagnosis

### Step 1: Basic Checks

Let's start with basic system checks...

```bash
# Check BLNCS version
blncs version

# Verify configuration
blncs config validate

# Check Lightning node status
blncs node info
```

### Step 2: Connection Testing

Testing your Lightning node connection...

```bash
# Test node connectivity
ping <your_node_host>

# Check port accessibility
telnet <your_node_host> <port>

# Verify certificates
blncs connection verify
```

### Step 3: Log Analysis

Analyzing recent activity...

```bash
# Check for errors
blncs logs --level ERROR --tail 20

# Look for warnings
blncs logs --level WARN --tail 50

# Filter by component
blncs logs --component lightning --tail 30
```

### Step 4: Resolution

Based on the diagnosis, here are suggested solutions...

**Common Fixes:**
- Certificate/permission issues
- Network connectivity problems
- Configuration errors
- Resource constraints

## Get Additional Help

If the assistant can't resolve your issue:

1. **Generate Support Bundle**: `blncs support bundle`
2. **Check Documentation**: `blncs docs search <issue>`
3. **Community Support**: Visit our community forums
4. **Professional Support**: Contact our support team

**Emergency Recovery:** `blncs --recovery-mode`
''',
            category='support',
            keywords=['troubleshooting', 'problem', 'issue', 'fix', 'debug', 'error'],
            interactive=True,
            difficulty='beginner'
        )
        
        # Add interactive topics
        self.add_help_topic(quick_start)
        self.add_help_topic(command_helper)
        self.add_help_topic(troubleshooting_assistant)
    
    def build_topic_relationships(self):
        """Build relationships between help topics"""
        for topic_id, topic in self.help_topics.items():
            # Find related topics based on keywords and category
            related = []
            
            for other_id, other_topic in self.help_topics.items():
                if other_id == topic_id:
                    continue
                
                # Same category topics are related
                if other_topic.category == topic.category:
                    related.append(other_id)
                    continue
                
                # Topics with common keywords are related
                common_keywords = set(topic.keywords) & set(other_topic.keywords)
                if len(common_keywords) >= 2:
                    related.append(other_id)
            
            # Update topic with related topics (limit to 5)
            topic.related_topics = related[:5]
    
    def add_help_topic(self, topic: HelpTopic):
        """Add a help topic"""
        with self.lock:
            self.help_topics[topic.id] = topic
            
            # Update categories
            if topic.category not in self.topic_categories:
                self.topic_categories[topic.category] = []
            if topic.id not in self.topic_categories[topic.category]:
                self.topic_categories[topic.category].append(topic.id)
    
    def get_help_topic(self, topic_id: str) -> Optional[HelpTopic]:
        """Get a specific help topic"""
        return self.help_topics.get(topic_id)
    
    def search_help(self, query: str, max_results: int = 5) -> List[HelpTopic]:
        """Search help topics"""
        query_words = query.lower().split()
        results = []
        
        for topic in self.help_topics.values():
            score = 0
            
            # Title matching (highest priority)
            title_lower = topic.title.lower()
            for word in query_words:
                if word in title_lower:
                    score += 20
            
            # Keyword matching
            for keyword in topic.keywords:
                for word in query_words:
                    if word in keyword.lower():
                        score += 15
            
            # Description matching  
            description_lower = topic.description.lower()
            for word in query_words:
                if word in description_lower:
                    score += 10
            
            # Content matching (lower priority due to length)
            content_lower = topic.content.lower()
            for word in query_words:
                if word in content_lower:
                    score += 1  # Low weight to avoid overwhelming results
            
            # Context matching bonus
            context_score = self.current_context.matches(topic)
            score += context_score * 0.3  # 30% weight for context
            
            if score > 0:
                results.append((topic, score))
        
        # Sort by score and return top results
        results.sort(key=lambda x: x[1], reverse=True)
        return [topic for topic, score in results[:max_results]]
    
    def get_contextual_help(self, context: Optional[HelpContext] = None) -> List[HelpTopic]:
        """Get help topics relevant to current context"""
        if context:
            self.current_context = context
        
        # Find topics that match current context
        relevant_topics = []
        
        for topic in self.help_topics.values():
            match_score = self.current_context.matches(topic)
            if match_score > 20:  # Minimum relevance threshold
                relevant_topics.append((topic, match_score))
        
        # Sort by relevance
        relevant_topics.sort(key=lambda x: x[1], reverse=True)
        
        # Return top 10 most relevant topics
        return [topic for topic, score in relevant_topics[:10]]
    
    def get_help_by_category(self, category: str) -> List[HelpTopic]:
        """Get all help topics in a category"""
        topic_ids = self.topic_categories.get(category, [])
        return [self.help_topics[topic_id] for topic_id in topic_ids if topic_id in self.help_topics]
    
    def get_all_categories(self) -> List[str]:
        """Get all help categories"""
        return list(self.topic_categories.keys())
    
    def show_help_topic(self, topic_id: str) -> str:
        """Show formatted help topic"""
        topic = self.get_help_topic(topic_id)
        if not topic:
            return f"Help topic '{topic_id}' not found."
        
        # Add to help history
        self.help_history.append(topic_id)
        if len(self.help_history) > 20:  # Keep last 20
            self.help_history.pop(0)
        
        # Format help content
        output = []
        output.append(f"# {topic.title}")
        output.append(f"**Category**: {topic.category} | **Difficulty**: {topic.difficulty}")
        
        if topic.interactive:
            output.append("🔧 **Interactive Help Available**")
        
        output.append("")
        output.append(topic.description)
        output.append("")
        output.append(topic.content)
        
        # Add related topics
        if topic.related_topics:
            output.append("\n## Related Topics")
            for related_id in topic.related_topics[:3]:  # Show top 3
                related = self.get_help_topic(related_id)
                if related:
                    output.append(f"- [{related.title}]({related_id})")
        
        return '\n'.join(output)
    
    def get_command_help(self, command: str) -> str:
        """Get help for a specific command"""
        # Update context
        self.current_context.command = command
        self.current_context.recent_commands.append(command)
        
        # Search for command-specific help
        results = self.search_help(f"command {command}", max_results=3)
        
        if results:
            return self.show_help_topic(results[0].id)
        else:
            # Generate generic command help
            return self.generate_command_help(command)
    
    def generate_command_help(self, command: str) -> str:
        """Generate generic help for a command"""
        return f"""# Help for '{command}'

Unfortunately, specific help for the command '{command}' is not available.

## General Help

- Use `blncs --help` to see all available commands
- Use `blncs {command} --help` to see command-specific options  
- Use `blncs help search {command}` to search for related topics

## Getting More Help

- `blncs help topics` - List all help topics
- `blncs help troubleshooting` - Troubleshooting assistant
- `blncs docs open` - Open full documentation

## Recent Commands

{', '.join(self.current_context.recent_commands[-5:]) if self.current_context.recent_commands else 'None'}

Need more specific help? Try `blncs help search <your_question>`
"""
    
    def get_error_help(self, error_message: str, error_type: str = None) -> str:
        """Get help for specific error"""
        # Update context with error information
        self.current_context.error_type = error_type or 'unknown'
        
        # Search for error-related help
        search_query = f"error {error_type or ''} {error_message}"
        results = self.search_help(search_query, max_results=3)
        
        if results:
            return self.show_help_topic(results[0].id)
        else:
            return self.generate_error_help(error_message, error_type)
    
    def generate_error_help(self, error_message: str, error_type: str = None) -> str:
        """Generate generic error help"""
        return f"""# Error Help

**Error Type**: {error_type or 'Unknown'}
**Error Message**: {error_message}

## Suggested Actions

1. **Check the logs** for more details:
   ```bash
   blncs logs --tail 50
   ```

2. **Run diagnostics**:
   ```bash
   blncs diagnostics
   ```

3. **Verify configuration**:
   ```bash
   blncs config validate
   ```

4. **Test connections**:
   ```bash
   blncs connection test
   ```

## Common Error Solutions

- **Connection errors**: Check node status and network connectivity
- **Authentication errors**: Verify certificates and macaroon files
- **Permission errors**: Check file permissions (should be 600)
- **Configuration errors**: Use `blncs config validate` to check settings

## Get More Help

- `blncs help troubleshooting` - Interactive troubleshooting
- `blncs help search "{error_type}"` - Search for specific error type
- `blncs support bundle` - Generate support information

If the error persists, consider generating a support bundle with `blncs support bundle`.
"""
    
    def suggest_next_steps(self, current_topic: str) -> List[str]:
        """Suggest logical next steps based on current help topic"""
        topic = self.get_help_topic(current_topic)
        if not topic:
            return []
        
        suggestions = []
        
        # Add related topics
        suggestions.extend(topic.related_topics[:2])
        
        # Add category-based suggestions
        if topic.category == 'getting_started':
            suggestions.extend(['node_configuration', 'channel_management'])
        elif topic.category == 'configuration':
            suggestions.extend(['getting_started', 'monitoring_setup'])
        elif topic.category == 'operations':
            suggestions.extend(['troubleshooting', 'monitoring_setup'])
        
        # Remove duplicates and current topic
        suggestions = list(set(suggestions))
        if current_topic in suggestions:
            suggestions.remove(current_topic)
        
        return suggestions[:5]  # Return top 5 suggestions
    
    def get_help_statistics(self) -> Dict[str, Any]:
        """Get help system statistics"""
        return {
            'total_topics': len(self.help_topics),
            'categories': len(self.topic_categories),
            'interactive_topics': len([t for t in self.help_topics.values() if t.interactive]),
            'help_history_length': len(self.help_history),
            'most_accessed': self.help_history[-10:] if self.help_history else [],
            'current_context': {
                'command': self.current_context.command,
                'module': self.current_context.module,
                'user_level': self.current_context.user_level
            }
        }


# Global help system instance
_help_system = None
_help_system_lock = Lock()


def get_help_system() -> HelpSystem:
    """Get global help system instance"""
    global _help_system
    
    if _help_system is None:
        with _help_system_lock:
            if _help_system is None:
                _help_system = HelpSystem()
    
    return _help_system


def show_help(topic: str = None, query: str = None, command: str = None, 
              error: str = None, error_type: str = None) -> str:
    """Convenience function to show help"""
    help_system = get_help_system()
    
    if topic:
        return help_system.show_help_topic(topic)
    elif query:
        results = help_system.search_help(query)
        if results:
            return help_system.show_help_topic(results[0].id)
        else:
            return f"No help found for '{query}'. Try `blncs help topics` for all available help."
    elif command:
        return help_system.get_command_help(command)
    elif error:
        return help_system.get_error_help(error, error_type)
    else:
        # Show general help
        return help_system.show_help_topic('quick_start_wizard')


if __name__ == "__main__":
    # Test help system
    help_system = HelpSystem()
    
    print("Help System Test")
    print("=" * 30)
    
    # Test topic listing
    topics = list(help_system.help_topics.keys())
    print(f"Available topics: {len(topics)}")
    
    # Test search
    results = help_system.search_help("lightning channel")
    print(f"Search results for 'lightning channel': {len(results)}")
    for result in results[:3]:
        print(f"  - {result.title} ({result.category})")
    
    # Test contextual help
    context = HelpContext(command='channels', operation='open')
    help_system.current_context = context
    contextual = help_system.get_contextual_help()
    print(f"Contextual help topics: {len(contextual)}")
    
    # Test categories
    categories = help_system.get_all_categories()
    print(f"Help categories: {categories}")
    
    # Test help display
    help_content = help_system.show_help_topic('quick_start_wizard')
    print(f"Help content length: {len(help_content)} characters")
    
    print("Help system test completed")